/**
 * 编排内核：RunSpec → 冻结 Plan → 执行(进程内 L0 或 子进程 L1) → 对账 → 门禁 → receipt → 退出码。
 * 只负责编排顺序，不越权实现各模块算法（归属于 control/adapters/worker/reports）。
 * @module @deepseek-ai/dsh-plugin-testbed/kernel
 */
import { randomUUID } from 'node:crypto'
import { createRequire } from 'node:module'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { isAbsolute } from 'node:path'
import { isRunSpecVersion } from './protocol/schemas.js'
import { sha256Hex, canonicalJson } from './protocol/digest.js'
import { compilePlanCandidate, freezePlan } from './control/plan.js'
import { applyAssertion } from './control/assert.js'
import { reconcile } from './control/reconcile.js'
import { aggregateGateDecision } from './control/gate.js'
import { buildReceipt } from './reports/shape.js'
import { persistReceipt } from './reports/receipt.js'
import { resolveExitCode } from './reports/exit.js'
import { makeInProcessPort } from './adapters/inprocess.js'
import { CAPABILITY_PROBE_VERSION, probeCapabilities } from './worker/probe.js'

const BASE_LIMITATIONS = Object.freeze([
  'local-only',
  'no-external-trust-anchor',
  'no-signature',
])

// 版本锚（候选锁定，已记录进 receipt provenance）：
// DSH checkout HEAD = 86a402200d（= 架构 §13 核对快照）；Cordis = 4.0.5-alpha.2（vendored built entry）。
const LOCKED_DSH_COMMIT = '86a402200d95fecef4529d969836f1fe13c6cb0d'
const LOCKED_CORDIS_VERSION = '4.0.5-alpha.2'

/**
 * 默认 cordis 入口的解析链（全部失败 → null，由调用方在需要时 fail-closed）：
 * 1. 环境变量 DSH_TESTBED_CORDIS_ENTRY（本地路径或 file:// URL）；
 * 2. 从本包位置向上解析 cordis——装进 DSH 宿主时命中的就是宿主自带的。
 *
 * 此前这里是开发者本机的绝对路径（file:///D:/deepseek-harness/...），任何
 * fresh clone 的 load-put 场景都必然 import 失败（M3 三个失败同因）。
 */
function resolveDefaultCordisEntry() {
  const env = process.env.DSH_TESTBED_CORDIS_ENTRY
  if (env) return pathToFileURL(env).href
  try {
    const require = createRequire(import.meta.url)
    for (const specifier of ['cordis/lib/index.js', 'cordis']) {
      try { return pathToFileURL(require.resolve(specifier)).href } catch { /* 试下一个 */ }
    }
  } catch { /* 解析环境不可用视同未找到 */ }
  return null
}
const DEFAULT_CORDIS_ENTRY = resolveDefaultCordisEntry()

function freshRunId() {
  return `run-${Date.now().toString(36)}-${randomUUID().slice(0, 8)}`
}

/** 深冻结：冻结后的 Plan 不可变，任何运行时增删改在严格模式下抛错（对象安全）。 */
function deepFreeze(obj) {
  if (obj && typeof obj === 'object' && !Object.isFrozen(obj)) {
    Object.freeze(obj)
    for (const key of Object.keys(obj)) deepFreeze(obj[key])
  }
  return obj
}

/**
 * 执行一次显式本地自检。返回 JSON-safe 摘要（完整 receipt 落盘）。
 * @param {object} runSpec run-spec/v1
 * @param {{ profile?: string, receiptOutDir?: string, overwrite?: boolean,
 *   executionMode?: 'in-process'|'subprocess', timeoutMs?: number }} [opts]
 */
export async function runSelfCheck(runSpec, opts = {}) {
  const profile = opts.profile ?? 'local-selfcheck/v1'
  const receiptOut = opts.receiptOutDir ?? '.dsh-testbed-receipts'
  const executionMode = opts.executionMode ?? 'in-process'
  const runId = freshRunId()
  const limitations = [...BASE_LIMITATIONS]
  if (executionMode === 'subprocess') {
    limitations.push('l1-subprocess', 'unenforced: filesystem,network,subprocess,devices,cpu,memory')
  }

  /** 落盘 + 退出码；写不出有效 receipt 时进程级失败。 */
  const finish = (receipt) => {
    try {
      const persisted = persistReceipt(receipt, receiptOut, { overwrite: opts.overwrite ?? false })
      return {
        runId: receipt.run_id,
        gateDecision: receipt.gate_decision ?? null,
        trustScope: receipt.trust_scope,
        marketEligible: receipt.market_eligible,
        exitCode: resolveExitCode({ kind: 'receipt', receipt }, profile),
        profileId: profile,
        receiptPath: persisted.path,
        recordDigest: persisted.recordDigest,
        reconciliation: receipt.reconciliation ?? null,
      }
    } catch (err) {
      return {
        runId,
        gateDecision: null,
        trustScope: 'local-only',
        marketEligible: false,
        exitCode: resolveExitCode({ kind: 'write-failure' }, profile),
        profileId: profile,
        receiptPath: null,
        recordDigest: receipt?.integrity?.record_digest ?? null,
        reconciliation: null,
        writeError: String(err?.message ?? err),
      }
    }
  }

  const prePlanBlocked = (stage, reasonCodes) => finish(buildReceipt({
    shape: 'pre-plan-blocked',
    runId,
    profileRef: runSpec?.profile_ref ?? null,
    scenarioRef: runSpec?.scenario_ref ?? null,
    targetRef: targetReference(runSpec?.target),
    provenance: provenanceOf(runSpec, executionMode),
    planCandidateRef: null,
    blockedStage: stage,
    reasonCodes,
    limitations,
  }))

  const prePlanCancelled = (stage, reasonCodes) => finish(buildReceipt({
    shape: 'pre-plan-cancelled',
    runId,
    profileRef: runSpec?.profile_ref ?? null,
    scenarioRef: runSpec?.scenario_ref ?? null,
    targetRef: targetReference(runSpec?.target),
    provenance: provenanceOf(runSpec, executionMode),
    planCandidateRef: null,
    cancelledStage: stage,
    reasonCodes,
    limitations,
  }))

  if (!runSpec || !isRunSpecVersion(runSpec.schema_version)) {
    return prePlanBlocked('intake', ['run-spec-version-unknown'])
  }
  const cases = runSpec?.scenario?.cases
  if (!Array.isArray(cases) || cases.length === 0) {
    return prePlanBlocked('intake', ['missing-or-empty-scenario'])
  }

  const compiled = compilePlanCandidate(cases)
  if (!compiled.ok) {
    return prePlanBlocked('compile-plan-candidate', compiled.errors)
  }

  // Caller capability claims are never trusted. Reject them before a Plan exists;
  // the only capability records in this MVP come from the control-created probe.
  if (cases.some((caseSpec) => caseSpec && Object.hasOwn(caseSpec, 'capability'))) {
    return prePlanBlocked('capability-admission', ['case-capability-untrusted'])
  }

  // M5: tool admission happens before freeze. The manifest is the only source of
  // tool_ref; artifactPath/workspaceRoot are pinned as constructor bindings.
  let toolLib = null
  const toolBindings = Object.create(null)
  const toolRefs = []
  const toolCases = cases.filter((caseSpec) => caseSpec && caseSpec.tool)
  if (toolCases.length > 0) {
    if (targetReference(runSpec?.target) === null) {
      return prePlanBlocked('tool-admission', ['tool-target-reference-invalid'])
    }
    const { validateToolManifest } = await import('./protocol/tool-manifest.js')
    const { validateValue } = await import('./protocol/jsonschema.js')
    const { pinManifestArtifact } = await import('./worker/runner.js')
    toolLib = { validateValue }
    for (const caseSpec of toolCases) {
      const tool = caseSpec.tool
      const mv = validateToolManifest(tool?.manifest)
      if (!mv.ok) return prePlanBlocked('tool-admission', ['tool-manifest-invalid: ' + (mv.errors[0] ?? 'unknown')])
      const iv = validateValue(tool.input, tool.manifest.input_schema)
      if (!iv.ok) return prePlanBlocked('tool-admission', ['tool-input-schema-invalid: ' + (iv.errors[0] ?? 'unknown')])
      if (typeof tool.artifactPath !== 'string' || !isAbsolute(tool.artifactPath) ||
          typeof tool.workspaceRoot !== 'string' || !isAbsolute(tool.workspaceRoot)) {
        return prePlanBlocked('tool-admission', ['tool-binding-invalid'])
      }
      // Read/hash the exact artifact bytes before plan freeze. This prevents a
      // caller-supplied manifest digest from becoming a trusted tool_ref.
      const pinned = await pinManifestArtifact({
        manifest: tool.manifest,
        artifactPath: tool.artifactPath,
        workspaceRoot: tool.workspaceRoot,
      })
      if (!pinned.ok) return prePlanBlocked('tool-admission', [pinned.errors?.[0] ?? 'tool-artifact-invalid'])
      const binding = {
        manifest: tool.manifest,
        artifactPath: pinned.artifact_path,
        workspaceRoot: tool.workspaceRoot,
        toolRef: pinned.tool_ref,
      }
      toolBindings[caseSpec.test_id] = binding
      toolRefs.push(pinned.tool_ref)
    }
  }

  const probeContext = {
    put_digest: null,
    environment_fingerprint: null,
    probe_version: CAPABILITY_PROBE_VERSION,
  }
  const capabilities = probeCapabilities(cases, probeContext)

  // MVP never establishes not-applicable: all probe observations are unknown.
  const notApplicable = []
  const notApplicableReasons = []
  // Plan cancellation before the first test request retains the pre-plan shape.
  if (opts.signal?.aborted) {
    return prePlanCancelled('pre-freeze', ['cancelled'])
  }
  const preapprovedWaivers = Array.isArray(runSpec?.policy?.preapproved_waivers)
    ? runSpec.policy.preapproved_waivers
    : []
  const frozen = freezePlan(compiled.candidate, {
    capabilitySnapshots: capabilities,
    planContext: probeContext,
    notApplicable,
    preapprovedWaivers,
  })
  deepFreeze(frozen)

  // Execute, then verify cleanup before constructing/digesting the receipt.
  const toolCapabilitySnapshotRefs = Object.fromEntries(
    Object.keys(toolBindings).map((id) => [id, frozen.capabilitySnapshotRefs[id]]),
  )
  let subprocessAdapter = null
  let port = null
  let abortHandler = null
  const recordsByTestId = Object.create(null)
  const observationsAll = []
  let reconciliation = null
  let gate = null
  let cleanup = null
  let cleanupFailure = null
  try {
    // 只有 load-put 探针需要 cordis；其余场景不因 cordis 缺席而失败。
    const needsCordis = compiled.candidate.cases.some((c) => c.probe?.op === 'load-put')
    const cordisEntry = opts.cordisEntry ?? DEFAULT_CORDIS_ENTRY
    if (!cordisEntry && needsCordis) {
      throw new Error('未找到 cordis 入口（load-put 场景需要）：装进 DSH 宿主时会自动解析宿主自带的 cordis；'
        + '独立使用请设置环境变量 DSH_TESTBED_CORDIS_ENTRY（本地路径或 file:// URL），或传入 opts.cordisEntry。')
    }
    port = await makePort(executionMode, {
      runId,
      planId: frozen.plan_id,
      timeoutMs: opts.timeoutMs,
      cordisEntry,
      toolBindings,
      capabilitySnapshotRefs: toolCapabilitySnapshotRefs,
      targetRef: targetReference(runSpec?.target),
      onAdapter(a) { subprocessAdapter = a },
    })
    abortHandler = () => {
      try { port?.cancel?.() } catch { /* signal remains the authoritative cancellation state */ }
      try { subprocessAdapter?.cancel?.() } catch { /* reap below verifies final state */ }
    }
    opts.signal?.addEventListener?.('abort', abortHandler, { once: true })
    if (opts.signal?.aborted) abortHandler()

    for (const caseSpec of compiled.candidate.cases) {
      if (opts.signal?.aborted) break
      if (frozen.notApplicable.includes(caseSpec.test_id)) continue
      // Missing terminal injection remains missing; it is not a synthetic attempt.
      if (caseSpec.no_terminal === true) continue

      const maxAttempts = Math.max(1, caseSpec.retry?.max_attempts ?? 1)
      const attempts = []
      let finalOutcome = null
      let finalObservation = null
      let finalVerdict = null
      let finalReasonCodes = []
      for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
        if (opts.signal?.aborted) break
        // Negative-test simulation only: admission is caller-supplied in RunSpec,
        // so this is not an independent GatePolicy decision. The kernel's actual
        // local fact is that this branch bypasses port.execute().
        const callerRequestedNoDispatch = caseSpec.admission === 'rejected'
        const outcome = callerRequestedNoDispatch
          ? {
              admission_status: 'rejected', execution_status: 'skipped',
              observations: [], reason_codes: ['caller_requested_no_dispatch'],
            }
          : await port.execute(caseSpec, runId, frozen.plan_id, attempt)
        const invocationStatus = callerRequestedNoDispatch ? 'not-started' : 'unknown'
        let verdict
        const reasonCodes = Array.isArray(outcome.reason_codes) ? [...outcome.reason_codes] : []
        if (outcome.execution_status === 'completed') {
          const value = outcome.observations[0]?.value ?? outcome.observations[0] ?? null
          if (caseSpec.tool && toolLib) {
            const ov = toolLib.validateValue(value, caseSpec.tool.manifest.observation_schema)
            if (!ov.ok) {
              verdict = 'error'
              reasonCodes.push('observation-schema-invalid')
            }
          }
          if (verdict === undefined) {
            verdict = caseSpec.criteria ? applyAssertion(value, caseSpec.criteria).verdict : 'inconclusive'
          }
        } else if (outcome.execution_status === 'skipped') {
          verdict = 'skip'
        } else {
          verdict = 'error'
        }
        const observation = outcome.observations[0] ?? null
        if (observation) observationsAll.push(observation)
        attempts.push({
          attempt,
          admission_status: outcome.admission_status,
          execution_status: outcome.execution_status,
          invocation_status: invocationStatus,
          invocation_evidence_verified: false,
          verdict,
          reason_codes: reasonCodes,
        })
        finalOutcome = outcome
        finalObservation = observation
        finalVerdict = verdict
        finalReasonCodes = reasonCodes
        if (verdict === 'pass') break
      }

      // An aborted case that never reached dispatch stays absent so reconciliation
      // records it as missing; completed attempts above are retained verbatim.
      if (finalOutcome === null) break
      recordsByTestId[caseSpec.test_id] = {
        test_id: caseSpec.test_id,
        classification: caseSpec.classification,
        verdict: finalVerdict,
        invocation_status: attempts.at(-1).invocation_status,
        invocation_evidence_verified: false,
        execution_status: finalOutcome.execution_status,
        admission_status: finalOutcome.admission_status,
        reason_codes: finalReasonCodes,
        dimensions: caseSpec.dimensions ?? {},
        criteria_ref: caseSpec.criteria ? 'criteria/' + caseSpec.test_id : null,
        attempts,
        observation_refs: finalObservation ? [finalObservation.observation_id] : [],
      }
    }

    const resultsByTestId = Object.fromEntries(
      Object.entries(recordsByTestId).map(([id, record]) => [id, { verdict: record.verdict }]),
    )
    reconciliation = reconcile(frozen, resultsByTestId, [])
    gate = aggregateGateDecision(frozen, reconciliation, recordsByTestId)
  } finally {
    opts.signal?.removeEventListener?.('abort', abortHandler)
    if (subprocessAdapter) {
      try {
        const report = await subprocessAdapter.reap()
        cleanup = report
        if (report?.pid_alive !== false || report?.temp_removed !== true) {
          cleanupFailure = { reason: 'cleanup-failed', report: report ?? null }
        }
      } catch (err) {
        cleanupFailure = { reason: 'cleanup-failed', error: String(err?.message ?? err) }
      }
    }
  }

  if (cleanupFailure) gate = { gate_decision: 'blocked', reason: 'cleanup-failed' }
  const receipt = buildReceipt({
    shape: 'frozen',
    runId,
    profileRef: runSpec?.profile_ref ?? null,
    scenarioRef: runSpec?.scenario_ref ?? null,
    targetRef: targetReference(runSpec?.target),
    provenance: provenanceOf(runSpec, executionMode, subprocessAdapter?.launchRecord ?? null, {
      cleanup: subprocessAdapter ? cleanup : null,
      cleanup_failure: cleanupFailure,
      toolRefs,
    }),
    planCandidateRef: {
      digest: 'sha256:' + sha256Hex(canonicalJson(compiled.candidate.testIds)),
      baseline_test_ids: compiled.candidate.baselineTestIds,
      required_test_ids: compiled.candidate.requiredTestIds,
    },
    planResolution: {
      plan_id: frozen.plan_id,
      test_cases: frozen.testCases,
      capability_snapshot: capabilities,
      not_applicable: notApplicableReasons,
    },
    reconciliation,
    testCases: Object.values(recordsByTestId),
    observations: observationsAll,
    artifacts: [],
    gateDecision: gate?.gate_decision ?? 'blocked',
    gateReason: gate?.reason ?? 'execution-incomplete',
    runStatus: opts.signal?.aborted ? 'cancelled' : 'completed',
    limitations,
  })
  return finish(receipt)
}

/** 构建执行 port：in-process（同步 L0）或 subprocess（异步 L1）。 */
async function makePort(mode, {
  runId, planId, timeoutMs, cordisEntry, onAdapter,
  toolBindings = Object.create(null), capabilitySnapshotRefs = Object.create(null),
  targetRef,
}) {
  if (mode === 'subprocess') {
    const { makeSubprocessAdapter } = await import('./adapters/subprocess.js')
    const workerEntry = fileURLToPath(new URL('./worker/host.js', import.meta.url))
    const hasTools = Object.keys(toolBindings).length > 0
    const adapter = makeSubprocessAdapter({
      workerEntry,
      runId,
      timeoutMs: timeoutMs ?? 15000,
      toolBindings: hasTools ? toolBindings : undefined,
      capabilitySnapshotRefs: hasTools ? capabilitySnapshotRefs : undefined,
    })
    adapter.start()
    onAdapter(adapter)
    return {
      cancel() { adapter.cancel?.() },
      async execute(caseSpec, rid, pid, attempt = 1) {
        const requestId = `req-${rid}-${caseSpec.test_id}-${attempt}`
        if (caseSpec.tool) {
          const deadline = new Date(Date.now() + (timeoutMs ?? 15000)).toISOString()
          return adapter.execute({
            protocol_version: 'test-tool/v1',
            request_id: requestId,
            run_id: rid,
            plan_id: pid,
            test_id: caseSpec.test_id,
            attempt,
            tool_ref: toolBindings[caseSpec.test_id]?.toolRef,
            target_ref: targetRef,
            input: caseSpec.tool.input,
            deadline,
            capability_snapshot_ref: capabilitySnapshotRefs[caseSpec.test_id],
          })
        }
        const probe = caseSpec.probe ?? {}
        const input = { op: probe.op ?? 'echo', value: probe.value ?? null, delay_ms: probe.delay_ms ?? 0 }
        if (probe.op === 'load-put') {
          input.cordis_entry = cordisEntry
          input.put_entry = probe.put_entry
          input.put_config = probe.put_config ?? {}
        }
        return adapter.execute({
          request_id: requestId, run_id: rid, plan_id: pid,
          test_id: caseSpec.test_id, attempt, input,
        })
      },
    }
  }
  const inProcess = makeInProcessPort()
  return { execute(caseSpec) { return inProcess.execute(caseSpec) } }
}

function targetReference(target) {
  if (typeof target?.put_digest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(target.put_digest)) return null
  return {
    kind: typeof target?.kind === 'string' && target.kind.length > 0 ? target.kind : 'plugin',
    owner_put_digest: target.put_digest,
    origin: 'run-spec-unverified',
  }
}

function provenanceOf(runSpec, executionMode, launchRecord = null, details = {}) {
  const provider = executionMode === 'subprocess'
    ? { adapter_ref: 'subprocess-l1@0.1.0', isolation: 'L1-subprocess', launch_record: launchRecord }
    : { adapter_ref: 'in-process-l0@0.1.0', isolation: 'L0-in-process' }
  return {
    // RunSpec target digests are caller assertions, never provenance attestations.
    put_digest: null,
    dsh_commit: LOCKED_DSH_COMMIT,
    cordis_version: LOCKED_CORDIS_VERSION,
    ...provider,
    tool_refs: details.toolRefs ?? [],
    cordis_entry: details.cordis_entry ?? null,
    assertion_refs: [],
    cleanup: details.cleanup ?? null,
    cleanup_failure: details.cleanup_failure ?? null,
    policy_ref: runSpec?.policy_ref ?? null,
    node_version: process.version,
    os_platform: process.platform,
    os_arch: process.arch,
    environment_fingerprint: 'sha256:' + sha256Hex(canonicalJson({
      node: process.version,
      platform: process.platform,
      arch: process.arch,
    })),
  }
}