/**
 * 编排内核：RunSpec → PlanCandidate → worker 两阶段能力探测 → 控制面核验 →
 * 冻结 Plan → 执行(L0 进程内 / L1 子进程) → 对账 → GatePolicy 聚合 → receipt → 退出码。
 *
 * 固定运行顺序（architecture §10 / §12，development.md「实现一条可审计的运行链」）：
 *   intake → candidate → worker probe → control verification → freeze →
 *   execute → reconcile → aggregate → receipt/project/exit
 *
 * 本文件只做集成编排与证据搬运：
 *   - 不实现控制算法（plan/capability/admission/execute/reconcile/gate 归 `control/`）；
 *   - 不实现 worker 内部探测或工具执行（归 `worker/`）；
 *   - 不实现 adapter 生命周期与独立启动见证（归 `adapters/`）；
 *   - 不把 worker 自报的 verdict / gate / started 时间戳当作权威事实。
 *
 * 关键集成约束：
 *   1. 运行时锚点不再硬编码任何主机路径；由 `opts.runtimeAnchor` / 环境变量 /
 *      已安装包解析（worker/runtime.js）得到，并把可观测 provenance 写入 receipt。
 *   2. 能力探测通过 `control-protocol/v1` 的 `op:'probe-capabilities'` 在 worker 内
 *      真实执行；快照取自 `observations[0].value`，由控制面用 `probeCapabilities
 *      ({snapshot})` 核验后才用于冻结。
 *   3. `invocation_status=started` 只来自 adapter 的 OS spawn 见证；legacy
 *      load-put / echo 等控制面 op 没有该见证，保持 `unknown`。
 *   4. 冻结后的拒绝只来自控制面 `decideAdmission`（从不读取 caller `admission`），
 *      并在 receipt 中按 `rejected/skipped/skip/not-started` + `policy_rejected` 留痕。
 *   5. 落盘前用 `receipt/v1` 严格校验；构造失败按 §11.2.2 返回进程级失败（exit 3），
 *      绝不落盘无效 receipt。
 *
 * @module @deepseek-ai/dsh-plugin-testbed/kernel
 */
import { createHash, randomUUID } from 'node:crypto'
import { readFile, stat } from 'node:fs/promises'
import { isAbsolute } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { isRunSpecVersion } from './protocol/schemas.js'
import { validateReceiptV1 } from './protocol/contracts.js'
import { sha256Hex, canonicalJson } from './protocol/digest.js'
import { compilePlanCandidate, freezePlan, verifyFrozenPlan, planResolutionEntries } from './control/plan.js'
import { validateRunSpec, validateGatePolicy } from './control/spec.js'
import { CAPABILITY_PREDICATE_VERSION } from './control/capability.js'
import { executeFrozenPlan } from './control/execute.js'
import { reconcile, reconcileAdoptedAttempts } from './control/reconcile.js'
import { aggregateGateDecision } from './control/gate.js'
import {
  resolveRunBudget,
  assertPlanAttemptsWithinBudget,
  planDeclaredAttempts,
  createBudgetLedger,
  DEFAULT_RUN_BUDGET,
} from './control/budget.js'
import { validateToolManifest } from './protocol/tool-manifest.js'
import { validateValue } from './protocol/jsonschema.js'
import { pinManifestArtifact } from './worker/runner.js'
import {
  CAPABILITY_PROBE_VERSION,
  caseRecordsFromSnapshot,
  probeCapabilities,
} from './worker/probe.js'
import { MAX_RUNTIME_ENTRY_BYTES, resolveRuntimeAnchor, runtimeProvenanceForReceipt } from './worker/runtime.js'
import { makeInProcessPort } from './adapters/inprocess.js'
import {
  ADAPTER_REF,
  ISOLATION_LEVEL,
  UNENFORCED_RESOURCES,
  makeSubprocessAdapter,
} from './adapters/subprocess.js'
import { buildReceipt } from './reports/shape.js'
import { persistReceipt } from './reports/receipt.js'
import { resolveExitCode } from './reports/exit.js'

const WORKER_ENTRY = fileURLToPath(new URL('./worker/host.js', import.meta.url))
const PROVISIONAL_PROBE_PLAN_ID = 'plan-probe-pending'
const ISOLATION_LABEL = ISOLATION_LEVEL

const BASE_LIMITATIONS = Object.freeze([
  'local-only',
  'no-external-trust-anchor',
  'no-signature',
])

const SUPPORTED_PROFILES = Object.freeze(['local-selfcheck/v1', 'market-required/v1'])

function freshRunId() {
  return `run-${Date.now().toString(36)}-${randomUUID().slice(0, 8)}`
}

/** @param {unknown} v */
function isPlainRecord(v) {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false
  const proto = Object.getPrototypeOf(v)
  return proto === Object.prototype || proto === null
}

/** @param {unknown} v */
function nonEmptyString(v) {
  return typeof v === 'string' && v.length > 0
}

/** Deterministic JSON projection; drops functions/symbols so receipt bytes stay canonical. */
function jsonSafe(value) {
  try {
    const text = JSON.stringify(value === undefined ? null : value)
    if (text === undefined) return null
    return JSON.parse(text)
  } catch {
    return null
  }
}

/** @param {object|null|undefined} ref */
function receiptVersionRef(ref) {
  if (!isPlainRecord(ref) || !nonEmptyString(ref.id) || !nonEmptyString(ref.version)) return null
  // RunSpec references may omit a content digest. The receipt binds the exact
  // declaration available at run time: re-use a declared digest when valid,
  // otherwise hash the canonical declaration (never invent a content claim).
  const digest = typeof ref.digest === 'string' && /^sha256:[0-9a-f]{64}$/.test(ref.digest)
    ? ref.digest
    : 'sha256:' + sha256Hex(canonicalJson({ id: ref.id, version: ref.version }))
  return { id: ref.id, version: ref.version, digest }
}

/** @param {object|null|undefined} target */
function targetReference(target) {
  if (!isPlainRecord(target) || typeof target.put_digest !== 'string' ||
      !/^sha256:[0-9a-f]{64}$/.test(target.put_digest)) {
    return null
  }
  return {
    kind: typeof target.kind === 'string' && target.kind.length > 0 ? target.kind : 'plugin',
    owner_put_digest: target.put_digest,
    origin: typeof target.origin === 'string' && target.origin.length > 0 ? target.origin : 'run-spec-unverified',
  }
}

/** Candidate baseline digest: binds the exact candidate test list and policy baseline. */
function candidateReference(candidate) {
  if (!candidate) return null
  const input = {
    baseline_test_ids: [...(candidate.baselineTestIds ?? [])],
    required_test_ids: [...(candidate.requiredTestIds ?? [])],
    topo_order: [...(candidate.topoOrder ?? [])],
  }
  return {
    digest: 'sha256:' + sha256Hex(canonicalJson(input)),
    baseline_test_ids: input.baseline_test_ids,
    required_test_ids: input.required_test_ids,
  }
}

/**
 * Synthesize the frozen `gate-policy/v1` declaration from the caller scenario.
 *
 * The localized MVP has no separate external policy artifact: the scenario's
 * classification is the candidate baseline and the fixed aggregation order is
 * the only accepted precedence. Every applicability predicate must already be
 * declared by the scenario; the policy merely makes it explicit and freezeable.
 */
function synthesizeGatePolicy(runSpec, cases) {
  const required = []
  const optional = []
  const predicates = []
  for (const caseSpec of cases) {
    if (caseSpec.classification === 'required') required.push(caseSpec.test_id)
    else optional.push(caseSpec.test_id)
    if (isPlainRecord(caseSpec.not_applicable_when) &&
        nonEmptyString(caseSpec.not_applicable_when.observed)) {
      predicates.push({
        test_id: caseSpec.test_id,
        predicate_version: CAPABILITY_PREDICATE_VERSION,
        observed: caseSpec.not_applicable_when.observed,
        verification: 'corroborated',
      })
    }
  }
  const waivers = Array.isArray(runSpec?.policy?.preapproved_waivers)
    ? [...runSpec.policy.preapproved_waivers]
    : []
  return {
    schema_version: 'gate-policy/v1',
    required_baseline: required,
    optional_baseline: optional,
    not_applicable_predicates: predicates,
    waiver_rules: waivers.map((testId) => ({
      test_id: testId,
      scope: 'preapproved',
      reason: 'run-spec-preapproved-waiver',
    })),
    aggregation: { precedence: ['blocked', 'reject', 'pass'] },
  }
}

/** Normalize a `file:` URL / absolute path to `{path,url}`; relative paths are rejected. */
function normalizeFileEntry(entry) {
  if (typeof entry !== 'string' || entry.length === 0 || entry.includes('\0')) return null
  let path
  if (entry.startsWith('file:')) {
    try {
      path = fileURLToPath(entry)
    } catch {
      return null
    }
  } else if (isAbsolute(entry)) {
    path = entry
  } else {
    return null
  }
  return { path, url: pathToFileURL(path).href }
}

/**
 * Pin PUT bytes before the worker loads them: the control face hashes the exact
 * bytes and requires the caller's target digest to match. This turns a caller
 * assertion into a control-plane pinned digest without ever trusting a path.
 */
async function pinPutEntry(cases, runSpec) {
  const entries = [...new Set(cases
    .map((caseSpec) => caseSpec?.probe?.put_entry)
    .filter((entry) => typeof entry === 'string' && entry.length > 0))]
  if (entries.length === 0) return { ok: true, putDigest: null, putEntry: null }
  if (entries.length > 1) return { ok: false, errors: ['multiple-put-entries-unsupported'] }
  const descriptor = normalizeFileEntry(entries[0])
  if (descriptor === null) return { ok: false, errors: ['put-entry-invalid'] }
  let bytes
  try {
    const info = await stat(descriptor.path)
    if (!info.isFile() || info.size > MAX_RUNTIME_ENTRY_BYTES) throw new Error('put-entry-invalid')
    bytes = await readFile(descriptor.path)
  } catch {
    return { ok: false, errors: ['put-entry-invalid'] }
  }
  if (bytes.byteLength > MAX_RUNTIME_ENTRY_BYTES) return { ok: false, errors: ['put-entry-invalid'] }
  const putDigest = 'sha256:' + createHash('sha256').update(bytes).digest('hex')
  if (putDigest !== runSpec?.target?.put_digest) return { ok: false, errors: ['target-digest-mismatch'] }
  return { ok: true, putDigest, putEntry: descriptor.url }
}

/**
 * Pin tool manifests/artifacts before the Plan exists (architecture §9.4 step 1,
 * CONTRACT-m5 §3). The manifest is the only source of tool_ref.
 */
async function pinToolBindings(cases, runSpec) {
  const bindings = Object.create(null)
  const toolRefs = []
  const toolCases = cases.filter((caseSpec) => caseSpec && caseSpec.tool)
  if (toolCases.length === 0) return { ok: true, bindings, toolRefs }
  if (targetReference(runSpec?.target) === null) {
    return { ok: false, errors: ['tool-target-reference-invalid'] }
  }
  for (const caseSpec of toolCases) {
    const tool = caseSpec.tool
    const manifestCheck = validateToolManifest(tool?.manifest)
    if (!manifestCheck.ok) {
      return { ok: false, errors: ['tool-manifest-invalid: ' + (manifestCheck.errors[0] ?? 'unknown')] }
    }
    const inputCheck = validateValue(tool.input, tool.manifest.input_schema)
    if (!inputCheck.ok) {
      return { ok: false, errors: ['tool-input-schema-invalid: ' + (inputCheck.errors[0] ?? 'unknown')] }
    }
    if (typeof tool.artifactPath !== 'string' || !isAbsolute(tool.artifactPath) ||
        typeof tool.workspaceRoot !== 'string' || !isAbsolute(tool.workspaceRoot)) {
      return { ok: false, errors: ['tool-binding-invalid'] }
    }
    let pinned
    try {
      pinned = await pinManifestArtifact({
        manifest: tool.manifest,
        artifactPath: tool.artifactPath,
        workspaceRoot: tool.workspaceRoot,
      })
    } catch (err) {
      return { ok: false, errors: ['tool-artifact-invalid: ' + String(err?.message ?? err)] }
    }
    if (!pinned.ok) return { ok: false, errors: [pinned.errors?.[0] ?? 'tool-artifact-invalid'] }
    bindings[caseSpec.test_id] = {
      manifest: tool.manifest,
      artifactPath: pinned.artifact_path,
      workspaceRoot: tool.workspaceRoot,
      toolRef: pinned.tool_ref,
    }
    toolRefs.push(pinned.tool_ref)
  }
  return { ok: true, bindings, toolRefs }
}

/**
 * Resolve the runtime anchor from trusted embedding configuration only. No
 * host path is hard-coded; absent an injected anchor the worker either resolves
 * an installed package or reports `unavailable` (never a fabricated present).
 */
async function resolveKernelRuntime(opts) {
  let injection = null
  if (Object.hasOwn(opts, 'runtimeAnchor')) injection = opts.runtimeAnchor
  else if (typeof opts.cordisEntry === 'string' && opts.cordisEntry.length > 0) {
    injection = {
      cordis_entry: opts.cordisEntry,
      cordis_version: typeof opts.cordisVersion === 'string' ? opts.cordisVersion : null,
      dsh_commit: typeof opts.dshCommit === 'string' ? opts.dshCommit : null,
      runtime_kind: typeof opts.runtimeKind === 'string' ? opts.runtimeKind : 'injected-runtime',
    }
  }
  try {
    return await resolveRuntimeAnchor({
      injection,
      env: opts.env ?? process.env,
      cwd: opts.cwd ?? process.cwd(),
    })
  } catch (err) {
    const reason = 'runtime-anchor-invalid'
    return {
      status: 'unavailable',
      reason,
      anchor: null,
      provenance: {
        cordis_version: null,
        dsh_commit: null,
        cordis_version_observed: null,
        cordis_version_verified: false,
        dsh_commit_verified: false,
        cordis_entry: null,
        source: 'none',
        runtime_kind: null,
        node_version: process.version,
        os_platform: process.platform,
        os_arch: process.arch,
        environment_fingerprint: 'sha256:' + sha256Hex(canonicalJson({
          anchor_status: 'unavailable',
          reason,
          node_version: process.version,
          os_platform: process.platform,
          os_arch: process.arch,
        })),
      },
      limitations: [`runtime-unavailable:${reason}:${String(err?.message ?? err).slice(0, 128)}`],
    }
  }
}

/** Serialize a resolved anchor into the closed descriptor accepted by the worker CLI. */
function serializeRuntimeAnchor(anchor) {
  if (!isPlainRecord(anchor) || !nonEmptyString(anchor.cordis_entry)) return undefined
  const descriptor = {
    schema_version: anchor.schema_version,
    cordis_entry: anchor.cordis_entry,
    runtime_kind: anchor.runtime_kind ?? 'injected-runtime',
  }
  for (const key of ['cordis_version', 'dsh_commit', 'node_version', 'platform', 'arch', 'notes']) {
    if (anchor[key] !== undefined && anchor[key] !== null) descriptor[key] = anchor[key]
  }
  return JSON.stringify(descriptor)
}

/** Compact probe cases: keep only the fields worker/probe.js declares/measures. */
function compactProbeCases(cases) {
  return cases.map((caseSpec) => {
    const compact = { test_id: caseSpec.test_id }
    if (isPlainRecord(caseSpec.probe) && nonEmptyString(caseSpec.probe.op)) {
      compact.probe = { op: caseSpec.probe.op }
    }
    if (isPlainRecord(caseSpec.tool) && isPlainRecord(caseSpec.tool.manifest) &&
        Array.isArray(caseSpec.tool.manifest.requires)) {
      compact.tool = {
        manifest: {
          requires: caseSpec.tool.manifest.requires
            .filter((item) => typeof item === 'string')
            .slice(0, 64),
        },
      }
    }
    return compact
  })
}

/**
 * Run the two-phase capability probe in an independent L1 worker.
 *
 * The request travels through `control-protocol/v1`; the snapshot is returned as
 * `observations[0].value`. The worker never reports verification/not-applicable
 * /verdict: the control face derives those through `probeCapabilities({snapshot})`.
 */
async function probeWorkerInL1({ cases, put, runtime, runId, timeoutMs, probeTime, signal }) {
  const adapter = makeSubprocessAdapter({
    workerEntry: WORKER_ENTRY,
    runId,
    timeoutMs,
    runtimeAnchor: serializeRuntimeAnchor(runtime?.anchor),
  })
  const input = {
    op: 'probe-capabilities',
    probe: {
      cases: compactProbeCases(cases),
      put: put === null ? null : { entry: put.putEntry, digest: put.putDigest, config: put.putConfig ?? {} },
      probe_time: probeTime,
    },
  }
  let outcome = null
  let cleanupReport = null
  let failure = null
  const onAbort = () => {
    try { adapter.cancel() } catch { /* reap verifies the final state */ }
  }
  try {
    adapter.start()
    signal?.addEventListener?.('abort', onAbort, { once: true })
    if (signal?.aborted) onAbort()
    outcome = await adapter.execute({
      request_id: `req-probe-${runId}`,
      run_id: runId,
      plan_id: PROVISIONAL_PROBE_PLAN_ID,
      test_id: 'capability-probe',
      attempt: 1,
      input,
    })
  } catch (err) {
    failure = `probe-worker-failed:${String(err?.message ?? err).slice(0, 160)}`
  } finally {
    signal?.removeEventListener?.('abort', onAbort)
    try {
      cleanupReport = await adapter.reap()
    } catch (err) {
      failure = failure ?? `probe-reap-failed:${String(err?.message ?? err).slice(0, 160)}`
      cleanupReport = null
    }
  }

  if (failure !== null) {
    return { snapshot: null, records: null, failure, cleanupReport, reason: failure }
  }
  if (!isPlainRecord(outcome) || outcome.execution_status !== 'completed') {
    const reason = Array.isArray(outcome?.reason_codes) && outcome.reason_codes.length > 0
      ? outcome.reason_codes[0]
      : 'probe-not-completed'
    return { snapshot: null, records: null, failure: `capability-probe-unavailable:${reason}`, cleanupReport }
  }
  const snapshot = outcome.observations?.[0]?.value
  if (!isPlainRecord(snapshot)) {
    return { snapshot: null, records: null, failure: 'capability-probe-unavailable:snapshot-missing', cleanupReport }
  }
  const validated = caseRecordsFromSnapshot(snapshot)
  if (!validated.ok) {
    return {
      snapshot,
      records: null,
      failure: `capability-probe-unavailable:${validated.errors[0] ?? 'snapshot-invalid'}`,
      cleanupReport,
    }
  }
  const reasonCodes = Array.isArray(outcome.reason_codes) ? outcome.reason_codes : []
  const unavailable = reasonCodes.find((code) => code === 'cordis-runtime-unavailable') ?? null
  return { snapshot, records: validated.records, failure: unavailable, cleanupReport, reason: unavailable }
}

/** Evidence shape accepted by `control/execute.adoptInvocationEvidence`. */
function toControlInvocationEvidence(witness) {
  const correlation = witness?.correlation
  if (!isPlainRecord(correlation)) return null
  return {
    source: 'adapter-witness',
    request_id: correlation.request_id,
    run_id: correlation.run_id,
    plan_id: correlation.plan_id,
    test_id: correlation.test_id,
    attempt: correlation.attempt,
    started_at: witness.started_at,
    mechanism: witness.observed?.mechanism ?? null,
    child_pid: witness.observed?.child_pid ?? null,
    isolation: witness.isolation ?? null,
  }
}

/**
 * Project worker observations onto the closed receipt/v1 observation shape.
 * Adds the schema reference the worker/control-op path does not carry and makes
 * observation IDs unique per test case (receipt references stay consistent).
 */
function normalizeReceiptObservations(raw, caseSpec, testId, mode) {
  if (!Array.isArray(raw)) return []
  const manifest = caseSpec?.tool?.manifest
  const toolSchemaRef = isPlainRecord(manifest)
    ? (nonEmptyString(manifest.observation_schema?.$id)
        ? manifest.observation_schema.$id
        : `${String(manifest.tool_id)}@${String(manifest.tool_version)}#observation_schema`)
    : null
  const fallbackRef = toolSchemaRef ?? `urn:dsh:plugin-testbed:observation:${mode}:v1`
  return raw.filter(isPlainRecord).map((observation, index) => {
    const sourceId = nonEmptyString(observation.observation_id)
      ? observation.observation_id
      : `obs-${index + 1}`
    return {
      observation_id: `${testId}#${sourceId}`,
      schema_ref: nonEmptyString(observation.schema_ref) ? observation.schema_ref : fallbackRef,
      value: jsonSafe(observation.value),
      source: observation.source === 'worker' ? 'worker' : 'worker',
      limitations: Array.isArray(observation.limitations)
        ? observation.limitations.filter(nonEmptyString).slice(0, 32)
        : [],
    }
  })
}

/** Build the legacy control-protocol input for non-tool frozen cases. */
function legacyCaseInput(request, caseSpec) {
  if (isPlainRecord(caseSpec?.tool)) return request.input
  const input = isPlainRecord(request.input) ? { ...request.input } : {}
  const probe = isPlainRecord(caseSpec?.probe) ? caseSpec.probe : {}
  if (probe.op === 'load-put') {
    if (typeof probe.put_entry === 'string') input.put_entry = probe.put_entry
    input.put_config = isPlainRecord(probe.put_config) ? probe.put_config : {}
  }
  delete input.put_timeout_ms
  return { op: nonEmptyString(probe.op) ? probe.op : 'echo', ...input }
}

/**
 * Wrap a raw adapter/in-process outcome into a control-adoptable candidate:
 * canonical observations + only independently witnessed invocation evidence.
 */
function enrichOutcome(outcome, { adapter, request, caseSpec, mode }) {
  const observations = normalizeReceiptObservations(outcome?.observations, caseSpec, request.test_id, mode)
  if (!isPlainRecord(outcome)) {
    return {
      admission_status: 'accepted',
      execution_status: 'error',
      invocation_status: 'unknown',
      invocation_evidence_verified: false,
      observations: [],
      reason_codes: ['invalid-response'],
    }
  }
  const enriched = { ...outcome, observations }
  const witness = adapter && typeof adapter.reportInvocationStart === 'function'
    ? adapter.reportInvocationStart({ run_id: adapter.runId }, request.test_id, request.attempt)
    : null
  const evidence = witness === null ? null : toControlInvocationEvidence(witness)
  if (evidence !== null) {
    enriched.invocation_status = 'started'
    enriched.invocation_evidence_verified = true
    enriched.invocation_evidence = evidence
    enriched.started_at = evidence.started_at
    return enriched
  }
  // No independent OS-spawn witness → never trust the worker's started claim.
  if (enriched.invocation_status === 'started') enriched.invocation_status = 'unknown'
  if (!['not-started', 'unknown', 'started'].includes(enriched.invocation_status)) {
    enriched.invocation_status = 'unknown'
  }
  enriched.invocation_evidence_verified = false
  enriched.invocation_evidence = null
  delete enriched.started_at
  return enriched
}

/** Construct the execution dispatch port (control `DispatchPort` shape). */
function makeDispatchPort({ adapter, frozenPlan, mode }) {
  const caseById = new Map((frozenPlan.testCases ?? []).map((caseSpec) => [caseSpec.test_id, caseSpec]))
  if (adapter === null) {
    const inProcess = makeInProcessPort()
    return {
      async execute(caseSpec) {
        const testId = caseSpec.test_id
        const request = { test_id: testId, attempt: 1, run_id: null, plan_id: frozenPlan.plan_id }
        const outcome = enrichOutcome(inProcess.execute(caseSpec), {
          adapter: null,
          request,
          caseSpec,
          mode,
        })
        if (outcome.invocation_status === 'started') {
          outcome.invocation_status = 'unknown'
          outcome.invocation_evidence_verified = false
        }
        return outcome
      },
    }
  }
  return {
    async dispatchToolRequest(request, signal) {
      const caseSpec = caseById.get(request.test_id) ?? null
      const effectiveRequest = isPlainRecord(caseSpec?.tool)
        ? request
        : { ...request, input: legacyCaseInput(request, caseSpec) }
      if (!isPlainRecord(caseSpec?.tool)) {
        // `execute.buildToolRequest` always tags requests as test-tool/v1; legacy
        // control ops (echo/load-put/...) use control-protocol/v1 instead.
        delete effectiveRequest.protocol_version
        delete effectiveRequest.target_ref
      }
      const onAbort = () => {
        try { adapter.cancel() } catch { /* reap verifies the final state */ }
      }
      signal?.addEventListener?.('abort', onAbort, { once: true })
      if (signal?.aborted) onAbort()
      let outcome
      try {
        outcome = await adapter.execute(effectiveRequest)
      } catch (err) {
        outcome = {
          admission_status: 'accepted',
          execution_status: 'error',
          invocation_status: 'unknown',
          observations: [],
          reason_codes: ['dispatch-error'],
          diagnostics: [String(err?.message ?? err).slice(0, 200)],
        }
      } finally {
        signal?.removeEventListener?.('abort', onAbort)
      }
      return enrichOutcome(outcome, { adapter, request: effectiveRequest, caseSpec, mode })
    },
  }
}

/** Append the canonical `policy_rejected` umbrella code to control-plane rejections. */
function normalizePolicyRejectedRecords(recordsByTestId) {
  const out = Object.create(null)
  for (const [testId, record] of Object.entries(recordsByTestId ?? {})) {
    if (!isPlainRecord(record) || record.admission_status !== 'rejected') {
      out[testId] = record
      continue
    }
    const recordCodes = Array.isArray(record.reason_codes) ? [...record.reason_codes] : []
    if (!recordCodes.includes('policy_rejected')) recordCodes.unshift('policy_rejected')
    const attempts = Array.isArray(record.attempts)
      ? record.attempts.map((attempt) => {
          if (!isPlainRecord(attempt) || attempt.admission_status !== 'rejected') return attempt
          const codes = Array.isArray(attempt.reason_codes) ? [...attempt.reason_codes] : []
          if (!codes.includes('policy_rejected')) codes.unshift('policy_rejected')
          return { ...attempt, reason_codes: codes }
        })
      : record.attempts
    out[testId] = { ...record, reason_codes: recordCodes, attempts }
  }
  return out
}

/**
 * Execute one explicit local self-check. Returns a JSON-safe summary; the full
 * authority record is persisted as `receipt/v1` (all receipts are local-only).
 *
 * @param {object} runSpec run-spec/v1
 * @param {{ profile?: string, receiptOutDir?: string, overwrite?: boolean,
 *   executionMode?: 'in-process'|'subprocess', timeoutMs?: number,
 *   runtimeAnchor?: object|string|null, cordisEntry?: string, env?: object,
 *   probeTime?: string, signal?: AbortSignal }} [opts]
 */
export async function runSelfCheck(runSpec, opts = {}) {
  const profile = nonEmptyString(opts.profile) ? opts.profile : 'local-selfcheck/v1'
  const receiptOut = nonEmptyString(opts.receiptOutDir) ? opts.receiptOutDir : '.dsh-testbed-receipts'
  const executionMode = opts.executionMode === 'subprocess' ? 'subprocess' : 'in-process'
  const timeoutMs = Number.isSafeInteger(opts.timeoutMs) && opts.timeoutMs > 0 ? opts.timeoutMs : 15_000
  const probeTime = typeof opts.probeTime === 'string' && Number.isFinite(Date.parse(opts.probeTime))
    ? new Date(Date.parse(opts.probeTime)).toISOString()
    : new Date().toISOString()
  const runId = freshRunId()
  const limitationSet = new Set([
    ...BASE_LIMITATIONS,
    executionMode === 'subprocess' ? 'l1-subprocess' : 'l0-in-process',
  ])
  if (executionMode === 'subprocess') {
    limitationSet.add(`unenforced: ${UNENFORCED_RESOURCES.join(',')}`)
  }

  const finish = (receipt, meta = {}) => {
    try {
      const validation = validateReceiptV1(receipt)
      if (!validation.ok) {
        throw new Error(`receipt-validation-failed:${(validation.errors ?? []).slice(0, 5).join(';')}`)
      }
      const persisted = persistReceipt(receipt, receiptOut, { overwrite: opts.overwrite ?? false })
      return {
        runId: receipt.run_id,
        planId: receipt.plan_id ?? null,
        gateDecision: receipt.gate_decision ?? null,
        gateReason: meta.gateReason ?? null,
        trustScope: receipt.trust_scope,
        marketEligible: receipt.market_eligible,
        exitCode: resolveExitCode({ kind: 'receipt', receipt }, profile),
        profileId: profile,
        receiptPath: persisted.path,
        recordDigest: persisted.recordDigest,
        reconciliation: receipt.reconciliation ?? null,
        limitations: [...limitationSet],
      }
    } catch (err) {
      return {
        runId,
        planId: null,
        gateDecision: null,
        gateReason: 'receipt-unavailable',
        trustScope: 'local-only',
        marketEligible: false,
        exitCode: resolveExitCode({ kind: 'write-failure' }, profile),
        profileId: profile,
        receiptPath: null,
        recordDigest: null,
        reconciliation: null,
        limitations: [...limitationSet],
        writeError: String(err?.message ?? err),
      }
    }
  }

  const receiptRefs = () => ({
    profileRef: receiptVersionRef(runSpec?.profile_ref),
    scenarioRef: receiptVersionRef(runSpec?.scenario_ref),
    targetRef: targetReference(runSpec?.target),
  })

  const baseProvenance = () => ({
    put_digest: null,
    dsh_commit: null,
    cordis_version: null,
    adapter_ref: executionMode === 'subprocess' ? ADAPTER_REF : 'in-process-l0@0.1.0',
    tool_refs: [],
    assertion_refs: [],
    policy_ref: receiptVersionRef(runSpec?.policy_ref),
    environment_fingerprint: null,
    node_version: process.version,
    os_platform: process.platform,
    os_arch: process.arch,
    worker_ref: executionMode === 'subprocess' ? 'worker/l1-subprocess@0.1.0' : 'worker/l0-in-process@0.1.0',
    isolation: executionMode === 'subprocess' ? ISOLATION_LABEL : 'L0-in-process',
    redaction_status: 'worker-redaction/v1',
  })

  const prePlanBlocked = (stage, reasonCodes, extra = {}) => finish(buildReceipt({
    shape: 'pre-plan-blocked',
    runId,
    ...receiptRefs(),
    provenance: baseProvenance(),
    planCandidateRef: extra.candidateRef ?? null,
    blockedStage: stage,
    reasonCodes: reasonCodes.length > 0 ? reasonCodes : [`blocked-at-${stage}`],
    limitations: [...limitationSet],
  }), { gateReason: reasonCodes[0] ?? stage })

  const prePlanCancelled = (stage, reasonCodes, extra = {}) => finish(buildReceipt({
    shape: 'pre-plan-cancelled',
    runId,
    ...receiptRefs(),
    provenance: baseProvenance(),
    planCandidateRef: extra.candidateRef ?? null,
    cancelledStage: stage,
    reasonCodes: reasonCodes.length > 0 ? reasonCodes : ['cancelled'],
    limitations: [...limitationSet],
  }), { gateReason: 'cancelled' })

  // -------------------------------------------------------------------------
  // 1. Intake: fail closed before any PUT/tool code is loaded.
  // -------------------------------------------------------------------------
  if (!runSpec || !isRunSpecVersion(runSpec.schema_version)) {
    return prePlanBlocked('intake', ['run-spec-version-unknown'])
  }
  const cases = runSpec?.scenario?.cases
  if (Array.isArray(cases) && cases.some((caseSpec) => caseSpec && Object.hasOwn(caseSpec, 'capability'))) {
    // Caller-supplied capability evidence is never authoritative. Reject it
    // before protocol validation so the stage/reason stay explicit.
    return prePlanBlocked('capability-admission', ['case-capability-untrusted'])
  }
  const specCheck = validateRunSpec(runSpec)
  if (!specCheck.ok) {
    return prePlanBlocked('intake', specCheck.errors)
  }
  const budgetResolution = resolveRunBudget(runSpec?.policy?.budget)
  if (!budgetResolution.ok) {
    return prePlanBlocked('budget-admission', budgetResolution.errors)
  }
  const budget = budgetResolution.budget
  if (!Array.isArray(cases) || cases.length === 0) {
    return prePlanBlocked('intake', ['missing-or-empty-scenario'])
  }

  // -------------------------------------------------------------------------
  // 2. Candidate + frozen policy baseline (before loading PUT).
  // -------------------------------------------------------------------------
  const gatePolicy = synthesizeGatePolicy(runSpec, cases)
  const policyCheck = validateGatePolicy(gatePolicy, { caseTestIds: cases.map((caseSpec) => caseSpec.test_id) })
  if (!policyCheck.ok) {
    return prePlanBlocked('policy-admission', policyCheck.errors)
  }
  const preapprovedWaivers = Array.isArray(runSpec?.policy?.preapproved_waivers)
    ? [...runSpec.policy.preapproved_waivers]
    : []
  const caseIds = new Set(cases.map((caseSpec) => caseSpec.test_id))
  const unknownWaivers = preapprovedWaivers.filter((id) => !caseIds.has(id))
  if (unknownWaivers.length > 0) {
    return prePlanBlocked('policy-admission', unknownWaivers.map((id) => `preapproved-waiver-unknown-test:${id}`))
  }

  const compiled = compilePlanCandidate(cases, { gatePolicy })
  if (!compiled.ok) {
    return prePlanBlocked('compile-plan-candidate', compiled.errors)
  }
  const candidateRef = candidateReference(compiled.candidate)
  const attemptFit = assertPlanAttemptsWithinBudget(planDeclaredAttempts(compiled.candidate.cases), budget)
  if (!attemptFit.ok) {
    return prePlanBlocked('budget-admission', attemptFit.errors, { candidateRef })
  }

  // -------------------------------------------------------------------------
  // 3. Pin PUT bytes and tool artifacts before any worker loads them.
  // -------------------------------------------------------------------------
  const pinPut = await pinPutEntry(cases, runSpec)
  if (!pinPut.ok) {
    return prePlanBlocked('target-admission', pinPut.errors, { candidateRef })
  }
  const pinnedTools = await pinToolBindings(cases, runSpec)
  if (!pinnedTools.ok) {
    return prePlanBlocked('tool-admission', pinnedTools.errors, { candidateRef })
  }
  const toolBindings = pinnedTools.bindings
  const hasToolCases = Object.keys(toolBindings).length > 0

  if (opts.signal?.aborted) {
    return prePlanCancelled('pre-freeze', ['cancelled'], { candidateRef })
  }

  // -------------------------------------------------------------------------
  // 4. Worker probe → control verification → freeze Plan.
  // -------------------------------------------------------------------------
  const runtime = await resolveKernelRuntime(opts)
  for (const limitation of runtime.limitations ?? []) limitationSet.add(limitation)

  const putForProbe = pinPut.putEntry === null
    ? null
    : {
        putEntry: pinPut.putEntry,
        putDigest: pinPut.putDigest,
        putConfig: firstPutConfig(cases),
      }
  let probeResult = { snapshot: null, records: null, failure: null, cleanupReport: null }
  if (executionMode === 'subprocess') {
    probeResult = await probeWorkerInL1({
      cases,
      put: putForProbe,
      runtime,
      runId,
      timeoutMs,
      probeTime,
      signal: opts.signal,
    })
    if (probeResult.failure !== null) limitationSet.add(probeResult.failure)
    const snapshotRuntime = isPlainRecord(probeResult.snapshot?.runtime) ? probeResult.snapshot.runtime : null
    if (snapshotRuntime && snapshotRuntime.status !== 'available') {
      limitationSet.add(`runtime-unavailable:${snapshotRuntime.reason ?? 'unknown'}`)
    }
    for (const limitation of probeResult.snapshot?.limitations ?? []) {
      if (typeof limitation === 'string') limitationSet.add(limitation)
    }
  }

  const probeContext = {
    put_digest: pinPut.putDigest,
    probe_version: CAPABILITY_PROBE_VERSION,
    probe_time: probeTime,
    environment_fingerprint: runtime.provenance?.environment_fingerprint ?? null,
  }
  const capabilityRecords = probeCapabilities(cases, {
    ...probeContext,
    snapshot: probeResult.snapshot ?? undefined,
  })
  if (probeResult.snapshot === null && executionMode === 'subprocess') {
    limitationSet.add('capability-probe-unavailable')
  }

  if (opts.signal?.aborted) {
    return prePlanCancelled('pre-freeze', ['cancelled'], { candidateRef })
  }

  const planContext = {
    put_digest: pinPut.putDigest,
    environment_fingerprint: runtime.provenance?.environment_fingerprint ?? null,
    probe_version: CAPABILITY_PROBE_VERSION,
  }
  const notApplicableCandidates = cases
    .filter((caseSpec) => isPlainRecord(caseSpec.not_applicable_when))
    .map((caseSpec) => caseSpec.test_id)

  let frozen
  try {
    frozen = freezePlan(compiled.candidate, {
      capabilitySnapshots: capabilityRecords,
      planContext,
      notApplicable: notApplicableCandidates,
      preapprovedWaivers,
      gatePolicy,
      budget,
    })
    const planCheck = verifyFrozenPlan(frozen)
    if (!planCheck.ok) throw new TypeError(`frozen-plan-invalid:${planCheck.errors[0] ?? 'unknown'}`)
  } catch (err) {
    return prePlanBlocked('plan-freeze', [`plan-freeze-failed:${String(err?.message ?? err).slice(0, 200)}`], { candidateRef })
  }

  // -------------------------------------------------------------------------
  // 5. Execute the frozen Plan through the dispatch port.
  // -------------------------------------------------------------------------
  const budgetLedger = createBudgetLedger(budget)
  const recordsByTestIdRaw = Object.create(null)
  let observations = []
  let adoptedAttempts = []
  let budgetExceeded = null
  let cancelled = false
  let executionFailure = null
  let executionAdapter = null
  let cleanup = null
  let cleanupFailure = null
  if (probeResult.cleanupReport !== null && !cleanupReportOk(probeResult.cleanupReport)) {
    cleanupFailure = { reason: 'cleanup-failed', report: probeResult.cleanupReport }
  } else if (typeof probeResult.failure === 'string' && probeResult.failure.startsWith('probe-reap-failed')) {
    cleanupFailure = { reason: 'cleanup-failed', report: null, error: probeResult.failure }
  }
  let abortHandler = null
  try {
    try {
      const toolSnapshotRefs = Object.create(null)
      for (const testId of Object.keys(toolBindings)) {
        toolSnapshotRefs[testId] = frozen.capabilitySnapshotRefs?.[testId]
      }
      executionAdapter = makeExecutionAdapter({
        executionMode,
        runId,
        timeoutMs,
        toolBindings,
        capabilitySnapshotRefs: toolSnapshotRefs,
        runtime,
      })
    } catch (err) {
      executionFailure = `execution-adapter-unavailable:${String(err?.message ?? err).slice(0, 160)}`
      limitationSet.add(executionFailure)
    }

    if (executionFailure === null) {
      if (executionAdapter !== null) {
        abortHandler = () => {
          try { executionAdapter.cancel?.() } catch { /* reap verifies the final state */ }
        }
        opts.signal?.addEventListener?.('abort', abortHandler, { once: true })
        if (opts.signal?.aborted) abortHandler()
      }

      const port = makeDispatchPort({
        adapter: executionAdapter,
        frozenPlan: frozen,
        mode: executionMode,
      })
      const result = await executeFrozenPlan(frozen, port, {
        runId,
        signal: opts.signal,
        budgetLedger,
        toolBindings: hasToolCases ? toolBindings : undefined,
        targetRef: targetReference(runSpec.target),
        timeoutMs,
      })
      Object.assign(recordsByTestIdRaw, normalizePolicyRejectedRecords(result.recordsByTestId))
      observations = result.observations
      adoptedAttempts = result.adoptedAttempts
      budgetExceeded = result.budget_exceeded
      cancelled = result.cancelled === true
    }
  } catch (err) {
    executionFailure = `execution-failed:${String(err?.message ?? err).slice(0, 200)}`
    limitationSet.add(executionFailure)
  } finally {
    opts.signal?.removeEventListener?.('abort', abortHandler)
    if (executionAdapter !== null) {
      try {
        const report = await executionAdapter.reap()
        if (!cleanupReportOk(report)) cleanupFailure = { reason: 'cleanup-failed', report }
        else if (cleanupFailure === null) cleanup = report
        if (cleanupFailure !== null) cleanup = cleanupFailure.report ?? cleanup
      } catch (err) {
        cleanupFailure = { reason: 'cleanup-failed', report: null, error: String(err?.message ?? err).slice(0, 200) }
        cleanup = null
      }
    }
  }

  // -------------------------------------------------------------------------
  // 6. Reconcile + aggregate; run-level vetoes stay fail-closed.
  // -------------------------------------------------------------------------
  let reconciliation
  try {
    reconciliation = adoptedAttempts.length > 0
      ? reconcileAdoptedAttempts(frozen, adoptedAttempts, [])
      : reconcile(frozen, Object.create(null), [])
  } catch (err) {
    return prePlanBlocked('reconcile', [`reconcile-failed:${String(err?.message ?? err).slice(0, 200)}`], { candidateRef })
  }
  let gate = aggregateGateDecision(frozen, reconciliation, recordsByTestIdRaw)
  if (budgetExceeded !== null) gate = { ...gate, gate_decision: 'blocked', reason: budgetExceeded }
  else if (cleanupFailure !== null) gate = { ...gate, gate_decision: 'blocked', reason: 'cleanup-failed' }
  else if (executionFailure !== null) gate = { ...gate, gate_decision: 'blocked', reason: 'execution-unavailable' }

  const runCancelled = cancelled || opts.signal?.aborted === true
  if (runCancelled) limitationSet.add('run-cancelled')

  const capabilityRefs = Object.values(frozen.capabilitySnapshotRefs ?? {})
  const provenance = {
    ...baseProvenance(),
    put_digest: pinPut.putDigest,
    ...runtimeProvenanceForReceipt(runtime, {
      workerRef: executionMode === 'subprocess' ? 'worker/l1-subprocess@0.1.0' : 'worker/l0-in-process@0.1.0',
      isolation: executionMode === 'subprocess' ? ISOLATION_LABEL : 'L0-in-process',
    }),
    adapter_ref: executionMode === 'subprocess' ? ADAPTER_REF : 'in-process-l0@0.1.0',
    tool_refs: pinnedTools.toolRefs,
    policy_ref: receiptVersionRef(runSpec?.policy_ref),
    capability_snapshot_ref: capabilityRefs.length === 1 ? capabilityRefs[0] : null,
    granted_permissions: executionAdapter?.launchRecord
      ? { grants: executionAdapter.launchRecord.grants }
      : null,
    launch_record: executionAdapter?.launchRecord ?? null,
    cleanup,
    cleanup_failure: cleanupFailure,
    run_budget: budget ?? DEFAULT_RUN_BUDGET,
    budget_actuals: budgetLedger.snapshot(),
  }

  const receipt = buildReceipt({
    shape: 'frozen',
    runId,
    ...receiptRefs(),
    provenance,
    planCandidateRef: candidateRef,
    planId: frozen.plan_id,
    planResolution: planResolutionEntries(frozen),
    reconciliation,
    testCases: Object.values(recordsByTestIdRaw),
    observations,
    artifacts: [],
    gateDecision: gate.gate_decision,
    runStatus: runCancelled ? 'cancelled' : 'completed',
    limitations: [...limitationSet],
  })
  return finish(receipt, { gateReason: gate.reason ?? null })
}

/** @param {unknown} report */
function cleanupReportOk(report) {
  return isPlainRecord(report) && report.pid_alive === false && report.temp_removed === true
}

/** @param {object[]} cases */
function firstPutConfig(cases) {
  for (const caseSpec of cases) {
    if (caseSpec?.probe?.op === 'load-put' && isPlainRecord(caseSpec.probe.put_config)) {
      return jsonSafe(caseSpec.probe.put_config)
    }
  }
  return {}
}

/** Build the post-freeze execution adapter (tool mode pins bindings + snapshot refs). */
function makeExecutionAdapter({ executionMode, runId, timeoutMs, toolBindings, capabilitySnapshotRefs, runtime }) {
  if (executionMode !== 'subprocess') return null
  const hasTools = Object.keys(toolBindings).length > 0
  const adapter = makeSubprocessAdapter({
    workerEntry: WORKER_ENTRY,
    runId,
    timeoutMs,
    toolBindings: hasTools ? toolBindings : undefined,
    capabilitySnapshotRefs: hasTools ? capabilitySnapshotRefs : undefined,
    runtimeAnchor: serializeRuntimeAnchor(runtime?.anchor),
  })
  adapter.start()
  return adapter
}
