/**
 * worker host 入口 —— 真实 L1 子进程（标准 Node ESM；仅 import `node:*` 与 `../protocol/*`、`./*`）。
 *
 * ⚠️ 隔离定位（如实标注）：
 * - **L1 子进程 = 普通同权限进程**：只隔离崩溃/堆/生命周期，**不是安全边界**；
 *   filesystem / network / subprocess / devices / cpu / memory 一律 `unenforced`。
 * - 内建 op：`echo` / `error` / `sleep` / `env-audit`（传输与生命周期验收）、
 *   `load-put`（用真实 Cordis 装载 fixture PUT）、`probe-capabilities`
 *   （两阶段能力探测：环境预检 → 装载 PUT/读声明/实测）。
 * - Cordis 入口**不硬编码**：由 CLI `--runtime-anchor`、`DSH_TESTBED_RUNTIME_ANCHOR` /
 *   `DSH_TESTBED_CORDIS_ENTRY`、或已解析的安装包注入/解析；真实运行时可解析时
 *   观测结果标 `real-cordis`，注入的非锁定运行时标 `injected-runtime`。
 *   真实 Cordis 不可用 → 明确 `error`/`cordis-runtime-unavailable`（load-put）或
 *   快照 `runtime.status='unavailable'` + `observed='unknown'`（探测），绝不伪造 pass。
 * - worker 启动即清理环境：只保留系统 allowlist 键，控制面凭据/签名密钥/ambient
 *   credentials 不进入 worker；工具子进程只收到最小环境。
 *
 * 帧协议（control-protocol/v1，NDJSON，每行一个 JSON）：
 * - 收：`request` 帧（protocol_version + request_id/run_id/plan_id/test_id/attempt + input）；
 *   以及闭集 `test-tool/v1` ToolRequest（工具模式）。
 * - 发：内建合法 request 先 `started`，manifest request 仅在子进程真实 spawn 后发通知。
 *       `started` 只回显 correlation tuple，**无权威时间戳、不是独立可信启动证据**；
 *       adapter 侧另有独立见证，未接入时 invocation_status 保持 unknown。
 * - 所有帧写 stdout（一行一个 JSON）；诊断一律 `console.error` 到 stderr，stdout 零杂音。
 *
 * @module @deepseek-ai/dsh-plugin-testbed/worker/host
 */

import { createInterface } from 'node:readline'
import { readFile, stat } from 'node:fs/promises'
import { isAbsolute, relative, resolve, sep, win32 } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { CONTROL_PROTOCOL_VERSION, MAX_FRAME_BYTES, assertFrameShape, assertToolRequest, assertToolResponse } from '../protocol/transport.js'
import { EXECUTION_STATUS, TEST_TOOL_PROTOCOL_VERSION } from '../protocol/enums.js'
import { validateToolManifest } from '../protocol/tool-manifest.js'
import { runToolRequest } from './runner.js'
import { createWorkerLifecycle, installSignalHandlers } from './boundary.js'
import { captureRuntimeEnvironment, scrubAmbientEnvironment } from './environment.js'
import { boundObservationValue, isPlainRecord, sanitizeError } from './observe.js'
import { probeWorkerCapabilities } from './probe.js'
import {
  MAX_RUNTIME_ENTRY_BYTES,
  makeRuntimeAnchor,
  resolveRuntimeAnchor,
} from './runtime.js'

// 执行级 reason code（CONTRACT-m2 §2 逐字）；不属于传输级 TRANSPORT_REASON_CODES。
const REASON_WORKER_ERROR = 'worker-error'
const REASON_CORDIS_UNAVAILABLE = 'cordis-runtime-unavailable'
const REASON_PUT_ENTRY_INVALID = 'put-entry-invalid'
const REASON_PROBE_INVALID = 'capability-probe-invalid'
const REASON_PROBE_FAILED = 'capability-probe-failed'
const WORKER_CONTEXT_VERSION = 'worker-context/v1'
const CAPABILITY_REF_RE = /^cap-sha256:[0-9a-f]{64}$/
const SHA256_RE = /^sha256:[0-9a-f]{64}$/
const TOOL_REF_KEYS = ['tool_id', 'version', 'artifact_digest']
const CONTEXT_BINDING_KEYS = ['manifest', 'artifactPath', 'workspaceRoot', 'toolRef']
const MAX_PUT_CONFIG_BYTES = 64 * 1024
const BUILTIN_OPS = ['echo', 'error', 'sleep', 'load-put', 'env-audit', 'probe-capabilities']

function plainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

function sameToolRef(left, right) {
  return plainRecord(left) && plainRecord(right) && TOOL_REF_KEYS.every((key) => left[key] === right[key]) &&
    Object.keys(left).length === TOOL_REF_KEYS.length && Object.keys(right).length === TOOL_REF_KEYS.length
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  Object.freeze(value)
  for (const child of Object.values(value)) deepFreeze(child)
  return value
}

function validateWorkerContext(value) {
  if (!plainRecord(value) || value.schema_version !== WORKER_CONTEXT_VERSION ||
      !plainRecord(value.bindings) || !plainRecord(value.capability_snapshot_refs) ||
      Object.keys(value.bindings).length === 0 ||
      Object.keys(value.bindings).length !== Object.keys(value.capability_snapshot_refs).length ||
      Object.keys(value).some((key) => !['schema_version', 'bindings', 'capability_snapshot_refs'].includes(key))) {
    throw new Error('invalid worker context')
  }
  const bindings = Object.create(null)
  const refs = Object.create(null)
  for (const testId of Object.keys(value.bindings)) {
    if (!testId || ['__proto__', 'constructor', 'prototype'].includes(testId)) throw new Error('invalid worker context test_id')
    const binding = value.bindings[testId]
    if (!plainRecord(binding) || Object.keys(binding).length !== CONTEXT_BINDING_KEYS.length ||
        CONTEXT_BINDING_KEYS.some((key) => !Object.hasOwn(binding, key)) ||
        typeof binding.artifactPath !== 'string' || typeof binding.workspaceRoot !== 'string' ||
        !plainRecord(binding.manifest) || !plainRecord(binding.toolRef) ||
        !sameToolRef(binding.toolRef, { tool_id: binding.manifest.tool_id, version: binding.manifest.tool_version, artifact_digest: binding.manifest.artifact_digest }) ||
        !SHA256_RE.test(binding.toolRef.artifact_digest) || !validateToolManifest(binding.manifest).ok) {
      throw new Error(`invalid worker context binding: ${testId}`)
    }
    if (!(/^(?:[A-Za-z]:[\\/]|\\\\|\/)/.test(binding.artifactPath)) ||
        !(/^(?:[A-Za-z]:[\\/]|\\\\|\/)/.test(binding.workspaceRoot))) throw new Error(`invalid worker context path: ${testId}`)
    const rootPath = resolve(binding.workspaceRoot)
    const artifactPath = resolve(binding.artifactPath)
    const artifactRel = relative(rootPath, artifactPath)
    if (!artifactRel || artifactRel === '.' || artifactRel === '..' || artifactRel.startsWith(`..${sep}`) ||
        isAbsolute(artifactRel) || win32.isAbsolute(artifactRel)) throw new Error(`artifact path escapes workspace root: ${testId}`)
    const capRef = value.capability_snapshot_refs[testId]
    if (typeof capRef !== 'string' || !CAPABILITY_REF_RE.test(capRef)) throw new Error(`invalid worker context capability ref: ${testId}`)
    bindings[testId] = binding
    refs[testId] = capRef
  }
  return deepFreeze({ schema_version: WORKER_CONTEXT_VERSION, bindings, capability_snapshot_refs: refs })
}

/**
 * Parse host arguments. `--worker-context` is the M5 launcher contract and stays
 * stable; `--runtime-anchor` is an optional locked-runtime injection. Each flag
 * may appear at most once; unknown/duplicate arguments fail closed.
 * @param {string[]} argv
 */
export function parseWorkerArgs(argv) {
  const options = { contextPath: null, runtimeAnchor: null }
  if (!Array.isArray(argv)) throw new Error('invalid worker host arguments')
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index]
    const value = argv[index + 1]
    if (typeof flag !== 'string' || typeof value !== 'string' || value.length === 0) {
      throw new Error('invalid worker host arguments')
    }
    if (flag === '--worker-context' && options.contextPath === null) options.contextPath = value
    else if (flag === '--runtime-anchor' && options.runtimeAnchor === null) options.runtimeAnchor = value
    else throw new Error('invalid worker host arguments')
  }
  return options
}

async function loadWorkerContext(contextPath) {
  if (contextPath === null || contextPath === undefined) return null
  if (typeof contextPath !== 'string' || !contextPath) throw new Error('invalid worker context path')
  const fileStat = await stat(contextPath)
  if (!fileStat.isFile() || fileStat.size > MAX_FRAME_BYTES) throw new Error('worker context exceeds size limit')
  const source = await readFile(contextPath, 'utf8')
  if (Buffer.byteLength(source, 'utf8') > MAX_FRAME_BYTES) throw new Error('worker context exceeds size limit')
  const raw = JSON.parse(source)
  return validateWorkerContext(raw)
}

// fiber.state 是 const enum，运行时无数值→名对象，须自备映射（CONTRACT-m3 §0 实测锚定）：
//   PENDING=0 LOADING=1 ACTIVE=2 FAILED=3 DISPOSED=4 UNLOADING=5
const FIBER_STATES = ['PENDING', 'LOADING', 'ACTIVE', 'FAILED', 'DISPOSED', 'UNLOADING']
const fiberStateName = (value) => (Number.isInteger(value) && FIBER_STATES[value]) || 'UNKNOWN'

// 开发期不变量：本 host 产出的 execution_status 必须落在协议闭集内，防词汇漂移。
for (const status of ['completed', 'error']) {
  if (!EXECUTION_STATUS.includes(status)) {
    throw new Error(`worker/host: execution_status "${status}" outside protocol closed set`)
  }
}

/** 写一行 JSON 到 stdout 并 await flush（保证 `process.exit(0)` 前不丢帧）。 */
function send(frame) {
  return new Promise((resolvePromise) => {
    process.stdout.write(JSON.stringify(frame) + '\n', (err) => {
      if (err) console.error(`[worker/host] stdout write failed: ${err?.message ?? err}`)
      resolvePromise()
    })
  })
}

/** 从帧提取 correlation tuple（缺失字段为 null；合法 request 帧必全有）。 */
function correlationOf(frame) {
  return {
    request_id: frame?.request_id ?? null,
    run_id: frame?.run_id ?? null,
    plan_id: frame?.plan_id ?? null,
    test_id: frame?.test_id ?? null,
    attempt: frame?.attempt ?? null,
    tool_ref: frame?.tool_ref ?? null,
  }
}

/** `started` 仅回显 correlation + tool_ref；**绝不携带时间戳或权威状态**。 */
function startedFrame(corr, toolRef) {
  const frame = { protocol_version: CONTROL_PROTOCOL_VERSION, kind: 'started', ...corr }
  if (toolRef !== undefined) frame.tool_ref = toolRef
  return frame
}

function responseFrame(corr, execution_status, observations, reason_codes) {
  return {
    protocol_version: CONTROL_PROTOCOL_VERSION,
    kind: 'response',
    ...corr,
    execution_status,
    observations,
    reason_codes,
  }
}

function boundedObservation(observationId, rawValue, limitations, options = {}) {
  const bounded = boundObservationValue(rawValue, { maxBytes: options.maxBytes ?? 512 * 1024, maxDepth: 8 })
  return {
    observation_id: observationId,
    value: bounded.value,
    source: 'worker',
    limitations: [...new Set([...limitations, ...bounded.limitations])].slice(0, 32),
  }
}

/** Best-effort, bounded dispose so a hung load cannot pin the worker forever. */
async function disposeWithTimeout(fiber, timeoutMs = 2000) {
  if (!fiber || typeof fiber.dispose !== 'function') return
  let timer = null
  await Promise.race([
    Promise.resolve().then(() => fiber.dispose()).catch(() => {}),
    new Promise((resolvePromise) => { timer = setTimeout(resolvePromise, timeoutMs) }),
  ])
  if (timer) clearTimeout(timer)
}

/**
 * Resolve the locked runtime for one operation.
 * Explicit request fields win; otherwise the launcher injection (CLI env) is used.
 */
async function resolveRuntimeFor(input, runtimeInjection) {
  if (typeof input?.cordis_entry === 'string' && input.cordis_entry.length > 0) {
    return resolveRuntimeAnchor({
      injection: makeRuntimeAnchor({
        cordis_entry: input.cordis_entry,
        cordis_version: typeof input.cordis_version === 'string' ? input.cordis_version : null,
        dsh_commit: typeof input.dsh_commit === 'string' ? input.dsh_commit : null,
        runtime_kind: typeof input.runtime_kind === 'string' ? input.runtime_kind : 'locked-runtime',
      }),
      env: {},
    })
  }
  const injection = input?.runtime_anchor ?? input?.runtime ?? runtimeInjection
  return resolveRuntimeAnchor({ injection: injection ?? null, env: process.env })
}

function runtimeLimitations(runtime) {
  const limitations = ['l1-subprocess']
  if (runtime.status === 'available') {
    limitations.push(runtime.anchor?.runtime_kind === 'locked-runtime' && runtime.provenance?.cordis_version_verified
      ? 'real-cordis'
      : 'injected-runtime')
    limitations.push(...(runtime.limitations ?? []))
  } else {
    limitations.push(REASON_CORDIS_UNAVAILABLE)
  }
  return [...new Set(limitations)]
}

function normalizeEntryPath(entry) {
  if (typeof entry !== 'string' || entry.length === 0 || entry.includes('\0')) return null
  if (entry.startsWith('file:')) {
    try { return resolve(fileURLToPath(entry)) } catch { return null }
  }
  if (isAbsolute(entry) || win32.isAbsolute(entry) || entry.startsWith('/')) return resolve(entry)
  return null
}

/**
 * 执行 `load-put`：用真实（或被显式注入的）Cordis 装载 PUT，产出可核验 observation。
 * failing PUT 仍是 `completed`（FAILED 是待断言观测值）；只有运行时不可用 / PUT 入口
 * 非法 / import 失败 / 非法 put 形状才 `error`。
 */
async function handleLoadPut(corr, input, runtimeInjection) {
  const runtime = await resolveRuntimeFor(input, runtimeInjection)
  if (runtime.status !== 'available' || !runtime.anchor?.cordis_entry) {
    return responseFrame(corr, 'error', [], [REASON_CORDIS_UNAVAILABLE])
  }

  const putEntryPath = normalizeEntryPath(input?.put_entry)
  if (putEntryPath === null) return responseFrame(corr, 'error', [], [REASON_PUT_ENTRY_INVALID])
  let putBytes
  try {
    const info = await stat(putEntryPath)
    if (!info.isFile() || info.size > MAX_RUNTIME_ENTRY_BYTES) throw new Error('put-entry-invalid')
    putBytes = await readFile(putEntryPath)
  } catch {
    return responseFrame(corr, 'error', [], [REASON_PUT_ENTRY_INVALID])
  }
  if (putBytes.byteLength > MAX_RUNTIME_ENTRY_BYTES) {
    return responseFrame(corr, 'error', [], [REASON_PUT_ENTRY_INVALID])
  }

  const putConfig = plainRecord(input?.put_config) ? input.put_config : {}
  let configBytes = Infinity
  try { configBytes = Buffer.byteLength(JSON.stringify(putConfig), 'utf8') } catch { /* non-JSON */ }
  if (configBytes > MAX_PUT_CONFIG_BYTES) {
    return responseFrame(corr, 'error', [], [REASON_PUT_ENTRY_INVALID])
  }

  let Context
  try {
    const cordis = await import(runtime.anchor.cordis_entry)
    Context = cordis.Context
  } catch (error) {
    console.error(`[worker/host] load-put: import(cordis_entry) failed: ${sanitizeError(error).message}`)
    return responseFrame(corr, 'error', [], [REASON_WORKER_ERROR])
  }
  if (typeof Context !== 'function') {
    return responseFrame(corr, 'error', [], [REASON_CORDIS_UNAVAILABLE])
  }

  let mod
  try {
    mod = await import(pathToFileURL(putEntryPath).href)
  } catch (error) {
    console.error(`[worker/host] load-put: import(put_entry) failed: ${sanitizeError(error).message}`)
    return responseFrame(corr, 'error', [], [REASON_WORKER_ERROR])
  }
  const put = mod?.default ?? mod?.put ?? mod

  const transitions = []
  let root = null
  let fiber = null
  let listener = null
  let stateAfterPlugin = null
  let stateAfterLoad = null
  let stateAfterDispose = null
  let effectsCount = 0
  let loadError = null
  let loadPhase = null
  try {
    try {
      root = new Context()
      if (typeof root.on === 'function') {
        listener = (target, oldState) => {
          if (transitions.length >= 32) return
          transitions.push({ from: fiberStateName(oldState), to: fiberStateName(target?.state) })
        }
        try { root.on('internal/status', listener) } catch { listener = null }
      }
      fiber = root.plugin(put, putConfig)
    } catch (error) {
      console.error(`[worker/host] load-put: root.plugin() failed: ${sanitizeError(error).message}`)
      return responseFrame(corr, 'error', [], [REASON_WORKER_ERROR])
    }
    stateAfterPlugin = fiberStateName(fiber?.state)

    // await fiber 结算加载；apply 抛错则 reject，把消息存为 error（FAILED 是待断言观测值）。
    try {
      await fiber
    } catch (error) {
      loadPhase = 'host-apply'
      loadError = sanitizeError(error, { phase: 'host-apply' }).message
    }
  } finally {
    stateAfterLoad = fiberStateName(fiber?.state)
    if (fiber && typeof fiber.getEffects === 'function') {
      try { effectsCount = fiber.getEffects().length } catch { effectsCount = 0 }
    }
    if (fiber && typeof fiber.dispose === 'function') {
      await disposeWithTimeout(fiber, 2000)
    }
    stateAfterDispose = fiberStateName(fiber?.state)
    if (listener && root && typeof root.off === 'function') {
      try { root.off('internal/status', listener) } catch { /* best effort */ }
    }
    if (root && typeof root.dispose === 'function') {
      await disposeWithTimeout(root, 2000)
    }
  }

  const value = {
    state_after_plugin: stateAfterPlugin,
    state_after_load: stateAfterLoad,
    effects_count: effectsCount,
    state_after_dispose: stateAfterDispose,
    transitions,
    load_phase: loadPhase,
    error: loadError,
    put_state: mod?.state ?? null,
    runtime: {
      status: runtime.status,
      source: runtime.provenance.source,
      runtime_kind: runtime.provenance.runtime_kind,
      cordis_version: runtime.provenance.cordis_version,
      cordis_version_verified: runtime.provenance.cordis_version_verified,
      dsh_commit: runtime.provenance.dsh_commit,
    },
  }
  return responseFrame(corr, 'completed', [
    boundedObservation('obs-1', value, runtimeLimitations(runtime)),
  ], [])
}

/** Validate + compact probe request payload; control owns the full case semantics. */
function compactProbeInput(input) {
  const probe = input?.probe
  if (!plainRecord(probe) || !Array.isArray(probe.cases)) return null
  if (probe.cases.length > 256) return null
  const cases = []
  for (const caseSpec of probe.cases) {
    if (!plainRecord(caseSpec) || typeof caseSpec.test_id !== 'string' || caseSpec.test_id.length === 0) return null
    const compact = { test_id: caseSpec.test_id }
    if (plainRecord(caseSpec.probe) && typeof caseSpec.probe.op === 'string') compact.probe = { op: caseSpec.probe.op }
    if (plainRecord(caseSpec.tool) && plainRecord(caseSpec.tool.manifest) && Array.isArray(caseSpec.tool.manifest.requires)) {
      compact.tool = { manifest: { requires: caseSpec.tool.manifest.requires.filter((item) => typeof item === 'string').slice(0, 64) } }
    }
    cases.push(compact)
  }
  const put = plainRecord(probe.put)
    ? {
        entry: typeof probe.put.entry === 'string' ? probe.put.entry : null,
        digest: typeof probe.put.digest === 'string' ? probe.put.digest : null,
        config: plainRecord(probe.put.config) ? probe.put.config : {},
      }
    : null
  return {
    cases,
    put,
    runtimeAnchor: probe.runtime_anchor ?? probe.runtime ?? null,
    probeTime: typeof probe.probe_time === 'string' ? probe.probe_time : undefined,
    putTimeoutMs: Number.isSafeInteger(probe.put_timeout_ms) ? probe.put_timeout_ms : undefined,
  }
}

/** `probe-capabilities`：worker 内两阶段探测，快照经 observations[].value 回传。 */
async function handleCapabilityProbe(corr, input, runtimeInjection, envState, signal) {
  const compact = compactProbeInput(input)
  if (compact === null) return responseFrame(corr, 'error', [], [REASON_PROBE_INVALID])
  let result
  try {
    result = await probeWorkerCapabilities({
      cases: compact.cases,
      put: compact.put,
      runtime: compact.runtimeAnchor ?? runtimeInjection,
      env: process.env,
      environmentAudit: envState.envAudit,
      probe_time: compact.probeTime,
      putTimeoutMs: compact.putTimeoutMs,
      signal,
    })
  } catch (error) {
    console.error(`[worker/host] probe-capabilities failed: ${sanitizeError(error).message}`)
    return responseFrame(corr, 'error', [], [REASON_PROBE_FAILED])
  }
  if (!result.ok) return responseFrame(corr, 'error', [], [REASON_PROBE_INVALID])

  const snapshot = result.snapshot
  const reasonCodes = snapshot.runtime.status === 'available' ? [] : [REASON_CORDIS_UNAVAILABLE]
  const observation = boundedObservation('obs-capability-probe', snapshot, snapshot.limitations, { maxBytes: 900 * 1024 })
  return responseFrame(corr, 'completed', [observation], reasonCodes)
}

/** `env-audit`：只回传环境键名/计数，绝不回传环境值。 */
function handleEnvAudit(corr, envState) {
  const audit = envState.envAudit
  return responseFrame(corr, 'completed', [boundedObservation('obs-env-audit', {
    schema_version: 'worker-env-audit/v1',
    isolation: 'L1-subprocess',
    removed_env_name_count: audit.removed_count,
    credential_name_count: audit.credential_name_count,
    ambient_credentials_observed: audit.ambient_credentials_observed,
    kept_env_names: audit.kept_names,
    process_env_key_count: Object.keys(process.env).length,
  }, ['l1-subprocess', 'env-values-never-reported'])], [])
}

function toolResponseError(request, reason) {
  return {
    protocol_version: TEST_TOOL_PROTOCOL_VERSION,
    request_id: request.request_id,
    run_id: request.run_id,
    plan_id: request.plan_id,
    test_id: request.test_id,
    attempt: request.attempt,
    tool_ref: request.tool_ref,
    execution_status: 'error',
    observations: [],
    artifact_refs: [],
    diagnostics: [reason],
  }
}

async function handleToolRequest(frame, context, signal) {
  const shape = assertToolRequest(frame)
  if (!shape.ok) {
    console.error(`[worker/host] dropped invalid test-tool request: ${shape.reason_code}`)
    return
  }
  const binding = context && Object.hasOwn(context.bindings, frame.test_id) ? context.bindings[frame.test_id] : undefined
  const expectedCapabilitySnapshotRef = context && Object.hasOwn(context.capability_snapshot_refs, frame.test_id)
    ? context.capability_snapshot_refs[frame.test_id]
    : undefined
  let startedSent = false
  const emitStarted = async () => {
    if (startedSent) return
    const started = startedFrame(correlationOf(frame), frame.tool_ref)
    const checked = assertFrameShape(started)
    if (!checked.ok) throw new Error('invalid test-tool started frame')
    startedSent = true
    await send(started)
  }
  let response
  try {
    response = await runToolRequest({
      request: frame,
      binding,
      expectedCapabilitySnapshotRef,
      signal,
      onStarted: emitStarted,
    })
  } catch (err) {
    console.error(`[worker/host] tool runner failed: ${sanitizeError(err).message}`)
    response = toolResponseError(frame, 'tool-runner-error')
  }
  const responseCheck = assertToolResponse(response, frame)
  if (!responseCheck.ok) response = toolResponseError(frame, responseCheck.reason_code)
  await send(response)
}

function delay(ms, signal) {
  if (!(ms > 0)) return Promise.resolve()
  return new Promise((resolvePromise) => {
    if (signal?.aborted) return resolvePromise()
    const timer = setTimeout(done, ms)
    function done() {
      clearTimeout(timer)
      signal?.removeEventListener('abort', done)
      resolvePromise()
    }
    signal?.addEventListener('abort', done, { once: true })
  })
}

/** Process one NDJSON line; dispatch both protocols without mutating either envelope. */
async function handleLine(line, envState) {
  if (Buffer.byteLength(line, 'utf8') > MAX_FRAME_BYTES) {
    console.error('[worker/host] dropped oversized stdin line')
    return
  }
  let frame
  try {
    frame = JSON.parse(line)
  } catch (err) {
    // 非 JSON 行：不写 stdout（保持零杂音），诊断到 stderr，继续下一行。
    console.error(`[worker/host] dropped non-JSON stdin line: ${err?.message ?? err}`)
    return
  }

  const begun = envState.lifecycle.beginOp(
    frame?.protocol_version === TEST_TOOL_PROTOCOL_VERSION ? 'tool-request' : `control:${frame?.input?.op ?? 'echo'}`,
  )
  if (!begun.ok) {
    console.error(`[worker/host] rejected frame while ${begun.reason}`)
    return
  }
  const signal = begun.handle.signal
  try {
    if (frame?.protocol_version === TEST_TOOL_PROTOCOL_VERSION) {
      await handleToolRequest(frame, envState.context, signal)
      return
    }

    const shape = assertFrameShape(frame)
    if (!shape.ok) {
      // 非法帧（未知版本 / 缺 correlation 字段 / 未知字段）→ error response 后继续读。
      await send(responseFrame(correlationOf(frame), 'error', [], [shape.reason_code]))
      return
    }

    // 合法 request 帧 → 先 emit started（worker 侧通知；不是独立启动证据）。
    const corr = correlationOf(frame)
    await send(startedFrame(corr))

    const input = plainRecord(frame.input) ? frame.input : {}
    const op = typeof input.op === 'string' && input.op.length > 0 ? input.op : 'echo'

    if (op === 'error') {
      await send(responseFrame(corr, 'error', [], [REASON_WORKER_ERROR]))
      return
    }

    if (op === 'load-put') {
      await send(await handleLoadPut(corr, input, envState.runtimeInjection))
      return
    }

    if (op === 'probe-capabilities') {
      await send(await handleCapabilityProbe(corr, input, envState.runtimeInjection, envState, signal))
      return
    }

    if (op === 'env-audit') {
      await send(handleEnvAudit(corr, envState))
      return
    }

    if (!BUILTIN_OPS.includes(op)) {
      await send(responseFrame(corr, 'error', [], [REASON_WORKER_ERROR]))
      return
    }

    // op ∈ { 'echo'（缺省）, 'sleep' }：await delay_ms 后按 echo 回传 value（原样透传）。
    const delayMs = Math.max(0, Math.min(300_000, Number(input.delay_ms) || 0))
    await delay(delayMs, signal)
    if (signal.aborted) {
      await send(responseFrame(corr, 'error', [], ['worker-cancelled']))
      return
    }
    const echoObservation = boundedObservation('obs-1', input.value, ['l1-subprocess'], { maxBytes: 512 * 1024 })
    await send(responseFrame(corr, 'completed', [echoObservation], []))
  } catch (error) {
    console.error(`[worker/host] unhandled frame error: ${sanitizeError(error).message}`)
  } finally {
    begun.handle.end()
  }
}

/** Runtime injection from `--runtime-anchor` or the launcher environment. */
function runtimeInjectionFrom(options, envState) {
  if (options.runtimeAnchor !== null) return options.runtimeAnchor
  const captured = envState.capturedRuntime
  if (captured.runtime_anchor) return captured.runtime_anchor
  if (captured.cordis_entry) {
    return makeRuntimeAnchor({
      cordis_entry: captured.cordis_entry,
      cordis_version: captured.cordis_version ?? null,
      dsh_commit: captured.dsh_commit ?? null,
      runtime_kind: captured.runtime_kind ?? 'locked-runtime',
    })
  }
  return null
}

async function main() {
  const options = parseWorkerArgs(process.argv.slice(2))
  // Capture runtime configuration *before* scrubbing ambient environment; the
  // captured values are paths/versions only, never credentials.
  const capturedRuntime = captureRuntimeEnvironment(process.env)
  const envAudit = scrubAmbientEnvironment(process.env)
  const context = await loadWorkerContext(options.contextPath)

  const lifecycle = createWorkerLifecycle({ onShutdown: async () => { /* probes dispose their own fibers */ } })
  lifecycle.markReady()
  const uninstallSignals = installSignalHandlers(lifecycle, { exit: (code) => process.exit(code) })
  const envState = {
    context,
    lifecycle,
    envAudit,
    capturedRuntime,
    runtimeInjection: runtimeInjectionFrom(options, { capturedRuntime }),
  }

  const rl = createInterface({ input: process.stdin })
  try {
    for await (const line of rl) {
      try {
        await handleLine(line, envState)
      } catch (err) {
        // 单个帧处理异常不拖垮 worker；诊断到 stderr，继续下一帧。
        console.error(`[worker/host] unhandled frame error: ${sanitizeError(err).message}`)
      }
    }
  } finally {
    uninstallSignals()
    await lifecycle.shutdown('stdin-end')
    // stdin 'close' → 处理完全部帧后正常退出（exit 0）。
    process.exit(0)
  }
}

await main()
