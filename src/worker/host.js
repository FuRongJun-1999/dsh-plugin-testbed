/**
 * worker host 入口 —— 真实 L1 子进程（标准 Node ESM；仅 import `node:*` 与 `../protocol/*`）。
 *
 * ⚠️ 隔离定位（如实标注）：
 * - 这是 **L1 子进程内建 smoke 能力**：内建 op = `echo` / `error` / `sleep`（传输与生命周期
 *   验收）+ `load-put`（M3：用真实 Cordis 装载 fixture PUT，产出加载/卸载 observation）。
 * - `L1-subprocess` = 普通同权限子进程，仅隔离崩溃/堆/生命周期，**不是安全边界**；
 *   filesystem / network / subprocess / devices / cpu / memory 均无法由 OS 强制 → 一律 `unenforced`。
 * - `load-put` 用真实 Cordis（`import(cordis_entry)` 取 `Context`）在**本进程内**装载 PUT，
 *   属进程内行为隔离；**不使用 `node:vm`**。failing PUT 仍回 `completed`（FAILED 是待断言观测值）。
 *
 * 帧协议（control-protocol/v1，NDJSON，每行一个 JSON）：
 * - 收：`request` 帧（protocol_version + request_id/run_id/plan_id/test_id/attempt + input）。
 * - 发：内建合法 request 先 `started`，manifest request 仅在预检通过且子进程启动后发通知。
 *       `started` 仅回显 correlation tuple，**不是独立可信的启动证据**；没有另行接入的
 *       可信控制源时 invocation_status 保持 unknown、invocation_evidence_verified 保持 false。
 * - 所有帧写 stdout（一行一个 JSON；同一字节等价于 `console.log(JSON.stringify(frame))`，
 *   改用带 flush 回调的 `process.stdout.write` 是为了退出前不截断）；诊断一律
 *   `console.error` 到 stderr，stdout 绝无非 JSON 杂音。
 *
 * @module @deepseek-ai/dsh-plugin-testbed/worker/host
 */

import { createInterface } from 'node:readline'
import { readFile, stat } from 'node:fs/promises'
import { isAbsolute, relative, resolve, sep, win32 } from 'node:path'
import { CONTROL_PROTOCOL_VERSION, MAX_FRAME_BYTES, assertFrameShape, assertToolRequest, assertToolResponse } from '../protocol/transport.js'
import { EXECUTION_STATUS, TEST_TOOL_PROTOCOL_VERSION } from '../protocol/enums.js'
import { validateToolManifest } from '../protocol/tool-manifest.js'
import { runToolRequest } from './runner.js'

// 执行级 reason code（CONTRACT-m2 §2 逐字）；不属于传输级 TRANSPORT_REASON_CODES。
const REASON_WORKER_ERROR = 'worker-error'
const WORKER_CONTEXT_VERSION = 'worker-context/v1'
const CAPABILITY_REF_RE = /^cap-sha256:[0-9a-f]{64}$/
const SHA256_RE = /^sha256:[0-9a-f]{64}$/
const TOOL_REF_KEYS = ['tool_id', 'version', 'artifact_digest']
const CONTEXT_BINDING_KEYS = ['manifest', 'artifactPath', 'workspaceRoot', 'toolRef']

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

async function loadWorkerContext() {
  const args = process.argv.slice(2)
  if (args.length === 0) return null
  if (args.length !== 2 || args[0] !== '--worker-context') throw new Error('invalid worker host arguments')
  const path = args[1]
  if (typeof path !== 'string' || !path) throw new Error('invalid worker context path')
  const fileStat = await stat(path)
  if (!fileStat.isFile() || fileStat.size > MAX_FRAME_BYTES) throw new Error('worker context exceeds size limit')
  const source = await readFile(path, 'utf8')
  if (Buffer.byteLength(source, 'utf8') > MAX_FRAME_BYTES) throw new Error('worker context exceeds size limit')
  const raw = JSON.parse(source)
  return validateWorkerContext(raw)
}

// fiber.state 是 const enum，运行时无数值→名对象，须自备映射（CONTRACT-m3 §0 实测锚定）：
//   PENDING=0 LOADING=1 ACTIVE=2 FAILED=3 DISPOSED=4 UNLOADING=5
const FIBER_STATES = ['PENDING', 'LOADING', 'ACTIVE', 'FAILED', 'DISPOSED', 'UNLOADING']

// 开发期不变量：本 host 产出的 execution_status 必须落在协议闭集内，防词汇漂移。
for (const status of ['completed', 'error']) {
  if (!EXECUTION_STATUS.includes(status)) {
    throw new Error(`worker/host: execution_status "${status}" outside protocol closed set`)
  }
}

/** 写一行 JSON 到 stdout 并 await flush（保证 `process.exit(0)` 前不丢帧）。 */
function send(frame) {
  return new Promise((resolve) => {
    process.stdout.write(JSON.stringify(frame) + '\n', (err) => {
      if (err) console.error(`[worker/host] stdout write failed: ${err?.message ?? err}`)
      resolve()
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

/**
 * 执行 `load-put`：用真实 Cordis 装载 PUT，产出可核验 observation。
 * 返回 response 帧对象（failing PUT 仍是 `completed`；只有 import 失败 / 非法 put 形状才 `error`）。
 */
async function handleLoadPut(corr, input) {
  let Context
  try {
    const cordis = await import(input.cordis_entry)
    Context = cordis.Context
  } catch (err) {
    console.error(`[worker/host] load-put: import(cordis_entry) failed: ${err?.message ?? err}`)
    return responseFrame(corr, 'error', [], [REASON_WORKER_ERROR])
  }

  let mod
  try {
    mod = await import(input.put_entry)
  } catch (err) {
    console.error(`[worker/host] load-put: import(put_entry) failed: ${err?.message ?? err}`)
    return responseFrame(corr, 'error', [], [REASON_WORKER_ERROR])
  }
  const put = mod.default ?? mod.put ?? mod

  let fiber
  try {
    fiber = new Context().plugin(put, input.put_config ?? {})
  } catch (err) {
    // 非法 put 形状（plugin() 同步抛「invalid plugin」）→ 视为装载失败。
    console.error(`[worker/host] load-put: root.plugin() failed: ${err?.message ?? err}`)
    return responseFrame(corr, 'error', [], [REASON_WORKER_ERROR])
  }

  // await fiber 结算加载；apply 抛错则 reject，把消息存为 error（FAILED 是待断言观测值，非传输错误）。
  let loadError = null
  try {
    await fiber
  } catch (err) {
    loadError = err instanceof Error ? err.message : String(err)
  }
  const stateAfterLoad = FIBER_STATES[fiber.state]
  const effectsCount = typeof fiber.getEffects === 'function' ? fiber.getEffects().length : 0

  try {
    await fiber.dispose()
  } catch (err) {
    console.error(`[worker/host] load-put: fiber.dispose() failed: ${err?.message ?? err}`)
  }
  const stateAfterDispose = FIBER_STATES[fiber.state]

  return responseFrame(corr, 'completed', [{
    observation_id: 'obs-1',
    value: {
      state_after_load: stateAfterLoad,
      effects_count: effectsCount,
      state_after_dispose: stateAfterDispose,
      error: loadError,
      put_state: mod.state ?? null,
    },
    source: 'worker',
    limitations: ['l1-subprocess', 'real-cordis'],
  }], [])
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

async function handleToolRequest(frame, context) {
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
      onStarted: emitStarted,
    })
  } catch (err) {
    console.error(`[worker/host] tool runner failed: ${err?.message ?? err}`)
    response = toolResponseError(frame, 'tool-runner-error')
  }
  const responseCheck = assertToolResponse(response, frame)
  if (!responseCheck.ok) response = toolResponseError(frame, responseCheck.reason_code)
  await send(response)
}

/** Process one NDJSON line; dispatch the two protocols without mutating either envelope. */
async function handleLine(line, context) {
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

  if (frame?.protocol_version === TEST_TOOL_PROTOCOL_VERSION) {
    await handleToolRequest(frame, context)
    return
  }

  const shape = assertFrameShape(frame)
  if (!shape.ok) {
    // 非法帧（未知版本 / 缺 correlation 字段 / 未知字段）→ error response 后继续读。
    await send(responseFrame(correlationOf(frame), 'error', [], [shape.reason_code]))
    return
  }

  // 合法 request 帧 → 先 emit started（可核验调用开始事件的 worker 侧来源）。
  const corr = correlationOf(frame)
  await send(startedFrame(corr))

  const input = frame.input ?? {}
  const op = input.op ?? 'echo'

  if (op === 'error') {
    await send(responseFrame(corr, 'error', [], [REASON_WORKER_ERROR]))
    return
  }

  if (op === 'load-put') {
    await send(await handleLoadPut(corr, input))
    return
  }

  if (op !== 'echo' && op !== 'sleep') {
    // 非支持 op → error（M3：只有 import 失败或非支持 op 才 error）。
    await send(responseFrame(corr, 'error', [], [REASON_WORKER_ERROR]))
    return
  }

  // op ∈ { 'echo'（缺省）, 'sleep' }：await delay_ms 后按 echo 回传 value（原样透传）。
  const delayMs = Math.max(0, Number(input.delay_ms) || 0)
  if (delayMs > 0) await new Promise((resolve) => setTimeout(resolve, delayMs))
  await send(responseFrame(corr, 'completed', [{
    observation_id: 'obs-1',
    value: input.value,
    source: 'worker',
    limitations: ['l1-subprocess'],
  }], []))
}

async function main() {
  const context = await loadWorkerContext()
  const rl = createInterface({ input: process.stdin })
  try {
    for await (const line of rl) {
      try {
        await handleLine(line, context)
      } catch (err) {
        // 单个帧处理异常不拖垮 worker；诊断到 stderr，继续下一帧。
        console.error(`[worker/host] unhandled frame error: ${err?.message ?? err}`)
      }
    }
  } finally {
    // stdin 'close' → 处理完全部帧后正常退出（exit 0）。
    process.exit(0)
  }
}

await main()