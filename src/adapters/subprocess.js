/**
 * 控制面侧「L1 子进程」本地 worker adapter / launcher + NDJSON 传输 + 生命周期/回收。
 *
 * 隔离定位（务必如实）：**L1 = 普通同权限子进程 = fault 隔离（仅隔离崩溃/堆/生命周期），不是安全边界**。
 *   - 文件系统 / 网络 / 子进程 / 设备 / CPU / 内存 在 L1 下**无法由 OS 强制** → 一律记 `unenforced`，
 *     不得据此给出市场/安全结论。
 *   - 进程内强制 request/frame/output 上限、deadline 与串行调度；L1 不提供 OS 资源隔离。
 *   - Manifest tool mode 固定启动 worker/host.js 并通过权限收紧的临时 worker-context 文件传入 pinned bindings。
 *   - One adapter/host can process mixed built-in control frames and strict `test-tool/v1` requests.
 *
 * `test-tool/v1` ToolResponse does not carry lifecycle status. Exact-correlated
 * `control-protocol/v1` started frames are validated worker notifications only; this adapter has no
 * separate trusted control-plane start source, so they never set `invocation_evidence_verified` or
 * `invocation_status: 'started'`. A passing gate remains blocked until such a source is wired.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/adapters/subprocess
 */
import { spawn } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join, isAbsolute, relative, resolve, sep } from 'node:path'
import { writeFileSync, chmodSync, mkdtempSync, rmSync } from 'node:fs'
import { rm, access } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

import {
  buildRequestFrame,
  buildToolRequestFrame,
  assertFrameShape,
  assertToolRequest,
  assertToolResponse,
  MAX_FRAME_BYTES,
  DEFAULT_MAX_OUTPUT_BYTES,
} from '../protocol/transport.js'
import { EXECUTION_STATUS } from '../protocol/enums.js'

/** 隔离等级：L1 子进程（fault 隔离，非安全边界）。 */
export const ISOLATION_LEVEL = 'L1-subprocess'

/** L1 无法由 OS 强制的资源（文件/网络/子进程/设备/CPU/内存），一律记 unenforced。 */
export const UNENFORCED_RESOURCES = Object.freeze([
  'filesystem', 'network', 'subprocess', 'devices', 'cpu_ms', 'memory_mb',
])

/** L1 进程内可强制上限（adapter 侧真实施行的边界）。 */
export const ENFORCED_LIMITS = Object.freeze([
  'max_frame_bytes', 'max_output_bytes', 'timeout_ms', 'processes',
])

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const TOOL_CONTEXT_VERSION = 'worker-context/v1'
const CAPABILITY_REF_RE = /^cap-sha256:[0-9a-f]{64}$/
const SHA256_RE = /^sha256:[0-9a-f]{64}$/
const TOOL_REF_KEYS = ['tool_id', 'version', 'artifact_digest']
const CORRELATION_KEYS = ['request_id', 'run_id', 'plan_id', 'test_id', 'attempt']

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

function sameToolRef(a, b) {
  return isPlainRecord(a) && isPlainRecord(b) && TOOL_REF_KEYS.every((key) => a[key] === b[key]) &&
    Object.keys(a).length === TOOL_REF_KEYS.length && Object.keys(b).length === TOOL_REF_KEYS.length
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  Object.freeze(value)
  for (const child of Object.values(value)) deepFreeze(child)
  return value
}

function createPinnedToolContext(toolBindings, capabilitySnapshotRefs) {
  if (toolBindings === undefined && capabilitySnapshotRefs === undefined) return null
  if (!isPlainRecord(toolBindings) || !isPlainRecord(capabilitySnapshotRefs)) {
    throw new TypeError('makeSubprocessAdapter: toolBindings and capabilitySnapshotRefs must be records')
  }
  const bindingIds = Object.keys(toolBindings)
  if (bindingIds.length === 0 || bindingIds.some((id) => !id || ['__proto__', 'constructor', 'prototype'].includes(id))) {
    throw new TypeError('makeSubprocessAdapter: toolBindings must contain safe test_id keys')
  }
  const refIds = Object.keys(capabilitySnapshotRefs)
  if (bindingIds.length !== refIds.length || bindingIds.some((id) => !Object.hasOwn(capabilitySnapshotRefs, id))) {
    throw new TypeError('makeSubprocessAdapter: every pinned binding must have exactly one capability snapshot ref')
  }

  const bindings = Object.create(null)
  const refs = Object.create(null)
  for (const testId of bindingIds) {
    const binding = toolBindings[testId]
    if (!isPlainRecord(binding) || Object.keys(binding).some((key) =>
      !['manifest', 'artifactPath', 'workspaceRoot', 'toolRef'].includes(key)) ||
      !['manifest', 'artifactPath', 'workspaceRoot', 'toolRef'].every((key) => Object.hasOwn(binding, key)) ||
      !isPlainRecord(binding.manifest) || !isPlainRecord(binding.toolRef) ||
      typeof binding.artifactPath !== 'string' || !isAbsolute(binding.artifactPath) ||
      typeof binding.workspaceRoot !== 'string' || !isAbsolute(binding.workspaceRoot) ||
      !sameToolRef(binding.toolRef, {
        tool_id: binding.manifest.tool_id,
        version: binding.manifest.tool_version,
        artifact_digest: binding.manifest.artifact_digest,
      }) || !SHA256_RE.test(binding.toolRef.artifact_digest)) {
      throw new TypeError(`makeSubprocessAdapter: invalid pinned binding for test_id ${testId}`)
    }
    const root = resolve(binding.workspaceRoot)
    const artifact = resolve(binding.artifactPath)
    const rel = relative(root, artifact)
    if (!rel || rel === '.' || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
      throw new TypeError(`makeSubprocessAdapter: artifactPath must be a file below workspaceRoot for test_id ${testId}`)
    }
    const capRef = capabilitySnapshotRefs[testId]
    if (typeof capRef !== 'string' || !CAPABILITY_REF_RE.test(capRef)) {
      throw new TypeError(`makeSubprocessAdapter: invalid capability snapshot ref for test_id ${testId}`)
    }
    // JSON clone rejects functions, cycles, BigInt, and non-JSON data before startup.
    let clone
    try { clone = JSON.parse(JSON.stringify(binding)) } catch {
      throw new TypeError(`makeSubprocessAdapter: binding is not bounded JSON for test_id ${testId}`)
    }
    bindings[testId] = clone
    refs[testId] = capRef
  }
  return deepFreeze({ schema_version: TOOL_CONTEXT_VERSION, bindings, capability_snapshot_refs: refs })
}

/** @param {number|undefined|null} pid */
function isPidAlive(pid) {
  if (!pid || typeof pid !== 'number') return false
  try {
    process.kill(pid, 0)
    return true
  } catch (err) {
    // EPERM = 进程存在但无权限访问（仍视为存活）；ESRCH = 进程不存在。
    return err && err.code === 'EPERM'
  }
}

async function pathExists(p) {
  try {
    await access(p)
    return true
  } catch {
    return false
  }
}

/**
 * 归一化 response 帧的 observations：强制 `source='worker'`，`limitations` 缺省 `[]`，
 * 保留 `value` 与（可选的）`schema_ref`；`observation_id` 缺省补 `obs-<序号>`（1-based）。
 * @param {unknown} raw
 * @returns {Array<object>}
 */
function normalizeObservations(raw) {
  if (!Array.isArray(raw)) return []
  const out = []
  for (let i = 0; i < raw.length; i++) {
    const obs = raw[i]
    if (!obs || typeof obs !== 'object') continue
    const normalized = {
      observation_id:
        typeof obs.observation_id === 'string' && obs.observation_id !== '' ? obs.observation_id : `obs-${i + 1}`,
      value: 'value' in obs ? obs.value : undefined,
      source: 'worker',
      limitations: Array.isArray(obs.limitations) ? obs.limitations : [],
    }
    if (obs.schema_ref !== undefined && obs.schema_ref !== null) normalized.schema_ref = obs.schema_ref
    out.push(normalized)
  }
  return out
}

/**
 * @typedef {{ request_id:string, run_id:string, plan_id:string, test_id:string, attempt:number, input:unknown }} Request
 * @typedef {{ admission_status:'accepted'|'rejected', execution_status:string, invocation_status:string,
 *   invocation_evidence_verified:boolean, observations:Array<object>, artifact_refs:Array<object>, diagnostics:Array<unknown>, reason_codes:unknown[] }} AttemptTerminal
 * @typedef {{ pid_alive:boolean, temp_removed:boolean }} ReclaimReport
 */

/**
 * 构造 L1 子进程 adapter。
 * @param {{workerEntry:string, runId?:string, maxFrameBytes?:number, maxOutputBytes?:number,
 *   timeoutMs?:number, graceMs?:number, maxContextBytes?:number,
 *   toolBindings?:Record<string,{manifest:object,artifactPath:string,workspaceRoot:string,toolRef:object}>,
 *   capabilitySnapshotRefs?:Record<string,string>}} [opts]
 */
export function makeSubprocessAdapter(opts = {}) {
  const workerEntry = opts.workerEntry
  if (!workerEntry) {
    throw new Error('makeSubprocessAdapter: opts.workerEntry (absolute path to worker entry) is required')
  }
  const maxFrameBytes = opts.maxFrameBytes ?? MAX_FRAME_BYTES
  const maxOutputBytes = opts.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES
  const timeoutMs = opts.timeoutMs ?? 15000
  const graceMs = opts.graceMs ?? 3000
  const runId = opts.runId ?? `run-subprocess-${Date.now().toString(36)}`
  const pinnedToolContext = createPinnedToolContext(opts.toolBindings, opts.capabilitySnapshotRefs)
  const toolMode = pinnedToolContext !== null
  const activeWorkerEntry = toolMode
    ? fileURLToPath(new URL('../worker/host.js', import.meta.url))
    : workerEntry
  const maxContextBytes = opts.maxContextBytes ?? maxFrameBytes
  const safeRunId = String(runId).replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 96) || 'run'
  let tempDir = null
  let contextPath = null

  /** @type {import('node:child_process').ChildProcess|null} */
  let child = null
  let pid = null
  let started = false
  let cancelled = false

  let reapPromise = null
  let cancelTimer = null

  // NDJSON 行缓冲 + 单个 in-flight 执行器（串行；tool mode also has a per-tool child).
  let lineBuf = ''
  /** @type {{ onLine:(line:string)=>void, onOutputBytes:(size:number)=>void, onStdioEnd:()=>void, onExit:()=>void }|null} */
  let current = null
  const seenRequestIds = new Set()

  /** 终止整个进程树（无 shell）。win32 走 taskkill /T /F；posix 走进程组 SIGKILL。 */
  function killProcessTree() {
    if (!child || !pid) return
    if (process.platform === 'win32') {
      try {
        spawn('taskkill', ['/pid', String(pid), '/T', '/F'], { stdio: 'ignore' })
      } catch {
        /* 忽略：reap() 的核验会如实报告 pid 是否仍存活 */
      }
    } else {
      try {
        process.kill(-pid, 'SIGKILL') // detached:true 使 child 成为进程组组长
      } catch {
        /* 忽略 */
      }
      try {
        child.kill('SIGKILL')
      } catch {
        /* 忽略 */
      }
    }
  }

  function start() {
    if (started) return { pid }
    tempDir = mkdtempSync(join(tmpdir(), `dsh-testbed-${safeRunId}-`))
    try {
      chmodSync(tempDir, 0o700)
      if (toolMode) {
        const contextJson = JSON.stringify(pinnedToolContext)
        if (Buffer.byteLength(contextJson, 'utf8') > maxContextBytes) {
          throw new Error('makeSubprocessAdapter.start: pinned worker context exceeds maxContextBytes')
        }
        contextPath = join(tempDir, 'worker-context.json')
        writeFileSync(contextPath, contextJson, { encoding: 'utf8', flag: 'wx', mode: 0o600 })
        chmodSync(contextPath, 0o600)
      }
      const spawnOpts = { stdio: ['pipe', 'pipe', 'pipe'], shell: false, windowsHide: true }
      if (process.platform !== 'win32') spawnOpts.detached = true
      const args = [activeWorkerEntry]
      if (toolMode) args.push('--worker-context', contextPath)
      child = spawn(process.execPath, args, spawnOpts)
      pid = child.pid
      started = true

      child.stdout.setEncoding('utf8')
      child.stdout.on('data', (chunk) => {
        const chunkBytes = Buffer.byteLength(chunk, 'utf8')
        if (!current) { killProcessTree(); return }
        current.onOutputBytes(chunkBytes)
        if (!current) return
        lineBuf += chunk
        if (Buffer.byteLength(lineBuf, 'utf8') > maxFrameBytes && !lineBuf.includes('\n')) {
          current.onOutputBytes(maxOutputBytes + 1)
          lineBuf = ''
          return
        }
        let idx
        while ((idx = lineBuf.indexOf('\n')) >= 0) {
          const line = lineBuf.slice(0, idx)
          lineBuf = lineBuf.slice(idx + 1)
          const waiter = current
          if (waiter) waiter.onLine(line)
          if (Buffer.byteLength(lineBuf, 'utf8') > maxFrameBytes && !lineBuf.includes('\n')) {
            if (current) current.onOutputBytes(maxOutputBytes + 1)
            lineBuf = ''
            return
          }
        }
      })
      child.stdout.on('end', () => {
        if (current) current.onStdioEnd()
      })
      child.stderr.on('data', (chunk) => {
        if (current) current.onOutputBytes(Buffer.byteLength(chunk))
      })
      child.on('exit', () => {
        if (current) current.onExit()
      })
      child.on('error', () => {
        if (current) current.onExit()
      })
      return { pid }
    } catch (error) {
      if (tempDir) rmSync(tempDir, { recursive: true, force: true })
      tempDir = null
      contextPath = null
      throw error
    }
  }

  /**
   * Execute one legacy control request or strict test-tool/v1 request. Manifest
   * binding/path/capability data are accepted only from constructor-pinned context.
   * @param {Request|object} req
   * @returns {Promise<AttemptTerminal>}
   */
  function execute(req) {
    const failed = (reason, invocation = 'not-started') => ({
      admission_status: 'accepted', execution_status: 'error', invocation_status: invocation,
      invocation_evidence_verified: false, observations: [], artifact_refs: [], diagnostics: [], reason_codes: [reason],
    })
    if (!started || !child || reaped()) return Promise.resolve(failed('no-response'))
    if (current !== null) return Promise.resolve(failed('out-of-order', 'unknown'))
    if (!req || typeof req !== 'object' || Array.isArray(req)) return Promise.resolve(failed('unknown-field'))
    const isToolRequest = req.protocol_version === 'test-tool/v1'
    if (req.protocol_version !== undefined && req.protocol_version !== 'test-tool/v1' && req.protocol_version !== 'control-protocol/v1') {
      return Promise.resolve(failed('unknown-version'))
    }
    if (isToolRequest && !toolMode) return Promise.resolve(failed('unknown-field'))
    if (seenRequestIds.has(req.request_id)) return Promise.resolve(failed('duplicate', 'unknown'))

    let requestFrame
    let line
    let effectiveTimeoutMs = timeoutMs
    try {
      if (isToolRequest) {
        const binding = pinnedToolContext.bindings[req.test_id]
        const expectedCapRef = pinnedToolContext.capability_snapshot_refs[req.test_id]
        if (!binding || !sameToolRef(req.tool_ref, binding.toolRef) || req.capability_snapshot_ref !== expectedCapRef) {
          return Promise.resolve(failed('correlation-mismatch'))
        }
        const requestedDeadline = Date.parse(req.deadline)
        if (!Number.isFinite(requestedDeadline)) return Promise.resolve(failed('unknown-field'))
        const deadline = new Date(Math.min(requestedDeadline, Date.now() + timeoutMs)).toISOString()
        const { protocol_version: _protocolVersion, ...toolRequestParams } = req
        requestFrame = buildToolRequestFrame({ ...toolRequestParams, deadline })
        const shape = assertToolRequest(requestFrame, { maxBytes: maxFrameBytes })
        if (!shape.ok) return Promise.resolve(failed(shape.reason_code ?? 'unknown-field'))
        effectiveTimeoutMs = Math.max(1, Math.min(timeoutMs, Date.parse(requestFrame.deadline) - Date.now()))
      } else {
        requestFrame = buildRequestFrame({ ...req, deadline_ms: timeoutMs })
        line = JSON.stringify(requestFrame)
      }
      if (isToolRequest) line = JSON.stringify(requestFrame)
    } catch {
      return Promise.resolve(failed('unknown-field'))
    }
    if (Buffer.byteLength(line, 'utf8') > maxFrameBytes) return Promise.resolve(failed('oversize'))
    seenRequestIds.add(req.request_id)

    return new Promise((resolveResult) => {
      let settled = false
      // No trusted control-plane start source is currently wired. The flag stays false even when
      // an exact-correlated worker `started` notification is received.
      const invocationEvidenceVerified = false
      let outputBytes = 0
      let deadlineTimer = null
      const matchesCorrelation = (frame) => CORRELATION_KEYS.every((key) => frame[key] === requestFrame[key])
      const matchesTool = (value) => requestFrame.tool_ref === null
        ? value === null || value === undefined
        : sameToolRef(value, requestFrame.tool_ref)
      const done = (result) => {
        if (settled) return
        settled = true
        if (deadlineTimer) clearTimeout(deadlineTimer)
        if (current === waiter) current = null
        resolveResult({ invocation_evidence_verified: invocationEvidenceVerified, ...result })
      }
      const rejectWith = (reasonCode) => {
        killProcessTree()
        return done({
        admission_status: 'accepted', execution_status: 'error',
        invocation_status: invocationEvidenceVerified ? 'started' : 'unknown',
        observations: [], artifact_refs: [], diagnostics: [], reason_codes: [reasonCode],
        })
      }
      const waiter = {
        onOutputBytes(size) {
          if (settled) return
          outputBytes += size
          if (outputBytes > maxOutputBytes) {
            killProcessTree()
            rejectWith('oversize')
          }
        },
        onLine(rawLine) {
          if (settled) return
          if (Buffer.byteLength(rawLine, 'utf8') > maxFrameBytes) return rejectWith('oversize')
          let frame
          try { frame = JSON.parse(rawLine) } catch { return rejectWith('unknown-field') }
          if (isToolRequest && frame?.protocol_version === 'test-tool/v1' && frame.kind === undefined) {
            const checked = assertToolResponse(frame, requestFrame, { maxBytes: maxFrameBytes })
            if (!checked.ok) return rejectWith(checked.reason_code ?? 'unknown-field')
            // A ToolResponse is not lifecycle evidence. A worker started frame is only
            // a notification; without separate trusted control-plane evidence, status remains unknown.
            return done({
              admission_status: 'accepted', execution_status: frame.execution_status,
              invocation_status: invocationEvidenceVerified ? 'started' : 'unknown',
              observations: normalizeObservations(frame.observations),
              artifact_refs: frame.artifact_refs, diagnostics: frame.diagnostics, reason_codes: [],
            })
          }
          const shape = assertFrameShape(frame)
          if (!shape.ok) return rejectWith(shape.reason_code ?? 'unknown-field')
          if (!matchesCorrelation(frame) || !matchesTool(frame.tool_ref)) return rejectWith('correlation-mismatch')
          if (frame.kind === 'started') {
            // Validated worker notification only; no trusted control-plane event is wired.
            return
          }
          if (frame.kind === 'response') {
            const result = {
              admission_status: 'accepted',
              execution_status: EXECUTION_STATUS.includes(frame.execution_status) ? frame.execution_status : 'error',
              invocation_status: invocationEvidenceVerified ? 'started' : 'unknown',
              observations: normalizeObservations(frame.observations),
              artifact_refs: Array.isArray(frame.artifact_refs) ? frame.artifact_refs : [],
              diagnostics: Array.isArray(frame.diagnostics) ? frame.diagnostics : [],
              reason_codes: Array.isArray(frame.reason_codes) ? Array.from(frame.reason_codes) : [],
            }
            return done(result)
          }
          return rejectWith('unknown-field')
        },
        onStdioEnd() {
          if (settled) return
          done({ admission_status: 'accepted', execution_status: 'error',
            invocation_status: invocationEvidenceVerified ? 'started' : 'unknown', observations: [],
            artifact_refs: [], diagnostics: [], reason_codes: ['worker-crash'] })
        },
        onExit() {
          if (settled) return
          const status = cancelled ? 'cancelled' : 'error'
          done({ admission_status: 'accepted', execution_status: status,
            invocation_status: invocationEvidenceVerified ? 'started' : 'unknown', observations: [],
            artifact_refs: [], diagnostics: [], reason_codes: [cancelled ? 'cancelled' : 'worker-crash'] })
        },
      }
      current = waiter
      deadlineTimer = setTimeout(() => {
        if (settled) return
        killProcessTree()
        done({ admission_status: 'accepted', execution_status: 'timeout',
          invocation_status: 'unknown', observations: [],
          artifact_refs: [], diagnostics: [], reason_codes: ['deadline'] })
      }, effectiveTimeoutMs)
      child.stdin.write(line + '\n', (err) => {
        if (err && !settled) done({ admission_status: 'accepted', execution_status: 'error',
          invocation_status: 'not-started', observations: [], artifact_refs: [], diagnostics: [], reason_codes: ['no-response'] })
      })
    })
  }

  /** 幂等取消：关 stdin + SIGTERM，graceMs 后进程树 SIGKILL。 */
  function cancel() {
    if (cancelled) return
    cancelled = true
    if (!child || reaped()) return
    try {
      child.stdin.end()
    } catch {
      /* 忽略 */
    }
    try {
      child.kill('SIGTERM')
    } catch {
      /* 忽略 */
    }
    if (cancelTimer) clearTimeout(cancelTimer)
    cancelTimer = setTimeout(() => killProcessTree(), graceMs)
    if (cancelTimer && cancelTimer.unref) cancelTimer.unref()
  }

  function reaped() {
    return reapPromise !== null
  }

  /**
   * 幂等回收：kill 进程树 + 删临时目录，并真实核验（不以退出码替代回收验收）。
   * @returns {Promise<ReclaimReport>}
   */
  function reap() {
    if (reapPromise) return reapPromise
    reapPromise = (async () => {
      if (cancelTimer) {
        clearTimeout(cancelTimer)
        cancelTimer = null
      }
      killProcessTree()

      // 轮询等进程树真正退出（不是看 exit code）。
      const deadlineAt = Date.now() + 2500
      while (Date.now() < deadlineAt) {
        if (!isPidAlive(pid)) break
        await sleep(50)
      }
      const pid_alive = isPidAlive(pid)

      try {
        await rm(tempDir, { recursive: true, force: true })
      } catch {
        /* 忽略：下面用存在性核验 temp_removed */
      }
      const temp_removed = !(await pathExists(tempDir))

      return { pid_alive, temp_removed }
    })()
    return reapPromise
  }

  return {
    start,
    execute,
    cancel,
    reap,
    get launchRecord() {
      return {
        isolation: ISOLATION_LEVEL,
        pid,
        enforceable: ENFORCED_LIMITS,
        unenforced: UNENFORCED_RESOURCES,
        max_frame_bytes: maxFrameBytes,
        max_output_bytes: maxOutputBytes,
        timeout_ms: timeoutMs,
        temp_dir: tempDir,
      }
    },
  }
}