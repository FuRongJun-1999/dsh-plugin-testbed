/**
 * 控制面侧「local-worker-json / L1 子进程」本地 worker adapter + launcher 生命周期、
 * NDJSON 传输边界、按 owner 回收，以及**独立可核验 invocation start 见证**。
 *
 * ## 隔离定位（务必如实）
 * **L1 = 普通同权限子进程 = fault 隔离（仅隔离崩溃/堆/生命周期），不是安全边界。**
 *   - 文件系统 / 网络 / 子进程 / 设备 / CPU / 内存 在 L1 下**无法由 OS 强制** → 一律记 `unenforced`，
 *     不得据此给出市场/安全结论（`market_conclusion` 恒为 `none`、`trust_scope` 恒为 `local-only`）。
 *   - 进程内强制 frame/output/attachment/context 上限、deadline、串行调度；L1 不提供 OS 资源隔离。
 *   - worker 环境是**显式非密钥白名单**（不透传控制面/父进程自定义 env 与 credentials）；
 *     Windows 下 OS/Node 会为子系统补入少量非密钥用户变量（如 PATH/USERPROFILE），
 *     但这只兑现「不注入凭据」，不构成文件/网络隔离。
 *
 * ## 独立 invocation start 见证（核心）
 * `invocation_status=started` 的唯一来源是 adapter 自己发起的 OS 进程创建事实：
 *   - 每次 `test-tool/v1` attempt，adapter 用**固定 worker 引导入口 + 参数数组 + `shell:false`**
 *     spawn 一个一次性 L1 worker 子进程；Node `ChildProcess` 的 `spawn` 事件与 `pid` 是 OS
 *     进程创建的可观察事实，由控制面 launcher 记录（`mechanism='os-child-spawn'`）。
 *   - correlation tuple（`request_id/run_id/plan_id/test_id/attempt/tool_ref`）来自 adapter
 *     自己的 in-flight 表（dispatch 前固定），`started_at` 来自 adapter 时钟。
 *   - **不采信** worker `started` 帧、worker 自报时间戳、`ToolResponse`、`RunSpec` 或任何 caller
 *     字段；这些只能作为数据/通知，永远不升级为 `started`。
 *   - 只有在 spawn 成功后才交给 control `InvocationStartEvent`（`reportInvocationStart`
 *     与 attempt 终态里的 `invocation_evidence`）；spawn 失败、adapter 在派发前拒绝、
 *     无法确认时一律 `unknown`（派发前有证据被阻止的 binding/capability 拒绝记 `not-started`）。
 *
 * ## 传输/生命周期纪律
 * - `test-tool/v1`：一次性子进程 + 闭集 `ToolResponse` 校验；worker 的 control-protocol
 *   `started` 帧只作通知。
 * - `control-protocol/v1`：运行级常驻 worker（owner/lifecycle anchor）；其 `started` 帧同样
 *   只作通知，不产出启动见证（built-in op 无独立 OS 启动事实）。
 * - 串行 in-flight、重复/乱序/迟到/错配/未知版本/未知字段/超限拒绝、deadline、取消、
 *   进程树 + 临时目录按 owner 实测回收，`reap()` 幂等且不以 exit code 替代验收。
 * - **取消/结算/回收等待完整进程树**：Windows 等待 `taskkill /T /F` 自身退出并轮询
 *   OS 实测，POSIX 走进程组 SIGTERM→graceMs→SIGKILL；runner 孙进程 pid 由可信 runner
 *   的 stderr 清理标记上报（仅用于回收，不是 invocation start 证据），避免「已 resolve
 *   但孙进程仍持有 workspace cwd」导致 Windows 目录回收偶发 EPERM。
 *
 * @module @deepseek-ai/dsh-plugin-testbed/adapters/subprocess
 */
import { spawn } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join, isAbsolute, relative, resolve, sep, win32 } from 'node:path'
import {
  writeFileSync, chmodSync, mkdtempSync, rmSync, realpathSync, statSync,
} from 'node:fs'
import { rm, access, readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

import {
  buildRequestFrame,
  buildToolRequestFrame,
  assertFrameShape,
  assertToolResponse,
  CONTROL_PROTOCOL_VERSION,
  MAX_FRAME_BYTES,
  DEFAULT_MAX_OUTPUT_BYTES,
} from '../protocol/transport.js'
import { EXECUTION_STATUS, INVOCATION_STATUS, TEST_TOOL_PROTOCOL_VERSION, TOOL_PERMISSION_KEYS } from '../protocol/enums.js'
import { validateValue } from '../protocol/jsonschema.js'
import { validateToolManifest } from '../protocol/tool-manifest.js'
import {
  INVOCATION_START_KIND,
  INVOCATION_WITNESS_MECHANISM,
  INVOCATION_WITNESS_SCOPE,
  INVOCATION_WITNESS_SOURCE,
  createInvocationStartEvent,
} from './invocation-witness.js'

/** adapter 身份（architecture §8.1 唯一本地 MVP adapter）。 */
export const ADAPTER_REF = 'local-worker-json@1.0.0'

/** 隔离等级：L1 子进程（fault 隔离，非安全边界）。 */
export const ISOLATION_LEVEL = 'L1-subprocess'

/** L1 无法由 OS 强制的权限/资源类，一律记 unenforced。 */
export const UNENFORCED_RESOURCES = Object.freeze([
  'filesystem', 'network', 'subprocess', 'devices', 'cpu_ms', 'memory_mb',
])

/** adapter/launcher 在进程内真实可强制的上限（不是 OS 资源隔离）。 */
export const ENFORCED_LIMITS = Object.freeze([
  'max_frame_bytes', 'max_output_bytes', 'attachment_bytes', 'timeout_ms', 'concurrency', 'max_context_bytes',
])

/** pinned worker-context 版本（与 worker/host.js 同一契约）。 */
export const WORKER_CONTEXT_VERSION = 'worker-context/v1'
/** 可信运行时锚的固定 argv 键（内容 schema 由 worker-owner 定义；adapter 只透传可信配置）。 */
export const RUNTIME_ANCHOR_ARG = '--runtime-anchor'
/** 单个 artifact 内容上限（与 worker runner 的 MAX_ARTIFACT_BYTES 对齐）。 */
export const DEFAULT_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
/** artifact_refs 字节总和上限（L1 进程内强制）。 */
export const DEFAULT_MAX_ATTACHMENT_BYTES = 1024 * 1024
/** worker 环境白名单：只有非密钥的 OS 路径变量 + 固定 NODE_NO_WARNINGS。 */
export const WORKER_ENV_PASSTHROUGH = Object.freeze(
  process.platform === 'win32'
    ? ['SystemRoot', 'SystemDrive', 'windir', 'TEMP', 'TMP']
    : ['TMPDIR'],
)

const CAPABILITY_REF_RE = /^cap-sha256:[0-9a-f]{64}$/
const SHA256_RE = /^sha256:[0-9a-f]{64}$/
const TOOL_REF_KEYS = ['tool_id', 'version', 'artifact_digest']
const CORRELATION_KEYS = ['request_id', 'run_id', 'plan_id', 'test_id', 'attempt']
/**
 * Upper bound for "wait until the whole process tree is confirmed gone".
 * Cleanup is fail-closed: if the bound is exceeded the reap report says the
 * tree is still alive instead of claiming success.
 */
const REAP_TIMEOUT_MS = 5000
const PID_POLL_INTERVAL_MS = 25
/**
 * Windows keeps a terminated process object visible to `OpenProcess` (and thus
 * `process.kill(pid, 0)`) until the last handle/object reference is released.
 * A single "not alive" sample can therefore be followed by a transient "alive"
 * sample for a process that is already terminated. Reap confirmation must require
 * a **stable absence window**, otherwise an adapter can resolve while the OS is
 * still tearing the tree down (and tests/workspace cleanup race it).
 */
const REAP_SETTLE_MS = 60
const TASKKILL_TIMEOUT_MS = 3000
/** Runner child cleanup marker channel (see worker/runner.js) — cleanup only. */
const WORKER_CHILD_CLEANUP_MARKER = '[dsh-testbed-cleanup]'

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

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

/**
 * worker 进程环境：显式非密钥白名单，移除父进程自定义 env / ambient credentials。
 * 注意：Windows 上 OS/Node 会为子系统自动补入少量非密钥用户变量（如 PATH/USERPROFILE），
 * 它们不是控制面注入的凭据；本函数只保证控制面/父进程的 secret 不被透传。
 * 这只兑现「不注入凭据」，不构成 L1 文件/网络隔离。
 * @param {Record<string, string|undefined>} [source]
 * @returns {Readonly<Record<string,string>>}
 */
export function buildWorkerEnvironment(source = process.env) {
  const env = Object.create(null)
  for (const key of WORKER_ENV_PASSTHROUGH) {
    const value = source?.[key]
    if (typeof value === 'string' && value.length > 0) env[key] = value
  }
  env.NODE_NO_WARNINGS = '1'
  return Object.freeze(env)
}

/** @param {number} pid */
export function isPidAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (err) {
    // EPERM = 进程存在但无权限访问（仍视为存活）；ESRCH = 进程不存在。
    return err && err.code === 'EPERM'
  }
}

/**
 * 轮询直到给定 pid 全部消失（OS 实测，不以 exit code/进程句柄事件替代）。
 * 成功要求 **稳定缺失窗口**（默认 `settleMs`），避免 Windows terminated-object
 * 的瞬时 `isPidAlive=true` 被误判为「已确认消失」而过早返回。
 * @param {Iterable<number>} pids
 * @param {{timeoutMs?:number, settleMs?:number}} [options]
 * @returns {Promise<{ok:boolean, remaining:number[]}>}
 */
export async function waitForPidsGone(pids, { timeoutMs = REAP_TIMEOUT_MS, settleMs = REAP_SETTLE_MS } = {}) {
  const targets = [...new Set([...pids])].filter((pid) => Number.isSafeInteger(pid) && pid > 0)
  const deadlineAt = Date.now() + Math.max(0, timeoutMs)
  let remaining = targets.filter(isPidAlive)
  while (remaining.length > 0 && Date.now() < deadlineAt) {
    await sleep(PID_POLL_INTERVAL_MS)
    remaining = remaining.filter(isPidAlive)
  }
  if (remaining.length > 0 || settleMs <= 0 || targets.length === 0) {
    return { ok: remaining.length === 0, remaining }
  }
  // Stable-absence confirmation: observe no target alive for a full settle window
  // (re-polling if any transiently reappears) before reporting success.
  let stableSince = Date.now()
  while (Date.now() < deadlineAt) {
    await sleep(Math.min(PID_POLL_INTERVAL_MS, settleMs))
    const alive = targets.filter(isPidAlive)
    if (alive.length > 0) {
      remaining = alive
      stableSince = Date.now()
      while (remaining.length > 0 && Date.now() < deadlineAt) {
        await sleep(PID_POLL_INTERVAL_MS)
        remaining = remaining.filter(isPidAlive)
      }
      if (remaining.length > 0) break
      stableSince = Date.now()
    } else if (Date.now() - stableSince >= settleMs) {
      break
    }
  }
  return { ok: remaining.length === 0, remaining }
}

/**
 * Windows `taskkill` 是异步子进程：必须等它自己退出（或超时被终止）后，
 * 再以 OS 实测确认目标消失；不能 spawn 后立即认为进程树已终止。
 */
async function runTaskkill(pid, { tree = true, timeoutMs = TASKKILL_TIMEOUT_MS } = {}) {
  if (process.platform !== 'win32' || !Number.isSafeInteger(pid) || pid < 1) return
  await new Promise((resolveDone) => {
    let settled = false
    let timer = null
    let taskkill = null
    const finish = () => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      resolveDone()
    }
    try {
      const args = ['/pid', String(pid), '/F']
      if (tree) args.push('/T')
      taskkill = spawn('taskkill', args, { stdio: 'ignore', windowsHide: true })
    } catch {
      return finish()
    }
    timer = setTimeout(() => {
      try { taskkill.kill() } catch { /* already gone */ }
      finish()
    }, timeoutMs)
    timer.unref?.()
    taskkill.once('error', finish)
    taskkill.once('close', finish)
  })
}

/**
 * 终止完整进程树并**等待 OS 确认**。Windows：await taskkill /T /F，随后对
 * 已知孙进程逐个补杀并轮询；POSIX：进程组 SIGTERM →（graceMs）→ SIGKILL，
 * 并对已知孙进程逐个补杀。返回实测 remaining；不把 exit code 当作清理成功。
 *
 * @param {number} pid 进程树根（adapter 自己 spawn 的 worker）
 * @param {{knownChildPids?:Iterable<number>, graceMs?:number, timeoutMs?:number}} [options]
 * @returns {Promise<{ok:boolean, remaining:number[]}>}
 */
export async function terminateProcessTree(pid, { knownChildPids = [], graceMs = 0, timeoutMs = REAP_TIMEOUT_MS } = {}) {
  if (!Number.isSafeInteger(pid) || pid < 1) return { ok: true, remaining: [] }
  const known = [...new Set([...knownChildPids])].filter((childPid) => Number.isSafeInteger(childPid) && childPid > 0)
  const targets = [pid, ...known]
  if (process.platform === 'win32') {
    // Must run while the root is still alive so /T can enumerate descendants.
    await runTaskkill(pid, { tree: true })
    for (const target of targets) {
      if (isPidAlive(target)) await runTaskkill(target, { tree: true })
    }
    let result = await waitForPidsGone(targets, { timeoutMs })
    // A second pass covers descendants re-parented between enumeration and kill.
    if (!result.ok) {
      await runTaskkill(pid, { tree: true })
      for (const target of result.remaining) await runTaskkill(target, { tree: true })
      result = await waitForPidsGone(targets, { timeoutMs })
    }
    return result
  }
  try { process.kill(-pid, 'SIGTERM') } catch { /* group already gone */ }
  for (const target of targets) {
    try { process.kill(target, 'SIGTERM') } catch { /* already gone */ }
  }
  if (graceMs > 0) {
    const graceful = await waitForPidsGone(targets, { timeoutMs: graceMs })
    if (graceful.ok) return graceful
  }
  try { process.kill(-pid, 'SIGKILL') } catch { /* group already gone */ }
  for (const target of targets) {
    try { process.kill(target, 'SIGKILL') } catch { /* already gone */ }
  }
  return waitForPidsGone(targets, { timeoutMs })
}

/**
 * 兼容用的 fire-and-forget 终止；产品清理路径必须使用可 await 的
 * `terminateProcessTree()`，否则会出现「已 resolve 但进程树仍存活」的竞态。
 * @param {number} pid
 */
export function killProcessTree(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) return
  void terminateProcessTree(pid)
}

async function pathExists(path) {
  try {
    await access(path)
    return true
  } catch {
    return false
  }
}

function normalizeWorkerEntry(value) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error('makeSubprocessAdapter: opts.workerEntry (absolute path to worker entry) is required')
  }
  let entry = value
  if (/^file:/i.test(entry)) entry = fileURLToPath(entry)
  if (!isAbsolute(entry)) {
    throw new TypeError('makeSubprocessAdapter: opts.workerEntry must be an absolute path or file: URL')
  }
  return resolve(entry)
}

/**
 * 可信运行时锚：只来自 adapter constructor（控制面配置），不接受 caller/worker/请求字段。
 * 内容 schema 由 worker-owner 定义；adapter 只做边界校验并作为固定 argv 透传。
 */
function normalizeRuntimeAnchor(value) {
  if (value === undefined || value === null) return null
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
    throw new TypeError('makeSubprocessAdapter: opts.runtimeAnchor must be a non-empty string')
  }
  if (Buffer.byteLength(value, 'utf8') > 64 * 1024) {
    throw new TypeError('makeSubprocessAdapter: opts.runtimeAnchor exceeds 64 KiB')
  }
  return value
}

function assertRegularFile(path, label) {
  let stats
  try {
    stats = statSync(path)
  } catch {
    throw new TypeError(`${label} does not exist: ${path}`)
  }
  if (!stats.isFile()) throw new TypeError(`${label} is not a regular file: ${path}`)
}

/**
 * pinned binding 的跨平台路径纪律：
 * - `workspaceRoot` / `artifactPath` 必须是绝对路径；
 * - artifact 必须是 workspaceRoot 下的文件（词法 + realpath 两层，拒绝 symlink/junction 逃逸）；
 * - 构造时做词法检查，`start()` 时做 realpath 检查（不改变同步 API）。
 * @param {Readonly<object>|null} pinned
 */
function assertPinnedPathsResolvable(pinned) {
  if (!pinned) return
  for (const [testId, binding] of Object.entries(pinned.bindings)) {
    let rootReal
    let artifactReal
    try {
      rootReal = realpathSync(resolve(binding.workspaceRoot))
      artifactReal = realpathSync(resolve(binding.artifactPath))
    } catch {
      throw new TypeError(`makeSubprocessAdapter: pinned binding paths for test_id ${testId} are not resolvable`)
    }
    if (!statSync(rootReal).isDirectory()) {
      throw new TypeError(`makeSubprocessAdapter: workspaceRoot for test_id ${testId} is not a directory`)
    }
    if (!statSync(artifactReal).isFile()) {
      throw new TypeError(`makeSubprocessAdapter: artifactPath for test_id ${testId} is not a file`)
    }
    const rel = relative(rootReal, artifactReal)
    if (!rel || rel === '.' || rel === '..' || rel.startsWith(`..${sep}`) ||
        isAbsolute(rel) || win32.isAbsolute(rel)) {
      throw new TypeError(`makeSubprocessAdapter: artifactPath must resolve to a file below workspaceRoot for test_id ${testId}`)
    }
  }
}

/**
 * 校验并冻结 constructor 传入的 pinned tool bindings。
 * manifest 是输入声明而非权限证明：这里只做 fail-closed 结构校验；权限可强制子集
 * 由 `buildLaunchGrants` 在 worker 外重算。
 */
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
      typeof binding.artifactPath !== 'string' || binding.artifactPath.includes('\0') || !isAbsolute(binding.artifactPath) ||
      typeof binding.workspaceRoot !== 'string' || binding.workspaceRoot.includes('\0') || !isAbsolute(binding.workspaceRoot) ||
      !sameToolRef(binding.toolRef, {
        tool_id: binding.manifest.tool_id,
        version: binding.manifest.tool_version,
        artifact_digest: binding.manifest.artifact_digest,
      }) || !SHA256_RE.test(binding.toolRef.artifact_digest)) {
      throw new TypeError(`makeSubprocessAdapter: invalid pinned binding for test_id ${testId}`)
    }
    const manifestCheck = validateToolManifest(binding.manifest)
    if (!manifestCheck.ok) {
      throw new TypeError(`makeSubprocessAdapter: invalid tool manifest for test_id ${testId}: ${manifestCheck.errors[0] ?? 'unknown'}`)
    }
    if (binding.manifest.runner?.adapter !== 'local-worker-json' || binding.manifest.runner?.entrypoint !== 'run') {
      throw new TypeError(`makeSubprocessAdapter: unsupported runner for test_id ${testId}`)
    }
    const root = resolve(binding.workspaceRoot)
    const artifact = resolve(binding.artifactPath)
    const rel = relative(root, artifact)
    if (!rel || rel === '.' || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel) || win32.isAbsolute(rel)) {
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
  return deepFreeze({ schema_version: WORKER_CONTEXT_VERSION, bindings, capability_snapshot_refs: refs })
}

/** @param {unknown} policyAllowed */
function normalizePolicyAllowed(policyAllowed) {
  const source = policyAllowed === undefined ? {} : policyAllowed
  if (!isPlainRecord(source)) {
    throw new TypeError('makeSubprocessAdapter: policyAllowed must be a record')
  }
  for (const key of Object.keys(source)) {
    if (!TOOL_PERMISSION_KEYS.includes(key)) {
      throw new TypeError(`makeSubprocessAdapter: unknown policyAllowed permission ${key}`)
    }
  }
  const normalized = Object.create(null)
  for (const key of TOOL_PERMISSION_KEYS) {
    const value = source[key] === undefined ? [] : source[key]
    if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || item.length === 0)) {
      throw new TypeError(`makeSubprocessAdapter: policyAllowed.${key} must be an array of non-empty strings`)
    }
    normalized[key] = [...new Set(value)].sort()
  }
  return deepFreeze({ ...normalized })
}

function minDeclaredLimit(pinned, limit) {
  if (!pinned) return null
  let min = null
  for (const binding of Object.values(pinned.bindings)) {
    const value = binding.manifest?.limits?.[limit]
    if (!Number.isSafeInteger(value) || value < 1) continue
    min = min === null ? value : Math.min(min, value)
  }
  return min
}

const GRANT_BASIS = Object.freeze({
  filesystem: 'L1 ordinary same-user child cannot restrict filesystem access',
  network: 'L1 cannot restrict network access',
  subprocess: 'L1 cannot stop the worker from spawning processes',
  devices: 'L1 cannot restrict device access',
  secrets: 'L1 cannot remove ambient credentials available to the same OS user',
})

/**
 * `granted = policy_allowed ∩ tool_requested`；L1 无法由 OS 强制的项一律 `unenforced`。
 * 例外：`secrets` 在 `granted` 为空时可由 launcher 真实兑现「不注入凭据」→ `enforced`。
 * @param {Readonly<object>|null} pinned
 * @param {Readonly<object>} policyAllowed
 * @returns {ReadonlyArray<object>}
 */
export function buildLaunchGrants(pinned, policyAllowed) {
  const grants = []
  for (const permission of TOOL_PERMISSION_KEYS) {
    const requested = new Set()
    if (pinned) {
      for (const binding of Object.values(pinned.bindings)) {
        const values = binding.manifest?.permissions?.[permission]
        if (Array.isArray(values)) for (const value of values) requested.add(value)
      }
    }
    const policy = policyAllowed?.[permission] ?? []
    const requestedSorted = [...requested].sort()
    const granted = requestedSorted.filter((value) => policy.includes(value))
    const enforced = permission === 'secrets' && granted.length === 0
    grants.push(deepFreeze({
      permission,
      requested: requestedSorted,
      policy_allowed: [...policy],
      granted,
      enforced,
      marking: enforced ? 'enforced' : 'unenforced',
      basis: enforced
        ? 'launcher injects no credentials; worker environment is an explicit non-secret allowlist'
        : GRANT_BASIS[permission],
    }))
  }
  return deepFreeze(grants)
}

/**
 * 有效上限留痕：`granted = min(adapter 上限, frozen manifest 声明)`；无 OS 强制力的项标记 unenforced。
 * @returns {ReadonlyArray<object>}
 */
export function buildLimitsEnforcement(limits) {
  const {
    pinned, maxFrameBytes = MAX_FRAME_BYTES, maxOutputBytes = DEFAULT_MAX_OUTPUT_BYTES,
    maxAttachmentBytes = DEFAULT_MAX_ATTACHMENT_BYTES, maxContextBytes = MAX_FRAME_BYTES,
    timeoutMs = 15000,
  } = limits ?? {}
  const declared = (name) => minDeclaredLimit(pinned ?? null, name)
  const effective = (value, declaredValue) => declaredValue === null ? value : Math.min(value, declaredValue)
  const entries = [
    { limit: 'max_frame_bytes', requested: null, granted: maxFrameBytes, enforced: true, mechanism: 'adapter NDJSON frame-size cap' },
    {
      limit: 'max_output_bytes', requested: declared('output_bytes'),
      granted: effective(maxOutputBytes, declared('output_bytes')), enforced: true,
      mechanism: 'adapter aggregate stdout/stderr cap',
    },
    {
      limit: 'attachment_bytes', requested: declared('attachment_bytes'),
      granted: effective(maxAttachmentBytes, declared('attachment_bytes')), enforced: true,
      mechanism: 'adapter artifact_refs byte-sum cap',
    },
    {
      limit: 'timeout_ms', requested: declared('timeout_ms'),
      granted: effective(timeoutMs, declared('timeout_ms')), enforced: true,
      mechanism: 'adapter wall-clock deadline + process-tree kill',
    },
    {
      limit: 'concurrency', requested: declared('concurrency') ?? 1, granted: 1, enforced: true,
      mechanism: 'adapter single in-flight attempt',
    },
    { limit: 'max_context_bytes', requested: null, granted: maxContextBytes, enforced: true, mechanism: 'adapter pinned worker-context cap' },
    {
      limit: 'processes', requested: declared('processes'), granted: declared('processes'), enforced: false,
      mechanism: 'launcher bounds its own spawn only; cannot stop worker forking',
    },
    {
      limit: 'cpu_ms', requested: declared('cpu_ms'), granted: declared('cpu_ms'), enforced: false,
      mechanism: 'no OS hard CPU limit under L1',
    },
    {
      limit: 'memory_mb', requested: declared('memory_mb'), granted: declared('memory_mb'), enforced: false,
      mechanism: 'no OS hard memory limit under L1',
    },
    {
      limit: 'temp_bytes', requested: declared('temp_bytes'), granted: declared('temp_bytes'), enforced: false,
      mechanism: 'launcher bounds its own temp dir only; worker can write elsewhere',
    },
  ]
  return deepFreeze(entries)
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
 *   invocation_evidence_verified:boolean, invocation_evidence:object|null,
 *   observations:Array<object>, artifact_refs:Array<object>, diagnostics:Array<unknown>, reason_codes:unknown[] }} AttemptTerminal
 * @typedef {{ pid_alive:boolean, temp_removed:boolean }} ReclaimReport
 */

/**
 * 构造 local-worker-json / L1 子进程 adapter。
 *
 * @param {{workerEntry:string, runId?:string, maxFrameBytes?:number, maxOutputBytes?:number,
 *   maxAttachmentBytes?:number, maxArtifactBytes?:number, timeoutMs?:number, graceMs?:number,
 *   maxContextBytes?:number,
 *   toolBindings?:Record<string,{manifest:object,artifactPath:string,workspaceRoot:string,toolRef:object}>,
 *   capabilitySnapshotRefs?:Record<string,string>,
 *   policyAllowed?:Record<string,string[]>}} [opts]
 */
export function makeSubprocessAdapter(opts = {}) {
  const workerEntry = normalizeWorkerEntry(opts.workerEntry)
  const maxFrameBytes = opts.maxFrameBytes ?? MAX_FRAME_BYTES
  const maxOutputBytes = opts.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES
  const maxAttachmentBytes = opts.maxAttachmentBytes ?? DEFAULT_MAX_ATTACHMENT_BYTES
  const maxArtifactBytes = opts.maxArtifactBytes ?? DEFAULT_MAX_ARTIFACT_BYTES
  const timeoutMs = opts.timeoutMs ?? 15000
  const graceMs = opts.graceMs ?? 3000
  const runId = opts.runId ?? `run-subprocess-${Date.now().toString(36)}`
  const pinnedToolContext = createPinnedToolContext(opts.toolBindings, opts.capabilitySnapshotRefs)
  const policyAllowed = normalizePolicyAllowed(opts.policyAllowed)
  const toolMode = pinnedToolContext !== null
  // 常驻 worker：run 生命周期/owner anchor + control-protocol built-in ops。
  const persistentEntry = toolMode
    ? fileURLToPath(new URL('../worker/host.js', import.meta.url))
    : workerEntry
  // 一次性 tool witness worker：固定引导入口（不得由 manifest/caller 选择）。
  const invocationEntry = fileURLToPath(new URL('../worker/host.js', import.meta.url))
  const maxContextBytes = opts.maxContextBytes ?? maxFrameBytes
  const runtimeAnchor = normalizeRuntimeAnchor(opts.runtimeAnchor)
  const workerEnv = buildWorkerEnvironment(process.env)
  const safeRunId = String(runId).replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 96) || 'run'
  const grants = buildLaunchGrants(pinnedToolContext, policyAllowed)
  const limitsEnforcement = buildLimitsEnforcement({
    pinned: pinnedToolContext, maxFrameBytes, maxOutputBytes, maxAttachmentBytes, maxContextBytes, timeoutMs,
  })

  let tempDir = null
  let contextPath = null
  let persistentChild = null
  let persistentPid = null
  let started = false
  let reapedFlag = false
  let cancelled = false
  /** @type {'idle'|'booting'|'ready'|'running'|'stopping'|'failed'|'reaped'} */
  let state = 'idle'

  let reapPromise = null
  let cancelTimer = null
  let attemptCounter = 0
  /** 常驻 worker 上当前 control attempt 的 waiter（串行，同一时刻至多一个）。 */
  let controlWaiter = null
  /** @type {null|{kind:'control'|'tool', request_id:string, cancel?:()=>void}} */
  let inFlight = null
  const seenRequestIds = new Set()
  const trackedPids = new Set()
  const liveChildren = new Set()
  /** Runner grandchildren currently known to be alive (cleanup coordination markers). */
  const liveRunnerChildPids = new Set()
  /** @type {Map<string, Readonly<object>>} attemptKey -> invocation start event */
  const witnessRecords = new Map()

  const attemptKey = (testId, attempt) => `${testId}\u0000${attempt}`

  /**
   * 消费 worker 的 stderr 清理标记（由可信 runner 写出，仅用于进程树回收）：
   *   `[dsh-testbed-cleanup] child_spawn pid=<n>`
   *   `[dsh-testbed-cleanup] child_exit pid=<n>`
   * 标记不是协议帧，也**不是** invocation start 证据；其他 stderr 字节仍计入输出上限。
   */
  function recordCleanupMarker(line) {
    if (!line.startsWith(`${WORKER_CHILD_CLEANUP_MARKER} `)) return false
    const match = /^(child_spawn|child_exit) pid=(\d+)$/.exec(line.slice(WORKER_CHILD_CLEANUP_MARKER.length + 1))
    if (!match) return false
    const pid = Number(match[2])
    if (!Number.isSafeInteger(pid) || pid < 1) return true
    if (match[1] === 'child_spawn') {
      liveRunnerChildPids.add(pid)
    } else {
      liveRunnerChildPids.delete(pid)
    }
    return true
  }

  /** stderr line consumer：清理标记不占输出字节，其余字节按原语义计数。 */
  function makeStderrConsumer(onBytes) {
    let buffer = ''
    return (chunk) => {
      buffer += chunk
      let idx
      while ((idx = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, idx)
        buffer = buffer.slice(idx + 1)
        if (recordCleanupMarker(line)) continue
        onBytes(Buffer.byteLength(line, 'utf8') + 1)
      }
      // 不能构成清理标记前缀的残行立即计费，避免无换行 stderr 逃过上界。
      const isMarkerPrefix = buffer.length <= WORKER_CHILD_CLEANUP_MARKER.length
        ? WORKER_CHILD_CLEANUP_MARKER.startsWith(buffer)
        : buffer.startsWith(WORKER_CHILD_CLEANUP_MARKER)
      if (buffer.length > 0 && !isMarkerPrefix) {
        onBytes(Buffer.byteLength(buffer, 'utf8'))
        buffer = ''
      }
      if (buffer.length > 8192) {
        onBytes(Buffer.byteLength(buffer, 'utf8'))
        buffer = ''
      }
    }
  }

  function rootPids() {
    const pids = new Set(trackedPids)
    if (persistentPid) pids.add(persistentPid)
    for (const child of liveChildren) {
      if (Number.isSafeInteger(child.pid)) pids.add(child.pid)
    }
    return [...pids].filter((pid) => Number.isSafeInteger(pid) && pid > 0)
  }

  /** 在任何 resolve 之前等待当前所有 worker 根 + 已知 runner 孙进程终止（fail-closed）。 */
  async function terminateLiveTrees({ graceful = false } = {}) {
    // Up to two passes: a grandchild may be re-parented while the root is being
    // terminated; the second pass kills any remaining known child directly.
    for (let pass = 0; pass < 2; pass += 1) {
      const knownChildren = [...liveRunnerChildPids]
      const roots = rootPids()
      const anyLive = roots.some(isPidAlive) || knownChildren.some(isPidAlive)
      if (!anyLive) break
      for (const root of roots) {
        if (!isPidAlive(root) && !knownChildren.some(isPidAlive)) continue
        await terminateProcessTree(root, {
          knownChildPids: knownChildren,
          graceMs: graceful ? graceMs : 0,
          timeoutMs: REAP_TIMEOUT_MS,
        })
      }
      // Root may already be gone while a known grandchild survives; kill it directly.
      for (const childPid of knownChildren) {
        if (isPidAlive(childPid)) {
          await terminateProcessTree(childPid, { graceMs: 0, timeoutMs: REAP_TIMEOUT_MS })
        }
      }
    }
    const observed = [...new Set([...rootPids(), ...[...liveRunnerChildPids]])]
    await waitForPidsGone(observed, { timeoutMs: REAP_TIMEOUT_MS })
  }

  function spawnOptions() {
    const options = {
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false,
      windowsHide: true,
      env: workerEnv,
    }
    if (process.platform !== 'win32') options.detached = true
    return options
  }

  /** 固定参数数组（无 shell 拼接）；runtime anchor 只来自可信 constructor 配置。 */
  function workerArgs(entry, contextFile = null) {
    const args = [entry]
    if (contextFile) args.push('--worker-context', contextFile)
    if (runtimeAnchor !== null) args.push(RUNTIME_ANCHOR_ARG, runtimeAnchor)
    return args
  }

  function transition(next) {
    state = next
  }

  function finishAttempt(marker) {
    if (inFlight === marker) inFlight = null
    if (state === 'running') transition(cancelled ? 'stopping' : 'ready')
  }

  /** 常驻 worker 的退出处理：in-flight attempt 由 stream waiter 结算；空闲退出记 failed。 */
  function onPersistentExit() {
    if (!started || reapedFlag) return
    if (!inFlight) transition('failed')
  }

  function attachPersistentStreams() {
    const child = persistentChild
    let lineBuf = ''
    child.stdout.setEncoding('utf8')
    child.stdout.on('data', (chunk) => {
      const chunkBytes = Buffer.byteLength(chunk, 'utf8')
      if (!controlWaiter) {
        void terminateProcessTree(child.pid, { knownChildPids: [...liveRunnerChildPids], timeoutMs: REAP_TIMEOUT_MS })
        return
      }
      controlWaiter.onOutputBytes(chunkBytes)
      if (!controlWaiter) return
      lineBuf += chunk
      if (Buffer.byteLength(lineBuf, 'utf8') > maxFrameBytes && !lineBuf.includes('\n')) {
        if (controlWaiter) controlWaiter.onOutputBytes(maxOutputBytes + 1)
        lineBuf = ''
        return
      }
      let idx
      while ((idx = lineBuf.indexOf('\n')) >= 0) {
        const line = lineBuf.slice(0, idx)
        lineBuf = lineBuf.slice(idx + 1)
        const active = controlWaiter
        if (active) active.onLine(line)
        if (Buffer.byteLength(lineBuf, 'utf8') > maxFrameBytes && !lineBuf.includes('\n')) {
          if (controlWaiter) controlWaiter.onOutputBytes(maxOutputBytes + 1)
          lineBuf = ''
          return
        }
      }
    })
    child.stdout.on('end', () => {
      if (controlWaiter) controlWaiter.onStdioEnd()
    })
    child.stderr.on('data', makeStderrConsumer((size) => {
      if (controlWaiter) controlWaiter.onOutputBytes(size)
    }))
    child.on('exit', () => {
      if (controlWaiter) controlWaiter.onExit()
    })
    child.on('error', () => {
      if (controlWaiter) controlWaiter.onExit()
    })
  }

  /**
   * 幂等回收：终止并**等待确认**完整进程树（含 worker 根与 runner 孙进程）+
   * 删除临时目录，实测核验。`pid_alive` 覆盖实际观察到的树，不以 exit code 替代验收。
   */
  function reap() {
    if (reapPromise) return reapPromise
    reapPromise = (async () => {
      if (cancelTimer) {
        clearTimeout(cancelTimer)
        cancelTimer = null
      }
      await terminateLiveTrees({ graceful: false })
      // Wait only for the tree actually observed for this adapter run (live roots
      // + runner grandchildren with a live marker). Exited historical PIDs are
      // intentionally excluded: Windows may recycle an exited PID for an
      // unrelated concurrent process, and waiting on it would turn PID reuse
      // into a false "residual tree" report.
      const observed = [...new Set([...rootPids(), ...[...liveRunnerChildPids]])]
      const gone = await waitForPidsGone(observed, { timeoutMs: REAP_TIMEOUT_MS })

      try {
        await rm(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 })
      } catch {
        /* 忽略：下面用存在性核验 temp_removed */
      }
      const tempRemoved = !(await pathExists(tempDir))

      reapedFlag = true
      transition('reaped')
      return { pid_alive: !gone.ok, temp_removed: tempRemoved }
    })()
    return reapPromise
  }

  function start() {
    if (reapedFlag) throw new Error('makeSubprocessAdapter.start: adapter already reaped')
    if (started) return { pid: persistentPid }
    transition('booting')
    try {
      assertWorkerEntry(persistentEntry, 'makeSubprocessAdapter: persistent worker entry')
      assertWorkerEntry(invocationEntry, 'makeSubprocessAdapter: invocation worker entry')
      assertPinnedPathsResolvable(pinnedToolContext)
      tempDir = mkdtempSync(join(tmpdir(), `dsh-testbed-${safeRunId}-`))
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
      const args = workerArgs(persistentEntry, toolMode ? contextPath : null)
      persistentChild = spawn(process.execPath, args, spawnOptions())
      persistentPid = persistentChild.pid
      persistentChild.on('error', () => { /* spawn 失败在 start() 同步检查；此处防止未处理 error */ })
      if (!Number.isSafeInteger(persistentPid) || persistentPid < 1) {
        throw new Error('makeSubprocessAdapter.start: worker entry failed to spawn')
      }
      trackedPids.add(persistentPid)
      liveChildren.add(persistentChild)
      started = true
      transition('ready')
      attachPersistentStreams()
      persistentChild.on('exit', onPersistentExit)
      return { pid: persistentPid }
    } catch (error) {
      if (persistentChild) {
        try { killProcessTree(persistentChild.pid) } catch { /* 忽略 */ }
      }
      if (tempDir) rmSync(tempDir, { recursive: true, force: true })
      tempDir = null
      contextPath = null
      persistentChild = null
      persistentPid = null
      transition('failed')
      throw error
    }
  }

  /**
   * 幂等取消：转发取消语义。工具 attempt 的取消在 `done()` 内等待完整进程树终止后
   * 才 resolve；这里只调度 graceMs 后的兜底终止（避免先杀死根进程导致子进程成为孤儿）。
   */
  function cancel() {
    if (reapedFlag || cancelled) return
    cancelled = true
    transition('stopping')
    const active = inFlight
    if (typeof active?.cancel === 'function') {
      try { active.cancel() } catch { /* cancel 只是转发；reap 实测清理 */ }
    } else if (persistentChild) {
      try { persistentChild.stdin?.end() } catch { /* 忽略 */ }
      try { persistentChild.kill('SIGTERM') } catch { /* 忽略 */ }
    }
    if (cancelTimer) clearTimeout(cancelTimer)
    cancelTimer = setTimeout(() => {
      void terminateLiveTrees({ graceful: false })
    }, graceMs)
    cancelTimer.unref?.()
  }

  function assertRunReady() {
    if (reapedFlag) return 'no-response'
    if (!started) return 'no-response'
    if (cancelled) return 'cancelled'
    return null
  }

  function failed(reason, invocation = 'unknown', admission = 'accepted', execution = 'error') {
    return makeTerminal({
      admission_status: admission,
      execution_status: execution,
      invocation_status: invocation,
      reason_codes: [reason],
    })
  }

  function makeTerminal({
    admission_status = 'accepted', execution_status, invocation_status = 'unknown',
    witness = null, observations = [], artifact_refs = [], diagnostics = [], reason_codes = [],
  }) {
    if (!EXECUTION_STATUS.includes(execution_status)) execution_status = 'error'
    const verified = witness !== null && invocation_status === 'started' && witness?.verified === true
    if (!verified && invocation_status === 'started') invocation_status = 'unknown'
    if (!INVOCATION_STATUS.includes(invocation_status)) invocation_status = 'unknown'
    return {
      admission_status,
      execution_status,
      invocation_status: verified ? 'started' : invocation_status,
      invocation_evidence_verified: verified,
      invocation_evidence: verified ? witness : null,
      // Only written when a control-verified start event exists (§6.1 / §9.5).
      started_at: verified ? witness.started_at : null,
      // adapter 绝不下发 verdict / GateDecision / required / expected / plan 修改。
      observations,
      artifact_refs,
      diagnostics,
      reason_codes,
    }
  }

  /** control-protocol/v1：常驻 worker，串行；worker started 帧只作通知，不产出启动见证。 */
  function executeControlAttempt(req) {
    let requestFrame
    let line
    try {
      requestFrame = buildRequestFrame({ ...req, deadline_ms: timeoutMs })
      line = JSON.stringify(requestFrame)
      const wireFrame = JSON.parse(line)
      const shape = assertFrameShape(wireFrame)
      if (!shape.ok) return Promise.resolve(failed(shape.reason_code ?? 'unknown-field', 'not-started'))
    } catch {
      return Promise.resolve(failed('unknown-field', 'not-started'))
    }
    if (Buffer.byteLength(line, 'utf8') > maxFrameBytes) {
      return Promise.resolve(failed('oversize', 'not-started'))
    }
    seenRequestIds.add(req.request_id)
    const dispatchedAt = Date.now()
    const deadlineAt = dispatchedAt + timeoutMs
    transition('running')

    return new Promise((resolveResult) => {
      let settled = false
      let outputBytes = 0
      let responded = false
      let deadlineTimer = null
      const marker = { kind: 'control', request_id: req.request_id, cancel: null }
      const matchesCorrelation = (frame) => CORRELATION_KEYS.every((key) => frame[key] === requestFrame[key])
      const matchesTool = (value) => requestFrame.tool_ref === null
        ? value === null || value === undefined
        : sameToolRef(value, requestFrame.tool_ref)

      const done = (result, { terminate = false } = {}) => {
        if (settled) return
        settled = true
        if (deadlineTimer) clearTimeout(deadlineTimer)
        controlWaiter = null
        const finalize = () => {
          finishAttempt(marker)
          resolveResult(makeTerminal({ ...result, witness: null }))
        }
        if (!terminate) return finalize()
        // reject/timeout 会终止常驻 worker：等待完整树终止后再 resolve。
        const knownChildren = [...liveRunnerChildPids]
        void (async () => {
          try {
            await terminateProcessTree(persistentPid, { knownChildPids: knownChildren, timeoutMs: REAP_TIMEOUT_MS })
          } catch {
            /* fail-closed：reap() 的实测报告暴露残留 */
          } finally {
            if (persistentChild) liveChildren.delete(persistentChild)
            finalize()
          }
        })()
      }
      const rejectWith = (reasonCode, execution = 'error') => {
        return done({
          admission_status: 'accepted', execution_status: execution,
          invocation_status: 'unknown',
          observations: [], artifact_refs: [], diagnostics: [], reason_codes: [reasonCode],
        }, { terminate: true })
      }
      const waiter = {
        onOutputBytes(size) {
          if (settled) return
          outputBytes += size
          if (outputBytes > maxOutputBytes) rejectWith('oversize')
        },
        onLine(rawLine) {
          if (settled) return
          if (Buffer.byteLength(rawLine, 'utf8') > maxFrameBytes) return rejectWith('oversize')
          if (Date.now() > deadlineAt) return rejectWith('deadline', 'timeout')
          let frame
          try { frame = JSON.parse(rawLine) } catch { return rejectWith('unknown-field') }
          const shape = assertFrameShape(frame)
          if (!shape.ok) return rejectWith(shape.reason_code ?? 'unknown-field')
          if (!matchesCorrelation(frame) || !matchesTool(frame.tool_ref)) return rejectWith('correlation-mismatch')
          if (frame.kind === 'started') {
            // 已验证的 worker 通知；control-plane 无独立 OS 启动事实 → 永不升级为 started。
            return
          }
          if (frame.kind === 'response') {
            responded = true
            return done({
              admission_status: 'accepted',
              execution_status: EXECUTION_STATUS.includes(frame.execution_status) ? frame.execution_status : 'error',
              invocation_status: 'unknown',
              observations: normalizeObservations(frame.observations),
              artifact_refs: Array.isArray(frame.artifact_refs) ? frame.artifact_refs : [],
              diagnostics: Array.isArray(frame.diagnostics) ? frame.diagnostics : [],
              reason_codes: Array.isArray(frame.reason_codes) ? Array.from(frame.reason_codes) : [],
            })
          }
          return rejectWith('unknown-field')
        },
        onStdioEnd() {
          if (settled || responded) return
          if (cancelled) {
            return done({
              admission_status: 'accepted', execution_status: 'cancelled', invocation_status: 'unknown',
              observations: [], artifact_refs: [], diagnostics: [], reason_codes: ['cancelled'],
            })
          }
          done({
            admission_status: 'accepted', execution_status: 'error', invocation_status: 'unknown',
            observations: [], artifact_refs: [], diagnostics: [], reason_codes: ['worker-crash'],
          })
        },
        onExit() {
          if (settled) return
          const status = cancelled ? 'cancelled' : 'error'
          done({
            admission_status: 'accepted', execution_status: status,
            invocation_status: 'unknown', observations: [], artifact_refs: [], diagnostics: [],
            reason_codes: [cancelled ? 'cancelled' : 'worker-crash'],
          })
        },
      }
      marker.cancel = () => {
        try { persistentChild.stdin.end() } catch { /* 忽略 */ }
        try { persistentChild.kill('SIGTERM') } catch { /* 忽略 */ }
      }
      inFlight = marker
      controlWaiter = waiter
      deadlineTimer = setTimeout(() => {
        if (settled) return
        done({
          admission_status: 'accepted', execution_status: 'timeout', invocation_status: 'unknown',
          observations: [], artifact_refs: [], diagnostics: [], reason_codes: ['deadline'],
        }, { terminate: true })
      }, timeoutMs)
      persistentChild.stdin.write(line + '\n', (err) => {
        if (err && !settled) {
          done({
            admission_status: 'accepted', execution_status: 'error', invocation_status: 'unknown',
            observations: [], artifact_refs: [], diagnostics: [], reason_codes: ['no-response'],
          })
        }
      })
    })
  }

  function writeInvocationContext(testId, binding, capabilityRef) {
    if (!tempDir) throw new Error('makeSubprocessAdapter.execute: adapter is not started')
    const context = {
      schema_version: WORKER_CONTEXT_VERSION,
      bindings: { [testId]: binding },
      capability_snapshot_refs: { [testId]: capabilityRef },
    }
    const contextJson = JSON.stringify(context)
    if (Buffer.byteLength(contextJson, 'utf8') > maxContextBytes) {
      throw new Error('makeSubprocessAdapter.execute: pinned worker context exceeds maxContextBytes')
    }
    const path = join(tempDir, `invocation-${++attemptCounter}-${randomBytes(8).toString('hex')}.json`)
    writeFileSync(path, contextJson, { encoding: 'utf8', flag: 'wx', mode: 0o600 })
    chmodSync(path, 0o600)
    return path
  }

  /**
   * adapter 侧派发前 admission：只有全部通过才允许 spawn 一次性 L1 子进程，
   * 使「OS 进程创建」与「该 attempt 已被准入执行」严格对应。
   */
  async function admitToolAttempt(req) {
    const binding = pinnedToolContext.bindings[req.test_id]
    const expectedCapabilityRef = pinnedToolContext.capability_snapshot_refs[req.test_id]
    if (!binding || !sameToolRef(req.tool_ref, binding.toolRef) || req.capability_snapshot_ref !== expectedCapabilityRef) {
      return { ok: false, terminal: failed('correlation-mismatch', 'not-started') }
    }
    const requestedDeadline = Date.parse(req.deadline)
    if (!Number.isFinite(requestedDeadline)) {
      return { ok: false, terminal: failed('unknown-field', 'not-started') }
    }
    let requestFrame
    try {
      const { protocol_version: _protocolVersion, ...params } = req
      requestFrame = buildToolRequestFrame({
        ...params,
        deadline: new Date(Math.min(requestedDeadline, Date.now() + timeoutMs)).toISOString(),
      })
    } catch {
      return { ok: false, terminal: failed('unknown-field', 'not-started') }
    }
    const line = JSON.stringify(requestFrame)
    if (Buffer.byteLength(line, 'utf8') > maxFrameBytes) {
      return { ok: false, terminal: failed('oversize', 'not-started') }
    }
    // 以下预检使 spawn 只发生在「已准入且工具工件可执行」的 attempt 上。
    const manifestCheck = validateToolManifest(binding.manifest)
    if (!manifestCheck.ok) {
      return { ok: false, terminal: makeTerminal({ execution_status: 'error', invocation_status: 'not-started', diagnostics: ['tool-manifest-invalid'] }) }
    }
    const inputCheck = validateValue(requestFrame.input, binding.manifest.input_schema)
    if (!inputCheck.ok) {
      return { ok: false, terminal: makeTerminal({ execution_status: 'error', invocation_status: 'not-started', diagnostics: ['tool-input-schema-invalid'] }) }
    }
    let artifactBytes
    try {
      artifactBytes = await readFile(resolve(binding.artifactPath))
    } catch {
      return { ok: false, terminal: makeTerminal({ execution_status: 'error', invocation_status: 'not-started', diagnostics: ['tool-artifact-not-found'] }) }
    }
    if (artifactBytes.byteLength > maxArtifactBytes) {
      return { ok: false, terminal: makeTerminal({ execution_status: 'error', invocation_status: 'not-started', diagnostics: ['tool-artifact-oversize'] }) }
    }
    const digest = `sha256:${createHash('sha256').update(artifactBytes).digest('hex')}`
    if (digest !== binding.toolRef.artifact_digest) {
      return { ok: false, terminal: makeTerminal({ execution_status: 'error', invocation_status: 'not-started', diagnostics: ['tool-digest-mismatch'] }) }
    }

    const deadlineAt = Date.parse(requestFrame.deadline)
    const manifestTimeout = Number(binding.manifest.limits?.timeout_ms) || timeoutMs
    const effectiveTimeoutMs = Math.max(1, Math.min(timeoutMs, manifestTimeout, deadlineAt - Date.now()))
    const outputLimit = Math.min(maxOutputBytes, Number(binding.manifest.limits?.output_bytes) || maxOutputBytes)
    const attachmentLimit = Math.min(maxAttachmentBytes, Number(binding.manifest.limits?.attachment_bytes) || maxAttachmentBytes)
    return {
      ok: true,
      requestFrame,
      line,
      binding,
      capabilityRef: expectedCapabilityRef,
      deadlineAt,
      effectiveTimeoutMs,
      outputLimit,
      attachmentLimit,
    }
  }

  /**
   * test-tool/v1：spawn 一次性固定 worker 子进程；OS `spawn` 事件 = 独立启动见证。
   * worker 的 control-protocol started 帧只校验、不采信；ToolResponse 只作执行结果数据。
   */
  function dispatchInvocationAttempt(admitted, req) {
    return new Promise((resolveResult) => {
      let settled = false
      let spawned = false
      let witness = null
      let outputBytes = 0
      let lineBuf = ''
      let responseSeen = false
      let contextFile = null
      let child = null
      let deadlineTimer = null
      const recordKey = attemptKey(req.test_id, req.attempt)
      const requestFrame = admitted.requestFrame
      const marker = { kind: 'tool', request_id: req.request_id, cancel: null }
      inFlight = marker
      transition('running')

      const matchesCorrelation = (frame) => CORRELATION_KEYS.every((key) => frame[key] === requestFrame[key])
      const matchesTool = (value) => sameToolRef(value, requestFrame.tool_ref)

      /**
       * 结算 attempt。**先等待完整进程树（含 runner 孙进程）终止**，再 resolve：
       * 否则 kernel/测试会在 worker 根已退出、孙进程仍持有 workspace cwd 时继续，
       * Windows 上会导致 after-hook rmSync 偶发 EPERM。
       */
      const done = (result) => {
        if (settled) return
        settled = true
        if (deadlineTimer) clearTimeout(deadlineTimer)
        if (contextFile) {
          try { rmSync(contextFile, { force: true }) } catch { /* reap 统一清理 tempDir */ }
          contextFile = null
        }
        const knownChildren = [...liveRunnerChildPids]
        void (async () => {
          try {
            const childPid = child && Number.isSafeInteger(child.pid) ? child.pid : null
            const childAlive = childPid !== null && isPidAlive(childPid)
            if (childAlive) {
              await terminateProcessTree(childPid, {
                knownChildPids: knownChildren,
                graceMs: cancelled ? graceMs : 0,
                timeoutMs: REAP_TIMEOUT_MS,
              })
            } else {
              // Root already exited (or never spawned): known runner grandchildren
              // must still be terminated directly instead of resolving over them.
              for (const childPidToKill of knownChildren) {
                if (isPidAlive(childPidToKill)) {
                  await terminateProcessTree(childPidToKill, { graceMs: 0, timeoutMs: REAP_TIMEOUT_MS })
                }
              }
            }
            // Final complete-tree confirmation. Re-snapshot the live marker set so
            // a `child_spawn` marker observed during/after termination is included.
            const observed = [...new Set([
              ...(childPid === null ? [] : [childPid]),
              ...knownChildren,
              ...[...liveRunnerChildPids],
            ])]
            await waitForPidsGone(observed, { timeoutMs: REAP_TIMEOUT_MS })
          } catch {
            /* fail-closed：残留由 reap() 的实测报告暴露 */
          } finally {
            if (child) liveChildren.delete(child)
            finishAttempt(marker)
            resolveResult(makeTerminal({ ...result, witness }))
          }
        })()
      }
      const rejectWith = (reasonCode, execution = 'error') => {
        done({
          admission_status: 'accepted', execution_status: execution,
          invocation_status: witness ? 'started' : 'unknown',
          observations: [], artifact_refs: [], diagnostics: [], reason_codes: [reasonCode],
        })
      }

      try {
        contextFile = writeInvocationContext(req.test_id, admitted.binding, admitted.capabilityRef)
        child = spawn(process.execPath, workerArgs(invocationEntry, contextFile), spawnOptions())
      } catch {
        return done({
          admission_status: 'accepted', execution_status: 'error', invocation_status: 'not-started',
          observations: [], artifact_refs: [], diagnostics: [], reason_codes: ['no-response'],
        })
      }
      liveChildren.add(child)

      child.once('spawn', () => {
        spawned = true
        trackedPids.add(child.pid)
        // === 独立启动见证：控制面自己发起的 OS 进程创建，correlation 由 adapter 固定 ===
        try {
          witness = createInvocationStartEvent({
            correlation: {
              request_id: requestFrame.request_id,
              run_id: requestFrame.run_id,
              plan_id: requestFrame.plan_id,
              test_id: requestFrame.test_id,
              attempt: requestFrame.attempt,
              tool_ref: requestFrame.tool_ref,
            },
            pid: child.pid,
            launcherPid: process.pid,
            startedAt: new Date().toISOString(),
            pidAliveAtWitness: isPidAlive(child.pid),
          })
          witnessRecords.set(recordKey, witness)
        } catch {
          witness = null
        }
      })

      const attachStdout = () => {
        child.stdout.setEncoding('utf8')
        child.stdout.on('data', (chunk) => {
          if (settled) return
          const size = Buffer.byteLength(chunk, 'utf8')
          outputBytes += size
          if (outputBytes > admitted.outputLimit) {
            return rejectWith('oversize')
          }
          lineBuf += chunk
          if (Buffer.byteLength(lineBuf, 'utf8') > maxFrameBytes && !lineBuf.includes('\n')) {
            return rejectWith('oversize')
          }
          let idx
          while ((idx = lineBuf.indexOf('\n')) >= 0) {
            const line = lineBuf.slice(0, idx)
            lineBuf = lineBuf.slice(idx + 1)
            handleLine(line)
            if (settled) return
          }
        })
        child.stdout.on('end', () => {
          if (settled || responseSeen) return
          rejectWith('worker-crash')
        })
        child.stderr.on('data', makeStderrConsumer((size) => {
          if (settled) return
          outputBytes += size
          if (outputBytes > admitted.outputLimit) rejectWith('oversize')
        }))
      }

      const handleLine = (rawLine) => {
        if (rawLine.trim() === '') return
        if (Buffer.byteLength(rawLine, 'utf8') > maxFrameBytes) return rejectWith('oversize')
        if (Date.now() > admitted.deadlineAt) return rejectWith('deadline', 'timeout')
        let frame
        try { frame = JSON.parse(rawLine) } catch { return rejectWith('unknown-field') }
        // 一次性 worker 会先发一条 control-protocol started 通知（仅 notification，绝不采信）。
        if (frame?.protocol_version === CONTROL_PROTOCOL_VERSION && frame.kind === 'started') {
          const shape = assertFrameShape(frame)
          if (!shape.ok) return rejectWith(shape.reason_code ?? 'unknown-field')
          if (!matchesCorrelation(frame) || !matchesTool(frame.tool_ref)) return rejectWith('correlation-mismatch')
          return
        }
        if (frame?.protocol_version === TEST_TOOL_PROTOCOL_VERSION && frame.kind === undefined) {
          const checked = assertToolResponse(frame, requestFrame, { maxBytes: maxFrameBytes })
          if (!checked.ok) return rejectWith(checked.reason_code ?? 'unknown-field')
          const attachmentBytes = frame.artifact_refs.reduce((sum, ref) => sum + ref.size_bytes, 0)
          if (attachmentBytes > admitted.attachmentLimit) return rejectWith('oversize')
          responseSeen = true
          return done({
            admission_status: 'accepted',
            execution_status: frame.execution_status,
            invocation_status: witness ? 'started' : 'unknown',
            observations: normalizeObservations(frame.observations),
            artifact_refs: frame.artifact_refs,
            diagnostics: frame.diagnostics,
            reason_codes: [],
          })
        }
        return rejectWith('unknown-field')
      }

      child.on('error', () => {
        if (settled) return
        if (!spawned) {
          return done({
            admission_status: 'accepted', execution_status: 'error', invocation_status: 'not-started',
            observations: [], artifact_refs: [], diagnostics: [], reason_codes: ['no-response'],
          })
        }
        rejectWith('worker-crash')
      })
      child.on('exit', () => {
        if (settled) return
        if (cancelled) {
          return done({
            admission_status: 'accepted', execution_status: 'cancelled',
            invocation_status: witness ? 'started' : 'unknown',
            observations: [], artifact_refs: [], diagnostics: [], reason_codes: ['cancelled'],
          })
        }
        if (!responseSeen) rejectWith('worker-crash')
      })
      attachStdout()

      marker.cancel = () => {
        if (settled) return
        // 不在 done() 前单独 SIGTERM 根进程：Windows 上根先死会使 /T 无法枚举
        // runner 孙进程；done() 会等待完整进程树终止后再 resolve。
        done({
          admission_status: 'accepted', execution_status: 'cancelled',
          invocation_status: witness ? 'started' : 'unknown',
          observations: [], artifact_refs: [], diagnostics: [], reason_codes: ['cancelled'],
        })
      }

      deadlineTimer = setTimeout(() => {
        if (settled) return
        done({
          admission_status: 'accepted', execution_status: 'timeout',
          invocation_status: witness ? 'started' : 'unknown',
          observations: [], artifact_refs: [], diagnostics: [], reason_codes: ['deadline'],
        })
      }, admitted.effectiveTimeoutMs)

      child.stdin.write(admitted.line + '\n', (err) => {
        if (err && !settled) rejectWith('no-response')
        if (!err) {
          try { child.stdin.end() } catch { /* 忽略 */ }
        }
      })
    })
  }

  /** test-tool/v1 入口：先在 adapter 侧完成准入，再 spawn 一次性见证子进程。 */
  async function executeToolAttempt(req) {
    const admissionMarker = { kind: 'tool', request_id: req.request_id, cancel: null }
    inFlight = admissionMarker
    transition('running')
    let admitted
    try {
      admitted = await admitToolAttempt(req)
    } catch {
      admitted = { ok: false, terminal: failed('unknown-field', 'not-started') }
    }
    if (!admitted.ok) {
      finishAttempt(admissionMarker)
      return admitted.terminal
    }
    if (reapedFlag) {
      finishAttempt(admissionMarker)
      return failed('no-response', 'not-started')
    }
    if (cancelled) {
      finishAttempt(admissionMarker)
      return failed('cancelled', 'not-started')
    }
    seenRequestIds.add(req.request_id)
    inFlight = null // dispatchInvocationAttempt 会安装真正的 in-flight marker
    return dispatchInvocationAttempt(admitted, req)
  }

  /**
   * 执行一个 legacy control request 或严格 test-tool/v1 request。
   * 只有 test-tool attempt 有独立 OS 启动见证；其余路径保持 `unknown`。
   * @param {Request|object} req
   * @returns {Promise<AttemptTerminal>}
   */
  function execute(req) {
    const notReadyReason = assertRunReady()
    if (notReadyReason) return Promise.resolve(failed(notReadyReason, 'not-started'))
    if (inFlight !== null) return Promise.resolve(failed('out-of-order', 'unknown'))
    if (!isPlainRecord(req)) return Promise.resolve(failed('unknown-field', 'not-started'))
    const protocolVersion = req.protocol_version
    if (protocolVersion !== undefined &&
        protocolVersion !== TEST_TOOL_PROTOCOL_VERSION &&
        protocolVersion !== CONTROL_PROTOCOL_VERSION) {
      return Promise.resolve(failed('unknown-version', 'not-started'))
    }
    if (typeof req.request_id !== 'string' || req.request_id.length === 0) {
      return Promise.resolve(failed('unknown-field', 'not-started'))
    }
    if (seenRequestIds.has(req.request_id)) return Promise.resolve(failed('duplicate', 'unknown'))
    if (protocolVersion === TEST_TOOL_PROTOCOL_VERSION) {
      if (!toolMode) return Promise.resolve(failed('unknown-field', 'not-started'))
      return executeToolAttempt(req)
    }
    return executeControlAttempt(req)
  }

  /**
   * 控制面获取独立启动见证（DispatchPort 契约）。
   * 只返回 adapter 自己经 OS spawn 事实记录的事件；其余情况一律 `null` → control 记 `unknown`。
   *
   * @param {{run_id?:string}|string|null|undefined} workerRef
   * @param {string} testId
   * @param {number} attempt
   * @returns {Readonly<object>|null}
   */
  function reportInvocationStart(workerRef, testId, attempt) {
    let refRunId = runId
    if (typeof workerRef === 'string') refRunId = workerRef
    else if (isPlainRecord(workerRef)) {
      refRunId = workerRef.run_id ?? workerRef.runId ?? null
      if (typeof refRunId !== 'string') return null
    } else if (workerRef !== undefined && workerRef !== null) return null
    if (refRunId !== runId) return null
    if (typeof testId !== 'string' || testId.length === 0) return null
    if (!Number.isSafeInteger(attempt) || attempt < 1) return null
    return witnessRecords.get(attemptKey(testId, attempt)) ?? null
  }

  return {
    adapterRef: ADAPTER_REF,
    runId,
    start,
    execute,
    cancel,
    reap,
    reportInvocationStart,
    get state() { return state },
    get launchRecord() {
      return deepFreeze({
        adapter_ref: ADAPTER_REF,
        run_id: runId,
        owner: runId,
        isolation: ISOLATION_LEVEL,
        isolation_level: 'L1',
        process_mode: toolMode ? 'run-worker+per-attempt-tool-child' : 'run-worker',
        pid: persistentPid,
        state,
        temp_dir: tempDir,
        temp_dir_owner: runId,
        enforceable: [...ENFORCED_LIMITS],
        unenforced: [...UNENFORCED_RESOURCES],
        limits_enforcement: limitsEnforcement,
        grants,
        policy_allowed: policyAllowed,
        max_frame_bytes: maxFrameBytes,
        max_output_bytes: maxOutputBytes,
        max_attachment_bytes: maxAttachmentBytes,
        max_context_bytes: maxContextBytes,
        timeout_ms: timeoutMs,
        runtime_anchor_configured: runtimeAnchor !== null,
        market_conclusion: 'none',
        trust_scope: 'local-only',
        invocation_witness: {
          kind: INVOCATION_START_KIND,
          mechanism: INVOCATION_WITNESS_MECHANISM,
          source: INVOCATION_WITNESS_SOURCE,
          scope: INVOCATION_WITNESS_SCOPE,
          worker_self_report_used: false,
        },
        limitations: [
          'l1-fault-isolation-is-not-a-security-boundary',
          'filesystem/network/subprocess/devices/cpu/memory are unenforced under L1',
        ],
      })
    },
  }
}

function assertWorkerEntry(entry, label) {
  assertRegularFile(entry, label)
}
