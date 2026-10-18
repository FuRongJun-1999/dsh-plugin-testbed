/**
 * 控制面侧「独立可核验 invocation start 见证」契约。
 *
 * 权威语义（architecture §9.5 / §16.1，development.md 状态表）：
 * - `invocation_status=started` 只能来自**控制面可核验的调用开始事件**；
 * - 派发请求、worker 自报 `started` 帧、worker 自报时间戳、`ToolResponse`、
 *   `RunSpec` 或任何 caller 字段都**不是**证据；
 * - 无法核实时必须保持 `unknown`，不得猜 `started` 或 `not-started`。
 *
 * 本模块只定义 adapter（控制面 launcher 侧）产出的见证记录结构与合法性校验，
 * **不计算 verdict / GateDecision / required / expected**，也不代表安全隔离：
 * L1 普通同权限子进程只提供故障隔离，不是安全沙箱。
 *
 * 见证来源固定为 adapter 自己发起的 OS 进程创建：
 *   - `mechanism = 'os-child-spawn'`：adapter 用固定 worker 引导入口、参数数组、
 *     `shell:false` spawn 一次性 L1 子进程，并观察 Node `ChildProcess` 的 `spawn`
 *     事件与 `pid`；该事件由 OS 进程创建产生，不是 worker 消息；
 *   - `source = 'control-plane-launcher'`：记录者是控制面 launcher 本身；
 *   - `worker_self_report_used = false`：见证从不读取 worker 的 `started`/时间戳；
 *   - correlation（`request_id/run_id/plan_id/test_id/attempt/tool_ref`）由 adapter
 *     在其 in-flight 表中固定，不从响应回显反推。
 *
 * @module @deepseek-ai/dsh-plugin-testbed/adapters/invocation-witness
 */

import { INVOCATION_STATUS } from '../protocol/enums.js'

/** 见证记录 kind（adapter 内部契约，不是 worker 协议帧）。 */
export const INVOCATION_START_KIND = 'invocation-start/v1'

/** 唯一被接受的启动见证机制：OS 子进程创建（由控制面 launcher 发起）。 */
export const INVOCATION_WITNESS_MECHANISM = 'os-child-spawn'

/** 见证记录来源：控制面 launcher（不是 worker 自报）。 */
export const INVOCATION_WITNESS_SOURCE = 'control-plane-launcher'

/** 见证覆盖范围：每次 test-tool/v1 attempt 的一次性 L1 进程。 */
export const INVOCATION_WITNESS_SCOPE = 'test-tool-attempts'

/** 见证记录必须自带的局限声明（不得把 L1 描述为安全边界）。 */
export const INVOCATION_WITNESS_LIMITATIONS = Object.freeze([
  'l1-fault-isolation-is-not-a-security-boundary',
  'worker-notifications-and-tool-responses-are-not-start-evidence',
])

const SHA256_RE = /^sha256:[0-9a-f]{64}$/
const TOOL_REF_KEYS = ['tool_id', 'version', 'artifact_digest']

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  Object.freeze(value)
  for (const child of Object.values(value)) deepFreeze(child)
  return value
}

/** @param {unknown} value */
export function isInvocationStatus(value) {
  return INVOCATION_STATUS.includes(value)
}

/**
 * 固定 correlation tuple 的合法性（adapter 侧 in-flight 记录，不是响应回显）。
 * @param {unknown} correlation
 * @returns {boolean}
 */
export function isValidInvocationCorrelation(correlation) {
  if (!isPlainRecord(correlation)) return false
  if (!isNonEmptyString(correlation.request_id) || !isNonEmptyString(correlation.run_id) ||
      !isNonEmptyString(correlation.plan_id) || !isNonEmptyString(correlation.test_id)) return false
  if (!Number.isSafeInteger(correlation.attempt) || correlation.attempt < 1) return false
  const toolRef = correlation.tool_ref
  if (!isPlainRecord(toolRef)) return false
  if (Object.keys(toolRef).length !== TOOL_REF_KEYS.length) return false
  if (!TOOL_REF_KEYS.every((key) => isNonEmptyString(toolRef[key]))) return false
  return SHA256_RE.test(toolRef.artifact_digest)
}

/**
 * 构造一条不可变的 invocation start 见证记录。
 *
 * 调用者（adapters/subprocess.js）只能在其自己 spawn 的 OS 子进程 `spawn` 事件
 * 触发后调用；本函数不读取任何 worker 帧、`ToolResponse`、`RunSpec` 或 caller 字段。
 *
 * @param {{ correlation: object, pid: number, launcherPid: number, startedAt: string,
 *   pidAliveAtWitness?: boolean }} input
 * @returns {Readonly<object>} deep-frozen 见证记录
 */
export function createInvocationStartEvent({
  correlation,
  pid,
  launcherPid,
  startedAt,
  pidAliveAtWitness = false,
} = {}) {
  if (!isValidInvocationCorrelation(correlation)) {
    throw new TypeError('createInvocationStartEvent: invalid adapter-fixed correlation tuple')
  }
  if (!Number.isSafeInteger(pid) || pid < 1) {
    throw new TypeError('createInvocationStartEvent: pid must be a positive safe integer')
  }
  if (!Number.isSafeInteger(launcherPid) || launcherPid < 1) {
    throw new TypeError('createInvocationStartEvent: launcherPid must be a positive safe integer')
  }
  if (typeof startedAt !== 'string' || !Number.isFinite(Date.parse(startedAt))) {
    throw new TypeError('createInvocationStartEvent: startedAt must be an RFC 3339 timestamp')
  }
  if (typeof pidAliveAtWitness !== 'boolean') {
    throw new TypeError('createInvocationStartEvent: pidAliveAtWitness must be a boolean')
  }
  return deepFreeze({
    kind: INVOCATION_START_KIND,
    verified: true,
    correlation: {
      request_id: correlation.request_id,
      run_id: correlation.run_id,
      plan_id: correlation.plan_id,
      test_id: correlation.test_id,
      attempt: correlation.attempt,
      tool_ref: {
        tool_id: correlation.tool_ref.tool_id,
        version: correlation.tool_ref.version,
        artifact_digest: correlation.tool_ref.artifact_digest,
      },
    },
    started_at: startedAt,
    isolation: 'L1-subprocess',
    observed: {
      mechanism: INVOCATION_WITNESS_MECHANISM,
      source: INVOCATION_WITNESS_SOURCE,
      worker_self_report_used: false,
      child_pid: pid,
      launcher_pid: launcherPid,
      pid_alive_at_witness: pidAliveAtWitness,
    },
    limitations: INVOCATION_WITNESS_LIMITATIONS,
  })
}
