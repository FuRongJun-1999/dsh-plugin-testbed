/**
 * `src/adapters/` 门面：控制面侧本地 worker adapter 的稳定导入面。
 *
 * 导出两类能力：
 * 1. L1 子进程 adapter（`makeSubprocessAdapter`）：生命周期、传输边界、owner 回收、
 *    权限 requested∩policy∩enforced 留痕与独立 invocation start 见证；
 * 2. 进程内 L0 port（`makeInProcessPort`）：无子进程、无 VM、无安全边界的行为 port。
 *
 * `makeLocalWorkerDispatchPort` 是对 control 设计 §13.1 `DispatchPort` 的最小适配：
 * `startWorker / dispatchToolRequest / reportInvocationStart / cancel / cleanup`。
 * 它只做转发与生命周期编排，**不计算 verdict / GateDecision / required / expected**。
 *
 * @module @deepseek-ai/dsh-plugin-testbed/adapters
 */
export {
  ADAPTER_REF,
  ISOLATION_LEVEL,
  UNENFORCED_RESOURCES,
  ENFORCED_LIMITS,
  DEFAULT_MAX_ARTIFACT_BYTES,
  DEFAULT_MAX_ATTACHMENT_BYTES,
  WORKER_CONTEXT_VERSION,
  RUNTIME_ANCHOR_ARG,
  WORKER_ENV_PASSTHROUGH,
  buildWorkerEnvironment,
  buildLaunchGrants,
  buildLimitsEnforcement,
  isPidAlive,
  killProcessTree,
  makeSubprocessAdapter,
} from './subprocess.js'
export {
  ISOLATION_LEVEL as IN_PROCESS_ISOLATION_LEVEL,
  makeInProcessPort,
} from './inprocess.js'
export {
  INVOCATION_START_KIND,
  INVOCATION_WITNESS_MECHANISM,
  INVOCATION_WITNESS_SCOPE,
  INVOCATION_WITNESS_SOURCE,
  INVOCATION_WITNESS_LIMITATIONS,
  createInvocationStartEvent,
  isInvocationStatus,
  isValidInvocationCorrelation,
} from './invocation-witness.js'

import {
  ADAPTER_REF,
  ENFORCED_LIMITS,
  ISOLATION_LEVEL,
  UNENFORCED_RESOURCES,
  makeSubprocessAdapter,
} from './subprocess.js'

/**
 * 构造 control-plane `DispatchPort` 的最小实现（单 adapter 实例、单 run）。
 *
 * 语义与 control 设计一致：
 * - `reportInvocationStart` 只返回 adapter 自己经 OS spawn 事实核验的事件，否则 `null`
 *   → control 必须写 `invocation_status=unknown`；
 * - `dispatchToolRequest` 的返回是 attempt 终态候选（含 `invocation_evidence`），
 *   不是 verdict/GateDecision；
 * - `cleanup` 幂等返回实测 `{pid_alive, temp_removed}`，不以 exit code 替代验收。
 *
 * @param {object} options `makeSubprocessAdapter` 的构造参数（runId/workerEntry/...）
 */
export function makeLocalWorkerDispatchPort(options = {}) {
  const adapter = makeSubprocessAdapter(options)
  const workerRef = Object.freeze({ adapter_ref: ADAPTER_REF, run_id: adapter.runId })
  let started = false

  return Object.freeze({
    adapter,
    adapterRef: ADAPTER_REF,
    startWorker() {
      if (!started) {
        adapter.start()
        started = true
      }
      return workerRef
    },
    /** 环境/隔离预检：只声明 L1 能/不能强制什么，不产生能力结论。 */
    precheckEnvironment(_workerRef) {
      return Object.freeze({
        adapter_ref: ADAPTER_REF,
        isolation: ISOLATION_LEVEL,
        trust_scope: 'local-only',
        market_conclusion: 'none',
        enforceable: [...ENFORCED_LIMITS],
        unenforced: [...UNENFORCED_RESOURCES],
        launch_record: adapter.launchRecord,
      })
    },
    async dispatchToolRequest(_workerRef, request, signal) {
      if (!started) throw new Error('makeLocalWorkerDispatchPort: startWorker() must be called first')
      const onAbort = () => adapter.cancel()
      signal?.addEventListener?.('abort', onAbort, { once: true })
      try {
        return await adapter.execute(request)
      } finally {
        signal?.removeEventListener?.('abort', onAbort)
      }
    },
    reportInvocationStart(_workerRef, testId, attempt) {
      return adapter.reportInvocationStart(workerRef, testId, attempt)
    },
    cancel(_workerRef) {
      adapter.cancel()
    },
    cleanup(_workerRef) {
      return adapter.reap()
    },
    launchRecord() {
      return adapter.launchRecord
    },
  })
}
