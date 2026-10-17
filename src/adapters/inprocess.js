/**
 * 控制面侧「进程内」本地 worker adapter / port。
 *
 * 本文件显式声明：这是 **进程内、L0 行为隔离、非安全边界** ——
 *   - 不启动子进程；
 *   - 不使用 `node:vm`；
 *   - 不声明任何 OS / 网络 / 文件系统隔离；
 *   - 不把普通同权限子进程或 `node:vm` 当作安全沙箱。
 *
 * 普通同权限子进程才对应 L1 故障隔离（崩溃/堆/生命周期隔离，仍是「非安全边界」），
 * 本期（M2 前）未实现，留待 M2 的 `src/adapters/` 子进程 launcher / adapter 落地。
 *
 * 本 port 只把 `caseSpec.probe` 里的「进程内 observation 生产者」归一化为 attempt 终态
 * `{ admission_status, execution_status, invocation_status, observations, reason_codes }`：
 *   - 绝不装载 PUT 代码、绝不执行工具、绝不 spawn 进程；
 *   - 绝不产出 `verdict` / `gate_decision` / `required` / `expected` / Plan 修改；
 *   - probe 不能证明受控调用已开始；有 probe 时 `invocation_status` 固定为 `unknown`，
 *     且永不产生可用于 §6.1 放行的独立启动证据。
 *
 * @module @deepseek-ai/dsh-plugin-testbed/adapters/inprocess
 */

/** 隔离等级：进程内、L0 行为隔离、非安全边界（非 L1 子进程、非沙箱）。 */
export const ISOLATION_LEVEL = 'L0-in-process'

/**
 * 归一化单条 observation：强制 `source='worker'`，`limitations` 缺省 `[]`，
 * 保留 `value` 与（可选的）`schema_ref`；`observation_id` 缺省时自动补 `obs-<序号>`（1-based）。
 * @param {object|undefined} obs probe 里的一条 observation
 * @param {number} index 1-based 序号
 * @returns {{ observation_id: string, value: unknown, source: 'worker', limitations: unknown[] , schema_ref?: string }}
 */
function normalizeObservation(obs, index) {
  const normalized = {
    observation_id:
      obs && typeof obs.observation_id === 'string' && obs.observation_id !== ''
        ? obs.observation_id
        : `obs-${index}`,
    value: obs ? obs.value : undefined,
    source: 'worker',
    limitations: Array.isArray(obs && obs.limitations) ? obs.limitations : [],
  }
  if (obs && obs.schema_ref !== undefined && obs.schema_ref !== null) {
    normalized.schema_ref = obs.schema_ref
  }
  return normalized
}

/**
 * 构造进程内 port。`execute` 是无状态的（不跨 case 共享可变状态），
 * 只回传 observation + 执行/启动状态，绝不产出 `verdict` / `gate_decision` /
 * `required` / `expected` / Plan 修改。
 * @returns {{ execute(caseSpec: object): object }}
 */
export function makeInProcessPort() {
  return {
    /**
     * 把单个场景用例（`caseSpec`）归一化为 attempt 终态。
     * - 无 `probe` → `{ admission_status:'rejected', execution_status:'error',
     *   invocation_status:'not-started', observations:[], reason_codes:['no-probe'] }`
     * - 有 `probe` → 逐字段组装：`admission_status='accepted'`，
     *   `execution_status` 缺省 `'completed'`，`invocation_status` 固定 `'unknown'` 且未核验，
     *   `observations` 归一化，`reason_codes` 按输入保留（缺省 `[]`）。
     * @param {object} caseSpec 场景用例（含可选 probe）
     * @returns {{ admission_status:'accepted'|'rejected',
     *   execution_status:'completed'|'skipped'|'error'|'timeout'|'cancelled',
     *   invocation_status:'not-started'|'started'|'unknown',
     *   observations: Array<any>, reason_codes: unknown[] }}
     */
    execute(caseSpec) {
      const probe = caseSpec && caseSpec.probe
      if (!probe) {
        return {
          admission_status: 'rejected',
          execution_status: 'error',
          invocation_status: 'not-started',
          observations: [],
          reason_codes: ['no-probe'],
        }
      }
      const rawObservations = Array.isArray(probe.observations) ? probe.observations : []
      const observations = rawObservations.map((obs, idx) => normalizeObservation(obs, idx + 1))
      return {
        admission_status: 'accepted',
        execution_status: probe.execution_status ?? 'completed',
        // A caller-provided probe is data, not an independently verified start event.
        invocation_status: 'unknown',
        invocation_evidence_verified: false,
        observations,
        reason_codes: Array.isArray(probe.reason_codes) ? Array.from(probe.reason_codes) : [],
      }
    },
  }
}