/**
 * 控制面全局聚合资源/运行预算（development-plan §跨阶段不变量 7、architecture §16.1
 * 「资源与信任边界」）。
 *
 * 提供版本化、有边界的 `run-budget/v1` policy：表达「整次运行」的聚合上限
 * （attempts / wall-clock / output / cpu / memory）。控制面据此：
 *   - fail-closed 校验预算本身（schema + 硬平台上限，用户只能收紧不能放宽）；
 *   - 冻结前静态拒绝「声明 attempt 总数超预算」的计划；
 *   - 执行期用 ledger 计量并强制 L1 实际可测的维度（wall-clock、序列化输出字节、
 *     attempt 次数），超限即终止派发并把 run 降为 blocked（`budget-exceeded`）；
 *   - cpu/memory 聚合上限仍写入 schema 与 receipt，但 L1 无法由 OS 强制 → 记
 *     `unenforced`，不得据此下安全结论（与现有 L1 口径一致）。
 *
 * 纯控制面模块：只 import `../protocol/*` 与 `./plan.js` 的硬上限常量，不触碰 worker。
 *
 * Migration phase `pure control`: typed `RunBudget`/`BudgetLedger`, `unknown` at the
 * policy boundary, same rejection codes and clamping semantics as the JS baseline.
 * @module @deepseek-ai/dsh-plugin-testbed/control/budget
 */
import { MAX_PLAN_TOTAL_ATTEMPTS } from './limits.js'
import type { RunBudget, UnknownRecord, ValidationResult } from '../protocol/types.js'

/** 全局预算协议版本。 */
export const RUN_BUDGET_VERSION = 'run-budget/v1'

/** L1 可实际强制的维度（时间 / 输出 / attempts 由控制面计量）。 */
export const BUDGET_ENFORCED_AT_L1 = Object.freeze([
  'max_total_time_ms', 'max_total_output_bytes', 'max_total_attempts',
] as const)

/** L1 无法由 OS 强制的维度（只能写入 schema/receipt，记为 `unenforced`）。 */
export const BUDGET_UNENFORCED_AT_L1 = Object.freeze([
  'max_total_cpu_ms', 'max_total_memory_mb',
] as const)

/**
 * 硬平台上限。用户预算只能在此之内收紧；任何超限字段在入口即拒绝。
 * `max_total_attempts` 与 `./plan.js` 的 `MAX_PLAN_TOTAL_ATTEMPTS` 一致（256×3）。
 */
export const PLATFORM_BUDGET_CEILINGS = Object.freeze({
  max_total_attempts: MAX_PLAN_TOTAL_ATTEMPTS,
  max_total_time_ms: 10 * 60 * 1000, // 10 分钟聚合 wall-clock
  max_total_cpu_ms: 10 * 60 * 1000, // 声明值；L1 不强制
  max_total_memory_mb: 4096, // 声明值；L1 不强制
  max_total_output_bytes: 8 * 1024 * 1024, // 8 MiB 聚合序列化输出
})

const BUDGET_FIELDS = Object.freeze(Object.keys(PLATFORM_BUDGET_CEILINGS)) as readonly (keyof typeof PLATFORM_BUDGET_CEILINGS)[]
const KNOWN_FIELDS: readonly string[] = Object.freeze(['schema_version', ...BUDGET_FIELDS])

/** 缺省（用户未提供 `policy.budget` 时生效的）平台预算 = 硬上限本身。 */
export const DEFAULT_RUN_BUDGET: Readonly<RunBudget> = Object.freeze({
  schema_version: RUN_BUDGET_VERSION,
  ...PLATFORM_BUDGET_CEILINGS,
})

/** Fail-closed budget validation result. */
export type BudgetValidation =
  | { ok: true; budget: RunBudget }
  | { ok: false; errors: string[] }

/** Execution-time aggregate meter; only L1-measurable dimensions are recorded. */
export interface BudgetLedger {
  readonly budget: RunBudget
  /** Read-only pre-flight: may one more attempt still be reserved? */
  canReserveAttempt(): boolean
  /** Reserve one attempt before dispatch; reason on exhaustion, else null. */
  reserveAttempt(): string | null
  /** Add actual attempt consumption; reason when the aggregate exceeds budget. */
  record(input: { elapsed_ms?: unknown; output_bytes?: unknown }): string | null
  /** JSON-safe snapshot for the receipt/observability. */
  snapshot(): {
    elapsed_ms: number
    output_bytes: number
    attempts: number
    budget: RunBudget
  }
}

function isPlainRecord(value: unknown): value is UnknownRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

/**
 * 校验 `run-budget/v1`。所有字段必填、为正安全整数且 ≤ 平台硬上限；未知字段拒绝。
 */
export function validateRunBudget(budget: unknown): BudgetValidation {
  const errors: string[] = []
  if (!isPlainRecord(budget)) return { ok: false, errors: ['budget-not-object'] }
  if (budget.schema_version !== RUN_BUDGET_VERSION) errors.push('budget-schema-version-invalid')
  for (const key of Object.keys(budget)) {
    if (!KNOWN_FIELDS.includes(key)) errors.push(`budget-unknown-field:${key}`)
  }
  for (const field of BUDGET_FIELDS) {
    const value = budget[field]
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) errors.push(`budget-${field}-invalid`)
    else if (value > PLATFORM_BUDGET_CEILINGS[field]) errors.push(`budget-${field}-exceeds-ceiling`)
  }
  if (errors.length > 0) return { ok: false, errors }
  return { ok: true, budget: Object.freeze({ schema_version: RUN_BUDGET_VERSION, ...budget }) as RunBudget }
}

/**
 * 解析可选预算：缺省用平台缺省预算，否则 fail-closed 校验。
 */
export function resolveRunBudget(rawBudget: unknown): BudgetValidation {
  if (rawBudget === undefined || rawBudget === null) return { ok: true, budget: DEFAULT_RUN_BUDGET as RunBudget }
  return validateRunBudget(rawBudget)
}

/** 冻结计划声明的最坏 attempt 总数 = Σ 每用例 `retry.max_attempts`（缺省 1）。 */
export function planDeclaredAttempts(cases: unknown): number {
  if (!Array.isArray(cases)) return 0
  return cases.reduce((sum: number, c: unknown) => {
    const record = c !== null && typeof c === 'object' ? (c as UnknownRecord) : undefined
    const retry = record?.retry
    const retryRecord = retry !== null && typeof retry === 'object' ? (retry as UnknownRecord) : undefined
    const maxAttempts = retryRecord?.max_attempts
    return sum + (typeof maxAttempts === 'number' && Number.isSafeInteger(maxAttempts) && maxAttempts >= 1
      ? maxAttempts
      : 1)
  }, 0)
}

/**
 * 冻结前静态断言：计划声明 attempt 总数不得超出聚合预算；超限 fail-closed。
 */
export function assertPlanAttemptsWithinBudget(totalAttempts: number, budget: RunBudget): ValidationResult {
  const maxAttempts = budget?.max_total_attempts
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1) {
    return { ok: false, errors: ['budget-max-total-attempts-invalid'] }
  }
  if (!Number.isSafeInteger(totalAttempts) || totalAttempts < 0) {
    return { ok: false, errors: ['budget-plan-attempts-invalid'] }
  }
  if (totalAttempts > maxAttempts) {
    return { ok: false, errors: [`plan-declared-attempts-exceed-budget:${maxAttempts}`] }
  }
  return { ok: true, errors: [] }
}

/**
 * 创建执行期聚合计量器（JSON-safe）。只在控制面计量 L1 可测维度：
 *   - attempts：每次派发前预留（前置检查，超限则拒绝派发）；
 *   - wall-clock / 输出字节：每次 attempt 结束后按实际值累加；若把聚合推超预算，
 *     返回 `budget-time-exceeded` / `budget-output-exceeded`（run 级 fail-closed）。
 * cpu/memory 不在此计量（L1 不可测），仅随 schema 记录为 `unenforced`。
 */
export function createBudgetLedger(budget: RunBudget): BudgetLedger {
  let elapsedMs = 0
  let outputBytes = 0
  let attempts = 0

  return {
    get budget() { return budget },
    /** 只读前置检查：当前是否仍可预留一个 attempt（不改变计量状态）。 */
    canReserveAttempt(): boolean {
      return attempts + 1 <= budget.max_total_attempts
    },
    /** 派发前预留一个 attempt；超限返回 reason，否则 null。 */
    reserveAttempt(): string | null {
      if (attempts + 1 > budget.max_total_attempts) return 'budget-attempts-exceeded'
      attempts += 1
      return null
    },
    /** attempt 结束后累加实际消耗；把聚合推超预算则返回 reason，否则 null。 */
    record({ elapsed_ms, output_bytes }: { elapsed_ms?: unknown; output_bytes?: unknown }): string | null {
      const e = typeof elapsed_ms === 'number' && Number.isSafeInteger(elapsed_ms) && elapsed_ms >= 0 ? elapsed_ms : 0
      const o = typeof output_bytes === 'number' && Number.isSafeInteger(output_bytes) && output_bytes >= 0 ? output_bytes : 0
      elapsedMs += e
      outputBytes += o
      if (elapsedMs > budget.max_total_time_ms) return 'budget-time-exceeded'
      if (outputBytes > budget.max_total_output_bytes) return 'budget-output-exceeded'
      return null
    },
    snapshot() {
      return {
        elapsed_ms: elapsedMs,
        output_bytes: outputBytes,
        attempts,
        budget,
      }
    },
  }
}
