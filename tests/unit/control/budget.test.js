/**
 * 全局聚合预算（control/budget.js）纯函数单元测试。
 * 覆盖：schema/上限 fail-closed 校验、缺省预算解析、计划 attempt 聚合静态断言，
 * 以及执行期 ledger 对 attempts / wall-clock / 输出字节的计量与超限判定。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  RUN_BUDGET_VERSION,
  PLATFORM_BUDGET_CEILINGS,
  DEFAULT_RUN_BUDGET,
  validateRunBudget,
  resolveRunBudget,
  planDeclaredAttempts,
  assertPlanAttemptsWithinBudget,
  createBudgetLedger,
  BUDGET_ENFORCED_AT_L1,
  BUDGET_UNENFORCED_AT_L1,
} from '../../../src/control/budget.js'

const budget = (overrides = {}) => ({
  schema_version: RUN_BUDGET_VERSION,
  max_total_attempts: 768,
  max_total_time_ms: 600_000,
  max_total_cpu_ms: 600_000,
  max_total_memory_mb: 4096,
  max_total_output_bytes: 8 * 1024 * 1024,
  ...overrides,
})

test('budget: 合法 run-budget/v1 通过校验', () => {
  const r = validateRunBudget(budget())
  assert.equal(r.ok, true)
  assert.equal(r.budget.schema_version, RUN_BUDGET_VERSION)
  assert.equal(r.budget.max_total_attempts, 768)
})

test('budget: schema_version 不匹配 → fail-closed', () => {
  const r = validateRunBudget(budget({ schema_version: 'run-budget/v2' }))
  assert.equal(r.ok, false)
  assert.ok(r.errors.includes('budget-schema-version-invalid'))
})

test('budget: 非对象 / 数组 / 标量 → budget-not-object', () => {
  for (const value of [null, [], 'x', 42]) {
    assert.equal(validateRunBudget(value).ok, false)
    assert.ok(validateRunBudget(value).errors.includes('budget-not-object'))
  }
})

test('budget: 超平台硬上限 → exceeds-ceiling（用户只能收紧不能放宽）', () => {
  const r = validateRunBudget(budget({ max_total_time_ms: 60 * 60 * 1000 }))
  assert.equal(r.ok, false)
  assert.ok(r.errors.includes('budget-max_total_time_ms-exceeds-ceiling'))
  assert.ok(60 * 60 * 1000 > PLATFORM_BUDGET_CEILINGS.max_total_time_ms)
})

test('budget: 非法/零/非整数 → invalid', () => {
  const r = validateRunBudget(budget({ max_total_attempts: 0 }))
  assert.equal(r.ok, false)
  assert.ok(r.errors.includes('budget-max_total_attempts-invalid'))
  const r2 = validateRunBudget(budget({ max_total_memory_mb: 1.5 }))
  assert.equal(r2.ok, false)
  assert.ok(r2.errors.includes('budget-max_total_memory_mb-invalid'))
})

test('budget: 未知字段 → unknown-field', () => {
  const r = validateRunBudget(budget({ made_up: 1 }))
  assert.equal(r.ok, false)
  assert.ok(r.errors.includes('budget-unknown-field:made_up'))
})

test('budget: 缺字段 → invalid（所有字段必填）', () => {
  const { max_total_attempts: _dropped, ...withoutAttempts } = budget()
  const r = validateRunBudget(withoutAttempts)
  assert.equal(r.ok, false)
  assert.ok(r.errors.includes('budget-max_total_attempts-invalid'))
})

test('budget: resolveRunBudget 缺省返回平台硬上限', () => {
  const r = resolveRunBudget(undefined)
  assert.equal(r.ok, true)
  assert.deepEqual(r.budget, DEFAULT_RUN_BUDGET)
  const r2 = resolveRunBudget(null)
  assert.equal(r2.ok, true)
  assert.equal(r2.budget.max_total_attempts, PLATFORM_BUDGET_CEILINGS.max_total_attempts)
})

test('budget: resolveRunBudget 非法输入 → fail-closed', () => {
  const r = resolveRunBudget({ schema_version: 'run-budget/v1', max_total_attempts: -1 })
  assert.equal(r.ok, false)
  assert.ok(r.errors.length > 0)
})

test('budget: planDeclaredAttempts 聚合缺省 1 与显式 max_attempts', () => {
  assert.equal(planDeclaredAttempts([]), 0)
  assert.equal(planDeclaredAttempts([{}, {}]), 2)
  assert.equal(planDeclaredAttempts([{ retry: { max_attempts: 3 } }, {}, { retry: { max_attempts: 2 } }]), 6)
})

test('budget: assertPlanAttemptsWithinBudget 超限 fail-closed，范围内通过', () => {
  assert.equal(assertPlanAttemptsWithinBudget(2, budget({ max_total_attempts: 2 })).ok, true)
  const r = assertPlanAttemptsWithinBudget(3, budget({ max_total_attempts: 2 }))
  assert.equal(r.ok, false)
  assert.ok(r.errors.includes('plan-declared-attempts-exceed-budget:2'))
})

test('budget: ledger attempts 配额按派发前预留，超限拒绝', () => {
  const ledger = createBudgetLedger(budget({ max_total_attempts: 2 }))
  assert.equal(ledger.reserveAttempt(), null)
  assert.equal(ledger.reserveAttempt(), null)
  assert.equal(ledger.reserveAttempt(), 'budget-attempts-exceeded')
  assert.equal(ledger.snapshot().attempts, 2)
})

test('budget: ledger 累计 wall-clock 超限 → budget-time-exceeded', () => {
  const ledger = createBudgetLedger(budget({ max_total_time_ms: 1000 }))
  assert.equal(ledger.record({ elapsed_ms: 600, output_bytes: 0 }), null)
  assert.equal(ledger.record({ elapsed_ms: 500, output_bytes: 0 }), 'budget-time-exceeded')
  assert.equal(ledger.snapshot().elapsed_ms, 1100)
})

test('budget: ledger 累计输出字节超限 → budget-output-exceeded', () => {
  const ledger = createBudgetLedger(budget({ max_total_output_bytes: 100 }))
  assert.equal(ledger.record({ elapsed_ms: 0, output_bytes: 60 }), null)
  assert.equal(ledger.record({ elapsed_ms: 0, output_bytes: 50 }), 'budget-output-exceeded')
  assert.equal(ledger.snapshot().output_bytes, 110)
})

test('budget: L1 可强制与 unenforced 维度划分明确', () => {
  assert.deepEqual(BUDGET_ENFORCED_AT_L1, ['max_total_time_ms', 'max_total_output_bytes', 'max_total_attempts'])
  assert.deepEqual(BUDGET_UNENFORCED_AT_L1, ['max_total_cpu_ms', 'max_total_memory_mb'])
})

test('budget: ledger 忽略非法计量输入（NaN/负）而不崩', () => {
  const ledger = createBudgetLedger(budget({ max_total_time_ms: 100 }))
  assert.equal(ledger.record({ elapsed_ms: -5, output_bytes: NaN }), null)
  assert.equal(ledger.snapshot().elapsed_ms, 0)
  assert.equal(ledger.snapshot().output_bytes, 0)
})