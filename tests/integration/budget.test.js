/**
 * 全局聚合预算（run-budget/v1）纵向闭环负向回归（in-process）。
 *
 * 证明两件事 finance-closed：
 *   ① 计划声明 attempt 总数超聚合预算 → Plan 冻结前 `blocked`（budget-admission），
 *      不伪造 expected / 逐项 verdict；
 *   ② 单用例判据已 pass，但执行期累计序列化输出字节超预算 → run 级 `blocked`
 *      （`budget-output-exceeded`），即便该 required 用例 pass 也不得 pass。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { runSelfCheck } from '../../src/index.js'
import { makeRunSpec, probeValue, criteriaEquals } from '../fixtures/run-specs.js'

function tmpDir() {
  return mkdtempSync(join(tmpdir(), 'testbed-budget-'))
}
function cleanup(t, dir) {
  t.after(() => rmSync(dir, { recursive: true, force: true }))
}
function readReceipt(result) {
  return JSON.parse(readFileSync(result.receiptPath, 'utf8'))
}

const budget = (overrides = {}) => ({
  schema_version: 'run-budget/v1',
  max_total_attempts: 768,
  max_total_time_ms: 600_000,
  max_total_cpu_ms: 600_000,
  max_total_memory_mb: 4096,
  max_total_output_bytes: 8 * 1024 * 1024,
  ...overrides,
})

function passingRequired(id, value = 200) {
  return { test_id: id, node_id: id, classification: 'required', criteria: criteriaEquals(value), probe: probeValue(value) }
}

test('budget integration ① 计划 attempts 超聚合预算 → 冻结前 blocked，无虚构 expected', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const spec = makeRunSpec([
    passingRequired('b.a'),
    passingRequired('b.b'),
  ], { policy: { budget: budget({ max_total_attempts: 1 }) } })
  const out = await runSelfCheck(spec, { receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  assert.equal(receipt.run_status, 'blocked')
  assert.equal(receipt.plan_id, null)
  assert.equal(receipt.reconciliation, null)
  assert.equal(receipt.blocked_stage, 'budget-admission')
  assert.ok(Array.isArray(receipt.test_cases) && receipt.test_cases.length === 0, 'pre-plan must not forge per-item verdicts')
  assert.ok(receipt.reason_codes.some((rc) => rc === 'plan-declared-attempts-exceed-budget:1'), JSON.stringify(receipt.reason_codes))
})

test('budget integration ② 通过用例输出超聚合预算 → 虽有 pass 仍 run-level blocked', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const big = 'y'.repeat(400)
  const spec = makeRunSpec([
    passingRequired('b.out', big),
  ], { policy: { budget: budget({ max_total_output_bytes: 32 }) } })
  const out = await runSelfCheck(spec, { receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  assert.equal(out.gateReason, 'budget-output-exceeded')
  // 该 required 用例判据确实 pass，但预算超限使 run 保持 blocked。
  const tc = receipt.test_cases.find((c) => c.test_id === 'b.out')
  assert.equal(tc.verdict, 'pass')
  // 预算与消耗均落入 receipt provenance，可用作复核证据。
  assert.equal(receipt.provenance.run_budget.max_total_output_bytes, 32)
  assert.ok(receipt.provenance.budget_actuals.output_bytes > 32, JSON.stringify(receipt.provenance.budget_actuals))
})

test('budget integration ③ 未提供 budget 时按平台缺省预算运行，不改变既有行为', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const spec = makeRunSpec([passingRequired('b.default')])
  const out = await runSelfCheck(spec, { receiptOutDir: dir })
  // 无独立调用启动证据（MVP L0/L1 现状）：即使判据 pass，gate 仍 blocked；预算路径不抬升信任。
  assert.equal(out.gateDecision, 'blocked')
  const receipt = readReceipt(out)
  assert.equal(receipt.provenance.run_budget.schema_version, 'run-budget/v1')
  assert.ok(receipt.provenance.budget_actuals.attempts >= 1)
})