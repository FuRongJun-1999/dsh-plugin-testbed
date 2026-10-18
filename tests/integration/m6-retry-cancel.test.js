/**
 * M6 缺口收口 · 重试 + Plan 前取消（node:test，纯 ESM）。
 *
 * 覆盖 §16.1 行3（重试追加/保留历史）与行8（Plan 前取消）：
 *   ① 重试 fail 到底 → attempts.length=3 全 fail、历史不覆盖、case verdict=fail、gate=reject。
 *   ② 重试 pass 即止 → max_attempts=3 但首个 attempt pass 即 break，attempts.length=1。
 *   ③ Plan 前取消（freeze 前 signal aborted）→ pre-plan-cancelled receipt（run_status=cancelled、
 *      plan_id=null、reconciliation=null、cancelled_stage 非空、不伪造 expected/missing/verdict）。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { runSelfCheck } from '../../src/index.js'
import { makeRunSpec, probeValue, criteriaEquals } from '../fixtures/run-specs.js'

function tmpDir() {
  return mkdtempSync(join(tmpdir(), 'testbed-rc-'))
}
function cleanup(t, dir) {
  t.after(() => rmSync(dir, { recursive: true, force: true }))
}
function readReceipt(result) {
  return JSON.parse(readFileSync(result.receiptPath, 'utf8'))
}

// ---------------------------------------------------------------------------
// ① 重试 fail 到底 → 3 attempt 全 fail、历史不覆盖
// ---------------------------------------------------------------------------

test('m6-rc ① 重试 fail 到底 → attempts.length=3 全 fail、case verdict=fail、gate=reject', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const spec = makeRunSpec([
    {
      test_id: 'req.r1', node_id: 'req.r1', classification: 'required',
      retry: { safe: false, max_attempts: 3 },
      criteria: criteriaEquals('good', 'status'),
      probe: probeValue({ status: 'bad' }),
    },
  ])

  const out = await runSelfCheck(spec, { receiptOutDir: dir })
  assert.equal(out.gateDecision, 'reject')
  assert.equal(out.exitCode, 1)

  const receipt = readReceipt(out)
  const tc = receipt.test_cases.find((c) => c.test_id === 'req.r1')
  assert.equal(tc.attempts.length, 3, '应追加 3 个 attempt')
  for (const a of tc.attempts) {
    assert.equal(a.verdict, 'fail', `每次 attempt 均应 fail，got: ${JSON.stringify(a)}`)
  }
  assert.equal(tc.verdict, 'fail', 'case 级 verdict = 最后一次 attempt = fail')
})

// ---------------------------------------------------------------------------
// ② 重试 pass 即止 → 1 attempt
// ---------------------------------------------------------------------------

test('m6-rc ② retry stops at first pass; verdict is pass while gate stays blocked without invocation evidence', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const spec = makeRunSpec([
    {
      test_id: 'req.r2', node_id: 'req.r2', classification: 'required',
      retry: { safe: false, max_attempts: 3 },
      criteria: criteriaEquals('good', 'status'),
      probe: probeValue({ status: 'good' }),
    },
  ])

  const out = await runSelfCheck(spec, { receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  const tc = receipt.test_cases.find((c) => c.test_id === 'req.r2')
  assert.equal(tc.attempts.length, 1, 'pass 不重试，应只有 1 个 attempt')
  assert.equal(tc.attempts[0].verdict, 'pass')
  assert.equal(tc.verdict, 'pass')
})

// ---------------------------------------------------------------------------
// ③ Plan 前取消 → pre-plan-cancelled receipt
// ---------------------------------------------------------------------------

test('m6-rc ③ Plan 前取消 → run_status=cancelled、plan_id=null、reconciliation=null、exit 2', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const spec = makeRunSpec([
    { test_id: 'req.c1', node_id: 'req.c1', classification: 'required', criteria: criteriaEquals(200), probe: probeValue(200) },
  ])

  const ac = new AbortController()
  ac.abort() // freeze 前已取消
  const out = await runSelfCheck(spec, { signal: ac.signal, receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked') // 取消 receipt 的 gate_decision 固定 blocked
  assert.equal(out.exitCode, 2)
  assert.equal(out.reconciliation, null)

  const receipt = readReceipt(out)
  assert.equal(receipt.run_status, 'cancelled')
  assert.equal(receipt.plan_id, null)
  assert.equal(receipt.reconciliation, null)
  assert.deepEqual(receipt.test_cases, [])
  assert.ok(typeof receipt.cancelled_stage === 'string' && receipt.cancelled_stage.length > 0, 'cancelled_stage 应非空')
  // 无伪造 expected/missing/verdict（reconciliation 为 null，无可信逐项终态）
  assert.equal(receipt.expected, undefined)
  assert.equal(receipt.missing, undefined)
  assert.equal(receipt.waived, undefined)
})