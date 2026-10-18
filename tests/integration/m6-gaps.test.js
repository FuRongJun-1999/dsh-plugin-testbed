/**
 * M6 缺口回归（node:test，纯 ESM）。
 *
 * Plan 冻结后的拒绝必须来自**控制面独立准入**（`decideAdmission`），而不是
 * caller 在 RunSpec 里塞入的 `admission` 模拟字段。本文件用「expected 项没有任何
 * observation producer」触发控制面拒绝，并反向断言 caller-supplied `admission`
 * 在 intake 阶段就被协议/控制面拒绝（它没有权威性）。
 *
 *   ① required 无 producer → admission_status=rejected、execution_status=skipped、
 *      verdict=skip、invocation_status=not-started、reason_codes 含 policy_rejected；
 *      required skip → gate=blocked、exit 2。
 *   ② optional 无 producer → optional 拒绝不改变 required 证据要求；required pass
 *      但 invocation 未验证 → gate=blocked（no-required-started-pass）。
 *   ③ optional fail 单独报告 → verdict=fail 仍被记录；required invocation 未验证仍 blocked。
 *   ④ 伪造开始时间戳 → 严格协议拒绝 worker 自报 started_at，invocation 保持 unknown/unverified。
 *   ⑤ caller-supplied `admission` 不是权威字段 → Plan 前 blocked，不生成逐项终态。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { runSelfCheck } from '../../src/index.js'
import { makeSubprocessAdapter } from '../../src/adapters/subprocess.js'
import { makeRunSpec, probeValue, criteriaEquals } from '../fixtures/run-specs.js'

function tmpDir() {
  return mkdtempSync(join(tmpdir(), 'testbed-m6-'))
}
function cleanup(t, dir) {
  t.after(() => rmSync(dir, { recursive: true, force: true }))
}
function readReceipt(result) {
  assert.ok(result.receiptPath, `receipt 必须落盘：${result.writeError ?? 'unknown error'}`)
  return JSON.parse(readFileSync(result.receiptPath, 'utf8'))
}

/** required 通过用例（in-process probe echo + criteria equals）。 */
function passingRequired(id) {
  return { test_id: id, node_id: id, classification: 'required', criteria: criteriaEquals(200), probe: probeValue(200) }
}
/** optional 故意 fail 用例。 */
function optionalFailing(id) {
  return { test_id: id, node_id: id, classification: 'optional', criteria: criteriaEquals('good'), probe: probeValue('bad') }
}
/** 无任何 observation producer 的用例：控制面必须在派发前独立拒绝。 */
function noProducerCase(id, classification) {
  return { test_id: id, node_id: id, classification }
}

// ---------------------------------------------------------------------------
// ① 控制面独立拒绝（required）→ blocked
// ---------------------------------------------------------------------------

test('m6 ① required 无 observation producer → 控制面拒绝（skip/rejected/not-started）、gate=blocked、exit 2', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const out = await runSelfCheck(makeRunSpec([noProducerCase('req.rej', 'required')]), { receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  assert.notEqual(receipt.plan_id, null, '拒绝发生在 Plan 冻结后 → 保留冻结形态')
  const tc = receipt.test_cases.find((c) => c.test_id === 'req.rej')
  assert.equal(tc.verdict, 'skip')
  assert.equal(tc.admission_status, 'rejected')
  assert.equal(tc.execution_status, 'skipped')
  assert.equal(tc.invocation_status, 'not-started')
  assert.equal(tc.invocation_evidence_verified, false)
  assert.equal(tc.attempts[0].invocation_status, 'not-started')
  assert.ok(tc.reason_codes.includes('policy_rejected'), `reason_codes=${JSON.stringify(tc.reason_codes)}`)
  assert.ok(tc.reason_codes.includes('no-observation-producer'), `reason_codes=${JSON.stringify(tc.reason_codes)}`)
})

// ---------------------------------------------------------------------------
// ② optional 控制面拒绝 → optional skip 不阻断；required invocation 未验证仍 blocked
// ---------------------------------------------------------------------------

test('m6 ② optional 控制面拒绝不绕过 required 的独立启动证据要求', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const spec = makeRunSpec([
    passingRequired('req.pass'),
    noProducerCase('opt.rej', 'optional'),
  ])
  const out = await runSelfCheck(spec, { receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  assert.equal(out.gateReason, 'no-required-started-pass')
  const req = receipt.test_cases.find((c) => c.test_id === 'req.pass')
  assert.equal(req.verdict, 'pass')
  assert.equal(req.invocation_status, 'unknown')
  assert.equal(req.invocation_evidence_verified, false)

  const opt = receipt.test_cases.find((c) => c.test_id === 'opt.rej')
  assert.equal(opt.verdict, 'skip') // optional skip 不阻断
  assert.equal(opt.admission_status, 'rejected')
  assert.equal(opt.execution_status, 'skipped')
  assert.equal(opt.invocation_status, 'not-started')
  assert.equal(opt.invocation_evidence_verified, false)
  assert.equal(opt.attempts[0].invocation_status, 'not-started')
  assert.ok(opt.reason_codes.includes('policy_rejected'), `reason_codes=${JSON.stringify(opt.reason_codes)}`)
})

// ---------------------------------------------------------------------------
// ③ optional fail 单独报告；required invocation 未验证 → blocked
// ---------------------------------------------------------------------------

test('m6 ③ optional fail remains reported; required pass without verified invocation blocks gate', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const spec = makeRunSpec([
    passingRequired('req.pass2'),
    optionalFailing('opt.fail'),
  ])
  const out = await runSelfCheck(spec, { receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  assert.equal(out.gateReason, 'no-required-started-pass')
  const req = receipt.test_cases.find((c) => c.test_id === 'req.pass2')
  assert.equal(req.verdict, 'pass')
  assert.equal(req.invocation_status, 'unknown')
  assert.equal(req.invocation_evidence_verified, false)

  const opt = receipt.test_cases.find((c) => c.test_id === 'opt.fail')
  assert.equal(opt.verdict, 'fail', 'optional fail remains recorded without changing the required invocation gate')
})

// ---------------------------------------------------------------------------
// ④ 伪造开始时间戳 → invocation_status=unknown
// ---------------------------------------------------------------------------

test('m6 ④ worker 自报 started_at 被严格协议拒绝且不产生 invocation evidence', async () => {
  const workerEntry = fileURLToPath(new URL('../fixtures/worker-fake-timestamp.mjs', import.meta.url))
  const adapter = makeSubprocessAdapter({ workerEntry, runId: `fake-ts-${Date.now()}` })
  try {
    adapter.start()
    const outcome = await adapter.execute({
      request_id: 'req-fake-1',
      run_id: 'run-fake',
      plan_id: 'plan-fake',
      test_id: 't-fake',
      attempt: 1,
      input: { op: 'echo', value: { status_code: 200 } },
    })
    // Strict framing rejects the worker's self-reported started_at; it cannot verify invocation.
    assert.equal(outcome.execution_status, 'error')
    assert.equal(outcome.invocation_status, 'unknown')
    assert.equal(outcome.invocation_evidence_verified, false)
    assert.ok(outcome.reason_codes.includes('unknown-field'))
  } finally {
    await adapter.reap()
  }
})

// ---------------------------------------------------------------------------
// ⑤ caller-supplied admission 没有权威性 → Plan 前 blocked
// ---------------------------------------------------------------------------

test('m6 ⑤ caller-supplied admission 模拟被 intake 拒绝，绝不降级为 Plan 后策略拒绝', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const spec = makeRunSpec([
    { ...passingRequired('req.sim'), admission: 'rejected' },
  ])
  const out = await runSelfCheck(spec, { receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  assert.equal(receipt.plan_id, null, 'caller admission 没有形成 Plan')
  assert.equal(receipt.reconciliation, null)
  assert.deepEqual(receipt.test_cases, [])
  assert.equal(receipt.blocked_stage, 'intake')
  assert.ok(
    receipt.reason_codes.some((code) => String(code).includes('untrusted-caller-field:admission')),
    `reason_codes=${JSON.stringify(receipt.reason_codes)}`,
  )
})
