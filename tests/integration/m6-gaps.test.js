/**
 * M6 缺口回归（node:test，纯 ESM）。
 *
 * `admission:'rejected'` 是 caller-supplied 的负向模拟输入，不是独立
 * GatePolicy 评估。它只验证 kernel 按该输入跳过 adapter dispatch，并把此
 * 局部事实记为 not-started；required 项仍阻断 Gate。
 *   ① caller-requested no-dispatch（required）→ gate=blocked、exit 2；
 *      verdict=skip / admission_status=rejected / execution_status=skipped /
 *      invocation_status=not-started / invocation_evidence_verified=false。
 *   ② caller-requested no-dispatch（optional）→ optional skip 不阻断；
 *      required pass 但 invocation 未验证 → gate=blocked。
 *   ③ optional fail 单独报告 → optional 项 verdict=fail 仍被记录；required invocation 未验证仍 gate=blocked。
 *   ④ 伪造开始时间戳 → 严格协议拒绝 worker 自报 started_at，invocation 保持 unknown/unverified。
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
/** caller-requested no-dispatch simulation; not an independent policy verdict. */
function callerRequestedNoDispatch(id, classification) {
  return { test_id: id, node_id: id, classification, admission: 'rejected' }
}

// ---------------------------------------------------------------------------
// ① caller_requested_no_dispatch（required）→ blocked
// ---------------------------------------------------------------------------

test('m6 ① caller_requested_no_dispatch（required）→ gate=blocked、exit 2，receipt 记 skip/rejected/not-started', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const out = await runSelfCheck(makeRunSpec([callerRequestedNoDispatch('req.rej', 'required')]), { receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  const tc = receipt.test_cases.find((c) => c.test_id === 'req.rej')
  assert.equal(tc.verdict, 'skip')
  assert.equal(tc.admission_status, 'rejected')
  assert.equal(tc.execution_status, 'skipped')
  assert.equal(tc.invocation_status, 'not-started')
  assert.equal(tc.invocation_evidence_verified, false)
  assert.equal(tc.attempts[0].invocation_status, 'not-started')
  assert.ok(Array.isArray(tc.reason_codes) && tc.reason_codes.includes('caller_requested_no_dispatch'), `reason_codes=${JSON.stringify(tc.reason_codes)}`)
})

// ---------------------------------------------------------------------------
// ② caller_requested_no_dispatch（optional）→ optional skip 不阻断，但缺少独立 required invocation 证据时仍 blocked
// ---------------------------------------------------------------------------

test('m6 ② optional caller-requested no-dispatch simulation does not bypass required invocation evidence', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const spec = makeRunSpec([
    passingRequired('req.pass'),
    callerRequestedNoDispatch('opt.rej', 'optional'),
  ])
  const out = await runSelfCheck(spec, { receiptOutDir: dir })
  // A passing result does not satisfy the gate until independent invocation evidence exists.
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  assert.equal(receipt.gate_reason, 'no-required-started-pass')
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
  assert.ok(Array.isArray(opt.reason_codes) && opt.reason_codes.includes('caller_requested_no_dispatch'))
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
  assert.equal(receipt.gate_reason, 'no-required-started-pass')
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