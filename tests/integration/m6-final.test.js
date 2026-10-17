/**
 * M6 收尾 · 乱序 / 错配 / smoke probe（node:test，纯 ESM）。
 *
 *   ① 乱序（out-of-order）：subprocess adapter 单 in-flight（processes=1）——第一个 execute
 *      未 await（in-flight），紧接着第二个 execute → 第二个返回 error + reason 'out-of-order'。
 *   ② 错配（correlation-mismatch）：worker 回错配 request_id 的 response → reason 'correlation-mismatch'。
 *   ③ smoke probe preserves dimensions and pass verdict; gate is blocked without independent invocation evidence.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { runSelfCheck } from '../../src/index.js'
import { makeSubprocessAdapter } from '../../src/adapters/subprocess.js'
import { makeRunSpec, criteriaEquals } from '../fixtures/run-specs.js'

const HOST_ENTRY = fileURLToPath(new URL('../../src/worker/host.js', import.meta.url))
const WRONG_CORR_WORKER = fileURLToPath(new URL('../fixtures/worker-wrong-corr.mjs', import.meta.url))

function tmpDir() {
  return mkdtempSync(join(tmpdir(), 'testbed-final-'))
}
function cleanup(t, dir) {
  t.after(() => rmSync(dir, { recursive: true, force: true }))
}
function readReceipt(result) {
  return JSON.parse(readFileSync(result.receiptPath, 'utf8'))
}

// ---------------------------------------------------------------------------
// ① 乱序（out-of-order）
// ---------------------------------------------------------------------------

test('m6-final ① 并发第二个 execute（in-flight 未 await）→ out-of-order', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry: HOST_ENTRY, runId: `ooo-${Date.now()}` })
  try {
    adapter.start()
    // 第一个 execute 不 await（in-flight），current 被占用 → 第二个应为 out-of-order。
    const p1 = adapter.execute({
      request_id: 'req-ooo-1', run_id: 'run-ooo', plan_id: 'plan-ooo', test_id: 't-1', attempt: 1,
      input: { op: 'echo', value: 1 },
    })
    const r2 = await adapter.execute({
      request_id: 'req-ooo-2', run_id: 'run-ooo', plan_id: 'plan-ooo', test_id: 't-2', attempt: 1,
      input: { op: 'echo', value: 2 },
    })

    assert.equal(r2.execution_status, 'error')
    assert.ok(Array.isArray(r2.reason_codes) && r2.reason_codes.includes('out-of-order'), `reason_codes=${JSON.stringify(r2.reason_codes)}`)
    await p1 // 排空第一个 in-flight（正常回显）
  } finally {
    await adapter.reap()
  }
})

// ---------------------------------------------------------------------------
// ② 错配（correlation-mismatch）
// ---------------------------------------------------------------------------

test('m6-final ② response request_id mismatch → correlation-mismatch; invocation evidence remains unknown', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry: WRONG_CORR_WORKER, runId: `corr-${Date.now()}` })
  try {
    adapter.start()
    const outcome = await adapter.execute({
      request_id: 'req-corr-1', run_id: 'run-corr', plan_id: 'plan-corr', test_id: 't-corr', attempt: 1,
      input: { op: 'echo', value: { status: 'ok' } },
    })

    assert.equal(outcome.execution_status, 'error')
    assert.ok(Array.isArray(outcome.reason_codes) && outcome.reason_codes.includes('correlation-mismatch'), `reason_codes=${JSON.stringify(outcome.reason_codes)}`)
    assert.equal(outcome.invocation_status, 'unknown', 'worker lifecycle frame is not independent invocation evidence')
    assert.equal(outcome.invocation_evidence_verified, false)
  } finally {
    await adapter.reap()
  }
})

// ---------------------------------------------------------------------------
// ③ smoke probe（suite_profile=smoke dimension）
// ---------------------------------------------------------------------------

test('m6-final ③ smoke probe preserves dimensions and pass verdict; gate blocks without independent invocation evidence', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const spec = makeRunSpec([
    {
      test_id: 'req.smoke', node_id: 'req.smoke', classification: 'required',
      dimensions: { suite_profile: 'smoke' },
      criteria: criteriaEquals('ok', 'status'),
      probe: { op: 'echo', value: { status: 'ok' } },
    },
  ])

  const out = await runSelfCheck(spec, { executionMode: 'subprocess', receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  const tc = receipt.test_cases.find((c) => c.test_id === 'req.smoke')
  assert.equal(tc.dimensions?.suite_profile, 'smoke')
  assert.equal(tc.verdict, 'pass')
})