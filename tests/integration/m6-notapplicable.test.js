/**
 * M6 缺口收口 · not-applicable 适用性谓词（node:test，纯 ESM）。
 *
 * Capability assertions embedded in a RunSpec are rejected before Plan freeze.
 * The MVP probe emits `unknown`; that observation cannot establish not-applicable.
 *   ① forged corroborated claim → capability-admission blocked.
 *   ② unknown probe → case verdict pass remains visible, aggregate gate blocked.
 *   ③ contradicted caller claim → capability-admission blocked.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { runSelfCheck } from '../../src/index.js'
import { makeRunSpec, probeValue, criteriaEquals } from '../fixtures/run-specs.js'

function tmpDir() {
  return mkdtempSync(join(tmpdir(), 'testbed-na-'))
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

// ---------------------------------------------------------------------------
// ① caller-embedded capability claim → reject before Plan freeze; no not-applicable claim accepted
// ---------------------------------------------------------------------------

test('m6-na ① forged corroborated claim → blocked before Plan freeze', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const spec = makeRunSpec([
    passingRequired('req.a'),
    {
      test_id: 'req.b',
      node_id: 'req.b',
      classification: 'required',
      not_applicable_when: { observed: 'absent' },
      capability: { observed: 'absent', verification: 'corroborated' },
    },
  ])

  const out = await runSelfCheck(spec, { receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)
  const receipt = readReceipt(out)
  assert.equal(receipt.plan_id, null, 'caller capability claim is rejected before freeze')
  assert.equal(receipt.blocked_stage, 'capability-admission')
  assert.deepEqual(receipt.reason_codes, ['case-capability-untrusted'])
})

// ---------------------------------------------------------------------------
// ② unknown capability probe → case verdict can pass, but aggregate gate remains blocked
// ---------------------------------------------------------------------------

test('m6-na ② 未知/未核验 → 不排除；execution verdict pass but gate blocked', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const spec = makeRunSpec([
    {
      test_id: 'req.c',
      node_id: 'req.c',
      classification: 'required',
      not_applicable_when: { observed: 'absent' },
      criteria: criteriaEquals(200),
      probe: probeValue(200),
    },
  ])

  const out = await runSelfCheck(spec, { receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  assert.ok(receipt.reconciliation.expected.includes('req.c'), 'expected 应含 req.c（未核验不排除）')
  assert.equal(receipt.plan_resolution.not_applicable.length, 0, 'not_applicable 应为空')
  const tc = receipt.test_cases.find((c) => c.test_id === 'req.c')
  assert.equal(tc.verdict, 'pass', 'req.c execution verdict remains pass')
  assert.equal(tc.invocation_status, 'unknown')
  assert.equal(tc.invocation_evidence_verified, false)
})

// ---------------------------------------------------------------------------
// ③ contradicted caller claim is rejected before plan freeze
// ---------------------------------------------------------------------------

test('m6-na ③ contradicted claim rejected pre-freeze; caller cannot establish capability state', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const spec = makeRunSpec([
    {
      test_id: 'req.d',
      node_id: 'req.d',
      classification: 'required',
      not_applicable_when: { observed: 'absent' },
      capability: { observed: 'absent', verification: 'contradicted' },
      criteria: criteriaEquals(200),
      probe: probeValue(200),
    },
  ])

  const out = await runSelfCheck(spec, { receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')

  const receipt = readReceipt(out)
  assert.equal(out.exitCode, 2)
  assert.equal(receipt.plan_id, null)
  assert.equal(receipt.reconciliation, null)
  assert.deepEqual(receipt.test_cases, [])
  assert.equal(receipt.blocked_stage, 'capability-admission')
  assert.deepEqual(receipt.reason_codes, ['case-capability-untrusted'])
})