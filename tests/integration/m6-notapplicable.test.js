/**
 * M6 缺口收口 · not-applicable 适用性谓词（node:test，纯 ESM）。
 *
 * Capability assertions embedded in a RunSpec are rejected before Plan freeze.
 * The control face may only mark an item `not-applicable` when the worker probe
 * measured a corroborated snapshot bound to the pinned PUT digest/environment
 * and the policy pre-declared the predicate.
 *   ① forged caller capability claim → capability-admission blocked.
 *   ② unknown probe → case verdict pass remains visible, aggregate gate blocked.
 *   ③ contradicted caller claim → capability-admission blocked.
 *   ④ verified corroborated snapshot + declared predicate → not-applicable is
 *      recorded with predicate version / snapshot ref / reason and never forged.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { runSelfCheck } from '../../src/index.js'
import { makeRuntimeAnchor } from '../../src/worker/runtime.js'
import { verifyReceipt } from '../../src/reports/shape.js'
import { makeRunSpec, probeValue, criteriaEquals } from '../fixtures/run-specs.js'

const STUB_RUNTIME_URL = new URL('../fixtures/fake-cordis-stub.mjs', import.meta.url).href
const PUT_COMPLIANT_URL = new URL('../fixtures/put-compliant.js', import.meta.url).href
const PROBE_TIME = '2026-01-01T00:00:00.000Z'

function tmpDir() {
  return mkdtempSync(join(tmpdir(), 'testbed-na-'))
}
function cleanup(t, dir) {
  t.after(() => rmSync(dir, { recursive: true, force: true }))
}
function readReceipt(result) {
  assert.ok(result.receiptPath, `receipt 必须落盘：${result.writeError ?? 'unknown error'}`)
  return JSON.parse(readFileSync(result.receiptPath, 'utf8'))
}
function putDigestOf(url) {
  return 'sha256:' + createHash('sha256').update(readFileSync(fileURLToPath(url))).digest('hex')
}

/** required 通过用例（in-process probe echo + criteria equals）。 */
function passingRequired(id) {
  return { test_id: id, node_id: id, classification: 'required', criteria: criteriaEquals(200), probe: probeValue(200) }
}

// ---------------------------------------------------------------------------
// ① caller-embedded capability claim → reject before Plan freeze
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
  assert.ok(
    Array.isArray(receipt.plan_resolution) &&
      receipt.plan_resolution.every((entry) => entry.not_applicable === undefined),
    `not_applicable 应为空，got: ${JSON.stringify(receipt.plan_resolution)}`,
  )
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

// ---------------------------------------------------------------------------
// ④ verified not-applicable: corroborated worker snapshot + pre-declared predicate
// ---------------------------------------------------------------------------

test('m6-na ④ 已核验 corroborated 快照 + 预声明谓词 → not-applicable 留痕且不进入 expected', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const spec = makeRunSpec([
    {
      test_id: 'na.present-op',
      node_id: 'na.present-op',
      classification: 'required',
      not_applicable_when: { observed: 'present' },
      probe: { op: 'echo', value: 1 },
    },
    {
      test_id: 'na.put.load',
      node_id: 'na.put.load',
      classification: 'required',
      criteria: { assert: 'equals', path: 'state_after_load', expected: 'ACTIVE' },
      probe: { op: 'load-put', put_entry: PUT_COMPLIANT_URL, put_config: {} },
    },
  ], { target: { kind: 'plugin', put_digest: putDigestOf(PUT_COMPLIANT_URL) } })

  const out = await runSelfCheck(spec, {
    executionMode: 'subprocess',
    runtimeAnchor: makeRuntimeAnchor({
      cordis_entry: STUB_RUNTIME_URL,
      cordis_version: '0.0.0-fixture',
      runtime_kind: 'test-fixture',
    }),
    probeTime: PROBE_TIME,
    receiptOutDir: dir,
  })
  assert.equal(out.gateDecision, 'blocked') // load-put has no OS-spawn witness
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  assert.equal(verifyReceipt(receipt).status, 'ok', JSON.stringify(verifyReceipt(receipt)))
  assert.ok(!receipt.reconciliation.expected.includes('na.present-op'), 'not-applicable 项不应进入 expected')
  assert.ok(receipt.reconciliation.expected.includes('na.put.load'))
  const entry = receipt.plan_resolution.find((item) => item.test_id === 'na.present-op')
  assert.ok(entry?.not_applicable, 'applicability judgement must be recorded')
  assert.equal(entry.not_applicable.predicate_version, 'capability-predicate/v1')
  assert.match(entry.not_applicable.capability_snapshot_ref, /^cap-sha256:[0-9a-f]{64}$/)
  assert.equal(entry.not_applicable.reason, 'capability-present')
})
