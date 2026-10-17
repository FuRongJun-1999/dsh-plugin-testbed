import { test } from 'node:test'
import assert from 'node:assert/strict'
import { project, projectAll, PROJECT_FORMATS } from '../../../../src/reports/project/index.js'
import { makeReceipt } from './_fixtures.js'

test('project: returns { exporter_id, format_version, source_receipt_digest, body }', () => {
  const r = makeReceipt()
  const out = project(r, 'ci-summary', 'exporter-1')
  assert.equal(out.exporter_id, 'exporter-1')
  assert.equal(out.format_version, 'ci-summary/v1')
  assert.equal(out.source_receipt_digest, r.integrity.record_digest)
  assert.equal(typeof out.body, 'string')
})

test('project: ci-summary includes digest + local exit code + counts; never market eligible', () => {
  const r = makeReceipt()
  const { body } = project(r, 'ci-summary', 'exporter-1')
  assert.match(body, /source_receipt_digest: sha256:/)
  assert.match(body, /exporter_id: exporter-1/)
  assert.match(body, /exit_code\(local\): 2/)
  assert.match(body, /gate_decision: blocked/)
  assert.match(body, /market_eligible: false/)
  assert.match(body, /expected=6 executed=5 missing=1 waived=0/)
})

test('project: unknown format → throws', () => {
  assert.throws(() => project(makeReceipt(), 'sarif', 'e'), /unknown format/)
})

test('project: verify failure → throws (no half product)', () => {
  const r = makeReceipt()
  r.limitations.push('tampered') // digest mismatch
  assert.throws(() => project(r, 'junit', 'e'), /invalid receipt/)
})

test('project: does not mutate the receipt', () => {
  const r = makeReceipt()
  const before = JSON.stringify(r)
  projectAll(r, 'e')
  assert.equal(JSON.stringify(r), before)
})

test('projectAll: returns all four formats + byte-stable across two runs', () => {
  const r = makeReceipt()
  const a = projectAll(r, 'exporter-a')
  const b = projectAll(r, 'exporter-a')
  assert.deepEqual(Object.keys(a).sort(), ['ci-summary', 'html', 'junit', 'tap'])
  for (const fmt of PROJECT_FORMATS) {
    assert.equal(a[fmt].body, b[fmt].body)
    assert.equal(a[fmt].source_receipt_digest, r.integrity.record_digest)
  }
})

test('projectAll: tampered receipt throws', () => {
  const r = makeReceipt()
  r.trust_scope = 'market'
  assert.throws(() => projectAll(r, 'e'), /invalid receipt/)
})