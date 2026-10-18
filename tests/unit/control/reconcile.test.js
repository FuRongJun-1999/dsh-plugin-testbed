import { test } from 'node:test'
import assert from 'node:assert/strict'
import { reconcile, reconcileAdoptedAttempts } from '../../../src/control/reconcile.js'

const frozen = { expected: ['a', 'b', 'c'], required: ['a', 'b'], waiverAllowlist: ['b'] }

test('reconcile: executed ⊂ expected, missing computed independently', () => {
  const r = reconcile(frozen, { a: { verdict: 'pass' }, b: { verdict: 'fail' } })
  assert.deepEqual(r.executed, ['a', 'b'])
  assert.deepEqual(r.missing, ['c'])
  assert.deepEqual(r.missing_required, [])
})

test('reconcile: missing_required = required side of missing', () => {
  const r = reconcile(frozen, { a: { verdict: 'pass' } })
  assert.deepEqual(r.missing, ['b', 'c'])
  assert.deepEqual(r.missing_required, ['b'])
})

test('reconcile: waived removes from missing (MVP empty)', () => {
  const r = reconcile(frozen, { a: { verdict: 'pass' } }, ['b'])
  assert.deepEqual(r.missing, ['c'])
  assert.deepEqual(r.missing_required, [])
  assert.deepEqual(r.waived, ['b'])
})

test('reconcile: extra result not in expected is rejected fail-closed', () => {
  assert.throws(
    () => reconcile(frozen, { a: { verdict: 'pass' }, ghost: { verdict: 'pass' } }),
    /result ID is not expected/,
  )
})

test('reconcile: malformed, duplicate, and invalid records/waivers reject', () => {
  assert.throws(() => reconcile(frozen, { a: { verdict: 'bogus' } }), /result is malformed/)
  assert.throws(() => reconcile(frozen, { a: { verdict: 'pass' } }, ['b', 'b']), /duplicate ID/)
  assert.throws(() => reconcile(frozen, { a: { verdict: 'pass' } }, ['c']), /waiver is not pre-approved/)
  assert.throws(() => reconcile(frozen, { a: { verdict: 'pass' } }, ['ghost']), /waiver ID is not expected/)
})

test('reconcile: no results → all expected missing', () => {
  const r = reconcile(frozen, {})
  assert.deepEqual(r.missing, ['a', 'b', 'c'])
  assert.deepEqual(r.missing_required, ['a', 'b'])
})

test('reconcile: adopted attempts use the final adopted verdict per test', () => {
  const r = reconcileAdoptedAttempts(frozen, [
    { test_id: 'a', attempt: { attempt: 1, verdict: 'fail' } },
    { test_id: 'a', attempt: { attempt: 2, verdict: 'pass' } },
    { test_id: 'b', attempt: { attempt: 1, verdict: 'fail' } },
  ])
  assert.deepEqual(r.executed, ['a', 'b'])
  assert.deepEqual(r.missing, ['c'])
  assert.deepEqual(r.missing_required, [])
})

test('reconcile: adopted attempts reject foreign IDs, duplicate attempts and authority fields', () => {
  assert.throws(
    () => reconcileAdoptedAttempts(frozen, [{ test_id: 'ghost', attempt: { attempt: 1, verdict: 'pass' } }]),
    /not expected/,
  )
  assert.throws(
    () => reconcileAdoptedAttempts(frozen, [
      { test_id: 'a', attempt: { attempt: 1, verdict: 'pass' } },
      { test_id: 'a', attempt: { attempt: 1, verdict: 'pass' } },
    ]),
    /duplicate attempt/,
  )
  assert.throws(
    () => reconcileAdoptedAttempts(frozen, [
      { test_id: 'a', attempt: { attempt: 1, verdict: 'pass', gate_decision: 'pass' } },
    ]),
    /authority field: gate_decision/,
  )
  assert.throws(
    () => reconcileAdoptedAttempts(frozen, [{ test_id: 'a', attempt: { attempt: 1, verdict: 'bogus' } }]),
    /malformed/,
  )
})

test('reconcile: a frozen plan carrying caller admission authority is rejected', () => {
  assert.throws(
    () => reconcile({ ...frozen, testCases: [{ test_id: 'a', classification: 'required', admission: 'rejected' }] }, {}),
    /authority field: admission/,
  )
})