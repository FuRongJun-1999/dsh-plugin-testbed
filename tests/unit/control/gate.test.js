import { test } from 'node:test'
import assert from 'node:assert/strict'
import { aggregateGateDecision } from '../../../src/control/gate.js'

const plan = (required) => ({ required })
const rec = (verdict, invocation_status = 'started', invocation_evidence_verified = false) => ({
  verdict,
  invocation_status,
  invocation_evidence_verified,
  classification: 'required',
})

test('gate: zero required → blocked', () => {
  const r = aggregateGateDecision(plan([]), { missing_required: [] }, {})
  assert.equal(r.gate_decision, 'blocked')
  assert.equal(r.reason, 'zero-required')
})

test('gate: missing_required non-empty → blocked', () => {
  const r = aggregateGateDecision(plan(['a']), { missing_required: ['a'] }, {})
  assert.equal(r.gate_decision, 'blocked')
  assert.equal(r.reason, 'missing-required')
})

test('gate: required fail → reject', () => {
  const r = aggregateGateDecision(plan(['a']), { missing_required: [] }, { a: rec('fail') })
  assert.equal(r.gate_decision, 'reject')
  assert.equal(r.reason, 'required-fail')
})

test('gate: required skip/error/inconclusive → blocked (priority over fail)', () => {
  const records = { a: rec('skip'), b: rec('fail'), c: rec('error'), d: rec('inconclusive') }
  assert.equal(aggregateGateDecision(plan(['a', 'b', 'c', 'd']), { missing_required: [] }, records).gate_decision, 'blocked')
  assert.equal(aggregateGateDecision(plan(['b']), { missing_required: [] }, { b: rec('fail') }).gate_decision, 'reject')
})

test('gate: started status alone is not trusted; L0/caller probe remains blocked', () => {
  const r = aggregateGateDecision(
    plan(['a', 'b']),
    { missing_required: [] },
    { a: rec('pass', 'started'), b: rec('pass', 'started') },
  )
  assert.equal(r.gate_decision, 'blocked')
  assert.equal(r.reason, 'invocation-evidence-unverified')
})

test('gate: independently verified adapter start evidence permits pass', () => {
  const r = aggregateGateDecision(
    plan(['a', 'b']),
    { missing_required: [] },
    { a: rec('pass', 'started', true), b: rec('pass', 'started', true) },
  )
  assert.equal(r.gate_decision, 'pass')
})

test('gate: all pass but none started → blocked (pass needs started+pass)', () => {
  const r = aggregateGateDecision(
    plan(['a']),
    { missing_required: [] },
    { a: rec('pass', 'unknown') },
  )
  assert.equal(r.gate_decision, 'blocked')
  assert.equal(r.reason, 'no-required-started-pass')
})

test('gate: required missing record (not in recordsByTestId) → blocked via incomplete', () => {
  const r = aggregateGateDecision(plan(['a']), { missing_required: [], waived: [] }, {})
  assert.equal(r.gate_decision, 'blocked')
})

test('gate: waived required is excluded from required universe', () => {
  // missing_required empty, only required 'a' is waived; 'a' has skip → but it's waived → pass requires a started pass of remaining
  const r = aggregateGateDecision(
    { expected: ['a', 'b'], required: ['a', 'b'], waiverAllowlist: ['a'] },
    { missing_required: [], waived: ['a'] },
    { a: rec('skip'), b: rec('pass', 'started', true) },
  )
  assert.equal(r.gate_decision, 'pass')
})

test('gate: caller-supplied admission on a frozen case cannot drive the decision', () => {
  const frozen = { expected: ['a'], required: ['a'], testCases: [{ test_id: 'a', admission: 'rejected' }] }
  const r = aggregateGateDecision(frozen, { missing_required: [] }, { a: rec('pass', 'started', true) })
  assert.equal(r.gate_decision, 'blocked')
  assert.equal(r.reason, 'caller-admission-not-authoritative')
})

test('gate: worker authority fields in adopted records are rejected', () => {
  for (const field of ['gate_decision', 'required', 'expected', 'plan']) {
    const record = { ...rec('pass', 'started', true), [field]: 'x' }
    const r = aggregateGateDecision(plan(['a']), { missing_required: [] }, { a: record })
    assert.equal(r.gate_decision, 'blocked')
    assert.equal(r.reason, `worker-authority-field:${field}`)
  }
})

test('gate: verified evidence flag must agree with invocation_status', () => {
  const inconsistent = aggregateGateDecision(plan(['a']), { missing_required: [] }, {
    a: { ...rec('pass', 'unknown', true) },
  })
  assert.equal(inconsistent.gate_decision, 'blocked')
  assert.equal(inconsistent.reason, 'inconsistent-reconciliation')
})

test('gate: rejected admission must be a skipped/skip/not-started terminal', () => {
  const consistent = aggregateGateDecision(plan(['a']), { missing_required: [] }, {
    a: { verdict: 'skip', invocation_status: 'not-started', admission_status: 'rejected', execution_status: 'skipped' },
  })
  assert.equal(consistent.gate_decision, 'blocked')
  assert.equal(consistent.reason, 'required-skip')

  const inconsistent = aggregateGateDecision(plan(['a']), { missing_required: [] }, {
    a: { verdict: 'pass', invocation_status: 'started', invocation_evidence_verified: true, admission_status: 'rejected', execution_status: 'completed' },
  })
  assert.equal(inconsistent.gate_decision, 'blocked')
  assert.equal(inconsistent.reason, 'inconsistent-reconciliation')
})

test('gate: optional fail is reported but does not change an otherwise verified pass', () => {
  const frozen = { expected: ['a', 'opt'], required: ['a'] }
  const r = aggregateGateDecision(frozen, { missing_required: [] }, {
    a: rec('pass', 'started', true),
    opt: { verdict: 'fail', invocation_status: 'unknown', classification: 'optional' },
  })
  assert.equal(r.gate_decision, 'pass')
  assert.equal(r.reason, 'all-required-pass-started')
  assert.deepEqual(r.optional_issues, [{ test_id: 'opt', verdict: 'fail', issue: 'non-pass' }])
})

test('gate: aggregation is a pure offline-recomputable function', () => {
  const frozen = { expected: ['a'], required: ['a'] }
  const reconciliation = { missing_required: [] }
  const records = { a: rec('pass', 'started', true) }
  const first = aggregateGateDecision(frozen, reconciliation, records)
  const second = aggregateGateDecision(frozen, reconciliation, structuredClone(records))
  assert.deepEqual(first, second)
  assert.equal(first.gate_decision, 'pass')
})