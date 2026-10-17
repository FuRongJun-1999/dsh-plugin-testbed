import { test } from 'node:test'
import assert from 'node:assert/strict'
import { aggregateGateDecision } from '../../../src/control/gate.js'

const plan = (required) => ({ required })
const rec = (verdict, invocation_status = 'started') => ({ verdict, invocation_status, classification: 'required' })

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
    { a: rec('pass', 'started'), b: rec('pass', 'started') },
    { invocationEvidenceVerified: true },
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
    { a: rec('skip'), b: rec('pass', 'started') },
    { invocationEvidenceVerified: true },
  )
  assert.equal(r.gate_decision, 'pass')
})