/** Control-plane six-field state normalisation tests (pure functions). */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  AUTHORITY_FIELDS,
  findAuthorityFields,
  hasVerifiedStartedPass,
  normalizeAdmissionStatus,
  normalizeAttempt,
  summarizeCaseState,
} from '../../../src/control/state.js'

const baseAttempt = (over = {}) => ({
  attempt: 1,
  admission_status: 'accepted',
  execution_status: 'completed',
  invocation_status: 'unknown',
  invocation_evidence_verified: false,
  verdict: 'pass',
  reason_codes: [],
  observation_refs: ['obs-1'],
  ...over,
})

test('state: valid attempt normalises deterministically', () => {
  const result = normalizeAttempt(baseAttempt())
  assert.equal(result.ok, true)
  assert.deepEqual(result.attempt, {
    attempt: 1,
    admission_status: 'accepted',
    execution_status: 'completed',
    invocation_status: 'unknown',
    verdict: 'pass',
    invocation_evidence_verified: false,
    reason_codes: [],
    observation_refs: ['obs-1'],
  })
})

test('state: started invocation requires independently verified control evidence', () => {
  const missing = normalizeAttempt(baseAttempt({ invocation_status: 'started' }))
  assert.equal(missing.ok, false)
  assert.ok(missing.errors.includes('started-invocation-requires-control-evidence'))

  const evidenceWithoutStarted = normalizeAttempt(baseAttempt({ invocation_evidence_verified: true }))
  assert.equal(evidenceWithoutStarted.ok, false)
  assert.ok(evidenceWithoutStarted.errors.includes('control-evidence-requires-started-invocation'))

  const valid = normalizeAttempt(baseAttempt({
    invocation_status: 'started',
    invocation_evidence_verified: true,
    started_at: '2026-01-01T00:00:00.000Z',
  }))
  assert.equal(valid.ok, true)
  assert.equal(valid.attempt.invocation_evidence_verified, true)
})

test('state: rejected admission must be skipped/skip/not-started', () => {
  const rejected = normalizeAttempt(baseAttempt({
    admission_status: 'rejected',
    execution_status: 'skipped',
    verdict: 'skip',
    invocation_status: 'not-started',
  }))
  assert.equal(rejected.ok, true)

  const inconsistent = normalizeAttempt(baseAttempt({
    admission_status: 'rejected',
    execution_status: 'completed',
    verdict: 'pass',
  }))
  assert.equal(inconsistent.ok, false)
  assert.ok(inconsistent.errors.includes('rejected-attempt-must-be-skipped'))
  assert.ok(inconsistent.errors.includes('rejected-attempt-must-be-skip'))
})

test('state: impossible terminal/verdict combinations fail closed', () => {
  assert.equal(normalizeAttempt(baseAttempt({ execution_status: 'completed', verdict: 'skip' })).ok, false)
  assert.equal(normalizeAttempt(baseAttempt({ execution_status: 'skipped', verdict: 'pass' })).ok, false)
  assert.equal(normalizeAttempt(baseAttempt({ execution_status: 'timeout', verdict: 'pass' })).ok, false)
  assert.equal(normalizeAttempt(baseAttempt({ verdict: 'bogus' })).ok, false)
  assert.equal(normalizeAttempt(baseAttempt({ invocation_evidence_verified: 'yes' })).ok, false)
})

test('state: authority-field scanner finds nested caller/worker authority claims', () => {
  const hits = findAuthorityFields({
    test_id: 'a',
    verdict: 'pass',
    nested: { gate_decision: 'pass', attempts: [{ required: ['a'] }] },
  })
  assert.deepEqual(hits.sort(), ['nested.attempts[0].required', 'nested.gate_decision', 'verdict'].sort())
  for (const field of ['verdict', 'gate_decision', 'required', 'expected', 'plan']) {
    assert.ok(AUTHORITY_FIELDS.includes(field))
  }
})

test('state: admission normalisation never invents "accepted"', () => {
  assert.equal(normalizeAdmissionStatus('accepted').admission_status, 'accepted')
  const rejected = normalizeAdmissionStatus('something-else')
  assert.equal(rejected.admission_status, 'rejected')
  assert.deepEqual(rejected.reason_codes, ['admission-rejected-without-reason'])
})

test('state: summarizeCaseState keeps retry history and last adopted verdict', () => {
  const summary = summarizeCaseState('t1', 'required', [
    baseAttempt({ attempt: 1, verdict: 'fail', reason_codes: ['equals-mismatch'] }),
    baseAttempt({ attempt: 2, verdict: 'pass' }),
  ], { dimensions: { test_level: 'unit' } })
  assert.equal(summary.ok, true)
  assert.equal(summary.record.verdict, 'pass')
  assert.equal(summary.record.attempts.length, 2)
  assert.equal(summary.record.attempts[0].verdict, 'fail')
  assert.equal(summary.record.criteria_ref, 'criteria/t1')
  assert.deepEqual(summary.record.dimensions, { test_level: 'unit' })
})

test('state: verify-pass helper requires started + verified + pass together', () => {
  assert.equal(hasVerifiedStartedPass({ verdict: 'pass', invocation_status: 'started', invocation_evidence_verified: true }), true)
  assert.equal(hasVerifiedStartedPass({ verdict: 'pass', invocation_status: 'started', invocation_evidence_verified: false }), false)
  assert.equal(hasVerifiedStartedPass({ verdict: 'fail', invocation_status: 'started', invocation_evidence_verified: true }), false)
  assert.equal(hasVerifiedStartedPass({ verdict: 'pass', invocation_status: 'unknown', invocation_evidence_verified: false }), false)
})
