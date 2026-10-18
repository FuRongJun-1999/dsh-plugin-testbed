/** Two-phase capability verification tests (control/capability.js). */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  CAPABILITY_PREDICATE_VERSION,
  capabilitySnapshotRef,
  deriveVerification,
  normalizeCapabilitySnapshots,
  verifyCapabilitySnapshot,
  verifySnapshotBindings,
} from '../../../src/control/capability.js'

const sha = (c) => 'sha256:' + c.repeat(64)
const context = {
  put_digest: sha('a'),
  environment_fingerprint: sha('b'),
  probe_version: 'capability-probe/test',
}

function caseSpec(testId, overrides = {}) {
  return {
    test_id: testId,
    node_id: testId,
    classification: 'optional',
    not_applicable_when: { observed: 'absent', verification: 'corroborated' },
    ...overrides,
  }
}

function snapshot(testId, overrides = {}) {
  return {
    test_id: testId,
    source: 'worker',
    claim: 'not-declared',
    observed: 'absent',
    probe_version: context.probe_version,
    probe_time: '2026-01-01T00:00:00.000Z',
    environment_fingerprint: context.environment_fingerprint,
    put_digest: context.put_digest,
    worker_fingerprint: null,
    evidence_ref: null,
    limitations: [],
    ...overrides,
  }
}

function verify(cases, snapshots, options = {}) {
  return verifyCapabilitySnapshot({ cases }, snapshots, { planContext: context, ...options })
}

test('capability: verification derivation table', () => {
  assert.equal(deriveVerification('declared', 'present'), 'corroborated')
  assert.equal(deriveVerification('declared', 'absent'), 'contradicted')
  assert.equal(deriveVerification('not-declared', 'present'), 'contradicted')
  assert.equal(deriveVerification('not-declared', 'absent'), 'corroborated')
  for (const claim of ['declared', 'not-declared', 'bogus']) {
    assert.equal(deriveVerification(claim, 'unknown'), 'not-run')
  }
  assert.equal(deriveVerification('bogus', 'present'), 'not-run')
  assert.equal(deriveVerification(undefined, undefined), 'not-run')
})

test('capability: reserved IDs survive snapshot normalisation', () => {
  const input = Object.create(null)
  input.__proto__ = { test_id: '__proto__', claim: 'not-declared', observed: 'unknown' }
  const snapshots = normalizeCapabilitySnapshots(input)
  assert.equal(Object.hasOwn(snapshots, '__proto__'), true)
  const envelope = normalizeCapabilitySnapshots({
    probe_version: 'v', records: [{ test_id: 'a', claim: 'not-declared', observed: 'absent' }],
  })
  assert.equal(envelope.a.probe_version, 'v')
  assert.equal(envelope.a.test_id, 'a')
})

test('capability: only corroborated, correctly bound snapshots can mark not-applicable', () => {
  const result = verify([caseSpec('t1'), caseSpec('t2')], { t1: snapshot('t1') }, { notApplicable: ['t1'] })
  assert.deepEqual(result.notApplicable, ['t1'])
  assert.equal(result.records.t1.verification, 'corroborated')
  assert.equal(result.records.t1.trusted, true)
  assert.equal(result.notApplicableDetails[0].not_applicable.predicate_version, CAPABILITY_PREDICATE_VERSION)
  assert.match(result.notApplicableDetails[0].not_applicable.capability_snapshot_ref, /^cap-sha256:[0-9a-f]{64}$/)
  assert.equal(capabilitySnapshotRef(result.snapshots.t1), result.notApplicableDetails[0].not_applicable.capability_snapshot_ref)
})

test('capability: unknown capability never marks not-applicable and keeps expected/required', () => {
  const result = verify([caseSpec('t1')], { t1: snapshot('t1', { observed: 'unknown', claim: 'not-declared' }) }, { notApplicable: ['t1'] })
  assert.deepEqual(result.notApplicable, [])
  assert.equal(result.records.t1.verification, 'not-run')
  assert.ok(result.diagnostics.some((d) => d.test_id === 't1' && d.reason === 'capability-snapshot-not-corroborated'))
})

test('capability: contradicted declarations never mark not-applicable', () => {
  const declaredAbsent = verify([caseSpec('t1')], { t1: snapshot('t1', { claim: 'declared', observed: 'absent' }) }, { notApplicable: ['t1'] })
  assert.deepEqual(declaredAbsent.notApplicable, [])
  assert.equal(declaredAbsent.records.t1.verification, 'contradicted')

  const undeclaredPresent = verify([caseSpec('t1')], { t1: snapshot('t1', { claim: 'not-declared', observed: 'present' }) }, { notApplicable: ['t1'] })
  assert.deepEqual(undeclaredPresent.notApplicable, [])
  assert.equal(undeclaredPresent.records.t1.verification, 'contradicted')
})

test('capability: missing snapshot or missing predicate never marks not-applicable', () => {
  const missing = verify([caseSpec('t1')], {}, { notApplicable: ['t1'] })
  assert.deepEqual(missing.notApplicable, [])
  assert.ok(missing.diagnostics.some((d) => d.reason === 'capability-snapshot-missing'))

  const noPredicate = verify([{ test_id: 't1', node_id: 't1', classification: 'required' }], { t1: snapshot('t1') }, { notApplicable: ['t1'] })
  assert.deepEqual(noPredicate.notApplicable, [])
  assert.ok(noPredicate.diagnostics.some((d) => d.reason === 'not-applicable-predicate-missing-or-invalid'))
})

test('capability: unbound snapshots are untrusted and cannot reduce required', () => {
  const wrongPut = snapshot('t1', { put_digest: sha('c') })
  const result = verify([caseSpec('t1')], { t1: wrongPut }, { notApplicable: ['t1'] })
  assert.deepEqual(result.notApplicable, [])
  assert.equal(result.records.t1.trusted, false)
  assert.ok(result.diagnostics.some((d) => d.reason === 'capability-put-digest-mismatch'))

  const missingBindings = verifyCapabilitySnapshot(
    { cases: [caseSpec('t1')] },
    { t1: snapshot('t1') },
    { notApplicable: ['t1'] },
  )
  assert.deepEqual(missingBindings.notApplicable, [])
  assert.equal(missingBindings.records.t1.verification, 'not-run')
})

test('capability: worker-supplied verification is ignored unless it matches the derivation', () => {
  const honest = verify([caseSpec('t1')], { t1: snapshot('t1', { verification: 'corroborated' }) }, { notApplicable: ['t1'] })
  assert.deepEqual(honest.notApplicable, ['t1'])

  const forged = verify([caseSpec('t1')], { t1: snapshot('t1', { verification: 'contradicted' }) }, { notApplicable: ['t1'] })
  assert.deepEqual(forged.notApplicable, [])
  assert.equal(forged.records.t1.trusted, false)
  assert.ok(forged.diagnostics.some((d) => d.reason === 'capability-worker-verification-mismatch'))
})

test('capability: a policy-declared predicate is required when a gate policy is supplied', () => {
  const policy = {
    schema_version: 'gate-policy/v1',
    required_baseline: [],
    optional_baseline: ['t1'],
    not_applicable_predicates: [],
    waiver_rules: [],
    aggregation: { precedence: ['blocked', 'reject', 'pass'] },
  }
  const result = verify([caseSpec('t1')], { t1: snapshot('t1') }, { notApplicable: ['t1'], gatePolicy: policy })
  assert.deepEqual(result.notApplicable, [])
  assert.ok(result.diagnostics.some((d) => d.reason === 'not-applicable-predicate-not-in-policy'))

  const withPredicate = verify([caseSpec('t1')], { t1: snapshot('t1') }, {
    notApplicable: ['t1'],
    gatePolicy: { ...policy, not_applicable_predicates: [{ test_id: 't1', predicate_version: 'pred/v2', observed: 'absent' }] },
  })
  assert.deepEqual(withPredicate.notApplicable, ['t1'])
  assert.equal(withPredicate.notApplicableDetails[0].not_applicable.predicate_version, 'pred/v2')
})

test('capability: diagnostics are bound to the source worker record fields', () => {
  const result = verifySnapshotBindings(snapshot('t1', {
    source: 'caller', probe_time: 'not-a-time', probe_version: 'other',
  }), context)
  assert.equal(result.trusted, false)
  for (const reason of [
    'capability-snapshot-source-invalid',
    'capability-probe-time-invalid',
    'capability-probe-version-mismatch',
  ]) {
    assert.ok(result.diagnostics.includes(reason), reason)
  }
})
