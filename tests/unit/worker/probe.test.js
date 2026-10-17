/** Worker capability probe tests. */
import test from 'node:test'
import assert from 'node:assert/strict'
import { probeCapabilities } from '../../../src/worker/probe.js'
import { CAPABILITY_CLAIM, CAPABILITY_OBSERVED } from '../../../src/protocol/enums.js'

const digest = 'sha256:' + 'a'.repeat(64)

function assertUnknownRecord(record, testId) {
  assert.equal(record.test_id, testId)
  assert.equal(record.source, 'worker')
  assert.equal(record.claim, 'not-declared')
  assert.equal(record.observed, 'unknown')
  assert.ok(!Object.hasOwn(record, 'verification'), 'worker must not derive verification')
  assert.ok(CAPABILITY_CLAIM.includes(record.claim))
  assert.ok(CAPABILITY_OBSERVED.includes(record.observed))
  assert.equal(record.put_digest, null)
  assert.equal(record.environment_fingerprint, null)
  assert.equal(record.evidence_ref, null)
  assert.ok(Array.isArray(record.limitations))
}

test('probe never trusts caller capability declarations and emits unknown worker records', () => {
  const result = probeCapabilities([{
    test_id: 'contract.login.schema',
    capability: { claim: 'declared', observed: 'present', verification: 'corroborated' },
    probe: { execution_status: 'completed' },
  }])
  assertUnknownRecord(result['contract.login.schema'], 'contract.login.schema')
  assert.ok(result['contract.login.schema'].limitations.includes('capability-not-measured-by-mvp-probe'))
})

test('probe binds supplied context digests but does not fabricate observations', () => {
  const result = probeCapabilities([{ test_id: 'smoke.load' }], {
    put_digest: digest,
    environment_fingerprint: digest,
    probe_version: 'capability-probe/test',
  })
  const record = result['smoke.load']
  assertUnknownRecord({ ...record, put_digest: null, environment_fingerprint: null }, 'smoke.load')
  assert.equal(record.put_digest, digest)
  assert.equal(record.environment_fingerprint, digest)
  assert.equal(record.probe_version, 'capability-probe/test')
})

test('all cases are retained, including required and optional; unknown is not absent', () => {
  const result = probeCapabilities([
    { test_id: 'req.case', classification: 'required' },
    { test_id: 'opt.case', classification: 'optional' },
  ])
  assert.deepEqual(Object.keys(result).sort(), ['opt.case', 'req.case'])
  for (const [id, record] of Object.entries(result)) assertUnknownRecord(record, id)
  assert.ok(!Object.values(result).some((record) => record.observed === 'absent'))
})

test('reserved IDs remain own snapshot keys with matching test_id bindings', () => {
  const result = probeCapabilities([
    { test_id: '__proto__' },
    { test_id: 'constructor' },
  ])
  assert.equal(Object.hasOwn(result, '__proto__'), true)
  assert.equal(Object.hasOwn(result, 'constructor'), true)
  assertUnknownRecord(result['__proto__'], '__proto__')
  assertUnknownRecord(result.constructor, 'constructor')
})

test('malformed/non-array input is defensive and empty', () => {
  assert.deepEqual(probeCapabilities([]), {})
  assert.deepEqual(probeCapabilities(null), {})
  assert.deepEqual(probeCapabilities(undefined), {})
  assert.deepEqual(probeCapabilities([{ node_id: 'missing-test-id' }]), {})
})
