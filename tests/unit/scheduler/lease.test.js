/**
 * `scheduler-lease/v1` construction, validation and fencing semantics.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  assertFencingCurrent,
  buildLease,
  fencingRelation,
  isLeaseActive,
  normalizeCancel,
  normalizeScope,
  validateLease,
  SCHEDULER_LEASE_SCHEMA_VERSION,
} from '../../../src/scheduler/index.js'

const TARGET = 'sha256:' + 'a'.repeat(64)

function leaseInput(overrides = {}) {
  return {
    leaseId: 'lease-1',
    runId: 'run-1',
    scheduleId: 'sched-1',
    ownerId: 'owner-A',
    scope: { profile: 'local', target_digest: TARGET, tenant: 'local', max_concurrency: 1 },
    fencingToken: 1,
    epoch: 1,
    acquiredAt: '2026-10-19T00:00:00.000Z',
    expiresAt: '2026-10-19T00:01:00.000Z',
    ttlMs: 60_000,
    ...overrides,
  }
}

test('lease: buildLease emits a frozen scheduler-lease/v1 with store facts', () => {
  const built = buildLease(leaseInput())
  assert.equal(built.ok, true)
  assert.equal(built.lease.schema_version, SCHEDULER_LEASE_SCHEMA_VERSION)
  assert.equal(built.lease.state, 'active')
  assert.equal(built.lease.fencing_token, 1)
  assert.equal(built.lease.store.durable, true)
  assert.equal(built.lease.store.provider_id, 'node-sqlite-single-host')
  assert.deepEqual(built.lease.cancel, { requested_at: null, token_id: null })
  assert.equal(Object.isFrozen(built.lease), true)
  assert.equal(Object.isFrozen(built.lease.scope), true)
  assert.match(built.scopeKey, /^scope-sha256:[0-9a-f]{64}$/)
})

test('lease: normalizeScope pins one owner per scope and rejects extension keys', () => {
  const ok = normalizeScope({ profile: 'local', target_digest: TARGET, max_concurrency: 1 })
  assert.equal(ok.ok, true)
  assert.equal(ok.scope.tenant, 'local')

  for (const [scope, error] of [
    [{ profile: 'local', target_digest: TARGET, max_concurrency: 2 }, 'lease-scope-max-concurrency-must-be-1'],
    [{ profile: 'local', target_digest: 'sha256:bad', max_concurrency: 1 }, 'lease-scope-target-digest-invalid'],
    [{ profile: 'local', target_digest: TARGET, max_concurrency: 1, extra: true }, 'lease-scope-unknown-field:extra'],
    [{ profile: '', target_digest: TARGET, max_concurrency: 1 }, 'lease-scope-profile-invalid'],
  ]) {
    const result = normalizeScope(scope)
    assert.equal(result.ok, false)
    assert.ok(result.errors.includes(error), `expected ${error}, got ${JSON.stringify(result.errors)}`)
  }
})

test('lease: buildLease rejects invalid tiers/times/ids/cancel', () => {
  const cases = [
    [{ ttlMs: 0 }, 'lease-ttl-ms-invalid'],
    [{ fencingToken: 0 }, 'lease-fencing-token-invalid'],
    [{ epoch: 0 }, 'lease-epoch-invalid'],
    [{ state: 'zombie' }, 'lease-state-invalid'],
    [{ expiresAt: '2026-10-18T23:59:00.000Z' }, 'lease-expires-at-not-after-acquired-at'],
    [{ acquiredAt: 'not-a-time' }, 'lease-acquired-at-invalid'],
    [{ ownerId: '' }, 'lease-owner_id-invalid'],
    [{ cancel: { requested_at: 'not-a-time', token_id: 'c' } }, 'lease-cancel-invalid'],
    [{ evidenceRefs: [42] }, 'lease-evidence-refs-invalid'],
  ]
  for (const [override, error] of cases) {
    const result = buildLease(leaseInput(override))
    assert.equal(result.ok, false, `expected failure for ${JSON.stringify(override)}`)
    assert.ok(result.errors.includes(error), `expected ${error}, got ${JSON.stringify(result.errors)}`)
  }
})

test('lease: validateLease round-trips a built lease and rejects tampering', () => {
  const built = buildLease(leaseInput())
  const checked = validateLease(JSON.parse(JSON.stringify(built.lease)))
  assert.equal(checked.ok, true)

  const wrongSchema = { ...built.lease, schema_version: 'scheduler-lease/v2' }
  assert.equal(validateLease(wrongSchema).ok, false)

  const notDurable = { ...built.lease, store: { ...built.lease.store, durable: false } }
  assert.equal(validateLease(notDurable).ok, false)
  assert.ok(validateLease(notDurable).errors.includes('lease-store-invalid'))

  assert.equal(validateLease(null).ok, false)
})

test('lease: normalizeCancel accepts null/epoch and rejects partial records', () => {
  assert.deepEqual(normalizeCancel(undefined), { requested_at: null, token_id: null })
  assert.deepEqual(normalizeCancel({ requested_at: null, token_id: null }), { requested_at: null, token_id: null })
  assert.equal(normalizeCancel({ requested_at: null, token_id: 'x' }), null)
  assert.equal(normalizeCancel({ requested_at: '2026-10-19T00:00:00.000Z', token_id: null }), null)
  assert.deepEqual(
    normalizeCancel({ requested_at: '2026-10-19T00:00:00.000Z', token_id: 'cancel-1' }),
    { requested_at: '2026-10-19T00:00:00.000Z', token_id: 'cancel-1' },
  )
})

test('lease: fencingRelation classifies current/stale/future/invalid', () => {
  assert.equal(fencingRelation(5, 5), 'current')
  assert.equal(fencingRelation(5, 4), 'stale')
  assert.equal(fencingRelation(5, 0), 'stale')
  assert.equal(fencingRelation(5, 6), 'future')
  assert.equal(fencingRelation(5, '5'), 'invalid')
  assert.equal(fencingRelation(5, 1.5), 'invalid')
})

test('lease: assertFencingCurrent rejects stale token, wrong state and expired lease', () => {
  const built = buildLease(leaseInput())
  const lease = built.lease
  assert.deepEqual(assertFencingCurrent(lease, 1), { ok: true })
  assert.deepEqual(assertFencingCurrent(lease, 2), { ok: false, reason: 'fencing-token-unknown' })
  assert.deepEqual(assertFencingCurrent(lease, 0), { ok: false, reason: 'fencing-token-stale' })
  assert.deepEqual(assertFencingCurrent(null, 1), { ok: false, reason: 'lease-not-found' })

  const released = { ...lease, state: 'released' }
  assert.deepEqual(assertFencingCurrent(released, 1), { ok: false, reason: 'lease-released' })

  // 2026-10-19T00:01:00.000Z is the lease expiry.
  assert.deepEqual(
    assertFencingCurrent(lease, 1, { atWallMs: Date.UTC(2026, 9, 19, 0, 1, 0) }),
    { ok: false, reason: 'lease-expired' },
  )
  assert.equal(isLeaseActive(lease, Date.UTC(2026, 9, 19, 0, 0, 30)), true)
  assert.equal(isLeaseActive(lease, Date.UTC(2026, 9, 19, 0, 1, 0)), false)
  assert.equal(isLeaseActive(released, Date.UTC(2026, 9, 19, 0, 0, 30)), false)
})
