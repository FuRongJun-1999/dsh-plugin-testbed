/**
 * Integration: durable scheduler lifecycle against a real SQLite store
 * (WAL + fsync), two scopes, fencing, TTL/tick and clean reopen persistence.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  createScheduler,
  validateLease,
} from '../../../src/scheduler/index.js'
import {
  TARGET_A,
  TARGET_B,
  createManualClock,
  createTestScheduler,
  enqueueAndAcquire,
  makeEnableAuthorization,
  makeFrozenPlan,
  makePolicy,
  registerTestSchedule,
} from '../../unit/scheduler/_helpers.js'

function submit(scheduler, lease, result = { status: 'healthy', severity: 'info' }) {
  return scheduler.submitResult({
    leaseId: lease.lease_id,
    fencingToken: lease.fencing_token,
    runId: lease.run_id,
    result,
  })
}

test('integration: two governed scopes run, submit and release; events and audit verify', (t) => {
  const fixture = createTestScheduler(t)
  const { scheduler, clock, planFixture } = fixture
  registerTestSchedule(scheduler, fixture, { scheduleId: 'sched-a', targetDigest: TARGET_A })
  registerTestSchedule(scheduler, fixture, { scheduleId: 'sched-b', targetDigest: TARGET_B })

  const a = enqueueAndAcquire(scheduler, { scheduleId: 'sched-a', runId: 'run-a', idempotencyKey: 'idem-a' })
  const b = enqueueAndAcquire(scheduler, { scheduleId: 'sched-b', runId: 'run-b', idempotencyKey: 'idem-b' })
  assert.equal(a.acquired.ok, true, a.acquired.reason_codes?.join(','))
  assert.equal(b.acquired.ok, true, b.acquired.reason_codes?.join(','))
  assert.equal(a.acquired.lease.fencing_token, 1)
  assert.equal(b.acquired.lease.fencing_token, 1, 'fencing tokens are per scope')
  assert.equal(validateLease(JSON.parse(JSON.stringify(a.acquired.lease))).ok, true)

  clock.advance(500)
  assert.equal(scheduler.heartbeat({
    leaseId: a.acquired.lease.lease_id, fencingToken: a.acquired.lease.fencing_token, ttlMs: 60_000,
  }).ok, true)
  assert.equal(submit(scheduler, a.acquired.lease).ok, true)
  assert.equal(submit(scheduler, b.acquired.lease).ok, true)
  assert.equal(scheduler.release({
    leaseId: a.acquired.lease.lease_id, fencingToken: a.acquired.lease.fencing_token,
  }).ok, true)
  assert.equal(scheduler.release({
    leaseId: b.acquired.lease.lease_id, fencingToken: b.acquired.lease.fencing_token,
  }).ok, true)

  for (const lease of [a.acquired.lease, b.acquired.lease]) {
    const timeline = scheduler.timeline({ leaseId: lease.lease_id })
    assert.equal(timeline.ok, true)
    assert.equal(timeline.events[0].type, 'acquire')
    assert.equal(timeline.events.at(-1).type, 'release')
    for (const event of timeline.events) {
      assert.equal(event.binding.plan_digest, planFixture.planDigest)
      assert.equal(event.binding.policy_digest, a.acquired.binding.policy_digest)
    }
  }
  const verify = scheduler.verify()
  assert.equal(verify.ok, true)
  assert.equal(verify.integrity.event_chain.ok, true)
  assert.equal(verify.integrity.counts.queue, 2)
  assert.equal(scheduler.status().counts.active_leases, 0)
  assert.equal(scheduler.auditLog().entries.some((entry) => entry.action === 'schedule-create'), true)
})

test('integration: fencing tokens are monotonic per scope and old tokens cannot write results', (t) => {
  const fixture = createTestScheduler(t)
  const { scheduler } = fixture
  assert.equal(registerTestSchedule(scheduler, fixture).result.ok, true)
  const tokens = []
  const leases = []
  for (let i = 1; i <= 3; i += 1) {
    scheduler.enqueue({ scheduleId: 'sched-1', runId: `run-${i}`, idempotencyKey: `idem-${i}` })
    const acquired = scheduler.acquire({ scheduleId: 'sched-1', runId: `run-${i}`, idempotencyKey: `idem-${i}` })
    assert.equal(acquired.ok, true)
    tokens.push(acquired.lease.fencing_token)
    leases.push(acquired.lease)
    assert.equal(submit(scheduler, acquired.lease).ok, true)
    scheduler.release({ leaseId: acquired.lease.lease_id, fencingToken: acquired.lease.fencing_token })
  }
  assert.deepEqual(tokens, [1, 2, 3])

  for (const lease of leases.slice(0, 2)) {
    const stale = submit(scheduler, lease)
    assert.equal(stale.ok, false)
    assert.ok(stale.reason_codes.includes('fencing-token-stale'), JSON.stringify(stale.reason_codes))
  }
})

test('integration: TTL expiry + deterministic tick requeue the run and fence the next owner', (t) => {
  const fixture = createTestScheduler(t)
  const { scheduler, clock } = fixture
  assert.equal(registerTestSchedule(scheduler, fixture).result.ok, true)
  const { acquired } = enqueueAndAcquire(scheduler, { ttlMs: 1_000 })
  clock.advance(1_500)

  const tick = scheduler.tick()
  assert.equal(tick.ok, true)
  assert.equal(tick.expired.length, 1)
  assert.equal(tick.cron_enabled, false)
  assert.equal(tick.background, false)

  const next = scheduler.acquire({ scheduleId: 'sched-1', runId: 'run-1', idempotencyKey: 'idem-1' })
  assert.equal(next.ok, true)
  assert.equal(next.lease.fencing_token, acquired.lease.fencing_token + 1)
})

test('integration: clean close/reopen keeps active leases durable; TTL eventually frees the scope', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'testbed-scheduler-int-'))
  const storePath = join(dir, 'scheduler.sqlite')
  const clock = createManualClock()
  const policy = makePolicy()
  const planFixture = makeFrozenPlan()
  let first = null
  let second = null
  t.after(() => {
    try { first?.close() } catch { /* closed */ }
    try { second?.close() } catch { /* closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  first = createScheduler({
    enabled: true,
    storePath,
    clock,
    policy,
    authorization: makeEnableAuthorization(clock),
    ownerId: 'owner-A',
    host: 'test-host',
    pid: process.pid,
    maxClockSkewMs: 5_000,
    maxForwardJumpMs: 5_000,
  })
  assert.equal(first.status().state, 'enabled')
  const fixture = { clock, planFixture, targetDigest: TARGET_A, policy }
  assert.equal(registerTestSchedule(first, fixture).result.ok, true)
  const { acquired } = enqueueAndAcquire(first, { ttlMs: 2_000 })
  assert.equal(acquired.ok, true)
  first.close()

  second = createScheduler({
    enabled: true,
    storePath,
    clock,
    policy,
    authorization: makeEnableAuthorization(clock),
    ownerId: 'owner-B',
    host: 'test-host',
    pid: process.pid,
    isOwnerAlive: () => true, // owner-A still considered alive => lease preserved
    maxClockSkewMs: 5_000,
    maxForwardJumpMs: 5_000,
  })
  assert.equal(second.status().state, 'enabled')
  const recovered = second.recover()
  assert.equal(recovered.ok, true)
  assert.deepEqual(recovered.kept, [acquired.lease.lease_id])

  const conflict = second.acquire({ scheduleId: 'sched-1', runId: 'run-1', idempotencyKey: 'idem-1' })
  assert.equal(conflict.ok, false)
  assert.ok(['lease-acquire-conflict', 'scheduler-duplicate-run'].includes(conflict.reason_codes[0]),
    JSON.stringify(conflict.reason_codes))

  clock.advance(3_000)
  const tick = second.tick()
  assert.equal(tick.ok, true)
  const afterExpiry = second.acquire({ scheduleId: 'sched-1', runId: 'run-1', idempotencyKey: 'idem-1' })
  assert.equal(afterExpiry.ok, true)
  assert.equal(afterExpiry.lease.fencing_token, acquired.lease.fencing_token + 1)
  assert.equal(second.verify().ok, true)
})

test('integration: policy concurrency limits are enforced against durable active leases', (t) => {
  const fixture = createTestScheduler(t, {
    policy: makePolicy({ max_global_concurrency: 1, max_target_concurrency: 1 }),
  })
  const { scheduler, clock, planFixture } = fixture
  registerTestSchedule(scheduler, fixture, { scheduleId: 'sched-a', targetDigest: TARGET_A })
  registerTestSchedule(scheduler, fixture, { scheduleId: 'sched-b', targetDigest: TARGET_B })

  const a = enqueueAndAcquire(scheduler, { scheduleId: 'sched-a', runId: 'run-a', idempotencyKey: 'idem-a' })
  assert.equal(a.acquired.ok, true)
  scheduler.enqueue({ scheduleId: 'sched-b', runId: 'run-b', idempotencyKey: 'idem-b' })
  const limited = scheduler.acquire({ scheduleId: 'sched-b', runId: 'run-b', idempotencyKey: 'idem-b' })
  assert.equal(limited.ok, false)
  assert.ok(limited.reason_codes.includes('scheduler-concurrency-limit'))

  scheduler.release({ leaseId: a.acquired.lease.lease_id, fencingToken: a.acquired.lease.fencing_token })
  const allowed = scheduler.acquire({ scheduleId: 'sched-b', runId: 'run-b', idempotencyKey: 'idem-b' })
  assert.equal(allowed.ok, true)
  assert.equal(allowed.binding.target_digest, TARGET_B)
})
