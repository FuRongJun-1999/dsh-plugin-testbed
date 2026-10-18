/**
 * Integration: crash recovery, persisted clock faults and durable kill switch
 * across real SQLite store instances (no in-memory mock).
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createScheduler } from '../../../src/scheduler/index.js'
import {
  TARGET_A,
  createManualClock,
  enqueueAndAcquire,
  makeAuthorization,
  makeEnableAuthorization,
  makeFrozenPlan,
  makePolicy,
  registerTestSchedule,
} from '../../unit/scheduler/_helpers.js'

function workspace(t) {
  const dir = mkdtempSync(join(tmpdir(), 'testbed-scheduler-crash-'))
  return { dir, storePath: join(dir, 'scheduler.sqlite') }
}

function makeScheduler({
  storePath,
  clock,
  policy,
  ownerId,
  isOwnerAlive,
  authorization,
}) {
  return createScheduler({
    enabled: true,
    storePath,
    clock,
    policy,
    authorization: authorization ?? makeEnableAuthorization(clock),
    ownerId,
    host: 'test-host',
    pid: process.pid,
    ...(isOwnerAlive === undefined ? {} : { isOwnerAlive }),
    maxClockSkewMs: 5_000,
    maxForwardJumpMs: 5_000,
  })
}

test('crash: acquire-then-die lease is recovered by the next owner and its old token is fenced', (t) => {
  const { dir, storePath } = workspace(t)
  const clock = createManualClock()
  const planFixture = makeFrozenPlan()
  const policy = makePolicy()
  const fixture = { clock, planFixture, targetDigest: TARGET_A, policy }
  let a = null
  let b = null
  t.after(() => {
    try { a?.close() } catch { /* closed */ }
    try { b?.close() } catch { /* closed */ }
    rmSync(dir, { recursive: true, force: true })
  })

  a = makeScheduler({ storePath, clock, policy, ownerId: 'owner-A' })
  assert.equal(a.status().state, 'enabled')
  assert.equal(registerTestSchedule(a, fixture).result.ok, true)
  const first = enqueueAndAcquire(a, { runId: 'run-1', idempotencyKey: 'idem-1' })
  assert.equal(first.acquired.ok, true)
  a.close() // crash: no release, no cancel, store handle dropped

  b = makeScheduler({ storePath, clock, policy, ownerId: 'owner-B', isOwnerAlive: () => false })
  assert.equal(b.status().state, 'enabled')
  assert.deepEqual(b.status().recovery.recovered, [
    { lease_id: first.acquired.lease.lease_id, reason: 'owner-process-dead' },
  ])

  const timeline = b.timeline({ leaseId: first.acquired.lease.lease_id })
  assert.equal(timeline.ok, true)
  assert.deepEqual(timeline.events.map((event) => event.type), ['acquire', 'expire'])
  assert.equal(timeline.events.at(-1).payload.reason, 'owner-process-dead')
  assert.ok(timeline.events.at(-1).binding.plan_digest)

  const storeTimeline = b.timeline()
  assert.ok(storeTimeline.events.some((event) => event.type === 'store-recover'))

  const oldResult = b.submitResult({
    leaseId: first.acquired.lease.lease_id,
    fencingToken: first.acquired.lease.fencing_token,
    runId: 'run-1',
    result: { status: 'healthy' },
  })
  assert.equal(oldResult.ok, false)
  assert.ok(
    oldResult.reason_codes.some((code) => ['lease-expired', 'fencing-token-stale'].includes(code)),
    JSON.stringify(oldResult.reason_codes),
  )

  const reacquired = b.acquire({ scheduleId: 'sched-1', runId: 'run-1', idempotencyKey: 'idem-1' })
  assert.equal(reacquired.ok, true)
  assert.equal(reacquired.lease.fencing_token, first.acquired.lease.fencing_token + 1)
  assert.equal(b.submitResult({
    leaseId: reacquired.lease.lease_id,
    fencingToken: reacquired.lease.fencing_token,
    runId: 'run-1',
    result: { status: 'healthy' },
  }).ok, true)
  assert.equal(b.verify().ok, true)
})

test('crash: running lease with heartbeat is recovered; heartbeat sequence and event chain survive', (t) => {
  const { dir, storePath } = workspace(t)
  const clock = createManualClock()
  const planFixture = makeFrozenPlan()
  const policy = makePolicy()
  const fixture = { clock, planFixture, targetDigest: TARGET_A, policy }
  let a = null
  let b = null
  t.after(() => {
    try { a?.close() } catch { /* closed */ }
    try { b?.close() } catch { /* closed */ }
    rmSync(dir, { recursive: true, force: true })
  })

  a = makeScheduler({ storePath, clock, policy, ownerId: 'owner-A' })
  registerTestSchedule(a, fixture)
  const first = enqueueAndAcquire(a, { runId: 'run-2', idempotencyKey: 'idem-2', ttlMs: 5_000 })
  assert.equal(first.acquired.ok, true)
  clock.advance(1_000)
  const renewed = a.heartbeat({
    leaseId: first.acquired.lease.lease_id,
    fencingToken: first.acquired.lease.fencing_token,
    ttlMs: 5_000,
  })
  assert.equal(renewed.ok, true)
  assert.equal(renewed.lease.heartbeat_seq, 1)
  a.close()

  b = makeScheduler({ storePath, clock, policy, ownerId: 'owner-B', isOwnerAlive: () => false })
  const timeline = b.timeline({ leaseId: first.acquired.lease.lease_id })
  assert.deepEqual(timeline.events.map((event) => event.type), ['acquire', 'renew', 'expire'])
  assert.equal(timeline.events[1].payload.heartbeat_seq, 1)
  assert.equal(timeline.events[1].fencing_token, first.acquired.lease.fencing_token)

  const renewOld = b.heartbeat({
    leaseId: first.acquired.lease.lease_id,
    fencingToken: first.acquired.lease.fencing_token,
    ownerId: 'owner-A',
    ttlMs: 5_000,
  })
  assert.equal(renewOld.ok, false)
  assert.ok(renewOld.reason_codes.some((code) => ['lease-expired', 'fencing-token-stale'].includes(code)),
    JSON.stringify(renewOld.reason_codes))
  assert.equal(b.verify().integrity.event_chain.ok, true)
})

test('crash: persisted clock fault blocks restart until an explicit operator recovery', (t) => {
  const { dir, storePath } = workspace(t)
  const clock = createManualClock()
  const policy = makePolicy()
  let a = null
  let b = null
  t.after(() => {
    try { a?.close() } catch { /* closed */ }
    try { b?.close() } catch { /* closed */ }
    rmSync(dir, { recursive: true, force: true })
  })

  const highWater = clock.wallNow()
  a = makeScheduler({ storePath, clock, policy, ownerId: 'owner-A' })
  assert.equal(a.status().state, 'enabled')
  clock.shiftWall(-60_000)
  assert.ok(a.status().reason_codes.includes('scheduler-clock-skew'))
  assert.equal(a.store.clockFault().faults.includes('wall-clock-rollback'), true)
  a.close()

  b = makeScheduler({ storePath, clock, policy, ownerId: 'owner-B' })
  const blocked = b.status()
  assert.equal(blocked.state, 'blocked')
  assert.ok(blocked.reason_codes.includes('scheduler-clock-fault-persisted'), JSON.stringify(blocked.reason_codes))

  const whileBehind = b.recoverClockFault({
    actor: { id: 'operator:alice', role: 'operator' }, reason: 'try while behind',
  })
  assert.equal(whileBehind.ok, false)
  assert.ok(whileBehind.reason_codes.includes('scheduler-clock-skew'))

  clock.setWall(highWater)
  const recovered = b.recoverClockFault({
    actor: { id: 'operator:alice', role: 'operator' }, reason: 'wall clock restored and verified',
  })
  assert.equal(recovered.state === 'enabled' || recovered.state === 'blocked', true)
  assert.equal(b.store.clockFault(), null)

  const enabled = b.enable({ authorization: makeEnableAuthorization(clock), policy })
  assert.equal(enabled.state, 'enabled', JSON.stringify(enabled.reason_codes))
})

test('crash: global kill switch survives a store restart and still blocks new acquires', (t) => {
  const { dir, storePath } = workspace(t)
  const clock = createManualClock()
  const planFixture = makeFrozenPlan()
  const policy = makePolicy()
  const fixture = { clock, planFixture, targetDigest: TARGET_A, policy }
  let a = null
  let b = null
  t.after(() => {
    try { a?.close() } catch { /* closed */ }
    try { b?.close() } catch { /* closed */ }
    rmSync(dir, { recursive: true, force: true })
  })

  a = makeScheduler({ storePath, clock, policy, ownerId: 'owner-A' })
  registerTestSchedule(a, fixture)
  const engaged = a.engageKillSwitch({
    actor: { id: 'operator:alice', role: 'operator' }, reason: 'incident',
  })
  assert.equal(engaged.state, 'blocked')
  a.close()

  b = makeScheduler({ storePath, clock, policy, ownerId: 'owner-B' })
  const blocked = b.status()
  assert.equal(blocked.state, 'blocked')
  assert.ok(blocked.reason_codes.includes('scheduler-kill-switch'), JSON.stringify(blocked.reason_codes))
  const enqueue = b.enqueue({ scheduleId: 'sched-1', runId: 'run-1', idempotencyKey: 'idem-1' })
  assert.equal(enqueue.ok, false)
  assert.ok(enqueue.reason_codes.includes('scheduler-kill-switch'))

  const released = b.releaseKillSwitch({
    actor: { id: 'operator:alice', role: 'operator' },
    reason: 'incident resolved',
    authorization: makeAuthorization({ action: 'release-kill-switch', nowMs: clock.wallNow() }),
  })
  assert.equal(released.state, 'enabled', JSON.stringify(released.reason_codes))
  assert.equal(b.enqueue({ scheduleId: 'sched-1', runId: 'run-1', idempotencyKey: 'idem-1' }).ok, true)
})

test('crash: corrupted store file blocks the scheduler instead of being treated as empty', (t) => {
  const { dir, storePath } = workspace(t)
  const clock = createManualClock()
  const policy = makePolicy()
  let a = null
  let b = null
  t.after(() => {
    try { a?.close() } catch { /* closed */ }
    try { b?.close() } catch { /* closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  a = makeScheduler({ storePath, clock, policy, ownerId: 'owner-A' })
  assert.equal(a.status().state, 'enabled')
  a.close()
  writeFileSync(storePath, 'not a sqlite database at all', 'utf8')

  b = makeScheduler({ storePath, clock, policy, ownerId: 'owner-B' })
  const blocked = b.status()
  assert.equal(blocked.state, 'blocked')
  assert.ok(blocked.reason_codes.some((code) =>
    ['scheduler-store-corrupt', 'scheduler-store-unavailable'].includes(code)), JSON.stringify(blocked.reason_codes))
  assert.equal(b.enqueue({ scheduleId: 'sched-1', runId: 'run-1', idempotencyKey: 'idem-1' }).ok, false)
})
