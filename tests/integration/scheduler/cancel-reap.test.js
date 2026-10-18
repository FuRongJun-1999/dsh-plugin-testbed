/**
 * Integration: durable cancel + complete process-tree reclamation confirmation.
 * Uses a real Node process tree and the OS-measured default reaper; failed or
 * unconfirmed reaps never become acknowledged cancels.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import {
  isPidAlive,
  terminateProcessTree,
} from '../../../src/scheduler/index.js'
import {
  TARGET_A,
  createTestScheduler,
  enqueueAndAcquire,
  registerTestSchedule,
} from '../../unit/scheduler/_helpers.js'

const TREE_FIXTURE = fileURLToPath(new URL('./fixtures/tree-child.mjs', import.meta.url))

function readPidLine(child, timeoutMs = 10_000) {
  return new Promise((resolve, reject) => {
    let buffer = ''
    const timer = setTimeout(() => reject(new Error('pid line timeout')), timeoutMs)
    child.stdout.setEncoding('utf8')
    child.stdout.on('data', (chunk) => {
      buffer += chunk
      const index = buffer.indexOf('\n')
      if (index >= 0) {
        clearTimeout(timer)
        resolve(Number(buffer.slice(0, index)))
      }
    })
    child.once('error', (error) => {
      clearTimeout(timer)
      reject(error)
    })
  })
}

async function spawnTree(t) {
  const root = spawn(process.execPath, [TREE_FIXTURE], {
    stdio: ['ignore', 'pipe', 'ignore'],
    windowsHide: true,
  })
  t.after(async () => {
    await terminateProcessTree(root.pid, { timeoutMs: 5_000 })
  })
  const grandchildPid = await readPidLine(root)
  assert.ok(Number.isSafeInteger(grandchildPid) && grandchildPid > 0)
  return { root, grandchildPid }
}

function trackedFixture(t) {
  const fixture = createTestScheduler(t)
  const { scheduler } = fixture
  assert.equal(registerTestSchedule(scheduler, fixture).result.ok, true)
  return fixture
}

test('cancel: real process tree is reclaimed, acknowledged and audited; re-cancel is idempotent', async (t) => {
  const fixture = trackedFixture(t)
  const { scheduler, clock } = fixture
  const { root, grandchildPid } = await spawnTree(t)
  const { acquired } = enqueueAndAcquire(scheduler, { ttlMs: 60_000 })
  assert.equal(acquired.ok, true)

  const tracked = scheduler.trackProcessTree({
    leaseId: acquired.lease.lease_id,
    fencingToken: acquired.lease.fencing_token,
    rootPid: root.pid,
    knownChildPids: [grandchildPid],
  })
  assert.equal(tracked.ok, true, tracked.reason_codes?.join(','))

  assert.equal(isPidAlive(root.pid), true)
  assert.equal(isPidAlive(grandchildPid), true)

  const cancelled = await scheduler.cancel({
    leaseId: acquired.lease.lease_id,
    actor: { id: 'operator:alice', role: 'operator' },
    reason: 'integration cancel',
    timeoutMs: 8_000,
  })
  assert.equal(cancelled.ok, true, cancelled.reason_codes?.join(','))
  assert.equal(cancelled.cancel_acknowledged, true)
  assert.equal(cancelled.reaped, true)
  assert.deepEqual(cancelled.remaining, [])
  assert.equal(cancelled.lease.state, 'cancelled')
  assert.equal(isPidAlive(root.pid), false, 'root process must be observed gone')
  assert.equal(isPidAlive(grandchildPid), false, 'grandchild process must be observed gone')

  const timeline = scheduler.timeline({ leaseId: acquired.lease.lease_id })
  assert.deepEqual(timeline.events.map((event) => event.type), ['acquire', 'cancel', 'reap'])
  assert.equal(timeline.events.at(-1).payload.outcome, 'reaped')
  assert.deepEqual(timeline.events.at(-1).payload.remaining, [])
  assert.equal(timeline.events.at(-1).fencing_token, acquired.lease.fencing_token)

  const again = await scheduler.cancel({
    leaseId: acquired.lease.lease_id,
    actor: { id: 'operator:alice', role: 'operator' },
  })
  assert.equal(again.ok, true)
  assert.equal(again.idempotent, true)
  assert.equal(again.cancel_acknowledged, true)

  const queue = scheduler.timeline()
  assert.equal(queue.ok, true)
  assert.equal(scheduler.verify().integrity.event_chain.ok, true)
  clock.advance(1_000)
})

test('cancel: failed reap is not acknowledged; retry with a confirmed reap completes idempotently', async (t) => {
  const fixture = trackedFixture(t)
  const { scheduler } = fixture
  const { acquired } = enqueueAndAcquire(scheduler, { ttlMs: 60_000 })
  assert.equal(scheduler.trackProcessTree({
    leaseId: acquired.lease.lease_id,
    fencingToken: acquired.lease.fencing_token,
    rootPid: 987_654,
    knownChildPids: [987_655],
  }).ok, true)

  const failed = await scheduler.cancel({
    leaseId: acquired.lease.lease_id,
    actor: { id: 'operator:alice', role: 'operator' },
    reason: 'reap should fail',
    reaper: async () => ({ ok: false, remaining: [987_654, 987_655], mechanism: 'injected-failure' }),
  })
  assert.equal(failed.ok, false)
  assert.ok(failed.reason_codes.includes('cancel-not-acknowledged'), JSON.stringify(failed.reason_codes))
  assert.ok(failed.reason_codes.includes('reap-incomplete'))
  assert.deepEqual(failed.remaining, [987_654, 987_655])
  assert.equal(failed.cancel_acknowledged, false)

  // The cancel request itself is durable: the lease cannot accept results now.
  const blockedResult = scheduler.submitResult({
    leaseId: acquired.lease.lease_id,
    fencingToken: acquired.lease.fencing_token,
    runId: acquired.lease.run_id,
    result: { status: 'healthy' },
  })
  assert.equal(blockedResult.ok, false)

  const events = scheduler.timeline({ leaseId: acquired.lease.lease_id })
  assert.deepEqual(events.events.map((event) => event.type), ['acquire', 'cancel', 'reap'])
  assert.equal(events.events.at(-1).payload.outcome, 'failed')

  const retried = await scheduler.reap({
    leaseId: acquired.lease.lease_id,
    actor: { id: 'operator:alice', role: 'operator' },
    reaper: async () => ({ ok: true, remaining: [], mechanism: 'injected-success' }),
  })
  assert.equal(retried.ok, true, retried.reason_codes?.join(','))
  assert.equal(retried.cancel_acknowledged, true)
  assert.equal(retried.mechanism, 'injected-success')
  const leaseEvents = scheduler.timeline({ leaseId: acquired.lease.lease_id })
  assert.deepEqual(leaseEvents.events.map((event) => event.type), ['acquire', 'cancel', 'reap', 'reap'])
})

test('cancel: no tracked process tree cannot be acknowledged (fail-closed)', async (t) => {
  const fixture = trackedFixture(t)
  const { scheduler } = fixture
  const { acquired } = enqueueAndAcquire(scheduler, { ttlMs: 60_000 })
  const result = await scheduler.cancel({
    leaseId: acquired.lease.lease_id,
    actor: { id: 'operator:alice', role: 'operator' },
    reason: 'unknown tree',
  })
  assert.equal(result.ok, false)
  assert.ok(result.reason_codes.includes('cancel-not-acknowledged'))
  assert.ok(result.reason_codes.includes('reap-incomplete'))
  assert.equal(result.cancel_acknowledged, false)
  assert.equal(isPidAlive(process.pid), true)
  const events = scheduler.timeline({ leaseId: acquired.lease.lease_id })
  assert.deepEqual(events.events.map((event) => event.type), ['acquire', 'cancel', 'reap'])
  assert.equal(events.events.at(-1).payload.error, 'no tracked process tree')
})

test('cancel: cancelAll reclaims every tracked lease with the injected reaper', async (t) => {
  const fixture = createTestScheduler(t, {
    reaper: async () => ({ ok: true, remaining: [], mechanism: 'test-reaper' }),
  })
  const { scheduler } = fixture
  assert.equal(registerTestSchedule(scheduler, fixture, {
    scheduleId: 'sched-a', targetDigest: TARGET_A,
  }).result.ok, true)
  assert.equal(registerTestSchedule(scheduler, fixture, {
    scheduleId: 'sched-b', targetDigest: 'sha256:' + 'b'.repeat(64),
  }).result.ok, true)
  const first = enqueueAndAcquire(scheduler, { scheduleId: 'sched-a', runId: 'run-1', idempotencyKey: 'idem-1' })
  const second = enqueueAndAcquire(scheduler, { scheduleId: 'sched-b', runId: 'run-2', idempotencyKey: 'idem-2' })
  assert.equal(first.acquired.ok, true)
  assert.equal(second.acquired.ok, true)
  assert.equal(scheduler.trackProcessTree({
    leaseId: first.acquired.lease.lease_id,
    fencingToken: first.acquired.lease.fencing_token,
    rootPid: 900_001,
  }).ok, true)
  assert.equal(scheduler.trackProcessTree({
    leaseId: second.acquired.lease.lease_id,
    fencingToken: second.acquired.lease.fencing_token,
    rootPid: 900_002,
  }).ok, true)
  const all = await scheduler.cancelAll({
    actor: { id: 'operator:alice', role: 'operator' },
    reason: 'global cancel',
  })
  assert.equal(all.ok, true, JSON.stringify(all.results?.map((entry) => entry.result?.reason_codes ?? null)))
  assert.equal(all.cancelled, 2)
  assert.equal(all.attempted, 2)
  for (const entry of all.results) assert.equal(entry.result.ok, true)
})

test('cancel: unknown and released leases are handled without destructive side effects', async (t) => {
  const fixture = trackedFixture(t)
  const { scheduler } = fixture
  const missing = await scheduler.cancel({
    leaseId: 'lease-does-not-exist', actor: { id: 'operator:alice', role: 'operator' },
  })
  assert.equal(missing.ok, false)
  assert.ok(missing.reason_codes.includes('lease-not-found'))

  const { acquired } = enqueueAndAcquire(scheduler, { ttlMs: 60_000 })
  assert.equal(scheduler.release({
    leaseId: acquired.lease.lease_id, fencingToken: acquired.lease.fencing_token,
  }).ok, true)
  const released = await scheduler.cancel({
    leaseId: acquired.lease.lease_id, actor: { id: 'operator:alice', role: 'operator' },
  })
  assert.equal(released.ok, true)
  assert.equal(released.idempotent, true)
  assert.equal(released.cancel_acknowledged, false)
  assert.equal(scheduler.verify().ok, true)
  void TARGET_A
})
