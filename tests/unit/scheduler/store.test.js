/**
 * Durable SQLite store unit tests: transaction/CAS acquire, fencing, TTL,
 * append-only events, persistence across reopen, kill switch, corruption and
 * DB-level single-owner enforcement. Real `node:sqlite` files (no mock).
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import {
  SchedulerStoreError,
  buildMonitoringObservation,
  normalizeScope,
  openSchedulerStore,
  validateLease,
} from '../../../src/scheduler/index.js'

const BASE_MS = Date.UTC(2026, 9, 19, 0, 0, 0)
const TARGET_A = 'sha256:' + 'a'.repeat(64)
const TARGET_B = 'sha256:' + 'b'.repeat(64)
const PLAN = 'sha256:' + '1'.repeat(64)
const POLICY = 'sha256:' + '2'.repeat(64)

function at(offsetMs = 0) {
  return { atMs: BASE_MS + offsetMs, atIso: new Date(BASE_MS + offsetMs).toISOString() }
}

function tempDir(t) {
  const dir = mkdtempSync(join(tmpdir(), 'testbed-store-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function openStore(t, { file = 'scheduler.sqlite' } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'testbed-store-'))
  const filePath = join(dir, file)
  const store = openSchedulerStore({ filePath, atIso: at().atIso })
  t.after(() => {
    try { store.close() } catch { /* closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return { store, dir, filePath }
}

function registerSchedule(store, { scheduleId = 'sched-1', target = TARGET_A, atMs = BASE_MS } = {}) {
  return store.registerSchedule({
    scheduleId,
    version: 1,
    contentDigest: 'sha256:' + 'c'.repeat(64),
    planDigest: PLAN,
    targetDigest: target,
    policyDigest: POLICY,
    config: { schema_version: 'scheduler-schedule/v1', schedule_id: scheduleId, target_digest: target },
    atIso: new Date(atMs).toISOString(),
  })
}

function enqueue(store, {
  scheduleId = 'sched-1',
  runId = 'run-1',
  idempotencyKey = 'idem-1',
  target = TARGET_A,
  atMs = BASE_MS,
  maxQueueDepth = 10,
} = {}) {
  const scope = normalizeScope({ profile: 'local', target_digest: target, max_concurrency: 1 })
  assert.equal(scope.ok, true)
  return store.enqueue({
    schedule: { scheduleId, planDigest: PLAN, targetDigest: target, policyDigest: POLICY },
    scopeKey: scope.scopeKey,
    runId,
    idempotencyKey,
    atIso: new Date(atMs).toISOString(),
    maxQueueDepth,
  })
}

function acquire(store, {
  scheduleId = 'sched-1',
  runId = 'run-1',
  idempotencyKey = 'idem-1',
  ownerId = 'owner-A',
  target = TARGET_A,
  ttlMs = 60_000,
  atMs = BASE_MS,
  maxGlobalConcurrency = 4,
  maxTargetConcurrency = 4,
} = {}) {
  return store.acquire({
    schedule: { scheduleId, planDigest: PLAN, targetDigest: target, policyDigest: POLICY },
    scope: { profile: 'local', target_digest: target, tenant: 'local', max_concurrency: 1 },
    scopeKey: normalizeScope({ profile: 'local', target_digest: target, max_concurrency: 1 }).scopeKey,
    ownerId,
    runId,
    idempotencyKey,
    ttlMs,
    atIso: new Date(atMs).toISOString(),
    atMs,
    maxGlobalConcurrency,
    maxTargetConcurrency,
  })
}

function observation(lease) {
  const built = buildMonitoringObservation(
    { status: 'healthy', severity: 'info', metrics: { latency_ms: 5 } },
    {
      scheduleId: lease.schedule_id,
      runId: lease.run_id,
      leaseId: lease.lease_id,
      fencingToken: lease.fencing_token,
      atIso: new Date(BASE_MS).toISOString(),
      binding: {
        schedule_id: lease.schedule_id,
        plan_digest: PLAN,
        policy_digest: POLICY,
        target_digest: TARGET_A,
      },
    },
  )
  assert.equal(built.ok, true)
  return built
}

test('store: opens WAL + synchronous=FULL, initialises versioned meta and verifies integrity', (t) => {
  const { store } = openStore(t)
  const facts = store.storeFacts()
  assert.equal(facts.journal_mode, 'wal')
  assert.equal(facts.synchronous, 'FULL')
  assert.equal(facts.provider.durable, true)
  assert.equal(facts.provider.single_host, true)
  assert.equal(facts.provider.ha, false)
  const integrity = store.verifyIntegrity()
  assert.equal(integrity.ok, true, integrity.errors.join(','))
  assert.deepEqual(integrity.counts, { leases: 0, events: 0, queue: 0 })
  assert.equal(integrity.event_chain.count, 0)
  assert.deepEqual(store.killSwitch(), {
    engaged: false, actor_id: null, actor_role: null, at: null, reason: null,
  })
  assert.equal(store.clockFault(), null)
})

test('store: schedule registration is idempotent by digest and conflicts otherwise', (t) => {
  const { store } = openStore(t)
  assert.equal(registerSchedule(store).ok, true)
  const again = registerSchedule(store)
  assert.equal(again.ok, true)
  assert.equal(again.idempotent, true)

  const conflict = store.registerSchedule({
    scheduleId: 'sched-1',
    version: 2,
    contentDigest: 'sha256:' + 'd'.repeat(64),
    planDigest: PLAN,
    targetDigest: TARGET_A,
    policyDigest: POLICY,
    config: {},
    atIso: at().atIso,
  })
  assert.equal(conflict.ok, false)
  assert.equal(conflict.reason, 'scheduler-schedule-conflict')

  const missing = store.setScheduleState({ scheduleId: 'nope', state: 'paused', atIso: at().atIso })
  assert.equal(missing.ok, false)
  assert.equal(missing.reason, 'scheduler-schedule-not-found')
})

test('store: enqueue dedupes by idempotency key, records duplicate-detect, enforces queue depth', (t) => {
  const { store } = openStore(t)
  registerSchedule(store)
  const first = enqueue(store)
  assert.equal(first.ok, true)

  const duplicate = enqueue(store)
  assert.equal(duplicate.ok, false)
  assert.equal(duplicate.reason, 'scheduler-duplicate-run')
  assert.equal(duplicate.duplicate, true)
  assert.equal(duplicate.queue_id, first.queue_id)

  const events = store.readEvents()
  assert.ok(events.some((event) => event.type === 'duplicate-detect'))
  assert.equal(verifyChain(store).ok, true)

  const full = enqueue(store, { runId: 'run-2', idempotencyKey: 'idem-2', maxQueueDepth: 1 })
  assert.equal(full.ok, false)
  assert.equal(full.reason, 'scheduler-queue-full')
})

function verifyChain(store) {
  return store.verifyEvents()
}

test('store: transactional acquire enforces a single active owner per scope', (t) => {
  const { store, filePath } = openStore(t)
  registerSchedule(store)
  enqueue(store, { runId: 'run-1', idempotencyKey: 'idem-1' })
  enqueue(store, { runId: 'run-2', idempotencyKey: 'idem-2' })

  const first = acquire(store)
  assert.equal(first.ok, true)
  assert.equal(validateLease(JSON.parse(JSON.stringify(first.lease))).ok, true)
  assert.equal(first.lease.fencing_token, 1)
  assert.equal(first.lease.epoch, 1)
  assert.equal(first.binding.plan_digest, PLAN)
  assert.equal(first.binding.policy_digest, POLICY)
  assert.equal(first.binding.target_digest, TARGET_A)

  const second = acquire(store, { runId: 'run-2', idempotencyKey: 'idem-2', ownerId: 'owner-B' })
  assert.equal(second.ok, false)
  assert.equal(second.reason, 'lease-acquire-conflict')
  assert.equal(second.owner_id, 'owner-A')

  // The partial unique index is the DB-level final arbiter: a raw second active
  // row for the same scope cannot be inserted even bypassing application checks.
  const raw = new DatabaseSync(filePath)
  try {
    assert.throws(() => {
      raw.prepare(
        'INSERT INTO scheduler_leases (lease_id, run_id, schedule_id, owner_id, scope_key, scope_json, profile, tenant, ' +
        'target_digest, plan_digest, policy_digest, fencing_token, epoch, state, acquired_at, expires_at, expires_at_ms, ' +
        'ttl_ms, heartbeat_seq, evidence_refs_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)',
      ).run(
        'raw-lease', 'run-raw', 'sched-1', 'owner-X', first.binding.scope_key, '{}', 'local', 'local',
        TARGET_A, PLAN, POLICY, 99, 99, 'active', at().atIso, at(60_000).atIso, BASE_MS + 60_000, 60_000, '[]',
      )
    }, /UNIQUE|constraint/i)
  } finally {
    raw.close()
  }

  const released = store.release({
    leaseId: first.lease.lease_id,
    fencingToken: first.lease.fencing_token,
    ownerId: 'owner-A',
    atIso: at(1_000).atIso,
    actor: { id: 'owner-A', role: 'scheduler' },
  })
  assert.equal(released.ok, true)

  const third = acquire(store, { runId: 'run-2', idempotencyKey: 'idem-2', ownerId: 'owner-B', atMs: BASE_MS + 1_000 })
  assert.equal(third.ok, true)
  assert.equal(third.lease.fencing_token, 2, 'fencing token must be monotonic per scope')
  assert.equal(third.lease.owner_id, 'owner-B')
})

test('store: renew/release enforce fencing, owner and lifecycle state', (t) => {
  const { store } = openStore(t)
  registerSchedule(store)
  enqueue(store)
  const acquired = acquire(store)
  assert.equal(acquired.ok, true)
  const lease = acquired.lease

  const renew = store.renew({
    leaseId: lease.lease_id,
    fencingToken: lease.fencing_token,
    ownerId: 'owner-A',
    ttlMs: 60_000,
    atIso: at(1_000).atIso,
    atMs: BASE_MS + 1_000,
  })
  assert.equal(renew.ok, true)
  assert.equal(renew.lease.heartbeat_seq, 1)
  assert.ok(Date.parse(renew.lease.expires_at) > Date.parse(lease.expires_at))

  const stale = store.renew({
    leaseId: lease.lease_id, fencingToken: lease.fencing_token - 1, ownerId: 'owner-A',
    ttlMs: 60_000, atIso: at(2_000).atIso, atMs: BASE_MS + 2_000,
  })
  assert.equal(stale.ok, false)
  assert.equal(stale.reason, 'fencing-token-stale')

  const future = store.renew({
    leaseId: lease.lease_id, fencingToken: lease.fencing_token + 1, ownerId: 'owner-A',
    ttlMs: 60_000, atIso: at(2_000).atIso, atMs: BASE_MS + 2_000,
  })
  assert.equal(future.ok, false)
  assert.equal(future.reason, 'fencing-token-unknown')

  const wrongOwner = store.renew({
    leaseId: lease.lease_id, fencingToken: lease.fencing_token, ownerId: 'owner-B',
    ttlMs: 60_000, atIso: at(2_000).atIso, atMs: BASE_MS + 2_000,
  })
  assert.equal(wrongOwner.ok, false)
  assert.equal(wrongOwner.reason, 'lease-owner-mismatch')

  const released = store.release({
    leaseId: lease.lease_id, fencingToken: lease.fencing_token, ownerId: 'owner-A',
    atIso: at(3_000).atIso, actor: { id: 'owner-A', role: 'scheduler' },
  })
  assert.equal(released.ok, true)
  assert.equal(released.lease.state, 'released')

  const idempotent = store.release({
    leaseId: lease.lease_id, fencingToken: lease.fencing_token, ownerId: 'owner-A',
    atIso: at(4_000).atIso,
  })
  assert.equal(idempotent.ok, true)
  assert.equal(idempotent.idempotent, true)

  const renewAfterRelease = store.renew({
    leaseId: lease.lease_id, fencingToken: lease.fencing_token, ownerId: 'owner-A',
    ttlMs: 60_000, atIso: at(5_000).atIso, atMs: BASE_MS + 5_000,
  })
  assert.equal(renewAfterRelease.ok, false)
  assert.equal(renewAfterRelease.reason, 'lease-not-active')
})

test('store: stale fencing token result write is rejected after expiry + reacquire', (t) => {
  const { store } = openStore(t)
  registerSchedule(store)
  enqueue(store)
  const first = acquire(store)
  assert.equal(first.ok, true)

  const maintenance = store.expireStale({ atIso: at(60_001).atIso, atMs: BASE_MS + 60_001 })
  assert.equal(maintenance.ok, true)
  assert.equal(maintenance.expired.length, 1)

  const second = acquire(store, { atMs: BASE_MS + 60_002 })
  assert.equal(second.ok, true)
  assert.equal(second.lease.fencing_token, second.lease.fencing_token)
  assert.ok(second.lease.fencing_token > first.lease.fencing_token)

  const wrapped = observation(first.lease)
  const staleResult = store.submitResult({
    leaseId: first.lease.lease_id,
    fencingToken: first.lease.fencing_token,
    runId: 'run-1',
    observation: wrapped.observation,
    resultDigest: wrapped.digest,
    atIso: at(60_003).atIso,
    atMs: BASE_MS + 60_003,
    actor: { id: 'owner-A', role: 'scheduler' },
  })
  assert.equal(staleResult.ok, false)
  assert.equal(staleResult.reason, 'fencing-token-stale')
  assert.equal(staleResult.current_fencing_token, second.lease.fencing_token)

  const expiredResult = store.submitResult({
    leaseId: first.lease.lease_id,
    fencingToken: first.lease.fencing_token,
    runId: 'run-1',
    observation: wrapped.observation,
    resultDigest: wrapped.digest,
    atIso: at(60_004).atIso,
    atMs: BASE_MS + 60_004,
    actor: { id: 'owner-A', role: 'scheduler' },
  })
  assert.equal(expiredResult.ok, false)
  assert.equal(expiredResult.reason, 'fencing-token-stale')

  const renewExpired = store.renew({
    leaseId: first.lease.lease_id,
    fencingToken: first.lease.fencing_token,
    ownerId: 'owner-A',
    ttlMs: 60_000,
    atIso: at(60_005).atIso,
    atMs: BASE_MS + 60_005,
  })
  assert.equal(renewExpired.ok, false)
  assert.equal(renewExpired.reason, 'lease-expired')

  const events = store.readEvents()
  const expireEvent = events.find((event) => event.type === 'expire')
  assert.ok(expireEvent)
  assert.equal(expireEvent.binding.plan_digest, PLAN)
})

test('store: current-token results are stored idempotently and reject digest conflicts', (t) => {
  const { store } = openStore(t)
  registerSchedule(store)
  enqueue(store)
  const acquired = acquire(store)
  const lease = acquired.lease
  const wrapped = observation(lease)

  const first = store.submitResult({
    leaseId: lease.lease_id,
    fencingToken: lease.fencing_token,
    runId: lease.run_id,
    observation: wrapped.observation,
    resultDigest: wrapped.digest,
    atIso: at(1_000).atIso,
    atMs: BASE_MS + 1_000,
    actor: { id: 'owner-A', role: 'scheduler' },
  })
  assert.equal(first.ok, true)
  assert.equal(first.idempotent, false)
  assert.equal(first.observation.gate_effect, 'none')

  const idempotent = store.submitResult({
    leaseId: lease.lease_id,
    fencingToken: lease.fencing_token,
    runId: lease.run_id,
    observation: wrapped.observation,
    resultDigest: wrapped.digest,
    atIso: at(2_000).atIso,
    atMs: BASE_MS + 2_000,
    actor: { id: 'owner-A', role: 'scheduler' },
  })
  assert.equal(idempotent.ok, true)
  assert.equal(idempotent.idempotent, true)
  assert.equal(idempotent.result_id, first.result_id)

  const conflict = store.submitResult({
    leaseId: lease.lease_id,
    fencingToken: lease.fencing_token,
    runId: lease.run_id,
    observation: wrapped.observation,
    resultDigest: 'sha256:' + 'f'.repeat(64),
    atIso: at(3_000).atIso,
    atMs: BASE_MS + 3_000,
    actor: { id: 'owner-A', role: 'scheduler' },
  })
  assert.equal(conflict.ok, false)
  assert.equal(conflict.reason, 'scheduler-result-conflict')
})

test('store: events are append-only at the SQLite trigger level and form a verified hash chain', (t) => {
  const { store, filePath } = openStore(t)
  registerSchedule(store)
  enqueue(store)
  const acquired = acquire(store)
  store.renew({
    leaseId: acquired.lease.lease_id, fencingToken: acquired.lease.fencing_token,
    ownerId: 'owner-A', ttlMs: 60_000, atIso: at(1_000).atIso, atMs: BASE_MS + 1_000,
  })

  const chain = store.verifyEvents()
  assert.equal(chain.ok, true, chain.errors.join(','))
  assert.ok(chain.count >= 2)
  assert.equal(chain.last_digest, store.readEvents().at(-1).event_digest)
  store.appendAudit({
    action: 'test-audit', actor: { id: 'system', role: 'system' }, atIso: at(2_000).atIso,
  })

  const raw = new DatabaseSync(filePath)
  try {
    assert.throws(() => raw.exec('UPDATE scheduler_events SET type = \'release\''),
      /append-only/i)
    assert.throws(() => raw.exec('DELETE FROM scheduler_events'), /append-only/i)
    assert.throws(() => raw.exec('UPDATE scheduler_audit SET action = \'x\''), /append-only/i)
  } finally {
    raw.close()
  }
})

test('store: leases survive close/reopen; recovery expires dead-owner leases and fencing continues', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'testbed-store-'))
  const filePath = join(dir, 'scheduler.sqlite')
  const first = openSchedulerStore({ filePath, atIso: at().atIso })
  let reopened = null
  t.after(() => {
    try { first.close() } catch { /* closed */ }
    try { reopened?.close() } catch { /* closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  registerSchedule(first)
  enqueue(first)
  const acquired = acquire(first)
  assert.equal(acquired.ok, true)
  first.close()

  reopened = openSchedulerStore({ filePath, atIso: at(1_000).atIso })
  const loaded = reopened.getLease(acquired.lease.lease_id)
  assert.equal(loaded.lease.state, 'active')
  assert.equal(loaded.lease.fencing_token, acquired.lease.fencing_token)
  assert.equal(reopened.verifyEvents().ok, true)

  const recovered = reopened.recover({
    atIso: at(1_000).atIso,
    atMs: BASE_MS + 1_000,
    isOwnerAlive: () => false,
  })
  assert.equal(recovered.recovered.length, 1)
  assert.equal(recovered.recovered[0].reason, 'owner-process-dead')
  assert.equal(reopened.getLease(acquired.lease.lease_id).lease.state, 'expired')

  const queue = reopened.listQueue({ scheduleId: 'sched-1' })
  assert.equal(queue[0].state, 'queued', 'expired lease must requeue its run for retry')

  const next = acquire(reopened, { atMs: BASE_MS + 2_000 })
  assert.equal(next.ok, true)
  assert.equal(next.lease.fencing_token, acquired.lease.fencing_token + 1)
})

test('store: kill switch is durable and blocks acquire', (t) => {
  const { store } = openStore(t)
  registerSchedule(store)
  enqueue(store)
  const engaged = store.engageKillSwitch({
    actor: { id: 'operator:alice', role: 'operator' },
    atIso: at().atIso,
    reason: 'incident',
  })
  assert.equal(engaged.ok, true)
  assert.equal(engaged.kill_switch.engaged, true)
  assert.equal(store.engageKillSwitch({
    actor: { id: 'operator:alice', role: 'operator' }, atIso: at(1).atIso, reason: 'again',
  }).idempotent, true)

  const blocked = acquire(store)
  assert.equal(blocked.ok, false)
  assert.equal(blocked.reason, 'scheduler-kill-switch')

  const released = store.releaseKillSwitch({
    actor: { id: 'operator:alice', role: 'operator' },
    atIso: at(2).atIso,
    reason: 'resolved',
    authorizationDigest: 'sha256:' + '1'.repeat(64),
  })
  assert.equal(released.ok, true)
  assert.equal(acquire(store, { atMs: BASE_MS + 2 }).ok, true)
})

test('store: clock-fault and max-wall metadata persist and are cleared explicitly', (t) => {
  const { store } = openStore(t)
  store.noteWallMs(BASE_MS)
  assert.equal(store.maxWallMs(), BASE_MS)
  store.setClockFault({ faults: ['wall-clock-rollback'], atIso: at().atIso, wallMs: BASE_MS, detail: 'test' })
  const fault = store.clockFault()
  assert.deepEqual(fault.faults, ['wall-clock-rollback'])
  assert.equal(fault.wall_ms, BASE_MS)

  store.clearClockFault({ actor: { id: 'operator:alice', role: 'operator' }, atIso: at(1).atIso, reason: 'verified' })
  assert.equal(store.clockFault(), null)
  const audit = store.readAudit()
  assert.ok(audit.some((entry) => entry.action === 'clock-fault-cleared'))
})

test('store: owner registry records and updates local owners', (t) => {
  const { store } = openStore(t)
  store.registerOwner({ ownerId: 'owner-A', host: 'test-host', pid: process.pid, atIso: at().atIso })
  const owner = store.owner('owner-A')
  assert.equal(owner.host, 'test-host')
  assert.equal(owner.pid, process.pid)
  assert.equal(owner.state, 'active')
  const touched = store.touchOwner({ ownerId: 'owner-A', atIso: at(5_000).atIso })
  assert.equal(touched.ok, true)
  assert.equal(touched.owner.last_seen_at, at(5_000).atIso)
  assert.equal(store.touchOwner({ ownerId: 'missing', atIso: at().atIso }).ok, false)
})

test('store: unavailable path and corrupt file fail closed with typed errors', (t) => {
  const dir = tempDir(t)
  assert.throws(
    () => openSchedulerStore({ filePath: join(dir, 'missing-subdir', 'scheduler.sqlite'), atIso: at().atIso }),
    (err) => err instanceof SchedulerStoreError && err.reason === 'scheduler-store-unavailable',
  )

  const corruptPath = join(dir, 'corrupt.sqlite')
  writeFileSync(corruptPath, 'this is not a sqlite database at all', 'utf8')
  assert.throws(
    () => openSchedulerStore({ filePath: corruptPath, atIso: at().atIso }),
    (err) => err instanceof SchedulerStoreError &&
      ['scheduler-store-corrupt', 'scheduler-store-unavailable'].includes(err.reason),
  )
})

test('store: explicit expireLease is idempotent and records a fenced expire event', (t) => {
  const { store } = openStore(t)
  registerSchedule(store)
  enqueue(store)
  const acquired = acquire(store)
  const expired = store.expireLease({
    leaseId: acquired.lease.lease_id,
    actor: { id: 'scheduler', role: 'scheduler' },
    atIso: at(1_000).atIso,
    atMs: BASE_MS + 1_000,
    reason: 'heartbeat-lost',
  })
  assert.equal(expired.ok, true)
  assert.equal(expired.lease.state, 'expired')
  const again = store.expireLease({
    leaseId: acquired.lease.lease_id,
    actor: { id: 'scheduler', role: 'scheduler' },
    atIso: at(2_000).atIso,
    atMs: BASE_MS + 2_000,
    reason: 'heartbeat-lost',
  })
  assert.equal(again.ok, true)
  assert.equal(again.idempotent, true)
  const events = store.readEvents()
  const expireEvents = events.filter((event) => event.type === 'expire')
  assert.equal(expireEvents.length, 1)
  assert.equal(expireEvents[0].payload.reason, 'heartbeat-lost')
})
