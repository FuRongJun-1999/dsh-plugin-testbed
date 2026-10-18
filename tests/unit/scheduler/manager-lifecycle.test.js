/**
 * Governed scheduler lifecycle: authorization, plan/policy binding, enqueue /
 * acquire / heartbeat / release / submit, TTL, kill switch, clock faults,
 * observation-only results and explicit deterministic ticks.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  DEFAULT_SCHEDULER_POLICY,
  buildMonitoringObservation,
} from '../../../src/scheduler/index.js'
import {
  TARGET_A,
  TARGET_B,
  createTestScheduler,
  enqueueAndAcquire,
  makeAuthorization,
  makeCreateAuthorization,
  makePolicy,
  makeScheduleConfig,
  registerTestSchedule,
} from './_helpers.js'

function enabledFixture(t, options = {}) {
  const fixture = createTestScheduler(t, options)
  assert.equal(fixture.scheduler.status().state, 'enabled')
  const registered = registerTestSchedule(fixture.scheduler, fixture)
  assert.equal(registered.result.ok, true, registered.result.reason_codes?.join(','))
  return { ...fixture, registered }
}

function act(scheduler, lease, result = { status: 'healthy', severity: 'info' }) {
  return scheduler.submitResult({
    leaseId: lease.lease_id,
    fencingToken: lease.fencing_token,
    runId: lease.run_id,
    result,
  })
}

test('schedule: creation requires an explicit, matching, non-expired authorization', (t) => {
  const fixture = createTestScheduler(t)
  const { scheduler, clock, planFixture } = fixture
  const config = makeScheduleConfig({ plan: planFixture.plan, targetDigest: TARGET_A, nowMs: clock.wallNow() })

  const missing = scheduler.registerSchedule({ config, frozenPlan: planFixture.plan })
  assert.equal(missing.ok, false)
  assert.ok(missing.reason_codes.includes('scheduler-authorization-required'))

  const wrongAction = scheduler.registerSchedule({
    config,
    frozenPlan: planFixture.plan,
    authorization: makeAuthorization({ action: 'pause-schedule', nowMs: clock.wallNow() }),
  })
  assert.equal(wrongAction.ok, false)
  assert.ok(wrongAction.reason_codes.some((code) =>
    ['scheduler-authorization-invalid', 'authorization-action-mismatch'].includes(code)))

  const selfApproved = scheduler.registerSchedule({
    config,
    frozenPlan: planFixture.plan,
    authorization: makeCreateAuthorization({
      clock, scheduleId: 'sched-1', planDigest: planFixture.planDigest,
      authorizedBy: 'engineer:bob', requestor: 'engineer:bob',
    }),
  })
  assert.equal(selfApproved.ok, false)
  assert.ok(selfApproved.reason_codes.includes('scheduler-authorization-self-approved'))

  const expired = scheduler.registerSchedule({
    config,
    frozenPlan: planFixture.plan,
    authorization: makeCreateAuthorization({
      clock, scheduleId: 'sched-1', planDigest: planFixture.planDigest,
      issuedAtMs: clock.wallNow() - 10_000, expiresAtMs: clock.wallNow() - 1,
    }),
  })
  assert.equal(expired.ok, false)
  assert.ok(expired.reason_codes.includes('scheduler-authorization-expired'))

  const ok = registerTestSchedule(scheduler, fixture)
  assert.equal(ok.result.ok, true)
  assert.equal(ok.result.schedule.plan_digest, planFixture.planDigest)
  assert.equal(ok.result.schedule.market_auto_publish, false)
  assert.equal(ok.result.schedule.observation_only, true)
})

test('schedule: duplicate registration is idempotent, conflicting content is refused', (t) => {
  const fixture = enabledFixture(t)
  const { scheduler, clock, planFixture } = fixture

  const duplicate = scheduler.registerSchedule({
    config: fixture.registered.config,
    frozenPlan: fixture.planFixture.plan,
    authorization: fixture.registered.authorization,
  })
  assert.equal(duplicate.ok, true)
  assert.equal(duplicate.idempotent, true)

  const conflict = scheduler.registerSchedule({
    config: makeScheduleConfig({
      scheduleId: 'sched-1', plan: planFixture.plan, nowMs: clock.wallNow(),
      overrides: { notes: 'different content' },
    }),
    frozenPlan: planFixture.plan,
    authorization: makeCreateAuthorization({
      clock, scheduleId: 'sched-1', planDigest: planFixture.planDigest, version: 2,
    }),
  })
  assert.equal(conflict.ok, false)
  assert.ok(conflict.reason_codes.includes('scheduler-schedule-conflict'))
})

test('schedule: plan mutation, market auto-publish, cron, authority fields and plan tamper are all refused', (t) => {
  const fixture = enabledFixture(t)
  const { scheduler, clock, planFixture } = fixture
  const base = makeScheduleConfig({ plan: planFixture.plan, nowMs: clock.wallNow() })
  const authorization = () => makeCreateAuthorization({
    clock, scheduleId: 'sched-1', planDigest: planFixture.planDigest,
  })

  const planPatch = scheduler.registerSchedule({
    config: { ...base, plan_patch: 'shrink' },
    frozenPlan: planFixture.plan,
    authorization: authorization(),
  })
  assert.equal(planPatch.ok, false)
  assert.ok(planPatch.reason_codes.includes('scheduler-schedule-invalid'))

  const market = scheduler.registerSchedule({
    config: { ...base, market_auto_publish: true },
    frozenPlan: planFixture.plan,
    authorization: authorization(),
  })
  assert.equal(market.ok, false)
  assert.ok(market.reason_codes.includes('scheduler-market-autopublish-forbidden'))

  const cron = scheduler.registerSchedule({
    config: {
      ...base,
      periodic: { enabled: true, mode: 'interval', interval_ms: 60_000, cron: '* * * * *' },
    },
    frozenPlan: planFixture.plan,
    authorization: makeCreateAuthorization({
      clock, scheduleId: 'sched-1', planDigest: planFixture.planDigest, periodic: true,
    }),
  })
  assert.equal(cron.ok, false)
  assert.ok(cron.reason_codes.includes('scheduler-schedule-invalid'))
  assert.ok(cron.errors.some((error) => error.includes('schedule-cron-forbidden:cron')))

  const authority = scheduler.registerSchedule({
    config: { ...base, gate: { verdict: 'pass' } },
    frozenPlan: planFixture.plan,
    authorization: authorization(),
  })
  assert.equal(authority.ok, false)
  assert.ok(authority.reason_codes.includes('scheduler-authority-field-rejected'))

  const tamperedPlan = structuredClone(planFixture.plan)
  const tamper = scheduler.registerSchedule({
    config: base,
    frozenPlan: tamperedPlan,
    authorization: authorization(),
  })
  assert.equal(tamper.ok, false)
  assert.ok(tamper.reason_codes.some((code) =>
    ['scheduler-plan-binding-mismatch', 'scheduler-plan-mutation-rejected'].includes(code)))
})

test('enqueue: requires an enabled schedule, dedupes idempotency keys and enforces queue depth', (t) => {
  const { scheduler, clock, planFixture } = createTestScheduler(t)
  const disabledSchedule = registerTestSchedule(scheduler, {
    clock,
    planFixture,
    targetDigest: TARGET_A,
  }, { enabled: false, config: makeScheduleConfig({
    plan: planFixture.plan, enabled: false, nowMs: clock.wallNow(),
  }) })
  assert.equal(disabledSchedule.result.ok, true)
  const paused = scheduler.enqueue({ scheduleId: 'sched-1', runId: 'run-1', idempotencyKey: 'idem-1' })
  assert.equal(paused.ok, false)
  assert.ok(paused.reason_codes.includes('scheduler-schedule-paused'))
})

test('enqueue/acquire: durable queue, scope conflict, fencing and bindings', (t) => {
  const fixture = enabledFixture(t)
  const { scheduler, planFixture } = fixture

  const first = enqueueAndAcquire(scheduler)
  assert.equal(first.enqueued.ok, true)
  assert.equal(first.acquired.ok, true, first.acquired.reason_codes?.join(','))
  const lease = first.acquired.lease
  assert.equal(lease.schema_version, 'scheduler-lease/v1')
  assert.equal(lease.fencing_token, 1)
  assert.equal(lease.heartbeat_seq, 0)
  assert.equal(first.acquired.binding.plan_digest, planFixture.planDigest)
  assert.equal(first.acquired.binding.target_digest, TARGET_A)
  assert.match(first.acquired.binding.policy_digest, /^sha256:[0-9a-f]{64}$/)
  assert.match(first.acquired.binding.scope_key, /^scope-sha256:[0-9a-f]{64}$/)

  // Second queued run in the same scope cannot be acquired while the first owns it.
  assert.equal(scheduler.enqueue({ scheduleId: 'sched-1', runId: 'run-2', idempotencyKey: 'idem-2' }).ok, true)
  const conflict = scheduler.acquire({ scheduleId: 'sched-1', runId: 'run-2', idempotencyKey: 'idem-2' })
  assert.equal(conflict.ok, false)
  assert.ok(['lease-acquire-conflict', 'scheduler-duplicate-run'].includes(conflict.reason_codes[0]),
    JSON.stringify(conflict.reason_codes))

  const duplicateEnqueue = scheduler.enqueue({ scheduleId: 'sched-1', runId: 'run-1', idempotencyKey: 'idem-1' })
  assert.equal(duplicateEnqueue.ok, false)
  assert.ok(duplicateEnqueue.reason_codes.includes('scheduler-duplicate-run'))
  assert.equal(duplicateEnqueue.duplicate, true)

  const released = scheduler.release({ leaseId: lease.lease_id, fencingToken: lease.fencing_token })
  assert.equal(released.ok, true)

  const reacquired = scheduler.acquire({ scheduleId: 'sched-1', runId: 'run-2', idempotencyKey: 'idem-2' })
  assert.equal(reacquired.ok, true)
  assert.equal(reacquired.lease.fencing_token, 2)
})

test('concurrency/queue: global limit, target limit and bounded queue refuse with stable codes', (t) => {
  const fixture = createTestScheduler(t, {
    policy: makePolicy({ max_global_concurrency: 1, max_target_concurrency: 1, max_queue_depth: 1 }),
  })
  const { scheduler, clock, planFixture } = fixture
  registerTestSchedule(scheduler, fixture, { scheduleId: 'sched-a', targetDigest: TARGET_A })
  registerTestSchedule(scheduler, fixture, { scheduleId: 'sched-b', targetDigest: TARGET_B })

  const a = enqueueAndAcquire(scheduler, { scheduleId: 'sched-a', runId: 'run-a', idempotencyKey: 'idem-a' })
  assert.equal(a.acquired.ok, true)
  assert.equal(scheduler.enqueue({ scheduleId: 'sched-b', runId: 'run-b', idempotencyKey: 'idem-b' }).ok, true)
  const limited = scheduler.acquire({ scheduleId: 'sched-b', runId: 'run-b', idempotencyKey: 'idem-b' })
  assert.equal(limited.ok, false)
  assert.ok(limited.reason_codes.includes('scheduler-concurrency-limit'), JSON.stringify(limited.reason_codes))

  const full = scheduler.enqueue({ scheduleId: 'sched-a', runId: 'run-c', idempotencyKey: 'idem-c' })
  assert.equal(full.ok, false)
  assert.ok(full.reason_codes.includes('scheduler-queue-full'))
})

test('ttl: acquire refuses TTL outside the frozen policy bounds', (t) => {
  const fixture = enabledFixture(t)
  const { scheduler } = fixture
  assert.equal(scheduler.enqueue({ scheduleId: 'sched-1', runId: 'run-1', idempotencyKey: 'idem-1' }).ok, true)
  const tooShort = scheduler.acquire({ scheduleId: 'sched-1', runId: 'run-1', idempotencyKey: 'idem-1', ttlMs: 1 })
  assert.equal(tooShort.ok, false)
  assert.ok(tooShort.reason_codes.includes('scheduler-invalid-input'))
  const tooLong = scheduler.acquire({
    scheduleId: 'sched-1', runId: 'run-1', idempotencyKey: 'idem-1',
    ttlMs: DEFAULT_SCHEDULER_POLICY.max_ttl_ms + 1,
  })
  assert.equal(tooLong.ok, false)
  assert.ok(tooLong.reason_codes.includes('scheduler-invalid-input'))
})

test('heartbeat: renews, rejects stale token and wrong owner, and declares lost heartbeat after TTL', (t) => {
  const fixture = enabledFixture(t)
  const { scheduler, clock } = fixture
  const { acquired } = enqueueAndAcquire(scheduler, { ttlMs: 2_000 })
  const lease = acquired.lease

  const renewed = scheduler.heartbeat({ leaseId: lease.lease_id, fencingToken: lease.fencing_token, ttlMs: 2_000 })
  assert.equal(renewed.ok, true)
  assert.equal(renewed.lease.heartbeat_seq, 1)

  const stale = scheduler.heartbeat({ leaseId: lease.lease_id, fencingToken: lease.fencing_token - 1, ttlMs: 2_000 })
  assert.equal(stale.ok, false)
  assert.ok(stale.reason_codes.includes('fencing-token-stale'))

  const wrongOwner = scheduler.heartbeat({
    leaseId: lease.lease_id, fencingToken: lease.fencing_token, ownerId: 'owner-imposter', ttlMs: 2_000,
  })
  assert.equal(wrongOwner.ok, false)
  assert.ok(wrongOwner.reason_codes.includes('lease-owner-mismatch'))

  clock.advance(3_000)
  const lost = scheduler.heartbeat({ leaseId: lease.lease_id, fencingToken: lease.fencing_token, ttlMs: 2_000 })
  assert.equal(lost.ok, false)
  assert.ok(lost.reason_codes.includes('lease-heartbeat-lost'), JSON.stringify(lost.reason_codes))

  const timeline = scheduler.timeline({ leaseId: lease.lease_id })
  assert.equal(timeline.ok, true)
  assert.ok(timeline.events.some((event) => event.type === 'expire'))
})

test('release: idempotent and rejects stale tokens after a newer acquire', (t) => {
  const fixture = enabledFixture(t)
  const { scheduler } = fixture
  const { acquired } = enqueueAndAcquire(scheduler, { runId: 'run-1', idempotencyKey: 'idem-1' })
  const lease = acquired.lease

  const released = scheduler.release({ leaseId: lease.lease_id, fencingToken: lease.fencing_token })
  assert.equal(released.ok, true)
  const again = scheduler.release({ leaseId: lease.lease_id, fencingToken: lease.fencing_token })
  assert.equal(again.ok, true)
  assert.equal(again.idempotent, true)

  scheduler.enqueue({ scheduleId: 'sched-1', runId: 'run-2', idempotencyKey: 'idem-2' })
  const next = scheduler.acquire({ scheduleId: 'sched-1', runId: 'run-2', idempotencyKey: 'idem-2' })
  assert.equal(next.ok, true)
  assert.equal(next.lease.fencing_token, 2)

  const staleRelease = scheduler.release({ leaseId: lease.lease_id, fencingToken: lease.fencing_token })
  assert.equal(staleRelease.ok, true)
  assert.equal(staleRelease.idempotent, true, 'release is idempotent for a terminal lease')
  const staleRenew = scheduler.heartbeat({ leaseId: lease.lease_id, fencingToken: lease.fencing_token })
  assert.equal(staleRenew.ok, false)
  assert.ok(staleRenew.reason_codes.some((code) =>
    ['lease-not-active', 'fencing-token-stale'].includes(code)), JSON.stringify(staleRenew.reason_codes))
})

test('submitResult: observation-only, authority rejected, stale token rejected after reacquire', (t) => {
  const fixture = enabledFixture(t)
  const { scheduler, planFixture } = fixture
  const { acquired } = enqueueAndAcquire(scheduler, { runId: 'run-1', idempotencyKey: 'idem-1' })
  const lease = acquired.lease

  const submitted = act(scheduler, lease, {
    status: 'healthy', severity: 'info', alerts: [], metrics: { p95_ms: 12 }, summary: 'probe ok',
  })
  assert.equal(submitted.ok, true, submitted.reason_codes?.join(','))
  assert.equal(submitted.observation.observation_only, true)
  assert.equal(submitted.observation.gate_effect, 'none')
  assert.equal(submitted.observation.binding.plan_digest, planFixture.planDigest)

  const authority = act(scheduler, lease, { status: 'healthy', gate_decision: 'pass' })
  assert.equal(authority.ok, false)
  assert.ok(authority.reason_codes.includes('scheduler-authority-field-rejected'))

  const verdict = act(scheduler, lease, { verdict: 'pass' })
  assert.equal(verdict.ok, false)
  assert.ok(verdict.reason_codes.includes('scheduler-authority-field-rejected'))

  scheduler.release({ leaseId: lease.lease_id, fencingToken: lease.fencing_token })
  scheduler.enqueue({ scheduleId: 'sched-1', runId: 'run-2', idempotencyKey: 'idem-2' })
  const next = scheduler.acquire({ scheduleId: 'sched-1', runId: 'run-2', idempotencyKey: 'idem-2' })
  assert.equal(next.ok, true)

  const stale = scheduler.submitResult({
    leaseId: lease.lease_id,
    fencingToken: lease.fencing_token,
    runId: lease.run_id,
    result: { status: 'healthy' },
  })
  assert.equal(stale.ok, false)
  assert.ok(stale.reason_codes.includes('fencing-token-stale'), JSON.stringify(stale.reason_codes))
})

test('submitResult: heartbeat loss blocks result writes before the store accepts them', (t) => {
  const fixture = enabledFixture(t)
  const { scheduler, clock } = fixture
  const { acquired } = enqueueAndAcquire(scheduler, { ttlMs: 1_000 })
  clock.advance(2_000)
  const submitted = act(scheduler, acquired.lease)
  assert.equal(submitted.ok, false)
  assert.ok(
    submitted.reason_codes.some((code) =>
      ['lease-heartbeat-lost', 'lease-expired', 'fencing-token-stale'].includes(code)),
    JSON.stringify(submitted.reason_codes),
  )
})

test('tick/maintenance: deterministic explicit TTL expiry requeues the run and fences a new owner', (t) => {
  const fixture = enabledFixture(t)
  const { scheduler, clock } = fixture
  const { acquired } = enqueueAndAcquire(scheduler, { ttlMs: 1_000 })
  clock.advance(2_000)

  const tick = scheduler.tick()
  assert.equal(tick.ok, true)
  assert.equal(tick.deterministic, true)
  assert.equal(tick.cron_enabled, false)
  assert.equal(tick.background, false)
  assert.equal(tick.expired.length, 1)
  assert.equal(tick.expired[0].lease_id, acquired.lease.lease_id)

  const reacquired = scheduler.acquire({
    scheduleId: 'sched-1', runId: 'run-1', idempotencyKey: 'idem-1',
  })
  assert.equal(reacquired.ok, true)
  assert.equal(reacquired.lease.fencing_token, 2)
  assert.equal(typeof scheduler.startCron, 'undefined')
  assert.equal(typeof scheduler.cron, 'undefined')
})

test('kill switch: durable global stop blocks work; release requires operator authorization', (t) => {
  const fixture = enabledFixture(t)
  const { scheduler, clock, planFixture } = fixture
  const engaged = scheduler.engageKillSwitch({
    actor: { id: 'operator:alice', role: 'operator' }, reason: 'incident',
  })
  assert.equal(engaged.state, 'blocked')
  assert.ok(engaged.reason_codes.includes('scheduler-kill-switch'))

  const blocked = scheduler.enqueue({ scheduleId: 'sched-1', runId: 'run-1', idempotencyKey: 'idem-1' })
  assert.equal(blocked.ok, false)
  assert.ok(blocked.reason_codes.includes('scheduler-kill-switch'))

  const unauthorized = scheduler.releaseKillSwitch({
    actor: { id: 'engineer:bob', role: 'operator' }, reason: 'let me release',
  })
  assert.equal(unauthorized.ok, false)
  assert.ok(unauthorized.reason_codes.includes('scheduler-authorization-required'))

  const released = scheduler.releaseKillSwitch({
    actor: { id: 'operator:alice', role: 'operator' },
    reason: 'resolved',
    authorization: makeAuthorization({
      action: 'release-kill-switch', nowMs: clock.wallNow(),
    }),
  })
  assert.equal(released.state, 'enabled', JSON.stringify(released.reason_codes))
  assert.equal(scheduler.enqueue({ scheduleId: 'sched-1', runId: 'run-1', idempotencyKey: 'idem-1' }).ok, true)
  assert.equal(scheduler.verify().ok, true)
  assert.ok(scheduler.auditLog().entries.some((entry) => entry.action === 'kill-switch-engage'))
})

test('clock fault: rollback blocks the enabled scheduler and requires explicit operator recovery', (t) => {
  const fixture = enabledFixture(t)
  const { scheduler, clock, planFixture } = fixture
  const highWater = clock.wallNow()
  assert.equal(scheduler.status().state, 'enabled')

  clock.shiftWall(-60_000)
  const blocked = scheduler.status()
  assert.equal(blocked.state, 'blocked')
  assert.ok(blocked.reason_codes.includes('scheduler-clock-skew'), JSON.stringify(blocked.reason_codes))
  const acquire = scheduler.enqueue({ scheduleId: 'sched-1', runId: 'run-1', idempotencyKey: 'idem-1' })
  assert.equal(acquire.ok, false)
  assert.ok(acquire.reason_codes.some((code) =>
    ['scheduler-clock-skew', 'scheduler-clock-fault-persisted'].includes(code)))

  const noActor = scheduler.recoverClockFault({ reason: 'operator says ok' })
  assert.equal(noActor.ok, false)
  assert.ok(noActor.reason_codes.includes('scheduler-authorization-required'))

  const stillBehind = scheduler.recoverClockFault({
    actor: { id: 'operator:alice', role: 'operator' }, reason: 'still behind',
  })
  assert.equal(stillBehind.ok, false)
  assert.ok(stillBehind.reason_codes.includes('scheduler-clock-skew'))

  clock.setWall(highWater)
  const recovered = scheduler.recoverClockFault({
    actor: { id: 'operator:alice', role: 'operator' }, reason: 'wall clock verified',
  })
  assert.equal(recovered.state, 'enabled', JSON.stringify(recovered.reason_codes))
  assert.equal(scheduler.clockGuard.status().ok, true)
})

test('periodic: policy and authorization must both opt in; enabled config still observation-only', (t) => {
  const fixture = createTestScheduler(t, { policy: makePolicy({ periodic_enabled: true }) })
  const { scheduler, clock, planFixture } = fixture
  assert.equal(scheduler.status().state, 'enabled')

  const periodicAuth = makeCreateAuthorization({
    clock, scheduleId: 'sched-periodic', planDigest: planFixture.planDigest, periodic: true, activate: false,
  })
  const config = makeScheduleConfig({
    scheduleId: 'sched-periodic', plan: planFixture.plan, enabled: false, nowMs: clock.wallNow(),
    periodic: { enabled: true, mode: 'interval', interval_ms: 60_000 },
  })
  const created = scheduler.registerSchedule({ config, frozenPlan: planFixture.plan, authorization: periodicAuth })
  assert.equal(created.ok, true, created.reason_codes?.join(',') ?? created.errors?.join(','))
  assert.equal(created.schedule.periodic.enabled, true)
  assert.equal(created.schedule.market_auto_publish, false)

  const noPeriodicAuth = makeCreateAuthorization({
    clock, scheduleId: 'sched-plain', planDigest: planFixture.planDigest, periodic: false,
  })
  const refused = scheduler.registerSchedule({
    config: makeScheduleConfig({
      scheduleId: 'sched-plain', plan: planFixture.plan, nowMs: clock.wallNow(),
      periodic: { enabled: true, mode: 'interval', interval_ms: 60_000 },
    }),
    frozenPlan: planFixture.plan,
    authorization: noPeriodicAuth,
  })
  assert.equal(refused.ok, false)
  assert.ok(refused.reason_codes.includes('scheduler-not-periodic-authorized'))

  const noPolicyFixture = createTestScheduler(t, { policy: makePolicy({ periodic_enabled: false }) })
  const rejectedByPolicy = noPolicyFixture.scheduler.registerSchedule({
    config: makeScheduleConfig({
      scheduleId: 'sched-periodic', plan: noPolicyFixture.planFixture.plan, nowMs: noPolicyFixture.clock.wallNow(),
      periodic: { enabled: true, mode: 'interval', interval_ms: 60_000 },
    }),
    frozenPlan: noPolicyFixture.planFixture.plan,
    authorization: makeCreateAuthorization({
      clock: noPolicyFixture.clock,
      scheduleId: 'sched-periodic',
      planDigest: noPolicyFixture.planFixture.planDigest,
      periodic: true,
    }),
  })
  assert.equal(rejectedByPolicy.ok, false)
  assert.ok(rejectedByPolicy.reason_codes.includes('scheduler-not-periodic-authorized'))
})

test('pause: requires authorization and stops enqueue; audit trail records governed actions', (t) => {
  const fixture = enabledFixture(t)
  const { scheduler, clock } = fixture
  scheduler.enqueue({ scheduleId: 'sched-1', runId: 'run-1', idempotencyKey: 'idem-1' })

  const missing = scheduler.pauseSchedule({ scheduleId: 'sched-1', version: 1 })
  assert.equal(missing.ok, false)
  assert.ok(missing.reason_codes.includes('scheduler-authorization-required'))

  const paused = scheduler.pauseSchedule({
    scheduleId: 'sched-1',
    version: 1,
    authorization: makeAuthorization({
      action: 'pause-schedule',
      nowMs: clock.wallNow(),
      scope: { schedule_id: 'sched-1', schedule_version: 1 },
    }),
  })
  assert.equal(paused.ok, true)
  assert.equal(paused.state, 'paused')

  const afterPause = scheduler.enqueue({ scheduleId: 'sched-1', runId: 'run-2', idempotencyKey: 'idem-2' })
  assert.equal(afterPause.ok, false)
  assert.ok(afterPause.reason_codes.includes('scheduler-schedule-paused'))

  const audit = scheduler.auditLog()
  assert.equal(audit.ok, true)
  assert.ok(audit.entries.some((entry) => entry.action === 'scheduler-enabled'))
  assert.ok(audit.entries.some((entry) => entry.action === 'schedule-create'))
  assert.ok(audit.entries.some((entry) => entry.action === 'schedule-pause'))
})

test('timeline/verify: event chain binds plan/policy/target and integrity passes after a full cycle', (t) => {
  const fixture = enabledFixture(t)
  const { scheduler, planFixture } = fixture
  const { acquired } = enqueueAndAcquire(scheduler)
  const lease = acquired.lease
  scheduler.heartbeat({ leaseId: lease.lease_id, fencingToken: lease.fencing_token })
  const submitted = act(scheduler, lease)
  assert.equal(submitted.ok, true)
  scheduler.release({ leaseId: lease.lease_id, fencingToken: lease.fencing_token })

  const timeline = scheduler.timeline({ leaseId: lease.lease_id })
  assert.equal(timeline.ok, true)
  assert.deepEqual(timeline.events.map((event) => event.type), ['acquire', 'renew', 'release'])
  for (const event of timeline.events) {
    assert.equal(event.binding.plan_digest, planFixture.planDigest)
    assert.equal(event.binding.target_digest, TARGET_A)
    assert.match(event.binding.policy_digest, /^sha256:[0-9a-f]{64}$/)
    assert.equal(event.schema_version, 'scheduler-event/v1')
  }
  assert.equal(timeline.chain.ok, true)

  const verify = scheduler.verify()
  assert.equal(verify.ok, true, verify.reason_codes?.join(',') ?? '')
  assert.equal(verify.integrity.event_chain.ok, true)
  assert.equal(verify.integrity.counts.events >= 3, true)
})
