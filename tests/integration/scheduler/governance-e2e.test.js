/**
 * Integration: governed scheduling end-to-end. Proves that scheduling stays
 * default-off, that enabling/periodic mode require explicit authorization, that
 * the frozen Plan is never mutated, and that monitoring results cannot become
 * GateDecisions or market approvals.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  DEFAULT_SCHEDULER_POLICY,
  SCHEDULER_LIMITATIONS,
  assertObservationOnly,
  createScheduler,
  planDigestFromPlanId,
} from '../../../src/scheduler/index.js'
import {
  TARGET_A,
  createManualClock,
  createTestScheduler,
  enqueueAndAcquire,
  makeAuthorization,
  makeCreateAuthorization,
  makeEnableAuthorization,
  makeFrozenPlan,
  makePolicy,
  makeScheduleConfig,
} from '../../unit/scheduler/_helpers.js'

test('governance e2e: default-off -> authorized enable -> authorized periodic schedule -> observation only', (t) => {
  const clock = createManualClock()
  const planFixture = makeFrozenPlan()
  const planSnapshot = JSON.stringify(planFixture.plan)
  const policy = makePolicy({ periodic_enabled: true })

  const disabled = createScheduler({ clock })
  assert.equal(disabled.status().state, 'disabled')
  const withoutStore = disabled.enable({
    authorization: makeEnableAuthorization(clock, { periodic: true }),
    policy,
  })
  assert.equal(withoutStore.state, 'blocked')
  assert.ok(withoutStore.reason_codes.includes('scheduler-store-required'))

  const fixture = createTestScheduler(t, { clock, policy, planFixture })
  const { scheduler: governed } = fixture
  assert.equal(governed.status().state, 'enabled')

  const registered = governed.registerSchedule({
    config: makeScheduleConfig({
      scheduleId: 'sched-periodic',
      plan: planFixture.plan,
      targetDigest: TARGET_A,
      nowMs: clock.wallNow(),
      periodic: { enabled: true, mode: 'interval', interval_ms: 60_000 },
    }),
    frozenPlan: planFixture.plan,
    authorization: makeCreateAuthorization({
      clock,
      scheduleId: 'sched-periodic',
      planDigest: planFixture.planDigest,
      targetDigest: TARGET_A,
      periodic: true,
      activate: true,
    }),
  })
  assert.equal(registered.ok, true, registered.reason_codes?.join(',') ?? registered.errors?.join(','))
  assert.equal(registered.schedule.periodic.enabled, true)
  assert.equal(registered.schedule.market_auto_publish, false)
  assert.equal(registered.schedule.plan_digest, planDigestFromPlanId(planFixture.plan.plan_id))

  const run = enqueueAndAcquire(governed, {
    scheduleId: 'sched-periodic',
    runId: 'periodic-run-1',
    idempotencyKey: 'periodic-idem-1',
  })
  assert.equal(run.acquired.ok, true, run.acquired.reason_codes?.join(','))

  const submitted = governed.submitResult({
    leaseId: run.acquired.lease.lease_id,
    fencingToken: run.acquired.lease.fencing_token,
    runId: 'periodic-run-1',
    result: { status: 'unhealthy', severity: 'warn', alerts: ['latency'], metrics: { p95_ms: 120 } },
  })
  assert.equal(submitted.ok, true)
  assert.deepEqual(assertObservationOnly(submitted.observation), [])
  assert.equal(submitted.observation.outcome.status, 'unhealthy')
  assert.equal(submitted.observation.outcome.severity, 'warn')

  const gateAttempt = governed.submitResult({
    leaseId: run.acquired.lease.lease_id,
    fencingToken: run.acquired.lease.fencing_token,
    runId: 'periodic-run-1',
    result: { status: 'healthy', gate_decision: 'pass' },
  })
  assert.equal(gateAttempt.ok, false)
  assert.ok(gateAttempt.reason_codes.includes('scheduler-authority-field-rejected'))

  const marketAttempt = governed.submitResult({
    leaseId: run.acquired.lease.lease_id,
    fencingToken: run.acquired.lease.fencing_token,
    runId: 'periodic-run-1',
    result: { status: 'healthy', market_eligible: true },
  })
  assert.equal(marketAttempt.ok, false)

  assert.equal(JSON.stringify(planFixture.plan), planSnapshot, 'scheduler must never mutate the frozen Plan')
  assert.equal(governed.verify().ok, true)
  assert.equal(governed.status().runtime.cron_enabled, false)
})

test('governance e2e: no kill-switch bypass, no schedule without authorization, honest limits', (t) => {
  const fixture = createTestScheduler(t)
  const { scheduler, clock, planFixture } = fixture
  const status = scheduler.status()
  assert.equal(status.single_host, true)
  assert.equal(status.ha, false)
  assert.equal(status.runtime.scheduling_default_enabled, false)
  assert.equal(status.runtime.background_loops, false)
  assert.equal(status.provider.ha, false)
  assert.equal(status.provider.single_host, true)
  for (const limitation of SCHEDULER_LIMITATIONS) {
    assert.ok(status.limitations.includes(limitation), `missing declared limitation ${limitation}`)
  }

  const decided = scheduler.engageKillSwitch({
    actor: { id: 'operator:alice', role: 'operator' }, reason: 'freeze scheduling',
  })
  assert.equal(decided.state, 'blocked')
  assert.ok(decided.reason_codes.includes('scheduler-kill-switch'))

  const createAttempt = scheduler.registerSchedule({
    config: makeScheduleConfig({
      scheduleId: 'sched-killed', plan: planFixture.plan, targetDigest: TARGET_A, nowMs: clock.wallNow(),
    }),
    frozenPlan: planFixture.plan,
    authorization: makeCreateAuthorization({
      clock, scheduleId: 'sched-killed', planDigest: planFixture.planDigest, targetDigest: TARGET_A,
    }),
  })
  assert.equal(createAttempt.ok, false)
  assert.ok(createAttempt.reason_codes.includes('scheduler-kill-switch'))

  const enableAttempt = scheduler.enable({
    authorization: makeEnableAuthorization(clock),
    policy: DEFAULT_SCHEDULER_POLICY,
  })
  assert.equal(enableAttempt.state, 'blocked')
  assert.ok(enableAttempt.reason_codes.includes('scheduler-kill-switch'))
})

test('governance e2e: plan tamper, market-policy widening and forged authorization are rejected', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'testbed-scheduler-gov-'))
  const clock = createManualClock()
  const planFixture = makeFrozenPlan()
  const policy = makePolicy()
  let base = null
  let widened = null
  let forged = null
  t.after(() => {
    try { base?.close() } catch { /* closed */ }
    try { widened?.close() } catch { /* closed */ }
    try { forged?.close() } catch { /* closed */ }
    rmSync(dir, { recursive: true, force: true })
  })

  base = createScheduler({
    enabled: true,
    storePath: join(dir, 'base.sqlite'),
    clock,
    policy,
    authorization: makeEnableAuthorization(clock),
    ownerId: 'owner-A',
    host: 'test-host',
    pid: process.pid,
    maxClockSkewMs: 5_000,
    maxForwardJumpMs: 5_000,
  })
  assert.equal(base.status().state, 'enabled')

  const tampered = base.registerSchedule({
    config: makeScheduleConfig({
      plan: planFixture.plan, targetDigest: TARGET_A, nowMs: clock.wallNow(),
    }),
    frozenPlan: { ...planFixture.plan },
    authorization: makeCreateAuthorization({
      clock, scheduleId: 'sched-1', planDigest: planFixture.planDigest, targetDigest: TARGET_A,
    }),
  })
  assert.equal(tampered.ok, false)
  assert.ok(tampered.reason_codes.some((code) =>
    ['scheduler-plan-binding-mismatch', 'scheduler-plan-mutation-rejected'].includes(code)),
    JSON.stringify(tampered.reason_codes))

  widened = createScheduler({
    enabled: true,
    storePath: join(dir, 'widened.sqlite'),
    clock,
    policy: makePolicy({ market_auto_publish: true }),
    authorization: makeEnableAuthorization(clock),
    ownerId: 'owner-W',
    host: 'test-host',
    pid: process.pid,
  })
  assert.equal(widened.status().state, 'blocked')
  assert.ok(widened.status().reason_codes.includes('scheduler-policy-invalid'))

  forged = createScheduler({
    enabled: true,
    storePath: join(dir, 'forged.sqlite'),
    clock,
    policy,
    authorization: makeAuthorization({
      action: 'enable-scheduler',
      nowMs: clock.wallNow(),
      overrides: { market_approved: true },
    }),
    ownerId: 'owner-F',
    host: 'test-host',
    pid: process.pid,
    capability: base.capability,
  })
  assert.equal(forged.status().state, 'blocked')
  assert.ok(forged.status().reason_codes.includes('scheduler-authorization-invalid'))
})
