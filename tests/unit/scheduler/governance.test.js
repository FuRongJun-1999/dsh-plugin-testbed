/**
 * Scheduler governance: frozen policy, explicit authorization, frozen-plan
 * binding, cron/market refusals and observation-only results.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { AUTHORITY_FIELDS } from '../../../src/control/state.js'
import {
  DEFAULT_SCHEDULER_POLICY,
  SCHEDULER_AUTHORITY_FIELDS,
  assertObservationOnly,
  bindFrozenPlan,
  buildMonitoringObservation,
  compareAuthorizationScope,
  contentDigest,
  createFrozenSchedule,
  defaultSchedulerPolicy,
  planDigestFromPlanId,
  validateSchedulerAuthorization,
  validateSchedulerPolicy,
  verifyFrozenSchedule,
} from '../../../src/scheduler/index.js'
import {
  TARGET_A,
  createManualClock,
  makeAuthorization,
  makeFrozenPlan,
  makePolicy,
  makeScheduleConfig,
} from './_helpers.js'

test('governance: default policy is validated, frozen and pins every safe default', () => {
  const { policy, digest } = defaultSchedulerPolicy()
  assert.equal(policy.default_enabled, false)
  assert.equal(policy.require_authorization, true)
  assert.equal(policy.market_auto_publish, false)
  assert.equal(policy.observation_only, true)
  assert.equal(policy.periodic_enabled, false)
  assert.match(digest, /^sha256:[0-9a-f]{64}$/)
  assert.equal(Object.isFrozen(policy), true)
  assert.equal(validateSchedulerPolicy(DEFAULT_SCHEDULER_POLICY).ok, true)
})

test('governance: policy cannot be widened via default-enabled, market auto-publish, cron-ish or bad ttl bounds', () => {
  const cases = [
    [{ default_enabled: true }, 'policy-default-enabled-must-be-false'],
    [{ require_authorization: false }, 'policy-require-authorization-must-be-true'],
    [{ market_auto_publish: true }, 'policy-market-auto-publish-must-be-false'],
    [{ observation_only: false }, 'policy-observation-only-must-be-true'],
    [{ max_global_concurrency: 99 }, 'policy-max_global_concurrency-invalid'],
    [{ max_queue_depth: 0 }, 'policy-max_queue_depth-invalid'],
    [{ heartbeat_interval_ms: 30_000 }, 'policy-heartbeat-not-inside-ttl'],
    [{ min_ttl_ms: 60_000, max_ttl_ms: 10_000 }, 'policy-ttl-bounds-invalid'],
    [{ unknown_field: true }, 'policy-unknown-field:unknown_field'],
  ]
  for (const [override, error] of cases) {
    const result = validateSchedulerPolicy(makePolicy(override))
    assert.equal(result.ok, false, `expected failure for ${JSON.stringify(override)}`)
    assert.ok(result.errors.includes(error), `expected ${error}, got ${JSON.stringify(result.errors)}`)
  }
  assert.equal(validateSchedulerPolicy(null).ok, false)
})

test('governance: authorization requires separation of duties, freshness and a scoped action', () => {
  const clock = createManualClock()
  const nowMs = clock.wallNow()
  const valid = validateSchedulerAuthorization(makeAuthorization({
    action: 'enable-scheduler', scope: { profile: 'local' }, nowMs,
  }), { action: 'enable-scheduler', nowMs })
  assert.equal(valid.ok, true)
  assert.equal(valid.authorization.signature_present, false)
  assert.equal(valid.authorization.signature_verified, false)
  assert.match(valid.digest, /^sha256:[0-9a-f]{64}$/)
  assert.equal(valid.digest, contentDigest({
    schema_version: 'scheduler-authorization/v1',
    authorization_id: valid.authorization.authorization_id,
    action: 'enable-scheduler',
    authorized_by: 'operator:alice',
    role: 'operator',
    requestor: 'engineer:bob',
    issued_at: valid.authorization.issued_at,
    expires_at: valid.authorization.expires_at,
    scope: { profile: 'local' },
    reason: 'scheduler-test-authorization',
  }))

  const selfApproved = validateSchedulerAuthorization(makeAuthorization({
    action: 'enable-scheduler', nowMs, authorizedBy: 'engineer:bob', requestor: 'engineer:bob',
  }), { nowMs })
  assert.equal(selfApproved.ok, false)
  assert.equal(selfApproved.reason, 'scheduler-authorization-self-approved')

  const expired = validateSchedulerAuthorization(makeAuthorization({
    action: 'enable-scheduler', nowMs, issuedAtMs: nowMs - 10_000, expiresAtMs: nowMs - 1,
  }), { nowMs })
  assert.equal(expired.ok, false)
  assert.equal(expired.reason, 'scheduler-authorization-expired')

  const notYet = validateSchedulerAuthorization(makeAuthorization({
    action: 'enable-scheduler', nowMs, issuedAtMs: nowMs + 10_000, expiresAtMs: nowMs + 20_000,
  }), { nowMs })
  assert.equal(notYet.ok, false)
  assert.ok(notYet.errors.includes('authorization-not-yet-valid'))

  const wrongAction = validateSchedulerAuthorization(makeAuthorization({
    action: 'enable-scheduler', nowMs,
  }), { action: 'create-schedule', nowMs })
  assert.equal(wrongAction.ok, false)

  const badRole = validateSchedulerAuthorization(makeAuthorization({
    action: 'enable-scheduler', nowMs, role: 'robot',
  }), { nowMs })
  assert.equal(badRole.ok, false)
  assert.ok(badRole.errors.includes('authorization-role-invalid'))

  const badScope = validateSchedulerAuthorization(makeAuthorization({
    action: 'enable-scheduler', nowMs, scope: { periodic: 'yes' },
  }), { nowMs })
  assert.equal(badScope.ok, false)
  assert.ok(badScope.errors.includes('authorization-scope-periodic-invalid'))
})

test('governance: authorization scope must match schedule/plan/target/periodic/activation', () => {
  const clock = createManualClock()
  const nowMs = clock.wallNow()
  const { plan } = makeFrozenPlan()
  const planDigest = planDigestFromPlanId(plan.plan_id)
  const auth = makeAuthorization({
    action: 'create-schedule',
    nowMs,
    scope: { schedule_id: 'sched-1', target_digest: TARGET_A, plan_digest: planDigest, periodic: false, activate: true },
  })
  const checked = validateSchedulerAuthorization(auth, { action: 'create-schedule', nowMs })
  assert.equal(checked.ok, true)
  assert.deepEqual(compareAuthorizationScope(checked.authorization, {
    schedule_id: 'sched-1', target_digest: TARGET_A, plan_digest: planDigest, activate: true,
  }), [])
  assert.ok(compareAuthorizationScope(checked.authorization, { schedule_id: 'other' })
    .includes('authorization-scope-mismatch:schedule_id'))
  assert.ok(compareAuthorizationScope(checked.authorization, { periodic: true })
    .includes('authorization-periodic-not-authorized'))
  assert.ok(compareAuthorizationScope(checked.authorization, { activate: true, schedule_version: 2 })
    .some((error) => error.includes('schedule_version')) === false) // scope did not pin a version
})

test('governance: frozen plan binding derives plan_digest and rejects mutation/unfrozen plans', () => {
  const { plan, planDigest } = makeFrozenPlan()
  assert.match(planDigest, /^sha256:[0-9a-f]{64}$/)
  assert.equal(planDigest, planDigestFromPlanId(plan.plan_id))

  const bound = bindFrozenPlan({ frozenPlan: plan })
  assert.equal(bound.ok, true)
  assert.equal(bound.plan_id, plan.plan_id)
  assert.equal(bound.plan_digest, planDigest)

  assert.equal(bindFrozenPlan({ frozenPlan: structuredClone(plan) }).ok, false, 'unfrozen clone must be rejected')
  assert.equal(bindFrozenPlan({ frozenPlan: { ...plan, plan_id: 'plan-sha256:' + '0'.repeat(64) } }).ok, false)
  assert.equal(bindFrozenPlan({ frozenPlan: plan, planId: 'plan-sha256:' + '1'.repeat(64) }).reason,
    'scheduler-plan-mutation-rejected')
  assert.equal(bindFrozenPlan({ frozenPlan: plan, planDigest: 'sha256:' + '2'.repeat(64) }).reason,
    'scheduler-plan-mutation-rejected')
  assert.equal(bindFrozenPlan({}).ok, false)
})

test('governance: frozen schedule binds plan/policy/authorization and refuses cron/market/authority escapes', () => {
  const clock = createManualClock()
  const nowMs = clock.wallNow()
  const { plan, planDigest } = makeFrozenPlan()
  const policy = makePolicy()
  const policyChecked = validateSchedulerPolicy(policy)
  const auth = makeAuthorization({
    action: 'create-schedule',
    nowMs,
    scope: { schedule_id: 'sched-1', target_digest: TARGET_A, plan_digest: planDigest, periodic: false, activate: true },
  })
  const authChecked = validateSchedulerAuthorization(auth, { action: 'create-schedule', nowMs })
  const context = {
    frozenPlan: plan,
    policy: policyChecked.policy,
    policyDigest: policyChecked.digest,
    authorization: authChecked.authorization,
    authorizationDigest: authChecked.digest,
    nowMs,
    expectedScope: { schedule_id: 'sched-1', target_digest: TARGET_A, plan_digest: planDigest },
  }
  const config = makeScheduleConfig({ scheduleId: 'sched-1', plan, targetDigest: TARGET_A, nowMs })
  const created = createFrozenSchedule(config, context)
  assert.equal(created.ok, true, created.errors?.join(','))
  assert.equal(created.schedule.plan_digest, planDigest)
  assert.equal(created.schedule.policy_digest, policyChecked.digest)
  assert.equal(created.schedule.authorization_digest, authChecked.digest)
  assert.equal(created.schedule.market_auto_publish, false)
  assert.equal(created.schedule.observation_only, true)
  assert.equal(created.schedule.periodic.enabled, false)
  assert.equal(created.schedule.content_digest, created.digest)
  assert.equal(verifyFrozenSchedule(created.schedule).ok, true)

  // deterministic content digest
  const again = createFrozenSchedule(config, context)
  assert.equal(again.digest, created.digest)

  // plan mutation attempt
  const wrongPlan = createFrozenSchedule({ ...config, plan_id: 'plan-sha256:' + '9'.repeat(64) }, context)
  assert.equal(wrongPlan.ok, false)
  assert.equal(wrongPlan.reason, 'scheduler-plan-mutation-rejected')

  // market auto publish
  const market = createFrozenSchedule({ ...config, market_auto_publish: true }, context)
  assert.equal(market.ok, false)
  assert.equal(market.reason, 'scheduler-market-autopublish-forbidden')

  // cron
  const cron = createFrozenSchedule({
    ...config,
    periodic: { enabled: true, mode: 'interval', interval_ms: 60_000, cron: '* * * * *' },
  }, context)
  assert.equal(cron.ok, false)
  assert.ok(cron.errors.includes('schedule-cron-forbidden:cron'))

  // authority field injection
  const injected = createFrozenSchedule({ ...config, gate: { verdict: 'pass' } }, context)
  assert.equal(injected.ok, false)
  assert.equal(injected.reason, 'scheduler-authority-field-rejected')

  // plan mutation key
  const mutation = createFrozenSchedule({ ...config, plan_patch: 'shrink-required' }, context)
  assert.equal(mutation.ok, false)
  assert.ok(mutation.errors.includes('schedule-forbidden-field:plan_patch'))

  // unknown key / bad digest
  assert.equal(createFrozenSchedule({ ...config, extra: 1 }, context).ok, false)
  assert.equal(createFrozenSchedule({ ...config, plan_digest: 'sha256:' + '3'.repeat(64) }, context).ok, false)

  // tampering with the frozen schedule is detectable
  const tampered = { ...created.schedule, enabled: false }
  assert.equal(verifyFrozenSchedule(tampered).ok, false)
})

test('governance: periodic schedules need policy and authorization opt-in', () => {
  const clock = createManualClock()
  const nowMs = clock.wallNow()
  const { plan, planDigest } = makeFrozenPlan()
  const auth = makeAuthorization({
    action: 'create-schedule',
    nowMs,
    scope: {
      schedule_id: 'sched-periodic', target_digest: TARGET_A, plan_digest: planDigest,
      periodic: true, activate: true,
    },
  })
  const authChecked = validateSchedulerAuthorization(auth, { action: 'create-schedule', nowMs })
  const periodicConfig = makeScheduleConfig({
    scheduleId: 'sched-periodic', plan, nowMs,
    periodic: { enabled: true, mode: 'interval', interval_ms: 60_000 },
  })

  const policyDisabled = validateSchedulerPolicy(makePolicy({ periodic_enabled: false }))
  const noPolicy = createFrozenSchedule(periodicConfig, {
    frozenPlan: plan,
    policy: policyDisabled.policy,
    policyDigest: policyDisabled.digest,
    authorization: authChecked.authorization,
    authorizationDigest: authChecked.digest,
    nowMs,
  })
  assert.equal(noPolicy.ok, false)
  assert.equal(noPolicy.reason, 'scheduler-not-periodic-authorized')

  const policyEnabled = validateSchedulerPolicy(makePolicy({ periodic_enabled: true }))
  const authNoPeriodic = makeAuthorization({
    action: 'create-schedule',
    nowMs,
    scope: {
      schedule_id: 'sched-periodic', target_digest: TARGET_A, plan_digest: planDigest,
      periodic: false, activate: true,
    },
  })
  const authNoPeriodicChecked = validateSchedulerAuthorization(authNoPeriodic, { action: 'create-schedule', nowMs })
  const missingAuth = createFrozenSchedule(periodicConfig, {
    frozenPlan: plan,
    policy: policyEnabled.policy,
    policyDigest: policyEnabled.digest,
    authorization: authNoPeriodicChecked.authorization,
    authorizationDigest: authNoPeriodicChecked.digest,
    nowMs,
  })
  assert.equal(missingAuth.ok, false)
  assert.equal(missingAuth.reason, 'scheduler-not-periodic-authorized')

  const ok = createFrozenSchedule(periodicConfig, {
    frozenPlan: plan,
    policy: policyEnabled.policy,
    policyDigest: policyEnabled.digest,
    authorization: authChecked.authorization,
    authorizationDigest: authChecked.digest,
    nowMs,
    expectedScope: { schedule_id: 'sched-periodic', target_digest: TARGET_A, plan_digest: planDigest, periodic: true, activate: true },
  })
  assert.equal(ok.ok, true, ok.errors?.join(','))
  assert.equal(ok.schedule.periodic.enabled, true)
})

test('governance: monitoring observation is observation-only and rejects control authority', () => {
  const binding = {
    schedule_id: 'sched-1',
    plan_digest: 'sha256:' + 'b'.repeat(64),
    policy_digest: 'sha256:' + 'c'.repeat(64),
    target_digest: TARGET_A,
  }
  const context = {
    scheduleId: 'sched-1',
    runId: 'run-1',
    leaseId: 'lease-1',
    fencingToken: 3,
    atIso: '2026-10-19T00:00:00.000Z',
    binding,
  }
  const wrapped = buildMonitoringObservation({
    status: 'healthy', severity: 'info', alerts: ['none'], metrics: { latency_ms: 12 }, summary: 'ok',
  }, context)
  assert.equal(wrapped.ok, true)
  assert.equal(wrapped.observation.schema_version, 'monitoring-observation/v1')
  assert.equal(wrapped.observation.observation_only, true)
  assert.equal(wrapped.observation.gate_effect, 'none')
  assert.equal(wrapped.observation.market_auto_publish, false)
  assert.equal(wrapped.observation.trust_scope, 'local-only')
  assert.equal(wrapped.observation.fencing_token, 3)
  assert.equal(wrapped.observation.binding.plan_digest, binding.plan_digest)
  assert.equal(wrapped.observation.observation_digest, wrapped.digest)
  assert.deepEqual(assertObservationOnly(wrapped.observation), [])

  for (const authority of [{ verdict: 'pass' }, { gate_decision: 'pass' }, { required: ['x'] }, { expected: ['y'] }]) {
    const rejected = buildMonitoringObservation({ status: 'healthy', ...authority }, context)
    assert.equal(rejected.ok, false, `authority payload must be rejected: ${JSON.stringify(authority)}`)
    assert.equal(rejected.reason, 'scheduler-authority-field-rejected')
  }

  assert.equal(buildMonitoringObservation({
    status: 'healthy', gate_effect: 'none',
  }, context).ok, false, 'unknown observation fields are rejected')

  const tampered = { ...wrapped.observation, gate_effect: 'pass' }
  assert.ok(assertObservationOnly(tampered).includes('observation-gate-effect-not-none'))
  const withAuthority = { ...wrapped.observation, gate_decision: 'pass' }
  assert.ok(assertObservationOnly(withAuthority).some((error) => error.includes('authority-field')))
})

test('governance: scheduler authority list mirrors control authority list (no drift)', () => {
  assert.deepEqual([...SCHEDULER_AUTHORITY_FIELDS].sort(), [...AUTHORITY_FIELDS].sort())
})
