/**
 * Scheduler default-off posture and enable-gate tests (no store, capability,
 * authorization, policy, clock).
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  createScheduler,
  SCHEDULER_LIMITATIONS,
} from '../../../src/scheduler/index.js'
import {
  createManualClock,
  createTestScheduler,
  makeEnableAuthorization,
  makePolicy,
} from './_helpers.js'

function tempStore(t) {
  const dir = mkdtempSync(join(tmpdir(), 'testbed-sched-enable-'))
  t.after(async () => {
    for (let attempt = 0; attempt < 40; attempt += 1) {
      try {
        rmSync(dir, { recursive: true, force: true })
        return
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 25))
      }
    }
  })
  return join(dir, 'scheduler.sqlite')
}

test('default: createScheduler() is disabled with no store, no cron and blocked operations', () => {
  const scheduler = createScheduler()
  const status = scheduler.status()
  assert.equal(status.state, 'disabled')
  assert.equal(status.enabled, false)
  assert.equal(status.reason_codes.includes('scheduler-disabled'), true)
  assert.equal(status.store, null)
  assert.equal(status.runtime.scheduling_default_enabled, false)
  assert.equal(status.runtime.cron_enabled, false)
  assert.equal(status.runtime.background_loops, false)
  assert.equal(status.runtime.market_auto_publish, false)
  assert.equal(status.ha, false)
  assert.equal(status.single_host, true)
  assert.ok(SCHEDULER_LIMITATIONS.every((limit) => status.limitations.includes(limit)))

  for (const result of [
    scheduler.enqueue({ scheduleId: 'sched-1', runId: 'run-1', idempotencyKey: 'idem-1' }),
    scheduler.acquire({ scheduleId: 'sched-1', runId: 'run-1', idempotencyKey: 'idem-1' }),
    scheduler.registerSchedule({ config: {}, frozenPlan: {}, authorization: {} }),
    scheduler.maintenance(),
    scheduler.tick(),
  ]) {
    assert.equal(result.ok, false)
    assert.equal(result.status, 'blocked')
    assert.ok(result.reason_codes.includes('scheduler-disabled'), JSON.stringify(result.reason_codes))
  }
})

test('enable: missing explicit authorization stays blocked', (t) => {
  const clock = createManualClock()
  const storePath = tempStore(t)
  const scheduler = createScheduler({ clock, enabled: true, storePath })
  t.after(() => scheduler.close())
  const status = scheduler.status()
  assert.equal(status.state, 'blocked')
  assert.ok(status.reason_codes.includes('scheduler-authorization-required'))
  assert.equal(scheduler.acquire({ scheduleId: 's', runId: 'r', idempotencyKey: 'i' }).ok, false)
})

test('enable: missing store path is blocked before any store is opened', (t) => {
  const clock = createManualClock()
  const authorization = makeEnableAuthorization(clock)
  const scheduler = createScheduler({ clock, enabled: true, authorization })
  t.after(() => scheduler.close())
  const status = scheduler.status()
  assert.equal(status.state, 'blocked')
  assert.ok(status.reason_codes.includes('scheduler-store-required'))
  assert.equal(status.store, null)
})

test('enable: unavailable store path fails closed with scheduler-store-unavailable', (t) => {
  const clock = createManualClock()
  const authorization = makeEnableAuthorization(clock)
  const scheduler = createScheduler({
    clock,
    enabled: true,
    authorization,
    storePath: join(tmpdir(), 'definitely-missing-dir-t6', 'scheduler.sqlite'),
  })
  t.after(() => scheduler.close())
  const status = scheduler.status()
  assert.equal(status.state, 'blocked')
  assert.ok(status.reason_codes.some((code) =>
    ['scheduler-store-unavailable', 'scheduler-store-required'].includes(code)), JSON.stringify(status.reason_codes))
})

test('enable: failed capability probe blocks even with valid authorization', (t) => {
  const clock = createManualClock()
  const storePath = tempStore(t)
  const scheduler = createScheduler({
    clock,
    enabled: true,
    authorization: makeEnableAuthorization(clock),
    storePath,
    capability: {
      ok: false,
      provider: null,
      limitations: [],
      node_version: process.versions.node,
      reason_codes: ['scheduler-capability-unavailable', 'scheduler-store-unavailable'],
      detail: 'injected probe failure',
    },
  })
  t.after(() => scheduler.close())
  const status = scheduler.status()
  assert.equal(status.state, 'blocked')
  assert.ok(status.reason_codes.includes('scheduler-capability-unavailable'))
  assert.equal(status.store, null)
})

test('enable: valid capability + store + authorization enables the scheduler honestly', (t) => {
  const fixture = createTestScheduler(t)
  const status = fixture.scheduler.status()
  assert.equal(status.state, 'enabled')
  assert.deepEqual(status.reason_codes, [])
  assert.equal(status.store.journal_mode, 'wal')
  assert.equal(status.store.synchronous, 'FULL')
  assert.equal(status.provider.provider_id, 'node-sqlite-single-host')
  assert.equal(status.ha, false)
  assert.equal(status.single_host, true)
  assert.equal(status.policy.policy_id, 'scheduler-policy:default-local-only')
  assert.equal(status.authorization.signature_verified, false)
  assert.equal(status.kill_switch.engaged, false)
  assert.equal(status.clock.ok, true)
})

test('enable: expired authorization is refused with a stable reason', (t) => {
  const clock = createManualClock()
  const storePath = tempStore(t)
  const expired = makeEnableAuthorization(clock, {
    issuedAtMs: clock.wallNow() - 10_000,
    expiresAtMs: clock.wallNow() - 1,
  })
  const scheduler = createScheduler({ clock, enabled: true, authorization: expired, storePath })
  t.after(() => scheduler.close())
  const status = scheduler.status()
  assert.equal(status.state, 'blocked')
  assert.ok(status.reason_codes.includes('scheduler-authorization-expired'))
})

test('enable: self-approved authorization is refused', (t) => {
  const clock = createManualClock()
  const storePath = tempStore(t)
  const auth = makeEnableAuthorization(clock, { authorizedBy: 'engineer:bob', requestor: 'engineer:bob' })
  const scheduler = createScheduler({ clock, enabled: true, authorization: auth, storePath })
  t.after(() => scheduler.close())
  assert.ok(scheduler.status().reason_codes.includes('scheduler-authorization-self-approved'))
})

test('enable: unsafe policy (default-on / market publish) is refused', (t) => {
  for (const override of [{ default_enabled: true }, { market_auto_publish: true }, { require_authorization: false }]) {
    const clock = createManualClock()
    const storePath = tempStore(t)
    const scheduler = createScheduler({
      clock,
      enabled: true,
      authorization: makeEnableAuthorization(clock),
      policy: makePolicy(override),
      storePath,
    })
    t.after(() => scheduler.close())
    const status = scheduler.status()
    assert.equal(status.state, 'blocked', JSON.stringify(override))
    assert.ok(status.reason_codes.includes('scheduler-policy-invalid'), JSON.stringify(status.reason_codes))
  }
})

test('enable: periodic policy without periodic authorization scope is refused', (t) => {
  const clock = createManualClock()
  const storePath = tempStore(t)
  const scheduler = createScheduler({
    clock,
    enabled: true,
    authorization: makeEnableAuthorization(clock, { periodic: false }),
    policy: makePolicy({ periodic_enabled: true }),
    storePath,
  })
  t.after(() => scheduler.close())
  const status = scheduler.status()
  assert.equal(status.state, 'blocked')
  assert.ok(status.reason_codes.includes('scheduler-not-periodic-authorized'))
})

test('enable: wall-clock rollback detected before enable blocks the scheduler', (t) => {
  const clock = createManualClock()
  const storePath = tempStore(t)
  const scheduler = createScheduler({
    clock,
    enabled: false,
    storePath,
    authorization: makeEnableAuthorization(clock),
    maxClockSkewMs: 1_000,
  })
  t.after(() => scheduler.close())
  scheduler.status() // establish a wall high-water mark
  clock.shiftWall(-60_000)
  scheduler.enable({ authorization: makeEnableAuthorization(clock) })
  const status = scheduler.status()
  assert.equal(status.state, 'blocked')
  assert.ok(status.reason_codes.includes('scheduler-clock-skew'), JSON.stringify(status.reason_codes))
})

test('disable: explicit stop returns to disabled and blocks work; close closes the store', (t) => {
  const fixture = createTestScheduler(t)
  const { scheduler } = fixture
  assert.equal(scheduler.status().state, 'enabled')
  const disabled = scheduler.disable({ actor: { id: 'operator:alice', role: 'operator' }, reason: 'test stop' })
  assert.equal(disabled.state, 'disabled')
  assert.equal(disabled.reason_codes.includes('scheduler-disabled'), true)
  assert.equal(scheduler.maintenance().ok, false)

  const second = createTestScheduler(t).scheduler
  assert.equal(second.status().state, 'enabled')
  second.close()
  const closed = second.status()
  assert.equal(closed.state, 'blocked')
  assert.ok(closed.reason_codes.includes('scheduler-store-unavailable'), JSON.stringify(closed.reason_codes))
})
