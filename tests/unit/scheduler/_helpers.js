/**
 * Shared helpers for scheduler tests (unit + integration).
 *
 * Deterministic manual clock, frozen-plan / authorization / schedule builders,
 * and an enabled-scheduler fixture backed by a real temporary SQLite store.
 */
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { compilePlanCandidate, freezePlan } from '../../../src/control/index.js'
import {
  DEFAULT_SCHEDULER_POLICY,
  createScheduler,
  planDigestFromPlanId,
} from '../../../src/scheduler/index.js'

export const TARGET_A = 'sha256:' + 'a'.repeat(64)
export const TARGET_B = 'sha256:' + 'b'.repeat(64)

/** Deterministic wall + monotonic clock (both advance together by default). */
export function createManualClock({ wallMs = Date.UTC(2026, 9, 19, 0, 0, 0), monoMs = 1_000_000 } = {}) {
  const state = { wallMs, monoMs }
  return {
    state,
    wallNow: () => state.wallMs,
    monoNow: () => state.monoMs,
    iso: (ms) => new Date(ms).toISOString(),
    parse: (iso) => Date.parse(iso),
    /** Advance both clocks (simulates real elapsed time). */
    advance: (ms) => {
      state.wallMs += ms
      state.monoMs += ms
      return state
    },
    /** Move only the wall clock (clock drift / rollback / jump simulation). */
    shiftWall: (ms) => {
      state.wallMs += ms
      return state
    },
    setWall: (ms) => {
      state.wallMs = ms
      return state
    },
    setMono: (ms) => {
      state.monoMs = ms
      return state
    },
  }
}

/** @param {number} wallMs */
export function iso(wallMs) {
  return new Date(wallMs).toISOString()
}

/** Policy built from the frozen default; overrides may only tighten. */
export function makePolicy(overrides = {}) {
  return { ...DEFAULT_SCHEDULER_POLICY, ...overrides }
}

/** Frozen plan (produced by the real control kernel, empty case list). */
export function makeFrozenPlan() {
  const candidate = compilePlanCandidate([])
  if (!candidate.ok) throw new Error(`compilePlanCandidate failed: ${candidate.errors.join(',')}`)
  const plan = freezePlan(candidate.candidate)
  return { plan, planDigest: planDigestFromPlanId(plan.plan_id) }
}

let authorizationCounter = 0

/** `scheduler-authorization/v1` fixture with separation of duties. */
export function makeAuthorization({
  action,
  scope = {},
  nowMs,
  issuedAtMs = nowMs - 1_000,
  expiresAtMs = nowMs + 3_600_000,
  authorizedBy = 'operator:alice',
  requestor = 'engineer:bob',
  role = 'operator',
  signature = null,
  overrides = {},
} = {}) {
  authorizationCounter += 1
  return {
    schema_version: 'scheduler-authorization/v1',
    authorization_id: overrides.authorization_id ?? `auth-${authorizationCounter}`,
    action,
    authorized_by: authorizedBy,
    role,
    requestor,
    issued_at: iso(issuedAtMs),
    expires_at: iso(expiresAtMs),
    scope,
    reason: 'scheduler-test-authorization',
    signature,
    ...overrides,
  }
}

/** Enable-scheduler authorization. */
export function makeEnableAuthorization(clock, options = {}) {
  return makeAuthorization({
    action: 'enable-scheduler',
    scope: options.scope ?? { profile: 'local', periodic: options.periodic === true },
    nowMs: clock.wallNow(),
    ...options,
  })
}

/** Create-schedule authorization scoped to a plan/target/schedule. */
export function makeCreateAuthorization({
  clock,
  scheduleId,
  planDigest,
  targetDigest = TARGET_A,
  periodic = false,
  activate = true,
  version,
  ...rest
}) {
  return makeAuthorization({
    action: 'create-schedule',
    scope: {
      schedule_id: scheduleId,
      plan_digest: planDigest,
      target_digest: targetDigest,
      profile: 'local',
      periodic,
      activate,
      ...(version === undefined ? {} : { schedule_version: version }),
    },
    nowMs: clock.wallNow(),
    ...rest,
  })
}

/** `scheduler-schedule/v1` config input. */
export function makeScheduleConfig({
  scheduleId = 'sched-1',
  version = 1,
  enabled = true,
  plan,
  targetDigest = TARGET_A,
  profile = 'local',
  periodic = null,
  createdBy = 'engineer:bob',
  nowMs,
  overrides = {},
} = {}) {
  return {
    schema_version: 'scheduler-schedule/v1',
    schedule_id: scheduleId,
    version,
    enabled,
    profile,
    target_digest: targetDigest,
    plan_id: plan.plan_id,
    created_by: createdBy,
    created_at: iso(nowMs),
    ...(periodic === null ? {} : { periodic }),
    ...overrides,
  }
}

/**
 * Create a scheduler fixture. By default it is enabled with a real temp SQLite
 * store and a manual clock; `enabled:false` builds the default-off form.
 */
export function createTestScheduler(t, options = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'testbed-scheduler-'))
  const clock = options.clock ?? createManualClock()
  const policy = options.policy ?? makePolicy()
  const enableAuthorization = options.enableAuthorization === null
    ? null
    : options.enableAuthorization ?? makeEnableAuthorization(clock, { periodic: policy.periodic_enabled === true })
  const storePath = options.storePath ?? join(dir, 'scheduler.sqlite')
  const scheduler = createScheduler({
    enabled: options.enabled ?? true,
    storePath,
    clock,
    policy,
    authorization: enableAuthorization,
    ownerId: options.ownerId ?? 'owner-A',
    host: options.host ?? 'test-host',
    pid: options.pid ?? process.pid,
    ...(options.reaper === undefined ? {} : { reaper: options.reaper }),
    ...(options.isOwnerAlive === undefined ? {} : { isOwnerAlive: options.isOwnerAlive }),
    ...(options.capability === undefined ? {} : { capability: options.capability }),
    maxClockSkewMs: options.maxClockSkewMs ?? 5_000,
    maxForwardJumpMs: options.maxForwardJumpMs ?? 5_000,
  })
  t.after(() => {
    try { scheduler.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return {
    scheduler,
    clock,
    dir,
    storePath,
    policy,
    enableAuthorization,
    planFixture: options.planFixture ?? makeFrozenPlan(),
    targetDigest: options.targetDigest ?? TARGET_A,
  }
}

/** Register an enabled schedule through the governed manager. */
export function registerTestSchedule(scheduler, fixture, options = {}) {
  const { clock, targetDigest = fixture.targetDigest, planFixture = fixture.planFixture } = fixture
  const scheduleId = options.scheduleId ?? 'sched-1'
  const authorization = options.authorization ?? makeCreateAuthorization({
    clock,
    scheduleId,
    planDigest: planFixture.planDigest,
    targetDigest: options.targetDigest ?? targetDigest,
    periodic: options.periodic === true,
    activate: options.activate !== false,
  })
  const config = options.config ?? makeScheduleConfig({
    scheduleId,
    plan: planFixture.plan,
    targetDigest: options.targetDigest ?? targetDigest,
    enabled: options.enabled !== false,
    periodic: options.periodicConfig ?? null,
    nowMs: clock.wallNow(),
    version: options.version ?? 1,
  })
  return {
    authorization,
    config,
    result: scheduler.registerSchedule({
      config,
      frozenPlan: options.frozenPlan ?? planFixture.plan,
      authorization,
    }),
  }
}

/** Run enqueue+acquire for a registered schedule. */
export function enqueueAndAcquire(scheduler, {
  scheduleId = 'sched-1',
  runId = 'run-1',
  idempotencyKey = 'idem-1',
  ttlMs = 60_000,
  ownerId,
} = {}) {
  const enqueued = scheduler.enqueue({ scheduleId, runId, idempotencyKey })
  if (!enqueued.ok) return { enqueued, acquired: null }
  const acquired = scheduler.acquire({ scheduleId, runId, idempotencyKey, ttlMs, ownerId })
  return { enqueued, acquired }
}
