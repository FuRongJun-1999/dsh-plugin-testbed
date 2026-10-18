/**
 * Scheduler governance: frozen policy, explicit non-expired authorization,
 * frozen-plan binding, kill-switch semantics and observation-only results.
 *
 * Hard rules encoded here (NEXT-PHASE-REQUIREMENTS SCH-07/SCH-10, MKT-01,
 * §5.6.1):
 *   - scheduling is disabled by default; every state-changing scheduler action
 *     needs an explicit `scheduler-authorization/v1` record with separation of
 *     duties (requestor != authorizer), a scope and an expiry;
 *   - a schedule binds the frozen `plan_id` / target / policy digests; a config
 *     that tries to carry authority fields, mutate the plan, enable cron or
 *     auto-publish to market is rejected, never ignored;
 *   - periodic mode is opt-in *twice*: the frozen policy must allow it and the
 *     authorization scope must explicitly set `periodic: true`;
 *   - results can only become `monitoring-observation/v1` with
 *     `gate_effect: "none"`; control authority fields are rejected so a
 *     monitoring observation can never be promoted to a GateDecision.
 *
 * Plan binding: the control kernel (`control/plan.js`) remains the authority
 * that produces and re-verifies a frozen Plan. The scheduler re-checks that the
 * supplied plan is structurally a frozen Plan snapshot and derives
 * `sha256:<hex>` from its `plan-sha256:<hex>` identity; a caller-supplied digest
 * that disagrees is rejected as a mutation attempt. The scheduler never mutates
 * or re-freezes the plan.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/scheduler/governance
 */

import { canonicalJson, sha256Hex } from '../protocol/digest.js'
import { findSchedulerAuthorityFields } from './authority.js'
import { isRfc3339, wallMsFromIso } from './clock.js'
import { isDigest, isNonEmptyString, isPlainRecord } from './lease.js'
import type {
  EventBinding,
  FrozenSchedule,
  MonitoringObservation,
  ObservationOutcome,
  PeriodicConfig,
  SchedulerAuthorization,
  SchedulerPolicy,
} from './types.js'
import {
  DEFAULT_SCHEDULER_POLICY,
  MAX_GLOBAL_CONCURRENCY,
  MAX_QUEUE_DEPTH,
  MAX_SCHEDULER_TTL_MS,
  MAX_TARGET_CONCURRENCY,
  MIN_HEARTBEAT_INTERVAL_MS,
  MIN_PERIODIC_INTERVAL_MS,
  MIN_SCHEDULER_TTL_MS,
  MONITORING_OBSERVATION_SCHEMA_VERSION,
  SCHEDULER_AUTHORIZATION_ACTIONS,
  SCHEDULER_AUTHORIZATION_SCHEMA_VERSION,
  SCHEDULER_AUTHORIZER_ROLES,
  SCHEDULER_POLICY_SCHEMA_VERSION,
  SCHEDULER_REASON,
  SCHEDULER_SCHEDULE_SCHEMA_VERSION,
} from './limits.js'

/** Frozen Plan identity regex (`control/plan.js` `plan_id` form). */
const PLAN_ID_RE = /^plan-sha256:[0-9a-f]{64}$/

/**
 * Digest of any JSON value: `sha256:<hex>` over JCS canonical JSON.
 */
export function contentDigest(value: unknown): string {
  return 'sha256:' + sha256Hex(canonicalJson(value))
}

/**
 * Convert a frozen Plan identity (`plan-sha256:<hex>`) into the canonical
 * `sha256:<hex>` digest used by schedule bindings / scheduler events.
 */
export function planDigestFromPlanId(planId: string): string {
  return 'sha256:' + planId.slice('plan-sha256:'.length)
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value
  Object.freeze(value)
  for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child)
  return value
}

function rejectUnknownKeys(
  record: Record<string, unknown>,
  allowed: Set<string>,
  prefix: string,
  errors: string[],
): void {
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) errors.push(`${prefix}-unknown-field:${key}`)
  }
}

// ---------------------------------------------------------------------------
// Scheduler policy (`scheduler-policy/v1`)
// ---------------------------------------------------------------------------

const POLICY_FIELDS = new Set([
  'schema_version', 'policy_id', 'default_enabled', 'require_authorization',
  'periodic_enabled', 'market_auto_publish', 'observation_only',
  'max_global_concurrency', 'max_target_concurrency', 'max_queue_depth',
  'default_ttl_ms', 'min_ttl_ms', 'max_ttl_ms', 'heartbeat_interval_ms',
  'max_clock_skew_ms', 'max_clock_forward_jump_ms',
])

/**
 * Strictly validate a frozen scheduler policy. Default-deny booleans are
 * pinned: `default_enabled=false`, `require_authorization=true`,
 * `market_auto_publish=false`, `observation_only=true`.
 */
export function validateSchedulerPolicy(value: unknown):
  | { ok: true; policy: SchedulerPolicy; digest: string }
  | { ok: false; errors: string[]; reason: string } {
  if (!isPlainRecord(value)) {
    return { ok: false, errors: ['policy-not-object'], reason: SCHEDULER_REASON.POLICY_INVALID }
  }
  const errors: string[] = []
  rejectUnknownKeys(value, POLICY_FIELDS, 'policy', errors)
  if (value.schema_version !== SCHEDULER_POLICY_SCHEMA_VERSION) errors.push('policy-schema-version-invalid')
  if (!isNonEmptyString(value.policy_id)) errors.push('policy-id-invalid')
  if (value.default_enabled !== false) errors.push('policy-default-enabled-must-be-false')
  if (value.require_authorization !== true) errors.push('policy-require-authorization-must-be-true')
  if (value.market_auto_publish !== false) errors.push('policy-market-auto-publish-must-be-false')
  if (value.observation_only !== true) errors.push('policy-observation-only-must-be-true')
  if (typeof value.periodic_enabled !== 'boolean') errors.push('policy-periodic-enabled-invalid')

  const intField = (name: string, min: number, max: number): void => {
    const field = value[name]
    if (typeof field !== 'number' || !Number.isSafeInteger(field) || field < min || field > max) {
      errors.push(`policy-${name}-invalid`)
    }
  }
  intField('max_global_concurrency', 1, MAX_GLOBAL_CONCURRENCY)
  intField('max_target_concurrency', 1, MAX_TARGET_CONCURRENCY)
  intField('max_queue_depth', 1, MAX_QUEUE_DEPTH)
  intField('default_ttl_ms', MIN_SCHEDULER_TTL_MS, MAX_SCHEDULER_TTL_MS)
  intField('min_ttl_ms', MIN_SCHEDULER_TTL_MS, MAX_SCHEDULER_TTL_MS)
  intField('max_ttl_ms', MIN_SCHEDULER_TTL_MS, MAX_SCHEDULER_TTL_MS)
  intField('heartbeat_interval_ms', MIN_HEARTBEAT_INTERVAL_MS, MAX_SCHEDULER_TTL_MS)
  const minTtl = value.min_ttl_ms
  const maxTtl = value.max_ttl_ms
  const defaultTtl = value.default_ttl_ms
  const heartbeat = value.heartbeat_interval_ms
  if (typeof minTtl === 'number' && typeof maxTtl === 'number' && minTtl > maxTtl) {
    errors.push('policy-ttl-bounds-invalid')
  }
  if (typeof defaultTtl === 'number' && typeof minTtl === 'number' && typeof maxTtl === 'number' &&
      (defaultTtl < minTtl || defaultTtl > maxTtl)) {
    errors.push('policy-default-ttl-out-of-bounds')
  }
  if (typeof heartbeat === 'number' && typeof defaultTtl === 'number' && heartbeat >= defaultTtl) {
    errors.push('policy-heartbeat-not-inside-ttl')
  }
  if (typeof value.max_clock_skew_ms !== 'number' || !Number.isSafeInteger(value.max_clock_skew_ms) ||
      value.max_clock_skew_ms < 0) {
    errors.push('policy-max-clock-skew-invalid')
  }
  if (typeof value.max_clock_forward_jump_ms !== 'number' ||
      !Number.isSafeInteger(value.max_clock_forward_jump_ms) || value.max_clock_forward_jump_ms < 0) {
    errors.push('policy-max-clock-forward-jump-invalid')
  }
  if (errors.length > 0) {
    return { ok: false, errors, reason: SCHEDULER_REASON.POLICY_INVALID }
  }
  const policy: SchedulerPolicy = {
    schema_version: SCHEDULER_POLICY_SCHEMA_VERSION,
    policy_id: value.policy_id as string,
    default_enabled: false,
    require_authorization: true,
    periodic_enabled: value.periodic_enabled === true,
    market_auto_publish: false,
    observation_only: true,
    max_global_concurrency: value.max_global_concurrency as number,
    max_target_concurrency: value.max_target_concurrency as number,
    max_queue_depth: value.max_queue_depth as number,
    default_ttl_ms: value.default_ttl_ms as number,
    min_ttl_ms: value.min_ttl_ms as number,
    max_ttl_ms: value.max_ttl_ms as number,
    heartbeat_interval_ms: value.heartbeat_interval_ms as number,
    max_clock_skew_ms: value.max_clock_skew_ms as number,
    max_clock_forward_jump_ms: value.max_clock_forward_jump_ms as number,
  }
  return { ok: true, policy: deepFreeze(policy), digest: contentDigest(policy) }
}

/** The validated default policy (everything opt-in). */
export function defaultSchedulerPolicy(): { policy: SchedulerPolicy; digest: string } {
  const checked = validateSchedulerPolicy(DEFAULT_SCHEDULER_POLICY)
  if (!checked.ok) throw new Error(`default scheduler policy invalid: ${checked.errors.join(',')}`)
  return { policy: checked.policy, digest: checked.digest }
}

// ---------------------------------------------------------------------------
// Authorization (`scheduler-authorization/v1`)
// ---------------------------------------------------------------------------

const AUTHORIZATION_FIELDS = new Set([
  'schema_version', 'authorization_id', 'action', 'authorized_by', 'role',
  'requestor', 'issued_at', 'expires_at', 'scope', 'reason', 'signature',
])
const AUTHORIZATION_SCOPE_FIELDS = new Set([
  'schedule_id', 'plan_digest', 'target_digest', 'profile', 'tenant',
  'periodic', 'activate', 'schedule_version',
])
const DIGEST_FIELDS = Object.freeze(['plan_digest', 'target_digest'])

/** Authorization validation options. */
export interface AuthorizationValidationOptions {
  action?: string
  nowMs?: number
  expectedScope?: Record<string, unknown> | null
}

/** Authorization validation result. */
export type AuthorizationValidationResult =
  | { ok: true; authorization: SchedulerAuthorization; digest: string; signature_present: boolean }
  | { ok: false; reason: string; errors: string[] }

/**
 * Validate a governance authorization. The signature is optional in this
 * phase because no trusted signing/KMS provider exists (NEXT-PHASE-REQUIREMENTS
 * §4.6); when present it is structurally recorded but **never** reported as
 * cryptographically verified. Market auto-publish stays impossible regardless.
 */
export function validateSchedulerAuthorization(
  value: unknown,
  options: AuthorizationValidationOptions = {},
): AuthorizationValidationResult {
  const nowMs = typeof options.nowMs === 'number' && Number.isFinite(options.nowMs) ? options.nowMs : Date.now()
  const fail = (reason: string, errors: string[]): AuthorizationValidationResult => ({ ok: false, reason, errors })
  if (!isPlainRecord(value)) return fail(SCHEDULER_REASON.AUTHORIZATION_INVALID, ['authorization-not-object'])
  const errors: string[] = []
  rejectUnknownKeys(value, AUTHORIZATION_FIELDS, 'authorization', errors)
  if (value.schema_version !== SCHEDULER_AUTHORIZATION_SCHEMA_VERSION) errors.push('authorization-schema-version-invalid')
  if (!isNonEmptyString(value.authorization_id)) errors.push('authorization-id-invalid')
  if (typeof value.action !== 'string' ||
      !SCHEDULER_AUTHORIZATION_ACTIONS.includes(value.action)) errors.push('authorization-action-invalid')
  if (options.action !== undefined && value.action !== options.action) errors.push('authorization-action-mismatch')
  if (!isNonEmptyString(value.authorized_by)) errors.push('authorization-authorized-by-invalid')
  if (typeof value.role !== 'string' || !SCHEDULER_AUTHORIZER_ROLES.includes(value.role)) {
    errors.push('authorization-role-invalid')
  }
  if (!isNonEmptyString(value.requestor)) errors.push('authorization-requestor-invalid')
  if (isNonEmptyString(value.authorized_by) && value.authorized_by === value.requestor) {
    return fail(SCHEDULER_REASON.AUTHORIZATION_SELF_APPROVED, [...errors, 'authorization-self-approved'])
  }
  if (!isRfc3339(value.issued_at)) errors.push('authorization-issued-at-invalid')
  if (!isRfc3339(value.expires_at)) errors.push('authorization-expires-at-invalid')
  if (isRfc3339(value.issued_at) && isRfc3339(value.expires_at)) {
    const issued = wallMsFromIso(value.issued_at)
    const expires = wallMsFromIso(value.expires_at)
    if (expires <= issued) errors.push('authorization-expiry-not-after-issue')
    if (nowMs < issued) errors.push('authorization-not-yet-valid')
    if (nowMs >= expires) return fail(SCHEDULER_REASON.AUTHORIZATION_EXPIRED, [...errors, 'authorization-expired'])
  }
  if (typeof value.reason !== 'string' || value.reason.trim().length === 0) errors.push('authorization-reason-required')
  let scopeRecord: Record<string, unknown> = {}
  if (!isPlainRecord(value.scope)) {
    errors.push('authorization-scope-invalid')
  } else {
    scopeRecord = value.scope
    rejectUnknownKeys(value.scope, AUTHORIZATION_SCOPE_FIELDS, 'authorization-scope', errors)
    if (value.scope.schedule_id !== undefined && !isNonEmptyString(value.scope.schedule_id)) {
      errors.push('authorization-scope-schedule-id-invalid')
    }
    if (value.scope.profile !== undefined && !isNonEmptyString(value.scope.profile)) {
      errors.push('authorization-scope-profile-invalid')
    }
    if (value.scope.tenant !== undefined && !isNonEmptyString(value.scope.tenant)) {
      errors.push('authorization-scope-tenant-invalid')
    }
    for (const field of DIGEST_FIELDS) {
      if (value.scope[field] !== undefined && !isDigest(value.scope[field])) {
        errors.push(`authorization-scope-${field.replace('_', '-')}-invalid`)
      }
    }
    if (value.scope.periodic !== undefined && typeof value.scope.periodic !== 'boolean') {
      errors.push('authorization-scope-periodic-invalid')
    }
    if (value.scope.activate !== undefined && typeof value.scope.activate !== 'boolean') {
      errors.push('authorization-scope-activate-invalid')
    }
    if (value.scope.schedule_version !== undefined &&
        (typeof value.scope.schedule_version !== 'number' ||
         !Number.isSafeInteger(value.scope.schedule_version) || value.scope.schedule_version < 1)) {
      errors.push('authorization-scope-schedule-version-invalid')
    }
  }
  const signatureValue = value.signature ?? null
  let signature: { alg: string; key_id: string; value: string } | null = null
  if (signatureValue !== null) {
    if (!isPlainRecord(signatureValue) || !isNonEmptyString(signatureValue.alg) ||
        !isNonEmptyString(signatureValue.key_id) || !isNonEmptyString(signatureValue.value)) {
      errors.push('authorization-signature-invalid')
    } else {
      signature = {
        alg: signatureValue.alg as string,
        key_id: signatureValue.key_id as string,
        value: signatureValue.value as string,
      }
    }
  }
  if (errors.length > 0) {
    return fail(SCHEDULER_REASON.AUTHORIZATION_INVALID, errors)
  }

  const scope: SchedulerAuthorization['scope'] = {}
  if (isNonEmptyString(scopeRecord.schedule_id)) scope.schedule_id = scopeRecord.schedule_id
  if (isDigest(scopeRecord.plan_digest)) scope.plan_digest = scopeRecord.plan_digest
  if (isDigest(scopeRecord.target_digest)) scope.target_digest = scopeRecord.target_digest
  if (isNonEmptyString(scopeRecord.profile)) scope.profile = scopeRecord.profile
  if (isNonEmptyString(scopeRecord.tenant)) scope.tenant = scopeRecord.tenant
  if (typeof scopeRecord.periodic === 'boolean') scope.periodic = scopeRecord.periodic
  if (typeof scopeRecord.activate === 'boolean') scope.activate = scopeRecord.activate
  if (typeof scopeRecord.schedule_version === 'number') scope.schedule_version = scopeRecord.schedule_version

  const authorization: SchedulerAuthorization = {
    schema_version: SCHEDULER_AUTHORIZATION_SCHEMA_VERSION,
    authorization_id: value.authorization_id as string,
    action: value.action as string,
    authorized_by: value.authorized_by as string,
    role: value.role as string,
    requestor: value.requestor as string,
    issued_at: value.issued_at as string,
    expires_at: value.expires_at as string,
    scope,
    reason: value.reason as string,
    signature,
    signature_present: signature !== null,
    signature_verified: false,
  }

  const expected = options.expectedScope
  if (isPlainRecord(expected)) {
    const scopeErrors = compareAuthorizationScope(authorization, expected)
    if (scopeErrors.length > 0) {
      return fail(SCHEDULER_REASON.AUTHORIZATION_SCOPE_MISMATCH, scopeErrors)
    }
  }

  const body = structuredClone(value) as Record<string, unknown>
  delete body.signature
  return { ok: true, authorization: deepFreeze(authorization), digest: contentDigest(body), signature_present: signature !== null }
}

export function compareAuthorizationScope(
  authorization: SchedulerAuthorization,
  expected: Record<string, unknown>,
): string[] {
  const errors: string[] = []
  const scope = authorization.scope
  for (const field of ['schedule_id', 'profile', 'tenant'] as const) {
    if (expected[field] !== undefined && scope[field] !== expected[field]) {
      errors.push(`authorization-scope-mismatch:${field}`)
    }
  }
  for (const field of DIGEST_FIELDS) {
    if (expected[field] !== undefined && scope[field as 'plan_digest' | 'target_digest'] !== expected[field]) {
      errors.push(`authorization-scope-mismatch:${field}`)
    }
  }
  if (expected.periodic === true && scope.periodic !== true) {
    errors.push('authorization-periodic-not-authorized')
  }
  if (expected.activate === true && scope.activate !== true) {
    errors.push('authorization-activate-not-authorized')
  }
  if (expected.schedule_version !== undefined && scope.schedule_version !== undefined &&
      scope.schedule_version !== expected.schedule_version) {
    errors.push('authorization-scope-mismatch:schedule_version')
  }
  if (expected.requireScheduleIdentity === true && !isNonEmptyString(scope.schedule_id)) {
    errors.push('authorization-scope-schedule-id-required')
  }
  return errors
}

// ---------------------------------------------------------------------------
// Frozen plan binding
// ---------------------------------------------------------------------------

/** Plan binding input. */
export interface FrozenPlanBindingInput {
  frozenPlan?: unknown
  planId?: string | null
  planDigest?: string | null
}

/** Plan binding result. */
export type FrozenPlanBindingResult =
  | { ok: true; plan_id: string; plan_digest: string }
  | { ok: false; reason: string; errors: string[] }

/**
 * Validate a frozen plan binding. The scheduler may *read* the frozen plan but
 * must never mutate or re-freeze it; a caller-supplied digest is not trusted.
 * Full identity recomputation stays with the control kernel that produced the
 * plan (`freezePlan`/`verifyFrozenPlan`); here we refuse anything that is not a
 * structurally frozen Plan snapshot and derive the binding digest from its
 * identity.
 */
export function bindFrozenPlan(input: FrozenPlanBindingInput = {}): FrozenPlanBindingResult {
  const plan = input.frozenPlan
  const mismatch = (errors: string[]): FrozenPlanBindingResult => ({
    ok: false,
    reason: SCHEDULER_REASON.PLAN_BINDING_MISMATCH,
    errors,
  })
  if (!isPlainRecord(plan)) return mismatch(['frozen-plan-not-object'])
  if (typeof plan.plan_id !== 'string' || !PLAN_ID_RE.test(plan.plan_id)) {
    return mismatch(['frozen-plan-id-invalid'])
  }
  if (!Array.isArray(plan.testCases) || !Array.isArray(plan.expected) ||
      !Array.isArray(plan.required) || !Array.isArray(plan.optional)) {
    return mismatch(['frozen-plan-shape-invalid'])
  }
  if (!Object.isFrozen(plan)) return mismatch(['frozen-plan-not-frozen'])
  const planId = plan.plan_id
  const planDigest = planDigestFromPlanId(planId)
  if (input.planId !== undefined && input.planId !== null && input.planId !== planId) {
    return { ok: false, reason: SCHEDULER_REASON.PLAN_MUTATION_REJECTED, errors: ['plan-id-mismatch'] }
  }
  if (input.planDigest !== undefined && input.planDigest !== null && input.planDigest !== planDigest) {
    return { ok: false, reason: SCHEDULER_REASON.PLAN_MUTATION_REJECTED, errors: ['plan-digest-mismatch'] }
  }
  return { ok: true, plan_id: planId, plan_digest: planDigest }
}

// ---------------------------------------------------------------------------
// Frozen schedule config (`scheduler-schedule/v1`)
// ---------------------------------------------------------------------------

const SCHEDULE_FIELDS = new Set([
  'schema_version', 'schedule_id', 'version', 'enabled', 'profile',
  'target_digest', 'plan_id', 'plan_digest', 'run_spec_digest', 'periodic',
  'created_by', 'created_at', 'authorization_digest', 'policy_digest',
  'content_digest', 'market_auto_publish', 'observation_only', 'labels', 'notes',
])
const FORBIDDEN_SCHEDULE_FIELDS = new Set([
  'plan_mutation', 'plan_patch', 'plan_override', 'mutate_plan', 'plan_update',
  'gate_decision', 'verdict', 'admission_status', 'market_eligible',
  'required', 'expected', 'plan_resolution', 'run_status', 'gate',
])
const PERIODIC_FIELDS = new Set(['enabled', 'mode', 'interval_ms'])
const PERIODIC_FORBIDDEN_FIELDS = new Set(['cron', 'cron_expression', 'schedule_expression'])

/** Context required to freeze a schedule. */
export interface FrozenScheduleContext {
  frozenPlan: unknown
  policy: SchedulerPolicy
  policyDigest: string
  authorization: SchedulerAuthorization
  authorizationDigest: string
  nowMs: number
  expectedScope?: Record<string, unknown>
}

/** Frozen-schedule result. */
export type FrozenScheduleResult =
  | { ok: true; schedule: FrozenSchedule; digest: string }
  | { ok: false; reason: string; errors: string[] }

function normalizePeriodic(value: unknown):
  | { ok: true; periodic: PeriodicConfig }
  | { ok: false; errors: string[] } {
  if (value === undefined || value === null) {
    return { ok: true, periodic: { enabled: false, mode: 'interval', interval_ms: null } }
  }
  if (!isPlainRecord(value)) return { ok: false, errors: ['schedule-periodic-invalid'] }
  const errors: string[] = []
  rejectUnknownKeys(value, PERIODIC_FIELDS, 'schedule-periodic', errors)
  for (const forbidden of PERIODIC_FORBIDDEN_FIELDS) {
    if (Object.hasOwn(value, forbidden)) errors.push(`schedule-cron-forbidden:${forbidden}`)
  }
  if (typeof value.enabled !== 'boolean') errors.push('schedule-periodic-enabled-invalid')
  if (value.mode !== 'interval') errors.push('schedule-periodic-mode-invalid')
  if (value.enabled === true) {
    if (typeof value.interval_ms !== 'number' || !Number.isSafeInteger(value.interval_ms) ||
        value.interval_ms < MIN_PERIODIC_INTERVAL_MS) {
      errors.push('schedule-periodic-interval-invalid')
    }
  } else if (value.interval_ms !== null && value.interval_ms !== undefined &&
             (typeof value.interval_ms !== 'number' || !Number.isSafeInteger(value.interval_ms) ||
              value.interval_ms < MIN_PERIODIC_INTERVAL_MS)) {
    errors.push('schedule-periodic-interval-invalid')
  }
  if (errors.length > 0) return { ok: false, errors }
  return {
    ok: true,
    periodic: {
      enabled: value.enabled === true,
      mode: 'interval',
      interval_ms: typeof value.interval_ms === 'number' ? value.interval_ms : null,
    },
  }
}

/**
 * Build a frozen, versioned schedule config bound to a validated frozen plan,
 * policy and explicit authorization.
 */
export function createFrozenSchedule(config: unknown, context: FrozenScheduleContext): FrozenScheduleResult {
  const fail = (reason: string, errors: string[]): FrozenScheduleResult => ({ ok: false, reason, errors })
  if (!isPlainRecord(config)) return fail(SCHEDULER_REASON.SCHEDULE_INVALID, ['schedule-not-object'])
  const errors: string[] = []
  for (const forbidden of FORBIDDEN_SCHEDULE_FIELDS) {
    if (Object.hasOwn(config, forbidden)) errors.push(`schedule-forbidden-field:${forbidden}`)
  }
  const authorityFields = findSchedulerAuthorityFields(config)
  if (authorityFields.length > 0) {
    return fail(
      SCHEDULER_REASON.AUTHORITY_FIELD_REJECTED,
      authorityFields.map((path) => `schedule-authority-field:${path}`),
    )
  }
  rejectUnknownKeys(config, SCHEDULE_FIELDS, 'schedule', errors)
  if (config.schema_version !== SCHEDULER_SCHEDULE_SCHEMA_VERSION) errors.push('schedule-schema-version-invalid')
  if (!isNonEmptyString(config.schedule_id)) errors.push('schedule-id-invalid')
  if (typeof config.version !== 'number' || !Number.isSafeInteger(config.version) || config.version < 1) {
    errors.push('schedule-version-invalid')
  }
  if (config.enabled !== undefined && typeof config.enabled !== 'boolean') errors.push('schedule-enabled-invalid')
  if (!isNonEmptyString(config.profile)) errors.push('schedule-profile-invalid')
  if (!isDigest(config.target_digest)) errors.push('schedule-target-digest-invalid')
  if (!isNonEmptyString(config.created_by)) errors.push('schedule-created-by-invalid')
  if (!isRfc3339(config.created_at)) errors.push('schedule-created-at-invalid')
  if (config.policy_digest !== undefined && config.policy_digest !== null && !isDigest(config.policy_digest)) {
    errors.push('schedule-policy-digest-invalid')
  }
  if (config.authorization_digest !== undefined && config.authorization_digest !== null &&
      !isDigest(config.authorization_digest)) {
    errors.push('schedule-authorization-digest-invalid')
  }
  if (config.run_spec_digest !== undefined && config.run_spec_digest !== null && !isDigest(config.run_spec_digest)) {
    errors.push('schedule-run-spec-digest-invalid')
  }
  if (config.market_auto_publish !== undefined && config.market_auto_publish !== false) {
    return fail(SCHEDULER_REASON.MARKET_AUTOPUBLISH_FORBIDDEN, [...errors, 'schedule-market-auto-publish-forbidden'])
  }
  if (config.observation_only !== undefined && config.observation_only !== true) {
    errors.push('schedule-observation-only-must-be-true')
  }
  if (config.labels !== undefined &&
      (!isPlainRecord(config.labels) || !Object.values(config.labels).every((entry) => typeof entry === 'string'))) {
    errors.push('schedule-labels-invalid')
  }
  if (config.notes !== undefined && config.notes !== null && typeof config.notes !== 'string') {
    errors.push('schedule-notes-invalid')
  }
  const periodicResult = normalizePeriodic(config.periodic)
  if (!periodicResult.ok) {
    errors.push(...periodicResult.errors)
    return fail(SCHEDULER_REASON.SCHEDULE_INVALID, errors)
  }
  if (errors.length > 0) return fail(SCHEDULER_REASON.SCHEDULE_INVALID, errors)

  const policy = context.policy
  if (!isPlainRecord(policy) || policy.schema_version !== SCHEDULER_POLICY_SCHEMA_VERSION) {
    return fail(SCHEDULER_REASON.POLICY_INVALID, ['schedule-policy-not-frozen'])
  }
  if (config.policy_digest !== undefined && config.policy_digest !== null &&
      config.policy_digest !== context.policyDigest) {
    return fail(SCHEDULER_REASON.SCHEDULE_INVALID, ['schedule-policy-digest-mismatch'])
  }
  const authorization = context.authorization
  if (!isPlainRecord(authorization) || authorization.schema_version !== SCHEDULER_AUTHORIZATION_SCHEMA_VERSION) {
    return fail(SCHEDULER_REASON.AUTHORIZATION_REQUIRED, ['schedule-authorization-not-frozen'])
  }
  if (config.authorization_digest !== undefined && config.authorization_digest !== null &&
      config.authorization_digest !== context.authorizationDigest) {
    return fail(SCHEDULER_REASON.AUTHORIZATION_INVALID, ['schedule-authorization-digest-mismatch'])
  }

  const planBinding = bindFrozenPlan({
    frozenPlan: context.frozenPlan,
    planId: typeof config.plan_id === 'string' ? config.plan_id : (config.plan_id as string | undefined) ?? null,
    planDigest: typeof config.plan_digest === 'string'
      ? config.plan_digest
      : (config.plan_digest as string | undefined) ?? null,
  })
  if (!planBinding.ok) return fail(planBinding.reason, planBinding.errors)
  if (config.plan_digest !== undefined && config.plan_digest !== null &&
      (!isDigest(config.plan_digest) || config.plan_digest !== planBinding.plan_digest)) {
    return fail(SCHEDULER_REASON.PLAN_BINDING_MISMATCH, ['schedule-plan-binding-invalid'])
  }

  if (periodicResult.periodic.enabled === true) {
    if (policy.periodic_enabled !== true) {
      return fail(SCHEDULER_REASON.PERIODIC_NOT_AUTHORIZED, ['schedule-policy-periodic-disabled'])
    }
    if (authorization.scope.periodic !== true) {
      return fail(SCHEDULER_REASON.PERIODIC_NOT_AUTHORIZED, ['schedule-authorization-periodic-missing'])
    }
  }
  const enabled = config.enabled === true
  if (enabled && authorization.scope.activate !== true) {
    return fail(SCHEDULER_REASON.AUTHORIZATION_SCOPE_MISMATCH, ['schedule-activation-not-authorized'])
  }
  if (context.expectedScope) {
    const scopeErrors = compareAuthorizationScope(authorization, {
      ...context.expectedScope,
      periodic: periodicResult.periodic.enabled === true,
      activate: enabled,
    })
    if (scopeErrors.length > 0) {
      return fail(SCHEDULER_REASON.AUTHORIZATION_SCOPE_MISMATCH, scopeErrors)
    }
  }

  const labels: Record<string, string> = {}
  if (isPlainRecord(config.labels)) {
    for (const key of Object.keys(config.labels).sort()) {
      const entry = config.labels[key]
      if (typeof entry === 'string') labels[key] = entry
    }
  }
  const normalized: Omit<FrozenSchedule, 'content_digest'> = {
    schema_version: SCHEDULER_SCHEDULE_SCHEMA_VERSION,
    schedule_id: config.schedule_id as string,
    version: config.version as number,
    enabled,
    profile: config.profile as string,
    target_digest: config.target_digest as string,
    plan_id: planBinding.plan_id,
    plan_digest: planBinding.plan_digest,
    run_spec_digest: isDigest(config.run_spec_digest) ? config.run_spec_digest : null,
    periodic: periodicResult.periodic,
    created_by: config.created_by as string,
    created_at: config.created_at as string,
    authorization_digest: context.authorizationDigest,
    policy_digest: context.policyDigest,
    market_auto_publish: false,
    observation_only: true,
    labels,
    notes: typeof config.notes === 'string' ? config.notes : null,
  }
  const digest = contentDigest(normalized)
  const schedule: FrozenSchedule = deepFreeze({ ...normalized, content_digest: digest })
  return { ok: true, schedule, digest }
}

/**
 * Recompute and verify a frozen schedule's content digest and invariants.
 */
export function verifyFrozenSchedule(schedule: unknown):
  | { ok: true; digest: string }
  | { ok: false; errors: string[] } {
  if (!isPlainRecord(schedule)) return { ok: false, errors: ['schedule-not-object'] }
  const errors: string[] = []
  if (schedule.schema_version !== SCHEDULER_SCHEDULE_SCHEMA_VERSION) errors.push('schedule-schema-version-invalid')
  const planId = schedule.plan_id
  if (typeof planId !== 'string' || !PLAN_ID_RE.test(planId)) {
    errors.push('schedule-plan-id-invalid')
    errors.push('schedule-plan-binding-invalid')
  } else if (schedule.plan_digest !== planDigestFromPlanId(planId)) {
    errors.push('schedule-plan-binding-invalid')
  }
  if (schedule.market_auto_publish !== false) errors.push('schedule-market-auto-publish-forbidden')
  if (schedule.observation_only !== true) errors.push('schedule-observation-only-must-be-true')
  if (isPlainRecord(schedule.periodic) && schedule.periodic.enabled === true &&
      schedule.periodic.mode !== 'interval') {
    errors.push('schedule-periodic-mode-invalid')
  }
  const authorityFields = findSchedulerAuthorityFields(schedule)
  if (authorityFields.length > 0) errors.push(...authorityFields.map((path) => `schedule-authority-field:${path}`))
  if (errors.length > 0) return { ok: false, errors }
  const body = structuredClone(schedule) as Record<string, unknown>
  delete body.content_digest
  const digest = contentDigest(body)
  if (digest !== schedule.content_digest) return { ok: false, errors: ['schedule-content-digest-mismatch'] }
  return { ok: true, digest }
}

// ---------------------------------------------------------------------------
// Observation-only results
// ---------------------------------------------------------------------------

/** Result payload keys accepted from a monitoring run (authority is rejected). */
export const OBSERVATION_RESULT_KEYS: readonly string[] = Object.freeze([
  'status', 'severity', 'alerts', 'metrics', 'summary', 'details', 'note',
  'checked_at', 'evidence_refs',
])
const OBSERVATION_STATUS: readonly string[] = Object.freeze(['healthy', 'unhealthy', 'unknown'])
const OBSERVATION_SEVERITY: readonly string[] = Object.freeze(['info', 'warn', 'error'])

/** Context required to wrap a monitoring result. */
export interface ObservationContext {
  scheduleId: string
  runId: string
  leaseId: string | null
  fencingToken: number | null
  atIso: string
  binding: EventBinding
}

/** Observation wrapping result. */
export type ObservationResult =
  | { ok: true; observation: MonitoringObservation; digest: string }
  | { ok: false; reason: string; errors: string[] }

/**
 * Wrap a periodic-run result as a `monitoring-observation/v1`.
 *
 * The wrapper is deliberately unable to carry a GateDecision:
 *   - any control-authority field in the input is rejected, not stripped;
 *   - output pins `observation_only=true`, `gate_effect="none"`,
 *     `market_auto_publish=false`, `trust_scope="local-only"`.
 */
export function buildMonitoringObservation(result: unknown, context: ObservationContext): ObservationResult {
  const fail = (reason: string, errors: string[]): ObservationResult => ({ ok: false, reason, errors })
  if (!isPlainRecord(result)) return fail(SCHEDULER_REASON.INVALID_INPUT, ['observation-result-not-object'])
  const authorityFields = findSchedulerAuthorityFields(result)
  if (authorityFields.length > 0) {
    return fail(
      SCHEDULER_REASON.AUTHORITY_FIELD_REJECTED,
      authorityFields.map((path) => `observation-authority-field:${path}`),
    )
  }
  const forbidden = [...FORBIDDEN_SCHEDULE_FIELDS].filter((field) => Object.hasOwn(result, field))
  if (forbidden.length > 0) {
    return fail(SCHEDULER_REASON.AUTHORITY_FIELD_REJECTED, forbidden.map((field) => `observation-forbidden-field:${field}`))
  }
  const errors: string[] = []
  for (const key of Object.keys(result)) {
    if (!OBSERVATION_RESULT_KEYS.includes(key)) errors.push(`observation-unknown-field:${key}`)
  }
  const status = result.status ?? 'unknown'
  if (typeof status !== 'string' || !OBSERVATION_STATUS.includes(status)) errors.push('observation-status-invalid')
  const severity = result.severity ?? 'info'
  if (typeof severity !== 'string' || !OBSERVATION_SEVERITY.includes(severity)) {
    errors.push('observation-severity-invalid')
  }
  const alerts = result.alerts ?? []
  if (!Array.isArray(alerts) || alerts.some((alert) => typeof alert !== 'string')) {
    errors.push('observation-alerts-invalid')
  }
  const metricsValue = result.metrics ?? {}
  if (!isPlainRecord(metricsValue) ||
      !Object.values(metricsValue).every((entry) =>
        typeof entry === 'number' || typeof entry === 'string' || typeof entry === 'boolean')) {
    errors.push('observation-metrics-invalid')
  }
  if (result.summary !== undefined && typeof result.summary !== 'string') errors.push('observation-summary-invalid')
  if (result.note !== undefined && result.note !== null && typeof result.note !== 'string') {
    errors.push('observation-note-invalid')
  }
  if (result.checked_at !== undefined && !isRfc3339(result.checked_at)) errors.push('observation-checked-at-invalid')
  if (result.evidence_refs !== undefined &&
      (!Array.isArray(result.evidence_refs) || result.evidence_refs.some((ref) => typeof ref !== 'string'))) {
    errors.push('observation-evidence-refs-invalid')
  }
  if (errors.length > 0) return fail(SCHEDULER_REASON.INVALID_INPUT, errors)
  if (!isNonEmptyString(context.scheduleId) || !isNonEmptyString(context.runId) || !isRfc3339(context.atIso)) {
    return fail(SCHEDULER_REASON.INVALID_INPUT, ['observation-context-invalid'])
  }
  if (!isPlainRecord(context.binding)) {
    return fail(SCHEDULER_REASON.INVALID_INPUT, ['observation-binding-missing'])
  }

  const metrics: Record<string, number | string | boolean> = {}
  if (isPlainRecord(metricsValue)) {
    for (const [key, entry] of Object.entries(metricsValue)) {
      if (typeof entry === 'number' || typeof entry === 'string' || typeof entry === 'boolean') metrics[key] = entry
    }
  }
  const outcome: ObservationOutcome = {
    status: status as ObservationOutcome['status'],
    severity: severity as ObservationOutcome['severity'],
    alerts: Array.isArray(alerts) ? alerts.filter((alert): alert is string => typeof alert === 'string') : [],
    metrics,
    summary: typeof result.summary === 'string' ? result.summary : null,
    checked_at: typeof result.checked_at === 'string' ? result.checked_at : null,
  }
  const body: Omit<MonitoringObservation, 'observation_digest'> = {
    schema_version: MONITORING_OBSERVATION_SCHEMA_VERSION,
    schedule_id: context.scheduleId,
    run_id: context.runId,
    lease_id: context.leaseId,
    fencing_token: Number.isSafeInteger(context.fencingToken) ? context.fencingToken : null,
    observation_only: true,
    gate_effect: 'none',
    market_auto_publish: false,
    trust_scope: 'local-only',
    captured_at: context.atIso,
    binding: {
      schedule_id: context.binding.schedule_id ?? context.scheduleId,
      plan_digest: context.binding.plan_digest,
      policy_digest: context.binding.policy_digest,
      target_digest: context.binding.target_digest,
    },
    outcome,
    note: typeof result.note === 'string' ? result.note : null,
    evidence_refs: Array.isArray(result.evidence_refs)
      ? result.evidence_refs.filter((ref): ref is string => typeof ref === 'string')
      : [],
  }
  const digest = contentDigest(body)
  const observation: MonitoringObservation = deepFreeze({ ...body, observation_digest: digest })
  return { ok: true, observation, digest }
}

/**
 * Defense-in-depth check: an observation must never look like a control
 * decision. Returns errors (empty array when safe).
 */
export function assertObservationOnly(value: unknown): string[] {
  const errors: string[] = []
  if (!isPlainRecord(value)) return ['observation-not-object']
  if (value.schema_version !== MONITORING_OBSERVATION_SCHEMA_VERSION) errors.push('observation-schema-invalid')
  if (value.observation_only !== true) errors.push('observation-only-flag-missing')
  if (value.gate_effect !== 'none') errors.push('observation-gate-effect-not-none')
  if (value.market_auto_publish !== false) errors.push('observation-market-auto-publish-must-be-false')
  if (value.trust_scope !== 'local-only') errors.push('observation-trust-scope-must-be-local-only')
  const authorityFields = findSchedulerAuthorityFields(value)
  if (authorityFields.length > 0) errors.push(...authorityFields.map((path) => `observation-authority-field:${path}`))
  return errors
}
