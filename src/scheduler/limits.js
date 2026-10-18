/**
 * Durable scheduler vocabulary, version boundaries, fail-closed reason codes and
 * hard limits.
 *
 * Governance position (NEXT-PHASE-REQUIREMENTS §5.6, §6.9, §9.2):
 *   - scheduling is **disabled by default**; a scheduler instance only accepts
 *     work after an explicit, non-expired operator authorization and a passed
 *     store/clock/capability gate;
 *   - there is **no cron parser and no background timer** in this module. A
 *     "periodic" schedule is a versioned, authorized configuration record only;
 *     the caller drives every tick. Design for SCH-10.
 *   - `node:sqlite` is a **single-host** durable store candidate. It is not HA,
 *     not cross-host and not an external queue. These limitations are declared
 *     in every status document (`SCHEDULER_LIMITATIONS`) and must never be
 *     reported as HA.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/scheduler/limits
 */
// ---------------------------------------------------------------------------
// Schema versions (each artifact evolves independently; unknown => reject).
// ---------------------------------------------------------------------------
export const SCHEDULER_LEASE_SCHEMA_VERSION = 'scheduler-lease/v1';
export const SCHEDULER_EVENT_SCHEMA_VERSION = 'scheduler-event/v1';
export const SCHEDULER_POLICY_SCHEMA_VERSION = 'scheduler-policy/v1';
export const SCHEDULER_SCHEDULE_SCHEMA_VERSION = 'scheduler-schedule/v1';
export const SCHEDULER_AUTHORIZATION_SCHEMA_VERSION = 'scheduler-authorization/v1';
export const SCHEDULER_STATUS_SCHEMA_VERSION = 'scheduler-status/v1';
export const SCHEDULER_AUDIT_SCHEMA_VERSION = 'scheduler-audit/v1';
export const MONITORING_OBSERVATION_SCHEMA_VERSION = 'monitoring-observation/v1';
/** Durable store provider identity (single host; see SCHEDULER_LIMITATIONS). */
export const SCHEDULER_STORE_PROVIDER_ID = 'node-sqlite-single-host';
export const SCHEDULER_STORE_PROVIDER_VERSION = '1.0.0';
export const SCHEDULER_STORE_SCHEMA_VERSION = 1;
/**
 * Declared limitations of the only provider implemented here. These are part of
 * the machine-readable status; a consumer must not upgrade them to HA claims.
 */
export const SCHEDULER_LIMITATIONS = Object.freeze([
    'single-host',
    'single-point-of-failure',
    'no-ha',
    'no-cross-host-lease',
    'no-external-durable-store',
    'process-restart-required-to-reload-store',
]);
/** Lease lifecycle states. `active` is the only writable state. */
export const LEASE_STATES = Object.freeze(['active', 'released', 'expired', 'cancelled']);
/** `scheduler-event/v1.type` closed set (NEXT-PHASE-REQUIREMENTS §6.9). */
export const SCHEDULER_EVENT_TYPES = Object.freeze([
    'acquire', 'renew', 'release', 'expire', 'cancel', 'reap', 'duplicate-detect', 'store-recover',
]);
/** Actor roles allowed to act on scheduler state. */
export const SCHEDULER_ACTOR_ROLES = Object.freeze(['scheduler', 'operator', 'system']);
/** Roles that may authorize governed scheduler actions (separation of duties). */
export const SCHEDULER_AUTHORIZER_ROLES = Object.freeze(['operator', 'release-manager', 'security']);
/** Authorization actions understood by `governance.js`. */
export const SCHEDULER_AUTHORIZATION_ACTIONS = Object.freeze([
    'enable-scheduler',
    'create-schedule',
    'modify-schedule',
    'pause-schedule',
    'release-kill-switch',
    'reset-clock-fault',
]);
/** Maximum TTL accepted by the v1 policy (bounded lease, SCH-03). */
export const MAX_SCHEDULER_TTL_MS = 15 * 60 * 1000;
/** Minimum TTL accepted by the v1 policy. */
export const MIN_SCHEDULER_TTL_MS = 1_000;
/** Heartbeat must be strictly inside the TTL window. */
export const MIN_HEARTBEAT_INTERVAL_MS = 100;
/** Hard ceilings for queue/concurrency (policy may only tighten them). */
export const MAX_GLOBAL_CONCURRENCY = 32;
export const MAX_TARGET_CONCURRENCY = 8;
export const MAX_QUEUE_DEPTH = 1_024;
/** Interval-mode periodic schedules may not be shorter than one minute. */
export const MIN_PERIODIC_INTERVAL_MS = 60_000;
/** Tolerated wall-vs-monotonic drift before the clock guard trips. */
export const DEFAULT_MAX_CLOCK_SKEW_MS = 2_000;
/** Tolerated forward wall jump relative to monotonic time. */
export const DEFAULT_MAX_CLOCK_FORWARD_JUMP_MS = 5 * 60 * 1000;
/** Tolerated store/event verification gap before denying writes. */
export const MAX_EVENT_PAYLOAD_BYTES = 64 * 1024;
/** Bounded count for maintenance/expire loops (no unbounded scans). */
export const MAX_MAINTENANCE_LEASES = 512;
/** Default frozen scheduler policy: everything is opt-in. */
export const DEFAULT_SCHEDULER_POLICY = Object.freeze({
    schema_version: SCHEDULER_POLICY_SCHEMA_VERSION,
    policy_id: 'scheduler-policy:default-local-only',
    default_enabled: false,
    require_authorization: true,
    periodic_enabled: false,
    market_auto_publish: false,
    observation_only: true,
    max_global_concurrency: 2,
    max_target_concurrency: 1,
    max_queue_depth: 32,
    default_ttl_ms: 30_000,
    min_ttl_ms: MIN_SCHEDULER_TTL_MS,
    max_ttl_ms: 5 * 60 * 1000,
    heartbeat_interval_ms: 5_000,
    max_clock_skew_ms: DEFAULT_MAX_CLOCK_SKEW_MS,
    max_clock_forward_jump_ms: DEFAULT_MAX_CLOCK_FORWARD_JUMP_MS,
});
/**
 * Stable reason codes. Implementation may add codes, but the strings below are
 * part of the module contract and downstream tests bind to them verbatim
 * (NEXT-PHASE-REQUIREMENTS §9.2).
 */
export const SCHEDULER_REASON = Object.freeze({
    DISABLED: 'scheduler-disabled',
    STORE_UNAVAILABLE: 'scheduler-store-unavailable',
    STORE_CORRUPT: 'scheduler-store-corrupt',
    STORE_NOT_DURABLE: 'scheduler-store-not-durable',
    STORE_REQUIRED: 'scheduler-store-required',
    STORE_BUSY: 'scheduler-store-busy',
    CLOCK_SKEW: 'scheduler-clock-skew',
    CLOCK_FAULT_PERSISTED: 'scheduler-clock-fault-persisted',
    KILL_SWITCH: 'scheduler-kill-switch',
    AUTHORIZATION_REQUIRED: 'scheduler-authorization-required',
    AUTHORIZATION_INVALID: 'scheduler-authorization-invalid',
    AUTHORIZATION_EXPIRED: 'scheduler-authorization-expired',
    AUTHORIZATION_SELF_APPROVED: 'scheduler-authorization-self-approved',
    AUTHORIZATION_SCOPE_MISMATCH: 'scheduler-authorization-scope-mismatch',
    POLICY_INVALID: 'scheduler-policy-invalid',
    CAPABILITY_UNAVAILABLE: 'scheduler-capability-unavailable',
    MARKET_AUTOPUBLISH_FORBIDDEN: 'scheduler-market-autopublish-forbidden',
    MARKET_APPROVAL_BYPASS_FORBIDDEN: 'scheduler-market-approval-bypass-forbidden',
    PERIODIC_NOT_AUTHORIZED: 'scheduler-not-periodic-authorized',
    CRON_DISABLED: 'scheduler-cron-disabled',
    PLAN_BINDING_MISMATCH: 'scheduler-plan-binding-mismatch',
    PLAN_MUTATION_REJECTED: 'scheduler-plan-mutation-rejected',
    SCHEDULE_INVALID: 'scheduler-schedule-invalid',
    SCHEDULE_CONFLICT: 'scheduler-schedule-conflict',
    SCHEDULE_NOT_FOUND: 'scheduler-schedule-not-found',
    SCHEDULE_PAUSED: 'scheduler-schedule-paused',
    DUPLICATE_RUN: 'scheduler-duplicate-run',
    QUEUE_FULL: 'scheduler-queue-full',
    CONCURRENCY_LIMIT: 'scheduler-concurrency-limit',
    RUN_NOT_QUEUED: 'scheduler-run-not-queued',
    LEASE_ACQUIRE_CONFLICT: 'lease-acquire-conflict',
    LEASE_NOT_FOUND: 'lease-not-found',
    LEASE_NOT_ACTIVE: 'lease-not-active',
    LEASE_EXPIRED: 'lease-expired',
    LEASE_HEARTBEAT_LOST: 'lease-heartbeat-lost',
    LEASE_OWNER_MISMATCH: 'lease-owner-mismatch',
    LEASE_CANCELLING: 'cancel-not-acknowledged',
    FENCING_TOKEN_STALE: 'fencing-token-stale',
    FENCING_TOKEN_UNKNOWN: 'fencing-token-unknown',
    CANCEL_NOT_ACKNOWLEDGED: 'cancel-not-acknowledged',
    REAP_INCOMPLETE: 'reap-incomplete',
    RESULT_REJECTED: 'scheduler-result-rejected',
    RESULT_CONFLICT: 'scheduler-result-conflict',
    AUTHORITY_FIELD_REJECTED: 'scheduler-authority-field-rejected',
    INVALID_INPUT: 'scheduler-invalid-input',
    STORE_RECOVERY_FAILED: 'scheduler-store-recovery-failed',
});
/** Source-visible runtime capability facts recorded in every status snapshot. */
export const SCHEDULER_RUNTIME = Object.freeze({
    scheduling_default_enabled: false,
    cron_enabled: false,
    background_loops: false,
    market_auto_publish: false,
});
