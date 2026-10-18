/**
 * Public durable-scheduler surface.
 *
 * Wiring order (NEXT-PHASE-REQUIREMENTS §5.6 / §6.9):
 *   detectSchedulerCapability
 *     → openSchedulerStore (WAL + synchronous=FULL)
 *     → validateSchedulerPolicy + validateSchedulerAuthorization
 *     → registerSchedule (frozen plan binding)
 *     → enqueue → acquire → heartbeat / trackProcessTree
 *     → submitResult (observation only, current fencing token)
 *     → release
 *     → cancel / reap (durable + full process-tree confirmation)
 *
 * Scheduling is disabled by default; there is **no cron parser, no background
 * timer and no auto-enable**. Every state change is an explicit caller action
 * and every scheduler instance declares its single-host / no-HA limits.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/scheduler
 */
export { createScheduler, GovernedScheduler, frozenDefaultSchedulerPolicy } from './manager.js';
export { detectSchedulerCapability, loadNodeSqlite, schedulerStoreProvider } from './capability.js';
export { SchedulerStore, SchedulerStoreError, openSchedulerStore } from './store.js';
export { GENESIS_EVENT_DIGEST, buildEvent, eventDigest, rebuildLeaseTimeline, validateEvent, validateEventBinding, validateEventPayload, verifyEventChain, } from './events.js';
export { assertFencingCurrent, buildLease, fencingRelation, isDigest, isLeaseActive, isNonEmptyString, isPlainRecord, isScopeKey, normalizeCancel, normalizeScope, validateLease, } from './lease.js';
export { ClockGuard, CLOCK_FAULT, createClockGuard, createSystemClock, isRfc3339, isoFromWallMs, wallMsFromIso, } from './clock.js';
export { assertObservationOnly, bindFrozenPlan, buildMonitoringObservation, compareAuthorizationScope, contentDigest, createFrozenSchedule, defaultSchedulerPolicy, planDigestFromPlanId, validateSchedulerAuthorization, validateSchedulerPolicy, verifyFrozenSchedule, } from './governance.js';
export { defaultProcessTreeReaper, isPidAlive, reapMechanism, terminateProcessTree, waitForPidsGone, waitForTreeGone, } from './reaper.js';
export { SCHEDULER_AUTHORITY_FIELDS, findSchedulerAuthorityFields } from './authority.js';
export { DEFAULT_SCHEDULER_POLICY, LEASE_STATES, MAX_GLOBAL_CONCURRENCY, MAX_QUEUE_DEPTH, MAX_SCHEDULER_TTL_MS, MAX_TARGET_CONCURRENCY, MIN_HEARTBEAT_INTERVAL_MS, MIN_PERIODIC_INTERVAL_MS, MIN_SCHEDULER_TTL_MS, MONITORING_OBSERVATION_SCHEMA_VERSION, SCHEDULER_ACTOR_ROLES, SCHEDULER_AUTHORIZATION_ACTIONS, SCHEDULER_AUTHORIZATION_SCHEMA_VERSION, SCHEDULER_AUTHORIZER_ROLES, SCHEDULER_EVENT_SCHEMA_VERSION, SCHEDULER_EVENT_TYPES, SCHEDULER_LEASE_SCHEMA_VERSION, SCHEDULER_LIMITATIONS, SCHEDULER_POLICY_SCHEMA_VERSION, SCHEDULER_REASON, SCHEDULER_RUNTIME, SCHEDULER_SCHEDULE_SCHEMA_VERSION, SCHEDULER_STATUS_SCHEMA_VERSION, SCHEDULER_STORE_PROVIDER_ID, SCHEDULER_STORE_PROVIDER_VERSION, SCHEDULER_STORE_SCHEMA_VERSION, } from './limits.js';
// Final integration entry (t11): scheduler-disabled/enabled-policy semantics.
export { describeSchedulerEntry } from './entry.js';
