/**
 * Shared durable-scheduler type model (TypeScript migration phase).
 *
 * The trust boundary accepts `unknown`; every validator narrows explicitly with
 * predicates from `lease.ts`. No `any`, no `@ts-ignore`: the only casts are
 * documented schema assertions over SQLite rows (whose shape is created by the
 * versioned DDL in `store.ts`).
 *
 * @module @deepseek-ai/dsh-plugin-testbed/scheduler/types
 */

import type { JsonValue } from '../protocol/types.js'

/** Wall + monotonic clock used by leases; both are injectable for tests. */
export interface Clock {
  wallNow(): number
  monoNow(): number
  iso(wallMs: number): string
  parse(iso: string): number
}

/** One sampled pair of clocks. */
export interface ClockSample {
  ok: boolean
  wallMs: number | null
  monoMs: number | null
  faults: ClockFaultCode[]
  fault_codes: ClockFaultCode[]
  reason_codes: string[]
}

/** Detected clock anomalies (all map to `scheduler-clock-skew`). */
export type ClockFaultCode =
  | 'wall-clock-rollback'
  | 'wall-clock-forward-jump'
  | 'wall-vs-monotonic-drift'
  | 'monotonic-regression'
  | 'clock-non-finite'

/** Persisted clock-fault record. */
export interface ClockFaultRecord {
  faults: ClockFaultCode[]
  at: string
  wall_ms: number
  detail: string | null
}

/** Normalized lease scope; v1 pins concurrency to 1 (one owner per scope). */
export interface LeaseScope {
  profile: string
  target_digest: string
  tenant: string
  max_concurrency: 1
}

/** Lease lifecycle state. */
export type LeaseState = 'active' | 'released' | 'expired' | 'cancelled'

/** Cancel marker embedded in a lease. */
export interface LeaseCancel {
  requested_at: string | null
  token_id: string | null
}

/** Durable store identity embedded in every lease. */
export interface LeaseStoreRef {
  provider_id: string
  version: string
  durable: true
}

/** A `scheduler-lease/v1` document. */
export interface Lease {
  schema_version: string
  lease_id: string
  run_id: string
  schedule_id: string
  owner_id: string
  scope: LeaseScope
  fencing_token: number
  epoch: number
  state: LeaseState
  acquired_at: string
  expires_at: string
  ttl_ms: number
  heartbeat_seq: number
  store: LeaseStoreRef
  cancel: LeaseCancel
  evidence_refs: string[]
}

/** Event actor. */
export interface EventActor {
  id: string
  role: string
}

/** `scheduler-event/v1.type` closed set. */
export type SchedulerEventType =
  | 'acquire'
  | 'renew'
  | 'release'
  | 'expire'
  | 'cancel'
  | 'reap'
  | 'duplicate-detect'
  | 'store-recover'

/** Plan/policy/target binding carried by lease lifecycle events. */
export interface EventBinding {
  schedule_id: string
  plan_digest: string
  policy_digest: string
  target_digest: string
  scope_key?: string
}

/** A `scheduler-event/v1` document (append-only hash chain). */
export interface SchedulerEvent {
  schema_version: string
  event_id: string
  sequence: number
  lease_id: string | null
  type: SchedulerEventType
  actor: EventActor
  at: string
  fencing_token: number | null
  prev_digest: string
  event_digest: string
  binding?: EventBinding
  payload?: Record<string, unknown>
}

/** Lease record as returned by the store (public lease + internal binding). */
export interface LeaseRecord {
  lease: Lease
  scope_key: string
  binding: EventBinding
  expires_at_ms: number
  cancel_acknowledged_at: string | null
  reap_at: string | null
  released_at: string | null
  result_digest: string | null
}

/** `scheduler-policy/v1` after strict validation. */
export interface SchedulerPolicy {
  schema_version: string
  policy_id: string
  default_enabled: false
  require_authorization: true
  periodic_enabled: boolean
  market_auto_publish: false
  observation_only: true
  max_global_concurrency: number
  max_target_concurrency: number
  max_queue_depth: number
  default_ttl_ms: number
  min_ttl_ms: number
  max_ttl_ms: number
  heartbeat_interval_ms: number
  max_clock_skew_ms: number
  max_clock_forward_jump_ms: number
}

/** Authorization scope (`scheduler-authorization/v1.scope`). */
export interface AuthorizationScope {
  schedule_id?: string
  plan_digest?: string
  target_digest?: string
  profile?: string
  tenant?: string
  periodic?: boolean
  activate?: boolean
  schedule_version?: number
}

/** `scheduler-authorization/v1` after validation. */
export interface SchedulerAuthorization {
  schema_version: string
  authorization_id: string
  action: string
  authorized_by: string
  role: string
  requestor: string
  issued_at: string
  expires_at: string
  scope: AuthorizationScope
  reason: string
  signature: { alg: string; key_id: string; value: string } | null
  signature_present: boolean
  signature_verified: false
}

/** Periodic schedule configuration (interval mode only; cron is forbidden). */
export interface PeriodicConfig {
  enabled: boolean
  mode: 'interval'
  interval_ms: number | null
}

/** `scheduler-schedule/v1` frozen schedule. */
export interface FrozenSchedule {
  schema_version: string
  schedule_id: string
  version: number
  enabled: boolean
  profile: string
  target_digest: string
  plan_id: string
  plan_digest: string
  run_spec_digest: string | null
  periodic: PeriodicConfig
  created_by: string
  created_at: string
  authorization_digest: string
  policy_digest: string
  market_auto_publish: false
  observation_only: true
  labels: Record<string, string>
  notes: string | null
  content_digest: string
}

/** Observation outcome (monitoring only; never a GateDecision). */
export interface ObservationOutcome {
  status: 'healthy' | 'unhealthy' | 'unknown'
  severity: 'info' | 'warn' | 'error'
  alerts: string[]
  metrics: Record<string, number | string | boolean>
  summary: string | null
  checked_at: string | null
}

/** `monitoring-observation/v1`. */
export interface MonitoringObservation {
  schema_version: string
  schedule_id: string
  run_id: string
  lease_id: string | null
  fencing_token: number | null
  observation_only: true
  gate_effect: 'none'
  market_auto_publish: false
  trust_scope: 'local-only'
  captured_at: string
  binding: EventBinding
  outcome: ObservationOutcome
  note: string | null
  evidence_refs: string[]
  observation_digest: string
}

/** Store provider descriptor. */
export interface StoreProvider {
  provider_id: string
  version: string
  durable: boolean
  storage?: string
  single_host: boolean
  ha: boolean
  limitations?: string[]
}

/** Capability probe result. */
export interface CapabilityResult {
  ok: boolean
  provider: StoreProvider | null
  limitations: string[]
  node_version: string
  reason_codes: string[]
  detail: string | null
  checks?: Record<string, boolean>
}

/** Reaper report; `remaining` is OS-measured, never inferred from exit codes. */
export interface ReapReport {
  ok: boolean
  remaining: number[]
  mechanism: string
  error?: string
}

/** Common fail-closed command failure envelope. */
export interface SchedulerFailure {
  ok: false
  status: 'blocked'
  reason_codes: string[]
  detail: string | null
  [key: string]: unknown
}

/** Store health facts. */
export interface StoreFacts {
  provider: StoreProvider
  file_path: string
  journal_mode: string | null
  synchronous: string | null
}

/** Governance audit entry (append-only hash chain). */
export interface AuditEntry {
  schema_version: string
  audit_id: string
  sequence: number
  action: string
  actor: EventActor
  at: string
  detail: Record<string, unknown> | null
  prev_digest: string
  digest: string
}

/** Scheduler status snapshot (versioned public diagnostic). */
export interface SchedulerStatus {
  schema_version: string
  state: 'disabled' | 'blocked' | 'enabled'
  enabled: boolean
  enabled_requested: boolean
  reason_codes: string[]
  provider: StoreProvider | null
  limitations: string[]
  single_host: true
  ha: false
  store: (StoreFacts & { path: string | null }) | null
  store_fault: { reason: string; message: string } | null
  policy: {
    policy_id: string
    digest: string
    periodic_enabled: boolean
    max_global_concurrency: number
    max_target_concurrency: number
    max_queue_depth: number
    default_ttl_ms: number
  } | null
  authorization: {
    authorization_id: string
    digest: string
    role: string
    authorized_by: string
    expires_at: string
    signature_present: boolean
    signature_verified: false
  } | null
  kill_switch: {
    engaged: boolean
    actor_id: string | null
    actor_role: string | null
    at: string | null
    reason: string | null
  } | null
  clock: {
    ok: boolean
    faults: ClockFaultCode[]
    samples: number
    wall_ms: number | null
    mono_ms: number | null
  }
  ownership: {
    owner_id: string
    host: string
    pid: number
    tracked_process_trees: number
    owned_leases: number
  }
  runtime: {
    scheduling_default_enabled: boolean
    cron_enabled: boolean
    background_loops: boolean
    market_auto_publish: boolean
  }
  recovery: {
    recovered: Array<{ lease_id: string; reason: string }>
    kept: string[]
  } | null
  counts: Record<string, number> | null
  last_failure: { reason_codes: string[]; detail: string | null; at: string } | null
}

/** JSON-safe event payload value. */
export type EventPayload = Record<string, JsonValue>
