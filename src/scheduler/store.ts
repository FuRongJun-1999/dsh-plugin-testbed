/**
 * Durable single-host scheduler store (`scheduler-lease/v1` + `scheduler-event/v1`).
 *
 * ## Durability contract (NEXT-PHASE-REQUIREMENTS SCH-02/SCH-09)
 * - file-backed `node:sqlite`, `journal_mode=WAL`, `synchronous=FULL` (fsync);
 * - every state change runs in `BEGIN IMMEDIATE` + `COMMIT`, so acquire is a
 *   compare-and-swap and a second owner cannot slip in between read and write;
 * - an active lease is unique per scope via a partial unique index — the DB,
 *   not application code, is the final arbiter of "single scope, single owner";
 * - events are append-only: triggers abort UPDATE/DELETE, and each event's
 *   `event_digest` covers `prev_digest` (hash chain);
 * - corruption / non-durable open / missing schema fails closed with
 *   `scheduler-store-unavailable` / `scheduler-store-corrupt`.
 *
 * ## Limits (declared, never hidden)
 * This is a **single-host** store: there is no HA, no cross-host lease, no
 * external queue. Process-local monotonic TTL survives wall-clock rollback only
 * while the owner process lives; after a crash, recovery uses persisted wall
 * expiry plus local PID liveness (`SCHEDULER_LIMITATIONS`).
 *
 * @module @deepseek-ai/dsh-plugin-testbed/scheduler/store
 */

import { randomUUID } from 'node:crypto'
import { existsSync } from 'node:fs'
import { dirname } from 'node:path'
import type { DatabaseSync } from 'node:sqlite'
import { canonicalJson, sha256Hex } from '../protocol/digest.js'
import { GENESIS_EVENT_DIGEST, buildEvent, validateEvent, verifyEventChain } from './events.js'
import type { EventChainResult } from './events.js'
import { buildLease, isPlainRecord, normalizeScope } from './lease.js'
import { isoFromWallMs } from './clock.js'
import { loadNodeSqlite } from './capability.js'
import type {
  AuditEntry,
  ClockFaultRecord,
  EventActor,
  EventBinding,
  FrozenSchedule,
  Lease,
  LeaseRecord,
  MonitoringObservation,
  SchedulerEvent,
  SchedulerEventType,
  StoreFacts,
  StoreProvider,
} from './types.js'
import {
  MAX_MAINTENANCE_LEASES,
  SCHEDULER_EVENT_SCHEMA_VERSION,
  SCHEDULER_REASON,
  SCHEDULER_STORE_PROVIDER_ID,
  SCHEDULER_STORE_PROVIDER_VERSION,
  SCHEDULER_STORE_SCHEMA_VERSION,
} from './limits.js'

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS scheduler_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scheduler_schedules (
  schedule_id TEXT PRIMARY KEY,
  version INTEGER NOT NULL,
  content_digest TEXT NOT NULL,
  plan_digest TEXT NOT NULL,
  target_digest TEXT NOT NULL,
  policy_digest TEXT NOT NULL,
  config_json TEXT NOT NULL,
  state TEXT NOT NULL,
  registered_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scheduler_scope_counters (
  scope_key TEXT PRIMARY KEY,
  fencing_token INTEGER NOT NULL,
  epoch INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scheduler_leases (
  lease_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  schedule_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  scope_key TEXT NOT NULL,
  scope_json TEXT NOT NULL,
  profile TEXT NOT NULL,
  tenant TEXT NOT NULL,
  target_digest TEXT NOT NULL,
  plan_digest TEXT NOT NULL,
  policy_digest TEXT NOT NULL,
  fencing_token INTEGER NOT NULL,
  epoch INTEGER NOT NULL,
  state TEXT NOT NULL,
  acquired_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  ttl_ms INTEGER NOT NULL,
  heartbeat_seq INTEGER NOT NULL,
  last_heartbeat_at TEXT,
  cancel_requested_at TEXT,
  cancel_token_id TEXT,
  cancel_acknowledged_at TEXT,
  reap_at TEXT,
  released_at TEXT,
  result_digest TEXT,
  evidence_refs_json TEXT NOT NULL DEFAULT '[]'
);

CREATE UNIQUE INDEX IF NOT EXISTS scheduler_leases_one_active_per_scope
  ON scheduler_leases(scope_key) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS scheduler_leases_active_target
  ON scheduler_leases(target_digest) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS scheduler_leases_active_owner
  ON scheduler_leases(owner_id) WHERE state = 'active';

CREATE TABLE IF NOT EXISTS scheduler_queue (
  queue_id TEXT PRIMARY KEY,
  schedule_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  scope_key TEXT NOT NULL,
  target_digest TEXT NOT NULL,
  plan_digest TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL,
  enqueued_at TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  lease_id TEXT
);
CREATE INDEX IF NOT EXISTS scheduler_queue_ready
  ON scheduler_queue(state, priority DESC, enqueued_at ASC);

CREATE TABLE IF NOT EXISTS scheduler_results (
  result_id TEXT PRIMARY KEY,
  lease_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  fencing_token INTEGER NOT NULL,
  result_digest TEXT NOT NULL,
  observation_json TEXT NOT NULL,
  submitted_at TEXT NOT NULL,
  UNIQUE(lease_id, fencing_token)
);

CREATE TABLE IF NOT EXISTS scheduler_events (
  sequence INTEGER PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE,
  lease_id TEXT,
  type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  actor_role TEXT NOT NULL,
  at TEXT NOT NULL,
  fencing_token INTEGER,
  prev_digest TEXT NOT NULL,
  event_digest TEXT NOT NULL,
  binding_json TEXT,
  payload_json TEXT
);
CREATE INDEX IF NOT EXISTS scheduler_events_lease ON scheduler_events(lease_id, sequence);

CREATE TRIGGER IF NOT EXISTS scheduler_events_no_update
BEFORE UPDATE ON scheduler_events
BEGIN
  SELECT RAISE(ABORT, 'scheduler-events-append-only');
END;

CREATE TRIGGER IF NOT EXISTS scheduler_events_no_delete
BEFORE DELETE ON scheduler_events
BEGIN
  SELECT RAISE(ABORT, 'scheduler-events-append-only');
END;

CREATE TABLE IF NOT EXISTS scheduler_audit (
  sequence INTEGER PRIMARY KEY,
  audit_id TEXT NOT NULL UNIQUE,
  action TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  actor_role TEXT NOT NULL,
  at TEXT NOT NULL,
  detail_json TEXT,
  prev_digest TEXT NOT NULL,
  digest TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS scheduler_audit_no_update
BEFORE UPDATE ON scheduler_audit
BEGIN
  SELECT RAISE(ABORT, 'scheduler-audit-append-only');
END;

CREATE TRIGGER IF NOT EXISTS scheduler_audit_no_delete
BEFORE DELETE ON scheduler_audit
BEGIN
  SELECT RAISE(ABORT, 'scheduler-audit-append-only');
END;

CREATE TABLE IF NOT EXISTS scheduler_owners (
  owner_id TEXT PRIMARY KEY,
  host TEXT NOT NULL,
  pid INTEGER NOT NULL,
  boot_token TEXT,
  started_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  state TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS scheduler_owners_pid ON scheduler_owners(pid);
`

/** Store-level fail-closed error (reason is a stable scheduler reason code). */
export class SchedulerStoreError extends Error {
  reason: string
  details: unknown

  constructor(reason: string, message: string, details: unknown = null) {
    super(message)
    this.name = 'SchedulerStoreError'
    this.reason = reason
    this.details = details
  }
}

/** Common store failure shape (business refusals, never thrown). */
export interface StoreFailure {
  ok: false
  reason: string
  detail?: string | null
  [key: string]: unknown
}

interface MetaRow { value: string }
interface LeaseRow {
  lease_id: string
  run_id: string
  schedule_id: string
  owner_id: string
  scope_key: string
  scope_json: string
  target_digest: string
  plan_digest: string
  policy_digest: string
  fencing_token: number
  epoch: number
  state: string
  acquired_at: string
  expires_at: string
  expires_at_ms: number
  ttl_ms: number
  heartbeat_seq: number
  cancel_requested_at: string | null
  cancel_token_id: string | null
  cancel_acknowledged_at: string | null
  reap_at: string | null
  released_at: string | null
  result_digest: string | null
  evidence_refs_json: string
}
interface ScheduleRow {
  schedule_id: string
  version: number
  content_digest: string
  plan_digest: string
  target_digest: string
  policy_digest: string
  config_json: string
  state: string
  registered_at: string
  updated_at: string
}
interface QueueRow {
  queue_id: string
  schedule_id: string
  run_id: string
  idempotency_key: string
  scope_key: string
  target_digest: string
  plan_digest: string
  priority: number
  state: string
  enqueued_at: string
  attempts: number
  lease_id: string | null
}
interface EventRow {
  sequence: number
  event_id: string
  lease_id: string | null
  type: string
  actor_id: string
  actor_role: string
  at: string
  fencing_token: number | null
  prev_digest: string
  event_digest: string
  binding_json: string | null
  payload_json: string | null
}
interface AuditRow {
  sequence: number
  audit_id: string
  action: string
  actor_id: string
  actor_role: string
  at: string
  detail_json: string | null
  prev_digest: string
  digest: string
}
interface OwnerRow {
  owner_id: string
  host: string
  pid: number
  boot_token: string | null
  started_at: string
  last_seen_at: string
  state: string
}
interface ResultRow {
  result_id: string
  lease_id: string
  run_id: string
  fencing_token: number
  result_digest: string
  observation_json: string
  submitted_at: string
}

type SqlRow = Record<string, unknown>

function rowOne<T>(row: Record<string, unknown> | undefined): T | undefined {
  return row as unknown as T | undefined
}
function rowMany<T>(rows: Array<Record<string, unknown>>): T[] {
  return rows as unknown as T[]
}

function classifySqliteError(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err)
  if (/not a database|malformed|SQLITE_NOTADB|database disk image is malformed|file is encrypted/i.test(message)) {
    return SCHEDULER_REASON.STORE_CORRUPT
  }
  if (/database is locked|SQLITE_BUSY|database table is locked/i.test(message)) {
    return SCHEDULER_REASON.STORE_BUSY
  }
  return SCHEDULER_REASON.STORE_UNAVAILABLE
}

function storeError(err: unknown, details?: unknown): SchedulerStoreError {
  if (err instanceof SchedulerStoreError) return err
  return new SchedulerStoreError(
    classifySqliteError(err),
    err instanceof Error ? err.message : String(err),
    details ?? null,
  )
}

function parseJson(value: string | null | undefined, fallback: unknown = null): unknown {
  if (value === null || value === undefined) return fallback
  try {
    return JSON.parse(value) as unknown
  } catch {
    return fallback
  }
}

function asString(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback
}

function asNumber(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

/** Stored schedule record. */
export interface StoredSchedule {
  schedule_id: string
  version: number
  content_digest: string
  plan_digest: string
  target_digest: string
  policy_digest: string
  config: FrozenSchedule
  state: string
  registered_at: string
  updated_at: string
}

/** Queue record. */
export interface QueueRecord {
  queue_id: string
  schedule_id: string
  run_id: string
  idempotency_key: string
  scope_key: string
  target_digest: string
  plan_digest: string
  priority: number
  state: string
  enqueued_at: string
  attempts: number
  lease_id: string | null
}

/** Owner record. */
export interface OwnerRecord {
  owner_id: string
  host: string
  pid: number
  boot_token: string | null
  started_at: string
  last_seen_at: string
  state: string
}

/** Kill-switch record. */
export interface KillSwitchRecord {
  engaged: boolean
  actor_id: string | null
  actor_role: string | null
  at: string | null
  reason: string | null
}

/** Store integrity report. */
export interface IntegrityReport {
  ok: boolean
  errors: string[]
  counts: { leases: number; events: number; queue: number }
  event_chain: EventChainResult
}

/** Open options. */
export interface OpenSchedulerStoreOptions {
  filePath: string
  atIso: string
  requireExistingDirectory?: boolean
}

/** Acquire result. */
export type AcquireResult =
  | { ok: true; lease: Lease; binding: EventBinding; event: SchedulerEvent; queue_id: string; expires_at_ms: number }
  | StoreFailure
/** Renew result. */
export type RenewResult =
  | { ok: true; lease: Lease; binding: EventBinding; event: SchedulerEvent; expires_at_ms: number }
  | StoreFailure
/** Release result. */
export type ReleaseResult =
  | { ok: true; lease: Lease; binding?: EventBinding; event?: SchedulerEvent; idempotent?: boolean }
  | StoreFailure
/** Cancel-request result. */
export type CancelRequestResult =
  | { ok: true; lease: Lease; idempotent: boolean; event?: SchedulerEvent; cancel_token_id?: string }
  | StoreFailure
/** Cancel acknowledgement result. */
export type CancelAckResult =
  | { ok: true; lease: Lease; event?: SchedulerEvent; idempotent?: boolean; cancel_acknowledged: true }
  | StoreFailure
/** Result submission outcome. */
export type SubmitResultOutcome =
  | { ok: true; result_id: string; result_digest: string; observation: MonitoringObservation; idempotent: boolean }
  | StoreFailure

export function openSchedulerStore(options: OpenSchedulerStoreOptions): SchedulerStore {
  return SchedulerStore.open(options)
}

export class SchedulerStore {
  db: DatabaseSync | null
  filePath: string
  provider: StoreProvider
  closed: boolean
  journalMode: string | null
  synchronous: string | null
  openCount: number

  constructor(db: DatabaseSync, filePath: string, provider: StoreProvider) {
    this.db = db
    this.filePath = filePath
    this.provider = provider
    this.closed = false
    this.journalMode = null
    this.synchronous = null
    this.openCount = 0
  }

  static open(options: OpenSchedulerStoreOptions): SchedulerStore {
    const filePath = options.filePath
    if (typeof filePath !== 'string' || filePath.length === 0) {
      throw new SchedulerStoreError(SCHEDULER_REASON.STORE_REQUIRED, 'scheduler store path is required')
    }
    if (options.requireExistingDirectory !== false) {
      const parent = dirname(filePath)
      if (!existsSync(parent)) {
        throw new SchedulerStoreError(
          SCHEDULER_REASON.STORE_UNAVAILABLE,
          `scheduler store directory does not exist: ${parent}`,
        )
      }
    }
    const sqlite = loadNodeSqlite()
    if (!sqlite || typeof sqlite.DatabaseSync !== 'function') {
      throw new SchedulerStoreError(
        SCHEDULER_REASON.STORE_UNAVAILABLE,
        'node:sqlite DatabaseSync is not available in this runtime',
      )
    }
    let db: DatabaseSync | null = null
    try {
      db = new sqlite.DatabaseSync(filePath)
      db.exec('PRAGMA busy_timeout = 5000')
      const journal = db.prepare('PRAGMA journal_mode = WAL').get()
      if (String(journal?.journal_mode ?? '').toLowerCase() !== 'wal') {
        throw new SchedulerStoreError(
          SCHEDULER_REASON.STORE_NOT_DURABLE,
          `scheduler store could not enable WAL (journal_mode=${String(journal?.journal_mode)})`,
        )
      }
      db.exec('PRAGMA synchronous = FULL')
      const sync = db.prepare('PRAGMA synchronous').get()
      if (Number(sync?.synchronous) !== 2) {
        throw new SchedulerStoreError(
          SCHEDULER_REASON.STORE_NOT_DURABLE,
          `scheduler store could not enable synchronous=FULL (got ${String(sync?.synchronous)})`,
        )
      }
      db.exec('PRAGMA foreign_keys = ON')
      const check = db.prepare('PRAGMA quick_check').get()
      const checkValue = check?.quick_check
      if (checkValue !== 'ok') {
        throw new SchedulerStoreError(
          SCHEDULER_REASON.STORE_CORRUPT,
          `scheduler store integrity check failed: ${String(checkValue)}`,
        )
      }
      db.exec(SCHEMA_SQL)

      const store = new SchedulerStore(db, filePath, {
        provider_id: SCHEDULER_STORE_PROVIDER_ID,
        version: SCHEDULER_STORE_PROVIDER_VERSION,
        durable: true,
        storage: 'sqlite-wal-full',
        single_host: true,
        ha: false,
      })
      store.journalMode = 'wal'
      store.synchronous = 'FULL'
      store.#verifySchemaVersion()
      store.#initializeMeta(options.atIso)
      store.openCount += 1
      return store
    } catch (err) {
      if (db) {
        try { db.close() } catch { /* failed open */ }
      }
      throw storeError(err)
    }
  }

  #db(): DatabaseSync {
    if (this.closed || !this.db) {
      throw new SchedulerStoreError(SCHEDULER_REASON.STORE_UNAVAILABLE, 'scheduler store is closed')
    }
    return this.db
  }

  #verifySchemaVersion(): void {
    const row = rowOne<MetaRow>(this.#db().prepare('SELECT value FROM scheduler_meta WHERE key = ?').get('schema_version'))
    if (row === undefined) return
    if (String(row.value) !== String(SCHEDULER_STORE_SCHEMA_VERSION)) {
      throw new SchedulerStoreError(
        SCHEDULER_REASON.STORE_UNAVAILABLE,
        `scheduler store schema mismatch: found ${String(row.value)} expected ${SCHEDULER_STORE_SCHEMA_VERSION}`,
      )
    }
  }

  #initializeMeta(atIso: string): void {
    const existing = this.#db().prepare('SELECT value FROM scheduler_meta WHERE key = ?').get('store_id')
    if (existing === undefined) {
      this.#setMeta('store_id', `store-${randomUUID()}`)
      this.#setMeta('schema_version', String(SCHEDULER_STORE_SCHEMA_VERSION))
      this.#setMeta('provider_id', SCHEDULER_STORE_PROVIDER_ID)
      this.#setMeta('provider_version', SCHEDULER_STORE_PROVIDER_VERSION)
      this.#setMeta('created_at', atIso)
      this.#setMeta('kill_switch', JSON.stringify({
        engaged: false, actor_id: null, actor_role: null, at: null, reason: null,
      }))
      this.#setMeta('clock_fault', JSON.stringify(null))
      this.#setMeta('max_wall_ms', '0')
    } else {
      const opens = Number(this.#getMeta('open_count', '0'))
      this.#setMeta('open_count', String(Number.isSafeInteger(opens) ? opens + 1 : 1))
      this.#setMeta('last_opened_at', atIso)
    }
  }

  #getMeta(key: string, fallback: string | null = null): string | null {
    const row = rowOne<MetaRow>(this.#db().prepare('SELECT value FROM scheduler_meta WHERE key = ?').get(key))
    return row === undefined ? fallback : row.value
  }

  #setMeta(key: string, value: string): void {
    this.#db().prepare(
      'INSERT INTO scheduler_meta (key, value) VALUES (?, ?) ' +
      'ON CONFLICT(key) DO UPDATE SET value = excluded.value',
    ).run(key, value)
  }

  #transaction<T>(fn: () => T): T {
    const db = this.#db()
    db.exec('BEGIN IMMEDIATE')
    try {
      const result = fn()
      db.exec('COMMIT')
      return result
    } catch (err) {
      try { db.exec('ROLLBACK') } catch { /* transaction already failed */ }
      throw storeError(err)
    }
  }

  /** Close the handle. Idempotent; never deletes data. */
  close(): void {
    if (this.closed) return
    this.closed = true
    try { this.db?.close() } catch { /* best-effort close */ }
    this.db = null
  }

  /** Store facts for status/evidence. */
  storeFacts(): StoreFacts {
    return {
      provider: this.provider,
      file_path: this.filePath,
      journal_mode: this.journalMode,
      synchronous: this.synchronous,
    }
  }

  // -------------------------------------------------------------------------
  // Meta / control state
  // -------------------------------------------------------------------------

  killSwitch(): KillSwitchRecord {
    const value = parseJson(this.#getMeta('kill_switch'), null)
    if (!isPlainRecord(value) || typeof value.engaged !== 'boolean') {
      throw new SchedulerStoreError(SCHEDULER_REASON.STORE_CORRUPT, 'scheduler kill_switch meta is corrupt')
    }
    return {
      engaged: value.engaged,
      actor_id: typeof value.actor_id === 'string' ? value.actor_id : null,
      actor_role: typeof value.actor_role === 'string' ? value.actor_role : null,
      at: typeof value.at === 'string' ? value.at : null,
      reason: typeof value.reason === 'string' ? value.reason : null,
    }
  }

  engageKillSwitch(input: {
    actor: EventActor
    atIso: string
    reason: string
  }): { ok: true; idempotent?: boolean; kill_switch: KillSwitchRecord; audit?: AuditEntry } | StoreFailure {
    return this.#transaction(() => {
      const current = this.killSwitch()
      if (current.engaged) {
        return { ok: true as const, idempotent: true, kill_switch: current }
      }
      const next: KillSwitchRecord = {
        engaged: true,
        actor_id: input.actor.id,
        actor_role: input.actor.role,
        at: input.atIso,
        reason: input.reason,
      }
      this.#setMeta('kill_switch', JSON.stringify(next))
      const audit = this.#appendAuditTx({
        action: 'kill-switch-engage', actor: input.actor, atIso: input.atIso, detail: { reason: input.reason },
      })
      return { ok: true as const, kill_switch: next, audit }
    })
  }

  releaseKillSwitch(input: {
    actor: EventActor
    atIso: string
    reason: string
    authorizationDigest?: string | null
  }): { ok: true; idempotent?: boolean; kill_switch: KillSwitchRecord; audit?: AuditEntry } | StoreFailure {
    return this.#transaction(() => {
      const current = this.killSwitch()
      if (!current.engaged) {
        return { ok: true as const, idempotent: true, kill_switch: current }
      }
      const next: KillSwitchRecord = {
        engaged: false,
        actor_id: input.actor.id,
        actor_role: input.actor.role,
        at: input.atIso,
        reason: input.reason,
      }
      this.#setMeta('kill_switch', JSON.stringify(next))
      const audit = this.#appendAuditTx({
        action: 'kill-switch-release',
        actor: input.actor,
        atIso: input.atIso,
        detail: { reason: input.reason, authorization_digest: input.authorizationDigest ?? null },
      })
      return { ok: true as const, kill_switch: next, audit }
    })
  }

  clockFault(): ClockFaultRecord | null {
    const value = parseJson(this.#getMeta('clock_fault'), null)
    if (value === null) return null
    if (!isPlainRecord(value)) {
      throw new SchedulerStoreError(SCHEDULER_REASON.STORE_CORRUPT, 'scheduler clock_fault meta is corrupt')
    }
    return {
      faults: Array.isArray(value.faults)
        ? value.faults.filter((fault): fault is ClockFaultRecord['faults'][number] => typeof fault === 'string')
        : [],
      at: asString(value.at),
      wall_ms: asNumber(value.wall_ms),
      detail: typeof value.detail === 'string' ? value.detail : null,
    }
  }

  setClockFault(input: {
    faults: string[]
    atIso: string
    wallMs: number
    detail?: string | null
  }): { ok: true; clock_fault: ClockFaultRecord } {
    return this.#transaction(() => {
      const record: ClockFaultRecord = {
        faults: input.faults as ClockFaultRecord['faults'],
        at: input.atIso,
        wall_ms: input.wallMs,
        detail: input.detail ?? null,
      }
      this.#setMeta('clock_fault', JSON.stringify(record))
      this.#appendAuditTx({
        action: 'clock-fault-recorded',
        actor: { id: 'scheduler', role: 'system' },
        atIso: input.atIso,
        detail: { faults: record.faults, wall_ms: record.wall_ms },
      })
      return { ok: true as const, clock_fault: record }
    })
  }

  clearClockFault(input: {
    actor: EventActor
    atIso: string
    reason: string
  }): { ok: true; audit: AuditEntry } {
    return this.#transaction(() => {
      this.#setMeta('clock_fault', JSON.stringify(null))
      const audit = this.#appendAuditTx({
        action: 'clock-fault-cleared', actor: input.actor, atIso: input.atIso, detail: { reason: input.reason },
      })
      return { ok: true as const, audit }
    })
  }

  maxWallMs(): number {
    const value = Number(this.#getMeta('max_wall_ms', '0'))
    return Number.isFinite(value) && value > 0 ? value : 0
  }

  noteWallMs(wallMs: number): void {
    if (!Number.isFinite(wallMs)) return
    this.#transaction(() => {
      if (wallMs > this.maxWallMs()) this.#setMeta('max_wall_ms', String(Math.floor(wallMs)))
    })
  }

  // -------------------------------------------------------------------------
  // Audit (governance actions; append-only hash chain)
  // -------------------------------------------------------------------------

  #appendAuditTx(input: {
    action: string
    actor: EventActor
    atIso: string
    detail?: Record<string, unknown> | null
  }): AuditEntry {
    const last = rowOne<AuditRow>(this.#db().prepare(
      'SELECT sequence, digest FROM scheduler_audit ORDER BY sequence DESC LIMIT 1',
    ).get())
    const sequence = (last?.sequence ?? 0) + 1
    const prevDigest = last?.digest ?? GENESIS_EVENT_DIGEST
    const body = {
      schema_version: 'scheduler-audit/v1',
      audit_id: `audit-${randomUUID()}`,
      sequence,
      action: input.action,
      actor: { id: input.actor.id, role: input.actor.role },
      at: input.atIso,
      detail: input.detail ?? null,
      prev_digest: prevDigest,
    }
    const digest = 'sha256:' + sha256Hex(canonicalJson(body))
    this.#db().prepare(
      'INSERT INTO scheduler_audit (sequence, audit_id, action, actor_id, actor_role, at, detail_json, prev_digest, digest) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    ).run(
      sequence, body.audit_id, input.action, input.actor.id, input.actor.role, input.atIso,
      input.detail === undefined ? null : JSON.stringify(input.detail ?? null), prevDigest, digest,
    )
    return { ...body, digest }
  }

  appendAudit(input: {
    action: string
    actor: EventActor
    atIso: string
    detail?: Record<string, unknown> | null
  }): AuditEntry {
    return this.#transaction(() => this.#appendAuditTx(input))
  }

  readAudit({ limit = 10_000 }: { limit?: number } = {}): AuditEntry[] {
    const rows = rowMany<AuditRow>(this.#db().prepare(
      'SELECT * FROM scheduler_audit ORDER BY sequence ASC LIMIT ?',
    ).all(limit))
    return rows.map((row) => ({
      schema_version: 'scheduler-audit/v1',
      audit_id: row.audit_id,
      sequence: row.sequence,
      action: row.action,
      actor: { id: row.actor_id, role: row.actor_role },
      at: row.at,
      detail: parseJson(row.detail_json, null) as Record<string, unknown> | null,
      prev_digest: row.prev_digest,
      digest: row.digest,
    }))
  }

  // -------------------------------------------------------------------------
  // Owners (single-host crash recovery support)
  // -------------------------------------------------------------------------

  registerOwner(input: {
    ownerId: string
    host: string
    pid: number
    bootToken?: string | null
    atIso: string
  }): { ok: true; owner: OwnerRecord | null } {
    return this.#transaction(() => {
      const existing = rowOne<OwnerRow>(this.#db().prepare(
        'SELECT * FROM scheduler_owners WHERE owner_id = ?',
      ).get(input.ownerId))
      if (existing === undefined) {
        this.#db().prepare(
          'INSERT INTO scheduler_owners (owner_id, host, pid, boot_token, started_at, last_seen_at, state) ' +
          'VALUES (?, ?, ?, ?, ?, ?, ?)',
        ).run(input.ownerId, input.host, input.pid, input.bootToken ?? null, input.atIso, input.atIso, 'active')
      } else {
        this.#db().prepare(
          'UPDATE scheduler_owners SET host = ?, pid = ?, boot_token = ?, last_seen_at = ?, state = ? WHERE owner_id = ?',
        ).run(input.host, input.pid, input.bootToken ?? null, input.atIso, 'active', input.ownerId)
      }
      return { ok: true as const, owner: this.owner(input.ownerId) }
    })
  }

  owner(ownerId: string): OwnerRecord | null {
    const row = rowOne<OwnerRow>(this.#db().prepare(
      'SELECT * FROM scheduler_owners WHERE owner_id = ?',
    ).get(ownerId))
    if (row === undefined) return null
    return {
      owner_id: row.owner_id,
      host: row.host,
      pid: row.pid,
      boot_token: row.boot_token,
      started_at: row.started_at,
      last_seen_at: row.last_seen_at,
      state: row.state,
    }
  }

  touchOwner(input: { ownerId: string; atIso: string; state?: string }):
    { ok: true; owner: OwnerRecord | null } | StoreFailure {
    return this.#transaction(() => {
      const row = this.owner(input.ownerId)
      if (!row) return { ok: false as const, reason: SCHEDULER_REASON.LEASE_NOT_FOUND }
      this.#db().prepare('UPDATE scheduler_owners SET last_seen_at = ?, state = ? WHERE owner_id = ?')
        .run(input.atIso, input.state ?? 'active', input.ownerId)
      return { ok: true as const, owner: this.owner(input.ownerId) }
    })
  }

  // -------------------------------------------------------------------------
  // Events
  // -------------------------------------------------------------------------

  #appendEventTx(input: {
    leaseId: string | null
    type: SchedulerEventType
    actor: EventActor
    atIso: string
    fencingToken?: number | null
    binding?: EventBinding | null
    payload?: Record<string, unknown> | null
  }): SchedulerEvent {
    const last = rowOne<EventRow>(this.#db().prepare(
      'SELECT sequence, event_digest FROM scheduler_events ORDER BY sequence DESC LIMIT 1',
    ).get())
    const sequence = (last?.sequence ?? 0) + 1
    const prevDigest = last?.event_digest ?? GENESIS_EVENT_DIGEST
    const built = buildEvent({
      eventId: `evt-${randomUUID()}`,
      sequence,
      leaseId: input.leaseId,
      type: input.type,
      actor: input.actor,
      at: input.atIso,
      fencingToken: input.fencingToken ?? null,
      prevDigest,
      binding: input.binding ?? null,
      payload: input.payload ?? null,
    })
    if (!built.ok) {
      throw new SchedulerStoreError(
        SCHEDULER_REASON.STORE_UNAVAILABLE,
        `scheduler event build failed: ${built.errors.join(',')}`,
        built.errors,
      )
    }
    const event = built.event
    this.#db().prepare(
      'INSERT INTO scheduler_events (sequence, event_id, lease_id, type, actor_id, actor_role, at, ' +
      'fencing_token, prev_digest, event_digest, binding_json, payload_json) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    ).run(
      event.sequence, event.event_id, event.lease_id, event.type, event.actor.id, event.actor.role,
      event.at, event.fencing_token, event.prev_digest, event.event_digest,
      event.binding === undefined ? null : JSON.stringify(event.binding),
      event.payload === undefined ? null : JSON.stringify(event.payload),
    )
    return event
  }

  #checkFencing(leaseToken: number, presentedToken: unknown):
    { ok: true } | { ok: false; reason: string; current_fencing_token?: number; detail?: string } {
    if (typeof presentedToken !== 'number' || !Number.isSafeInteger(presentedToken) || presentedToken < 0) {
      return { ok: false, reason: SCHEDULER_REASON.INVALID_INPUT, detail: 'fencing_token must be a non-negative integer' }
    }
    if (presentedToken < leaseToken) {
      return { ok: false, reason: SCHEDULER_REASON.FENCING_TOKEN_STALE, current_fencing_token: leaseToken }
    }
    if (presentedToken > leaseToken) {
      return { ok: false, reason: SCHEDULER_REASON.FENCING_TOKEN_UNKNOWN, current_fencing_token: leaseToken }
    }
    return { ok: true }
  }

  #leaseFromRow(row: LeaseRow): LeaseRecord {
    const built = buildLease({
      leaseId: row.lease_id,
      runId: row.run_id,
      scheduleId: row.schedule_id,
      ownerId: row.owner_id,
      scope: parseJson(row.scope_json, null),
      fencingToken: row.fencing_token,
      epoch: row.epoch,
      state: row.state,
      acquiredAt: row.acquired_at,
      expiresAt: row.expires_at,
      ttlMs: row.ttl_ms,
      heartbeatSeq: row.heartbeat_seq,
      cancel: { requested_at: row.cancel_requested_at, token_id: row.cancel_token_id },
      evidenceRefs: Array.isArray(parseJson(row.evidence_refs_json, []))
        ? (parseJson(row.evidence_refs_json, []) as string[])
        : [],
    })
    if (!built.ok) {
      throw new SchedulerStoreError(
        SCHEDULER_REASON.STORE_CORRUPT,
        `scheduler lease row ${String(row.lease_id)} is invalid: ${built.errors.join(',')}`,
        built.errors,
      )
    }
    return {
      lease: built.lease,
      scope_key: row.scope_key,
      binding: {
        schedule_id: row.schedule_id,
        plan_digest: row.plan_digest,
        policy_digest: row.policy_digest,
        target_digest: row.target_digest,
        scope_key: row.scope_key,
      },
      expires_at_ms: row.expires_at_ms,
      cancel_acknowledged_at: row.cancel_acknowledged_at,
      reap_at: row.reap_at,
      released_at: row.released_at,
      result_digest: row.result_digest,
    }
  }

  getLease(leaseId: string): LeaseRecord | null {
    if (typeof leaseId !== 'string' || leaseId.length === 0) return null
    const row = rowOne<LeaseRow>(this.#db().prepare(
      'SELECT * FROM scheduler_leases WHERE lease_id = ?',
    ).get(leaseId))
    return row === undefined ? null : this.#leaseFromRow(row)
  }

  readEvents(filters: { leaseId?: string; limit?: number } = {}): SchedulerEvent[] {
    const limit = typeof filters.limit === 'number' && Number.isSafeInteger(filters.limit) && filters.limit > 0
      ? filters.limit
      : 50_000
    const db = this.#db()
    const rows = filters.leaseId
      ? rowMany<EventRow>(db.prepare('SELECT * FROM scheduler_events WHERE lease_id = ? ORDER BY sequence ASC LIMIT ?')
        .all(filters.leaseId, limit))
      : rowMany<EventRow>(db.prepare('SELECT * FROM scheduler_events ORDER BY sequence ASC LIMIT ?').all(limit))
    return rows.map((row) => this.#eventFromRow(row))
  }

  #eventFromRow(row: EventRow): SchedulerEvent {
    const raw: Record<string, unknown> = {
      schema_version: SCHEDULER_EVENT_SCHEMA_VERSION,
      event_id: row.event_id,
      sequence: row.sequence,
      lease_id: row.lease_id,
      type: row.type,
      actor: { id: row.actor_id, role: row.actor_role },
      at: row.at,
      fencing_token: row.fencing_token,
      prev_digest: row.prev_digest,
      event_digest: row.event_digest,
    }
    const binding = parseJson(row.binding_json, null)
    if (binding !== null) raw.binding = binding
    const payload = parseJson(row.payload_json, null)
    if (payload !== null) raw.payload = payload
    const checked = validateEvent(raw)
    if (!checked.ok) {
      throw new SchedulerStoreError(
        SCHEDULER_REASON.STORE_CORRUPT,
        `scheduler event ${String(row.event_id)} is invalid: ${checked.errors.join(',')}`,
        checked.errors,
      )
    }
    return checked.event
  }

  /** Verify the complete append-only event chain. */
  verifyEvents(): EventChainResult {
    return verifyEventChain(this.readEvents(), { requireGenesis: true })
  }

  // -------------------------------------------------------------------------
  // Schedules
  // -------------------------------------------------------------------------

  registerSchedule(input: {
    scheduleId: string
    version: number
    contentDigest: string
    planDigest: string
    targetDigest: string
    policyDigest: string
    config: FrozenSchedule
    atIso: string
  }): { ok: true; idempotent?: boolean; schedule: StoredSchedule | null } | StoreFailure {
    return this.#transaction(() => {
      const existing = rowOne<ScheduleRow>(this.#db().prepare(
        'SELECT * FROM scheduler_schedules WHERE schedule_id = ?',
      ).get(input.scheduleId))
      if (existing !== undefined) {
        if (existing.content_digest === input.contentDigest) {
          return { ok: true as const, idempotent: true, schedule: this.getSchedule(input.scheduleId) }
        }
        return {
          ok: false as const,
          reason: SCHEDULER_REASON.SCHEDULE_CONFLICT,
          detail: 'schedule_id already registered with a different content digest',
          existing_content_digest: existing.content_digest,
        }
      }
      this.#db().prepare(
        'INSERT INTO scheduler_schedules (schedule_id, version, content_digest, plan_digest, target_digest, ' +
        'policy_digest, config_json, state, registered_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      ).run(
        input.scheduleId, input.version, input.contentDigest, input.planDigest, input.targetDigest,
        input.policyDigest, JSON.stringify(input.config), 'active', input.atIso, input.atIso,
      )
      return { ok: true as const, schedule: this.getSchedule(input.scheduleId) }
    })
  }

  getSchedule(scheduleId: string): StoredSchedule | null {
    const row = rowOne<ScheduleRow>(this.#db().prepare(
      'SELECT * FROM scheduler_schedules WHERE schedule_id = ?',
    ).get(scheduleId))
    if (row === undefined) return null
    return {
      schedule_id: row.schedule_id,
      version: row.version,
      content_digest: row.content_digest,
      plan_digest: row.plan_digest,
      target_digest: row.target_digest,
      policy_digest: row.policy_digest,
      config: parseJson(row.config_json, null) as FrozenSchedule,
      state: row.state,
      registered_at: row.registered_at,
      updated_at: row.updated_at,
    }
  }

  setScheduleState(input: { scheduleId: string; state: string; atIso: string }):
    { ok: true; schedule: StoredSchedule | null } | StoreFailure {
    return this.#transaction(() => {
      const row = this.getSchedule(input.scheduleId)
      if (!row) return { ok: false as const, reason: SCHEDULER_REASON.SCHEDULE_NOT_FOUND }
      this.#db().prepare('UPDATE scheduler_schedules SET state = ?, updated_at = ? WHERE schedule_id = ?')
        .run(input.state, input.atIso, input.scheduleId)
      return { ok: true as const, schedule: this.getSchedule(input.scheduleId) }
    })
  }

  updateSchedule(input: {
    scheduleId: string
    version: number
    contentDigest: string
    planDigest: string
    targetDigest: string
    policyDigest: string
    config: FrozenSchedule
    state?: string
    atIso: string
  }): { ok: true; schedule: StoredSchedule | null } | StoreFailure {
    return this.#transaction(() => {
      const row = this.getSchedule(input.scheduleId)
      if (!row) return { ok: false as const, reason: SCHEDULER_REASON.SCHEDULE_NOT_FOUND }
      if (input.version <= row.version) {
        return {
          ok: false as const,
          reason: SCHEDULER_REASON.SCHEDULE_CONFLICT,
          detail: `schedule version must increase (current ${row.version})`,
          current_version: row.version,
        }
      }
      this.#db().prepare(
        'UPDATE scheduler_schedules SET version = ?, content_digest = ?, plan_digest = ?, target_digest = ?, ' +
        'policy_digest = ?, config_json = ?, state = ?, updated_at = ? WHERE schedule_id = ?',
      ).run(
        input.version, input.contentDigest, input.planDigest, input.targetDigest, input.policyDigest,
        JSON.stringify(input.config), input.state ?? row.state, input.atIso, input.scheduleId,
      )
      return { ok: true as const, schedule: this.getSchedule(input.scheduleId) }
    })
  }

  /** Active lease records (bounded). */
  listActiveLeases({ limit = MAX_MAINTENANCE_LEASES }: { limit?: number } = {}): LeaseRecord[] {
    const rows = rowMany<LeaseRow>(this.#db().prepare(
      "SELECT * FROM scheduler_leases WHERE state = 'active' ORDER BY acquired_at ASC LIMIT ?",
    ).all(limit))
    return rows.map((row) => this.#leaseFromRow(row))
  }

  /**
   * Operator/scheduler forced expiry (used on a lost heartbeat so the owner
   * loses the scope without waiting for the persisted TTL).
   */
  expireLease(input: {
    leaseId: string
    actor: EventActor
    atIso: string
    atMs: number
    reason: string
  }): { ok: true; lease: Lease; event?: SchedulerEvent; idempotent?: boolean } | StoreFailure {
    return this.#transaction(() => {
      const row = rowOne<LeaseRow>(this.#db().prepare(
        'SELECT * FROM scheduler_leases WHERE lease_id = ?',
      ).get(input.leaseId))
      if (row === undefined) return { ok: false as const, reason: SCHEDULER_REASON.LEASE_NOT_FOUND }
      if (row.state === 'expired') {
        return { ok: true as const, idempotent: true, lease: this.#leaseFromRow(row).lease }
      }
      if (row.state !== 'active') {
        return { ok: false as const, reason: SCHEDULER_REASON.LEASE_NOT_ACTIVE, lease_state: row.state }
      }
      this.#db().prepare("UPDATE scheduler_leases SET state = 'expired' WHERE lease_id = ? AND state = 'active'")
        .run(input.leaseId)
      this.#db().prepare("UPDATE scheduler_queue SET state = 'queued', lease_id = NULL WHERE lease_id = ? AND state = 'leased'")
        .run(input.leaseId)
      const updatedRow = rowOne<LeaseRow>(this.#db().prepare(
        'SELECT * FROM scheduler_leases WHERE lease_id = ?',
      ).get(input.leaseId))
      if (updatedRow === undefined) throw new SchedulerStoreError(SCHEDULER_REASON.STORE_CORRUPT, 'lease disappeared during expiry')
      const record = this.#leaseFromRow(updatedRow)
      const event = this.#appendEventTx({
        leaseId: input.leaseId,
        type: 'expire',
        actor: input.actor,
        atIso: input.atIso,
        fencingToken: row.fencing_token,
        binding: record.binding,
        payload: { reason: input.reason, at_ms: input.atMs, expires_at: row.expires_at },
      })
      return { ok: true as const, lease: record.lease, event }
    })
  }

  // -------------------------------------------------------------------------
  // Queue (bounded, idempotent)
  // -------------------------------------------------------------------------

  enqueue(input: {
    schedule: { scheduleId: string; planDigest: string; targetDigest: string; policyDigest: string }
    scopeKey: string
    runId: string
    idempotencyKey: string
    priority?: number
    atIso: string
    maxQueueDepth: number
  }): { ok: true; queue_id: string } | StoreFailure {
    return this.#transaction(() => {
      const existing = rowOne<QueueRow>(this.#db().prepare(
        'SELECT * FROM scheduler_queue WHERE idempotency_key = ?',
      ).get(input.idempotencyKey))
      if (existing !== undefined) {
        const event = this.#appendEventTx({
          leaseId: existing.lease_id,
          type: 'duplicate-detect',
          actor: { id: 'scheduler', role: 'scheduler' },
          atIso: input.atIso,
          fencingToken: null,
          binding: {
            schedule_id: input.schedule.scheduleId,
            plan_digest: input.schedule.planDigest,
            policy_digest: input.schedule.policyDigest,
            target_digest: input.schedule.targetDigest,
          },
          payload: {
            idempotency_key: input.idempotencyKey,
            existing_queue_id: existing.queue_id,
            existing_state: existing.state,
            run_id: input.runId,
          },
        })
        return {
          ok: false as const,
          reason: SCHEDULER_REASON.DUPLICATE_RUN,
          duplicate: true,
          queue_id: existing.queue_id,
          event,
        }
      }
      const queued = rowOne<{ count: number }>(this.#db().prepare(
        'SELECT COUNT(*) AS count FROM scheduler_queue WHERE state = ?',
      ).get('queued'))
      if (asNumber(queued?.count) >= input.maxQueueDepth) {
        return {
          ok: false as const,
          reason: SCHEDULER_REASON.QUEUE_FULL,
          queue_depth: asNumber(queued?.count),
          max_queue_depth: input.maxQueueDepth,
        }
      }
      const queueId = `queue-${randomUUID()}`
      this.#db().prepare(
        'INSERT INTO scheduler_queue (queue_id, schedule_id, run_id, idempotency_key, scope_key, ' +
        'target_digest, plan_digest, priority, state, enqueued_at, attempts, lease_id) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)',
      ).run(
        queueId, input.schedule.scheduleId, input.runId, input.idempotencyKey, input.scopeKey,
        input.schedule.targetDigest, input.schedule.planDigest,
        typeof input.priority === 'number' && Number.isSafeInteger(input.priority) ? input.priority : 0,
        'queued', input.atIso,
      )
      return { ok: true as const, queue_id: queueId }
    })
  }

  listQueue(filters: { scheduleId?: string; state?: string } = {}): QueueRecord[] {
    const rows = rowMany<QueueRow>(this.#db().prepare(
      'SELECT * FROM scheduler_queue WHERE (? IS NULL OR schedule_id = ?) AND (? IS NULL OR state = ?) ' +
      'ORDER BY priority DESC, enqueued_at ASC',
    ).all(filters.scheduleId ?? null, filters.scheduleId ?? null, filters.state ?? null, filters.state ?? null))
    return rows.map((row) => ({
      queue_id: row.queue_id,
      schedule_id: row.schedule_id,
      run_id: row.run_id,
      idempotency_key: row.idempotency_key,
      scope_key: row.scope_key,
      target_digest: row.target_digest,
      plan_digest: row.plan_digest,
      priority: row.priority,
      state: row.state,
      enqueued_at: row.enqueued_at,
      attempts: row.attempts,
      lease_id: row.lease_id,
    }))
  }

  // -------------------------------------------------------------------------
  // Lease lifecycle
  // -------------------------------------------------------------------------

  #activeCount(sql: string, args: Array<string | number> = []): number {
    const row = rowOne<{ count: number }>(this.#db().prepare(sql).get(...args))
    return asNumber(row?.count)
  }

  /**
   * Expire every active lease whose persisted wall expiry has passed. Used both
   * by maintenance and at the start of an acquire transaction.
   */
  #expireStaleTx(atIso: string, atMs: number, reason: string):
    Array<{ lease_id: string; fencing_token: number; event: SchedulerEvent }> {
    const rows = rowMany<LeaseRow>(this.#db().prepare(
      "SELECT * FROM scheduler_leases WHERE state = 'active' AND expires_at_ms <= ? " +
      'ORDER BY expires_at_ms ASC LIMIT ?',
    ).all(atMs, MAX_MAINTENANCE_LEASES))
    const expired: Array<{ lease_id: string; fencing_token: number; event: SchedulerEvent }> = []
    for (const row of rows) {
      const record = this.#leaseFromRow(row)
      this.#db().prepare("UPDATE scheduler_leases SET state = 'expired' WHERE lease_id = ? AND state = 'active'")
        .run(row.lease_id)
      this.#db().prepare("UPDATE scheduler_queue SET state = 'queued', lease_id = NULL WHERE lease_id = ? AND state = 'leased'")
        .run(row.lease_id)
      const event = this.#appendEventTx({
        leaseId: row.lease_id,
        type: 'expire',
        actor: { id: 'scheduler', role: 'scheduler' },
        atIso,
        fencingToken: row.fencing_token,
        binding: record.binding,
        payload: {
          reason,
          expires_at: row.expires_at,
          at_ms: atMs,
          fencing_token: row.fencing_token,
        },
      })
      expired.push({ lease_id: row.lease_id, fencing_token: row.fencing_token, event })
    }
    return expired
  }

  /** Public bounded maintenance. */
  expireStale(input: { atIso: string; atMs: number }):
    { ok: true; expired: Array<{ lease_id: string; fencing_token: number; event: SchedulerEvent }> } {
    return this.#transaction(() => {
      const expired = this.#expireStaleTx(input.atIso, input.atMs, 'ttl-expired')
      return { ok: true as const, expired }
    })
  }

  /**
   * Transactional compare-and-swap acquire.
   */
  acquire(input: {
    schedule: { scheduleId: string; planDigest: string; targetDigest: string; policyDigest: string }
    scope: unknown
    scopeKey: string
    ownerId: string
    runId: string
    idempotencyKey: string
    ttlMs: number
    atIso: string
    atMs: number
    maxGlobalConcurrency: number
    maxTargetConcurrency: number
    actor?: EventActor
  }): AcquireResult {
    const scope = normalizeScope(input.scope)
    if (!scope.ok) {
      return { ok: false, reason: SCHEDULER_REASON.INVALID_INPUT, errors: scope.errors }
    }
    return this.#transaction(() => {
      const db = this.#db()
      const kill = this.killSwitch()
      if (kill.engaged) return { ok: false as const, reason: SCHEDULER_REASON.KILL_SWITCH, kill_switch: kill }

      const scheduleRow = rowOne<ScheduleRow>(db.prepare(
        'SELECT * FROM scheduler_schedules WHERE schedule_id = ?',
      ).get(input.schedule.scheduleId))
      if (!scheduleRow) return { ok: false as const, reason: SCHEDULER_REASON.SCHEDULE_NOT_FOUND }
      if (scheduleRow.state !== 'active') {
        return { ok: false as const, reason: SCHEDULER_REASON.SCHEDULE_PAUSED, schedule_state: scheduleRow.state }
      }
      if (scheduleRow.plan_digest !== input.schedule.planDigest ||
          scheduleRow.target_digest !== input.schedule.targetDigest) {
        return { ok: false as const, reason: SCHEDULER_REASON.PLAN_BINDING_MISMATCH }
      }

      const queueRow = rowOne<QueueRow>(db.prepare(
        'SELECT * FROM scheduler_queue WHERE idempotency_key = ?',
      ).get(input.idempotencyKey))
      if (!queueRow) return { ok: false as const, reason: SCHEDULER_REASON.RUN_NOT_QUEUED }
      if (queueRow.schedule_id !== input.schedule.scheduleId || queueRow.run_id !== input.runId) {
        return { ok: false as const, reason: SCHEDULER_REASON.INVALID_INPUT, detail: 'queue row does not match schedule/run' }
      }
      if (queueRow.state === 'leased') {
        const active = queueRow.lease_id ? this.getLease(queueRow.lease_id) : null
        if (active && active.lease.state === 'active' && active.expires_at_ms > input.atMs) {
          return {
            ok: false as const,
            reason: SCHEDULER_REASON.DUPLICATE_RUN,
            lease_id: queueRow.lease_id,
            current_fencing_token: active.lease.fencing_token,
          }
        }
      } else if (queueRow.state !== 'queued') {
        return { ok: false as const, reason: SCHEDULER_REASON.RUN_NOT_QUEUED, queue_state: queueRow.state }
      }

      this.#expireStaleTx(input.atIso, input.atMs, 'expired-before-acquire')

      const existingActive = rowOne<LeaseRow>(db.prepare(
        "SELECT * FROM scheduler_leases WHERE scope_key = ? AND state = 'active'",
      ).get(scope.scopeKey))
      if (existingActive !== undefined) {
        return {
          ok: false as const,
          reason: SCHEDULER_REASON.LEASE_ACQUIRE_CONFLICT,
          owner_id: existingActive.owner_id,
          lease_id: existingActive.lease_id,
          current_fencing_token: existingActive.fencing_token,
        }
      }

      const activeGlobal = this.#activeCount("SELECT COUNT(*) AS count FROM scheduler_leases WHERE state = 'active'")
      if (activeGlobal >= input.maxGlobalConcurrency) {
        return {
          ok: false as const,
          reason: SCHEDULER_REASON.CONCURRENCY_LIMIT,
          scope: 'global',
          active: activeGlobal,
          limit: input.maxGlobalConcurrency,
        }
      }
      const activeTarget = this.#activeCount(
        "SELECT COUNT(*) AS count FROM scheduler_leases WHERE state = 'active' AND target_digest = ?",
        [input.schedule.targetDigest],
      )
      if (activeTarget >= input.maxTargetConcurrency) {
        return {
          ok: false as const,
          reason: SCHEDULER_REASON.CONCURRENCY_LIMIT,
          scope: 'target',
          active: activeTarget,
          limit: input.maxTargetConcurrency,
        }
      }

      const counter = rowOne<{ fencing_token: number; epoch: number }>(db.prepare(
        'SELECT * FROM scheduler_scope_counters WHERE scope_key = ?',
      ).get(scope.scopeKey))
      const fencingToken = asNumber(counter?.fencing_token) + 1
      const epoch = asNumber(counter?.epoch) + 1
      if (counter === undefined) {
        db.prepare('INSERT INTO scheduler_scope_counters (scope_key, fencing_token, epoch) VALUES (?, ?, ?)')
          .run(scope.scopeKey, fencingToken, epoch)
      } else {
        db.prepare('UPDATE scheduler_scope_counters SET fencing_token = ?, epoch = ? WHERE scope_key = ?')
          .run(fencingToken, epoch, scope.scopeKey)
      }

      const leaseId = `lease-${randomUUID()}`
      const expiresAt = isoFromWallMs(input.atMs + input.ttlMs)
      db.prepare(
        'INSERT INTO scheduler_leases (lease_id, run_id, schedule_id, owner_id, scope_key, scope_json, profile, ' +
        'tenant, target_digest, plan_digest, policy_digest, fencing_token, epoch, state, acquired_at, expires_at, ' +
        'expires_at_ms, ttl_ms, heartbeat_seq, last_heartbeat_at, cancel_requested_at, cancel_token_id, ' +
        'cancel_acknowledged_at, reap_at, released_at, result_digest, evidence_refs_json) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, NULL, NULL, NULL, NULL, NULL, NULL, ?)',
      ).run(
        leaseId, input.runId, input.schedule.scheduleId, input.ownerId, scope.scopeKey,
        JSON.stringify(scope.scope), scope.scope.profile, scope.scope.tenant,
        input.schedule.targetDigest, input.schedule.planDigest, input.schedule.policyDigest,
        fencingToken, epoch, 'active', input.atIso, expiresAt, input.atMs + input.ttlMs, input.ttlMs,
        input.atIso, '[]',
      )
      db.prepare("UPDATE scheduler_queue SET state = 'leased', lease_id = ?, attempts = attempts + 1 WHERE queue_id = ?")
        .run(leaseId, queueRow.queue_id)

      const record = this.getLease(leaseId)
      if (!record) throw new SchedulerStoreError(SCHEDULER_REASON.STORE_CORRUPT, 'lease row disappeared after insert')
      const event = this.#appendEventTx({
        leaseId,
        type: 'acquire',
        actor: input.actor ?? { id: input.ownerId, role: 'scheduler' },
        atIso: input.atIso,
        fencingToken,
        binding: record.binding,
        payload: {
          run_id: input.runId,
          owner_id: input.ownerId,
          ttl_ms: input.ttlMs,
          acquired_at: input.atIso,
          expires_at: expiresAt,
          fencing_token: fencingToken,
          epoch,
        },
      })
      return {
        ok: true as const,
        lease: record.lease,
        binding: record.binding,
        event,
        queue_id: queueRow.queue_id,
        expires_at_ms: record.expires_at_ms,
      }
    })
  }

  /**
   * Transactional heartbeat/renew.
   */
  renew(input: {
    leaseId: string
    fencingToken: number
    ownerId: string
    ttlMs: number
    atIso: string
    atMs: number
    actor?: EventActor
  }): RenewResult {
    return this.#transaction(() => {
      const row = rowOne<LeaseRow>(this.#db().prepare(
        'SELECT * FROM scheduler_leases WHERE lease_id = ?',
      ).get(input.leaseId))
      if (row === undefined) return { ok: false as const, reason: SCHEDULER_REASON.LEASE_NOT_FOUND }
      const fencing = this.#checkFencing(row.fencing_token, input.fencingToken)
      if (!fencing.ok) return fencing
      if (row.owner_id !== input.ownerId) {
        return { ok: false as const, reason: SCHEDULER_REASON.LEASE_OWNER_MISMATCH, current_owner_id: row.owner_id }
      }
      if (row.state !== 'active') {
        return {
          ok: false as const,
          reason: row.state === 'expired' ? SCHEDULER_REASON.LEASE_EXPIRED : SCHEDULER_REASON.LEASE_NOT_ACTIVE,
          lease_state: row.state,
        }
      }
      if (row.cancel_requested_at !== null) {
        return { ok: false as const, reason: SCHEDULER_REASON.LEASE_CANCELLING, lease: this.#leaseFromRow(row).lease }
      }
      if (Number(row.expires_at_ms) <= input.atMs) {
        const record = this.#leaseFromRow(row)
        this.#db().prepare("UPDATE scheduler_leases SET state = 'expired' WHERE lease_id = ? AND state = 'active'")
          .run(input.leaseId)
        this.#db().prepare("UPDATE scheduler_queue SET state = 'queued', lease_id = NULL WHERE lease_id = ? AND state = 'leased'")
          .run(input.leaseId)
        const expiredEvent = this.#appendEventTx({
          leaseId: input.leaseId,
          type: 'expire',
          actor: { id: 'scheduler', role: 'scheduler' },
          atIso: input.atIso,
          fencingToken: row.fencing_token,
          binding: record.binding,
          payload: { reason: 'heartbeat-after-expiry', expires_at: row.expires_at, at_ms: input.atMs },
        })
        return {
          ok: false as const,
          reason: SCHEDULER_REASON.LEASE_HEARTBEAT_LOST,
          lease_expired: true,
          event: expiredEvent,
          lease: this.getLease(input.leaseId)?.lease ?? null,
        }
      }
      const expiresAt = isoFromWallMs(input.atMs + input.ttlMs)
      this.#db().prepare(
        'UPDATE scheduler_leases SET expires_at = ?, expires_at_ms = ?, ttl_ms = ?, heartbeat_seq = heartbeat_seq + 1, ' +
        'last_heartbeat_at = ? WHERE lease_id = ?',
      ).run(expiresAt, input.atMs + input.ttlMs, input.ttlMs, input.atIso, input.leaseId)
      const updated = rowOne<LeaseRow>(this.#db().prepare(
        'SELECT * FROM scheduler_leases WHERE lease_id = ?',
      ).get(input.leaseId))
      if (updated === undefined) throw new SchedulerStoreError(SCHEDULER_REASON.STORE_CORRUPT, 'lease disappeared during renew')
      const record = this.#leaseFromRow(updated)
      const event = this.#appendEventTx({
        leaseId: input.leaseId,
        type: 'renew',
        actor: input.actor ?? { id: input.ownerId, role: 'scheduler' },
        atIso: input.atIso,
        fencingToken: row.fencing_token,
        binding: record.binding,
        payload: {
          heartbeat_seq: record.lease.heartbeat_seq,
          expires_at: expiresAt,
          ttl_ms: input.ttlMs,
        },
      })
      return { ok: true as const, lease: record.lease, binding: record.binding, event, expires_at_ms: record.expires_at_ms }
    })
  }

  release(input: {
    leaseId: string
    fencingToken: number
    ownerId: string
    atIso: string
    outcome?: string
    actor?: EventActor
  }): ReleaseResult {
    return this.#transaction(() => {
      const row = rowOne<LeaseRow>(this.#db().prepare(
        'SELECT * FROM scheduler_leases WHERE lease_id = ?',
      ).get(input.leaseId))
      if (row === undefined) return { ok: false as const, reason: SCHEDULER_REASON.LEASE_NOT_FOUND }
      const fencing = this.#checkFencing(row.fencing_token, input.fencingToken)
      if (!fencing.ok) return fencing
      if (row.owner_id !== input.ownerId) {
        return { ok: false as const, reason: SCHEDULER_REASON.LEASE_OWNER_MISMATCH, current_owner_id: row.owner_id }
      }
      if (row.state !== 'active') {
        if (row.state === 'expired') {
          return { ok: false as const, reason: SCHEDULER_REASON.LEASE_EXPIRED, lease_state: row.state }
        }
        return { ok: true as const, idempotent: true, lease: this.#leaseFromRow(row).lease, lease_state: row.state }
      }
      this.#db().prepare("UPDATE scheduler_leases SET state = 'released', released_at = ? WHERE lease_id = ? AND state = 'active'")
        .run(input.atIso, input.leaseId)
      this.#db().prepare("UPDATE scheduler_queue SET state = 'done' WHERE lease_id = ? AND state = 'leased'")
        .run(input.leaseId)
      const updated = rowOne<LeaseRow>(this.#db().prepare(
        'SELECT * FROM scheduler_leases WHERE lease_id = ?',
      ).get(input.leaseId))
      if (updated === undefined) throw new SchedulerStoreError(SCHEDULER_REASON.STORE_CORRUPT, 'lease disappeared during release')
      const record = this.#leaseFromRow(updated)
      const event = this.#appendEventTx({
        leaseId: input.leaseId,
        type: 'release',
        actor: input.actor ?? { id: input.ownerId, role: 'scheduler' },
        atIso: input.atIso,
        fencingToken: row.fencing_token,
        binding: record.binding,
        payload: { outcome: input.outcome ?? 'completed', fencing_token: row.fencing_token },
      })
      return { ok: true as const, lease: record.lease, binding: record.binding, event }
    })
  }

  /**
   * Durable cancel request (idempotent). State is not changed until the process
   * tree reclamation is confirmed by `acknowledgeCancel`.
   */
  requestCancel(input: {
    leaseId: string
    actor: EventActor
    atIso: string
    tokenId?: string
    reason?: string | null
  }): CancelRequestResult {
    return this.#transaction(() => {
      const row = rowOne<LeaseRow>(this.#db().prepare(
        'SELECT * FROM scheduler_leases WHERE lease_id = ?',
      ).get(input.leaseId))
      if (row === undefined) return { ok: false as const, reason: SCHEDULER_REASON.LEASE_NOT_FOUND }
      if (row.state === 'cancelled') {
        return { ok: true as const, idempotent: true, lease: this.#leaseFromRow(row).lease, cancel_acknowledged: true }
      }
      if (row.state !== 'active') {
        return { ok: true as const, idempotent: true, lease: this.#leaseFromRow(row).lease, lease_state: row.state }
      }
      if (row.cancel_requested_at !== null) {
        return {
          ok: true as const,
          idempotent: true,
          lease: this.#leaseFromRow(row).lease,
          cancel_requested_at: row.cancel_requested_at,
        }
      }
      const tokenId = typeof input.tokenId === 'string' && input.tokenId.length > 0
        ? input.tokenId
        : `cancel-${randomUUID()}`
      this.#db().prepare('UPDATE scheduler_leases SET cancel_requested_at = ?, cancel_token_id = ? WHERE lease_id = ?')
        .run(input.atIso, tokenId, input.leaseId)
      const updated = rowOne<LeaseRow>(this.#db().prepare(
        'SELECT * FROM scheduler_leases WHERE lease_id = ?',
      ).get(input.leaseId))
      if (updated === undefined) throw new SchedulerStoreError(SCHEDULER_REASON.STORE_CORRUPT, 'lease disappeared during cancel request')
      const record = this.#leaseFromRow(updated)
      const event = this.#appendEventTx({
        leaseId: input.leaseId,
        type: 'cancel',
        actor: input.actor,
        atIso: input.atIso,
        fencingToken: row.fencing_token,
        binding: record.binding,
        payload: {
          cancel_token_id: tokenId,
          reason: typeof input.reason === 'string' ? input.reason : null,
          requested_at: input.atIso,
        },
      })
      return { ok: true as const, idempotent: false, lease: record.lease, event, cancel_token_id: tokenId }
    })
  }

  /** Record a failed reap attempt (audit only; no state change). */
  recordReapFailure(input: {
    leaseId: string
    actor: EventActor
    atIso: string
    remaining: number[]
    mechanism?: string | null
    error?: string | null
  }): { ok: false; reason: string; event?: SchedulerEvent; lease?: Lease } | StoreFailure {
    return this.#transaction(() => {
      const row = rowOne<LeaseRow>(this.#db().prepare(
        'SELECT * FROM scheduler_leases WHERE lease_id = ?',
      ).get(input.leaseId))
      if (row === undefined) return { ok: false as const, reason: SCHEDULER_REASON.LEASE_NOT_FOUND }
      const record = this.#leaseFromRow(row)
      const event = this.#appendEventTx({
        leaseId: input.leaseId,
        type: 'reap',
        actor: input.actor,
        atIso: input.atIso,
        fencingToken: row.fencing_token,
        binding: record.binding,
        payload: {
          outcome: 'failed',
          remaining: Array.isArray(input.remaining)
            ? input.remaining.filter((pid) => Number.isSafeInteger(pid))
            : [],
          mechanism: input.mechanism ?? null,
          error: input.error ?? null,
        },
      })
      return { ok: false as const, reason: SCHEDULER_REASON.REAP_INCOMPLETE, event, lease: record.lease }
    })
  }

  /** Confirm a cancel after the complete process tree was observed gone. */
  acknowledgeCancel(input: {
    leaseId: string
    actor: EventActor
    atIso: string
    mechanism?: string | null
  }): CancelAckResult {
    return this.#transaction(() => {
      const row = rowOne<LeaseRow>(this.#db().prepare(
        'SELECT * FROM scheduler_leases WHERE lease_id = ?',
      ).get(input.leaseId))
      if (row === undefined) return { ok: false as const, reason: SCHEDULER_REASON.LEASE_NOT_FOUND }
      if (row.state === 'cancelled') {
        return {
          ok: true as const,
          idempotent: true,
          lease: this.#leaseFromRow(row).lease,
          cancel_acknowledged: true,
        }
      }
      if (row.state !== 'active') {
        return { ok: false as const, reason: SCHEDULER_REASON.LEASE_NOT_ACTIVE, lease_state: row.state }
      }
      if (row.cancel_requested_at === null) {
        return { ok: false as const, reason: SCHEDULER_REASON.INVALID_INPUT, detail: 'cancel was not requested' }
      }
      this.#db().prepare(
        "UPDATE scheduler_leases SET state = 'cancelled', cancel_acknowledged_at = ?, reap_at = ? WHERE lease_id = ?",
      ).run(input.atIso, input.atIso, input.leaseId)
      this.#db().prepare("UPDATE scheduler_queue SET state = 'cancelled' WHERE lease_id = ? AND state = 'leased'")
        .run(input.leaseId)
      const updated = rowOne<LeaseRow>(this.#db().prepare(
        'SELECT * FROM scheduler_leases WHERE lease_id = ?',
      ).get(input.leaseId))
      if (updated === undefined) throw new SchedulerStoreError(SCHEDULER_REASON.STORE_CORRUPT, 'lease disappeared during cancel ack')
      const record = this.#leaseFromRow(updated)
      const event = this.#appendEventTx({
        leaseId: input.leaseId,
        type: 'reap',
        actor: input.actor,
        atIso: input.atIso,
        fencingToken: row.fencing_token,
        binding: record.binding,
        payload: {
          outcome: 'reaped',
          remaining: [],
          mechanism: input.mechanism ?? null,
          cancel_acknowledged: true,
        },
      })
      return { ok: true as const, lease: record.lease, event, cancel_acknowledged: true }
    })
  }

  /**
   * Reject an old/expired writer's result write. Successful submission stores an
   * observation only (never a GateDecision) and is idempotent per
   * (lease_id, fencing_token).
   */
  submitResult(input: {
    leaseId: string
    fencingToken: number
    runId: string
    observation: MonitoringObservation
    resultDigest: string
    atIso: string
    atMs: number
    actor?: EventActor
  }): SubmitResultOutcome {
    return this.#transaction(() => {
      const row = rowOne<LeaseRow>(this.#db().prepare(
        'SELECT * FROM scheduler_leases WHERE lease_id = ?',
      ).get(input.leaseId))
      if (row === undefined) {
        const scopeToken = rowOne<{ fencing_token: number }>(this.#db().prepare(
          'SELECT fencing_token FROM scheduler_scope_counters WHERE scope_key = ?',
        ).get(''))
        return {
          ok: false as const,
          reason: SCHEDULER_REASON.LEASE_NOT_FOUND,
          current_fencing_token: scopeToken?.fencing_token ?? null,
        }
      }
      const record = this.#leaseFromRow(row)
      // Result fencing is compared against the *scope's* current token, not just
      // this lease row: once a newer acquire happened, an older owner's result is
      // stale even if its own row still carries the old token.
      const scopeCounter = rowOne<{ fencing_token: number }>(this.#db().prepare(
        'SELECT fencing_token FROM scheduler_scope_counters WHERE scope_key = ?',
      ).get(row.scope_key))
      const currentScopeToken = scopeCounter?.fencing_token ?? row.fencing_token
      if (input.fencingToken < currentScopeToken) {
        return {
          ok: false as const,
          reason: SCHEDULER_REASON.FENCING_TOKEN_STALE,
          current_fencing_token: currentScopeToken,
        }
      }
      if (input.fencingToken > currentScopeToken) {
        return {
          ok: false as const,
          reason: SCHEDULER_REASON.FENCING_TOKEN_UNKNOWN,
          current_fencing_token: currentScopeToken,
        }
      }
      const fencing = this.#checkFencing(row.fencing_token, input.fencingToken)
      if (!fencing.ok) return { ...fencing, lease_state: row.state }
      if (row.run_id !== input.runId) {
        return { ok: false as const, reason: SCHEDULER_REASON.RESULT_REJECTED, detail: 'run_id does not match lease' }
      }
      if (row.state !== 'active') {
        const counter = rowOne<{ fencing_token: number }>(this.#db().prepare(
          'SELECT fencing_token FROM scheduler_scope_counters WHERE scope_key = ?',
        ).get(row.scope_key))
        return {
          ok: false as const,
          reason: row.state === 'expired' ? SCHEDULER_REASON.LEASE_EXPIRED : SCHEDULER_REASON.LEASE_NOT_ACTIVE,
          lease_state: row.state,
          current_fencing_token: counter?.fencing_token ?? row.fencing_token,
        }
      }
      if (row.cancel_requested_at !== null) {
        return {
          ok: false as const,
          reason: SCHEDULER_REASON.LEASE_CANCELLING,
          current_fencing_token: row.fencing_token,
        }
      }
      if (Number(row.expires_at_ms) <= input.atMs) {
        this.#db().prepare("UPDATE scheduler_leases SET state = 'expired' WHERE lease_id = ? AND state = 'active'")
          .run(input.leaseId)
        this.#db().prepare("UPDATE scheduler_queue SET state = 'queued', lease_id = NULL WHERE lease_id = ? AND state = 'leased'")
          .run(input.leaseId)
        this.#appendEventTx({
          leaseId: input.leaseId,
          type: 'expire',
          actor: { id: 'scheduler', role: 'scheduler' },
          atIso: input.atIso,
          fencingToken: row.fencing_token,
          binding: record.binding,
          payload: { reason: 'result-after-expiry', expires_at: row.expires_at, at_ms: input.atMs },
        })
        const counter = rowOne<{ fencing_token: number }>(this.#db().prepare(
          'SELECT fencing_token FROM scheduler_scope_counters WHERE scope_key = ?',
        ).get(row.scope_key))
        return {
          ok: false as const,
          reason: SCHEDULER_REASON.LEASE_EXPIRED,
          lease_state: 'expired',
          current_fencing_token: counter?.fencing_token ?? row.fencing_token,
        }
      }
      if (input.actor !== undefined && row.owner_id !== input.actor.id &&
          input.actor.role !== 'operator' && input.actor.role !== 'system') {
        return { ok: false as const, reason: SCHEDULER_REASON.LEASE_OWNER_MISMATCH, current_owner_id: row.owner_id }
      }
      const existing = rowOne<ResultRow>(this.#db().prepare(
        'SELECT * FROM scheduler_results WHERE lease_id = ? AND fencing_token = ?',
      ).get(input.leaseId, input.fencingToken))
      if (existing !== undefined) {
        if (existing.result_digest !== input.resultDigest) {
          return {
            ok: false as const,
            reason: SCHEDULER_REASON.RESULT_CONFLICT,
            detail: 'same fencing token with a different result digest',
          }
        }
        return {
          ok: true as const,
          idempotent: true,
          result_id: existing.result_id,
          result_digest: existing.result_digest,
          observation: parseJson(existing.observation_json, null) as MonitoringObservation,
        }
      }
      const resultId = `result-${randomUUID()}`
      this.#db().prepare(
        'INSERT INTO scheduler_results (result_id, lease_id, run_id, fencing_token, result_digest, ' +
        'observation_json, submitted_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ).run(
        resultId, input.leaseId, input.runId, input.fencingToken, input.resultDigest,
        JSON.stringify(input.observation), input.atIso,
      )
      this.#db().prepare('UPDATE scheduler_leases SET result_digest = ? WHERE lease_id = ?')
        .run(input.resultDigest, input.leaseId)
      return {
        ok: true as const,
        idempotent: false,
        result_id: resultId,
        result_digest: input.resultDigest,
        observation: input.observation,
      }
    })
  }

  /**
   * Crash recovery: expire active leases whose TTL passed or whose owning
   * process is confirmed dead on this host, and append one store-recover event.
   */
  recover(input: {
    atIso: string
    atMs: number
    isOwnerAlive: ((ownerId: string) => boolean) | null
  }): {
    ok: true
    recovered: Array<{ lease_id: string; fencing_token: number; reason: string; event: SchedulerEvent }>
    kept: string[]
    event: SchedulerEvent
  } {
    return this.#transaction(() => {
      const rows = rowMany<LeaseRow>(this.#db().prepare(
        "SELECT * FROM scheduler_leases WHERE state = 'active' ORDER BY acquired_at ASC LIMIT ?",
      ).all(MAX_MAINTENANCE_LEASES))
      const recovered: Array<{ lease_id: string; fencing_token: number; reason: string; event: SchedulerEvent }> = []
      const kept: string[] = []
      for (const row of rows) {
        const record = this.#leaseFromRow(row)
        let reason: string | null = null
        if (Number(row.expires_at_ms) <= input.atMs) reason = 'ttl-expired-at-recovery'
        else if (typeof input.isOwnerAlive === 'function' && input.isOwnerAlive(row.owner_id) === false) {
          reason = 'owner-process-dead'
        }
        if (reason === null) {
          kept.push(row.lease_id)
          continue
        }
        this.#db().prepare("UPDATE scheduler_leases SET state = 'expired' WHERE lease_id = ? AND state = 'active'")
          .run(row.lease_id)
        this.#db().prepare("UPDATE scheduler_queue SET state = 'queued', lease_id = NULL WHERE lease_id = ? AND state = 'leased'")
          .run(row.lease_id)
        const event = this.#appendEventTx({
          leaseId: row.lease_id,
          type: 'expire',
          actor: { id: 'system', role: 'system' },
          atIso: input.atIso,
          fencingToken: row.fencing_token,
          binding: record.binding,
          payload: { reason, owner_id: row.owner_id, at_ms: input.atMs },
        })
        recovered.push({ lease_id: row.lease_id, fencing_token: row.fencing_token, reason, event })
      }
      const event = this.#appendEventTx({
        leaseId: null,
        type: 'store-recover',
        actor: { id: 'system', role: 'system' },
        atIso: input.atIso,
        fencingToken: null,
        payload: {
          recovered: recovered.map((item) => item.lease_id),
          kept,
          checked: rows.length,
        },
      })
      return { ok: true as const, recovered, kept, event }
    })
  }

  // -------------------------------------------------------------------------
  // Integrity / counts
  // -------------------------------------------------------------------------

  verifyIntegrity(): IntegrityReport {
    const db = this.#db()
    const errors: string[] = []
    try {
      const check = db.prepare('PRAGMA quick_check').get()
      const checkValue = check?.quick_check
      if (checkValue !== 'ok') errors.push(`store-integrity-check-failed:${String(checkValue)}`)
    } catch (err) {
      errors.push(`store-integrity-check-error:${err instanceof Error ? err.message : String(err)}`)
    }
    let eventChain: EventChainResult = {
      ok: false, errors: ['event-chain-unverified'], count: 0,
      first_sequence: null, last_sequence: null, last_digest: null,
    }
    try {
      eventChain = this.verifyEvents()
      if (!eventChain.ok) errors.push(...eventChain.errors)
    } catch (err) {
      errors.push(`event-chain-error:${err instanceof Error ? err.message : String(err)}`)
    }
    let leases = 0
    let events = 0
    let queue = 0
    try {
      leases = asNumber(rowOne<{ count: number }>(db.prepare('SELECT COUNT(*) AS count FROM scheduler_leases').get())?.count)
      events = asNumber(rowOne<{ count: number }>(db.prepare('SELECT COUNT(*) AS count FROM scheduler_events').get())?.count)
      queue = asNumber(rowOne<{ count: number }>(db.prepare('SELECT COUNT(*) AS count FROM scheduler_queue').get())?.count)
    } catch (err) {
      errors.push(`store-count-error:${err instanceof Error ? err.message : String(err)}`)
    }
    return {
      ok: errors.length === 0,
      errors,
      counts: { leases, events, queue },
      event_chain: eventChain,
    }
  }

  counts(): Record<string, number> {
    const db = this.#db()
    return {
      active_leases: asNumber(rowOne<{ count: number }>(db.prepare(
        "SELECT COUNT(*) AS count FROM scheduler_leases WHERE state = 'active'",
      ).get())?.count),
      total_leases: asNumber(rowOne<{ count: number }>(db.prepare(
        'SELECT COUNT(*) AS count FROM scheduler_leases',
      ).get())?.count),
      queued: asNumber(rowOne<{ count: number }>(db.prepare(
        "SELECT COUNT(*) AS count FROM scheduler_queue WHERE state = 'queued'",
      ).get())?.count),
      events: asNumber(rowOne<{ count: number }>(db.prepare(
        'SELECT COUNT(*) AS count FROM scheduler_events',
      ).get())?.count),
      results: asNumber(rowOne<{ count: number }>(db.prepare(
        'SELECT COUNT(*) AS count FROM scheduler_results',
      ).get())?.count),
    }
  }
}

/** Convenience for callers that only need a stable 32-char id. */
export function newSchedulerId(prefix: string): string {
  return `${prefix}-${randomUUID()}`
}
