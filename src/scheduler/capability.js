/**
 * Scheduler durable-store capability probe.
 *
 * Scheduling is **off by default** and the runtime capability gate is part of
 * the fail-closed contract: a scheduler may only leave `disabled/blocked` after
 * this probe proves that a real, file-backed SQLite store is available with
 * WAL journaling and `synchronous=FULL` (fsync), and that a value survives a
 * close/reopen cycle.
 *
 * The probe deliberately *does not* upgrade the provider: `node:sqlite` is a
 * single-host store; `ha:false` and `single_host:true` are recorded in the
 * probe result and must be copied verbatim into scheduler status / evidence.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/scheduler/capability
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { SCHEDULER_LIMITATIONS, SCHEDULER_REASON, SCHEDULER_STORE_PROVIDER_ID, SCHEDULER_STORE_PROVIDER_VERSION, } from './limits.js';
const moduleRequire = createRequire(import.meta.url);
/**
 * Lazy loader so the scheduler module stays importable on Node versions that do
 * not ship `node:sqlite` (the probe then reports the capability as unavailable
 * instead of crashing the process).
 */
export function loadNodeSqlite() {
    try {
        return moduleRequire('node:sqlite');
    }
    catch {
        return null;
    }
}
/** Machine-readable provider descriptor for the only implemented store. */
export function schedulerStoreProvider() {
    return Object.freeze({
        provider_id: SCHEDULER_STORE_PROVIDER_ID,
        version: SCHEDULER_STORE_PROVIDER_VERSION,
        durable: true,
        storage: 'sqlite-wal-full',
        single_host: true,
        ha: false,
        limitations: [...SCHEDULER_LIMITATIONS],
    });
}
/**
 * Probe `node:sqlite` durability on this host.
 */
export function detectSchedulerCapability(options = {}) {
    const sqlite = options.sqlite === undefined ? loadNodeSqlite() : options.sqlite;
    const nodeVersion = process.versions?.node ?? 'unknown';
    const removeProbe = options.removeProbe !== false;
    const base = {
        ok: false,
        provider: null,
        limitations: [...SCHEDULER_LIMITATIONS],
        node_version: nodeVersion,
        reason_codes: [],
        detail: null,
    };
    if (!sqlite || typeof sqlite.DatabaseSync !== 'function') {
        return {
            ...base,
            reason_codes: [SCHEDULER_REASON.CAPABILITY_UNAVAILABLE, SCHEDULER_REASON.STORE_UNAVAILABLE],
            detail: 'node:sqlite DatabaseSync is not available in this runtime',
        };
    }
    let dir = null;
    let database = null;
    const checks = {
        journal_mode_wal: false,
        synchronous_full: false,
        transaction: false,
        reopen_persisted: false,
        wal_reopen: false,
    };
    try {
        dir = mkdtempSync(join(options.tmpRoot ?? tmpdir(), 'dsh-scheduler-cap-'));
        const file = join(dir, 'probe.sqlite');
        database = new sqlite.DatabaseSync(file);
        database.exec('PRAGMA busy_timeout = 5000');
        const journal = database.prepare('PRAGMA journal_mode = WAL').get();
        checks.journal_mode_wal = String(journal?.journal_mode ?? '').toLowerCase() === 'wal';
        database.exec('PRAGMA synchronous = FULL');
        const sync = database.prepare('PRAGMA synchronous').get();
        checks.synchronous_full = Number(sync?.synchronous) === 2;
        database.exec('CREATE TABLE probe (id INTEGER PRIMARY KEY, value TEXT NOT NULL)');
        database.exec('BEGIN IMMEDIATE');
        database.prepare('INSERT INTO probe (id, value) VALUES (?, ?)').run(1, 'durable-probe');
        database.exec('COMMIT');
        checks.transaction = true;
        database.close();
        database = null;
        database = new sqlite.DatabaseSync(file);
        const reopened = database.prepare('SELECT value FROM probe WHERE id = ?').get(1);
        checks.reopen_persisted = reopened?.value === 'durable-probe';
        const reopenedJournal = database.prepare('PRAGMA journal_mode').get();
        checks.wal_reopen = String(reopenedJournal?.journal_mode ?? '').toLowerCase() === 'wal';
        database.close();
        database = null;
        if (!checks.journal_mode_wal || !checks.synchronous_full || !checks.transaction ||
            !checks.reopen_persisted || !checks.wal_reopen) {
            return {
                ...base,
                checks,
                reason_codes: [SCHEDULER_REASON.STORE_NOT_DURABLE, SCHEDULER_REASON.STORE_UNAVAILABLE],
                detail: `durability probe failed: ${JSON.stringify(checks)}`,
            };
        }
        return {
            ...base,
            ok: true,
            provider: { ...schedulerStoreProvider() },
            checks,
            reason_codes: [],
        };
    }
    catch (err) {
        return {
            ...base,
            checks,
            reason_codes: [SCHEDULER_REASON.CAPABILITY_UNAVAILABLE, SCHEDULER_REASON.STORE_UNAVAILABLE],
            detail: `capability probe error: ${err instanceof Error ? err.message : String(err)}`,
        };
    }
    finally {
        if (database) {
            try {
                database.close();
            }
            catch { /* probe only */ }
        }
        if (dir && removeProbe) {
            try {
                rmSync(dir, { recursive: true, force: true });
            }
            catch { /* temp probe files */ }
        }
    }
}
