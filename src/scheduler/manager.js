/**
 * Governed durable scheduler core.
 *
 * ## Default-off and fail-closed (NEXT-PHASE-REQUIREMENTS SCH-01..SCH-10)
 * - `createScheduler()` constructs a **disabled** scheduler with no store, no
 *   timers and no cron. Nothing runs in the background; every tick/acquire is an
 *   explicit caller action.
 * - `enable()` requires: a passing durable-store capability probe, a real
 *   SQLite WAL+fsync store, a sane clock, no persisted clock fault, and an
 *   explicit non-expired operator authorization with separation of duties.
 *   Any missing condition leaves the scheduler `disabled`/`blocked` with stable
 *   reason codes.
 * - Lease acquisition/renewal/release/result submission are transactional
 *   (SQLite `BEGIN IMMEDIATE`), fencing tokens are monotonic per scope, and an
 *   older token's result write is rejected.
 * - Cancel is durable, idempotent and only acknowledged after the **complete
 *   process tree** is observed gone; an unconfirmed reap returns
 *   `cancel-not-acknowledged` / `reap-incomplete`.
 * - A global durable kill switch blocks new work; schedule creation and
 *   modification need authorization and produce audit records.
 * - Periodic schedules are versioned data only; enabling one requires
 *   authorization scope `periodic: true` and a policy with `periodic_enabled`.
 *   The scheduler never modifies the frozen Plan, never bypasses market
 *   approval, and returns monitoring observations that always carry
 *   `gate_effect: "none"`.
 *
 * ## Declared limits
 * `node:sqlite` is single-host, single point of failure, no HA and no
 * cross-host lease. Crash recovery uses persisted TTL expiry plus local PID
 * liveness; it is not distributed consensus. See `SCHEDULER_LIMITATIONS`.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/scheduler/manager
 */
import { hostname } from 'node:os';
import { randomUUID } from 'node:crypto';
import { ClockGuard, CLOCK_FAULT, isoFromWallMs } from './clock.js';
import { detectSchedulerCapability, schedulerStoreProvider } from './capability.js';
import { buildMonitoringObservation, contentDigest, createFrozenSchedule, defaultSchedulerPolicy, planDigestFromPlanId, validateSchedulerAuthorization, validateSchedulerPolicy, verifyFrozenSchedule, } from './governance.js';
import { isNonEmptyString, isPlainRecord, normalizeScope } from './lease.js';
import { defaultProcessTreeReaper, isPidAlive } from './reaper.js';
import { openSchedulerStore, SchedulerStoreError } from './store.js';
import { DEFAULT_SCHEDULER_POLICY, SCHEDULER_ACTOR_ROLES, SCHEDULER_AUTHORIZER_ROLES, SCHEDULER_LIMITATIONS, SCHEDULER_REASON, SCHEDULER_RUNTIME, SCHEDULER_STATUS_SCHEMA_VERSION, SCHEDULER_STORE_PROVIDER_ID, } from './limits.js';
const SCHEDULER_ACTOR_OK = new Set([...SCHEDULER_ACTOR_ROLES, ...SCHEDULER_AUTHORIZER_ROLES]);
const CLOCK_RECOVERY_ROLES = new Set(['operator', 'security', 'release-manager']);
function dedupe(values) {
    return [...new Set(values.filter((value) => typeof value === 'string' && value.length > 0))];
}
function isActor(value) {
    return isPlainRecord(value) && isNonEmptyString(value.id) && typeof value.role === 'string' &&
        SCHEDULER_ACTOR_OK.has(value.role);
}
function isSchedulerFailure(value) {
    return isPlainRecord(value) && value.ok === false && Array.isArray(value.reason_codes);
}
function isStoreFailure(value) {
    return isPlainRecord(value) && value.ok === false && typeof value.reason === 'string';
}
/**
 * Durable, governed scheduler. Construct via {@link createScheduler}.
 */
export class GovernedScheduler {
    options;
    ownerId;
    host;
    pid;
    storePath;
    reaper;
    isOwnerAlive;
    clockGuard;
    store;
    storeError;
    storeFault;
    capability;
    policy;
    policyDigest;
    authorization;
    authorizationDigest;
    enabledRequested;
    enabled;
    killSwitchState;
    persistedClockFault;
    recovery;
    owned;
    tracked;
    lastFailure;
    blockReasons;
    constructor(options = {}) {
        if (options === null || typeof options !== 'object')
            throw new TypeError('scheduler options must be an object');
        this.options = options;
        this.ownerId = isNonEmptyString(options.ownerId) ? options.ownerId : `scheduler-owner-${randomUUID()}`;
        this.host = isNonEmptyString(options.host) ? options.host : hostname();
        this.pid = typeof options.pid === 'number' && Number.isSafeInteger(options.pid) && options.pid > 0
            ? options.pid
            : process.pid;
        this.storePath = isNonEmptyString(options.storePath) ? options.storePath : null;
        this.reaper = typeof options.reaper === 'function' ? options.reaper : defaultProcessTreeReaper;
        this.isOwnerAlive = typeof options.isOwnerAlive === 'function' ? options.isOwnerAlive : null;
        this.clockGuard = new ClockGuard({
            clock: options.clock,
            maxSkewMs: options.maxClockSkewMs,
            maxForwardJumpMs: options.maxForwardJumpMs,
        });
        this.store = null;
        this.storeError = null;
        this.storeFault = null;
        this.capability = null;
        this.policy = null;
        this.policyDigest = null;
        this.authorization = null;
        this.authorizationDigest = null;
        this.enabledRequested = options.enabled === true;
        this.enabled = false;
        this.killSwitchState = null;
        this.persistedClockFault = null;
        this.recovery = null;
        this.owned = new Map();
        this.tracked = new Map();
        this.lastFailure = null;
        this.blockReasons = [];
        if (options.enabled === true) {
            this.enable({
                authorization: options.authorization ?? null,
                policy: options.policy ?? null,
            });
        }
    }
    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------
    /**
     * Explicitly enable the scheduler. Safe to call again to retry after a
     * transient store/clock failure; never enables anything by itself.
     */
    enable(input = {}) {
        this.enabledRequested = true;
        this.enabled = false;
        this.storeError = null;
        this.storeFault = null;
        this.lastFailure = null;
        const capability = this.options.capability !== undefined
            ? this.options.capability
            : detectSchedulerCapability();
        this.capability = capability;
        if (!capability || capability.ok !== true || !isPlainRecord(capability.provider)) {
            const reasons = Array.isArray(capability?.reason_codes) && capability.reason_codes.length > 0
                ? capability.reason_codes
                : [SCHEDULER_REASON.CAPABILITY_UNAVAILABLE, SCHEDULER_REASON.STORE_UNAVAILABLE];
            return this.#block(reasons, capability?.detail ?? 'scheduler capability probe failed');
        }
        const sample = this.clockGuard.sample();
        if (!sample.ok) {
            this.#persistClockFault(sample);
            return this.#block([SCHEDULER_REASON.CLOCK_SKEW], `clock guard tripped: ${sample.faults.join(',')}`);
        }
        if (!this.storePath) {
            return this.#block([SCHEDULER_REASON.STORE_REQUIRED], 'scheduler storePath is required to enable scheduling');
        }
        if (!this.store || this.store.closed || this.store.filePath !== this.storePath) {
            try {
                this.store = openSchedulerStore({
                    filePath: this.storePath,
                    atIso: isoFromWallMs(sample.wallMs ?? Date.now()),
                });
            }
            catch (err) {
                this.store = null;
                this.storeError = err instanceof SchedulerStoreError
                    ? err
                    : new SchedulerStoreError(SCHEDULER_REASON.STORE_UNAVAILABLE, err instanceof Error ? err.message : String(err));
                return this.#block([this.storeError.reason], this.storeError.message);
            }
        }
        try {
            const persistedFault = this.store.clockFault();
            if (persistedFault) {
                this.persistedClockFault = persistedFault;
                return this.#block([SCHEDULER_REASON.CLOCK_FAULT_PERSISTED], `persisted clock fault: ${persistedFault.faults.join(',')}`);
            }
            const maxWall = this.store.maxWallMs();
            if (maxWall > 0 && (sample.wallMs ?? 0) + this.clockGuard.maxSkewMs < maxWall) {
                this.clockGuard.faults.add(CLOCK_FAULT.ROLLBACK);
                this.#persistClockFault({ ...sample, ok: false, faults: [CLOCK_FAULT.ROLLBACK] });
                return this.#block([SCHEDULER_REASON.CLOCK_SKEW], 'wall clock is behind the persisted high-water mark');
            }
            this.store.noteWallMs(sample.wallMs ?? 0);
        }
        catch (err) {
            const failure = this.#handleStoreError(err, 'enable-clock-check');
            return this.#block(failure.reason_codes, failure.detail ?? '');
        }
        const policyInput = input.policy ?? this.options.policy ?? DEFAULT_SCHEDULER_POLICY;
        const policyResult = validateSchedulerPolicy(policyInput);
        if (!policyResult.ok) {
            return this.#block([policyResult.reason], policyResult.errors.join(','));
        }
        this.policy = policyResult.policy;
        this.policyDigest = policyResult.digest;
        this.clockGuard.maxSkewMs = policyResult.policy.max_clock_skew_ms;
        this.clockGuard.maxForwardJumpMs = policyResult.policy.max_clock_forward_jump_ms;
        const authorizationInput = input.authorization ?? this.options.authorization ?? null;
        const authorizationResult = validateSchedulerAuthorization(authorizationInput, {
            action: 'enable-scheduler',
            nowMs: sample.wallMs ?? Date.now(),
        });
        if (!authorizationResult.ok) {
            return this.#block([authorizationResult.reason], authorizationResult.errors.join(','));
        }
        this.authorization = authorizationResult.authorization;
        this.authorizationDigest = authorizationResult.digest;
        if (this.authorization.scope.periodic === true && this.policy.periodic_enabled !== true) {
            return this.#block([SCHEDULER_REASON.PERIODIC_NOT_AUTHORIZED], 'authorization requests periodic work but the frozen policy disables periodic scheduling');
        }
        if (this.policy.periodic_enabled === true && this.authorization.scope.periodic !== true) {
            return this.#block([SCHEDULER_REASON.PERIODIC_NOT_AUTHORIZED], 'policy enables periodic scheduling but the authorization scope does not');
        }
        const atIso = isoFromWallMs(sample.wallMs ?? Date.now());
        try {
            this.store.registerOwner({ ownerId: this.ownerId, host: this.host, pid: this.pid, atIso });
            const recovery = this.store.recover({
                atIso,
                atMs: sample.wallMs ?? Date.now(),
                isOwnerAlive: this.#ownerAliveFn(),
            });
            this.recovery = {
                recovered: recovery.recovered.map((item) => ({ lease_id: item.lease_id, reason: item.reason })),
                kept: recovery.kept,
            };
            this.store.noteWallMs(sample.wallMs ?? 0);
            this.store.appendAudit({
                action: 'scheduler-enabled',
                actor: { id: this.authorization.authorized_by, role: this.authorization.role },
                atIso,
                detail: {
                    policy_digest: this.policyDigest,
                    authorization_digest: this.authorizationDigest,
                    signature_present: this.authorization.signature_present,
                    signature_verified: false,
                    store_file: this.storePath,
                    recovered_leases: this.recovery.recovered.map((item) => item.lease_id),
                    kept_leases: this.recovery.kept,
                    single_host: true,
                    ha: false,
                },
            });
        }
        catch (err) {
            const failure = this.#handleStoreError(err, 'enable-recovery');
            return this.#block(failure.reason_codes, failure.detail ?? '');
        }
        this.enabled = true;
        this.enabledRequested = true;
        this.storeFault = null;
        this.blockReasons = [];
        return this.status();
    }
    /**
     * Turn the scheduler off without deleting durable state. Leases stay durable
     * until release/TTL so a restart can recover them.
     */
    disable(input = {}) {
        const actor = isActor(input.actor) ? input.actor : { id: 'operator', role: 'operator' };
        if (this.store && !this.store.closed) {
            try {
                this.store.appendAudit({
                    action: 'scheduler-disabled',
                    actor,
                    atIso: isoFromWallMs(Date.now()),
                    detail: { reason: input.reason ?? null },
                });
            }
            catch (err) {
                this.#setStoreFault(err);
            }
        }
        this.enabled = false;
        this.enabledRequested = false;
        this.blockReasons = [];
        this.owned.clear();
        this.tracked.clear();
        return this.status();
    }
    /** Close the durable store handle. Does not release leases (crash-like). */
    close() {
        if (this.store && !this.store.closed)
            this.store.close();
        this.enabled = false;
        this.owned.clear();
        this.tracked.clear();
    }
    // -------------------------------------------------------------------------
    // Status
    // -------------------------------------------------------------------------
    #ownerAliveFn() {
        if (this.isOwnerAlive)
            return this.isOwnerAlive;
        return (ownerId) => {
            try {
                const owner = this.store?.owner(ownerId);
                if (!owner)
                    return false;
                if (owner.owner_id === this.ownerId)
                    return true;
                if (owner.host !== this.host)
                    return true; // cross-host unverifiable => TTL only
                return isPidAlive(owner.pid);
            }
            catch {
                return false;
            }
        };
    }
    #setStoreFault(err) {
        const reason = err instanceof SchedulerStoreError ? err.reason : SCHEDULER_REASON.STORE_UNAVAILABLE;
        this.storeFault = { reason, message: err instanceof Error ? err.message : String(err) };
        return this.storeFault;
    }
    #handleStoreError(err, operation) {
        if (err instanceof SchedulerStoreError && err.reason === SCHEDULER_REASON.STORE_BUSY) {
            return this.#fail(SCHEDULER_REASON.STORE_BUSY, err.message, { operation });
        }
        const fault = this.#setStoreFault(err);
        return this.#fail(fault.reason, fault.message, { operation });
    }
    #refreshFacts() {
        if (!this.store || this.store.closed)
            return;
        try {
            this.killSwitchState = this.store.killSwitch();
            this.persistedClockFault = this.store.clockFault();
        }
        catch (err) {
            this.#setStoreFault(err);
        }
    }
    #evaluate(options = {}) {
        const sample = this.clockGuard.sample();
        if (!sample.ok && options.persistClockFault === true)
            this.#persistClockFault(sample);
        const reasons = [];
        if (!this.enabledRequested) {
            reasons.push(SCHEDULER_REASON.DISABLED);
        }
        else {
            if (this.storeFault)
                reasons.push(this.storeFault.reason);
            else if (!this.store || this.store.closed) {
                reasons.push(this.storeError?.reason ?? SCHEDULER_REASON.STORE_UNAVAILABLE);
            }
            if (this.persistedClockFault)
                reasons.push(SCHEDULER_REASON.CLOCK_FAULT_PERSISTED);
            if (!sample.ok)
                reasons.push(SCHEDULER_REASON.CLOCK_SKEW);
            if (this.killSwitchState?.engaged === true)
                reasons.push(SCHEDULER_REASON.KILL_SWITCH);
            if (!this.policy)
                reasons.push(SCHEDULER_REASON.POLICY_INVALID);
            if (!this.authorization)
                reasons.push(SCHEDULER_REASON.AUTHORIZATION_REQUIRED);
        }
        const codes = dedupe(reasons);
        const state = !this.enabledRequested
            ? 'disabled'
            : codes.length === 0 && this.enabled
                ? 'enabled'
                : 'blocked';
        return { sample, reason_codes: codes, state };
    }
    /** Machine-readable status snapshot. */
    status() {
        this.#refreshFacts();
        const evaluation = this.#evaluate({ persistClockFault: true });
        const reasonCodes = evaluation.state === 'blocked'
            ? dedupe([...this.blockReasons, ...evaluation.reason_codes])
            : evaluation.reason_codes;
        const provider = this.capability?.provider ?? (this.store ? schedulerStoreProvider() : null);
        let counts = null;
        if (this.store && !this.store.closed && !this.storeFault) {
            try {
                counts = this.store.counts();
            }
            catch (err) {
                this.#setStoreFault(err);
            }
        }
        const store = this.store && !this.store.closed
            ? { ...this.store.storeFacts(), path: this.storePath }
            : null;
        return {
            schema_version: SCHEDULER_STATUS_SCHEMA_VERSION,
            state: evaluation.state,
            enabled: evaluation.state === 'enabled',
            enabled_requested: this.enabledRequested,
            reason_codes: reasonCodes,
            provider,
            limitations: [...SCHEDULER_LIMITATIONS],
            single_host: true,
            ha: false,
            store,
            store_fault: this.storeFault,
            policy: this.policy
                ? {
                    policy_id: this.policy.policy_id,
                    digest: this.policyDigest,
                    periodic_enabled: this.policy.periodic_enabled,
                    max_global_concurrency: this.policy.max_global_concurrency,
                    max_target_concurrency: this.policy.max_target_concurrency,
                    max_queue_depth: this.policy.max_queue_depth,
                    default_ttl_ms: this.policy.default_ttl_ms,
                }
                : null,
            authorization: this.authorization
                ? {
                    authorization_id: this.authorization.authorization_id,
                    digest: this.authorizationDigest,
                    role: this.authorization.role,
                    authorized_by: this.authorization.authorized_by,
                    expires_at: this.authorization.expires_at,
                    signature_present: this.authorization.signature_present,
                    signature_verified: false,
                }
                : null,
            kill_switch: this.killSwitchState,
            clock: {
                ok: evaluation.sample.ok,
                faults: evaluation.sample.faults,
                samples: this.clockGuard.samples,
                wall_ms: evaluation.sample.wallMs,
                mono_ms: evaluation.sample.monoMs,
            },
            ownership: {
                owner_id: this.ownerId,
                host: this.host,
                pid: this.pid,
                tracked_process_trees: this.tracked.size,
                owned_leases: this.owned.size,
            },
            runtime: { ...SCHEDULER_RUNTIME },
            recovery: this.recovery,
            counts,
            last_failure: this.lastFailure,
        };
    }
    // -------------------------------------------------------------------------
    // Guards / helpers
    // -------------------------------------------------------------------------
    #fail(reasons, detail = null, extra = {}) {
        const codes = dedupe(Array.isArray(reasons) ? reasons : [reasons]);
        const failure = {
            ...extra,
            ok: false,
            status: 'blocked',
            reason_codes: codes,
            detail: detail ?? null,
        };
        this.lastFailure = {
            reason_codes: codes,
            detail: failure.detail,
            at: isoFromWallMs(this.clockGuard.last?.wallMs ?? Date.now()),
        };
        return failure;
    }
    #block(reasons, detail) {
        this.blockReasons = dedupe(reasons);
        this.lastFailure = { reason_codes: this.blockReasons, detail, at: isoFromWallMs(Date.now()) };
        return this.status();
    }
    #persistClockFault(sample) {
        if (!this.store || this.store.closed || !sample || sample.ok)
            return;
        const atMs = typeof sample.wallMs === 'number' && Number.isFinite(sample.wallMs) ? sample.wallMs : Date.now();
        try {
            const existing = this.store.clockFault();
            const key = [...sample.faults].sort().join(',');
            if (existing && [...existing.faults].sort().join(',') === key) {
                this.persistedClockFault = existing;
                return;
            }
            this.store.setClockFault({
                faults: sample.faults,
                atIso: isoFromWallMs(atMs),
                wallMs: atMs,
                detail: 'clock guard tripped',
            });
            this.persistedClockFault = this.store.clockFault();
        }
        catch (err) {
            this.#setStoreFault(err);
        }
    }
    #ready(options = {}) {
        const requireEnabled = options.requireEnabled !== false;
        const requireClock = options.requireClock !== false;
        if (requireEnabled && !this.enabledRequested) {
            return { ok: false, failure: this.#fail(SCHEDULER_REASON.DISABLED, 'scheduling is disabled by default') };
        }
        const sample = this.clockGuard.sample();
        if (requireClock && !sample.ok) {
            this.#persistClockFault(sample);
            return {
                ok: false,
                failure: this.#fail(SCHEDULER_REASON.CLOCK_SKEW, `clock guard tripped: ${sample.faults.join(',')}`),
            };
        }
        this.#refreshFacts();
        if (this.storeFault) {
            return { ok: false, failure: this.#fail(this.storeFault.reason, this.storeFault.message) };
        }
        if (!this.store || this.store.closed) {
            return {
                ok: false,
                failure: this.#fail(this.storeError?.reason ?? SCHEDULER_REASON.STORE_UNAVAILABLE, this.storeError?.message ?? 'scheduler durable store is not open'),
            };
        }
        if (this.persistedClockFault) {
            return {
                ok: false,
                failure: this.#fail(SCHEDULER_REASON.CLOCK_FAULT_PERSISTED, `persisted clock fault: ${this.persistedClockFault.faults.join(',')}`),
            };
        }
        if (this.killSwitchState?.engaged === true) {
            return { ok: false, failure: this.#fail(SCHEDULER_REASON.KILL_SWITCH, 'global scheduler kill switch is engaged') };
        }
        if (requireEnabled) {
            if (!this.authorization) {
                return { ok: false, failure: this.#fail(SCHEDULER_REASON.AUTHORIZATION_REQUIRED, 'explicit scheduler authorization is required') };
            }
            if (!this.policy) {
                return { ok: false, failure: this.#fail(SCHEDULER_REASON.POLICY_INVALID, 'frozen scheduler policy is required') };
            }
        }
        return { ok: true, sample };
    }
    /** Store-only readiness (cancel/reap must work even when scheduling is off). */
    #storeReady() {
        this.#refreshFacts();
        if (this.storeFault) {
            return { ok: false, failure: this.#fail(this.storeFault.reason, this.storeFault.message) };
        }
        if (!this.store || this.store.closed) {
            return {
                ok: false,
                failure: this.#fail(this.storeError?.reason ?? SCHEDULER_REASON.STORE_UNAVAILABLE, this.storeError?.message ?? 'scheduler durable store is not open'),
            };
        }
        return { ok: true, sample: this.clockGuard.sample() };
    }
    #wrap(op, fn) {
        try {
            return fn();
        }
        catch (err) {
            return this.#handleStoreError(err, op);
        }
    }
    #loadSchedule(scheduleId) {
        if (!isNonEmptyString(scheduleId)) {
            return { ok: false, failure: this.#fail(SCHEDULER_REASON.INVALID_INPUT, 'schedule_id is required') };
        }
        const store = this.store;
        if (!store)
            return { ok: false, failure: this.#fail(SCHEDULER_REASON.STORE_UNAVAILABLE) };
        const row = store.getSchedule(scheduleId);
        if (!row)
            return { ok: false, failure: this.#fail(SCHEDULER_REASON.SCHEDULE_NOT_FOUND) };
        const verified = verifyFrozenSchedule(row.config);
        if (!verified.ok) {
            return {
                ok: false,
                failure: this.#fail(SCHEDULER_REASON.SCHEDULE_INVALID, verified.errors.join(','), {
                    stored_schedule_id: scheduleId,
                }),
            };
        }
        if (verified.digest !== row.content_digest ||
            row.config.plan_digest !== row.plan_digest ||
            row.config.target_digest !== row.target_digest ||
            row.config.policy_digest !== row.policy_digest) {
            return {
                ok: false,
                failure: this.#fail(SCHEDULER_REASON.SCHEDULE_INVALID, 'stored schedule digests do not match its frozen content'),
            };
        }
        return { ok: true, row, config: row.config, digest: verified.digest };
    }
    #authorizeAction(action, authorization, nowMs, expectedScope) {
        if (authorization === undefined || authorization === null) {
            return {
                ok: false,
                failure: this.#fail(SCHEDULER_REASON.AUTHORIZATION_REQUIRED, `explicit authorization is required for ${action}`),
            };
        }
        const checked = validateSchedulerAuthorization(authorization, { action, nowMs, expectedScope });
        if (!checked.ok) {
            return { ok: false, failure: this.#fail(checked.reason, checked.errors.join(','), { action }) };
        }
        if (checked.authorization.action !== action) {
            return { ok: false, failure: this.#fail(SCHEDULER_REASON.AUTHORIZATION_INVALID, 'authorization action mismatch') };
        }
        return { ok: true, authorization: checked.authorization, digest: checked.digest };
    }
    #scopeForConfig(config) {
        const scope = normalizeScope({
            profile: config.profile,
            target_digest: config.target_digest,
            tenant: 'local',
            max_concurrency: 1,
        });
        if (!scope.ok) {
            return { ok: false, failure: this.#fail(SCHEDULER_REASON.INVALID_INPUT, scope.errors.join(',')) };
        }
        return { ok: true, scope: scope.scope, scopeKey: scope.scopeKey };
    }
    #audit(action, actor, detail = null) {
        if (!this.store || this.store.closed)
            return;
        try {
            this.store.appendAudit({
                action,
                actor: isActor(actor) ? actor : { id: 'scheduler', role: 'scheduler' },
                atIso: isoFromWallMs(Date.now()),
                detail,
            });
        }
        catch (err) {
            this.#setStoreFault(err);
        }
    }
    // -------------------------------------------------------------------------
    // Schedule governance
    // -------------------------------------------------------------------------
    /** Register a frozen, versioned schedule bound to a frozen Plan. */
    registerSchedule(input = {}) {
        const ready = this.#ready();
        if (!ready.ok)
            return ready.failure;
        const nowMs = ready.sample.wallMs ?? Date.now();
        const config = isPlainRecord(input.config) ? input.config : {};
        const expectedPlanDigest = typeof config.plan_id === 'string' && /^plan-sha256:[0-9a-f]{64}$/.test(config.plan_id)
            ? planDigestFromPlanId(config.plan_id)
            : undefined;
        const expectedScope = {
            schedule_id: config.schedule_id,
            target_digest: config.target_digest,
            requireScheduleIdentity: true,
        };
        if (expectedPlanDigest !== undefined)
            expectedScope.plan_digest = expectedPlanDigest;
        const auth = this.#authorizeAction('create-schedule', input.authorization, nowMs, expectedScope);
        if (!auth.ok)
            return auth.failure;
        const frozen = createFrozenSchedule(input.config, {
            frozenPlan: input.frozenPlan,
            policy: this.policy,
            policyDigest: this.policyDigest,
            authorization: auth.authorization,
            authorizationDigest: auth.digest,
            nowMs,
            expectedScope: {
                schedule_id: config.schedule_id,
                target_digest: config.target_digest,
                plan_digest: expectedPlanDigest,
            },
        });
        if (!frozen.ok)
            return this.#fail(frozen.reason, frozen.errors.join(','), { errors: frozen.errors });
        const stored = this.#wrap('register-schedule', () => this.store.registerSchedule({
            scheduleId: frozen.schedule.schedule_id,
            version: frozen.schedule.version,
            contentDigest: frozen.digest,
            planDigest: frozen.schedule.plan_digest,
            targetDigest: frozen.schedule.target_digest,
            policyDigest: frozen.schedule.policy_digest,
            config: frozen.schedule,
            atIso: isoFromWallMs(nowMs),
        }));
        if (isSchedulerFailure(stored))
            return stored;
        if (stored.ok !== true) {
            return this.#fail(stored.reason, stored.detail ?? null);
        }
        this.#audit('schedule-create', {
            id: auth.authorization.authorized_by,
            role: auth.authorization.role,
        }, {
            schedule_id: frozen.schedule.schedule_id,
            content_digest: frozen.digest,
            plan_digest: frozen.schedule.plan_digest,
            policy_digest: frozen.schedule.policy_digest,
            periodic: frozen.schedule.periodic.enabled,
            idempotent: stored.idempotent === true,
        });
        return { ok: true, schedule: frozen.schedule, digest: frozen.digest, idempotent: stored.idempotent === true };
    }
    /** Pause a registered schedule (durable state change + audit). */
    pauseSchedule(input = {}) {
        const ready = this.#ready();
        if (!ready.ok)
            return ready.failure;
        const nowMs = ready.sample.wallMs ?? Date.now();
        const current = this.#loadSchedule(input.scheduleId);
        if (!current.ok)
            return current.failure;
        const auth = this.#authorizeAction('pause-schedule', input.authorization, nowMs, {
            schedule_id: input.scheduleId,
            schedule_version: input.version,
            requireScheduleIdentity: true,
        });
        if (!auth.ok)
            return auth.failure;
        const store = this.store;
        const stored = this.#wrap('pause-schedule', () => store.setScheduleState({
            scheduleId: input.scheduleId,
            state: 'paused',
            atIso: isoFromWallMs(nowMs),
        }));
        if (isSchedulerFailure(stored))
            return stored;
        if (stored.ok !== true)
            return this.#fail(stored.reason, stored.detail ?? null);
        this.#audit('schedule-pause', { id: auth.authorization.authorized_by, role: auth.authorization.role }, {
            schedule_id: input.scheduleId,
            version: current.row.version,
            authorization_digest: auth.digest,
        });
        return { ok: true, schedule_id: input.scheduleId, state: 'paused' };
    }
    /** Bounded FIFO/priority enqueue with idempotency-key dedupe and queue cap. */
    enqueue(input = {}) {
        const ready = this.#ready();
        if (!ready.ok)
            return ready.failure;
        const nowMs = ready.sample.wallMs ?? Date.now();
        const loaded = this.#loadSchedule(input.scheduleId);
        if (!loaded.ok)
            return loaded.failure;
        const config = loaded.config;
        if (loaded.row.state !== 'active' || config.enabled !== true) {
            return this.#fail(SCHEDULER_REASON.SCHEDULE_PAUSED, 'schedule is not active/enabled');
        }
        if (!isNonEmptyString(input.runId))
            return this.#fail(SCHEDULER_REASON.INVALID_INPUT, 'run_id is required');
        if (!isNonEmptyString(input.idempotencyKey)) {
            return this.#fail(SCHEDULER_REASON.INVALID_INPUT, 'idempotency_key is required');
        }
        const scope = this.#scopeForConfig(config);
        if (!scope.ok)
            return scope.failure;
        const store = this.store;
        const stored = this.#wrap('enqueue', () => store.enqueue({
            schedule: {
                scheduleId: config.schedule_id,
                planDigest: config.plan_digest,
                targetDigest: config.target_digest,
                policyDigest: config.policy_digest,
            },
            scopeKey: scope.scopeKey,
            runId: input.runId,
            idempotencyKey: input.idempotencyKey,
            priority: input.priority,
            atIso: isoFromWallMs(nowMs),
            maxQueueDepth: this.policy.max_queue_depth,
        }));
        if (isSchedulerFailure(stored))
            return stored;
        if (stored.ok !== true) {
            return this.#fail(stored.reason, stored.detail ?? null, {
                duplicate: stored.duplicate === true,
                queue_id: stored.queue_id ?? null,
            });
        }
        return {
            ok: true,
            queue_id: stored.queue_id,
            run_id: input.runId,
            idempotency_key: input.idempotencyKey,
        };
    }
    // -------------------------------------------------------------------------
    // Lease lifecycle
    // -------------------------------------------------------------------------
    /** Transactionally acquire the single active lease for a schedule's scope. */
    acquire(input = {}) {
        const ready = this.#ready();
        if (!ready.ok)
            return ready.failure;
        const nowMs = ready.sample.wallMs ?? Date.now();
        const loaded = this.#loadSchedule(input.scheduleId);
        if (!loaded.ok)
            return loaded.failure;
        const config = loaded.config;
        if (loaded.row.state !== 'active' || config.enabled !== true) {
            return this.#fail(SCHEDULER_REASON.SCHEDULE_PAUSED, 'schedule is not active/enabled');
        }
        const policy = this.policy;
        const ttlMs = input.ttlMs ?? policy.default_ttl_ms;
        if (typeof ttlMs !== 'number' || !Number.isSafeInteger(ttlMs) ||
            ttlMs < policy.min_ttl_ms || ttlMs > policy.max_ttl_ms) {
            return this.#fail(SCHEDULER_REASON.INVALID_INPUT, `ttl_ms must be an integer within [${policy.min_ttl_ms}, ${policy.max_ttl_ms}]`);
        }
        const ownerId = isNonEmptyString(input.ownerId) ? input.ownerId : this.ownerId;
        const scope = this.#scopeForConfig(config);
        if (!scope.ok)
            return scope.failure;
        const atIso = isoFromWallMs(nowMs);
        const store = this.store;
        const stored = this.#wrap('acquire', () => store.acquire({
            schedule: {
                scheduleId: config.schedule_id,
                planDigest: config.plan_digest,
                targetDigest: config.target_digest,
                policyDigest: config.policy_digest,
            },
            scope: scope.scope,
            scopeKey: scope.scopeKey,
            ownerId,
            runId: input.runId,
            idempotencyKey: input.idempotencyKey,
            ttlMs,
            atIso,
            atMs: nowMs,
            maxGlobalConcurrency: policy.max_global_concurrency,
            maxTargetConcurrency: policy.max_target_concurrency,
            actor: { id: ownerId, role: 'scheduler' },
        }));
        if (isSchedulerFailure(stored))
            return stored;
        if (stored.ok !== true) {
            return this.#fail(stored.reason, stored.detail ?? null, {
                owner_id: stored.owner_id ?? null,
                lease_id: stored.lease_id ?? null,
                current_fencing_token: stored.current_fencing_token ?? null,
            });
        }
        this.owned.set(stored.lease.lease_id, {
            fence: stored.lease.fencing_token,
            monoDeadlineMs: (ready.sample.monoMs ?? 0) + ttlMs,
            expiresAtMs: stored.expires_at_ms,
            runId: stored.lease.run_id,
            scheduleId: stored.lease.schedule_id,
            binding: stored.binding,
        });
        this.#wrap('note-wall', () => store.noteWallMs(nowMs));
        return {
            ok: true,
            lease: stored.lease,
            binding: stored.binding,
            fencing_token: stored.lease.fencing_token,
            expires_at_ms: stored.expires_at_ms,
            owner_id: ownerId,
        };
    }
    /**
     * Explicit heartbeat/renew. A lease whose process-local monotonic deadline
     * passed is expired immediately and the owner is told the heartbeat was lost.
     */
    heartbeat(input = {}) {
        const ready = this.#ready();
        if (!ready.ok)
            return ready.failure;
        const nowMs = ready.sample.wallMs ?? Date.now();
        const monoMs = ready.sample.monoMs ?? 0;
        const ownerId = isNonEmptyString(input.ownerId) ? input.ownerId : this.ownerId;
        const policy = this.policy;
        const ttlMs = input.ttlMs ?? policy.default_ttl_ms;
        if (typeof ttlMs !== 'number' || !Number.isSafeInteger(ttlMs) ||
            ttlMs < policy.min_ttl_ms || ttlMs > policy.max_ttl_ms) {
            return this.#fail(SCHEDULER_REASON.INVALID_INPUT, 'ttl_ms outside the frozen policy bounds');
        }
        const leaseId = input.leaseId;
        const owned = this.owned.get(leaseId);
        if (owned && Number.isFinite(owned.monoDeadlineMs) && monoMs > owned.monoDeadlineMs) {
            const store = this.store;
            const expired = this.#wrap('heartbeat-lost', () => store.expireLease({
                leaseId,
                actor: { id: 'scheduler', role: 'scheduler' },
                atIso: isoFromWallMs(nowMs),
                atMs: nowMs,
                reason: 'heartbeat-lost',
            }));
            this.owned.delete(leaseId);
            return this.#fail(SCHEDULER_REASON.LEASE_HEARTBEAT_LOST, 'monotonic heartbeat deadline exceeded', {
                expired: !isSchedulerFailure(expired) && !isStoreFailure(expired) && expired.ok === true,
            });
        }
        if (owned && input.fencingToken !== owned.fence) {
            return this.#fail(SCHEDULER_REASON.FENCING_TOKEN_STALE, 'heartbeat fencing token is not the current lease token', {
                current_fencing_token: owned.fence,
            });
        }
        const store = this.store;
        const stored = this.#wrap('renew', () => store.renew({
            leaseId,
            fencingToken: input.fencingToken,
            ownerId,
            ttlMs,
            atIso: isoFromWallMs(nowMs),
            atMs: nowMs,
            actor: { id: ownerId, role: 'scheduler' },
        }));
        if (isSchedulerFailure(stored))
            return stored;
        if (stored.ok !== true) {
            if (stored.reason === SCHEDULER_REASON.LEASE_HEARTBEAT_LOST ||
                stored.reason === SCHEDULER_REASON.LEASE_EXPIRED) {
                this.owned.delete(leaseId);
            }
            return this.#fail(stored.reason, stored.detail ?? null, {
                current_fencing_token: stored.current_fencing_token ?? null,
            });
        }
        this.owned.set(leaseId, {
            ...(owned ?? {
                fence: stored.lease.fencing_token,
                monoDeadlineMs: monoMs + ttlMs,
                expiresAtMs: stored.expires_at_ms,
                runId: stored.lease.run_id,
                scheduleId: stored.lease.schedule_id,
                binding: stored.binding,
            }),
            fence: stored.lease.fencing_token,
            monoDeadlineMs: monoMs + ttlMs,
            expiresAtMs: stored.expires_at_ms,
            runId: stored.lease.run_id,
            scheduleId: stored.lease.schedule_id,
            binding: stored.binding,
        });
        this.#wrap('note-wall', () => store.noteWallMs(nowMs));
        return {
            ok: true,
            lease: stored.lease,
            binding: stored.binding,
            fencing_token: stored.lease.fencing_token,
            expires_at_ms: stored.expires_at_ms,
        };
    }
    release(input = {}) {
        const ready = this.#ready();
        if (!ready.ok)
            return ready.failure;
        const nowMs = ready.sample.wallMs ?? Date.now();
        const ownerId = isNonEmptyString(input.ownerId) ? input.ownerId : this.ownerId;
        const store = this.store;
        const stored = this.#wrap('release', () => store.release({
            leaseId: input.leaseId,
            fencingToken: input.fencingToken,
            ownerId,
            atIso: isoFromWallMs(nowMs),
            outcome: input.outcome ?? 'completed',
            actor: { id: ownerId, role: 'scheduler' },
        }));
        if (isSchedulerFailure(stored))
            return stored;
        if (stored.ok !== true) {
            return this.#fail(stored.reason, stored.detail ?? null, { lease_state: stored.lease_state ?? null });
        }
        this.owned.delete(input.leaseId);
        return {
            ok: true,
            lease: stored.lease,
            idempotent: stored.idempotent === true,
            fencing_token: stored.lease.fencing_token,
        };
    }
    /**
     * Register the OS process tree that belongs to a lease so cancel can confirm
     * complete reclamation through the reaper.
     */
    trackProcessTree(input = {}) {
        const ready = this.#ready({ requireClock: false });
        if (!ready.ok)
            return ready.failure;
        const ownerId = isNonEmptyString(input.ownerId) ? input.ownerId : this.ownerId;
        if (typeof input.rootPid !== 'number' || !Number.isSafeInteger(input.rootPid) || input.rootPid < 1) {
            return this.#fail(SCHEDULER_REASON.INVALID_INPUT, 'root_pid must be a positive integer');
        }
        if (input.rootPid === process.pid) {
            return this.#fail(SCHEDULER_REASON.INVALID_INPUT, 'refusing to register the scheduler process itself for reaping');
        }
        const knownChildPids = Array.isArray(input.knownChildPids)
            ? input.knownChildPids.filter((pid) => Number.isSafeInteger(pid) && pid > 0)
            : [];
        const store = this.store;
        const record = this.#wrap('track-tree', () => store.getLease(input.leaseId));
        if (isSchedulerFailure(record))
            return record;
        if (!record)
            return this.#fail(SCHEDULER_REASON.LEASE_NOT_FOUND);
        if (record.lease.fencing_token !== input.fencingToken) {
            return this.#fail(SCHEDULER_REASON.FENCING_TOKEN_STALE, 'process tree fencing token is stale', {
                current_fencing_token: record.lease.fencing_token,
            });
        }
        if (record.lease.owner_id !== ownerId) {
            return this.#fail(SCHEDULER_REASON.LEASE_OWNER_MISMATCH, 'process tree owner mismatch');
        }
        if (record.lease.state !== 'active') {
            return this.#fail(SCHEDULER_REASON.LEASE_NOT_ACTIVE, `lease state is ${record.lease.state}`);
        }
        this.tracked.set(input.leaseId, { rootPid: input.rootPid, knownChildPids, ownerId });
        return { ok: true, lease_id: input.leaseId, root_pid: input.rootPid, known_child_pids: knownChildPids };
    }
    /**
     * Durable cancel + complete process-tree reclamation confirmation.
     */
    async cancel(input = {}) {
        const ready = this.#storeReady();
        if (!ready.ok)
            return ready.failure;
        const actor = isActor(input.actor) ? input.actor : { id: 'operator', role: 'operator' };
        const nowMs = typeof ready.sample.wallMs === 'number' && Number.isFinite(ready.sample.wallMs)
            ? ready.sample.wallMs
            : Date.now();
        const store = this.store;
        const leaseId = input.leaseId;
        const requested = this.#wrap('request-cancel', () => store.requestCancel({
            leaseId,
            actor,
            atIso: isoFromWallMs(nowMs),
            reason: input.reason ?? null,
        }));
        if (isSchedulerFailure(requested))
            return requested;
        if (requested.ok !== true)
            return this.#fail(requested.reason, requested.detail ?? null);
        if (requested.lease.state === 'cancelled') {
            this.owned.delete(leaseId);
            this.tracked.delete(leaseId);
            return { ok: true, idempotent: true, lease: requested.lease, cancel_acknowledged: true };
        }
        if (requested.lease.state !== 'active') {
            return { ok: true, idempotent: true, lease: requested.lease, cancel_acknowledged: false };
        }
        const tree = this.tracked.get(leaseId);
        if (!tree) {
            this.#wrap('reap-failure', () => store.recordReapFailure({
                leaseId,
                actor,
                atIso: isoFromWallMs(nowMs),
                remaining: [],
                mechanism: 'unavailable',
                error: 'no tracked process tree',
            }));
            return this.#fail([SCHEDULER_REASON.CANCEL_NOT_ACKNOWLEDGED, SCHEDULER_REASON.REAP_INCOMPLETE], 'cancel is durable but no tracked process tree is available to confirm reclamation', { remaining: [], cancel_acknowledged: false, cancel_requested: true });
        }
        const reaper = typeof input.reaper === 'function' ? input.reaper : this.reaper;
        let report;
        try {
            report = await reaper(tree.rootPid, {
                knownChildPids: tree.knownChildPids,
                timeoutMs: typeof input.timeoutMs === 'number' && Number.isSafeInteger(input.timeoutMs)
                    ? input.timeoutMs
                    : undefined,
            });
        }
        catch (err) {
            report = { ok: false, remaining: [], mechanism: 'error', error: err instanceof Error ? err.message : String(err) };
        }
        if (!report || report.ok !== true) {
            this.#wrap('reap-failure', () => store.recordReapFailure({
                leaseId,
                actor,
                atIso: isoFromWallMs(nowMs),
                remaining: Array.isArray(report?.remaining) ? report.remaining : [],
                mechanism: report?.mechanism ?? null,
                error: report?.error ?? 'process tree still alive',
            }));
            return this.#fail([SCHEDULER_REASON.CANCEL_NOT_ACKNOWLEDGED, SCHEDULER_REASON.REAP_INCOMPLETE], 'process tree reclamation is not confirmed; cancel not acknowledged', {
                remaining: Array.isArray(report?.remaining) ? report.remaining : [],
                cancel_acknowledged: false,
                cancel_requested: true,
            });
        }
        const acknowledged = this.#wrap('reap-ack', () => store.acknowledgeCancel({
            leaseId,
            actor,
            atIso: isoFromWallMs(nowMs),
            mechanism: report.mechanism ?? null,
        }));
        if (isSchedulerFailure(acknowledged))
            return acknowledged;
        if (acknowledged.ok !== true)
            return this.#fail(acknowledged.reason, acknowledged.detail ?? null);
        this.owned.delete(leaseId);
        this.tracked.delete(leaseId);
        return {
            ok: true,
            lease: acknowledged.lease,
            cancel_acknowledged: true,
            reaped: true,
            remaining: [],
            mechanism: report.mechanism ?? null,
        };
    }
    /** Retry reaping an already-cancelling lease. */
    async reap(input = {}) {
        return this.cancel(input);
    }
    async cancelAll(input = {}) {
        const ready = this.#storeReady();
        if (!ready.ok)
            return ready.failure;
        const store = this.store;
        let active;
        try {
            active = store.listActiveLeases();
        }
        catch (err) {
            return this.#handleStoreError(err, 'cancel-all');
        }
        const results = [];
        for (const record of active) {
            const result = await this.cancel({
                leaseId: record.lease.lease_id,
                actor: input.actor,
                reason: input.reason,
                timeoutMs: input.timeoutMs,
            });
            results.push({ lease_id: record.lease.lease_id, result });
        }
        return {
            ok: results.every((entry) => entry.result.ok === true),
            cancelled: results.filter((entry) => entry.result.ok === true).length,
            attempted: results.length,
            results,
        };
    }
    /**
     * Submit a run result. It must carry the current fencing token; results are
     * converted to observation-only monitoring records and stale tokens are
     * rejected by both the manager and the store.
     */
    submitResult(input = {}) {
        const ready = this.#ready();
        if (!ready.ok)
            return ready.failure;
        const nowMs = ready.sample.wallMs ?? Date.now();
        const monoMs = ready.sample.monoMs ?? 0;
        const ownerId = isNonEmptyString(input.ownerId) ? input.ownerId : this.ownerId;
        const store = this.store;
        const record = this.#wrap('result-lease', () => store.getLease(input.leaseId));
        if (isSchedulerFailure(record))
            return record;
        if (!record)
            return this.#fail(SCHEDULER_REASON.LEASE_NOT_FOUND);
        if (!isNonEmptyString(input.runId) || record.lease.run_id !== input.runId) {
            return this.#fail(SCHEDULER_REASON.RESULT_REJECTED, 'run_id does not match the lease');
        }
        if (record.lease.fencing_token !== input.fencingToken) {
            return this.#fail(SCHEDULER_REASON.FENCING_TOKEN_STALE, 'old fencing token result write rejected', {
                current_fencing_token: record.lease.fencing_token,
            });
        }
        const leaseId = input.leaseId;
        const owned = this.owned.get(leaseId);
        if (owned && Number.isFinite(owned.monoDeadlineMs) && monoMs > owned.monoDeadlineMs) {
            this.#wrap('result-heartbeat-lost', () => store.expireLease({
                leaseId,
                actor: { id: 'scheduler', role: 'scheduler' },
                atIso: isoFromWallMs(nowMs),
                atMs: nowMs,
                reason: 'heartbeat-lost-before-result',
            }));
            this.owned.delete(leaseId);
            return this.#fail(SCHEDULER_REASON.LEASE_HEARTBEAT_LOST, 'lease heartbeat was lost before result submission');
        }
        const observation = buildMonitoringObservation(input.result, {
            scheduleId: record.lease.schedule_id,
            runId: input.runId,
            leaseId,
            fencingToken: input.fencingToken,
            atIso: isoFromWallMs(nowMs),
            binding: record.binding,
        });
        if (!observation.ok) {
            return this.#fail(observation.reason, observation.errors.join(','), {
                errors: observation.errors,
                authority_fields_rejected: observation.reason === SCHEDULER_REASON.AUTHORITY_FIELD_REJECTED,
            });
        }
        const stored = this.#wrap('submit-result', () => store.submitResult({
            leaseId,
            fencingToken: input.fencingToken,
            runId: input.runId,
            observation: observation.observation,
            resultDigest: observation.digest,
            atIso: isoFromWallMs(nowMs),
            atMs: nowMs,
            actor: { id: ownerId, role: 'scheduler' },
        }));
        if (isSchedulerFailure(stored))
            return stored;
        if (stored.ok !== true) {
            return this.#fail(stored.reason, stored.detail ?? null, {
                current_fencing_token: stored.current_fencing_token ?? null,
                lease_state: stored.lease_state ?? null,
            });
        }
        return {
            ok: true,
            result_id: stored.result_id,
            result_digest: stored.result_digest,
            observation: stored.observation,
            idempotent: stored.idempotent === true,
        };
    }
    // -------------------------------------------------------------------------
    // Maintenance / recovery / kill switch
    // -------------------------------------------------------------------------
    /** Expire TTL-lapsed leases (bounded, explicit — no background loop). */
    maintenance() {
        const ready = this.#ready();
        if (!ready.ok)
            return ready.failure;
        const nowMs = ready.sample.wallMs ?? Date.now();
        const store = this.store;
        const stored = this.#wrap('maintenance', () => store.expireStale({
            atIso: isoFromWallMs(nowMs),
            atMs: nowMs,
        }));
        if (isSchedulerFailure(stored))
            return stored;
        for (const leaseId of [...this.owned.keys()]) {
            const record = this.#wrap('maintenance-owned', () => store.getLease(leaseId));
            if (isSchedulerFailure(record) || !record || record.lease.state !== 'active')
                this.owned.delete(leaseId);
        }
        this.#wrap('note-wall', () => store.noteWallMs(nowMs));
        return {
            ok: true,
            expired: stored.expired.map((item) => ({ lease_id: item.lease_id, fencing_token: item.fencing_token })),
            checked_at: isoFromWallMs(nowMs),
        };
    }
    /**
     * Deterministic, explicit scheduler tick: bounded TTL maintenance only.
     * There is no cron loop and no background timer; a caller (or a governed
     * external runner) must invoke this explicitly. Keeping it deterministic makes
     * crash/clock tests reproducible.
     */
    tick() {
        const result = this.maintenance();
        if (result.ok !== true)
            return result;
        return {
            ...result,
            deterministic: true,
            cron_enabled: SCHEDULER_RUNTIME.cron_enabled,
            background: SCHEDULER_RUNTIME.background_loops,
        };
    }
    /**
     * Explicit crash recovery: expire active leases whose TTL lapsed or whose
     * owning local process is dead, then append a `store-recover` event.
     */
    recover() {
        const ready = this.#storeReady();
        if (!ready.ok)
            return ready.failure;
        const nowMs = typeof ready.sample.wallMs === 'number' && Number.isFinite(ready.sample.wallMs)
            ? ready.sample.wallMs
            : Date.now();
        const store = this.store;
        const stored = this.#wrap('recover', () => store.recover({
            atIso: isoFromWallMs(nowMs),
            atMs: nowMs,
            isOwnerAlive: this.#ownerAliveFn(),
        }));
        if (isSchedulerFailure(stored))
            return stored;
        this.recovery = {
            recovered: stored.recovered.map((item) => ({ lease_id: item.lease_id, reason: item.reason })),
            kept: stored.kept,
        };
        this.#audit('store-recover', { id: 'system', role: 'system' }, {
            recovered: this.recovery.recovered.map((item) => item.lease_id),
            kept: stored.kept,
        });
        return { ok: true, recovered: this.recovery.recovered, kept: stored.kept };
    }
    /** Clear a persisted/in-memory clock fault after an explicit operator check. */
    recoverClockFault(input = {}) {
        const ready = this.#storeReady();
        if (!ready.ok)
            return ready.failure;
        const actor = isActor(input.actor) ? input.actor : null;
        if (!actor || !CLOCK_RECOVERY_ROLES.has(actor.role)) {
            return this.#fail(SCHEDULER_REASON.AUTHORIZATION_REQUIRED, 'clock-fault recovery requires an operator/security actor');
        }
        if (typeof input.reason !== 'string' || input.reason.trim().length === 0) {
            return this.#fail(SCHEDULER_REASON.AUTHORIZATION_REQUIRED, 'clock-fault recovery requires a reason');
        }
        if (input.authorization !== undefined && input.authorization !== null) {
            const checked = validateSchedulerAuthorization(input.authorization, {
                action: 'reset-clock-fault',
                nowMs: typeof ready.sample.wallMs === 'number' ? ready.sample.wallMs : Date.now(),
            });
            if (!checked.ok)
                return this.#fail(checked.reason, checked.errors.join(','));
        }
        // Persisted high-water mark survives restart: the guard's in-memory baseline
        // may have been re-based on the rolled-back value, so always compare against
        // the durable maximum wall time the store has observed.
        const storeHighWater = this.store.maxWallMs();
        const currentSample = this.clockGuard.sample();
        if (storeHighWater > 0 && (currentSample.wallMs ?? 0) + this.clockGuard.maxSkewMs < storeHighWater) {
            return this.#fail(SCHEDULER_REASON.CLOCK_SKEW, 'wall clock is still behind the persisted high-water mark');
        }
        const reset = this.clockGuard.reset({ reason: input.reason });
        if (!reset.ok) {
            return this.#fail(SCHEDULER_REASON.CLOCK_SKEW, `clock still abnormal; refusing recovery (${reset.faults.join(',')})`);
        }
        const nowMs = reset.wallMs ?? Date.now();
        const store = this.store;
        const stored = this.#wrap('clock-recovery', () => {
            store.clearClockFault({ actor, atIso: isoFromWallMs(nowMs), reason: input.reason });
            store.noteWallMs(nowMs);
            return { ok: true };
        });
        if (isSchedulerFailure(stored))
            return stored;
        this.persistedClockFault = null;
        this.lastFailure = null;
        return this.status();
    }
    /** Engage the durable global kill switch. */
    engageKillSwitch(input = {}) {
        const ready = this.#storeReady();
        if (!ready.ok)
            return ready.failure;
        const actor = isActor(input.actor) ? input.actor : null;
        if (!actor)
            return this.#fail(SCHEDULER_REASON.AUTHORIZATION_REQUIRED, 'kill switch requires an identified actor');
        if (typeof input.reason !== 'string' || input.reason.trim().length === 0) {
            return this.#fail(SCHEDULER_REASON.INVALID_INPUT, 'kill switch requires a reason');
        }
        const nowMs = typeof ready.sample.wallMs === 'number' ? ready.sample.wallMs : Date.now();
        const store = this.store;
        const stored = this.#wrap('kill-switch', () => store.engageKillSwitch({
            actor,
            atIso: isoFromWallMs(nowMs),
            reason: input.reason,
        }));
        if (isSchedulerFailure(stored))
            return stored;
        if (stored.ok !== true)
            return this.#fail(stored.reason ?? SCHEDULER_REASON.STORE_UNAVAILABLE);
        this.killSwitchState = stored.kill_switch;
        return this.status();
    }
    /** Release the kill switch; requires explicit operator authorization. */
    releaseKillSwitch(input = {}) {
        const ready = this.#storeReady();
        if (!ready.ok)
            return ready.failure;
        const actor = isActor(input.actor) ? input.actor : null;
        if (!actor)
            return this.#fail(SCHEDULER_REASON.AUTHORIZATION_REQUIRED, 'kill switch release requires an identified actor');
        const nowMs = typeof ready.sample.wallMs === 'number' ? ready.sample.wallMs : Date.now();
        const auth = this.#authorizeAction('release-kill-switch', input.authorization, nowMs, {});
        if (!auth.ok)
            return auth.failure;
        const store = this.store;
        const stored = this.#wrap('kill-switch-release', () => store.releaseKillSwitch({
            actor,
            atIso: isoFromWallMs(nowMs),
            reason: typeof input.reason === 'string' ? input.reason : 'operator release',
            authorizationDigest: auth.digest,
        }));
        if (isSchedulerFailure(stored))
            return stored;
        if (stored.ok !== true)
            return this.#fail(stored.reason ?? SCHEDULER_REASON.STORE_UNAVAILABLE);
        this.killSwitchState = stored.kill_switch;
        return this.status();
    }
    // -------------------------------------------------------------------------
    // Read-only diagnostics
    // -------------------------------------------------------------------------
    timeline(filters = {}) {
        const ready = this.#storeReady();
        if (!ready.ok)
            return ready.failure;
        const store = this.store;
        let events;
        let chain;
        try {
            events = store.readEvents({ limit: filters.limit });
            chain = store.verifyEvents();
        }
        catch (err) {
            return this.#handleStoreError(err, 'timeline');
        }
        if (!chain.ok) {
            return this.#fail(SCHEDULER_REASON.STORE_CORRUPT, `event chain invalid: ${chain.errors.join(',')}`, { chain });
        }
        const timeline = filters.leaseId ? events.filter((event) => event.lease_id === filters.leaseId) : events;
        return { ok: true, events: timeline, event_count: events.length, chain };
    }
    /** Verify store integrity (quick_check, event hash chain, counts). */
    verify() {
        const ready = this.#storeReady();
        if (!ready.ok)
            return ready.failure;
        const store = this.store;
        try {
            const integrity = store.verifyIntegrity();
            if (!integrity.ok) {
                return this.#fail(SCHEDULER_REASON.STORE_CORRUPT, integrity.errors.join(','), { integrity });
            }
            return { ok: true, integrity, facts: store.storeFacts() };
        }
        catch (err) {
            return this.#handleStoreError(err, 'verify');
        }
    }
    /** Read governance audit entries (append-only hash chain). */
    auditLog({ limit = 10_000 } = {}) {
        const ready = this.#storeReady();
        if (!ready.ok)
            return ready.failure;
        const store = this.store;
        try {
            return { ok: true, entries: store.readAudit({ limit }) };
        }
        catch (err) {
            return this.#handleStoreError(err, 'audit-log');
        }
    }
}
/**
 * Create a governed scheduler. Scheduling is **disabled** unless
 * `options.enabled === true` *and* a valid explicit authorization is supplied;
 * even then the capability/store/clock gate must pass.
 */
export function createScheduler(options = {}) {
    return new GovernedScheduler(options);
}
/** The validated default frozen scheduler policy. */
export function frozenDefaultSchedulerPolicy() {
    return defaultSchedulerPolicy();
}
/** Digest helper re-exported for tests/evidence binding of observations. */
export function schedulerContentDigest(value) {
    return contentDigest(value);
}
/** Binding of a lease record (defensive copy). */
export function scheduleBindingOf(record) {
    return { ...record.binding };
}
/** Provider id for status assertions. */
export const SCHEDULER_PROVIDER_ID = SCHEDULER_STORE_PROVIDER_ID;
