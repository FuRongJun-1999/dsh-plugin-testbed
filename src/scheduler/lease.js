/**
 * `scheduler-lease/v1` construction, strict validation and fencing comparison
 * (NEXT-PHASE-REQUIREMENTS SCH-01/SCH-04, §6.9).
 *
 * A lease is a durable capability to write one run's outcome for exactly one
 * `scope`. The fencing token is monotonic per scope and is **never** reused: a
 * writer presenting an older token is rejected with `fencing-token-stale`.
 * `max_concurrency` is pinned to 1 in v1 ("single scope, single owner").
 *
 * @module @deepseek-ai/dsh-plugin-testbed/scheduler/lease
 */
import { canonicalJson, sha256Hex } from '../protocol/digest.js';
import { LEASE_STATES, SCHEDULER_LEASE_SCHEMA_VERSION, SCHEDULER_STORE_PROVIDER_ID, SCHEDULER_STORE_PROVIDER_VERSION, } from './limits.js';
import { isRfc3339, wallMsFromIso } from './clock.js';
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const SCOPE_KEY_RE = /^scope-sha256:[0-9a-f]{64}$/;
const MAX_ID_LENGTH = 256;
const MAX_PROFILE_LENGTH = 128;
/** Narrow an `unknown` trust-boundary value to a plain record. */
export function isPlainRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
}
/** Non-empty bounded string. */
export function isNonEmptyString(value) {
    return typeof value === 'string' && value.length > 0 && value.length <= MAX_ID_LENGTH;
}
/** `sha256:<64 lowercase hex>` digest string. */
export function isDigest(value) {
    return typeof value === 'string' && SHA256_RE.test(value);
}
function isSafeInt(value, min = 0) {
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= min;
}
function deepFreeze(value) {
    if (value === null || typeof value !== 'object' || Object.isFrozen(value))
        return value;
    Object.freeze(value);
    for (const child of Object.values(value))
        deepFreeze(child);
    return value;
}
/**
 * Normalise a lease scope. v1 pins `max_concurrency` to 1 so a scope can never
 * hold two writers. Unknown keys are rejected (no silent extension surface).
 */
export function normalizeScope(scope) {
    if (!isPlainRecord(scope))
        return { ok: false, errors: ['lease-scope-invalid'] };
    const errors = [];
    const allowed = new Set(['profile', 'target_digest', 'tenant', 'max_concurrency']);
    for (const key of Object.keys(scope)) {
        if (!allowed.has(key))
            errors.push(`lease-scope-unknown-field:${key}`);
    }
    if (typeof scope.profile !== 'string' || scope.profile.length === 0 || scope.profile.length > MAX_PROFILE_LENGTH) {
        errors.push('lease-scope-profile-invalid');
    }
    if (!isDigest(scope.target_digest))
        errors.push('lease-scope-target-digest-invalid');
    const tenant = scope.tenant === undefined ? 'local' : scope.tenant;
    if (typeof tenant !== 'string' || tenant.length === 0 || tenant.length > MAX_PROFILE_LENGTH) {
        errors.push('lease-scope-tenant-invalid');
    }
    if (scope.max_concurrency !== 1)
        errors.push('lease-scope-max-concurrency-must-be-1');
    if (errors.length > 0)
        return { ok: false, errors };
    const normalized = {
        profile: scope.profile,
        target_digest: scope.target_digest,
        tenant: tenant,
        max_concurrency: 1,
    };
    const scopeKey = 'scope-sha256:' + sha256Hex(canonicalJson(normalized));
    return { ok: true, scope: normalized, scopeKey };
}
/**
 * Build a frozen `scheduler-lease/v1` object.
 */
export function buildLease(input) {
    const errors = [];
    for (const [field, value] of [
        ['lease_id', input.leaseId], ['run_id', input.runId],
        ['schedule_id', input.scheduleId], ['owner_id', input.ownerId],
    ]) {
        if (!isNonEmptyString(value))
            errors.push(`lease-${field}-invalid`);
    }
    const scopeResult = normalizeScope(input.scope);
    if (scopeResult.ok === false)
        errors.push(...scopeResult.errors);
    if (!isSafeInt(input.fencingToken, 1))
        errors.push('lease-fencing-token-invalid');
    if (!isSafeInt(input.epoch, 1))
        errors.push('lease-epoch-invalid');
    const state = input.state ?? 'active';
    if (typeof state !== 'string' || !LEASE_STATES.includes(state)) {
        errors.push('lease-state-invalid');
    }
    if (!isRfc3339(input.acquiredAt))
        errors.push('lease-acquired-at-invalid');
    if (!isRfc3339(input.expiresAt))
        errors.push('lease-expires-at-invalid');
    if (isRfc3339(input.acquiredAt) && isRfc3339(input.expiresAt) &&
        wallMsFromIso(input.expiresAt) <= wallMsFromIso(input.acquiredAt)) {
        errors.push('lease-expires-at-not-after-acquired-at');
    }
    if (!isSafeInt(input.ttlMs, 1))
        errors.push('lease-ttl-ms-invalid');
    const heartbeatSeq = input.heartbeatSeq ?? 0;
    if (!isSafeInt(heartbeatSeq, 0))
        errors.push('lease-heartbeat-seq-invalid');
    const cancel = normalizeCancel(input.cancel);
    if (cancel === null)
        errors.push('lease-cancel-invalid');
    const evidenceRefs = input.evidenceRefs ?? [];
    if (!Array.isArray(evidenceRefs) || evidenceRefs.some((ref) => !isNonEmptyString(ref))) {
        errors.push('lease-evidence-refs-invalid');
    }
    if (errors.length > 0)
        return { ok: false, errors };
    if (scopeResult.ok !== true)
        return { ok: false, errors: ['lease-scope-invalid'] };
    const lease = {
        schema_version: SCHEDULER_LEASE_SCHEMA_VERSION,
        lease_id: input.leaseId,
        run_id: input.runId,
        schedule_id: input.scheduleId,
        owner_id: input.ownerId,
        scope: scopeResult.scope,
        fencing_token: input.fencingToken,
        epoch: input.epoch,
        state: state,
        acquired_at: input.acquiredAt,
        expires_at: input.expiresAt,
        ttl_ms: input.ttlMs,
        heartbeat_seq: heartbeatSeq,
        store: {
            provider_id: SCHEDULER_STORE_PROVIDER_ID,
            version: SCHEDULER_STORE_PROVIDER_VERSION,
            durable: true,
        },
        cancel: cancel ?? { requested_at: null, token_id: null },
        evidence_refs: evidenceRefs.length > 0 ? [...evidenceRefs] : [],
    };
    return { ok: true, lease: deepFreeze(lease), scopeKey: scopeResult.scopeKey };
}
/** Normalise the cancel marker (structural only). */
export function normalizeCancel(value) {
    if (value === undefined || value === null)
        return { requested_at: null, token_id: null };
    if (!isPlainRecord(value))
        return null;
    const keys = Object.keys(value);
    if (keys.some((key) => !['requested_at', 'token_id'].includes(key)))
        return null;
    const requestedAt = value.requested_at ?? null;
    const tokenId = value.token_id ?? null;
    if (requestedAt === null && tokenId === null)
        return { requested_at: null, token_id: null };
    if (!isRfc3339(requestedAt))
        return null;
    if (!isNonEmptyString(tokenId))
        return null;
    return { requested_at: requestedAt, token_id: tokenId };
}
/** Validate a persisted `scheduler-lease/v1` document. */
export function validateLease(value) {
    if (!isPlainRecord(value))
        return { ok: false, errors: ['lease-not-object'] };
    const errors = [];
    if (value.schema_version !== SCHEDULER_LEASE_SCHEMA_VERSION)
        errors.push('lease-schema-version-invalid');
    for (const field of ['lease_id', 'run_id', 'schedule_id', 'owner_id']) {
        if (!isNonEmptyString(value[field]))
            errors.push(`lease-${field}-invalid`);
    }
    const scopeResult = normalizeScope(value.scope);
    if (scopeResult.ok === false)
        errors.push(...scopeResult.errors);
    if (!isSafeInt(value.fencing_token, 1))
        errors.push('lease-fencing-token-invalid');
    if (!isSafeInt(value.epoch, 1))
        errors.push('lease-epoch-invalid');
    if (typeof value.state !== 'string' || !LEASE_STATES.includes(value.state)) {
        errors.push('lease-state-invalid');
    }
    if (!isRfc3339(value.acquired_at))
        errors.push('lease-acquired-at-invalid');
    if (!isRfc3339(value.expires_at))
        errors.push('lease-expires-at-invalid');
    if (isRfc3339(value.acquired_at) && isRfc3339(value.expires_at) &&
        wallMsFromIso(value.expires_at) <= wallMsFromIso(value.acquired_at)) {
        errors.push('lease-expires-at-not-after-acquired-at');
    }
    if (!isSafeInt(value.ttl_ms, 1))
        errors.push('lease-ttl-ms-invalid');
    if (!isSafeInt(value.heartbeat_seq, 0))
        errors.push('lease-heartbeat-seq-invalid');
    if (!isPlainRecord(value.store) ||
        value.store.provider_id !== SCHEDULER_STORE_PROVIDER_ID ||
        value.store.version !== SCHEDULER_STORE_PROVIDER_VERSION ||
        value.store.durable !== true) {
        errors.push('lease-store-invalid');
    }
    if (normalizeCancel(value.cancel) === null)
        errors.push('lease-cancel-invalid');
    if (!Array.isArray(value.evidence_refs) || value.evidence_refs.some((ref) => !isNonEmptyString(ref))) {
        errors.push('lease-evidence-refs-invalid');
    }
    if (errors.length > 0)
        return { ok: false, errors };
    return { ok: true, lease: deepFreeze(structuredClone(value)) };
}
/**
 * True only for a structurally active lease whose wall expiry is in the future.
 */
export function isLeaseActive(lease, atWallMs) {
    return !!lease && lease.state === 'active' && Number.isFinite(atWallMs) &&
        wallMsFromIso(lease.expires_at) > atWallMs;
}
/** Compare a presented fencing token against the current lease token. */
export function fencingRelation(currentToken, presentedToken) {
    if (!isSafeInt(presentedToken, 0))
        return 'invalid';
    if (presentedToken === currentToken)
        return 'current';
    if (presentedToken < currentToken)
        return 'stale';
    return 'future';
}
/** Reject a write unless the presented token is exactly the current one. */
export function assertFencingCurrent(lease, presentedToken, options = {}) {
    if (!lease)
        return { ok: false, reason: 'lease-not-found' };
    const relation = fencingRelation(lease.fencing_token, presentedToken);
    if (relation === 'stale')
        return { ok: false, reason: 'fencing-token-stale' };
    if (relation === 'future')
        return { ok: false, reason: 'fencing-token-unknown' };
    if (relation === 'invalid')
        return { ok: false, reason: 'fencing-token-invalid' };
    if (lease.state !== 'active')
        return { ok: false, reason: `lease-${lease.state}` };
    if (typeof options.atWallMs === 'number' && Number.isFinite(options.atWallMs) &&
        wallMsFromIso(lease.expires_at) <= options.atWallMs) {
        return { ok: false, reason: 'lease-expired' };
    }
    return { ok: true };
}
/** True for a canonical scope key. */
export function isScopeKey(scopeKey) {
    return typeof scopeKey === 'string' && SCOPE_KEY_RE.test(scopeKey);
}
