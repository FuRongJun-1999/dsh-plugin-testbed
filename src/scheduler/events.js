/**
 * `scheduler-event/v1` append-only audit events and hash-chain verification
 * (NEXT-PHASE-REQUIREMENTS SCH-09, §6.9).
 *
 * Every durable scheduler state change appends exactly one event whose
 * `event_digest` covers the complete event body *including* `prev_digest`.
 * Events are never updated or deleted (enforced by SQLite triggers in
 * `store.ts`); a timeline is reconstructed by replaying the chain.
 *
 * Lease events additionally carry a `binding` with the owning schedule's
 * plan / policy / target digests, so an event cannot be detached from the
 * frozen plan or policy under which it was produced.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/scheduler/events
 */
import { canonicalJson, sha256Hex } from '../protocol/digest.js';
import { SCHEDULER_AUTHORITY_FIELDS } from './authority.js';
import { MAX_EVENT_PAYLOAD_BYTES, SCHEDULER_ACTOR_ROLES, SCHEDULER_EVENT_SCHEMA_VERSION, SCHEDULER_EVENT_TYPES, } from './limits.js';
import { isDigest, isNonEmptyString, isPlainRecord } from './lease.js';
import { isRfc3339 } from './clock.js';
/** Digest used as `prev_digest` for the first event in a fresh store. */
export const GENESIS_EVENT_DIGEST = 'sha256:' + '0'.repeat(64);
const EVENT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9:_-]{0,127}$/;
const SCOPE_KEY_RE = /^scope-sha256:[0-9a-f]{64}$/;
function deepFreeze(value) {
    if (value === null || typeof value !== 'object' || Object.isFrozen(value))
        return value;
    Object.freeze(value);
    for (const child of Object.values(value))
        deepFreeze(child);
    return value;
}
/**
 * Validate an event `binding`: the frozen plan, policy and target digests plus
 * the schedule identity under which a lease event was produced.
 */
export function validateEventBinding(binding) {
    const errors = [];
    if (!isPlainRecord(binding))
        return ['event-binding-invalid'];
    const allowed = new Set(['schedule_id', 'plan_digest', 'policy_digest', 'target_digest', 'scope_key']);
    for (const key of Object.keys(binding)) {
        if (!allowed.has(key))
            errors.push(`event-binding-unknown-field:${key}`);
    }
    if (!isNonEmptyString(binding.schedule_id))
        errors.push('event-binding-schedule-id-invalid');
    for (const field of ['plan_digest', 'policy_digest', 'target_digest']) {
        if (!isDigest(binding[field]))
            errors.push(`event-binding-${field.replace('_', '-')}-invalid`);
    }
    if (binding.scope_key !== undefined && !SCOPE_KEY_RE.test(String(binding.scope_key))) {
        errors.push('event-binding-scope-key-invalid');
    }
    return errors;
}
/**
 * Validate that an event payload cannot smuggle a control-authority decision
 * into the append-only audit log (scheduling never produces GateDecisions).
 */
export function validateEventPayload(payload) {
    if (payload === undefined || payload === null)
        return [];
    if (!isPlainRecord(payload))
        return ['event-payload-invalid'];
    const errors = [];
    const visit = (value, path) => {
        if (Array.isArray(value)) {
            value.forEach((item, index) => visit(item, `${path}[${index}]`));
            return;
        }
        if (!isPlainRecord(value))
            return;
        for (const [key, child] of Object.entries(value)) {
            const childPath = path === '' ? key : `${path}.${key}`;
            if (SCHEDULER_AUTHORITY_FIELDS.includes(key))
                errors.push(`event-payload-authority-field:${childPath}`);
            visit(child, childPath);
        }
    };
    visit(payload, '');
    let size = 0;
    try {
        size = Buffer.byteLength(canonicalJson(payload), 'utf8');
    }
    catch {
        errors.push('event-payload-not-canonicalizable');
    }
    if (size > MAX_EVENT_PAYLOAD_BYTES)
        errors.push('event-payload-too-large');
    return errors;
}
/**
 * Compute the canonical digest of an event body (all fields except
 * `event_digest`, including `prev_digest`).
 */
export function eventDigest(event) {
    const body = {};
    for (const [key, value] of Object.entries(event)) {
        if (key === 'event_digest')
            continue;
        body[key] = value;
    }
    return 'sha256:' + sha256Hex(canonicalJson(body));
}
/**
 * Build a frozen `scheduler-event/v1`.
 */
export function buildEvent(input) {
    const errors = [];
    if (typeof input.eventId !== 'string' || !EVENT_ID_RE.test(input.eventId))
        errors.push('event-id-invalid');
    if (!Number.isSafeInteger(input.sequence) || input.sequence < 1)
        errors.push('event-sequence-invalid');
    if (input.leaseId !== null && !isNonEmptyString(input.leaseId))
        errors.push('event-lease-id-invalid');
    if (!SCHEDULER_EVENT_TYPES.includes(input.type))
        errors.push('event-type-invalid');
    if (!isPlainRecord(input.actor) ||
        !isNonEmptyString(input.actor.id) ||
        !SCHEDULER_ACTOR_ROLES.includes(input.actor.role)) {
        errors.push('event-actor-invalid');
    }
    if (!isRfc3339(input.at))
        errors.push('event-at-invalid');
    if (input.fencingToken !== null &&
        (!Number.isSafeInteger(input.fencingToken) || input.fencingToken < 0)) {
        errors.push('event-fencing-token-invalid');
    }
    if (!isDigest(input.prevDigest))
        errors.push('event-prev-digest-invalid');
    if (input.binding !== undefined && input.binding !== null) {
        errors.push(...validateEventBinding(input.binding));
    }
    if (input.payload !== undefined && input.payload !== null) {
        errors.push(...validateEventPayload(input.payload));
    }
    if (errors.length > 0)
        return { ok: false, errors };
    const event = {
        schema_version: SCHEDULER_EVENT_SCHEMA_VERSION,
        event_id: input.eventId,
        sequence: input.sequence,
        lease_id: input.leaseId,
        type: input.type,
        actor: { id: input.actor.id, role: input.actor.role },
        at: input.at,
        fencing_token: input.fencingToken,
        prev_digest: input.prevDigest,
        event_digest: '',
    };
    if (input.binding !== undefined && input.binding !== null) {
        const binding = {
            schedule_id: input.binding.schedule_id,
            plan_digest: input.binding.plan_digest,
            policy_digest: input.binding.policy_digest,
            target_digest: input.binding.target_digest,
        };
        if (input.binding.scope_key !== undefined)
            binding.scope_key = input.binding.scope_key;
        event.binding = binding;
    }
    if (input.payload !== undefined && input.payload !== null) {
        event.payload = structuredClone(input.payload);
    }
    event.event_digest = eventDigest(event);
    return { ok: true, event: deepFreeze(event) };
}
/**
 * Validate a persisted `scheduler-event/v1` structure (digest recomputation is
 * `verifyEventChain`'s job so callers can report a tamper separately).
 */
export function validateEvent(value) {
    if (!isPlainRecord(value))
        return { ok: false, errors: ['event-not-object'] };
    const errors = [];
    if (value.schema_version !== SCHEDULER_EVENT_SCHEMA_VERSION)
        errors.push('event-schema-version-invalid');
    if (typeof value.event_id !== 'string' || !EVENT_ID_RE.test(value.event_id))
        errors.push('event-id-invalid');
    if (!Number.isSafeInteger(value.sequence) || value.sequence < 1)
        errors.push('event-sequence-invalid');
    if (value.lease_id !== null && !isNonEmptyString(value.lease_id))
        errors.push('event-lease-id-invalid');
    if (typeof value.type !== 'string' || !SCHEDULER_EVENT_TYPES.includes(value.type)) {
        errors.push('event-type-invalid');
    }
    if (!isPlainRecord(value.actor) ||
        !isNonEmptyString(value.actor.id) ||
        typeof value.actor.role !== 'string' ||
        !SCHEDULER_ACTOR_ROLES.includes(value.actor.role)) {
        errors.push('event-actor-invalid');
    }
    if (!isRfc3339(value.at))
        errors.push('event-at-invalid');
    if (value.fencing_token !== null &&
        (!Number.isSafeInteger(value.fencing_token) || value.fencing_token < 0)) {
        errors.push('event-fencing-token-invalid');
    }
    if (!isDigest(value.prev_digest))
        errors.push('event-prev-digest-invalid');
    if (!isDigest(value.event_digest))
        errors.push('event-digest-invalid');
    if (value.binding !== undefined)
        errors.push(...validateEventBinding(value.binding));
    if (value.payload !== undefined)
        errors.push(...validateEventPayload(value.payload));
    if (errors.length > 0)
        return { ok: false, errors };
    return { ok: true, event: deepFreeze(structuredClone(value)) };
}
/**
 * Verify an ordered event chain: schema, contiguous sequence, `prev_digest`
 * linkage and recomputed `event_digest`.
 */
export function verifyEventChain(events, options = {}) {
    const requireGenesis = options.requireGenesis !== false;
    const expectedStartDigest = options.expectedStartDigest ?? null;
    const errors = [];
    if (!Array.isArray(events)) {
        return { ok: false, errors: ['event-chain-not-array'], count: 0, first_sequence: null, last_sequence: null, last_digest: null };
    }
    let previous = null;
    for (let index = 0; index < events.length; index += 1) {
        const checked = validateEvent(events[index]);
        if (!checked.ok) {
            errors.push(...checked.errors.map((error) => `event[${index}]:${error}`));
            continue;
        }
        const event = checked.event;
        if (index === 0) {
            if (requireGenesis && event.prev_digest !== GENESIS_EVENT_DIGEST) {
                errors.push('event-chain-missing-genesis');
            }
            if (expectedStartDigest !== null && event.prev_digest !== expectedStartDigest) {
                errors.push('event-chain-start-digest-mismatch');
            }
        }
        else if (previous !== null) {
            if (event.sequence !== previous.sequence + 1)
                errors.push(`event-sequence-gap:${previous.sequence}->${event.sequence}`);
            if (event.prev_digest !== previous.event_digest)
                errors.push(`event-prev-digest-mismatch:${event.sequence}`);
        }
        const recomputed = eventDigest(event);
        if (recomputed !== event.event_digest)
            errors.push(`event-digest-mismatch:${event.sequence}`);
        previous = event;
    }
    return {
        ok: errors.length === 0,
        errors,
        count: events.length,
        first_sequence: events.length > 0 ? events[0].sequence : null,
        last_sequence: previous?.sequence ?? null,
        last_digest: previous?.event_digest ?? null,
    };
}
/**
 * Rebuild a per-lease timeline from the append-only chain without trusting any
 * caller-supplied ordering.
 */
export function rebuildLeaseTimeline(events, leaseId) {
    const chain = verifyEventChain(events, { requireGenesis: false });
    const timeline = events
        .filter((event) => event !== null && typeof event === 'object' && event.lease_id === leaseId)
        .map((event) => structuredClone(event));
    return { ok: chain.ok, errors: chain.errors, timeline };
}
