/**
 * Control-plane capability verification (`capability/` in
 * implementation-design-control §5, architecture §8.3 / §9.4 step 4).
 *
 * A worker reports the raw two-phase probe snapshot (`claim` + `observed` plus
 * its bindings). The worker never reports `verification`, `not-applicable` or a
 * verdict — the trusted control face derives all of those here:
 *
 *   claim        observed   → verification
 *   declared     present    → corroborated
 *   declared     absent     → contradicted
 *   not-declared present    → contradicted
 *   not-declared absent     → corroborated
 *   any          unknown    → not-run
 *
 * Only a corroborated, correctly bound snapshot can ever mark an item
 * `not-applicable`. Unknown / contradicted / unbound snapshots therefore never
 * reduce the required baseline: they stay in `expected` with a reason.
 *
 * Migration phase `pure control`: raw worker snapshots stay `unknown`, the
 * trusted binding context and result records are typed, and every diagnostic
 * reason is unchanged.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/control/capability
 */
import { CAPABILITY_CLAIM, CAPABILITY_OBSERVED, CAPABILITY_VERIFICATION, inSet } from '../protocol/enums.js';
import { canonicalJson, sha256Hex } from '../protocol/digest.js';
/** Default predicate version when the frozen policy does not declare one. */
export const CAPABILITY_PREDICATE_VERSION = 'capability-predicate/v1';
const SHA256 = /^sha256:[0-9a-f]{64}$/;
function isPlainObject(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
}
function nonEmptyString(v) {
    return typeof v === 'string' && v.length > 0;
}
/**
 * Derive the control-plane `verification` triple. Invalid inputs are `not-run`
 * (never treated as evidence).
 */
export function deriveVerification(claim, observed) {
    if (!inSet(CAPABILITY_CLAIM, claim) || !inSet(CAPABILITY_OBSERVED, observed))
        return 'not-run';
    if (observed === 'unknown')
        return 'not-run';
    if (claim === 'declared')
        return observed === 'present' ? 'corroborated' : 'contradicted';
    return observed === 'absent' ? 'corroborated' : 'contradicted';
}
/**
 * Normalize worker snapshots into a null-prototype map keyed by `test_id`.
 * Accepts either a record map or the protocol-compatible `{ records: [...] }`
 * envelope. Both the map key and `record.test_id` are part of the binding.
 */
export function normalizeCapabilitySnapshots(raw) {
    if (raw === undefined || raw === null)
        return Object.create(null);
    if (!isPlainObject(raw))
        throw new TypeError('capabilitySnapshots must be a record or records envelope');
    const out = Object.create(null);
    if (Array.isArray(raw.records)) {
        const envelope = Object.create(null);
        for (const [key, value] of Object.entries(raw)) {
            if (key !== 'records')
                envelope[key] = value;
        }
        for (const record of raw.records) {
            if (!isPlainObject(record) || !nonEmptyString(record.test_id)) {
                throw new TypeError('capabilitySnapshots.records contains malformed test_id');
            }
            const id = record.test_id;
            if (Object.hasOwn(out, id))
                throw new TypeError(`duplicate capability snapshot test_id: ${id}`);
            const normalized = Object.assign(Object.create(null), envelope, record);
            normalized.test_id = id;
            out[id] = normalized;
        }
        return out;
    }
    if (Object.hasOwn(raw, 'records'))
        throw new TypeError('capabilitySnapshots.records must be an array');
    for (const [id, value] of Object.entries(raw)) {
        if (!nonEmptyString(id))
            throw new TypeError('capabilitySnapshots contains malformed test_id');
        if (!isPlainObject(value))
            throw new TypeError(`capability snapshot is malformed: ${id}`);
        if (value.test_id !== undefined && value.test_id !== id) {
            throw new TypeError(`capability snapshot test_id mismatch: ${id}`);
        }
        const normalized = Object.assign(Object.create(null), value);
        normalized.test_id = id;
        out[id] = normalized;
    }
    return out;
}
/** Content-addressed snapshot reference used by plan identity / receipts. */
export function capabilitySnapshotRef(snapshot) {
    return 'cap-sha256:' + sha256Hex(canonicalJson(snapshot));
}
/**
 * Verify a worker snapshot against trusted control-plane bindings.
 */
export function verifySnapshotBindings(snapshot, context = {}) {
    const record = isPlainObject(snapshot) ? snapshot : undefined;
    const diagnostics = [];
    const derived = deriveVerification(record?.claim, record?.observed);
    if (record?.source !== 'worker')
        diagnostics.push('capability-snapshot-source-invalid');
    const probeTime = record?.probe_time;
    if (typeof probeTime !== 'string' || !Number.isFinite(Date.parse(probeTime))) {
        diagnostics.push('capability-probe-time-invalid');
    }
    const trustedPutDigest = context?.put_digest ?? null;
    if (typeof trustedPutDigest !== 'string' || !SHA256.test(trustedPutDigest)) {
        diagnostics.push('capability-put-digest-unavailable');
    }
    else if (record?.put_digest !== trustedPutDigest) {
        diagnostics.push('capability-put-digest-mismatch');
    }
    const trustedEnv = context?.environment_fingerprint ?? null;
    if (typeof trustedEnv !== 'string' || !SHA256.test(trustedEnv)) {
        diagnostics.push('capability-environment-unavailable');
    }
    else if (record?.environment_fingerprint !== trustedEnv) {
        diagnostics.push('capability-environment-mismatch');
    }
    const trustedProbeVersion = context?.probe_version ?? null;
    if (!nonEmptyString(trustedProbeVersion)) {
        diagnostics.push('capability-probe-version-unavailable');
    }
    else if (record?.probe_version !== trustedProbeVersion) {
        diagnostics.push('capability-probe-version-mismatch');
    }
    // A worker-supplied verification value is never authoritative. A matching
    // legacy value is tolerated for protocol compatibility; a contradictory one
    // makes the snapshot untrusted.
    if (record?.verification !== undefined) {
        if (record.verification !== derived)
            diagnostics.push('capability-worker-verification-mismatch');
    }
    const trusted = diagnostics.length === 0;
    // Verification is only evidence when the snapshot is correctly bound.
    const verification = derived === 'corroborated' && !trusted ? 'not-run' : derived;
    return { derived, verification, trusted, diagnostics };
}
/**
 * Verify a set of capability snapshots against a `PlanCandidate` / `FrozenPlan`
 * and evaluate pre-declared applicability predicates.
 */
export function verifyCapabilitySnapshot(planLike, snapshots, options = {}) {
    const plan = isPlainObject(planLike) ? planLike : undefined;
    const cases = Array.isArray(plan?.cases)
        ? plan.cases
        : (Array.isArray(plan?.testCases) ? plan.testCases : []);
    const caseById = new Map(cases.map((caseSpec) => [caseSpec.test_id, caseSpec]));
    const normalized = normalizeCapabilitySnapshots(snapshots);
    const context = isPlainObject(options.planContext) ? options.planContext : {};
    const gatePolicy = isPlainObject(options.gatePolicy) ? options.gatePolicy : undefined;
    const policyPredicates = new Map();
    if (Array.isArray(gatePolicy?.not_applicable_predicates)) {
        for (const raw of gatePolicy.not_applicable_predicates) {
            const predicate = raw;
            policyPredicates.set(predicate.test_id, predicate);
        }
    }
    const records = Object.create(null);
    const diagnostics = [];
    for (const [id, snapshot] of Object.entries(normalized)) {
        const binding = verifySnapshotBindings(snapshot, context);
        if (!caseById.has(id))
            diagnostics.push({ test_id: id, reason: 'capability-snapshot-id-not-in-plan' });
        if (binding.derived === 'corroborated' && !binding.trusted) {
            diagnostics.push({ test_id: id, reason: 'capability-snapshot-not-trusted' });
        }
        for (const reason of binding.diagnostics)
            diagnostics.push({ test_id: id, reason });
        records[id] = {
            ...snapshot,
            verification: binding.verification,
            trusted: binding.trusted,
        };
    }
    const requested = options.notApplicable ?? [];
    if (!Array.isArray(requested))
        throw new TypeError('verifyCapabilitySnapshot notApplicable must be an array');
    const notApplicable = [];
    const notApplicableDetails = [];
    const notApplicableEvidence = Object.create(null);
    const seen = new Set();
    for (const rawId of requested) {
        if (!nonEmptyString(rawId)) {
            diagnostics.push({ test_id: String(rawId), reason: 'not-applicable-id-invalid' });
            continue;
        }
        const id = rawId;
        if (seen.has(id)) {
            diagnostics.push({ test_id: id, reason: 'duplicate-not-applicable-id' });
            continue;
        }
        seen.add(id);
        const caseSpec = caseById.get(id);
        if (!caseSpec) {
            diagnostics.push({ test_id: id, reason: 'not-applicable-id-not-in-plan' });
            continue;
        }
        const predicate = caseSpec.not_applicable_when;
        if (!isPlainObject(predicate) || !inSet(CAPABILITY_OBSERVED, predicate.observed) ||
            (predicate.verification !== undefined && predicate.verification !== 'corroborated')) {
            diagnostics.push({ test_id: id, reason: 'not-applicable-predicate-missing-or-invalid' });
            continue;
        }
        if (predicate.observed === 'unknown') {
            diagnostics.push({ test_id: id, reason: 'not-applicable-predicate-cannot-be-unknown' });
            continue;
        }
        let predicateVersion = CAPABILITY_PREDICATE_VERSION;
        if (policyPredicates.size > 0 || options.gatePolicy !== undefined) {
            const policyPredicate = policyPredicates.get(id);
            if (!policyPredicate) {
                diagnostics.push({ test_id: id, reason: 'not-applicable-predicate-not-in-policy' });
                continue;
            }
            if (policyPredicate.observed !== predicate.observed) {
                diagnostics.push({ test_id: id, reason: 'not-applicable-predicate-policy-mismatch' });
                continue;
            }
            predicateVersion = nonEmptyString(policyPredicate.predicate_version)
                ? policyPredicate.predicate_version
                : CAPABILITY_PREDICATE_VERSION;
        }
        const record = records[id];
        if (!record) {
            diagnostics.push({ test_id: id, reason: 'capability-snapshot-missing' });
            continue;
        }
        if (record.source !== 'worker') {
            diagnostics.push({ test_id: id, reason: 'capability-snapshot-source-invalid' });
            continue;
        }
        if (!record.trusted) {
            diagnostics.push({ test_id: id, reason: 'capability-snapshot-not-trusted' });
            continue;
        }
        if (record.verification !== 'corroborated') {
            diagnostics.push({ test_id: id, reason: 'capability-snapshot-not-corroborated' });
            continue;
        }
        if (record.observed !== predicate.observed) {
            diagnostics.push({ test_id: id, reason: 'capability-snapshot-does-not-match-predicate' });
            continue;
        }
        notApplicable.push(id);
        notApplicableEvidence[id] = Object.assign(Object.create(null), record);
        notApplicableDetails.push({
            test_id: id,
            classification: caseSpec.classification,
            not_applicable: {
                predicate_version: predicateVersion,
                capability_snapshot_ref: capabilitySnapshotRef(normalized[id] ?? record),
                reason: `capability-${predicate.observed}`,
            },
        });
    }
    for (const entry of Object.values(records)) {
        if (!inSet(CAPABILITY_VERIFICATION, entry.verification))
            entry.verification = 'not-run';
    }
    return {
        ok: true,
        records,
        snapshots: normalized,
        notApplicable,
        notApplicableDetails,
        notApplicableEvidence,
        diagnostics,
    };
}
