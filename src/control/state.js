/**
 * Six-field state normalisation and authority guards (architecture §9.5,
 * implementation-design-control §10).
 *
 * The trusted control face owns `run_status`, `admission_status`,
 * `execution_status` (as an *adopted* terminal), `invocation_status`,
 * `verdict` and `gate_decision`. A worker response, a RunSpec case, a tool
 * payload or a report projector must never be able to inject any of those as
 * authoritative facts. The helpers here are pure and side-effect free.
 *
 * Migration phase `pure control`: `unknown` at the adoption boundary, typed
 * `AttemptRecord`/`CaseRecord` on output; every authority guard and rejection
 * code is unchanged from the JavaScript baseline.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/control/state
 */
import { ADMISSION_STATUS, EXECUTION_STATUS, INVOCATION_STATUS, RUN_STATUS, VERDICT, inSet, } from '../protocol/enums.js';
/**
 * Fields a worker frame / caller-supplied case may never carry as authority.
 * `admission_status` is intentionally absent: the adapter may report a local
 * dispatch fact, but control re-derives admission and never accepts it as a
 * GatePolicy decision.
 */
export const AUTHORITY_FIELDS = Object.freeze([
    'verdict', 'gate_decision', 'required', 'expected', 'plan', 'plan_resolution',
    'run_status', 'gate', 'worker_verdict', 'admission_decision', 'admission_source',
]);
/** Terminal execution states that may count as an adopted terminal. */
export const TERMINAL_EXECUTION_STATUS = Object.freeze([...EXECUTION_STATUS]);
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
function isPlainRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
}
function isNonEmptyString(value) {
    return typeof value === 'string' && value.length > 0;
}
/**
 * Recursively collect paths that try to smuggle an authority field. Arrays are
 * traversed; primitive values are ignored. The caller decides whether a hit is
 * fatal (worker envelope) or merely ignored (caller case fields stripped by
 * `freezePlan`).
 */
export function findAuthorityFields(value, path = '') {
    const hits = [];
    if (Array.isArray(value)) {
        value.forEach((item, index) => {
            hits.push(...findAuthorityFields(item, path === '' ? `[${index}]` : `${path}[${index}]`));
        });
        return hits;
    }
    if (!isPlainRecord(value))
        return hits;
    for (const [key, child] of Object.entries(value)) {
        const childPath = path === '' ? key : `${path}.${key}`;
        if (AUTHORITY_FIELDS.includes(key))
            hits.push(childPath);
        hits.push(...findAuthorityFields(child, childPath));
    }
    return hits;
}
/**
 * Normalize the control-plane `admission_status`. Only a control decision may
 * mark an attempt accepted; anything else is a rejection with a reason code.
 */
export function normalizeAdmissionStatus(value, reasonCodes = []) {
    const reasons = Array.isArray(reasonCodes)
        ? reasonCodes.filter((code) => isNonEmptyString(code))
        : [];
    if (value === 'accepted')
        return { admission_status: 'accepted', reason_codes: reasons };
    return {
        admission_status: 'rejected',
        reason_codes: reasons.length > 0 ? reasons : ['admission-rejected-without-reason'],
    };
}
export function isRunStatus(value) {
    return inSet(RUN_STATUS, value);
}
export function isAttemptVerdict(value) {
    return inSet(VERDICT, value);
}
/**
 * Validate and normalise one adopted attempt. Rejects unknown enums, impossible
 * field combinations (e.g. a rejection that somehow "passed"), and any
 * authority field injected through the adapter/worker channel.
 */
export function normalizeAttempt(input) {
    const errors = [];
    if (!isPlainRecord(input))
        return { ok: false, errors: ['attempt-not-object'] };
    if (typeof input.attempt !== 'number' || !Number.isSafeInteger(input.attempt) || input.attempt < 1) {
        errors.push('attempt-number-invalid');
    }
    if (!inSet(ADMISSION_STATUS, input.admission_status))
        errors.push('attempt-admission-status-invalid');
    if (!inSet(EXECUTION_STATUS, input.execution_status))
        errors.push('attempt-execution-status-invalid');
    if (!inSet(INVOCATION_STATUS, input.invocation_status))
        errors.push('attempt-invocation-status-invalid');
    if (!inSet(VERDICT, input.verdict))
        errors.push('attempt-verdict-invalid');
    const rawReasonCodes = input.reason_codes;
    const reasonCodes = rawReasonCodes === undefined
        ? []
        : (Array.isArray(rawReasonCodes) && rawReasonCodes.every(isNonEmptyString) ? [...rawReasonCodes] : null);
    if (reasonCodes === null)
        errors.push('attempt-reason-codes-invalid');
    const evidenceVerified = input.invocation_evidence_verified === undefined
        ? false
        : input.invocation_evidence_verified;
    if (typeof evidenceVerified !== 'boolean')
        errors.push('attempt-invocation-evidence-flag-invalid');
    const rawObservationRefs = input.observation_refs;
    const observationRefs = rawObservationRefs === undefined
        ? []
        : (Array.isArray(rawObservationRefs) && rawObservationRefs.every(isNonEmptyString)
            ? [...rawObservationRefs]
            : null);
    if (observationRefs === null)
        errors.push('attempt-observation-refs-invalid');
    for (const field of ['started_at', 'ended_at']) {
        const value = input[field];
        if (value !== undefined && (typeof value !== 'string' || !RFC3339.test(value))) {
            errors.push(`attempt-${field.replace('_', '-')}-invalid`);
        }
    }
    if (input.admission_status === 'rejected') {
        if (input.execution_status !== 'skipped')
            errors.push('rejected-attempt-must-be-skipped');
        if (input.verdict !== 'skip')
            errors.push('rejected-attempt-must-be-skip');
        if (input.invocation_status !== 'not-started')
            errors.push('rejected-attempt-must-be-not-started');
    }
    if (input.invocation_status === 'started' && evidenceVerified !== true) {
        errors.push('started-invocation-requires-control-evidence');
    }
    if (evidenceVerified === true && input.invocation_status !== 'started') {
        errors.push('control-evidence-requires-started-invocation');
    }
    if (input.invocation_status === 'not-started' && evidenceVerified === true) {
        errors.push('not-started-cannot-have-control-evidence');
    }
    if (input.started_at !== undefined && input.invocation_status !== 'started') {
        errors.push('started-at-without-started-invocation');
    }
    // Execution/verdict coupling: a terminal may not claim an impossible verdict.
    if (input.execution_status === 'completed' && input.verdict === 'skip')
        errors.push('completed-cannot-be-skip-verdict');
    if (input.execution_status === 'skipped' && input.verdict !== 'skip')
        errors.push('skipped-requires-skip-verdict');
    if ((input.execution_status === 'error' || input.execution_status === 'timeout' ||
        input.execution_status === 'cancelled') && input.verdict !== 'error') {
        errors.push('failed-terminal-requires-error-verdict');
    }
    if (errors.length > 0)
        return { ok: false, errors };
    const attempt = {
        attempt: input.attempt,
        admission_status: input.admission_status,
        execution_status: input.execution_status,
        invocation_status: input.invocation_status,
        verdict: input.verdict,
        invocation_evidence_verified: evidenceVerified,
        reason_codes: reasonCodes,
        observation_refs: observationRefs,
    };
    if (input.started_at !== undefined)
        attempt.started_at = input.started_at;
    if (input.ended_at !== undefined)
        attempt.ended_at = input.ended_at;
    return { ok: true, attempt };
}
/**
 * Aggregate per-attempt records into the per-test-case state fields. The final
 * verdict is the last adopted attempt (retry appends, never overwrites), which
 * matches the frozen retry policy: a pass stops further attempts.
 */
export function summarizeCaseState(testId, classification, attempts, extra = {}) {
    const errors = [];
    if (!isNonEmptyString(testId))
        errors.push('test-id-invalid');
    if (classification !== 'required' && classification !== 'optional')
        errors.push('test-classification-invalid');
    if (!Array.isArray(attempts) || attempts.length === 0) {
        return { ok: false, errors: [...errors, 'attempts-empty'] };
    }
    const normalized = [];
    for (const raw of attempts) {
        const candidate = raw !== null && typeof raw === 'object' ? raw : undefined;
        const checked = candidate?.ok === true
            ? raw
            : normalizeAttempt(raw);
        if (!checked.ok)
            errors.push(...checked.errors);
        else
            normalized.push(checked.attempt);
    }
    for (let i = 0; i < normalized.length; i += 1) {
        if (normalized[i].attempt !== i + 1)
            errors.push(`attempt-sequence-invalid:${normalized[i].attempt}`);
    }
    if (errors.length > 0)
        return { ok: false, errors };
    const final = normalized[normalized.length - 1];
    const record = {
        test_id: testId,
        classification: classification,
        verdict: final.verdict,
        admission_status: final.admission_status,
        execution_status: final.execution_status,
        invocation_status: final.invocation_status,
        invocation_evidence_verified: final.invocation_evidence_verified === true &&
            final.invocation_status === 'started',
        reason_codes: [...final.reason_codes],
        dimensions: isPlainRecord(extra.dimensions) ? { ...extra.dimensions } : {},
        criteria_ref: isNonEmptyString(extra.criteria_ref) ? extra.criteria_ref : `criteria/${testId}`,
        attempts: normalized,
        observation_refs: [...final.observation_refs],
    };
    return { ok: true, record };
}
/**
 * A record is a candidate for "verified started pass" only when the control
 * face independently verified the start event *and* the adopted verdict is
 * pass.
 */
export function hasVerifiedStartedPass(record) {
    if (record === null || typeof record !== 'object')
        return false;
    const value = record;
    return value.verdict === 'pass' &&
        value.invocation_status === 'started' &&
        value.invocation_evidence_verified === true;
}
