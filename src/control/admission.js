function isPlainRecord(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
}
function nonEmptyString(v) {
    return typeof v === 'string' && v.length > 0;
}
/** Reason codes emitted by the control-plane admission decision. */
export const ADMISSION_REASONS = Object.freeze({
    noObservationProducer: 'no-observation-producer',
    toolNotPinned: 'tool-ref-unpinned',
    toolDigestMismatch: 'tool-artifact-digest-mismatch',
    targetMissing: 'target-reference-missing',
    targetUnauthorized: 'unauthorized_target',
    budgetExhausted: 'budget_exhausted',
    notInFrozenPlan: 'not-in-frozen-plan',
    cancelled: 'cancelled',
});
/**
 * Decide whether one attempt of `caseSpec` may be dispatched.
 *
 * The decision is derived only from trusted control-plane context:
 * frozen plan membership, pinned tool bindings (artifact digest), a trusted
 * target reference and the aggregate budget ledger. `caseSpec.admission` is
 * deliberately never consulted.
 */
export function decideAdmission(caseSpec, context = {}) {
    const reasons = [];
    const caseRecord = isPlainRecord(caseSpec) ? caseSpec : undefined;
    const testId = caseRecord?.test_id;
    if (context.signal?.aborted === true) {
        return decision('rejected', [ADMISSION_REASONS.cancelled]);
    }
    if (context.frozenPlan !== undefined || context.expectedSet !== undefined) {
        const frozenPlan = isPlainRecord(context.frozenPlan) ? context.frozenPlan : undefined;
        const expected = context.expectedSet ?? new Set((frozenPlan?.expected ?? []));
        if (!expected.has(testId))
            return decision('rejected', [ADMISSION_REASONS.notInFrozenPlan]);
    }
    const tool = caseRecord?.tool;
    if (isPlainRecord(tool)) {
        const binding = context.toolBindings?.[String(testId)];
        if (!isPlainRecord(binding) || !isPlainRecord(binding.toolRef) || !nonEmptyString(binding.toolRef.artifact_digest)) {
            reasons.push(ADMISSION_REASONS.toolNotPinned);
        }
        else {
            const manifest = isPlainRecord(tool.manifest) ? tool.manifest : undefined;
            const manifestDigest = manifest?.artifact_digest;
            if (manifestDigest !== undefined && manifestDigest !== binding.toolRef.artifact_digest) {
                reasons.push(ADMISSION_REASONS.toolDigestMismatch);
            }
        }
        if (context.targetRef === null)
            reasons.push(ADMISSION_REASONS.targetMissing);
        else if (context.targetRef !== undefined && !isPlainRecord(context.targetRef)) {
            reasons.push(ADMISSION_REASONS.targetUnauthorized);
        }
    }
    else if (!isPlainRecord(caseRecord?.probe)) {
        // No tool and no in-process probe means there is no observation producer at
        // all; dispatching would be a guaranteed no-op, so the control face rejects.
        reasons.push(ADMISSION_REASONS.noObservationProducer);
    }
    const ledger = context.budgetLedger;
    if (ledger && typeof ledger === 'object' &&
        typeof ledger.canReserveAttempt === 'function' &&
        ledger.canReserveAttempt() !== true) {
        reasons.push(ADMISSION_REASONS.budgetExhausted);
    }
    if (reasons.length > 0)
        return decision('rejected', reasons);
    return decision('accepted', []);
}
function decision(status, reasons) {
    return Object.freeze({
        admission_status: status,
        reason_codes: Object.freeze([...reasons]),
        source: 'control-plane',
    });
}
