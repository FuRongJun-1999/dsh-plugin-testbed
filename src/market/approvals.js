/**
 * Approval + waiver ledger for the market gate (MKT-05/MKT-06, MKT-C08/C09).
 *
 * Rules enforced here (fail-closed):
 *  - approvals are pre-execution (`at` before the earliest measured test start),
 *    unexpired, policy/run/receipt/target bound, and signed;
 *  - each policy-required role approves once, with distinct principals
 *    (separation of duties) and without the worker/signer/archive principals
 *    approving themselves;
 *  - waivers are pre-approved, scoped, policy-version bound, TTL-bounded and
 *    can never target a non-waivable hard condition;
 *  - a valid waiver is recorded but **never** changes a condition status to
 *    `pass` (MKT-06).
 *
 * @module @deepseek-ai/dsh-plugin-testbed/market/approvals
 */
import { MARKET_REASON_CODES, NON_WAIVABLE_CONDITIONS, validateMarketApproval, validateMarketWaiver, } from '../protocol/market-schemas.js';
import { asRecord, asString, canonicalDigest, isArray, isNonEmptyString, parseTimeMs, } from './util.js';
const APPROVAL_CLOCK_SKEW_MS = 60_000;
function emptyResult() {
    return {
        ok: false,
        errors: [],
        reasonCodes: [],
        approvals: [],
        waivers: [],
        approvedRoles: [],
        approvalDigests: [],
        waiverDigests: [],
        limitations: [],
    };
}
function isolationRank(level) {
    if (level === 'L3')
        return 3;
    if (level === 'L2')
        return 2;
    if (level === 'L1-subprocess')
        return 1;
    if (level === 'L0-in-process')
        return 0;
    return -1;
}
function unique(values) {
    return [...new Set(values)];
}
/**
 * Validate and classify approval/waiver documents.
 *
 * @param {unknown} approvalsRaw
 * @param {unknown} waiversRaw
 * @param {ApprovalContext} context
 * @returns {ApprovalLedgerResult}
 */
export function validateApprovalLedger(approvalsRaw, waiversRaw, context) {
    const result = emptyResult();
    const reasons = new Set();
    const errors = [];
    const limitations = [];
    const forbidden = new Set(context.forbiddenPrincipals.filter(isNonEmptyString));
    if (approvalsRaw === undefined || approvalsRaw === null) {
        reasons.add(MARKET_REASON_CODES.MARKET_APPROVAL_MISSING);
        errors.push('approvals-missing');
    }
    else if (!isArray(approvalsRaw)) {
        reasons.add(MARKET_REASON_CODES.MARKET_APPROVAL_MISSING);
        errors.push('approvals-not-array');
    }
    if (waiversRaw !== undefined && waiversRaw !== null && !isArray(waiversRaw)) {
        reasons.add(MARKET_REASON_CODES.MARKET_WAIVER_INVALID);
        errors.push('waivers-not-array');
    }
    const approvalDocs = isArray(approvalsRaw) ? approvalsRaw : [];
    const waiverDocs = isArray(waiversRaw) ? waiversRaw : [];
    for (const [index, raw] of approvalDocs.entries()) {
        const label = `approval[${index}]`;
        const schema = validateMarketApproval(raw);
        if (!schema.ok) {
            reasons.add(MARKET_REASON_CODES.MARKET_APPROVAL_MISSING);
            errors.push(`${label}:${schema.errors.slice(0, 3).join(',')}`);
            continue;
        }
        const doc = raw;
        const approvalId = asString(doc.approval_id);
        const principal = asString(doc.principal);
        const role = asString(doc.role);
        const decision = asString(doc.decision);
        const atMs = parseTimeMs(doc.at);
        const expiresAtMs = doc.expires_at === null ? null : parseTimeMs(doc.expires_at);
        const scope = asRecord(doc.scope);
        const targetDigest = asString(scope?.target_digest);
        const isolationLevel = asString(scope?.isolation_level);
        const policy = asRecord(doc.policy);
        const policyDigest = asString(policy?.digest);
        const signatureRef = doc.signature_ref === null ? null : asString(doc.signature_ref);
        const runId = asString(doc.run_id);
        const receiptDigest = asString(doc.receipt_digest);
        const separation = asRecord(doc.separation);
        let localErrors = 0;
        const reject = (reason, message) => {
            reasons.add(reason);
            errors.push(`${label}:${message}`);
            localErrors += 1;
        };
        if (decision !== 'approve')
            reject(MARKET_REASON_CODES.MARKET_APPROVAL_MISSING, 'decision-not-approve');
        if (!runId || runId !== context.runId)
            reject(MARKET_REASON_CODES.MARKET_APPROVAL_SCOPE, 'run-id-mismatch');
        if (!receiptDigest || receiptDigest !== context.receiptDigest) {
            reject(MARKET_REASON_CODES.MARKET_APPROVAL_SCOPE, 'receipt-digest-mismatch');
        }
        if (!policyDigest || policyDigest !== context.policy.digest) {
            reject(MARKET_REASON_CODES.MARKET_APPROVAL_SCOPE, 'policy-digest-mismatch');
        }
        if (!policy || policy.id !== context.policy.policyId || policy.version !== context.policy.policyVersion) {
            reject(MARKET_REASON_CODES.MARKET_APPROVAL_SCOPE, 'policy-ref-mismatch');
        }
        if (!targetDigest || targetDigest !== context.targetDigest) {
            reject(MARKET_REASON_CODES.MARKET_APPROVAL_SCOPE, 'target-digest-mismatch');
        }
        if (!isolationLevel || isolationRank(isolationLevel) < isolationRank(context.requiredIsolation)) {
            reject(MARKET_REASON_CODES.MARKET_APPROVAL_SCOPE, 'isolation-level-insufficient');
        }
        if (atMs === null)
            reject(MARKET_REASON_CODES.MARKET_APPROVAL_INVALID, 'at-invalid');
        if (atMs !== null) {
            if (atMs > context.nowMs + APPROVAL_CLOCK_SKEW_MS)
                reject(MARKET_REASON_CODES.MARKET_APPROVAL_EXPIRED, 'at-in-future');
            if (atMs < context.policy.effectiveFromMs)
                reject(MARKET_REASON_CODES.MARKET_APPROVAL_EXPIRED, 'before-policy-effective');
            if (context.earliestStartedAtMs !== null && atMs > context.earliestStartedAtMs) {
                reject(MARKET_REASON_CODES.MARKET_APPROVAL_EXPIRED, 'approval-not-pre-execution');
            }
        }
        if (expiresAtMs !== null && expiresAtMs <= context.nowMs) {
            reject(MARKET_REASON_CODES.MARKET_APPROVAL_EXPIRED, 'approval-expired');
        }
        if (signatureRef === null)
            reject(MARKET_REASON_CODES.MARKET_APPROVAL_MISSING, 'approval-unsigned');
        if (forbidden.has(principal))
            reject(MARKET_REASON_CODES.MARKET_APPROVAL_SELF, 'self-approval');
        if (!separation || separation.worker !== false || separation.signer !== false ||
            separation.archive !== false || separation.self !== false) {
            reject(MARKET_REASON_CODES.MARKET_APPROVAL_SELF, 'separation-flags-invalid');
        }
        if (localErrors > 0)
            continue;
        result.approvals.push({
            raw: doc,
            approvalId,
            principal,
            role,
            decision,
            atMs: atMs,
            expiresAtMs,
            targetDigest: targetDigest,
            isolationLevel: isolationLevel,
            policyDigest: policyDigest,
            signatureRef,
        });
        result.approvalDigests.push(canonicalDigest(doc));
    }
    // Separation of duties: every policy role approves, principals are distinct.
    if (result.approvals.length > 0) {
        const roles = new Set(result.approvals.map((approval) => approval.role));
        for (const requiredRole of context.policy.approvalRoles) {
            if (!roles.has(requiredRole)) {
                reasons.add(MARKET_REASON_CODES.MARKET_APPROVAL_ROLE);
                errors.push(`missing-approval-role:${requiredRole}`);
            }
        }
        const principals = result.approvals.map((approval) => approval.principal);
        if (new Set(principals).size !== principals.length) {
            reasons.add(MARKET_REASON_CODES.MARKET_APPROVAL_SELF);
            errors.push('approval-principals-not-distinct');
        }
        if (context.policy.separationOfDuties && result.approvals.length < 2) {
            reasons.add(MARKET_REASON_CODES.MARKET_APPROVAL_ROLE);
            errors.push('separation-of-duties-needs-two-approvers');
        }
        result.approvedRoles = [...roles];
    }
    else if (approvalsRaw !== undefined && approvalsRaw !== null) {
        reasons.add(MARKET_REASON_CODES.MARKET_APPROVAL_MISSING);
    }
    for (const [index, raw] of waiverDocs.entries()) {
        const label = `waiver[${index}]`;
        const schema = validateMarketWaiver(raw);
        if (!schema.ok) {
            reasons.add(MARKET_REASON_CODES.MARKET_WAIVER_INVALID);
            errors.push(`${label}:${schema.errors.slice(0, 3).join(',')}`);
            continue;
        }
        const doc = raw;
        const waiverId = asString(doc.waiver_id);
        const conditionId = asString(doc.condition_id);
        const policy = asRecord(doc.policy);
        const policyDigest = asString(policy?.digest);
        const scope = asRecord(doc.scope);
        const runId = asString(scope?.run_id);
        const targetDigest = asString(scope?.target_digest);
        const approvedAtMs = parseTimeMs(doc.approved_at);
        const expiresAtMs = parseTimeMs(doc.expires_at);
        const approvedBy = asString(doc.approved_by);
        const requestedBy = asString(doc.requested_by);
        const approverRole = asString(doc.approver_role);
        const status = asString(doc.status);
        let localErrors = 0;
        const reject = (reason, message) => {
            reasons.add(reason);
            errors.push(`${label}:${message}`);
            localErrors += 1;
        };
        if (!policyDigest || policyDigest !== context.policy.digest) {
            reject(MARKET_REASON_CODES.MARKET_WAIVER_OUT_OF_SCOPE, 'policy-digest-mismatch');
        }
        if (!policy || policy.id !== context.policy.policyId || policy.version !== context.policy.policyVersion) {
            reject(MARKET_REASON_CODES.MARKET_WAIVER_OUT_OF_SCOPE, 'policy-ref-mismatch');
        }
        if (runId !== context.runId || targetDigest !== context.targetDigest) {
            reject(MARKET_REASON_CODES.MARKET_WAIVER_OUT_OF_SCOPE, 'scope-mismatch');
        }
        if (NON_WAIVABLE_CONDITIONS.includes(conditionId) ||
            context.policy.waiverRules.forbiddenFor.includes(conditionId)) {
            reject(MARKET_REASON_CODES.MARKET_WAIVER_FORBIDDEN, `condition-not-waivable:${conditionId}`);
        }
        if (status !== 'approved')
            reject(MARKET_REASON_CODES.MARKET_WAIVER_INVALID, 'status-not-approved');
        if (approvedAtMs === null || expiresAtMs === null) {
            reject(MARKET_REASON_CODES.MARKET_WAIVER_INVALID, 'timestamps-invalid');
        }
        else {
            if (approvedAtMs > context.nowMs + APPROVAL_CLOCK_SKEW_MS) {
                reject(MARKET_REASON_CODES.MARKET_WAIVER_INVALID, 'approved-in-future');
            }
            if (expiresAtMs <= context.nowMs)
                reject(MARKET_REASON_CODES.MARKET_WAIVER_EXPIRED, 'waiver-expired');
            if (context.earliestStartedAtMs !== null && approvedAtMs > context.earliestStartedAtMs) {
                reject(MARKET_REASON_CODES.MARKET_WAIVER_INVALID, 'waiver-not-pre-execution');
            }
            const maxTtlMs = context.policy.waiverRules.maxTtlHours * 3_600_000;
            if (expiresAtMs - approvedAtMs > maxTtlMs) {
                reject(MARKET_REASON_CODES.MARKET_WAIVER_INVALID, 'waiver-ttl-exceeds-policy');
            }
        }
        if (approvedBy === requestedBy)
            reject(MARKET_REASON_CODES.MARKET_WAIVER_INVALID, 'self-approved-waiver');
        if (!context.policy.waiverRules.approverRoles.includes(approverRole)) {
            reject(MARKET_REASON_CODES.MARKET_WAIVER_INVALID, 'approver-role-not-allowed');
        }
        if (localErrors > 0)
            continue;
        result.waivers.push({
            raw: doc,
            waiverId,
            conditionId,
            policyDigest: policyDigest,
            runId: runId,
            targetDigest: targetDigest,
            approvedAtMs: approvedAtMs,
            expiresAtMs: expiresAtMs,
            approvedBy,
            approverRole,
            status,
        });
        result.waiverDigests.push(canonicalDigest(doc));
    }
    if (result.waivers.length > 0) {
        limitations.push('valid-waivers-recorded-never-change-required-status');
    }
    result.ok = errors.length === 0;
    result.errors = errors;
    result.reasonCodes = unique([...reasons]);
    result.limitations = limitations;
    return result;
}
