/**
 * Generic adversarial-suite evidence validation (A2/A3).
 *
 * An adversarial suite result is evidence only when it is:
 *   - complete (every declared case present exactly once, no unknown cases);
 *   - bound to the exact provider digest / launcher version / level;
 *   - produced by an external environment (not a fixture/test double) at grade
 *     E2/E3;
 *   - executed under a verified low-privilege identity (elevated=false,
 *     integrity low/medium/appcontainer/lowbox);
 *   - fresh;
 *   - and each `pass` case carries a reproducible command, expected/observed
 *     output and evidence refs.
 *
 * Any incomplete or non-executable case yields `blocked`; a failed attack case
 * yields `fail`. Neither can ever produce `market_evidence=true`.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/isolation/suite-evidence
 */
import { ISOLATION_REASON, LOW_PRIVILEGE_INTEGRITY, MARKET_EVIDENCE_GRADES, deepFreeze, isEvidenceRef, isNonEmptyString, isPlainRecord, isRfc3339Utc, isSha256Digest, } from './contracts.js';
export const DEFAULT_MAX_SUITE_AGE_MS = 24 * 60 * 60 * 1000;
const RESULT_STATUSES = Object.freeze(['pass', 'fail', 'blocked']);
function caseResultRecord(result) {
    return { ...result };
}
/**
 * @param {SuiteCaseSpec} caseSpec
 * @param {SuiteCaseOutcome} outcome
 */
export function buildSuiteCaseResult(caseSpec, outcome) {
    const result = {
        case_id: caseSpec.id,
        category: caseSpec.category,
        status: outcome.status,
        command: outcome.command ?? null,
        expected: outcome.expected ?? caseSpec.expectation,
        observed: outcome.observed ?? null,
        evidence_refs: Array.isArray(outcome.evidence_refs) ? [...outcome.evidence_refs] : [],
        reason_codes: Array.isArray(outcome.reason_codes) ? [...outcome.reason_codes] : [],
        at: outcome.at ?? null,
        detail: outcome.detail ?? null,
    };
    return deepFreeze(result);
}
export function blockedSuiteCase(caseSpec, reasonCodes, detail = 'preconditions-not-met') {
    return buildSuiteCaseResult(caseSpec, {
        status: 'blocked',
        reason_codes: [...new Set(reasonCodes)],
        detail,
        at: new Date().toISOString(),
    });
}
/**
 * Validate + aggregate an adversarial suite evidence document.
 *
 * @param {unknown} evidence
 * @param {SuiteEvaluationOptions} options
 * @returns {SuiteEvaluation}
 */
export function evaluateSuiteEvidence(evidence, options) {
    const nowMs = resolveNowMs(options.now);
    const maxAgeMs = typeof options.maxAgeMs === 'number' && Number.isFinite(options.maxAgeMs)
        ? options.maxAgeMs
        : DEFAULT_MAX_SUITE_AGE_MS;
    const diagnostics = [];
    const reasons = new Set();
    const blockedResult = (caseList = []) => deepFreeze({
        result: 'blocked',
        ok: false,
        diagnostics,
        reason_codes: reasons.size > 0 ? [...reasons] : [ISOLATION_REASON.adversarialSuiteMissing],
        cases: caseList,
        market_evidence: false,
        evidence_grade: null,
        coverage: {},
    });
    if (!isPlainRecord(evidence)) {
        diagnostics.push('evidence-not-object');
        return blockedResult();
    }
    const doc = evidence;
    const allowed = [
        'schema_version', 'suite_version', 'suite_id', 'executor', 'provider',
        'started_at', 'completed_at', 'cases',
    ];
    for (const key of Object.keys(doc)) {
        if (!allowed.includes(key))
            diagnostics.push(`unknown-field:${key}`);
    }
    if (doc.suite_version !== options.suiteVersion)
        diagnostics.push('suite-version-mismatch');
    if (doc.schema_version !== options.schemaVersion)
        diagnostics.push('schema-version-mismatch');
    if (!isRfc3339Utc(doc.started_at) || !isRfc3339Utc(doc.completed_at))
        diagnostics.push('timestamps-invalid');
    if (!Array.isArray(doc.cases))
        diagnostics.push('cases-not-array');
    // Executor binding.
    const executor = isPlainRecord(doc.executor) ? doc.executor : null;
    if (!executor) {
        diagnostics.push('executor-missing');
        reasons.add(ISOLATION_REASON.workerIdentityNotLowPrivilege);
    }
    else {
        const identity = isPlainRecord(executor.identity) ? executor.identity : null;
        const lowPrivilege = identity !== null &&
            identity.elevated === false &&
            typeof identity.integrity === 'string' &&
            LOW_PRIVILEGE_INTEGRITY.includes(identity.integrity);
        if (!lowPrivilege) {
            diagnostics.push('executor-not-low-privilege');
            reasons.add(ISOLATION_REASON.workerIdentityNotLowPrivilege);
        }
        if (executor.executed_under_low_privilege !== true) {
            diagnostics.push('not-executed-under-low-privilege');
            reasons.add(ISOLATION_REASON.workerIdentityNotLowPrivilege);
        }
        if (!isSha256Digest(executor.environment_fingerprint))
            diagnostics.push('environment-fingerprint-invalid');
        if (!isSha256Digest(executor.host_fingerprint))
            diagnostics.push('host-fingerprint-invalid');
    }
    // Provider binding: fixture/test doubles and missing measurement never pass.
    const provider = isPlainRecord(doc.provider) ? doc.provider : null;
    if (!provider) {
        diagnostics.push('provider-missing');
        reasons.add(ISOLATION_REASON.fixtureNotMarketEvidence);
    }
    else {
        if (provider.provenance !== 'external-environment') {
            diagnostics.push('provider-provenance-not-external');
            reasons.add(ISOLATION_REASON.fixtureNotMarketEvidence);
        }
        if (typeof provider.evidence_grade !== 'string' ||
            !MARKET_EVIDENCE_GRADES.includes(provider.evidence_grade)) {
            diagnostics.push('provider-evidence-grade-not-market');
            reasons.add(ISOLATION_REASON.fixtureNotMarketEvidence);
        }
        if (provider.level !== 'L2' && provider.level !== 'L3')
            diagnostics.push('provider-level-invalid');
        if (!isSha256Digest(provider.provider_digest))
            diagnostics.push('provider-digest-invalid');
        if (!isNonEmptyString(provider.launcher_version))
            diagnostics.push('launcher-version-invalid');
        if (options.providerDescriptor) {
            if (provider.provider_digest !== options.providerDescriptor.provider_digest) {
                diagnostics.push('provider-digest-mismatch');
                reasons.add(ISOLATION_REASON.fixtureNotMarketEvidence);
            }
            if (provider.launcher_version !== options.providerDescriptor.launcher_version) {
                diagnostics.push('launcher-version-mismatch');
            }
            if (provider.provider_id !== options.providerDescriptor.launcher_id) {
                diagnostics.push('provider-id-mismatch');
            }
            if (provider.level !== options.providerDescriptor.isolation.level) {
                diagnostics.push('provider-level-mismatch');
            }
        }
    }
    // Freshness + order.
    const startedMs = Date.parse(String(doc.started_at));
    const completedMs = Date.parse(String(doc.completed_at));
    const timeOk = Number.isFinite(startedMs) && Number.isFinite(completedMs) &&
        completedMs >= startedMs && nowMs - completedMs <= maxAgeMs && completedMs <= nowMs + 60_000;
    if (!timeOk) {
        diagnostics.push('suite-evidence-stale-or-inconsistent');
        reasons.add(ISOLATION_REASON.adversarialSuiteMissing);
    }
    // Exact case coverage.
    const specs = new Map(options.caseSpecs.map((spec) => [spec.id, spec]));
    const seen = new Map();
    const cases = [];
    if (Array.isArray(doc.cases)) {
        for (const rawItem of doc.cases) {
            if (!isPlainRecord(rawItem) || !isNonEmptyString(rawItem.case_id)) {
                diagnostics.push('case-invalid');
                continue;
            }
            const item = rawItem;
            const caseId = item.case_id;
            if (seen.has(caseId)) {
                diagnostics.push(`case-duplicate:${caseId}`);
                continue;
            }
            const spec = specs.get(caseId);
            if (!spec) {
                diagnostics.push(`case-unknown:${caseId}`);
                continue;
            }
            seen.set(caseId, true);
            if (typeof item.status !== 'string' || !RESULT_STATUSES.includes(item.status)) {
                diagnostics.push(`case-status-invalid:${caseId}`);
                continue;
            }
            if (item.status === 'pass') {
                const refs = item.evidence_refs;
                const executable = isNonEmptyString(item.command) && item.command.length <= 4096 &&
                    isNonEmptyString(item.observed) && item.observed.length <= 8192 &&
                    isNonEmptyString(item.expected) && item.expected.length <= 4096 &&
                    Array.isArray(refs) && refs.length >= 1 &&
                    refs.every(isEvidenceRef) &&
                    isRfc3339Utc(item.at);
                if (!executable) {
                    diagnostics.push(`case-pass-without-evidence:${caseId}`);
                    cases.push({ ...item, status: 'blocked', reason_codes: [ISOLATION_REASON.adversarialSuiteMissing] });
                    continue;
                }
            }
            else {
                if (!Array.isArray(item.reason_codes) || item.reason_codes.length === 0) {
                    diagnostics.push(`case-${item.status}-without-reason:${caseId}`);
                }
            }
            if (item.category !== spec.category)
                diagnostics.push(`case-category-mismatch:${caseId}`);
            cases.push(item);
        }
    }
    const coverage = {};
    for (const spec of options.caseSpecs) {
        coverage[spec.category] = (coverage[spec.category] ?? 0) + 1;
        if (!seen.has(spec.id)) {
            diagnostics.push(`case-missing:${spec.id}`);
            reasons.add(ISOLATION_REASON.adversarialSuiteMissing);
        }
    }
    if (Array.isArray(options.requiredCategories)) {
        for (const category of options.requiredCategories) {
            if (!((coverage[category] ?? 0) > 0)) {
                diagnostics.push(`category-uncovered:${category}`);
                reasons.add(ISOLATION_REASON.adversarialSuiteMissing);
            }
        }
    }
    const anyFail = cases.some((item) => item.status === 'fail');
    const anyBlocked = cases.some((item) => item.status === 'blocked');
    const caseComplete = cases.length === options.caseSpecs.length && diagnostics.length === 0;
    let result;
    if (anyFail) {
        result = 'fail';
        reasons.add(ISOLATION_REASON.adversarialSuiteFailed);
    }
    else if (anyBlocked || !caseComplete || reasons.size > 0) {
        result = 'blocked';
        reasons.add(ISOLATION_REASON.adversarialSuiteMissing);
    }
    else {
        result = 'pass';
    }
    const marketEvidence = result === 'pass' &&
        provider !== null &&
        provider.provenance === 'external-environment' &&
        typeof provider.evidence_grade === 'string' &&
        MARKET_EVIDENCE_GRADES.includes(provider.evidence_grade) &&
        executor !== null &&
        executor.executed_under_low_privilege === true;
    if (result === 'pass' && !marketEvidence) {
        reasons.add(ISOLATION_REASON.fixtureNotMarketEvidence);
    }
    return deepFreeze({
        result,
        ok: result === 'pass' && marketEvidence,
        diagnostics,
        reason_codes: orderReasons(reasons),
        cases,
        market_evidence: marketEvidence,
        evidence_grade: marketEvidence && provider !== null ? String(provider.evidence_grade) : null,
        coverage,
    });
}
function orderReasons(reasons) {
    const priority = [
        ISOLATION_REASON.adversarialSuiteFailed,
        ISOLATION_REASON.adversarialSuiteMissing,
        ISOLATION_REASON.workerIdentityNotLowPrivilege,
        ISOLATION_REASON.fixtureNotMarketEvidence,
    ];
    const out = [];
    for (const code of priority) {
        if (reasons.has(code))
            out.push(code);
    }
    for (const code of reasons) {
        if (!out.includes(code))
            out.push(code);
    }
    return out;
}
function resolveNowMs(value) {
    if (value instanceof Date)
        return value.getTime();
    if (typeof value === 'number' && Number.isFinite(value))
        return value;
    if (typeof value === 'string') {
        const parsed = Date.parse(value);
        if (Number.isFinite(parsed))
            return parsed;
    }
    return Date.now();
}
