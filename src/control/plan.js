/**
 * Control-face plan compilation and freeze (`compile/` + `plan/` in
 * implementation-design-control §3–§6).
 *
 * Pure functions; only imports from `../protocol/*` and sibling pure control
 * modules (architecture §9.1, §9.4). Nothing here loads or executes PUT code.
 *
 * Guarantees:
 *   - the `PlanCandidate` baseline is non-removable: policy-declared required
 *     test IDs must be present and keep their required classification;
 *   - unknown / contradicted / unbound capability snapshots never shrink
 *     `expected` or `required` (only a control-verified predicate result may
 *     move an item to `not-applicable`, and the item stays in `testCases`);
 *   - caller-supplied authority fields (`admission`, `verdict`, …) are stripped
 *     from the frozen plan and cannot influence it;
 *   - the frozen plan is deep-frozen, `plan_id` binds the complete JSON
 *     semantics, and post-freeze mutations are rejected with a traceable
 *     `plan_immutable_violation` record.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/control/plan
 */
import { canonicalJson, sha256Hex } from '../protocol/digest.js';
import { capabilitySnapshotRef, normalizeCapabilitySnapshots, verifyCapabilitySnapshot, CAPABILITY_PREDICATE_VERSION, } from './capability.js';
import { compileScenarioGraph, SUPPORTED_ASSERTIONS } from './graph.js';
import { MAX_CASE_ATTEMPTS, MAX_PLAN_CASES, MAX_PLAN_TOTAL_ATTEMPTS } from './limits.js';
import { validateGatePolicy } from './spec.js';
import { AUTHORITY_FIELDS } from './state.js';
export { MAX_PLAN_CASES, MAX_CASE_ATTEMPTS, MAX_PLAN_TOTAL_ATTEMPTS };
const CLASSIFICATIONS = ['required', 'optional'];
/**
 * Caller/worker authority fields that are stripped (never trusted) from a
 * frozen case. `admission` is the caller-supplied negative-test simulation; it
 * is not a GatePolicy decision and must not survive into the immutable plan.
 */
const NON_AUTHORITATIVE_CASE_FIELDS = Object.freeze(['admission', ...AUTHORITY_FIELDS]);
/**
 * Statically compile a scenario into a non-removable `PlanCandidate`.
 *
 * Accepted inputs:
 *   - `cases[]` — legacy run-spec case list (kept for compatibility);
 *   - `{ scenario: { cases } }` / a `run-spec/v1` document — caller-authority
 *     fields inside cases are rejected;
 *   - `{ nodes: [...] }` — normalized scenario graph (see `graph.js`).
 *
 * @param {unknown} input
 * @param {{ gatePolicy?: object, budget?: object, target?: object, authorization?: object }} [options]
 * @returns {{ok:true, candidate:object} | {ok:false, errors:string[]}}
 */
export function compilePlanCandidate(input, options = {}, maybeScenario) {
    // Design-signature compatibility: compilePlanCandidate(runSpec, gatePolicy, scenario)
    if (isGatePolicyLike(options)) {
        const scenario = maybeScenario;
        options = { gatePolicy: options };
        if (scenario !== undefined) {
            if (Array.isArray(scenario))
                input = scenario;
            else if (Array.isArray(scenario.cases))
                input = { scenario };
            else if (Array.isArray(scenario.nodes))
                input = scenario;
        }
    }
    let result;
    if (Array.isArray(input)) {
        const errors = rejectCallerAuthorityFields(input);
        result = errors.length > 0 ? { ok: false, errors } : compileCases(input);
    }
    else if (input && typeof input === 'object' && Array.isArray(input.nodes)) {
        result = compileScenarioGraph(input, options);
    }
    else if (input && typeof input === 'object' && Array.isArray(input.scenario?.cases)) {
        const cases = input.scenario.cases;
        const errors = rejectCallerAuthorityFields(cases);
        result = errors.length > 0 ? { ok: false, errors } : compileCases(cases);
    }
    else if (input && typeof input === 'object' && Array.isArray(input.cases)) {
        const errors = rejectCallerAuthorityFields(input.cases);
        result = errors.length > 0 ? { ok: false, errors } : compileCases(input.cases);
    }
    else {
        return { ok: false, errors: ['scenario-not-object'] };
    }
    if (!result.ok)
        return result;
    if (options.gatePolicy !== undefined) {
        const policyCheck = validateGatePolicy(options.gatePolicy, { caseTestIds: result.candidate.testIds });
        if (!policyCheck.ok)
            return { ok: false, errors: policyCheck.errors };
        const classificationErrors = checkPolicyClassification(result.candidate, options.gatePolicy);
        if (classificationErrors.length > 0)
            return { ok: false, errors: classificationErrors };
    }
    return result;
}
/** @param {unknown} value */
function isGatePolicyLike(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value) && value.schema_version === 'gate-policy/v1';
}
/** @param {object[]} cases */
function rejectCallerAuthorityFields(cases) {
    const errors = [];
    for (const caseSpec of cases) {
        if (!caseSpec || typeof caseSpec !== 'object' || Array.isArray(caseSpec))
            continue;
        for (const field of NON_AUTHORITATIVE_CASE_FIELDS) {
            if (Object.hasOwn(caseSpec, field)) {
                errors.push(`untrusted-caller-field:${field}:${String(caseSpec.test_id)}`);
            }
        }
    }
    return errors;
}
/** @param {object} candidate @param {object} policy */
function checkPolicyClassification(candidate, policy) {
    const errors = [];
    const caseById = new Map(candidate.cases.map((caseSpec) => [caseSpec.test_id, caseSpec]));
    const requiredSet = new Set(policy.required_baseline);
    const optionalSet = new Set(policy.optional_baseline);
    for (const id of policy.required_baseline) {
        const caseSpec = caseById.get(id);
        if (!caseSpec)
            continue; // already reported by validateGatePolicy
        if (caseSpec.classification !== 'required')
            errors.push(`required-baseline-classification-mismatch:${id}`);
    }
    for (const caseSpec of candidate.cases) {
        const { test_id: id, classification } = caseSpec;
        if (classification === 'required' && !requiredSet.has(id)) {
            errors.push(`required-classification-not-in-policy:${id}`);
        }
        if (classification === 'optional' && requiredSet.has(id)) {
            errors.push(`optional-classification-conflicts-with-policy:${id}`);
        }
        if (optionalSet.has(id) && classification === 'required' && !requiredSet.has(id)) {
            errors.push(`required-classification-conflicts-with-policy:${id}`);
        }
    }
    return errors;
}
/** Legacy run-spec case compilation. @param {object[]} cases */
function compileCases(cases) {
    if (cases.length > MAX_PLAN_CASES) {
        return { ok: false, errors: [`case-count-exceeds-limit:${MAX_PLAN_CASES}`] };
    }
    const errors = [];
    const nodeById = Object.create(null);
    const seenNode = new Set();
    const seenTest = new Set();
    let totalAttempts = 0;
    for (const c of cases) {
        const nid = c?.node_id;
        const tid = c?.test_id;
        if (!nonEmptyString(tid) || !nonEmptyString(nid)) {
            errors.push(`missing-or-invalid-id:test_id=${String(tid)},node_id=${String(nid)}`);
            continue;
        }
        const retryError = caseRetryError(c);
        if (retryError)
            errors.push(`${retryError}:${tid}`);
        else {
            totalAttempts += c.retry?.max_attempts ?? 1;
            if (!Number.isSafeInteger(totalAttempts) || totalAttempts > MAX_PLAN_TOTAL_ATTEMPTS) {
                errors.push(`candidate-attempt-total-exceeds-limit:${MAX_PLAN_TOTAL_ATTEMPTS}`);
            }
        }
        if (seenTest.has(tid))
            errors.push(`duplicate-test-id:${tid}`);
        seenTest.add(tid);
        if (seenNode.has(nid))
            errors.push(`duplicate-node-id:${nid}`);
        seenNode.add(nid);
        if (!CLASSIFICATIONS.includes(c?.classification))
            errors.push(`invalid-classification:${tid}`);
        if (c?.criteria !== undefined &&
            (!c.criteria || typeof c.criteria !== 'object' || Array.isArray(c.criteria) ||
                !SUPPORTED_ASSERTIONS.includes(c.criteria.assert))) {
            // No user-supplied arbitrary assertion code: only the frozen built-in DSL.
            errors.push(`unsupported-assertion:${tid}`);
        }
        if (c?.needs !== undefined && (!Array.isArray(c.needs) || c.needs.some((dep) => !nonEmptyString(dep)))) {
            errors.push(`invalid-needs:${tid}`);
        }
        nodeById[nid] = c;
    }
    for (const c of cases) {
        if (!nonEmptyString(c?.test_id) || !nonEmptyString(c?.node_id))
            continue;
        for (const dep of Array.isArray(c?.needs) ? c.needs : []) {
            if (!seenNode.has(dep))
                errors.push(`unknown-needs-reference:${c.test_id}->${dep}`);
        }
    }
    if (errors.length > 0)
        return { ok: false, errors };
    const topo = stableTopo(cases);
    if (topo.length !== cases.length)
        return { ok: false, errors: ['cycle-detected'] };
    const orderedNodeIds = topo.map((c) => c.node_id);
    const orderedTestIds = topo.map((c) => c.test_id);
    const requiredTestIds = topo.filter((c) => c.classification === 'required').map((c) => c.test_id);
    return {
        ok: true,
        candidate: {
            nodeIds: orderedNodeIds,
            nodeById,
            testIds: orderedTestIds,
            baselineTestIds: orderedTestIds,
            requiredTestIds,
            topoOrder: orderedNodeIds,
            testOrder: orderedTestIds,
            cases: topo,
            dataEdges: [],
        },
    };
}
/**
 * Freeze a validated candidate into an immutable Plan.
 *
 * @param {object} candidate output of {@link compilePlanCandidate}
 * @param {{notApplicable?:string[], capabilitySnapshots?:object,
 *   capabilityVerification?:object, planContext?:object,
 *   preapprovedWaivers?:string[], gatePolicy?:object, budget?:object,
 *   environmentMatrix?:object}} [opts]
 * @returns {object} deep-frozen plan
 */
export function freezePlan(candidate, opts = {}) {
    // Design-signature compatibility: freezePlan(planCandidate, capabilityVerification)
    if (opts && opts.capabilityVerification === undefined && opts.records &&
        opts.snapshots && Array.isArray(opts.diagnostics)) {
        opts = { capabilityVerification: opts };
    }
    if (!opts || typeof opts !== 'object' || Array.isArray(opts))
        throw new TypeError('freezePlan options must be an object');
    const cases = candidate?.cases;
    if (!Array.isArray(cases))
        throw new TypeError('freezePlan candidate.cases must be an array');
    if (cases.length > MAX_PLAN_CASES)
        throw new TypeError(`freezePlan candidate case-count-exceeds-limit:${MAX_PLAN_CASES}`);
    const caseById = new Map();
    const nodeIds = new Set();
    const caseDiagnostics = [];
    for (const c of cases) {
        if (!c || typeof c !== 'object' || !nonEmptyString(c.test_id) || !nonEmptyString(c.node_id)) {
            throw new TypeError('freezePlan candidate contains malformed test/node IDs');
        }
        if (Object.hasOwn(c, 'capability')) {
            throw new TypeError(`freezePlan case-embedded capability is untrusted: ${c.test_id}`);
        }
        const retryError = caseRetryError(c);
        if (retryError)
            throw new TypeError(`freezePlan ${retryError}:${c.test_id}`);
        if (caseById.has(c.test_id))
            throw new TypeError(`freezePlan duplicate test_id: ${c.test_id}`);
        if (nodeIds.has(c.node_id))
            throw new TypeError(`freezePlan duplicate node_id: ${c.node_id}`);
        if (!CLASSIFICATIONS.includes(c.classification))
            throw new TypeError(`freezePlan invalid classification: ${c.test_id}`);
        for (const field of NON_AUTHORITATIVE_CASE_FIELDS) {
            if (Object.hasOwn(c, field))
                caseDiagnostics.push({ test_id: c.test_id, reason: `case-authority-field-stripped:${field}` });
        }
        caseById.set(c.test_id, c);
        nodeIds.add(c.node_id);
    }
    const caseOrder = cases.map((c) => c.test_id);
    const allTestIds = validatedCandidateIds(candidate, 'testIds', caseOrder, caseById);
    const baselineTestIds = validatedCandidateIds(candidate, 'baselineTestIds', allTestIds, caseById);
    const requiredTestIds = validatedCandidateIds(candidate, 'requiredTestIds', cases.filter((c) => c.classification === 'required').map((c) => c.test_id), caseById);
    if (!sameOrder(allTestIds, caseOrder) || !sameOrder(baselineTestIds, caseOrder)) {
        throw new TypeError('freezePlan testIds/baselineTestIds out of candidate order');
    }
    const derivedRequired = cases.filter((c) => c.classification === 'required').map((c) => c.test_id);
    if (!sameOrder(requiredTestIds, derivedRequired))
        throw new TypeError('freezePlan requiredTestIds out of candidate order or inconsistent');
    if (opts.gatePolicy !== undefined) {
        const policyCheck = validateGatePolicy(opts.gatePolicy, { caseTestIds: allTestIds });
        if (!policyCheck.ok)
            throw new TypeError(`freezePlan gate policy invalid: ${policyCheck.errors[0]}`);
        const caseByIdForPolicy = new Map(cases.map((caseSpec) => [caseSpec.test_id, caseSpec]));
        for (const id of opts.gatePolicy.required_baseline) {
            if (caseByIdForPolicy.get(id)?.classification !== 'required') {
                throw new TypeError(`freezePlan required-baseline-classification-mismatch:${id}`);
            }
        }
    }
    const planContext = opts.planContext == null ? null : cloneJson(opts.planContext, 'planContext');
    const budget = opts.budget === undefined || opts.budget === null ? null : cloneJson(opts.budget, 'budget');
    const environmentMatrix = opts.environmentMatrix == null
        ? null
        : cloneJson(opts.environmentMatrix, 'environmentMatrix');
    let rawCapabilitySnapshots = null;
    let verification = null;
    if (opts.capabilityVerification !== undefined) {
        verification = opts.capabilityVerification;
    }
    else {
        rawCapabilitySnapshots = opts.capabilitySnapshots == null
            ? null
            : cloneJson(opts.capabilitySnapshots, 'capabilitySnapshots');
        verification = verifyCapabilitySnapshot({ cases }, rawCapabilitySnapshots, {
            planContext: opts.planContext,
            notApplicable: opts.notApplicable ?? [],
            gatePolicy: opts.gatePolicy,
        });
    }
    if (!verification || typeof verification !== 'object')
        throw new TypeError('freezePlan capabilityVerification must be an object');
    const snapshots = verification.snapshots ?? normalizeCapabilitySnapshots(rawCapabilitySnapshots);
    const capabilitySnapshots = rawCapabilitySnapshots === null && opts.capabilityVerification === undefined
        ? null
        : snapshots;
    // Null-prototype maps keep reserved IDs (`__proto__`, `constructor`) as
    // ordinary own keys and prevent prototype mutation while deriving refs.
    const capabilitySnapshotRefs = Object.create(null);
    const capabilitySnapshotDiagnostics = [];
    for (const [id, snapshot] of Object.entries(snapshots)) {
        capabilitySnapshotRefs[id] = capabilitySnapshotRef(snapshot);
        if (!caseById.has(id))
            capabilitySnapshotDiagnostics.push({ test_id: id, reason: 'capability-snapshot-id-not-in-plan' });
        if (snapshot.test_id !== id)
            capabilitySnapshotDiagnostics.push({ test_id: id, reason: 'capability-snapshot-test-id-mismatch' });
    }
    // Only control-verified applicability results move items out of `expected`.
    const notApplicable = [...(verification.notApplicable ?? [])];
    const notApplicableDiagnostics = [...(verification.diagnostics ?? [])];
    const notApplicableEvidence = Object.create(null);
    for (const id of notApplicable) {
        if (!Object.hasOwn(snapshots, id)) {
            notApplicableDiagnostics.push({ test_id: id, reason: 'capability-snapshot-missing' });
            continue;
        }
        notApplicableEvidence[id] = cloneJson(snapshots[id], `capabilitySnapshots.${id}`);
    }
    const acceptedNotApplicable = notApplicable.filter((id) => Object.hasOwn(notApplicableEvidence, id));
    const waiverAllowlist = validateWaiverAllowlist(opts.preapprovedWaivers ?? [], caseById);
    const testCases = cases.map((c) => sanitizeCase(c));
    const expected = allTestIds.filter((id) => !acceptedNotApplicable.includes(id));
    const required = expected.filter((id) => caseById.get(id).classification === 'required');
    const optional = expected.filter((id) => caseById.get(id).classification === 'optional');
    const digestInput = {
        testCases,
        expected,
        required,
        optional,
        planContext,
        capabilitySnapshots,
        capabilitySnapshotRefs,
        not_applicable: acceptedNotApplicable,
        not_applicable_evidence: notApplicableEvidence,
        waiver_allowlist: waiverAllowlist,
        budget,
        environment_matrix: environmentMatrix,
    };
    const plan_id = 'plan-sha256:' + sha256Hex(canonicalJson(digestInput));
    const frozen = {
        plan_id,
        testCases,
        expected,
        required,
        optional,
        notApplicable: acceptedNotApplicable,
        notApplicableDetails: [...(verification.notApplicableDetails ?? [])],
        notApplicableDiagnostics,
        notApplicableEvidence,
        planContext,
        capabilitySnapshots,
        capabilitySnapshotRefs,
        capabilitySnapshotDiagnostics,
        waiverAllowlist,
        budget,
        environmentMatrix,
        classification: Object.freeze({
            required: [...required],
            optional: [...optional],
            not_applicable: [...acceptedNotApplicable],
        }),
        attemptLimits: Object.freeze({
            max_attempts_per_case: MAX_CASE_ATTEMPTS,
            max_total_attempts: MAX_PLAN_TOTAL_ATTEMPTS,
        }),
        topoOrder: [...(candidate.topoOrder ?? caseOrder)],
        testOrder: [...(candidate.testOrder ?? caseOrder)],
        dataEdges: cloneJsonJson(candidate.dataEdges ?? []),
        mutationDiagnostics: [...caseDiagnostics],
    };
    return deepFreeze(frozen);
}
/** Strip authority fields; clone everything else deterministically. */
function sanitizeCase(caseSpec) {
    const clone = cloneJson(caseSpec, `cases.${caseSpec.test_id}`);
    for (const field of NON_AUTHORITATIVE_CASE_FIELDS)
        delete clone[field];
    return clone;
}
/**
 * Verify a frozen plan's identity and structural invariants without trusting a
 * caller-supplied digest. Detects post-freeze mutation, inconsistent
 * classification, and objects that are no longer frozen.
 *
 * @param {unknown} frozenPlan
 * @returns {{ ok: boolean, errors: string[], recomputed: string|null }}
 */
export function verifyFrozenPlan(frozenPlan) {
    if (!frozenPlan || typeof frozenPlan !== 'object' || Array.isArray(frozenPlan)) {
        return { ok: false, errors: ['frozen-plan-not-object'], recomputed: null };
    }
    const errors = [];
    if (!Object.isFrozen(frozenPlan))
        errors.push('frozen-plan-not-frozen');
    if (typeof frozenPlan.plan_id !== 'string' || !/^plan-sha256:[0-9a-f]{64}$/.test(frozenPlan.plan_id)) {
        errors.push('frozen-plan-id-invalid');
    }
    if (!Array.isArray(frozenPlan.testCases) || !Array.isArray(frozenPlan.expected) || !Array.isArray(frozenPlan.required)) {
        return { ok: false, errors: [...errors, 'frozen-plan-shape-invalid'], recomputed: null };
    }
    const caseIds = new Set();
    for (const caseSpec of frozenPlan.testCases) {
        if (!caseSpec || typeof caseSpec !== 'object' || !nonEmptyString(caseSpec.test_id)) {
            errors.push('frozen-test-case-invalid');
            continue;
        }
        if (caseIds.has(caseSpec.test_id))
            errors.push(`frozen-test-case-duplicate:${caseSpec.test_id}`);
        caseIds.add(caseSpec.test_id);
        if (caseSpec.classification !== 'required' && caseSpec.classification !== 'optional') {
            errors.push(`frozen-test-case-classification-invalid:${caseSpec.test_id}`);
        }
        for (const field of NON_AUTHORITATIVE_CASE_FIELDS) {
            if (Object.hasOwn(caseSpec, field))
                errors.push(`frozen-test-case-authority-field:${field}:${caseSpec.test_id}`);
        }
    }
    const expectedSet = new Set(frozenPlan.expected);
    const requiredSet = new Set(frozenPlan.required);
    const naSet = new Set(frozenPlan.notApplicable ?? []);
    for (const id of frozenPlan.required)
        if (!expectedSet.has(id))
            errors.push(`frozen-required-not-expected:${id}`);
    for (const id of frozenPlan.expected)
        if (!caseIds.has(id))
            errors.push(`frozen-expected-not-in-plan:${id}`);
    for (const id of naSet)
        if (expectedSet.has(id))
            errors.push(`frozen-not-applicable-in-expected:${id}`);
    const covered = new Set([...frozenPlan.expected, ...naSet]);
    for (const id of caseIds)
        if (!covered.has(id))
            errors.push(`frozen-test-case-unclassified:${id}`);
    const derivedRequired = frozenPlan.testCases
        .filter((caseSpec) => caseSpec.classification === 'required')
        .map((caseSpec) => caseSpec.test_id);
    const expectedRequired = derivedRequired.filter((id) => expectedSet.has(id));
    if (!sameOrder(frozenPlan.required, expectedRequired))
        errors.push('frozen-required-classification-mismatch');
    let recomputed = null;
    try {
        recomputed = 'plan-sha256:' + sha256Hex(canonicalJson({
            testCases: frozenPlan.testCases,
            expected: frozenPlan.expected ?? [],
            required: frozenPlan.required ?? [],
            optional: frozenPlan.optional ?? [],
            planContext: frozenPlan.planContext ?? null,
            capabilitySnapshots: frozenPlan.capabilitySnapshots ?? null,
            capabilitySnapshotRefs: frozenPlan.capabilitySnapshotRefs ?? Object.create(null),
            not_applicable: frozenPlan.notApplicable ?? [],
            not_applicable_evidence: frozenPlan.notApplicableEvidence ?? Object.create(null),
            waiver_allowlist: frozenPlan.waiverAllowlist ?? [],
            budget: frozenPlan.budget ?? null,
            environment_matrix: frozenPlan.environmentMatrix ?? null,
        }));
    }
    catch (err) {
        return { ok: false, errors: [...errors, `frozen-plan-not-canonicalizable:${String(err?.message ?? err)}`], recomputed: null };
    }
    if (recomputed !== frozenPlan.plan_id)
        errors.push('plan-identity-mismatch');
    return { ok: errors.length === 0, errors, recomputed };
}
/**
 * Post-freeze mutation requests are always rejected and traced; the frozen plan
 * itself is never modified (implementation-design-control §6.2).
 *
 * @param {object} frozenPlan
 * @param {{operation?:string, test_id?:string, requestor?:string}} [mutation]
 * @param {{ now?: string }} [options]
 * @returns {{ ok: false, rejection: object }}
 */
export function rejectPlanMutation(frozenPlan, mutation = {}, options = {}) {
    const operation = typeof mutation?.operation === 'string' ? mutation.operation : 'update';
    const rejection = {
        type: 'plan_immutable_violation',
        reason: 'frozen-plan-is-immutable',
        plan_id: frozenPlan?.plan_id ?? null,
        operation,
        test_id: typeof mutation?.test_id === 'string' ? mutation.test_id : null,
        requestor: typeof mutation?.requestor === 'string' ? mutation.requestor : 'unknown',
        at: typeof options?.now === 'string' ? options.now : new Date().toISOString(),
    };
    return { ok: false, rejection: Object.freeze(rejection) };
}
/**
 * Project a frozen plan into receipt/v1 `plan_resolution` entries: every
 * candidate test case is retained (nothing silently deleted) and accepted
 * `not-applicable` items carry their predicate version / snapshot ref / reason.
 *
 * @param {object} frozenPlan
 * @returns {Array<{test_id:string, classification:string, not_applicable?:object}>}
 */
export function planResolutionEntries(frozenPlan) {
    const details = new Map();
    for (const detail of frozenPlan?.notApplicableDetails ?? []) {
        if (detail && typeof detail.test_id === 'string')
            details.set(detail.test_id, detail.not_applicable);
    }
    return (frozenPlan?.testCases ?? []).map((caseSpec) => {
        const entry = { test_id: caseSpec.test_id, classification: caseSpec.classification };
        if (details.has(caseSpec.test_id))
            entry.not_applicable = details.get(caseSpec.test_id);
        return entry;
    });
}
/**
 * A capability predicate version bound into a receipt's `plan_resolution`.
 * @param {object} policy
 * @param {string} testId
 */
export function predicateVersionFor(policy, testId) {
    const predicate = (policy?.not_applicable_predicates ?? []).find((entry) => entry.test_id === testId);
    return predicate?.predicate_version ?? CAPABILITY_PREDICATE_VERSION;
}
/** @param {object} candidate @param {string} field @param {string[]} fallback @param {Map<string,object>} caseById */
function validatedCandidateIds(candidate, field, fallback, caseById) {
    const ids = candidate[field] === undefined ? fallback : candidate[field];
    if (!Array.isArray(ids))
        throw new TypeError(`freezePlan candidate.${field} must be an array`);
    const seen = new Set();
    for (const id of ids) {
        if (!nonEmptyString(id))
            throw new TypeError(`freezePlan candidate.${field} contains malformed test_id`);
        if (seen.has(id))
            throw new TypeError(`freezePlan candidate.${field} contains duplicate test_id: ${id}`);
        if (!caseById.has(id))
            throw new TypeError(`freezePlan candidate.${field} contains unknown test_id: ${id}`);
        seen.add(id);
    }
    return [...ids];
}
function validateWaiverAllowlist(values, caseById) {
    if (!Array.isArray(values))
        throw new TypeError('freezePlan preapprovedWaivers must be an array');
    const seen = new Set();
    for (const id of values) {
        if (!nonEmptyString(id))
            throw new TypeError('freezePlan preapprovedWaivers contains malformed test_id');
        if (seen.has(id))
            throw new TypeError(`freezePlan duplicate preapproved waiver: ${id}`);
        if (!caseById.has(id))
            throw new TypeError(`freezePlan preapproved waiver is not in plan: ${id}`);
        seen.add(id);
    }
    return [...seen];
}
function sameOrder(a, b) {
    return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((id, index) => id === b[index]);
}
function nonEmptyString(value) {
    return typeof value === 'string' && value.length > 0;
}
function caseRetryError(caseSpec) {
    const retry = caseSpec?.retry;
    if (retry === undefined || retry === null)
        return null;
    if (!retry || typeof retry !== 'object' || Array.isArray(retry) ||
        (Object.getPrototypeOf(retry) !== Object.prototype && Object.getPrototypeOf(retry) !== null)) {
        return 'retry-invalid';
    }
    if (!Number.isSafeInteger(retry.max_attempts) || retry.max_attempts < 1)
        return 'retry-max-attempts-invalid';
    if (retry.max_attempts > MAX_CASE_ATTEMPTS)
        return 'retry-max-attempts-exceeds-limit';
    if (Object.hasOwn(retry, 'safe') && typeof retry.safe !== 'boolean')
        return 'retry-safe-invalid';
    return null;
}
/** Clone JSON-compatible values so the frozen digest cannot follow later mutation. */
function cloneJson(value, path) {
    if (value === null || typeof value === 'string' || typeof value === 'boolean')
        return value;
    if (typeof value === 'number' && Number.isFinite(value))
        return value;
    if (Array.isArray(value))
        return value.map((item, index) => {
            if (item === undefined)
                throw new TypeError(`non-JSON plan value at ${path}[${index}]`);
            return cloneJson(item, `${path}[${index}]`);
        });
    if (value && typeof value === 'object' && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)) {
        const out = Object.create(null);
        for (const [key, item] of Object.entries(value)) {
            if (item !== undefined)
                out[key] = cloneJson(item, `${path}.${key}`);
        }
        return out;
    }
    throw new TypeError(`non-JSON plan value at ${path}`);
}
/** cloneJson variant for internal arrays; an empty array stays an array. */
function cloneJsonJson(value) {
    return cloneJson(value, 'dataEdges');
}
/** Recursively freeze an object graph. */
function deepFreeze(value) {
    if (value === null || typeof value !== 'object' || Object.isFrozen(value))
        return value;
    for (const child of Object.values(value))
        deepFreeze(child);
    return Object.freeze(value);
}
/** Kahn topological sort; ready set always sorted by `node_id` (lexicographic). */
function stableTopo(cases) {
    const byId = new Map(cases.map((c) => [c.node_id, c]));
    const inDegree = new Map();
    const successors = new Map();
    for (const c of cases) {
        inDegree.set(c.node_id, 0);
        successors.set(c.node_id, []);
    }
    for (const c of cases) {
        for (const dep of Array.isArray(c.needs) ? c.needs : []) {
            if (byId.has(dep)) {
                inDegree.set(c.node_id, inDegree.get(c.node_id) + 1);
                successors.get(dep).push(c.node_id);
            }
        }
    }
    const ready = [];
    for (const c of cases)
        if (inDegree.get(c.node_id) === 0)
            ready.push(c.node_id);
    ready.sort();
    const order = [];
    while (ready.length) {
        const id = ready.shift();
        order.push(byId.get(id));
        for (const succ of successors.get(id)) {
            const degree = inDegree.get(succ) - 1;
            inDegree.set(succ, degree);
            if (degree === 0) {
                ready.push(succ);
                ready.sort();
            }
        }
    }
    return order;
}
