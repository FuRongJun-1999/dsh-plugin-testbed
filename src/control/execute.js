/**
 * Stable-topology execution, response verification and terminal adoption
 * (`execute/` in implementation-design-control §11, architecture §9.4 / §9.5).
 *
 * The control face dispatches frozen `expected` items in the deterministic
 * topological order, verifies every response against the correlation tuple and
 * the frozen tool schemas, then *adopts* a terminal itself:
 *
 *   - worker/adapter-supplied `verdict`, `gate_decision`, `required`,
 *     `expected` or plan changes are rejected, never adopted;
 *   - `admission_status` comes from {@link decideAdmission}, not from a
 *     caller-supplied RunSpec field;
 *   - `invocation_status=started` is written only when the adapter reports
 *     independently verified start evidence for the exact correlation tuple;
 *     worker self-reported timestamps and bare ToolResponses leave it `unknown`;
 *   - a control-plane rejection before dispatch records
 *     `rejected/skipped/skip/not-started` with a reason code.
 *
 * The returned adopted attempts are pure JSON and can be reconciled offline.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/control/execute
 */
import { EXECUTION_STATUS, VERDICT, inSet } from '../protocol/enums.js';
import { validateValue } from '../protocol/jsonschema.js';
import { decideAdmission } from './admission.js';
import { applyAssertion } from './assert.js';
import { createBudgetLedger, DEFAULT_RUN_BUDGET } from './budget.js';
import { AUTHORITY_FIELDS, normalizeAttempt, summarizeCaseState } from './state.js';
/** Adapter start-evidence sources that the control face treats as independent. */
export const CONTROL_EVIDENCE_SOURCES = Object.freeze(['adapter-lifecycle', 'adapter-witness', 'control-plane']);
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
/** @param {unknown} v */
function isPlainRecord(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
}
/** @param {unknown} v */
function nonEmptyString(v) {
    return typeof v === 'string' && v.length > 0;
}
/** @param {unknown} v */
function serializedBytes(v) {
    try {
        const text = JSON.stringify(v);
        return typeof text === 'string' ? Buffer.byteLength(text, 'utf8') : 0;
    }
    catch {
        return 0;
    }
}
/**
 * Build the bounded `test-tool/v1` request for one frozen attempt.
 * @param {object} frozenPlan
 * @param {object} caseSpec
 * @param {number} attempt
 * @param {{ runId?: string, toolBindings?: object, targetRef?: object,
 *   capabilitySnapshotRefs?: object, timeoutMs?: number, now?: () => number }} [context]
 */
export function buildToolRequest(frozenPlan, caseSpec, attempt, context = {}) {
    const testId = caseSpec.test_id;
    const runId = context.runId ?? 'run-unbound';
    const now = typeof context.now === 'function' ? context.now() : Date.now();
    const timeoutMs = Number.isSafeInteger(context.timeoutMs) && context.timeoutMs > 0 ? context.timeoutMs : 30_000;
    const binding = context.toolBindings?.[testId];
    const request = {
        protocol_version: 'test-tool/v1',
        request_id: `req-${runId}-${testId}-${attempt}`,
        run_id: runId,
        plan_id: frozenPlan.plan_id,
        test_id: testId,
        attempt,
        deadline: new Date(now + timeoutMs).toISOString(),
    };
    if (isPlainRecord(caseSpec.tool)) {
        request.tool_ref = binding?.toolRef ?? {
            tool_id: caseSpec.tool.manifest?.tool_id,
            version: caseSpec.tool.manifest?.tool_version,
            artifact_digest: caseSpec.tool.manifest?.artifact_digest,
        };
        const targetRef = context.targetRef ?? binding?.targetRef;
        if (targetRef !== undefined)
            request.target_ref = targetRef;
        request.input = caseSpec.tool.input ?? {};
        const snapshotRef = (context.capabilitySnapshotRefs ?? frozenPlan.capabilitySnapshotRefs)?.[testId];
        if (snapshotRef !== undefined)
            request.capability_snapshot_ref = snapshotRef;
    }
    else {
        const probe = isPlainRecord(caseSpec.probe) ? caseSpec.probe : {};
        request.input = {
            op: probe.op ?? 'echo',
            value: probe.value ?? null,
            delay_ms: probe.delay_ms ?? 0,
        };
        const targetRef = context.targetRef;
        if (targetRef !== undefined)
            request.target_ref = targetRef;
    }
    return request;
}
/**
 * Adopt independently verified invocation start evidence. Worker self-reported
 * `started_at` on the response envelope is ignored entirely; only an
 * adapter-attested evidence object may writer `started`.
 *
 * @param {object} outcome
 * @param {object} request
 * @returns {{ invocation_status: 'started'|'unknown', invocation_evidence_verified: boolean,
 *   started_at?: string, reason_codes: string[] }}
 */
export function adoptInvocationEvidence(outcome, request) {
    const verified = outcome?.invocation_evidence_verified === true;
    if (!verified) {
        return { invocation_status: 'unknown', invocation_evidence_verified: false, reason_codes: [] };
    }
    const evidence = outcome.invocation_evidence;
    if (evidence !== undefined) {
        if (!isPlainRecord(evidence) || !CONTROL_EVIDENCE_SOURCES.includes(evidence.source)) {
            return {
                invocation_status: 'unknown',
                invocation_evidence_verified: false,
                reason_codes: ['invocation-evidence-source-untrusted'],
            };
        }
        for (const field of ['request_id', 'run_id', 'plan_id', 'test_id', 'attempt']) {
            if (evidence[field] !== undefined && evidence[field] !== request[field]) {
                return {
                    invocation_status: 'unknown',
                    invocation_evidence_verified: false,
                    reason_codes: ['invocation-evidence-correlation-mismatch'],
                };
            }
        }
        if (evidence.started_at !== undefined &&
            (typeof evidence.started_at !== 'string' || !RFC3339.test(evidence.started_at))) {
            return {
                invocation_status: 'unknown',
                invocation_evidence_verified: false,
                reason_codes: ['invocation-evidence-timestamp-invalid'],
            };
        }
    }
    const result = { invocation_status: 'started', invocation_evidence_verified: true, reason_codes: [] };
    if (isPlainRecord(evidence) && typeof evidence.started_at === 'string')
        result.started_at = evidence.started_at;
    return result;
}
/** @param {object} outcome @param {object} request */
function findWorkerAuthorityFields(outcome) {
    const hits = [];
    if (!isPlainRecord(outcome))
        return hits;
    for (const key of Object.keys(outcome)) {
        if (AUTHORITY_FIELDS.includes(key))
            hits.push(key);
    }
    return hits;
}
/**
 * Turn a raw dispatch outcome into a control-adopted attempt.
 * Never throws for malformed responses: an invalid/late/mismatched outcome
 * becomes a non-pass controlled terminal (so reconciliation sees a terminal,
 * not a silent pass and not a fabricated success).
 *
 * @param {object} params
 * @returns {{ attempt: object, observations: object[] }}
 */
function adoptOutcome({ outcome, caseSpec, request, options }) {
    const guard = (executionStatus, verdict, reasonCodes, invocation = 'unknown') => normalizeAttempt({
        attempt: request.attempt,
        admission_status: 'accepted',
        execution_status: executionStatus,
        invocation_status: invocation,
        invocation_evidence_verified: false,
        verdict,
        reason_codes: reasonCodes,
        observation_refs: [],
    });
    if (!isPlainRecord(outcome)) {
        const fallback = guard('error', 'error', ['invalid-response']);
        return { attempt: fallback.ok ? fallback.attempt : fallback, observations: [] };
    }
    const authorityHits = findWorkerAuthorityFields(outcome);
    const correlationMismatch = ['request_id', 'run_id', 'plan_id', 'test_id', 'attempt']
        .filter((field) => outcome[field] !== undefined && outcome[field] !== request[field]);
    if (authorityHits.length > 0) {
        const fallback = guard('error', 'error', [`worker-authority-field:${authorityHits[0]}`]);
        return { attempt: fallback.ok ? fallback.attempt : fallback, observations: [] };
    }
    if (correlationMismatch.length > 0) {
        const fallback = guard('error', 'error', ['correlation-mismatch']);
        return { attempt: fallback.ok ? fallback.attempt : fallback, observations: [] };
    }
    if (request.tool_ref !== undefined && outcome.tool_ref !== undefined &&
        JSON.stringify(outcome.tool_ref) !== JSON.stringify(request.tool_ref)) {
        const fallback = guard('error', 'error', ['tool-ref-mismatch']);
        return { attempt: fallback.ok ? fallback.attempt : fallback, observations: [] };
    }
    const artifactError = validateArtifactRefs(outcome.artifact_refs, caseSpec);
    if (artifactError !== null) {
        const fallback = guard('error', 'error', [artifactError]);
        return { attempt: fallback.ok ? fallback.attempt : fallback, observations: [] };
    }
    if (!inSet(EXECUTION_STATUS, outcome.execution_status)) {
        const fallback = guard('error', 'error', ['execution-status-invalid']);
        return { attempt: fallback.ok ? fallback.attempt : fallback, observations: [] };
    }
    const evidence = adoptInvocationEvidence(outcome, request);
    const reasonCodes = Array.isArray(outcome.reason_codes)
        ? outcome.reason_codes.filter((code) => nonEmptyString(code))
        : [];
    for (const code of evidence.reason_codes)
        reasonCodes.push(code);
    // Adapter-local rejection (e.g. its own pre-dispatch check) is still a
    // control-recorded rejection, not a worker verdict.
    if (outcome.admission_status === 'rejected') {
        const attempt = normalizeAttempt({
            attempt: request.attempt,
            admission_status: 'rejected',
            execution_status: 'skipped',
            invocation_status: 'not-started',
            invocation_evidence_verified: false,
            verdict: 'skip',
            reason_codes: reasonCodes.length > 0 ? reasonCodes : ['adapter-dispatch-rejected'],
            observation_refs: [],
        });
        return { attempt: attempt.ok ? attempt.attempt : attempt, observations: [] };
    }
    const observations = Array.isArray(outcome.observations)
        ? outcome.observations.filter(isPlainRecord)
        : [];
    const observationError = validateObservations(observations, caseSpec, options);
    if (observationError !== null) {
        const fallback = guard('error', 'error', [observationError]);
        return { attempt: fallback.ok ? fallback.attempt : fallback, observations: [] };
    }
    // A late response is not adoptable as a pass/completion.
    if (options.deadline_exceeded === true && outcome.execution_status === 'completed') {
        const fallback = guard('timeout', 'error', ['deadline-exceeded']);
        return { attempt: fallback.ok ? fallback.attempt : fallback, observations };
    }
    let verdict;
    if (outcome.execution_status === 'completed') {
        if (caseSpec.criteria !== undefined) {
            const assertion = applyAssertion(observations[0]?.value ?? null, caseSpec.criteria);
            verdict = assertion.verdict;
            for (const code of assertion.reason_codes)
                reasonCodes.push(code);
        }
        else {
            verdict = 'inconclusive';
            reasonCodes.push('no-frozen-criteria');
        }
    }
    else if (outcome.execution_status === 'skipped') {
        verdict = 'skip';
    }
    else {
        verdict = 'error';
    }
    const observationRefs = observations
        .map((observation) => observation.observation_id)
        .filter(nonEmptyString);
    const input = {
        attempt: request.attempt,
        admission_status: 'accepted',
        execution_status: outcome.execution_status,
        invocation_status: evidence.invocation_status,
        invocation_evidence_verified: evidence.invocation_evidence_verified,
        verdict,
        reason_codes: reasonCodes,
        observation_refs: observationRefs,
    };
    if (evidence.started_at !== undefined)
        input.started_at = evidence.started_at;
    if (isPlainRecord(outcome) && typeof options.ended_at === 'string')
        input.ended_at = options.ended_at;
    const checked = normalizeAttempt(input);
    if (checked.ok)
        return { attempt: checked.attempt, observations };
    const fallback = guard('error', 'error', checked.errors);
    return { attempt: fallback.ok ? fallback.attempt : fallback, observations };
}
/** @param {unknown} refs @param {object} caseSpec @returns {string|null} */
function validateArtifactRefs(refs, caseSpec) {
    if (refs === undefined)
        return null;
    if (!Array.isArray(refs))
        return 'artifact-ref-invalid';
    let total = 0;
    for (const ref of refs) {
        if (!isPlainRecord(ref) || !nonEmptyString(ref.kind) ||
            typeof ref.digest !== 'string' || !SHA256.test(ref.digest) ||
            !Number.isSafeInteger(ref.size_bytes) || ref.size_bytes < 0) {
            return 'artifact-ref-invalid';
        }
        total += ref.size_bytes;
    }
    const limit = caseSpec.tool?.manifest?.limits?.attachment_bytes;
    if (Number.isSafeInteger(limit) && total > limit)
        return 'artifact-limit-exceeded';
    return null;
}
/** @param {object[]} observations @param {object} caseSpec @param {object} options */
function validateObservations(observations, caseSpec, options) {
    const schema = caseSpec.tool?.manifest?.observation_schema;
    for (const observation of observations) {
        if (!nonEmptyString(observation.observation_id))
            return 'observation-id-invalid';
        if (observation.source !== undefined && observation.source !== 'worker')
            return 'observation-source-invalid';
        if (schema !== undefined) {
            const checked = validateValue(observation.value, schema);
            if (!checked.ok)
                return 'observation-schema-invalid';
        }
    }
    const limits = caseSpec.tool?.manifest?.limits;
    if (isPlainRecord(limits) && Number.isSafeInteger(limits.output_bytes)) {
        if (serializedBytes(observations) > limits.output_bytes)
            return 'output-limit-exceeded';
    }
    return null;
}
/**
 * Execute a frozen plan in deterministic topological order through a dispatch
 * port (dependency inversion; `control/` never imports adapters/worker).
 *
 * Supported ports:
 *   - design `DispatchPort`: `{ dispatchToolRequest(request, signal) }`
 *   - legacy local port: `{ execute(caseSpec, runId, planId, attempt) }`
 *
 * @param {object} frozenPlan
 * @param {object} dispatchPort
 * @param {{ runId?: string, signal?: AbortSignal, budget?: object,
 *   budgetLedger?: object, toolBindings?: object, targetRef?: object,
 *   timeoutMs?: number, now?: () => number }} [options]
 * @returns {Promise<{plan_id:string, run_id:string, recordsByTestId:object,
 *   adoptedAttempts:object[], observations:object[], admission_decisions:object[],
 *   cancelled:boolean, budget_exceeded:string|null, budget:object|null}>}
 */
export async function executeFrozenPlan(frozenPlan, dispatchPort, options = {}) {
    if (!isPlainRecord(frozenPlan) || !nonEmptyString(frozenPlan.plan_id)) {
        throw new TypeError('executeFrozenPlan frozenPlan.plan_id is required');
    }
    if (!Array.isArray(frozenPlan.expected))
        throw new TypeError('executeFrozenPlan frozenPlan.expected must be an array');
    if (!isPlainRecord(dispatchPort))
        throw new TypeError('executeFrozenPlan dispatchPort must be an object');
    const runId = options.runId ?? 'run-unbound';
    const timeoutMs = Number.isSafeInteger(options.timeoutMs) && options.timeoutMs > 0 ? options.timeoutMs : 30_000;
    const clock = typeof options.now === 'function' ? options.now : Date.now;
    const budgetLedger = options.budgetLedger ?? createBudgetLedger(options.budget ?? DEFAULT_RUN_BUDGET);
    const caseById = new Map((frozenPlan.testCases ?? []).map((caseSpec) => [caseSpec.test_id, caseSpec]));
    const expectedSet = new Set(frozenPlan.expected);
    const order = [];
    for (const id of (frozenPlan.testOrder ?? frozenPlan.expected)) {
        if (expectedSet.has(id) && !order.includes(id))
            order.push(id);
    }
    for (const id of frozenPlan.expected)
        if (!order.includes(id))
            order.push(id);
    const recordsByTestId = Object.create(null);
    const adoptedAttempts = [];
    const observations = [];
    const admissionDecisions = [];
    let cancelled = false;
    let budgetExceeded = null;
    outer: for (const testId of order) {
        if (options.signal?.aborted) {
            cancelled = true;
            break;
        }
        const caseSpec = caseById.get(testId);
        if (!caseSpec)
            continue;
        const maxAttempts = Math.max(1, caseSpec.retry?.max_attempts ?? 1);
        const attempts = [];
        const decision = decideAdmission(caseSpec, {
            expectedSet,
            toolBindings: options.toolBindings,
            budgetLedger,
            targetRef: options.targetRef,
            signal: options.signal,
        });
        admissionDecisions.push({ test_id: testId, attempt: 1, ...decision });
        if (decision.admission_status === 'rejected') {
            const rejected = normalizeAttempt({
                attempt: 1,
                admission_status: 'rejected',
                execution_status: 'skipped',
                invocation_status: 'not-started',
                verdict: 'skip',
                reason_codes: [...decision.reason_codes],
                observation_refs: [],
            });
            if (!rejected.ok)
                throw new TypeError(`executeFrozenPlan admission terminal invalid: ${rejected.errors.join(',')}`);
            attempts.push(rejected.attempt);
            const summary = summarizeCaseState(testId, caseSpec.classification, attempts, extraFor(caseSpec));
            recordsByTestId[testId] = summary.record;
            for (const attempt of attempts)
                adoptedAttempts.push({ test_id: testId, plan_id: frozenPlan.plan_id, attempt });
            if (decision.reason_codes.includes('budget_exhausted')) {
                budgetExceeded = decision.reason_codes[0];
                break outer;
            }
            continue;
        }
        for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
            if (options.signal?.aborted) {
                cancelled = true;
                break outer;
            }
            const reserveReason = budgetLedger.reserveAttempt();
            if (reserveReason) {
                budgetExceeded = reserveReason;
                break outer;
            }
            const request = buildToolRequest(frozenPlan, caseSpec, attempt, {
                runId,
                toolBindings: options.toolBindings,
                targetRef: options.targetRef,
                capabilitySnapshotRefs: frozenPlan.capabilitySnapshotRefs,
                timeoutMs,
                now: clock,
            });
            const startedWall = clock();
            let outcome;
            try {
                outcome = await dispatch(dispatchPort, caseSpec, request, options.signal);
            }
            catch (err) {
                outcome = {
                    admission_status: 'accepted',
                    execution_status: 'error',
                    invocation_status: 'unknown',
                    observations: [],
                    reason_codes: ['dispatch-error'],
                    diagnostic: String(err?.message ?? err),
                };
            }
            const elapsedMs = Math.max(0, clock() - startedWall);
            const outputBytes = serializedBytes(isPlainRecord(outcome) ? outcome.observations : []);
            const recordReason = budgetLedger.record({ elapsed_ms: elapsedMs, output_bytes: outputBytes });
            const adopted = adoptOutcome({
                outcome,
                caseSpec,
                request,
                options: {
                    deadline_exceeded: elapsedMs > timeoutMs,
                    ended_at: new Date(clock()).toISOString(),
                },
            });
            attempts.push(adopted.attempt);
            observations.push(...adopted.observations);
            if (recordReason)
                budgetExceeded = recordReason;
            if (adopted.attempt.verdict === 'pass')
                break;
            if (budgetExceeded)
                break;
        }
        if (attempts.length > 0) {
            const summary = summarizeCaseState(testId, caseSpec.classification, attempts, extraFor(caseSpec));
            if (!summary.ok)
                throw new TypeError(`executeFrozenPlan case state invalid: ${summary.errors.join(',')}`);
            recordsByTestId[testId] = summary.record;
            for (const attempt of attempts)
                adoptedAttempts.push({ test_id: testId, plan_id: frozenPlan.plan_id, attempt });
        }
        if (budgetExceeded)
            break;
    }
    return {
        plan_id: frozenPlan.plan_id,
        run_id: runId,
        recordsByTestId,
        adoptedAttempts,
        observations,
        admission_decisions: admissionDecisions,
        cancelled,
        budget_exceeded: budgetExceeded,
        budget: budgetLedger.snapshot(),
    };
}
/** @param {object} caseSpec */
function extraFor(caseSpec) {
    return {
        dimensions: caseSpec?.dimensions,
        criteria_ref: caseSpec?.criteria?.ref ?? caseSpec?.criteria?.criteria_ref ?? `criteria/${caseSpec?.test_id}`,
    };
}
/** Dispatch through either the design port or the legacy local adapter port. */
async function dispatch(port, caseSpec, request, signal) {
    if (typeof port.dispatchToolRequest === 'function') {
        return port.dispatchToolRequest(request, signal);
    }
    if (typeof port.execute === 'function') {
        return port.execute(caseSpec, request.run_id, request.plan_id, request.attempt);
    }
    throw new TypeError('dispatchPort must expose dispatchToolRequest() or execute()');
}
/** Adopt a worker ToolResponse / attempt terminal (exported for unit tests). */
export function adoptToolOutcome(outcome, caseSpec, request, options = {}) {
    return adoptOutcome({ outcome, caseSpec, request, options });
}
/** @param {unknown} id */
export function isSha256Ref(id) {
    return typeof id === 'string' && SHA256.test(id);
}
/** Assert control-plane verification evidence for offline recomputation. */
export function isVerifiedStarted(record) {
    return !!record && record.invocation_status === 'started' &&
        record.invocation_evidence_verified === true && VERDICT.includes(record.verdict);
}
