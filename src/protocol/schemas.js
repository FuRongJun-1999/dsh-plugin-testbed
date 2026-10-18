/**
 * Strict, declarative protocol schemas (JSON Schema Draft 2020-12).
 *
 * This module is the single schema authority for the versioned artifacts
 * registered by `implementation-design-protocol.md` §1:
 *
 *   receipt/v1, run-spec/v1, gate-policy/v1, plan-candidate/v1, plan/v1,
 *   test-tool-manifest/v1, test-tool/v1 (request + response).
 *
 * Every schema closes its declared surface (`additionalProperties:false` where
 * the contract allows no unnamespaced extension), pins the version string with
 * `const`, and references the closed enums of `enums.js`. The three
 * `receipt/v1` forms are statically forced by `oneOf` — `plan_id === null`
 * implies `reconciliation === null` (architecture §11.2.1). Signed forms and
 * `market_eligible=true` are structurally unrepresentable: the MVP has no
 * signing shape and no market-eligibility path.
 *
 * These are *types/contracts*, not algorithms: no aggregation, reconciliation
 * or gate result is computed here. Executable fail-closed guards that need
 * cross-field reasoning live in `contracts.js`.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/protocol/schemas
 */
import { ADMISSION_STATUS, CAPABILITY_OBSERVED, DETERMINISM_VALUES, EXECUTION_STATUS, GATE_DECISION, GATE_POLICY_VERSION, INVOCATION_STATUS, OBSERVATION_SOURCE, PLAN_CANDIDATE_VERSION, PLAN_VERSION, RECEIPT_SCHEMA_VERSION, RUN_SPEC_VERSION, RUN_STATUS, TEST_CLASSIFICATION, TEST_TOOL_MANIFEST_VERSION, TEST_TOOL_PROTOCOL_VERSION, TOOL_PERMISSION_KEYS, TOOL_ROLE, VERDICT, } from './enums.js';
import { MAX_MANIFEST_LIMITS, MAX_RETRY_ATTEMPTS, TOOL_VERSION_PATTERN } from './tool-manifest.js';
import { CORRELATION_FIELDS, TOOL_REQUEST_FIELDS, TOOL_RESPONSE_FIELDS, TOOL_REF_FIELDS, TARGET_REF_FIELDS, } from './transport.js';
// ---------------------------------------------------------------------------
// Version guards — exact match only. Unknown/incompatible major versions are
// rejected, never implicitly downgraded (architecture §8.4.1, §11.2.1;
// development-plan「版本边界」).
// ---------------------------------------------------------------------------
/** @param {string} v */
export function isReceiptSchemaVersion(v) {
    return v === RECEIPT_SCHEMA_VERSION;
}
/** @param {string} v */
export function isRunSpecVersion(v) {
    return v === RUN_SPEC_VERSION;
}
/** @param {string} v */
export function isGatePolicyVersion(v) {
    return v === GATE_POLICY_VERSION;
}
/** @param {string} v */
export function isPlanCandidateVersion(v) {
    return v === PLAN_CANDIDATE_VERSION;
}
/** @param {string} v */
export function isPlanVersion(v) {
    return v === PLAN_VERSION;
}
/** @param {string} v */
export function isTestToolManifestVersion(v) {
    return v === TEST_TOOL_MANIFEST_VERSION;
}
/** @param {string} v */
export function isTestToolProtocolVersion(v) {
    return v === TEST_TOOL_PROTOCOL_VERSION;
}
// ---------------------------------------------------------------------------
// Shared fragments
// ---------------------------------------------------------------------------
const JSON_SCHEMA_DIALECT = 'https://json-schema.org/draft/2020-12/schema';
const NON_EMPTY = Object.freeze({ type: 'string', minLength: 1 });
const SHA256 = Object.freeze({ type: 'string', pattern: '^sha256:[0-9a-f]{64}$' });
const PLAN_SHA256 = Object.freeze({ type: 'string', pattern: '^plan-sha256:[0-9a-f]{64}$' });
const CAP_SHA256 = Object.freeze({ type: 'string', pattern: '^cap-sha256:[0-9a-f]{64}$' });
const RFC3339 = Object.freeze({
    type: 'string',
    pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:\\d{2})$',
});
const ID_ARRAY = Object.freeze({ type: 'array', items: NON_EMPTY, uniqueItems: true });
const NULL = Object.freeze({ type: 'null' });
/**
 * A versioned `{id, version, digest}` reference. Receipt references must bind
 * a content digest; RunSpec references may omit it before a plan is frozen.
 * @param {{ requireDigest: boolean }} options
 */
function versionRefSchema({ requireDigest }) {
    const properties = { id: NON_EMPTY, version: NON_EMPTY, digest: SHA256 };
    const required = requireDigest ? ['id', 'version', 'digest'] : ['id', 'version'];
    return { type: 'object', required, properties, additionalProperties: false };
}
const RECEIPT_VERSION_REF = versionRefSchema({ requireDigest: true });
const RUN_SPEC_VERSION_REF = versionRefSchema({ requireDigest: false });
const TOOL_REF = Object.freeze({
    type: 'object',
    required: TOOL_REF_FIELDS,
    additionalProperties: false,
    properties: {
        tool_id: NON_EMPTY,
        version: NON_EMPTY,
        artifact_digest: SHA256,
    },
});
const TARGET_REF = Object.freeze({
    type: 'object',
    required: TARGET_REF_FIELDS,
    additionalProperties: false,
    properties: {
        kind: NON_EMPTY,
        owner_put_digest: SHA256,
        origin: NON_EMPTY,
    },
});
const PLAN_CANDIDATE_REF = Object.freeze({
    type: 'object',
    required: ['digest', 'baseline_test_ids', 'required_test_ids'],
    additionalProperties: false,
    properties: {
        digest: SHA256,
        baseline_test_ids: ID_ARRAY,
        required_test_ids: ID_ARRAY,
    },
});
const RECONCILIATION = Object.freeze({
    type: 'object',
    required: ['expected', 'executed', 'missing', 'waived'],
    additionalProperties: false,
    properties: {
        expected: ID_ARRAY,
        executed: ID_ARRAY,
        missing: ID_ARRAY,
        waived: ID_ARRAY,
        // Control-plane-derived subset of `missing`; never forged by exporters.
        missing_required: ID_ARRAY,
    },
});
const INTEGRITY = Object.freeze({
    type: 'object',
    required: ['record_digest', 'signed'],
    additionalProperties: false,
    properties: {
        record_digest: SHA256,
        signed: { const: false },
    },
});
const PLAN_RESOLUTION_ENTRY = Object.freeze({
    type: 'object',
    required: ['test_id', 'classification'],
    additionalProperties: false,
    properties: {
        test_id: NON_EMPTY,
        classification: { enum: TEST_CLASSIFICATION },
        // P-6: a `not-applicable` entry keeps its predicate version, verified
        // snapshot reference and reason so nothing is silently deleted.
        not_applicable: {
            type: 'object',
            required: ['predicate_version', 'capability_snapshot_ref', 'reason'],
            additionalProperties: false,
            properties: {
                predicate_version: NON_EMPTY,
                capability_snapshot_ref: CAP_SHA256,
                reason: NON_EMPTY,
            },
        },
    },
});
const DIMENSIONS = Object.freeze({
    type: 'object',
    additionalProperties: false,
    properties: {
        test_level: { type: 'string' },
        test_type: { type: 'array', items: { type: 'string' } },
        test_technique: { type: 'array', items: { type: 'string' } },
        trigger: { type: 'string' },
        suite_profile: { type: 'string' },
        target_kind: { type: 'string' },
        execution_mode: { type: 'string' },
        repeatability: { type: 'string' },
        evidence_kind: { type: 'array', items: { type: 'string' } },
    },
});
const OBSERVATION = Object.freeze({
    type: 'object',
    required: ['observation_id', 'schema_ref', 'value', 'source', 'limitations'],
    additionalProperties: false,
    properties: {
        observation_id: NON_EMPTY,
        schema_ref: NON_EMPTY,
        value: Object.freeze({}), // constrained by the manifest observation_schema
        source: { enum: OBSERVATION_SOURCE },
        limitations: { type: 'array', items: { type: 'string' } },
    },
});
const WORKER_OBSERVATION = Object.freeze({
    type: 'object',
    required: ['observation_id', 'schema_ref', 'value', 'source', 'limitations'],
    additionalProperties: false,
    properties: {
        observation_id: NON_EMPTY,
        schema_ref: NON_EMPTY,
        value: Object.freeze({}),
        source: { const: 'worker' }, // §8.4.2: the worker cannot claim other sources
        limitations: { type: 'array', items: { type: 'string' } },
    },
});
const ARTIFACT_REF = Object.freeze({
    type: 'object',
    required: ['kind', 'digest', 'size_bytes'],
    additionalProperties: false,
    properties: {
        kind: NON_EMPTY,
        digest: SHA256,
        size_bytes: { type: 'integer', minimum: 0 },
    },
});
const ATTEMPT = Object.freeze({
    type: 'object',
    required: ['attempt', 'admission_status', 'execution_status', 'invocation_status', 'verdict'],
    additionalProperties: false,
    properties: {
        attempt: { type: 'integer', minimum: 1 },
        admission_status: { enum: ADMISSION_STATUS },
        execution_status: { enum: EXECUTION_STATUS },
        invocation_status: { enum: INVOCATION_STATUS },
        verdict: { enum: VERDICT },
        // Only written when a control-verified start event exists (§6.1, §9.5).
        started_at: RFC3339,
        ended_at: RFC3339,
        observation_refs: { type: 'array', items: NON_EMPTY },
        reason_codes: { type: 'array', items: NON_EMPTY },
        invocation_evidence_verified: { type: 'boolean' },
    },
});
const TEST_CASE = Object.freeze({
    type: 'object',
    required: ['test_id', 'dimensions', 'attempts', 'verdict', 'criteria_ref', 'reason_codes'],
    additionalProperties: false,
    properties: {
        test_id: NON_EMPTY,
        dimensions: DIMENSIONS,
        attempts: { type: 'array', minItems: 1, items: ATTEMPT },
        verdict: { enum: VERDICT },
        criteria_ref: NON_EMPTY,
        reason_codes: { type: 'array', items: NON_EMPTY },
        classification: { enum: ['required', 'optional'] },
        admission_status: { enum: ADMISSION_STATUS },
        execution_status: { enum: EXECUTION_STATUS },
        invocation_status: { enum: INVOCATION_STATUS },
        invocation_evidence_verified: { type: 'boolean' },
        observation_refs: { type: 'array', items: NON_EMPTY },
    },
});
const CLEANUP_REPORT = Object.freeze({
    type: 'object',
    required: ['pid_alive', 'temp_removed'],
    additionalProperties: false,
    properties: {
        pid_alive: { type: 'boolean' },
        temp_removed: { type: 'boolean' },
    },
});
/** A required provenance key whose value may be explicitly `null` (§11.2.1). */
function nullableText() {
    return { type: ['string', 'null'], minLength: 1 };
}
const PROVENANCE = Object.freeze({
    type: 'object',
    // Resource/environment details required by §11.2.1「实现必须额外保留」.
    // Missing values stay explicitly null; they are never silently dropped.
    required: [
        'put_digest', 'dsh_commit', 'cordis_version', 'adapter_ref', 'tool_refs',
        'assertion_refs', 'policy_ref', 'environment_fingerprint',
    ],
    additionalProperties: false,
    properties: {
        put_digest: { type: ['string', 'null'], pattern: '^sha256:[0-9a-f]{64}$' },
        dsh_commit: nullableText(),
        cordis_version: nullableText(),
        adapter_ref: nullableText(),
        tool_refs: { type: 'array', items: TOOL_REF },
        assertion_refs: { type: 'array', items: { type: 'string' } },
        policy_ref: { oneOf: [RECEIPT_VERSION_REF, NULL] },
        environment_fingerprint: { type: ['string', 'null'], pattern: '^sha256:[0-9a-f]{64}$' },
        // P-1 recommended extensions — optional, closed set, no signing shape.
        node_version: nullableText(),
        os_ref: nullableText(),
        os_platform: nullableText(),
        os_arch: nullableText(),
        worker_ref: nullableText(),
        isolation: nullableText(),
        capability_snapshot_ref: { type: ['string', 'null'], pattern: '^cap-sha256:[0-9a-f]{64}$' },
        granted_permissions: { type: ['object', 'null'] },
        random_seed: nullableText(),
        budget_usage: { type: ['object', 'null'] },
        run_budget: { type: ['object', 'null'] },
        budget_actuals: { type: ['object', 'null'] },
        redaction_status: nullableText(),
        launch_record: { type: ['object', 'null'] },
        cleanup: { oneOf: [CLEANUP_REPORT, NULL] },
        cleanup_failure: { type: ['object', 'null'] },
    },
});
// ---------------------------------------------------------------------------
// receipt/v1 — architecture §11.2.1; implementation-design-protocol §2.
// The always-present fields (A), the frozen-only fields (B) and the pre-plan
// fields (C) are combined through `oneOf`, so the three mutually-exclusive
// forms are enforced by the schema itself, not by convention.
// ---------------------------------------------------------------------------
const RECEIPT_ALWAYS_FIELDS = Object.freeze([
    'receipt_schema_version',
    'run_id',
    'plan_id',
    'scenario_ref',
    'profile_ref',
    'target_ref',
    'trust_scope',
    'market_eligible',
    'run_status',
    'gate_decision',
    'plan_candidate_ref',
    'provenance',
    'limitations',
    'integrity',
]);
const RECEIPT_FORM_FIELDS = Object.freeze([
    'plan_resolution',
    'reconciliation',
    'test_cases',
    'observations',
    'artifacts',
]);
const RECEIPT_FROZEN_FORM = Object.freeze({
    required: ['plan_id', 'plan_resolution', 'reconciliation'],
    properties: {
        plan_id: PLAN_SHA256,
        plan_resolution: { type: 'array', items: PLAN_RESOLUTION_ENTRY },
        reconciliation: RECONCILIATION,
    },
    // C-group fields belong only to the two pre-plan forms.
    not: Object.freeze({
        anyOf: Object.freeze([
            { required: ['blocked_stage'] },
            { required: ['cancelled_stage'] },
            { required: ['reason_codes'] },
        ]),
    }),
});
const RECEIPT_PRE_PLAN_COMMON = Object.freeze({
    required: [
        'plan_id', 'reconciliation', 'plan_resolution', 'run_status',
        'gate_decision', 'test_cases', 'observations', 'artifacts', 'reason_codes',
    ],
    properties: {
        plan_id: NULL,
        reconciliation: NULL,
        plan_resolution: NULL,
        gate_decision: { const: 'blocked' },
        test_cases: { type: 'array', maxItems: 0 },
        observations: { type: 'array', maxItems: 0 },
        artifacts: { type: 'array', maxItems: 0 },
        reason_codes: { type: 'array', minItems: 1, items: NON_EMPTY },
    },
});
const RECEIPT_PRE_PLAN_BLOCKED_FORM = Object.freeze({
    required: [...RECEIPT_PRE_PLAN_COMMON.required, 'blocked_stage'],
    properties: {
        ...RECEIPT_PRE_PLAN_COMMON.properties,
        run_status: { const: 'blocked' },
        blocked_stage: NON_EMPTY,
    },
    not: Object.freeze({ required: ['cancelled_stage'] }),
});
const RECEIPT_PRE_PLAN_CANCELLED_FORM = Object.freeze({
    required: [...RECEIPT_PRE_PLAN_COMMON.required, 'cancelled_stage'],
    properties: {
        ...RECEIPT_PRE_PLAN_COMMON.properties,
        run_status: { const: 'cancelled' },
        cancelled_stage: NON_EMPTY,
    },
    not: Object.freeze({ required: ['blocked_stage'] }),
});
/** `receipt/v1` — the only authoritative result JSON (architecture §11.2.1). */
export const RECEIPT_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:receipt:v1',
    title: 'receipt/v1',
    type: 'object',
    required: [...RECEIPT_ALWAYS_FIELDS, ...RECEIPT_FORM_FIELDS],
    additionalProperties: false,
    properties: {
        receipt_schema_version: { const: RECEIPT_SCHEMA_VERSION },
        run_id: NON_EMPTY,
        plan_id: { type: ['string', 'null'], pattern: PLAN_SHA256.pattern },
        scenario_ref: { oneOf: [RECEIPT_VERSION_REF, NULL] },
        profile_ref: { oneOf: [RECEIPT_VERSION_REF, NULL] },
        target_ref: { oneOf: [TARGET_REF, NULL] },
        trust_scope: { const: 'local-only' },
        market_eligible: { const: false },
        run_status: { enum: RUN_STATUS },
        gate_decision: { enum: GATE_DECISION },
        plan_candidate_ref: { oneOf: [PLAN_CANDIDATE_REF, NULL] },
        provenance: PROVENANCE,
        limitations: { type: 'array', minItems: 1, items: { type: 'string' } },
        integrity: INTEGRITY,
        plan_resolution: { oneOf: [{ type: 'array', items: PLAN_RESOLUTION_ENTRY }, NULL] },
        reconciliation: { oneOf: [RECONCILIATION, NULL] },
        test_cases: { type: 'array', items: TEST_CASE },
        observations: { type: 'array', items: OBSERVATION },
        artifacts: { type: 'array', items: ARTIFACT_REF },
        // C-group: only present in the two pre-plan forms.
        blocked_stage: NON_EMPTY,
        cancelled_stage: NON_EMPTY,
        reason_codes: { type: 'array', minItems: 1, items: NON_EMPTY },
    },
    oneOf: [RECEIPT_FROZEN_FORM, RECEIPT_PRE_PLAN_BLOCKED_FORM, RECEIPT_PRE_PLAN_CANCELLED_FORM],
});
// ---------------------------------------------------------------------------
// run-spec/v1 — fixed input to a run (architecture §9.1, §12;
// implementation-design-protocol §6.1). v1 shape is the realized local
// contract: a pinned target, a bounded scenario case list and versioned
// profile/policy references. The case-list compiler owns DAG validation.
// ---------------------------------------------------------------------------
const CRITERIA = Object.freeze({
    type: 'object',
    required: ['assert'],
    additionalProperties: false,
    properties: {
        assert: { enum: ['equals', 'contains', 'schema-valid', 'numeric-range', 'finding-count'] },
        path: { type: ['string', 'array'] },
        expected: Object.freeze({}),
        schema: { type: 'object' },
        min: { type: 'number' },
        max: { type: 'number' },
        ref: NON_EMPTY,
        criteria_ref: NON_EMPTY,
    },
});
const CAPABILITY_PREDICATE = Object.freeze({
    type: 'object',
    required: ['observed'],
    additionalProperties: false,
    properties: {
        observed: { enum: CAPABILITY_OBSERVED },
        verification: { const: 'corroborated' },
    },
});
const RUN_SPEC_CASE = Object.freeze({
    type: 'object',
    required: ['test_id', 'node_id', 'classification'],
    additionalProperties: false,
    properties: {
        test_id: NON_EMPTY,
        node_id: NON_EMPTY,
        classification: { enum: ['required', 'optional'] },
        needs: { type: 'array', items: NON_EMPTY, uniqueItems: true },
        dimensions: DIMENSIONS,
        criteria: CRITERIA,
        // Adapter-specific observation producer payload (L0/L1); the worker adapter
        // owns its shape and never turns it into a verdict or gate decision.
        probe: { type: 'object' },
        // Manifest tool binding; manifest/input are validated by control at intake.
        tool: {
            type: 'object',
            required: ['manifest', 'input'],
            additionalProperties: false,
            properties: {
                manifest: { type: 'object' },
                input: Object.freeze({}),
                artifactPath: NON_EMPTY,
                workspaceRoot: NON_EMPTY,
            },
        },
        retry: {
            type: 'object',
            required: ['safe', 'max_attempts'],
            additionalProperties: false,
            properties: {
                safe: { type: 'boolean' },
                max_attempts: { type: 'integer', minimum: 1, maximum: MAX_RETRY_ATTEMPTS },
            },
        },
        not_applicable_when: CAPABILITY_PREDICATE,
    },
});
/** `run-spec/v1` — caller-declared run input, closed and version-pinned. */
export const RUN_SPEC_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:run-spec:v1',
    title: 'run-spec/v1',
    type: 'object',
    required: ['schema_version', 'target', 'scenario'],
    additionalProperties: false,
    properties: {
        schema_version: { const: RUN_SPEC_VERSION },
        target: {
            type: 'object',
            required: ['kind', 'put_digest'],
            additionalProperties: false,
            properties: {
                kind: { enum: ['source', 'package', 'plugin', 'api', 'service', 'system', 'external-owned'] },
                put_digest: SHA256,
                origin: NON_EMPTY,
            },
        },
        scenario: {
            type: 'object',
            required: ['cases'],
            additionalProperties: false,
            properties: {
                cases: { type: 'array', minItems: 1, items: RUN_SPEC_CASE },
            },
        },
        profile_ref: { oneOf: [RUN_SPEC_VERSION_REF, NULL] },
        scenario_ref: { oneOf: [RUN_SPEC_VERSION_REF, NULL] },
        policy_ref: { oneOf: [RUN_SPEC_VERSION_REF, NULL] },
        policy: {
            type: 'object',
            additionalProperties: false,
            properties: {
                // `run-budget/v1` schema is owned by control/budget.js; this module only
                // registers the envelope slot, not the budget algorithm.
                budget: { type: 'object' },
                preapproved_waivers: { type: 'array', items: NON_EMPTY, uniqueItems: true },
            },
        },
    },
});
// ---------------------------------------------------------------------------
// gate-policy/v1 — frozen policy declaration (architecture §6.1, §9.1;
// implementation-design-protocol §6.2). Aggregation precedence is only a
// declaration: the algorithm belongs to the control plane.
// ---------------------------------------------------------------------------
const POLICY_PREDICATE = Object.freeze({
    type: 'object',
    required: ['test_id', 'observed'],
    additionalProperties: false,
    properties: {
        test_id: NON_EMPTY,
        predicate_version: NON_EMPTY,
        observed: { enum: CAPABILITY_OBSERVED },
        verification: { const: 'corroborated' },
    },
});
const WAIVER_RULE = Object.freeze({
    type: 'object',
    required: ['test_id'],
    additionalProperties: false,
    properties: {
        test_id: NON_EMPTY,
        scope: { enum: ['preapproved'] },
        reason: NON_EMPTY,
    },
});
/** `gate-policy/v1` — required/optional baseline, predicates and waivers. */
export const GATE_POLICY_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:gate-policy:v1',
    title: 'gate-policy/v1',
    type: 'object',
    required: [
        'schema_version', 'required_baseline', 'optional_baseline',
        'not_applicable_predicates', 'waiver_rules', 'aggregation',
    ],
    additionalProperties: false,
    properties: {
        schema_version: { const: GATE_POLICY_VERSION },
        required_baseline: ID_ARRAY,
        optional_baseline: ID_ARRAY,
        not_applicable_predicates: { type: 'array', items: POLICY_PREDICATE },
        waiver_rules: { type: 'array', items: WAIVER_RULE },
        aggregation: {
            type: 'object',
            required: ['precedence'],
            additionalProperties: false,
            properties: {
                // Declaration only; the frozen order is blocked > reject > pass (§6.1).
                precedence: { type: 'array', minItems: 3, maxItems: 3, uniqueItems: true, items: { enum: GATE_DECISION } },
            },
        },
    },
});
// ---------------------------------------------------------------------------
// plan-candidate/v1 and plan/v1 — public type shapes (architecture §9.4;
// implementation-design-protocol §6.3–6.4). Compilation/freezing algorithms
// are owned by control.
// ---------------------------------------------------------------------------
/** `plan-candidate/v1` — non-removable baseline before plan freeze. */
export const PLAN_CANDIDATE_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:plan-candidate:v1',
    title: 'plan-candidate/v1',
    type: 'object',
    required: ['schema_version', 'baseline_test_ids', 'required_test_ids', 'digest'],
    additionalProperties: false,
    properties: {
        schema_version: { const: PLAN_CANDIDATE_VERSION },
        baseline_test_ids: ID_ARRAY,
        required_test_ids: ID_ARRAY,
        nodes: { type: 'array', items: { type: 'object' } },
        node_refs: { type: 'array', items: { type: 'object' } },
        digest: SHA256,
    },
});
/** `plan/v1` — immutable frozen plan (never modified after freeze). */
export const PLAN_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:plan:v1',
    title: 'plan/v1',
    type: 'object',
    required: ['schema_version', 'plan_id', 'expected', 'classification'],
    additionalProperties: false,
    properties: {
        schema_version: { const: PLAN_VERSION },
        plan_id: PLAN_SHA256,
        expected: ID_ARRAY,
        classification: {
            type: 'object',
            required: ['required', 'optional', 'not_applicable'],
            additionalProperties: false,
            properties: {
                required: ID_ARRAY,
                optional: ID_ARRAY,
                not_applicable: ID_ARRAY,
            },
        },
        attempt_limits: {
            type: 'object',
            additionalProperties: false,
            properties: {
                max_attempts_per_case: { type: 'integer', minimum: 1, maximum: MAX_RETRY_ATTEMPTS },
                max_total_attempts: { type: 'integer', minimum: 1 },
            },
        },
        retry_budget: { type: 'object' },
        budget: { type: 'object' },
        environment_matrix: { type: 'object' },
        node_metadata: { type: 'array', items: { type: 'object' } },
    },
});
// ---------------------------------------------------------------------------
// test-tool-manifest/v1 — static declaration (§8.4.1). Unknown top-level
// fields are namespaced extension candidates and remain warnings in the
// executable validator (CONTRACT-m5 §2); everything declared here is closed.
// ---------------------------------------------------------------------------
const MANIFEST_LIMIT_PROPERTIES = {};
for (const [field, maximum] of Object.entries(MAX_MANIFEST_LIMITS)) {
    MANIFEST_LIMIT_PROPERTIES[field] = { type: 'integer', minimum: 1, maximum };
}
const PERMISSION_PROPERTIES = {};
for (const key of TOOL_PERMISSION_KEYS) {
    PERMISSION_PROPERTIES[key] = { type: 'array', items: { type: 'string' } };
}
/** `test-tool-manifest/v1` — declarative tool manifest (not a permission proof). */
export const TEST_TOOL_MANIFEST_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:test-tool-manifest:v1',
    title: 'test-tool-manifest/v1',
    type: 'object',
    required: [
        'schema_version', 'tool_id', 'tool_version', 'artifact_digest', 'role',
        'runner', 'input_schema', 'observation_schema', 'requires', 'permissions',
        'limits', 'determinism', 'retry',
    ],
    // Namespaced extensions are permitted by §8.4.1; the executable validator
    // reports unknown un-namespaced fields as warnings (CONTRACT-m5 §2).
    additionalProperties: true,
    properties: {
        schema_version: { const: TEST_TOOL_MANIFEST_VERSION },
        tool_id: NON_EMPTY,
        tool_version: { type: 'string', pattern: TOOL_VERSION_PATTERN },
        artifact_digest: SHA256,
        role: { enum: TOOL_ROLE },
        tags: { type: 'array', items: NON_EMPTY },
        runner: {
            type: 'object',
            required: ['adapter', 'entrypoint'],
            additionalProperties: false,
            properties: { adapter: NON_EMPTY, entrypoint: NON_EMPTY },
        },
        input_schema: { type: 'object' },
        observation_schema: { type: 'object' },
        requires: { type: 'array', items: NON_EMPTY },
        permissions: { type: 'object', additionalProperties: false, properties: PERMISSION_PROPERTIES },
        limits: {
            type: 'object',
            required: Object.keys(MAX_MANIFEST_LIMITS),
            additionalProperties: false,
            properties: MANIFEST_LIMIT_PROPERTIES,
        },
        determinism: { enum: DETERMINISM_VALUES },
        retry: {
            type: 'object',
            required: ['safe', 'max_attempts'],
            additionalProperties: false,
            properties: {
                safe: { type: 'boolean' },
                max_attempts: { type: 'integer', minimum: 1, maximum: MAX_RETRY_ATTEMPTS },
            },
        },
        evidence: { type: 'object' },
        compatibility: { type: 'object' },
    },
});
// ---------------------------------------------------------------------------
// test-tool/v1 — closed request/response envelopes (§8.4.2). Correlation
// echo is enforced executably by transport.js; these schemas fix the fields,
// version and enums, and cannot carry verdict/gate/plan-modifying authority.
// ---------------------------------------------------------------------------
const CORRELATION_PROPERTIES = Object.freeze({
    request_id: NON_EMPTY,
    run_id: NON_EMPTY,
    plan_id: NON_EMPTY,
    test_id: NON_EMPTY,
    attempt: { type: 'integer', minimum: 1 },
});
/** `test-tool/v1` ToolRequest schema. */
export const TEST_TOOL_REQUEST_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:test-tool-request:v1',
    title: 'test-tool/v1 ToolRequest',
    type: 'object',
    required: TOOL_REQUEST_FIELDS,
    additionalProperties: false,
    properties: {
        protocol_version: { const: TEST_TOOL_PROTOCOL_VERSION },
        ...CORRELATION_PROPERTIES,
        tool_ref: TOOL_REF,
        target_ref: TARGET_REF,
        input: Object.freeze({}),
        deadline: RFC3339,
        capability_snapshot_ref: CAP_SHA256,
    },
});
/** `test-tool/v1` ToolResponse schema — no verdict/gate/required/expected. */
export const TEST_TOOL_RESPONSE_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:test-tool-response:v1',
    title: 'test-tool/v1 ToolResponse',
    type: 'object',
    required: TOOL_RESPONSE_FIELDS,
    additionalProperties: false,
    properties: {
        protocol_version: { const: TEST_TOOL_PROTOCOL_VERSION },
        ...CORRELATION_PROPERTIES,
        tool_ref: TOOL_REF,
        execution_status: { enum: EXECUTION_STATUS },
        observations: { type: 'array', items: WORKER_OBSERVATION },
        artifact_refs: { type: 'array', items: ARTIFACT_REF },
        diagnostics: { type: 'array' },
    },
});
// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------
/** Single-document artifact schemas keyed by their exact version string. */
export const SCHEMA_BY_VERSION = Object.freeze({
    [RECEIPT_SCHEMA_VERSION]: RECEIPT_V1_SCHEMA,
    [RUN_SPEC_VERSION]: RUN_SPEC_V1_SCHEMA,
    [GATE_POLICY_VERSION]: GATE_POLICY_V1_SCHEMA,
    [PLAN_CANDIDATE_VERSION]: PLAN_CANDIDATE_V1_SCHEMA,
    [PLAN_VERSION]: PLAN_V1_SCHEMA,
    [TEST_TOOL_MANIFEST_VERSION]: TEST_TOOL_MANIFEST_V1_SCHEMA,
});
/** The two independent `test-tool/v1` envelope directions. */
export const TEST_TOOL_V1_SCHEMAS = Object.freeze({
    request: TEST_TOOL_REQUEST_V1_SCHEMA,
    response: TEST_TOOL_RESPONSE_V1_SCHEMA,
});
/** Correlation tuple echoed byte-for-byte by a response (§8.4.2). */
export const TEST_TOOL_CORRELATION_FIELDS = CORRELATION_FIELDS;
/**
 * Strict version lookup: only the registered exact version strings resolve.
 * Unknown or incompatible major versions return `null` — callers must reject,
 * never downgrade.
 * @param {unknown} version
 * @returns {object | null}
 */
export function schemaForVersion(version) {
    if (typeof version !== 'string' || !Object.hasOwn(SCHEMA_BY_VERSION, version))
        return null;
    return SCHEMA_BY_VERSION[version] ?? null;
}
// ---------------------------------------------------------------------------
/**
 * Recursively freeze schema literals so consumers cannot mutate the contract.
 * @param {unknown} value
 * @returns {unknown}
 */
function deepFreeze(value) {
    if (value === null || typeof value !== 'object' || Object.isFrozen(value))
        return value;
    for (const child of Object.values(value))
        deepFreeze(child);
    Object.freeze(value);
    return value;
}
