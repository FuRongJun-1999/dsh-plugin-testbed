/**
 * Canonical closed enums — the single vocabulary per architecture.md §9.5.
 * Do not invent synonymous values anywhere else in the codebase.
 *
 * Nothing in this module grants credentials or gate-execution authority: the
 * statuses below are *type registrations*; their producers are the trusted
 * control plane (architecture §9.5). `src/protocol/` contains no secrets.
 *
 * Migration notes: every enum is `as const` so its literal union is derived by
 * TypeScript instead of duplicated by hand. `inSet` is the only narrowing
 * helper; callers must not use a bare `.includes` on `unknown` input (that would
 * silently widen the closed vocabulary at the type level).
 *
 * @module @deepseek-ai/dsh-plugin-testbed/protocol/enums
 */
// ---------------------------------------------------------------------------
// §9.5 status normalisation — six distinct fields, never interchangeable.
// ---------------------------------------------------------------------------
export const RUN_STATUS = Object.freeze(['queued', 'running', 'completed', 'cancelled', 'blocked']);
export const ADMISSION_STATUS = Object.freeze(['accepted', 'rejected']);
export const EXECUTION_STATUS = Object.freeze(['completed', 'skipped', 'error', 'timeout', 'cancelled']);
export const INVOCATION_STATUS = Object.freeze(['not-started', 'started', 'unknown']);
export const VERDICT = Object.freeze(['pass', 'fail', 'skip', 'error', 'inconclusive']);
export const GATE_DECISION = Object.freeze(['pass', 'reject', 'blocked']);
// ---------------------------------------------------------------------------
// Auxiliary vocabularies (architecture §8.3 / §8.4.1 / §6.2).
// ---------------------------------------------------------------------------
export const CAPABILITY_CLAIM = Object.freeze(['declared', 'not-declared']);
export const CAPABILITY_OBSERVED = Object.freeze(['present', 'absent', 'unknown']);
export const CAPABILITY_VERIFICATION = Object.freeze(['corroborated', 'contradicted', 'not-run']);
export const TOOL_ADMISSION_STAGE = Object.freeze(['draft', 'validated', 'pinned']);
export const TOOL_ATTEMPT_STAGE = Object.freeze(['prepared', 'running', 'completed', 'skipped', 'error', 'timeout', 'cancelled']);
/** Tool roles are a restricted observation-producer set (§8.4.1). */
export const TOOL_ROLE = Object.freeze(['probe', 'fixture', 'transform']);
/** Requested capability namespaces of a tool manifest (§8.4.1). */
export const TOOL_PERMISSION_KEYS = Object.freeze(['filesystem', 'network', 'subprocess', 'devices', 'secrets']);
/** Determinism/repeatability values (§8.4.1, §6.2 `repeatability`). */
export const DETERMINISM_VALUES = Object.freeze(['deterministic', 'seeded', 'environment-bound', 'best-effort']);
/** Observation provenance enum (architecture §11.1). */
export const OBSERVATION_SOURCE = Object.freeze(['local', 'worker', 'control-plane', 'archive']);
/** Per-test classification in the frozen plan (§9.4, §11.2.1). */
export const TEST_CLASSIFICATION = Object.freeze(['required', 'optional', 'not-applicable']);
// ---------------------------------------------------------------------------
// Version boundaries (architecture §8.4.1 / §11.2.1; development-plan
// 「协议、receipt 与入口契约」). Each artifact evolves independently; an
// unknown or incompatible major version is rejected — never downgraded.
// ---------------------------------------------------------------------------
export const RECEIPT_SCHEMA_VERSION = 'receipt/v1';
export const TEST_TOOL_MANIFEST_VERSION = 'test-tool-manifest/v1';
export const TEST_TOOL_PROTOCOL_VERSION = 'test-tool/v1';
export const RUN_SPEC_VERSION = 'run-spec/v1';
export const GATE_POLICY_VERSION = 'gate-policy/v1';
export const PLAN_CANDIDATE_VERSION = 'plan-candidate/v1';
export const PLAN_VERSION = 'plan/v1';
/** Single-document protocol artifacts registered by `schemas.js`. */
export const KNOWN_SCHEMA_VERSIONS = Object.freeze([
    RECEIPT_SCHEMA_VERSION,
    RUN_SPEC_VERSION,
    GATE_POLICY_VERSION,
    PLAN_CANDIDATE_VERSION,
    PLAN_VERSION,
    TEST_TOOL_MANIFEST_VERSION,
]);
export const TRUST_SCOPE = Object.freeze(['local-only']);
export const EXIT_CODE_PROFILES = Object.freeze(['local-selfcheck/v1', 'market-required/v1']);
/**
 * Closed-set membership test with a type predicate.
 *
 * The runtime shape is unchanged from the JavaScript baseline
 * (`Array.isArray(set) && set.includes(v)`), so a malformed set still fails
 * closed. The predicate lets callers narrow `unknown` without `as any`.
 */
export function inSet(set, v) {
    return Array.isArray(set) && set.includes(v);
}
