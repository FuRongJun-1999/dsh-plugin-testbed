/**
 * Versioned market-evidence protocol schemas: signing, attestation, archive.
 *
 * This module is the single *type* authority for the market-stage evidence
 * contracts described by `NEXT-PHASE-REQUIREMENTS.md` §6.4–§6.6, §6.7 and
 * §9.2. It declares closed JSON Schemas only — no signature is produced, no
 * archive is written and no eligibility verdict is computed here. Executable
 * fail-closed checks that need cross-field or cryptographic reasoning live in
 * `src/evidence/`.
 *
 * Non-negotiable boundaries encoded below:
 *  - `receipt/v1` is untouched (see `schemas.js` / `contracts.js`); the market
 *    signing form exists only in the separate `market-attestation/v1` sidecar.
 *  - Signing/archive providers have an explicit trust class. Only
 *    `market-independent` may ever feed a market-eligible claim; development
 *    providers are `development-only` and MUST be rejected by the eligibility
 *    engine (`E1`, never market).
 *  - The environment of this repository has no KMS/HSM/OS keystore, no
 *    independent WORM/object-lock/tlog archive and no TSA. The `unavailable`
 *    trust class and the `blocked` reason codes record that fact instead of
 *    pretending a local digest is trust.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/protocol/market-schemas
 */
import { validateValue } from './jsonschema.js';
// ---------------------------------------------------------------------------
// Version boundaries — exact match only; unknown major versions are rejected,
// never downgraded (same rule as `schemas.js`).
// ---------------------------------------------------------------------------
export const SIGNING_PROVIDER_VERSION = 'signing-provider/v1';
export const SIGNING_REQUEST_VERSION = 'signing-request/v1';
export const SIGNING_RESPONSE_VERSION = 'signing-response/v1';
export const MARKET_ATTESTATION_VERSION = 'market-attestation/v1';
export const MARKET_ATTESTATION_VERIFICATION_VERSION = 'market-attestation-verification/v1';
export const MARKET_ARCHIVE_VERSION = 'market-archive/v1';
export const ARCHIVE_ENTRY_VERSION = 'archive-entry/v1';
export const ARCHIVE_ANCHOR_VERSION = 'archive-anchor/v1';
export const ARCHIVE_CHAIN_VERIFICATION_VERSION = 'archive-chain-verification/v1';
/** Market-gate policy frozen by the control plane before any market run. */
export const MARKET_GATE_POLICY_VERSION = 'market-gate-policy/v1';
/** Independent market eligibility decision (never a receipt/v1 field). */
export const MARKET_ELIGIBILITY_VERSION = 'market-eligibility/v1';
/** Bounded evidence package manifest (final artifact inventory, §6.12). */
export const MARKET_EVIDENCE_PACKAGE_VERSION = 'market-evidence-package/v1';
/** Pre-execution approval record (separation of duties, §5.1 C08/MKT-05). */
export const MARKET_APPROVAL_VERSION = 'market-approval/v1';
/** Pre-approved, scoped waiver record (§5.1 C08/MKT-06). */
export const MARKET_WAIVER_VERSION = 'market-waiver/v1';
/** Single-document market evidence artifacts registered by this module. */
export const MARKET_SCHEMA_VERSIONS = Object.freeze([
    SIGNING_PROVIDER_VERSION,
    SIGNING_REQUEST_VERSION,
    SIGNING_RESPONSE_VERSION,
    MARKET_ATTESTATION_VERSION,
    MARKET_ATTESTATION_VERIFICATION_VERSION,
    MARKET_ARCHIVE_VERSION,
    ARCHIVE_ENTRY_VERSION,
    ARCHIVE_ANCHOR_VERSION,
    ARCHIVE_CHAIN_VERIFICATION_VERSION,
]);
/** @param {string} v */
export function isSigningProviderVersion(v) {
    return v === SIGNING_PROVIDER_VERSION;
}
/** @param {string} v */
export function isSigningRequestVersion(v) {
    return v === SIGNING_REQUEST_VERSION;
}
/** @param {string} v */
export function isSigningResponseVersion(v) {
    return v === SIGNING_RESPONSE_VERSION;
}
/** @param {string} v */
export function isMarketAttestationVersion(v) {
    return v === MARKET_ATTESTATION_VERSION;
}
/** @param {string} v */
export function isMarketAttestationVerificationVersion(v) {
    return v === MARKET_ATTESTATION_VERIFICATION_VERSION;
}
/** @param {string} v */
export function isMarketArchiveVersion(v) {
    return v === MARKET_ARCHIVE_VERSION;
}
/** @param {string} v */
export function isArchiveEntryVersion(v) {
    return v === ARCHIVE_ENTRY_VERSION;
}
/** @param {string} v */
export function isArchiveAnchorVersion(v) {
    return v === ARCHIVE_ANCHOR_VERSION;
}
/** @param {string} v */
export function isArchiveChainVerificationVersion(v) {
    return v === ARCHIVE_CHAIN_VERIFICATION_VERSION;
}
/** @param {string} v */
export function isMarketGatePolicyVersion(v) {
    return v === MARKET_GATE_POLICY_VERSION;
}
/** @param {string} v */
export function isMarketEligibilityVersion(v) {
    return v === MARKET_ELIGIBILITY_VERSION;
}
/** @param {string} v */
export function isMarketEvidencePackageVersion(v) {
    return v === MARKET_EVIDENCE_PACKAGE_VERSION;
}
/** @param {string} v */
export function isMarketApprovalVersion(v) {
    return v === MARKET_APPROVAL_VERSION;
}
/** @param {string} v */
export function isMarketWaiverVersion(v) {
    return v === MARKET_WAIVER_VERSION;
}
// ---------------------------------------------------------------------------
// Closed vocabularies (NEXT-PHASE-REQUIREMENTS SIG-01/SIG-04/ARC-07).
// ---------------------------------------------------------------------------
/** SIG-01: the only market-acceptable signature algorithms. */
export const SIGNING_ALGORITHMS = Object.freeze(['ed25519', 'ecdsa-p256-sha256']);
/** SIG-04: key lifecycle states. Rotated/revoked keys stay published. */
export const SIGNING_KEY_STATES = Object.freeze(['active', 'rotated', 'revoked']);
/** SIG-01: fixed domain separation strings. */
export const SIGNING_DOMAIN_MARKET_ATTESTATION = 'dsh-market-attestation/v1';
export const SIGNING_DOMAIN_MARKET_ARCHIVE = 'dsh-market-archive/v1';
export const SIGNING_DOMAINS = Object.freeze([
    SIGNING_DOMAIN_MARKET_ATTESTATION,
    SIGNING_DOMAIN_MARKET_ARCHIVE,
]);
/** Payload kinds a `signing-request/v1` may reference. */
export const SIGNING_PAYLOAD_KINDS = Object.freeze([MARKET_ATTESTATION_VERSION]);
/**
 * Provider trust classes. `market-independent` is the only class that can
 * ever support an E3 market claim; `development-only` is E1/E0 test plumbing;
 * `unavailable` means the provider does not exist in this environment.
 */
export const PROVIDER_TRUST_CLASSES = Object.freeze([
    'market-independent',
    'independent-unverified',
    'development-only',
    'unavailable',
]);
/** Provider kinds (remote interfaces are declared, not faked). */
export const SIGNING_PROVIDER_KINDS = Object.freeze([
    'kms',
    'hsm',
    'os-keystore',
    'remote-signing-service',
    'development-local',
    'unavailable',
]);
/** ARC-07: modes that can satisfy independent WORM/object-lock/tlog custody. */
export const ARCHIVE_MARKET_MODES = Object.freeze([
    'object-lock',
    'worm',
    'tlog',
    'independent-archive-api',
]);
/** ARC-07: local file/git are development evidence only, never market anchors. */
export const ARCHIVE_DEVELOPMENT_MODES = Object.freeze(['local-file', 'git']);
/** All modes representable by `market-archive/v1`. */
export const ARCHIVE_MODES = Object.freeze([...ARCHIVE_MARKET_MODES, ...ARCHIVE_DEVELOPMENT_MODES]);
export const ARCHIVE_PROVIDER_KINDS = Object.freeze([
    'object-store',
    'worm-service',
    'transparency-log',
    'independent-archive-service',
    'development-local',
    'unavailable',
]);
export const ARCHIVE_TRUST_ANCHOR_TYPES = Object.freeze([
    'provider-signature',
    'tsa',
    'tlog',
    'none-development-only',
]);
export const TRUSTED_TIME_SOURCES = Object.freeze(['provider', 'tsa', 'host-clock-development-only']);
export const EVIDENCE_CLASSES = Object.freeze(['E0', 'E1', 'E2', 'E3']);
/** Attestation verification check statuses (`market-attestation-verification/v1`). */
export const VERIFICATION_CHECK_STATUSES = Object.freeze(['pass', 'fail', 'blocked']);
export const VERIFICATION_RESULTS = Object.freeze(['valid', 'invalid']);
/** Market-eligibility condition statuses (§6.7). `unknown` is never a pass. */
export const MARKET_CONDITION_STATUSES = Object.freeze(['pass', 'fail', 'unknown', 'not-applicable']);
/** Fixed condition ids MKT-C01..MKT-C10 (§5.1.3). C05 is a pre-sign trust gate. */
export const MARKET_CONDITION_IDS = Object.freeze([
    'MKT-C01', 'MKT-C02', 'MKT-C03', 'MKT-C04', 'MKT-C05',
    'MKT-C06', 'MKT-C07', 'MKT-C08', 'MKT-C09', 'MKT-C10',
]);
export const MARKET_DECISIONS = Object.freeze(['eligible', 'non-eligible']);
export const MARKET_APPROVAL_ROLES = Object.freeze(['reviewer', 'security', 'release']);
export const MARKET_APPROVAL_DECISIONS = Object.freeze(['approve', 'reject']);
export const MARKET_WAIVER_STATUSES = Object.freeze(['approved', 'revoked']);
/** Conditions that policy can never waive (hard isolation/runtime/signing/archive). */
export const NON_WAIVABLE_CONDITIONS = Object.freeze(['MKT-C01', 'MKT-C03', 'MKT-C05', 'MKT-C06']);
// ---------------------------------------------------------------------------
// Versioned reason codes (NEXT-PHASE-REQUIREMENTS §9.2, extended only with
// new version-scoped names; never re-purpose an existing code).
// ---------------------------------------------------------------------------
export const EVIDENCE_REASON_CODES = Object.freeze({
    // signing (SIG-*)
    SIGNING_PROVIDER_MISSING: 'signing-provider-missing',
    SIGNING_PROVIDER_UNTRUSTED: 'signing-provider-untrusted',
    SIGNING_KEY_UNKNOWN: 'signing-key-unknown',
    SIGNING_KEY_EXPIRED: 'signing-key-expired',
    SIGNING_KEY_REVOKED: 'signing-key-revoked',
    SIGNING_KEY_INACTIVE: 'signing-key-inactive',
    SIGNING_ALGORITHM_NOT_ALLOWED: 'signing-algorithm-not-allowed',
    SIGNING_KEY_CUSTODY_UNVERIFIED: 'signing-key-custody-unverified',
    SIGNING_REQUEST_INVALID: 'signing-request-invalid',
    SIGNING_REQUEST_UNAUTHORIZED: 'signing-request-unauthorized',
    SIGNING_REQUEST_STALE: 'signing-request-stale',
    SIGNING_BLIND_SIGN_FORBIDDEN: 'signing-blind-sign-forbidden',
    SIGNING_DOMAIN_SEPARATION_MISMATCH: 'signing-domain-separation-mismatch',
    SIGNING_PAYLOAD_DIGEST_MISMATCH: 'signing-payload-digest-mismatch',
    SIGNING_PAYLOAD_KIND_MISMATCH: 'signing-payload-kind-mismatch',
    SIGNING_RESPONSE_BINDING_MISMATCH: 'signing-response-binding-mismatch',
    SIGNATURE_VERIFICATION_FAILED: 'signature-verification-failed',
    // archive (ARC-*)
    ARCHIVE_PROVIDER_MISSING: 'archive-provider-missing',
    ARCHIVE_PROVIDER_UNTRUSTED: 'archive-provider-untrusted',
    ARCHIVE_MODE_NOT_IMMUTABLE: 'archive-mode-not-immutable',
    ARCHIVE_APPEND_FAILED: 'archive-append-failed',
    ARCHIVE_ANCHOR_MISSING: 'archive-anchor-missing',
    ARCHIVE_ANCHOR_MISMATCH: 'archive-anchor-mismatch',
    ARCHIVE_SEQUENCE_GAP: 'archive-sequence-gap',
    ARCHIVE_TAMPER_DETECTED: 'archive-tamper-detected',
    ARCHIVE_REPLAY_DETECTED: 'archive-replay-detected',
    ARCHIVE_ROLLBACK_DETECTED: 'archive-rollback-detected',
    ARCHIVE_TRUNCATION_DETECTED: 'archive-truncation-detected',
    ARCHIVE_TIME_REVERSED: 'archive-time-reversed',
    ARCHIVE_PROVIDER_TIME_REQUIRED: 'archive-provider-time-required',
    TRUSTED_TIME_UNAVAILABLE: 'trusted-time-unavailable',
    ARCHIVE_REQUEST_INVALID: 'archive-request-invalid',
    // shared evidence / fail-closed
    MARKET_EVIDENCE_INCOMPLETE: 'market-evidence-incomplete',
    FIXTURE_NOT_MARKET: 'fixture-not-market-evidence',
    DEVELOPMENT_ONLY_NOT_MARKET: 'development-only-not-market-evidence',
    EVIDENCE_UNVERIFIABLE: 'evidence-unverifiable',
    INTERNAL_ERROR: 'internal-error',
});
/**
 * Market-gate reason codes (§9.2). New version-scoped names are additive; an
 * existing code is never re-purposed. Dynamic condition codes use the
 * `market-condition-failed:<id>` / `market-condition-unknown:<id>` prefix so a
 * consumer can machine-parse them without a registry update.
 */
export const MARKET_REASON_CODES = Object.freeze({
    MARKET_POLICY_MISSING: 'market-policy-missing',
    MARKET_POLICY_VERSION_UNKNOWN: 'market-policy-version-unknown',
    MARKET_POLICY_DIGEST_MISMATCH: 'market-policy-digest-mismatch',
    MARKET_POLICY_EXPIRED: 'market-policy-expired',
    MARKET_POLICY_NOT_EFFECTIVE: 'market-policy-not-effective',
    MARKET_POLICY_INVALID: 'market-policy-invalid',
    MARKET_CONDITION_FAILED_PREFIX: 'market-condition-failed:',
    MARKET_CONDITION_UNKNOWN_PREFIX: 'market-condition-unknown:',
    MARKET_WAIVER_INVALID: 'market-waiver-invalid',
    MARKET_WAIVER_EXPIRED: 'market-waiver-expired',
    MARKET_WAIVER_OUT_OF_SCOPE: 'market-waiver-out-of-scope',
    MARKET_WAIVER_FORBIDDEN: 'market-waiver-forbidden',
    MARKET_APPROVAL_MISSING: 'market-approval-missing',
    MARKET_APPROVAL_INVALID: 'market-approval-invalid',
    MARKET_APPROVAL_SELF: 'market-approval-self',
    MARKET_APPROVAL_EXPIRED: 'market-approval-expired',
    MARKET_APPROVAL_ROLE: 'market-approval-role',
    MARKET_APPROVAL_SCOPE: 'market-approval-out-of-scope',
    MARKET_EVIDENCE_STALE: 'market-evidence-stale',
    MARKET_EVIDENCE_PATH_ESCAPE: 'market-evidence-path-escape',
    MARKET_EVIDENCE_UNREGISTERED: 'market-evidence-unregistered',
    MARKET_EVIDENCE_DIGEST_MISMATCH: 'market-evidence-digest-mismatch',
    MARKET_EVIDENCE_INCOMPLETE: 'market-evidence-incomplete',
    INTERNAL_ERROR: 'internal-error',
    FIXTURE_NOT_MARKET_EVIDENCE: 'fixture-not-market-evidence',
    APP_ASAR_NOT_MARKET_EVIDENCE: 'app-asar-not-market-evidence',
    LOCAL_RECEIPT_NOT_MARKET_EVIDENCE: 'local-receipt-not-market-evidence',
    MARKET_RUN_NOT_ELIGIBLE: 'market-run-not-eligible',
    MARKET_SIGNING_REQUIRED: 'market-signing-required',
    MARKET_ARCHIVE_REQUIRED: 'market-archive-required',
    MARKET_APPROVAL_REQUIRED: 'market-approval-required',
    MARKET_RUNTIME_REQUIRED: 'market-runtime-required',
    MARKET_ISOLATION_REQUIRED: 'market-isolation-required',
    MARKET_TRUSTED_TIME_REQUIRED: 'market-trusted-time-required',
    MARKET_SCHEDULER_EVIDENCE_REQUIRED: 'market-scheduler-evidence-required',
    MARKET_SCHEDULER_EVIDENCE_INVALID: 'market-scheduler-evidence-invalid',
    MARKET_RECEIPT_INVALID: 'market-receipt-invalid',
    MARKET_SEQUENCE_VIOLATION: 'market-sequence-violation',
});
// ---------------------------------------------------------------------------
// Shared fragments
// ---------------------------------------------------------------------------
const JSON_SCHEMA_DIALECT = 'https://json-schema.org/draft/2020-12/schema';
const NON_EMPTY = Object.freeze({ type: 'string', minLength: 1 });
const SHA256 = Object.freeze({ type: 'string', pattern: '^sha256:[0-9a-f]{64}$' });
const PLAN_SHA256 = Object.freeze({ type: 'string', pattern: '^plan-sha256:[0-9a-f]{64}$' });
/** SIG-01: base64url without padding. */
const BASE64URL = Object.freeze({ type: 'string', pattern: '^[A-Za-z0-9_-]+$' });
const RFC3339 = Object.freeze({
    type: 'string',
    pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:\\d{2})$',
});
const NULL = Object.freeze({ type: 'null' });
const STRING_ARRAY = Object.freeze({ type: 'array', items: { type: 'string' } });
/** @param {string} pattern */
function nullableString(pattern) {
    return pattern === undefined
        ? Object.freeze({ type: ['string', 'null'], minLength: 1 })
        : Object.freeze({ type: ['string', 'null'], pattern });
}
const NULLABLE_SHA256 = nullableString(SHA256.pattern);
const NULLABLE_RFC3339 = nullableString(RFC3339.pattern);
const NULLABLE_TEXT = nullableString();
const VERSION_REF = Object.freeze({
    type: 'object',
    required: ['id', 'version', 'digest'],
    additionalProperties: false,
    properties: {
        id: NON_EMPTY,
        version: NON_EMPTY,
        digest: SHA256,
    },
});
const CHECK_ENTRY = Object.freeze({
    type: 'object',
    required: ['id', 'status', 'reason_code', 'evidence_ref'],
    additionalProperties: false,
    properties: {
        id: NON_EMPTY,
        status: { enum: VERIFICATION_CHECK_STATUSES },
        reason_code: NULLABLE_TEXT,
        evidence_ref: NULLABLE_TEXT,
    },
});
// ---------------------------------------------------------------------------
// signing-provider/v1
// ---------------------------------------------------------------------------
const SIGNING_KEY = Object.freeze({
    type: 'object',
    required: [
        'key_id', 'alg', 'public_key', 'public_key_digest',
        'state', 'created_at', 'expires_at', 'attestation_ref',
    ],
    additionalProperties: false,
    properties: {
        key_id: NON_EMPTY,
        alg: { enum: SIGNING_ALGORITHMS },
        // SIG-01: base64url of the SPKI DER public key; digest over the same bytes.
        public_key: BASE64URL,
        public_key_digest: SHA256,
        state: { enum: SIGNING_KEY_STATES },
        created_at: RFC3339,
        expires_at: NULLABLE_RFC3339,
        rotated_at: NULLABLE_RFC3339,
        revoked_at: NULLABLE_RFC3339,
        revocation_reason: NULLABLE_TEXT,
        /** SIG-07: reference to the provider attestation of this key, if any. */
        attestation_ref: NULLABLE_TEXT,
    },
});
const PROVIDER_ATTESTATION = Object.freeze({
    type: 'object',
    required: ['schema_version', 'digest'],
    additionalProperties: false,
    properties: {
        schema_version: NON_EMPTY,
        digest: SHA256,
    },
});
const SIGNING_GUARANTEES = Object.freeze({
    type: 'object',
    required: ['private_key_export', 'signing_op', 'audit', 'blind_sign'],
    additionalProperties: false,
    properties: {
        private_key_export: { enum: ['never'] },
        signing_op: { enum: ['remote', 'local-development'] },
        audit: { enum: ['append-only', 'in-memory-development'] },
        blind_sign: { enum: ['forbidden'] },
    },
});
/** `signing-provider/v1` — provider capability + key metadata (public only). */
export const SIGNING_PROVIDER_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:signing-provider:v1',
    title: 'signing-provider/v1',
    type: 'object',
    required: [
        'schema_version', 'provider_id', 'provider_version', 'provider_kind',
        'trust_domain', 'algorithms', 'keys', 'guarantees', 'trust_class',
        'availability', 'limitations', 'attestation',
    ],
    additionalProperties: false,
    properties: {
        schema_version: { const: SIGNING_PROVIDER_VERSION },
        provider_id: NON_EMPTY,
        provider_version: NON_EMPTY,
        provider_kind: { enum: SIGNING_PROVIDER_KINDS },
        trust_domain: NON_EMPTY,
        algorithms: {
            type: 'array',
            minItems: 1,
            uniqueItems: true,
            items: { enum: SIGNING_ALGORITHMS },
        },
        keys: { type: 'array', items: SIGNING_KEY },
        guarantees: SIGNING_GUARANTEES,
        trust_class: { enum: PROVIDER_TRUST_CLASSES },
        availability: { enum: ['available', 'blocked'] },
        limitations: STRING_ARRAY,
        attestation: { oneOf: [PROVIDER_ATTESTATION, NULL] },
    },
});
// ---------------------------------------------------------------------------
// signing-request/v1 and signing-response/v1 (§6.4)
// ---------------------------------------------------------------------------
/** `signing-request/v1` — a request to sign one exact canonical payload. */
export const SIGNING_REQUEST_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:signing-request:v1',
    title: 'signing-request/v1',
    type: 'object',
    required: [
        'schema_version', 'request_id', 'key_id', 'alg', 'domain_separation',
        'payload_digest', 'payload_kind', 'audit_ref', 'requested_at', 'requester',
    ],
    additionalProperties: false,
    properties: {
        schema_version: { const: SIGNING_REQUEST_VERSION },
        request_id: NON_EMPTY,
        key_id: NON_EMPTY,
        alg: { enum: SIGNING_ALGORITHMS },
        domain_separation: { enum: SIGNING_DOMAINS },
        payload_digest: SHA256,
        payload_kind: { enum: SIGNING_PAYLOAD_KINDS },
        /**
         * Correlation id the provider MUST record in its append-only audit. It is
         * known before signing, so `market-attestation/v1.signing.provider_audit_ref`
         * can be part of the signed payload while still being provider-audited.
         */
        audit_ref: NON_EMPTY,
        requested_at: RFC3339,
        requester: {
            type: 'object',
            required: ['control_plane_id', 'authorization_ref'],
            additionalProperties: false,
            properties: {
                control_plane_id: NON_EMPTY,
                authorization_ref: NON_EMPTY,
            },
        },
    },
});
/** `signing-response/v1` — signature plus the request binding echoed back. */
export const SIGNING_RESPONSE_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:signing-response:v1',
    title: 'signing-response/v1',
    type: 'object',
    required: [
        'schema_version', 'request_id', 'key_id', 'alg', 'signature',
        'signed_payload_digest', 'signed_at', 'provider_audit_ref',
    ],
    additionalProperties: false,
    properties: {
        schema_version: { const: SIGNING_RESPONSE_VERSION },
        request_id: NON_EMPTY,
        key_id: NON_EMPTY,
        alg: { enum: SIGNING_ALGORITHMS },
        signature: BASE64URL,
        signed_payload_digest: SHA256,
        signed_at: RFC3339,
        provider_audit_ref: NON_EMPTY,
    },
});
// ---------------------------------------------------------------------------
// market-attestation/v1 (§6.5) and its independent verification record
// ---------------------------------------------------------------------------
const ATTESTATION_SUBJECT = Object.freeze({
    type: 'object',
    required: ['receipt_schema_version', 'run_id', 'plan_id', 'record_digest'],
    additionalProperties: false,
    properties: {
        receipt_schema_version: { const: 'receipt/v1' },
        run_id: NON_EMPTY,
        plan_id: PLAN_SHA256,
        record_digest: SHA256,
    },
});
const ATTESTATION_ELIGIBILITY_REF = Object.freeze({
    type: 'object',
    required: ['schema_version', 'decision_digest'],
    additionalProperties: false,
    properties: {
        schema_version: { const: 'market-eligibility/v1' },
        decision_digest: SHA256,
    },
});
const ATTESTATION_CONTROL_PLANE = Object.freeze({
    type: 'object',
    required: ['id', 'version', 'policy_ref'],
    additionalProperties: false,
    properties: {
        id: NON_EMPTY,
        version: NON_EMPTY,
        policy_ref: VERSION_REF,
    },
});
const ATTESTATION_ISOLATION = Object.freeze({
    type: 'object',
    required: ['level', 'attestation_digest', 'verification_digest'],
    additionalProperties: false,
    properties: {
        level: { enum: ['L0', 'L1', 'L2', 'L3'] },
        attestation_digest: SHA256,
        verification_digest: SHA256,
    },
});
const ATTESTATION_RUNTIME = Object.freeze({
    type: 'object',
    required: ['cordis_version', 'dsh_version', 'anchor_digest', 'contract_suite_digest'],
    additionalProperties: false,
    properties: {
        cordis_version: NON_EMPTY,
        dsh_version: NON_EMPTY,
        anchor_digest: SHA256,
        contract_suite_digest: SHA256,
    },
});
const ATTESTATION_SIGNING = Object.freeze({
    type: 'object',
    required: [
        'provider_id', 'key_id', 'alg', 'signature',
        'signed_at', 'provider_audit_ref',
    ],
    additionalProperties: false,
    properties: {
        provider_id: NON_EMPTY,
        key_id: NON_EMPTY,
        alg: { enum: SIGNING_ALGORITHMS },
        /** SIG-01: base64url, no padding; excluded from the signing input. */
        signature: BASE64URL,
        signed_at: RFC3339,
        provider_audit_ref: NON_EMPTY,
    },
});
const ATTESTATION_ARCHIVE = Object.freeze({
    type: 'object',
    required: ['provider_id', 'anchor_id', 'sequence', 'entry_digest', 'archived_at'],
    additionalProperties: false,
    properties: {
        provider_id: NON_EMPTY,
        anchor_id: NON_EMPTY,
        sequence: { type: 'integer', minimum: 1 },
        entry_digest: SHA256,
        /** Entry N (subject archive) time; must equal `anchor_N.archived_at`. */
        archived_at: RFC3339,
    },
});
/** `market-attestation/v1` — the signed market envelope (never inside receipt/v1). */
export const MARKET_ATTESTATION_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:market-attestation:v1',
    title: 'market-attestation/v1',
    type: 'object',
    required: [
        'schema_version', 'attestation_id', 'subject', 'eligibility',
        'control_plane', 'isolation', 'runtime', 'signing', 'archive',
        'limitations',
    ],
    additionalProperties: false,
    properties: {
        schema_version: { const: MARKET_ATTESTATION_VERSION },
        attestation_id: NON_EMPTY,
        subject: ATTESTATION_SUBJECT,
        eligibility: ATTESTATION_ELIGIBILITY_REF,
        control_plane: ATTESTATION_CONTROL_PLANE,
        isolation: ATTESTATION_ISOLATION,
        runtime: ATTESTATION_RUNTIME,
        signing: ATTESTATION_SIGNING,
        archive: ATTESTATION_ARCHIVE,
        limitations: STRING_ARRAY,
    },
});
/** `market-attestation-verification/v1` — independent verification record. */
export const MARKET_ATTESTATION_VERIFICATION_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:market-attestation-verification:v1',
    title: 'market-attestation-verification/v1',
    type: 'object',
    required: [
        'schema_version', 'verification_id', 'attestation_digest',
        'signature_verified', 'archive_chain_verified', 'checks', 'result',
        'verified_by', 'verified_at', 'reason_codes', 'limitations',
    ],
    additionalProperties: false,
    properties: {
        schema_version: { const: MARKET_ATTESTATION_VERIFICATION_VERSION },
        verification_id: NON_EMPTY,
        attestation_digest: SHA256,
        /** Digest of entry N+1 (eligibility + attestation) when checked. */
        attestation_archive_entry_digest: NULLABLE_SHA256,
        signature_verified: { type: 'boolean' },
        archive_chain_verified: { type: 'boolean' },
        checks: { type: 'array', minItems: 1, items: CHECK_ENTRY },
        result: { enum: VERIFICATION_RESULTS },
        verified_by: NON_EMPTY,
        verified_at: RFC3339,
        reason_codes: STRING_ARRAY,
        limitations: STRING_ARRAY,
    },
});
// ---------------------------------------------------------------------------
// market-archive/v1 (§6.6) — provider capability/immutability declaration
// ---------------------------------------------------------------------------
const ARCHIVE_IMMUTABILITY = Object.freeze({
    type: 'object',
    required: ['append_only', 'delete_forbidden', 'retention_days', 'legal_hold'],
    additionalProperties: false,
    properties: {
        append_only: { type: 'boolean' },
        delete_forbidden: { type: 'boolean' },
        retention_days: { type: 'integer', minimum: 0 },
        legal_hold: { type: 'boolean' },
    },
});
const ARCHIVE_TRUST_ANCHOR = Object.freeze({
    type: 'object',
    required: ['type', 'key_id', 'verification_ref'],
    additionalProperties: false,
    properties: {
        type: { enum: ARCHIVE_TRUST_ANCHOR_TYPES },
        key_id: NULLABLE_TEXT,
        verification_ref: NULLABLE_TEXT,
    },
});
const ARCHIVE_TRUSTED_TIME = Object.freeze({
    type: 'object',
    required: ['source', 'verified', 'reference'],
    additionalProperties: false,
    properties: {
        source: { enum: TRUSTED_TIME_SOURCES },
        verified: { type: 'boolean' },
        reference: NULLABLE_TEXT,
    },
});
/** `market-archive/v1` — archive provider declaration. */
export const MARKET_ARCHIVE_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:market-archive:v1',
    title: 'market-archive/v1',
    type: 'object',
    required: [
        'schema_version', 'provider_id', 'provider_version', 'provider_kind',
        'mode', 'immutability', 'trust_anchor', 'trusted_time',
        'sequence_head', 'trust_class', 'availability', 'limitations',
    ],
    additionalProperties: false,
    properties: {
        schema_version: { const: MARKET_ARCHIVE_VERSION },
        provider_id: NON_EMPTY,
        provider_version: NON_EMPTY,
        provider_kind: { enum: ARCHIVE_PROVIDER_KINDS },
        mode: { enum: ARCHIVE_MODES },
        immutability: ARCHIVE_IMMUTABILITY,
        trust_anchor: ARCHIVE_TRUST_ANCHOR,
        trusted_time: ARCHIVE_TRUSTED_TIME,
        sequence_head: { type: 'integer', minimum: 0 },
        trust_class: { enum: PROVIDER_TRUST_CLASSES },
        availability: { enum: ['available', 'blocked'] },
        limitations: STRING_ARRAY,
    },
});
// ---------------------------------------------------------------------------
// archive-entry/v1, archive-anchor/v1 and archive-chain-verification/v1
// ---------------------------------------------------------------------------
const PROVIDER_SIGNATURE = Object.freeze({
    type: 'object',
    required: ['alg', 'key_id', 'value'],
    additionalProperties: false,
    properties: {
        alg: NON_EMPTY,
        key_id: NON_EMPTY,
        /** Provider signature/MAC over the stored entry; never a worker secret. */
        value: NON_EMPTY,
    },
});
const ENTRY_TIME_SOURCE = Object.freeze({
    type: 'object',
    required: ['source', 'trusted', 'reference'],
    additionalProperties: false,
    properties: {
        source: { enum: TRUSTED_TIME_SOURCES },
        trusted: { type: 'boolean' },
        reference: NULLABLE_TEXT,
    },
});
/**
 * `archive-entry/v1`.
 *
 * `entry_digest` is computed over the canonical entry *excluding*
 * `entry_digest`, `provider_signature` and `provider_audit_ref`, because the
 * writer pins the chain digest before the provider assigns its own audit ref.
 * The provider signature covers the stored entry (including the audit ref).
 */
export const ARCHIVE_ENTRY_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:archive-entry:v1',
    title: 'archive-entry/v1',
    type: 'object',
    required: [
        'schema_version', 'archive_id', 'sequence', 'previous_entry_digest',
        'receipt_digest', 'isolation_attestation_digest', 'policy_digest',
        'approval_digests', 'attestation_digest', 'eligibility_digest',
        'entry_digest', 'archived_at', 'time_source', 'provider_signature',
        'provider_audit_ref',
    ],
    additionalProperties: false,
    properties: {
        schema_version: { const: ARCHIVE_ENTRY_VERSION },
        archive_id: NON_EMPTY,
        sequence: { type: 'integer', minimum: 1 },
        previous_entry_digest: NULLABLE_SHA256,
        receipt_digest: SHA256,
        isolation_attestation_digest: NULLABLE_SHA256,
        policy_digest: NULLABLE_SHA256,
        approval_digests: { type: 'array', items: SHA256, uniqueItems: true },
        attestation_digest: NULLABLE_SHA256,
        eligibility_digest: NULLABLE_SHA256,
        entry_digest: SHA256,
        archived_at: RFC3339,
        time_source: ENTRY_TIME_SOURCE,
        provider_signature: { oneOf: [PROVIDER_SIGNATURE, NULL] },
        provider_audit_ref: NON_EMPTY,
    },
});
/** `archive-anchor/v1` — ARC-04 anchor bound by receipt/attestation. */
export const ARCHIVE_ANCHOR_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:archive-anchor:v1',
    title: 'archive-anchor/v1',
    type: 'object',
    required: [
        'schema_version', 'anchor_id', 'provider_id', 'archive_id', 'sequence',
        'entry_digest', 'previous_entry_digest', 'receipt_digest', 'archived_at',
        'trust_anchor', 'trusted_time', 'provider_audit_ref',
    ],
    additionalProperties: false,
    properties: {
        schema_version: { const: ARCHIVE_ANCHOR_VERSION },
        anchor_id: NON_EMPTY,
        provider_id: NON_EMPTY,
        archive_id: NON_EMPTY,
        sequence: { type: 'integer', minimum: 1 },
        entry_digest: SHA256,
        previous_entry_digest: NULLABLE_SHA256,
        receipt_digest: SHA256,
        archived_at: RFC3339,
        trust_anchor: ARCHIVE_TRUST_ANCHOR,
        trusted_time: ARCHIVE_TRUSTED_TIME,
        provider_audit_ref: NON_EMPTY,
    },
});
const EXPECTED_HEAD = Object.freeze({
    type: ['object', 'null'],
    required: ['sequence', 'entry_digest'],
    additionalProperties: false,
    properties: {
        sequence: { type: 'integer', minimum: 0 },
        entry_digest: NULLABLE_SHA256,
    },
});
/** `archive-chain-verification/v1` — saved chain verification output (ARC-09). */
export const ARCHIVE_CHAIN_VERIFICATION_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:archive-chain-verification:v1',
    title: 'archive-chain-verification/v1',
    type: 'object',
    required: [
        'schema_version', 'verification_id', 'archive_id', 'provider_id',
        'sequence_head', 'head_entry_digest', 'expected_head', 'result',
        'checks', 'reason_codes', 'verified_at', 'limitations',
    ],
    additionalProperties: false,
    properties: {
        schema_version: { const: ARCHIVE_CHAIN_VERIFICATION_VERSION },
        verification_id: NON_EMPTY,
        archive_id: NON_EMPTY,
        provider_id: NON_EMPTY,
        sequence_head: { type: 'integer', minimum: 0 },
        head_entry_digest: NULLABLE_SHA256,
        expected_head: EXPECTED_HEAD,
        result: { enum: ['valid', 'invalid', 'blocked'] },
        checks: { type: 'array', minItems: 1, items: CHECK_ENTRY },
        reason_codes: STRING_ARRAY,
        verified_at: RFC3339,
        limitations: STRING_ARRAY,
    },
});
// ---------------------------------------------------------------------------
// market-gate-policy/v1 (§6.8) — frozen policy frozen before any market run.
//
// The policy carries both the specification view (`required_isolation`) and the
// isolation-admission view (`isolation`) so the single frozen document can be
// bound by the isolation attestation digest without a second policy object.
// The two views must agree; the cross-field check lives in src/market/policy.ts.
// ---------------------------------------------------------------------------
const ISOLATION_LIMITS = Object.freeze({
    type: 'object',
    required: ['cpu_ms', 'memory_mb', 'processes', 'temp_bytes', 'output_bytes'],
    additionalProperties: false,
    properties: {
        cpu_ms: { type: 'integer', minimum: 1 },
        memory_mb: { type: 'integer', minimum: 1 },
        processes: { type: 'integer', minimum: 1 },
        temp_bytes: { type: 'integer', minimum: 1 },
        output_bytes: { type: 'integer', minimum: 1 },
    },
});
const ISOLATION_POLICY = Object.freeze({
    type: 'object',
    required: ['required_level', 'max_attestation_age_ms', 'denied_roots', 'network_allowlist', 'limits'],
    additionalProperties: false,
    properties: {
        required_level: { enum: ['L2', 'L3'] },
        max_attestation_age_ms: { type: 'integer', minimum: 1, maximum: 60 * 60 * 1000 },
        denied_roots: { type: 'array', minItems: 1, uniqueItems: true, items: NON_EMPTY },
        network_allowlist: { type: 'array', uniqueItems: true, items: NON_EMPTY },
        limits: ISOLATION_LIMITS,
    },
});
const REQUIRED_ISOLATION = Object.freeze({
    type: 'object',
    required: ['minimum', 'require_l3_for'],
    additionalProperties: false,
    properties: {
        minimum: { enum: ['L2', 'L3'] },
        require_l3_for: STRING_ARRAY,
    },
});
const ALLOWED_RUNTIME = Object.freeze({
    type: 'object',
    required: ['package', 'version', 'integrity'],
    additionalProperties: false,
    properties: {
        package: NON_EMPTY,
        version: NON_EMPTY,
        integrity: NON_EMPTY,
    },
});
const ALLOWED_LAUNCHER = Object.freeze({
    type: 'object',
    required: ['launcher_id', 'attestation_required'],
    additionalProperties: false,
    properties: {
        launcher_id: NON_EMPTY,
        attestation_required: { type: 'boolean' },
    },
});
const ALLOWED_SIGNER = Object.freeze({
    type: 'object',
    required: ['key_id', 'alg', 'state'],
    additionalProperties: false,
    properties: {
        key_id: NON_EMPTY,
        alg: { enum: SIGNING_ALGORITHMS },
        state: { enum: SIGNING_KEY_STATES },
    },
});
const ALLOWED_ARCHIVE = Object.freeze({
    type: 'object',
    required: ['provider_id', 'mode'],
    additionalProperties: false,
    properties: {
        provider_id: NON_EMPTY,
        mode: { enum: ARCHIVE_MARKET_MODES },
    },
});
const WAIVER_RULES = Object.freeze({
    type: 'object',
    required: ['pre_approved_only', 'max_ttl_hours', 'forbidden_for', 'approver_roles'],
    additionalProperties: false,
    properties: {
        pre_approved_only: { type: 'boolean' },
        max_ttl_hours: { type: 'integer', minimum: 1 },
        forbidden_for: STRING_ARRAY,
        approver_roles: { type: 'array', minItems: 1, uniqueItems: true, items: { enum: MARKET_APPROVAL_ROLES } },
    },
});
/** `market-gate-policy/v1` — control-plane frozen market policy (§6.8). */
export const MARKET_GATE_POLICY_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:market-gate-policy:v1',
    title: 'market-gate-policy/v1',
    type: 'object',
    required: [
        'schema_version', 'policy_id', 'policy_version', 'effective_from',
        'effective_until', 'required_isolation', 'isolation', 'allowed_runtimes',
        'allowed_launchers', 'allowed_signers', 'allowed_archives',
        'required_suites', 'waiver_rules', 'separation_of_duties',
        'evidence_max_age_hours', 'fail_closed', 'required_conditions',
    ],
    additionalProperties: false,
    properties: {
        schema_version: { const: MARKET_GATE_POLICY_VERSION },
        policy_id: NON_EMPTY,
        policy_version: NON_EMPTY,
        effective_from: RFC3339,
        effective_until: NULLABLE_RFC3339,
        required_isolation: REQUIRED_ISOLATION,
        isolation: ISOLATION_POLICY,
        allowed_runtimes: { type: 'array', minItems: 1, items: ALLOWED_RUNTIME },
        allowed_launchers: { type: 'array', minItems: 1, items: ALLOWED_LAUNCHER },
        allowed_signers: { type: 'array', minItems: 1, items: ALLOWED_SIGNER },
        allowed_archives: { type: 'array', minItems: 1, items: ALLOWED_ARCHIVE },
        required_suites: { type: 'array', minItems: 1, uniqueItems: true, items: NON_EMPTY },
        waiver_rules: WAIVER_RULES,
        separation_of_duties: { type: 'boolean' },
        evidence_max_age_hours: { type: 'number', minimum: 1, maximum: 24 * 365 },
        fail_closed: { type: 'boolean' },
        /** Optional policy extension: roles that must each approve (default: all). */
        approval_roles: { type: 'array', minItems: 1, uniqueItems: true, items: { enum: MARKET_APPROVAL_ROLES } },
        /** Optional policy extension: governed scheduling evidence is required. */
        scheduler_required: { type: 'boolean' },
        /**
         * Frozen condition set. It must enumerate all ten MKT-C01..C10 exactly;
         * `validateMarketPolicy` additionally rejects partial/duplicate sets and
         * the gate itself never trusts a caller-supplied subset.
         */
        required_conditions: {
            type: 'array',
            minItems: MARKET_CONDITION_IDS.length,
            maxItems: MARKET_CONDITION_IDS.length,
            uniqueItems: true,
            items: { enum: MARKET_CONDITION_IDS },
        },
    },
});
// ---------------------------------------------------------------------------
// market-eligibility/v1 (§6.7) — independent, append-only decision sidecar.
// ---------------------------------------------------------------------------
const MARKET_CONDITION_ENTRY = Object.freeze({
    type: 'object',
    required: ['id', 'status', 'evidence_refs', 'reason_code'],
    additionalProperties: false,
    properties: {
        id: { enum: MARKET_CONDITION_IDS },
        status: { enum: MARKET_CONDITION_STATUSES },
        evidence_refs: STRING_ARRAY,
        reason_code: NULLABLE_TEXT,
    },
});
const MARKET_BLOCKER = Object.freeze({
    type: 'object',
    required: ['condition_id', 'reason_code'],
    additionalProperties: false,
    properties: {
        condition_id: { enum: MARKET_CONDITION_IDS },
        reason_code: NON_EMPTY,
    },
});
const MARKET_APPROVAL_REF = Object.freeze({
    type: 'object',
    required: ['principal', 'role', 'at', 'scope', 'decision', 'signature_ref'],
    additionalProperties: false,
    properties: {
        principal: NON_EMPTY,
        role: { enum: MARKET_APPROVAL_ROLES },
        at: RFC3339,
        scope: NON_EMPTY,
        decision: { enum: MARKET_APPROVAL_DECISIONS },
        signature_ref: NULLABLE_TEXT,
    },
});
/** `market-eligibility/v1` — immutable eligibility decision (§6.7). */
export const MARKET_ELIGIBILITY_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:market-eligibility:v1',
    title: 'market-eligibility/v1',
    type: 'object',
    required: [
        'schema_version', 'decision_id', 'decision', 'run_id', 'receipt_digest',
        'policy', 'evaluated_at', 'conditions', 'reason_codes', 'blockers',
        'approvals', 'evidence_manifest_digest', 'limitations',
    ],
    additionalProperties: false,
    properties: {
        schema_version: { const: MARKET_ELIGIBILITY_VERSION },
        decision_id: NON_EMPTY,
        decision: { enum: MARKET_DECISIONS },
        run_id: NON_EMPTY,
        receipt_digest: SHA256,
        policy: VERSION_REF,
        evaluated_at: RFC3339,
        conditions: { type: 'array', minItems: 1, items: MARKET_CONDITION_ENTRY },
        reason_codes: STRING_ARRAY,
        blockers: { type: 'array', items: MARKET_BLOCKER },
        approvals: { type: 'array', items: MARKET_APPROVAL_REF },
        evidence_manifest_digest: SHA256,
        limitations: STRING_ARRAY,
    },
});
// ---------------------------------------------------------------------------
// market-approval/v1 + market-waiver/v1 (§5.1 C08 / MKT-05 / MKT-06).
// ---------------------------------------------------------------------------
const APPROVAL_SCOPE = Object.freeze({
    type: 'object',
    required: ['target_digest', 'isolation_level'],
    additionalProperties: false,
    properties: {
        target_digest: SHA256,
        isolation_level: { enum: ['L2', 'L3'] },
        test_ids: STRING_ARRAY,
    },
});
const APPROVAL_SEPARATION = Object.freeze({
    type: 'object',
    required: ['worker', 'signer', 'archive', 'self'],
    additionalProperties: false,
    properties: {
        worker: { const: false },
        signer: { const: false },
        archive: { const: false },
        self: { const: false },
    },
});
/** `market-approval/v1` — pre-execution human/control-plane approval. */
export const MARKET_APPROVAL_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:market-approval:v1',
    title: 'market-approval/v1',
    type: 'object',
    required: [
        'schema_version', 'approval_id', 'run_id', 'receipt_digest', 'policy',
        'principal', 'role', 'decision', 'scope', 'at', 'expires_at',
        'signature_ref', 'separation',
    ],
    additionalProperties: false,
    properties: {
        schema_version: { const: MARKET_APPROVAL_VERSION },
        approval_id: NON_EMPTY,
        run_id: NON_EMPTY,
        receipt_digest: SHA256,
        policy: VERSION_REF,
        principal: NON_EMPTY,
        role: { enum: MARKET_APPROVAL_ROLES },
        decision: { enum: MARKET_APPROVAL_DECISIONS },
        scope: APPROVAL_SCOPE,
        at: RFC3339,
        expires_at: NULLABLE_RFC3339,
        signature_ref: NULLABLE_TEXT,
        separation: APPROVAL_SEPARATION,
    },
});
const WAIVER_SCOPE = Object.freeze({
    type: 'object',
    required: ['run_id', 'target_digest'],
    additionalProperties: false,
    properties: {
        run_id: NON_EMPTY,
        target_digest: SHA256,
    },
});
/** `market-waiver/v1` — scoped pre-approval; never turns a required into pass. */
export const MARKET_WAIVER_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:market-waiver:v1',
    title: 'market-waiver/v1',
    type: 'object',
    required: [
        'schema_version', 'waiver_id', 'policy', 'condition_id', 'scope',
        'reason', 'requested_by', 'approved_by', 'approver_role', 'approved_at',
        'expires_at', 'status', 'evidence_refs',
    ],
    additionalProperties: false,
    properties: {
        schema_version: { const: MARKET_WAIVER_VERSION },
        waiver_id: NON_EMPTY,
        policy: VERSION_REF,
        condition_id: { enum: MARKET_CONDITION_IDS },
        scope: WAIVER_SCOPE,
        reason: NON_EMPTY,
        requested_by: NON_EMPTY,
        approved_by: NON_EMPTY,
        approver_role: { enum: MARKET_APPROVAL_ROLES },
        approved_at: RFC3339,
        expires_at: RFC3339,
        status: { enum: MARKET_WAIVER_STATUSES },
        evidence_refs: STRING_ARRAY,
    },
});
// ---------------------------------------------------------------------------
// market-evidence-package/v1 (§6.12) — final artifact inventory.
// ---------------------------------------------------------------------------
const EVIDENCE_ARTIFACT = Object.freeze({
    type: 'object',
    required: ['path', 'kind', 'digest', 'size_bytes'],
    additionalProperties: false,
    properties: {
        path: NON_EMPTY,
        kind: NON_EMPTY,
        digest: SHA256,
        size_bytes: { type: 'integer', minimum: 0 },
    },
});
const EVIDENCE_RETENTION = Object.freeze({
    type: 'object',
    required: ['until', 'policy_ref'],
    additionalProperties: false,
    properties: {
        until: NULLABLE_RFC3339,
        policy_ref: NULLABLE_TEXT,
    },
});
const EVIDENCE_REDACTION = Object.freeze({
    type: 'object',
    required: ['status', 'notes'],
    additionalProperties: false,
    properties: {
        status: { enum: ['reviewed', 'not-reviewed'] },
        notes: NULLABLE_TEXT,
    },
});
/** `market-evidence-package/v1` — bounded, digest-verified artifact inventory. */
export const MARKET_EVIDENCE_PACKAGE_V1_SCHEMA = deepFreeze({
    $schema: JSON_SCHEMA_DIALECT,
    $id: 'urn:dsh:plugin-testbed:market-evidence-package:v1',
    title: 'market-evidence-package/v1',
    type: 'object',
    required: [
        'schema_version', 'package_id', 'run_id', 'receipt_digest', 'artifacts',
        'package_digest', 'created_at', 'retention', 'redaction',
    ],
    additionalProperties: false,
    properties: {
        schema_version: { const: MARKET_EVIDENCE_PACKAGE_VERSION },
        package_id: NON_EMPTY,
        run_id: NON_EMPTY,
        receipt_digest: SHA256,
        artifacts: { type: 'array', minItems: 1, items: EVIDENCE_ARTIFACT },
        package_digest: SHA256,
        created_at: RFC3339,
        retention: EVIDENCE_RETENTION,
        redaction: EVIDENCE_REDACTION,
    },
});
// ---------------------------------------------------------------------------
// Registry + lookup
// ---------------------------------------------------------------------------
/** Single-document market evidence schemas keyed by their exact version. */
export const MARKET_SCHEMA_BY_VERSION = Object.freeze({
    [SIGNING_PROVIDER_VERSION]: SIGNING_PROVIDER_V1_SCHEMA,
    [SIGNING_REQUEST_VERSION]: SIGNING_REQUEST_V1_SCHEMA,
    [SIGNING_RESPONSE_VERSION]: SIGNING_RESPONSE_V1_SCHEMA,
    [MARKET_ATTESTATION_VERSION]: MARKET_ATTESTATION_V1_SCHEMA,
    [MARKET_ATTESTATION_VERIFICATION_VERSION]: MARKET_ATTESTATION_VERIFICATION_V1_SCHEMA,
    [MARKET_ARCHIVE_VERSION]: MARKET_ARCHIVE_V1_SCHEMA,
    [ARCHIVE_ENTRY_VERSION]: ARCHIVE_ENTRY_V1_SCHEMA,
    [ARCHIVE_ANCHOR_VERSION]: ARCHIVE_ANCHOR_V1_SCHEMA,
    [ARCHIVE_CHAIN_VERIFICATION_VERSION]: ARCHIVE_CHAIN_VERIFICATION_V1_SCHEMA,
});
/**
 * Market-gate document registry (t8). Kept separate from the t5 evidence
 * registry above so the evidence module's schema-count contract is unchanged;
 * `marketSchemaForVersion` intentionally stays evidence-only.
 */
export const MARKET_GATE_SCHEMA_VERSIONS = Object.freeze([
    MARKET_GATE_POLICY_VERSION,
    MARKET_ELIGIBILITY_VERSION,
    MARKET_EVIDENCE_PACKAGE_VERSION,
    MARKET_APPROVAL_VERSION,
    MARKET_WAIVER_VERSION,
]);
/** Market-gate schemas keyed by their exact version. */
export const MARKET_GATE_SCHEMA_BY_VERSION = Object.freeze({
    [MARKET_GATE_POLICY_VERSION]: MARKET_GATE_POLICY_V1_SCHEMA,
    [MARKET_ELIGIBILITY_VERSION]: MARKET_ELIGIBILITY_V1_SCHEMA,
    [MARKET_EVIDENCE_PACKAGE_VERSION]: MARKET_EVIDENCE_PACKAGE_V1_SCHEMA,
    [MARKET_APPROVAL_VERSION]: MARKET_APPROVAL_V1_SCHEMA,
    [MARKET_WAIVER_VERSION]: MARKET_WAIVER_V1_SCHEMA,
});
/**
 * Strict lookup for market-gate documents. Unknown versions return `null`;
 * callers must reject rather than downgrade.
 */
export function marketGateSchemaForVersion(version) {
    if (typeof version !== 'string' || !Object.hasOwn(MARKET_GATE_SCHEMA_BY_VERSION, version))
        return null;
    return MARKET_GATE_SCHEMA_BY_VERSION[version] ?? null;
}
/**
 * Strict version lookup: only registered exact version strings resolve.
 * Unknown/incompatible versions return `null`; callers must reject.
 */
export function marketSchemaForVersion(version) {
    if (typeof version !== 'string' || !Object.hasOwn(MARKET_SCHEMA_BY_VERSION, version))
        return null;
    return MARKET_SCHEMA_BY_VERSION[version] ?? null;
}
/**
 * Validate a document against a registered market evidence schema. Returns the
 * raw JSON-Schema errors; cross-field rules are enforced by the evidence
 * modules (and are additive, never a relaxation of this result).
 */
export function validateMarketDocument(value, schema) {
    const result = validateValue(value, schema);
    return { ok: result.ok, errors: result.errors };
}
/** @param {unknown} value */
export function validateMarketGatePolicy(value) {
    return validateMarketDocument(value, MARKET_GATE_POLICY_V1_SCHEMA);
}
/** @param {unknown} value */
export function validateMarketEligibility(value) {
    return validateMarketDocument(value, MARKET_ELIGIBILITY_V1_SCHEMA);
}
/** @param {unknown} value */
export function validateMarketApproval(value) {
    return validateMarketDocument(value, MARKET_APPROVAL_V1_SCHEMA);
}
/** @param {unknown} value */
export function validateMarketWaiver(value) {
    return validateMarketDocument(value, MARKET_WAIVER_V1_SCHEMA);
}
/** @param {unknown} value */
export function validateMarketEvidencePackage(value) {
    return validateMarketDocument(value, MARKET_EVIDENCE_PACKAGE_V1_SCHEMA);
}
export function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
/**
 * Recursively freeze schema literals so consumers cannot mutate the contract.
 */
function deepFreeze(value) {
    if (value === null || typeof value !== 'object' || Object.isFrozen(value))
        return value;
    for (const child of Object.values(value))
        deepFreeze(child);
    return Object.freeze(value);
}
