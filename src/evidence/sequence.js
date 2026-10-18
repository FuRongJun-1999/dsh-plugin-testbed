/**
 * Ordered market-evidence sequence (SIG-08), fail-closed at every stage.
 *
 * Exact order implemented here:
 *
 *   1. strict `receipt/v1` validation (never modified)
 *   2. archive subject inputs (receipt/isolation/policy/approvals) as entry N
 *   3. eligibility (injected control-plane callback; this module does not own
 *      the market policy engine) — the callback receives anchor_N
 *   4. build `market-attestation/v1` with `archive = anchor_N`
 *   5. sign via the injected `signing-provider/v1`
 *   6. archive eligibility + attestation as entry N+1
 *   7. independent verification of signature + both archive entries
 *
 * Any failure stops the sequence at that stage. In particular a non-eligible
 * decision is never signed, and a signing/append failure never produces entry
 * N+1. With development providers the sequence always ends `non-eligible` /
 * `blocked` — it can never publish.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/evidence/sequence
 */
import { EVIDENCE_REASON_CODES, MARKET_ATTESTATION_VERSION, MARKET_ARCHIVE_V1_SCHEMA, SIGNING_PROVIDER_V1_SCHEMA, validateMarketDocument, } from '../protocol/market-schemas.js';
import { validateReceiptV1 } from '../protocol/contracts.js';
import { recordDigest } from '../protocol/digest.js';
import { canonicalDigest, marketAttestationDigest, } from './canonical.js';
import { buildAttestationEntryDraft, buildSubjectEntryDraft, } from './archive.js';
import { buildMarketAttestation, classifyMarketEvidence, verifyMarketAttestation, } from './attestation.js';
import { signMarketAttestation } from './signing.js';
/** Stages in the fixed SIG-08 order. */
export const EVIDENCE_SEQUENCE_STAGES = Object.freeze([
    'receipt-validation',
    'archive-subject',
    'eligibility',
    'attestation-build',
    'sign',
    'archive-attestation',
    'verification',
]);
function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function enter(steps, stage) {
    steps.push(stage);
}
/**
 * Build the digest over *eligibility inputs only* (no eligibility/attestation
 * output), so the eligibility record can bind its own advisory input without a
 * circular dependency (§6.7).
 */
export function evidenceManifestDigest(input) {
    return canonicalDigest({
        receipt_digest: input.receiptDigest,
        isolation_attestation_digest: input.isolationAttestationDigest ?? null,
        isolation_verification_digest: input.isolationVerificationDigest ?? null,
        policy_digest: input.policyDigest ?? null,
        approval_digests: [...(input.approvalDigests ?? [])].sort(),
        archive_anchor_digest: input.archiveAnchorDigest,
    });
}
/**
 * Read the full chain from an archive provider (sequence 1..count).
 */
export async function readArchiveEntries(provider, count) {
    const entries = [];
    for (let sequence = 1; sequence <= count; sequence += 1) {
        const result = await provider.get(sequence);
        if (!isPlainObject(result) || result.status !== 'ok' || !isPlainObject(result.entry))
            return null;
        entries.push(result.entry);
    }
    return entries;
}
/**
 * Run the complete ordered evidence sequence.
 */
export async function runMarketEvidenceSequence(options) {
    const steps = [];
    const fail = (stage, status, reasonCodes, detail) => ({
        status,
        failure_stage: stage,
        market_eligible: false,
        publish: false,
        steps,
        reason_codes: [...new Set(reasonCodes)],
        detail,
    });
    // ---- 1. receipt validation (never rewrite receipt/v1) ------------------
    const receipt = structuredClone(options.receipt);
    const receiptDigest = recordDigest(receipt);
    const receiptCheck = validateReceiptV1(receipt, { verifyDigest: true });
    if (!receiptCheck.ok) {
        return {
            ...fail('receipt-validation', 'blocked', [EVIDENCE_REASON_CODES.MARKET_EVIDENCE_INCOMPLETE], 'receipt/v1 is not strictly valid'),
            errors: receiptCheck.errors,
        };
    }
    enter(steps, 'receipt-validation');
    const archiveProvider = options.archiveProvider;
    const signingProvider = options.signingProvider;
    if (!isPlainObject(archiveProvider) || typeof archiveProvider.append !== 'function' ||
        typeof archiveProvider.describe !== 'function' || typeof archiveProvider.get !== 'function') {
        return fail('archive-subject', 'blocked', [EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_MISSING], 'archive provider interface missing');
    }
    if (!isPlainObject(signingProvider) || typeof signingProvider.sign !== 'function' ||
        typeof signingProvider.describe !== 'function') {
        return fail('archive-subject', 'blocked', [EVIDENCE_REASON_CODES.SIGNING_PROVIDER_MISSING], 'signing provider interface missing');
    }
    // Pin provider documents before any evidence is produced; the independent
    // verification below uses these snapshots, not a live provider self-claim.
    const pinnedArchiveProvider = structuredClone(await archiveProvider.describe());
    const pinnedSigningProvider = structuredClone(await signingProvider.describe());
    const archiveDoc = validateMarketDocument(pinnedArchiveProvider, MARKET_ARCHIVE_V1_SCHEMA);
    const signingDoc = validateMarketDocument(pinnedSigningProvider, SIGNING_PROVIDER_V1_SCHEMA);
    if (!archiveDoc.ok || !signingDoc.ok) {
        return fail('archive-subject', 'blocked', [EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE], `provider document invalid: ${[...archiveDoc.errors, ...signingDoc.errors].join(', ')}`);
    }
    const pinnedArchive = pinnedArchiveProvider;
    const pinnedSigner = pinnedSigningProvider;
    // ---- 2. archive subject inputs as entry N ------------------------------
    const headBefore = await archiveProvider.head();
    if (!isPlainObject(headBefore) || headBefore.status !== 'ok') {
        return fail('archive-subject', 'blocked', [EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_MISSING], 'archive head unavailable');
    }
    const headSequence = typeof headBefore.sequence === 'number' ? headBefore.sequence : 0;
    const headDigest = typeof headBefore.entry_digest === 'string' ? headBefore.entry_digest : null;
    const expectedSubject = options.expectedSubjectHead ?? {
        sequence: headSequence + 1,
        previous_entry_digest: headDigest,
    };
    const subjectDraft = buildSubjectEntryDraft({
        receiptDigest,
        isolationAttestationDigest: options.isolation.attestation_digest,
        policyDigest: options.policy.digest,
        approvalDigests: options.approvalDigests ?? [],
    });
    subjectDraft.expected = expectedSubject;
    const subjectResult = await archiveProvider.append(subjectDraft);
    if (!isPlainObject(subjectResult) || subjectResult.status !== 'appended' ||
        !isPlainObject(subjectResult.anchor)) {
        const codes = isPlainObject(subjectResult) && Array.isArray(subjectResult.reason_codes)
            ? subjectResult.reason_codes.filter((code) => typeof code === 'string')
            : [EVIDENCE_REASON_CODES.ARCHIVE_APPEND_FAILED];
        return fail('archive-subject', isPlainObject(subjectResult) && subjectResult.status === 'blocked' ? 'blocked' : 'rejected', codes, isPlainObject(subjectResult) && typeof subjectResult.detail === 'string'
            ? subjectResult.detail
            : 'subject append failed');
    }
    const subjectAnchor = subjectResult.anchor;
    const subjectEntry = subjectResult.entry;
    enter(steps, 'archive-subject');
    const subjectManifestDigest = evidenceManifestDigest({
        receiptDigest,
        isolationAttestationDigest: options.isolation.attestation_digest,
        isolationVerificationDigest: options.isolation.verification_digest,
        policyDigest: options.policy.digest,
        approvalDigests: options.approvalDigests ?? [],
        archiveAnchorDigest: canonicalDigest(subjectAnchor),
    });
    // ---- 3. eligibility (injected; based on anchor_N) ----------------------
    if (typeof options.computeEligibility !== 'function') {
        return fail('eligibility', 'blocked', [EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE], 'no eligibility engine injected');
    }
    let eligibilityRaw;
    try {
        eligibilityRaw = await options.computeEligibility({
            receipt,
            receiptDigest,
            subjectAnchor,
            subjectEntry,
            evidenceManifestDigest: subjectManifestDigest,
            policy: options.policy,
        });
    }
    catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return fail('eligibility', 'blocked', [EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE], `eligibility engine failed: ${message}`);
    }
    enter(steps, 'eligibility');
    if (!isPlainObject(eligibilityRaw) || eligibilityRaw.schema_version !== 'market-eligibility/v1') {
        return fail('eligibility', 'blocked', [EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE], 'eligibility record invalid');
    }
    const eligibility = eligibilityRaw;
    if (eligibility.evidence_manifest_digest !== subjectManifestDigest) {
        return fail('eligibility', 'blocked', [EVIDENCE_REASON_CODES.MARKET_EVIDENCE_INCOMPLETE], 'eligibility does not bind the subject manifest');
    }
    const eligibilityDigest = canonicalDigest(eligibility);
    if (eligibility.decision !== 'eligible') {
        const codes = Array.isArray(eligibility.reason_codes) && eligibility.reason_codes.length > 0
            ? eligibility.reason_codes
            : [EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE];
        return {
            ...fail('eligibility', 'non-eligible', codes, 'eligibility decision is not eligible'),
            receipt_digest: receiptDigest,
            subject_anchor: subjectAnchor,
            eligibility,
            eligibility_digest: eligibilityDigest,
        };
    }
    // ---- 4. build market-attestation/v1 (archive = anchor_N) --------------
    let attestationDraft;
    try {
        attestationDraft = buildMarketAttestation({
            attestationId: options.attestationId,
            receipt,
            receiptDigest,
            eligibility,
            eligibilityDigest,
            expectedManifestDigest: subjectManifestDigest,
            controlPlane: options.controlPlane,
            isolation: options.isolation,
            runtime: options.runtime,
            subjectAnchor,
            signing: {
                provider_id: pinnedSigner.provider_id,
                key_id: options.signing.key_id,
                alg: options.signing.alg,
                signed_at: options.signing.signed_at,
                provider_audit_ref: options.signing.provider_audit_ref,
            },
            limitations: ['development-sequence-inputs-not-market-evidence'],
        });
    }
    catch (error) {
        const reasonCode = error instanceof Error && 'reason_code' in error && typeof error.reason_code === 'string'
            ? error.reason_code
            : EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE;
        const message = error instanceof Error ? error.message : String(error);
        return {
            ...fail('attestation-build', 'blocked', [reasonCode], message),
            receipt_digest: receiptDigest,
            subject_anchor: subjectAnchor,
            eligibility,
        };
    }
    enter(steps, 'attestation-build');
    // ---- 5. sign (never sign a non-eligible or anchor-less payload) -------
    const signingResult = await signMarketAttestation({
        attestation: attestationDraft,
        signingProvider,
        requester: options.requester,
        requestId: options.requestId,
    });
    if (signingResult.status !== 'signed' || signingResult.attestation === undefined) {
        return {
            ...fail('sign', signingResult.status === 'blocked' ? 'blocked' : 'rejected', signingResult.reason_codes.length > 0
                ? signingResult.reason_codes
                : [EVIDENCE_REASON_CODES.SIGNATURE_VERIFICATION_FAILED], signingResult.detail ?? 'signing failed'),
            receipt_digest: receiptDigest,
            subject_anchor: subjectAnchor,
            eligibility,
            attestation_entry_absent: true,
        };
    }
    enter(steps, 'sign');
    const signedAttestation = signingResult.attestation;
    const signedAttestationDigest = marketAttestationDigest(signedAttestation);
    // ---- 6. archive eligibility + attestation as entry N+1 -----------------
    const attestationDraftEntry = buildAttestationEntryDraft({
        receiptDigest,
        eligibilityDigest,
        attestationDigest: signedAttestationDigest,
    });
    attestationDraftEntry.expected = {
        sequence: subjectAnchor.sequence + 1,
        previous_entry_digest: subjectAnchor.entry_digest,
    };
    const attestationEntryResult = await archiveProvider.append(attestationDraftEntry);
    if (!isPlainObject(attestationEntryResult) || attestationEntryResult.status !== 'appended' ||
        !isPlainObject(attestationEntryResult.anchor)) {
        const codes = isPlainObject(attestationEntryResult) && Array.isArray(attestationEntryResult.reason_codes)
            ? attestationEntryResult.reason_codes.filter((code) => typeof code === 'string')
            : [EVIDENCE_REASON_CODES.ARCHIVE_APPEND_FAILED];
        return {
            ...fail('archive-attestation', isPlainObject(attestationEntryResult) && attestationEntryResult.status === 'blocked' ? 'blocked' : 'rejected', codes, isPlainObject(attestationEntryResult) && typeof attestationEntryResult.detail === 'string'
                ? attestationEntryResult.detail
                : 'attestation append failed'),
            receipt_digest: receiptDigest,
            subject_anchor: subjectAnchor,
            eligibility,
            attestation: signedAttestation,
            attestation_digest: signedAttestationDigest,
        };
    }
    const attestationAnchor = attestationEntryResult.anchor;
    enter(steps, 'archive-attestation');
    // ---- 7. independent verification (pinned docs, read-back chain) -------
    const entries = await readArchiveEntries(archiveProvider, attestationAnchor.sequence);
    const verificationResult = verifyMarketAttestation({
        attestation: signedAttestation,
        pinnedSigningProvider,
        pinnedArchiveProvider,
        archiveEntries: entries ?? [],
        expectedReceiptDigest: receiptDigest,
        expectedEligibilityDigest: eligibilityDigest,
        expectedSubjectAnchor: subjectAnchor,
        policy: {
            ...(options.verifier.policy ?? {}),
            ...(options.expectedMinimumIsolation === undefined
                ? {}
                : { minimum_isolation: options.expectedMinimumIsolation }),
        },
        verificationId: `verify:${options.attestationId}`,
        verifiedBy: options.verifier.id,
        verifiedAt: options.verifier.verifiedAt,
        limitations: ['development-sequence-inputs-not-market-evidence'],
    });
    enter(steps, 'verification');
    const evidence = classifyMarketEvidence({
        signingProvider: pinnedSigner,
        archiveProvider: pinnedArchive,
        verificationValid: verificationResult.verification.result === 'valid',
    });
    const marketEligible = verificationResult.verification.result === 'valid' &&
        evidence.market_eligible === true &&
        verificationResult.market_eligible === true;
    // The receipt must be byte-for-byte immutability-checked at the end.
    const receiptUnchanged = recordDigest(receipt) === receiptDigest;
    if (!receiptUnchanged) {
        return fail('verification', 'blocked', [EVIDENCE_REASON_CODES.INTERNAL_ERROR], 'receipt/v1 was mutated by the evidence pipeline');
    }
    const devProviders = pinnedSigner.trust_class === 'development-only' ||
        pinnedArchive.trust_class === 'development-only';
    return {
        status: marketEligible ? 'verified' : (evidence.evidence_class === 'blocked' ? 'blocked' : 'non-eligible'),
        failure_stage: marketEligible ? null : 'verification',
        market_eligible: marketEligible,
        publish: marketEligible,
        steps,
        receipt_digest: receiptDigest,
        subject_anchor: subjectAnchor,
        subject_manifest_digest: subjectManifestDigest,
        eligibility,
        eligibility_digest: eligibilityDigest,
        attestation: signedAttestation,
        attestation_digest: signedAttestationDigest,
        attestation_anchor: attestationAnchor,
        verification: verificationResult.verification,
        evidence_class: evidence.evidence_class,
        reason_codes: marketEligible
            ? []
            : [...new Set([
                    ...verificationResult.verification.reason_codes,
                    ...evidence.reason_codes,
                    ...(devProviders ? [EVIDENCE_REASON_CODES.DEVELOPMENT_ONLY_NOT_MARKET] : []),
                ])],
        limitations: [
            'development-sequence-inputs-not-market-evidence',
            'no-kms-hsm-os-keystore',
            'no-independent-archive-tsa',
        ],
    };
}
export { MARKET_ATTESTATION_VERSION };
