/**
 * `market-attestation/v1` construction and independent market verification.
 *
 * This module implements the post-eligibility half of the fixed order in
 * SIG-08:
 *
 *   receipt/isolation/policy/approvals → entry N (anchor_N)
 *   → eligibility → build attestation (archive = anchor_N)
 *   → sign → entry N+1 → independent verification
 *
 * A cryptographic signature over a development signer is *not* market
 * evidence. `verifyMarketAttestation()` therefore separates three questions:
 * schema/bindings, cryptography, and provider trust. It can report a valid
 * cryptographic signature with `result: "invalid"` for a development or
 * unavailable provider, and only an E3 provider/archive pair with a valid,
 * durable chain can produce `result: "valid"` / `market_eligible: true`.
 * In this environment no such provider exists, so the honest outcome is always
 * `blocked`/`non-eligible` (fail-closed).
 *
 * @module @deepseek-ai/dsh-plugin-testbed/evidence/attestation
 */
import {
  EVIDENCE_REASON_CODES,
  MARKET_ATTESTATION_V1_SCHEMA,
  MARKET_ARCHIVE_V1_SCHEMA,
  MARKET_ATTESTATION_VERSION,
  MARKET_ATTESTATION_VERIFICATION_VERSION,
  SIGNING_PROVIDER_V1_SCHEMA,
  validateMarketDocument,
} from '../protocol/market-schemas.js'
import { validateReceiptV1 } from '../protocol/contracts.js'
import { recordDigest } from '../protocol/digest.js'
import {
  attestationVerificationDigest,
  canonicalDigest,
  marketAttestationDigest,
  validateArchiveAnchor,
  validateAttestationVerification,
} from './canonical.js'
import {
  archiveProviderTrustIssues,
  verifyArchiveChain,
} from './archive.js'
import {
  EvidenceError,
  checkKeyValidity,
  signingProviderTrustIssues,
  unique,
  validateVerificationRecord,
  verifyAttestationSignature,
} from './signing.js'
import type {
  ArchiveAnchor,
  ArchiveEntry,
  AttestationIsolation,
  AttestationRuntime,
  AttestationSigning,
  AttestationSubject,
  AttestationVerification,
  CheckEntry,
  ExpectedHead,
  MarketArchiveProviderDoc,
  MarketAttestation,
  MarketEligibility,
  PolicyReference,
  SigningKeyDoc,
  SigningProviderDoc,
  UnknownRecord,
  ValidationResult,
  VersionRef,
} from './types.js'

const ISOLATION_RANK: Readonly<Record<string, number>> = Object.freeze({ L0: 0, L1: 1, L2: 2, L3: 3 })

function isPlainObject(value: unknown): value is UnknownRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

/** Partial, null-safe view of an untrusted archive entry. */
function entryView(raw: unknown): Partial<ArchiveEntry> {
  return isPlainObject(raw) ? (raw as unknown as Partial<ArchiveEntry>) : {}
}

function check(id: string, ok: boolean, reasonCode: string, evidenceRef: string | null = null): CheckEntry {
  return {
    id,
    status: ok ? 'pass' : 'fail',
    reason_code: ok ? null : reasonCode,
    evidence_ref: evidenceRef,
  }
}

/**
 * Validate the unsigned form of `market-attestation/v1` (everything required
 * except `signing.signature`, which is added only by the signer).
 */
export function validateAttestationDraft(attestation: unknown): ValidationResult {
  const errors: string[] = []
  if (!isPlainObject(attestation)) return { ok: false, errors: ['not-object'] }
  if (attestation.schema_version !== MARKET_ATTESTATION_VERSION) {
    errors.push(`unknown-version:${String(attestation.schema_version)}`)
  }
  for (const field of [
    'attestation_id', 'subject', 'eligibility', 'control_plane',
    'isolation', 'runtime', 'signing', 'archive', 'limitations',
  ]) {
    if (!(field in attestation)) errors.push(`missing:${field}`)
  }
  const signing = attestation.signing
  if (isPlainObject(signing) && 'signature' in signing) {
    errors.push('draft-must-not-carry-signature')
  }
  for (const field of ['provider_id', 'key_id', 'alg', 'signed_at', 'provider_audit_ref']) {
    if (isPlainObject(signing) && typeof signing[field] !== 'string') {
      errors.push(`missing-signing:${field}`)
    }
  }
  return { ok: errors.length === 0, errors }
}

export interface BuildMarketAttestationInput {
  attestationId: string
  receipt: UnknownRecord
  receiptDigest?: string
  eligibility: MarketEligibility
  eligibilityDigest?: string
  expectedManifestDigest?: string
  controlPlane: {
    id: string
    version: string
    policy_ref: VersionRef
  }
  isolation: AttestationIsolation
  runtime: AttestationRuntime
  subjectAnchor: ArchiveAnchor
  signing: {
    provider_id: string
    key_id: string
    alg: string
    signed_at: string
    provider_audit_ref: string
  }
  limitations?: string[]
}

/**
 * Build the unsigned `market-attestation/v1` envelope.
 *
 * Preconditions are fail-closed: a structurally invalid receipt, a
 * non-eligible decision, a missing subject anchor, or a mismatch between
 * declared and computed digests throws `EvidenceError`. It never fills in a
 * placeholder signature.
 */
export function buildMarketAttestation(input: BuildMarketAttestationInput): MarketAttestation {
  const receiptCheck = validateReceiptV1(input.receipt, { verifyDigest: true })
  if (!receiptCheck.ok) {
    throw new EvidenceError(
      EVIDENCE_REASON_CODES.MARKET_EVIDENCE_INCOMPLETE,
      'receipt/v1 is not strictly valid; market attestation refuses it',
      { errors: receiptCheck.errors },
    )
  }
  const computedReceiptDigest = recordDigest(input.receipt)
  const receiptDigest = input.receiptDigest ?? computedReceiptDigest
  if (receiptDigest !== computedReceiptDigest) {
    throw new EvidenceError(
      EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISMATCH,
      'receipt digest binding mismatch',
    )
  }
  if (
    !isPlainObject(input.eligibility) ||
    input.eligibility.schema_version !== 'market-eligibility/v1' ||
    input.eligibility.decision !== 'eligible'
  ) {
    throw new EvidenceError(
      EVIDENCE_REASON_CODES.MARKET_EVIDENCE_INCOMPLETE,
      'market attestation requires an eligible market-eligibility/v1 decision',
    )
  }
  const eligibilityDigest = input.eligibilityDigest ?? canonicalDigest(input.eligibility)
  if (eligibilityDigest !== canonicalDigest(input.eligibility)) {
    throw new EvidenceError(
      EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISMATCH,
      'eligibility digest binding mismatch',
    )
  }
  if (typeof input.expectedManifestDigest === 'string' &&
    input.eligibility.evidence_manifest_digest !== input.expectedManifestDigest) {
    throw new EvidenceError(
      EVIDENCE_REASON_CODES.MARKET_EVIDENCE_INCOMPLETE,
      'eligibility does not bind the subject evidence manifest',
    )
  }
  const anchorCheck = validateArchiveAnchor(input.subjectAnchor)
  if (!anchorCheck.ok) {
    throw new EvidenceError(
      EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISSING,
      'subject archive anchor is not valid',
      { errors: anchorCheck.errors },
    )
  }
  if (input.subjectAnchor.receipt_digest !== receiptDigest) {
    throw new EvidenceError(
      EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISMATCH,
      'subject anchor does not bind the receipt digest',
    )
  }

  const subject: AttestationSubject = {
    receipt_schema_version: 'receipt/v1',
    run_id: input.receipt.run_id as string,
    plan_id: input.receipt.plan_id as string,
    record_digest: receiptDigest,
  }
  const signing: AttestationSigning = {
    provider_id: input.signing.provider_id,
    key_id: input.signing.key_id,
    alg: input.signing.alg,
    signed_at: input.signing.signed_at,
    provider_audit_ref: input.signing.provider_audit_ref,
  }
  const attestation: MarketAttestation = {
    schema_version: MARKET_ATTESTATION_VERSION,
    attestation_id: input.attestationId,
    subject,
    eligibility: {
      schema_version: 'market-eligibility/v1',
      decision_digest: eligibilityDigest,
    },
    control_plane: structuredClone(input.controlPlane),
    isolation: structuredClone(input.isolation),
    runtime: structuredClone(input.runtime),
    signing,
    archive: {
      provider_id: input.subjectAnchor.provider_id,
      anchor_id: input.subjectAnchor.anchor_id,
      sequence: input.subjectAnchor.sequence,
      entry_digest: input.subjectAnchor.entry_digest,
      archived_at: input.subjectAnchor.archived_at,
    },
    limitations: [...(input.limitations ?? [])],
  }
  const draft = validateAttestationDraft(attestation)
  if (!draft.ok) {
    throw new EvidenceError(
      EVIDENCE_REASON_CODES.MARKET_EVIDENCE_INCOMPLETE,
      'market attestation draft is not valid',
      { errors: draft.errors },
    )
  }
  return attestation
}

export interface VerifyMarketAttestationInput {
  attestation: unknown
  pinnedSigningProvider: unknown
  pinnedArchiveProvider: unknown
  archiveEntries?: unknown[]
  expectedReceiptDigest?: string
  expectedEligibilityDigest?: string
  expectedSubjectAnchor?: ArchiveAnchor
  policy?: PolicyReference
  providerAudit?: UnknownRecord
  /** Optional independent provider-signature/MAC check over each stored entry. */
  verifyArchiveProviderSignature?: (entry: unknown) => boolean
  verificationId?: string
  verifiedBy: string
  verifiedAt?: string
  limitations?: string[]
}

export interface MarketVerificationResult {
  verification: AttestationVerification
  ok: boolean
  evidence_class: string
  market_eligible: boolean
}

/**
 * Independent verification of a signed `market-attestation/v1`.
 *
 * All trust inputs are pinned by the caller/verifier; nothing is trusted from
 * the signer except the signed document itself. Missing archive entries, a
 * broken chain, a development-only provider, revoked keys or an absent trusted
 * time source all make the record `invalid` with stable reason codes.
 */
export function verifyMarketAttestation(input: VerifyMarketAttestationInput): MarketVerificationResult {
  const reasonCodes: string[] = []
  const checks: CheckEntry[] = []
  const limitations = [...(input.limitations ?? [])]
  const attestation = input.attestation

  const shaped = validateMarketDocument(attestation, MARKET_ATTESTATION_V1_SCHEMA)
  checks.push(check('schema', shaped.ok, EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE))
  if (!shaped.ok) {
    reasonCodes.push(EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE)
    return finishVerification({
      input,
      checks,
      reasonCodes,
      limitations,
      signatureVerified: false,
      archiveChainVerified: false,
    })
  }
  const doc = attestation as MarketAttestation
  if (doc.schema_version !== MARKET_ATTESTATION_VERSION) {
    return finishVerification({
      input,
      checks: [...checks, check('version', false, EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE)],
      reasonCodes: [EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE],
      limitations,
      signatureVerified: false,
      archiveChainVerified: false,
    })
  }

  // ---- provider trust (SIG-02/SIG-03/SIG-10, ARC-03/ARC-07) --------------
  const signingTrust = signingProviderTrustIssues(input.pinnedSigningProvider)
  const archiveTrust = archiveProviderTrustIssues(input.pinnedArchiveProvider)
  const devOnly = signingTrust.reason_codes.includes(EVIDENCE_REASON_CODES.DEVELOPMENT_ONLY_NOT_MARKET) ||
    archiveTrust.reason_codes.includes(EVIDENCE_REASON_CODES.DEVELOPMENT_ONLY_NOT_MARKET)
  reasonCodes.push(...signingTrust.reason_codes, ...archiveTrust.reason_codes)
  if (devOnly) reasonCodes.push(EVIDENCE_REASON_CODES.DEVELOPMENT_ONLY_NOT_MARKET)
  checks.push(check('signing-provider-trust', signingTrust.ok, EVIDENCE_REASON_CODES.SIGNING_PROVIDER_UNTRUSTED))
  checks.push(check('archive-provider-trust', archiveTrust.ok, EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_UNTRUSTED))
  const pinnedSigner = isPlainObject(input.pinnedSigningProvider)
    ? (input.pinnedSigningProvider as unknown as SigningProviderDoc)
    : null
  const pinnedArchive = isPlainObject(input.pinnedArchiveProvider)
    ? (input.pinnedArchiveProvider as unknown as MarketArchiveProviderDoc)
    : null
  const signingBindingOk = pinnedSigner !== null && doc.signing.provider_id === pinnedSigner.provider_id
  if (!signingBindingOk) reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_PROVIDER_UNTRUSTED)
  checks.push(check('signing-provider-binding', signingBindingOk, EVIDENCE_REASON_CODES.SIGNING_PROVIDER_UNTRUSTED))
  const archiveBindingOk = pinnedArchive !== null && doc.archive.provider_id === pinnedArchive.provider_id
  if (!archiveBindingOk) reasonCodes.push(EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_UNTRUSTED)
  checks.push(check('archive-provider-binding', archiveBindingOk, EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_UNTRUSTED))

  // ---- subject / eligibility bindings ------------------------------------
  const subjectOk = doc.subject.receipt_schema_version === 'receipt/v1' &&
    (input.expectedReceiptDigest === undefined || doc.subject.record_digest === input.expectedReceiptDigest)
  if (!subjectOk) reasonCodes.push(EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISMATCH)
  checks.push(check('receipt-digest-binding', subjectOk, EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISMATCH))

  const eligibilityOk = input.expectedEligibilityDigest === undefined ||
    doc.eligibility.decision_digest === input.expectedEligibilityDigest
  if (!eligibilityOk) reasonCodes.push(EVIDENCE_REASON_CODES.MARKET_EVIDENCE_INCOMPLETE)
  checks.push(check('eligibility-digest-binding', eligibilityOk, EVIDENCE_REASON_CODES.MARKET_EVIDENCE_INCOMPLETE))

  // ---- cryptographic signature ------------------------------------------
  const pinnedKeys: SigningKeyDoc[] = pinnedSigner !== null && Array.isArray(pinnedSigner.keys)
    ? pinnedSigner.keys
    : []
  const pinnedKey = pinnedKeys.find((candidate) => candidate.key_id === doc.signing.key_id)
  let signatureOk = false
  if (pinnedKey === undefined) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_KEY_UNKNOWN)
    checks.push(check('key-status', false, EVIDENCE_REASON_CODES.SIGNING_KEY_UNKNOWN))
  } else {
    const validity = checkKeyValidity(pinnedKey, { at: doc.signing.signed_at })
    reasonCodes.push(...validity.reason_codes)
    checks.push(check('key-status', validity.ok, validity.reason_codes[0] ?? EVIDENCE_REASON_CODES.SIGNING_KEY_INACTIVE))
    const policy = input.policy ?? {}
    const allowed = Array.isArray(policy.allowed_signers)
      ? policy.allowed_signers.some((signer) =>
        signer.key_id === pinnedKey.key_id &&
        signer.alg === pinnedKey.alg &&
        (signer.state === undefined || signer.state === 'active'))
      : true
    checks.push(check('signer-allowlist', allowed, EVIDENCE_REASON_CODES.SIGNING_PROVIDER_UNTRUSTED))
    if (!allowed) reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_PROVIDER_UNTRUSTED)
    const signature = verifyAttestationSignature({ attestation: doc, key: pinnedKey })
    signatureOk = signature.ok
    reasonCodes.push(...signature.reason_codes)
    checks.push(check('signature', signature.ok, EVIDENCE_REASON_CODES.SIGNATURE_VERIFICATION_FAILED))
  }

  // ---- provider audit ref ------------------------------------------------
  const auditRef = doc.signing.provider_audit_ref
  let auditOk = typeof auditRef === 'string' && auditRef.length > 0
  if (auditOk && isPlainObject(input.providerAudit)) {
    const entries = Array.isArray(input.providerAudit.entries) ? input.providerAudit.entries : []
    auditOk = entries.some((entry) => isPlainObject(entry) && entry.provider_audit_ref === auditRef)
    if (!auditOk) reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_PROVIDER_UNTRUSTED)
  } else if (auditOk) {
    limitations.push('provider-audit-ref-not-reverified')
  }
  checks.push(check('provider-audit-ref', auditOk, EVIDENCE_REASON_CODES.SIGNING_PROVIDER_UNTRUSTED))

  // ---- archive anchor + chain + entry N+1 --------------------------------
  const entries = Array.isArray(input.archiveEntries) ? input.archiveEntries : null
  let chainOk = false
  let attestationEntryOk = false
  let archiveChainVerified = false
  let trustedTimeOk = false
  let attestationArchiveEntryDigest: string | null = null
  if (entries === null) {
    reasonCodes.push(EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_MISSING)
    checks.push(check('archive-entries', false, EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_MISSING))
  } else {
    const subjectIndex = doc.archive.sequence - 1
    const subjectRaw = entries[subjectIndex]
    const subjectEntry = entryView(subjectRaw)
    const subjectArchiveId = typeof subjectEntry.archive_id === 'string' ? subjectEntry.archive_id : undefined
    let anchorOk = isPlainObject(subjectRaw) &&
      subjectEntry.sequence === doc.archive.sequence &&
      subjectEntry.entry_digest === doc.archive.entry_digest &&
      subjectEntry.archived_at === doc.archive.archived_at &&
      subjectEntry.receipt_digest === doc.subject.record_digest &&
      subjectEntry.attestation_digest === null
    if (input.expectedSubjectAnchor !== undefined) {
      const expected = input.expectedSubjectAnchor
      anchorOk = anchorOk &&
        isPlainObject(expected) &&
        expected.entry_digest === doc.archive.entry_digest &&
        expected.sequence === doc.archive.sequence &&
        expected.provider_id === doc.archive.provider_id &&
        expected.archived_at === doc.archive.archived_at
    }
    if (!anchorOk) reasonCodes.push(EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISMATCH)
    checks.push(check('archive-anchor-binding', anchorOk, EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISMATCH))

    const chain = verifyArchiveChain(entries, {
      archiveId: subjectArchiveId,
      providerId: doc.archive.provider_id,
      requireAttestationPair: true,
      verifyProviderSignature: input.verifyArchiveProviderSignature,
      verifiedAt: input.verifiedAt,
      verificationId: input.verificationId === undefined ? undefined : `${input.verificationId}:chain`,
      limitations,
    })
    chainOk = chain.ok
    reasonCodes.push(...chain.verification.reason_codes)
    checks.push(check('archive-chain', chain.ok, EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED))

    const attestationRaw = entries[doc.archive.sequence]
    const attestationEntry = entryView(attestationRaw)
    const signedAttestationDigest = marketAttestationDigest(doc)
    attestationEntryOk = isPlainObject(attestationRaw) &&
      attestationEntry.sequence === doc.archive.sequence + 1 &&
      attestationEntry.attestation_digest === signedAttestationDigest &&
      attestationEntry.eligibility_digest === doc.eligibility.decision_digest &&
      attestationEntry.receipt_digest === doc.subject.record_digest
    if (!attestationEntryOk) {
      reasonCodes.push(EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISSING)
      limitations.push('entry-n-plus-1-missing-or-mismatched')
    } else {
      attestationArchiveEntryDigest = typeof attestationEntry.entry_digest === 'string'
        ? attestationEntry.entry_digest
        : null
    }
    checks.push(check(
      'attestation-archive-entry',
      attestationEntryOk,
      EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISSING,
    ))
    archiveChainVerified = chainOk && attestationEntryOk

    // ---- trusted time -----------------------------------------------------
    const pinnedArchiveTime = pinnedArchive !== null ? pinnedArchive.trusted_time : null
    trustedTimeOk = isPlainObject(pinnedArchiveTime) &&
      pinnedArchiveTime.verified === true &&
      (pinnedArchiveTime.source === 'provider' || pinnedArchiveTime.source === 'tsa')
    if (!trustedTimeOk) reasonCodes.push(EVIDENCE_REASON_CODES.TRUSTED_TIME_UNAVAILABLE)
    checks.push(check('trusted-time', trustedTimeOk, EVIDENCE_REASON_CODES.TRUSTED_TIME_UNAVAILABLE))

    // Each stored entry must carry provider/TSA time, not a host-clock reading.
    const everyEntryTimeTrusted = entries.every((raw) => {
      const entry = entryView(raw)
      const timeSource = entry.time_source
      return isPlainObject(timeSource) &&
        timeSource.trusted === true &&
        (timeSource.source === 'provider' || timeSource.source === 'tsa')
    })
    if (!everyEntryTimeTrusted) reasonCodes.push(EVIDENCE_REASON_CODES.TRUSTED_TIME_UNAVAILABLE)
    checks.push(check(
      'entry-trusted-time',
      everyEntryTimeTrusted,
      EVIDENCE_REASON_CODES.TRUSTED_TIME_UNAVAILABLE,
    ))
  }

  // ---- policy allowlists / isolation level -------------------------------
  const policy = input.policy ?? {}
  const archiveAllowed = Array.isArray(policy.allowed_archives)
    ? policy.allowed_archives.some((candidate) =>
      candidate.provider_id === doc.archive.provider_id &&
      (candidate.mode === undefined || candidate.mode === pinnedArchive?.mode))
    : true
  checks.push(check('archive-allowlist', archiveAllowed, EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_UNTRUSTED))
  if (!archiveAllowed) reasonCodes.push(EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_UNTRUSTED)

  const requiredIsolation = policy.minimum_isolation
  const isolationOk = requiredIsolation === undefined ||
    (ISOLATION_RANK[doc.isolation.level] ?? -1) >= (ISOLATION_RANK[requiredIsolation] ?? 99)
  if (!isolationOk) reasonCodes.push('isolation-level-insufficient')
  checks.push(check('isolation-level', isolationOk, 'isolation-level-insufficient'))

  return finishVerification({
    input,
    checks,
    reasonCodes,
    limitations,
    signatureVerified: signatureOk,
    archiveChainVerified,
    attestationArchiveEntryDigest,
  })
}

/**
 * Classify the evidence level of a signed + verified envelope.
 *
 * Only E3 (independent signing provider, independent archive, verified
 * providers, valid verification) may ever be presented to an eligibility
 * engine; E1/development objects are permanently excluded and unavailable
 * providers yield `blocked`.
 */
export function classifyMarketEvidence(input: {
  signingProvider?: unknown
  archiveProvider?: unknown
  verificationValid?: boolean
}): { evidence_class: string; market_eligible: boolean; reason_codes: string[] } {
  const signingIssues = input.signingProvider === undefined
    ? { ok: false, reason_codes: [EVIDENCE_REASON_CODES.SIGNING_PROVIDER_MISSING], errors: [] }
    : signingProviderTrustIssues(input.signingProvider)
  const archiveIssues = input.archiveProvider === undefined
    ? { ok: false, reason_codes: [EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_MISSING], errors: [] }
    : archiveProviderTrustIssues(input.archiveProvider)
  const reasonCodes = unique([...signingIssues.reason_codes, ...archiveIssues.reason_codes])
  const signer = isPlainObject(input.signingProvider) ? input.signingProvider : null
  const archive = isPlainObject(input.archiveProvider) ? input.archiveProvider : null
  const unavailable = signer?.trust_class === 'unavailable' ||
    archive?.trust_class === 'unavailable' ||
    signer?.availability === 'blocked' ||
    archive?.availability === 'blocked'
  const verificationValid = input.verificationValid === true

  let evidenceClass = 'E1'
  if (unavailable) evidenceClass = 'blocked'
  else if (reasonCodes.includes(EVIDENCE_REASON_CODES.DEVELOPMENT_ONLY_NOT_MARKET)) evidenceClass = 'E1'
  else if (signingIssues.ok && archiveIssues.ok && verificationValid) evidenceClass = 'E3'
  else evidenceClass = 'E2'

  const marketEligible = evidenceClass === 'E3' && verificationValid && reasonCodes.length === 0
  if (!marketEligible) reasonCodes.push(EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE)
  return {
    evidence_class: evidenceClass,
    market_eligible: marketEligible,
    reason_codes: unique(reasonCodes),
  }
}

/**
 * Convenience: verify and classify in one fail-closed call.
 */
export function verifyAndClassify(input: VerifyMarketAttestationInput): {
  verification: AttestationVerification
  evidence: { evidence_class: string; market_eligible: boolean; reason_codes: string[] }
  market_eligible: boolean
} {
  const result = verifyMarketAttestation(input)
  const evidence = classifyMarketEvidence({
    signingProvider: input.pinnedSigningProvider,
    archiveProvider: input.pinnedArchiveProvider,
    verificationValid: result.verification.result === 'valid',
  })
  return {
    verification: result.verification,
    evidence,
    market_eligible: result.verification.result === 'valid' && evidence.market_eligible,
  }
}

/**
 * Verify an already-produced verification record against an attestation
 * (used when consuming a saved evidence package).
 */
export function verifySavedVerificationRecord(
  verification: unknown,
  attestation: unknown,
): { ok: boolean; errors: string[]; reason_codes: string[] } {
  const errors: string[] = []
  const shaped = validateAttestationVerification(verification)
  if (!shaped.ok) errors.push(...shaped.errors.map((error) => `schema:${error}`))
  const record = validateVerificationRecord(verification)
  if (!record.ok) errors.push(...record.errors)
  if (isPlainObject(attestation) && isPlainObject(verification) &&
    verification.attestation_digest !== marketAttestationDigest(attestation)) {
    errors.push('attestation-digest-mismatch')
  }
  return {
    ok: errors.length === 0,
    errors,
    reason_codes: errors.length === 0 ? [] : [EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE],
  }
}

/** Digest of a verification record (saved in the evidence package). */
export function verificationDigest(verification: unknown): string {
  return attestationVerificationDigest(verification)
}

// ---------------------------------------------------------------------------

interface FinishContext {
  input: VerifyMarketAttestationInput
  checks: CheckEntry[]
  reasonCodes: string[]
  limitations: string[]
  signatureVerified: boolean
  archiveChainVerified: boolean
  attestationArchiveEntryDigest?: string | null
}

/**
 * Build the verification record and apply the fail-closed result rule.
 */
function finishVerification(context: FinishContext): MarketVerificationResult {
  const signingIssues = signingProviderTrustIssues(context.input.pinnedSigningProvider)
  const archiveIssues = archiveProviderTrustIssues(context.input.pinnedArchiveProvider)
  const trustOk = signingIssues.ok && archiveIssues.ok
  const reasonCodes = unique([
    ...context.reasonCodes,
    ...signingIssues.reason_codes,
    ...archiveIssues.reason_codes,
  ])
  const allChecksPass = context.checks.length > 0 && context.checks.every((entry) => entry.status === 'pass')
  const valid = trustOk && allChecksPass && reasonCodes.length === 0 &&
    context.signatureVerified === true && context.archiveChainVerified === true &&
    isPlainObject(context.input.attestation)
  if (!valid && reasonCodes.length === 0) reasonCodes.push(EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE)
  const evidence = classifyMarketEvidence({
    signingProvider: context.input.pinnedSigningProvider,
    archiveProvider: context.input.pinnedArchiveProvider,
    verificationValid: valid,
  })

  const attestation = context.input.attestation
  const verification: AttestationVerification = {
    schema_version: MARKET_ATTESTATION_VERIFICATION_VERSION,
    verification_id: context.input.verificationId ??
      `attestation-verify:${String(isPlainObject(attestation) ? attestation.attestation_id : 'unknown')}`,
    attestation_digest: isPlainObject(attestation)
      ? marketAttestationDigest(attestation)
      : 'sha256:' + '0'.repeat(64),
    attestation_archive_entry_digest: context.attestationArchiveEntryDigest ?? null,
    signature_verified: context.signatureVerified === true,
    archive_chain_verified: context.archiveChainVerified === true,
    checks: context.checks,
    result: valid ? 'valid' : 'invalid',
    verified_by: context.input.verifiedBy,
    verified_at: context.input.verifiedAt ?? new Date().toISOString(),
    reason_codes: reasonCodes,
    limitations: unique(context.limitations),
  }
  const recorded = validateVerificationRecord(verification)
  if (!recorded.ok) {
    verification.result = 'invalid'
    verification.signature_verified = false
    verification.archive_chain_verified = false
    verification.reason_codes.push(EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE)
    verification.reason_codes = unique(verification.reason_codes)
  }
  return {
    verification,
    ok: verification.result === 'valid',
    evidence_class: evidence.evidence_class,
    market_eligible: valid && evidence.market_eligible,
  }
}

export { MARKET_ATTESTATION_V1_SCHEMA, MARKET_ARCHIVE_V1_SCHEMA, SIGNING_PROVIDER_V1_SCHEMA }
