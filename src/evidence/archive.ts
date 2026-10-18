/**
 * Append-only archive chain: entry digest, anchor construction and the pure
 * chain verifier (ARC-01, ARC-02, ARC-04, ARC-08).
 *
 * The verifier is deliberately separate from any provider: it accepts the
 * entries read back from storage plus an optional *previously recorded* head
 * (`expectedHead`) and reports tamper, deletion/sequence-gap, replay and
 * rollback. A chain cannot prove its own freshness; callers must pin the last
 * anchor they saw (SIG-08 / ARC-08 "重放旧 anchor").
 *
 * No private key, MAC key or provider credential is used in this module.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/evidence/archive
 */
import {
  ARCHIVE_ANCHOR_VERSION,
  ARCHIVE_CHAIN_VERIFICATION_VERSION,
  ARCHIVE_MARKET_MODES,
  EVIDENCE_REASON_CODES,
  MARKET_ARCHIVE_V1_SCHEMA,
  validateMarketDocument,
} from '../protocol/market-schemas.js'
import {
  archiveEntryDigest,
  canonicalDigest,
  validateArchiveAnchor,
  validateArchiveEntry,
} from './canonical.js'
import { EvidenceError, unique } from './signing.js'
import type {
  ArchiveAnchor,
  ArchiveChainVerification,
  ArchiveEntry,
  ArchiveEntryDraft,
  CheckEntry,
  ExpectedHead,
  MarketArchiveProviderDoc,
  ReasonResult,
  UnknownRecord,
} from './types.js'

function isPlainObject(value: unknown): value is UnknownRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function addReason(reasonCodes: string[], reasonCode: string): void {
  if (!reasonCodes.includes(reasonCode)) reasonCodes.push(reasonCode)
}

function makeCheck(
  id: string,
  ok: boolean,
  reasonCode: string | null,
  evidenceRef: string | null = null,
): CheckEntry {
  return {
    id,
    status: ok ? 'pass' : 'fail',
    reason_code: ok ? null : reasonCode,
    evidence_ref: evidenceRef,
  }
}

/** Partial, null-safe view of an untrusted entry read back from storage. */
function view(raw: unknown): Partial<ArchiveEntry> {
  return isPlainObject(raw) ? (raw as unknown as Partial<ArchiveEntry>) : {}
}

/**
 * Validate archive provider capabilities and compute market trust issues.
 * ARC-03/ARC-06/ARC-07: independent custody, immutable mode and trusted time
 * are all mandatory; local file/git and unavailable providers always fail.
 */
export function archiveProviderTrustIssues(providerDoc: unknown): ReasonResult {
  const reasonCodes: string[] = []
  const errors: string[] = []
  const shaped = validateMarketDocument(providerDoc, MARKET_ARCHIVE_V1_SCHEMA)
  if (!shaped.ok) {
    return {
      ok: false,
      reason_codes: [EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_UNTRUSTED, EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE],
      errors: shaped.errors.map((error) => `schema:${error}`),
    }
  }
  const doc = providerDoc as MarketArchiveProviderDoc
  if (doc.availability !== 'available') {
    addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_MISSING)
    errors.push('provider-unavailable')
  }
  if (doc.trust_class === 'development-only') {
    addReason(reasonCodes, EVIDENCE_REASON_CODES.DEVELOPMENT_ONLY_NOT_MARKET)
    addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_UNTRUSTED)
    errors.push('provider-development-only')
  } else if (doc.trust_class !== 'market-independent') {
    addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_UNTRUSTED)
    errors.push(`provider-trust-class-${doc.trust_class}`)
  }
  if (!(ARCHIVE_MARKET_MODES as readonly string[]).includes(doc.mode)) {
    addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_MODE_NOT_IMMUTABLE)
    errors.push(`archive-mode-not-market:${doc.mode}`)
  }
  const immutability = doc.immutability
  if (immutability.append_only !== true) {
    addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_MODE_NOT_IMMUTABLE)
    errors.push('append-only-not-declared')
  }
  if (immutability.delete_forbidden !== true) {
    addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_MODE_NOT_IMMUTABLE)
    errors.push('delete-not-forbidden')
  }
  if (immutability.retention_days < 1) {
    addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_MODE_NOT_IMMUTABLE)
    errors.push('retention-too-short')
  }
  if (immutability.legal_hold !== true) {
    addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_MODE_NOT_IMMUTABLE)
    errors.push('legal-hold-missing')
  }
  if (doc.trust_anchor.type === 'none-development-only') {
    addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_UNTRUSTED)
    errors.push('trust-anchor-development-only')
  }
  if (doc.trust_anchor.verification_ref === null) {
    addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISSING)
    errors.push('trust-anchor-verification-ref-missing')
  }
  if (doc.trusted_time.verified !== true) {
    addReason(reasonCodes, EVIDENCE_REASON_CODES.TRUSTED_TIME_UNAVAILABLE)
    errors.push('trusted-time-not-verified')
  }
  if (doc.trusted_time.source === 'host-clock-development-only') {
    addReason(reasonCodes, EVIDENCE_REASON_CODES.TRUSTED_TIME_UNAVAILABLE)
    errors.push('trusted-time-host-clock')
  }
  return { ok: reasonCodes.length === 0, reason_codes: unique(reasonCodes), errors }
}

/**
 * Build an `archive-anchor/v1` from a stored entry and provider capabilities.
 */
export function buildArchiveAnchor(entry: ArchiveEntry, providerDoc: MarketArchiveProviderDoc): ArchiveAnchor {
  const anchor: ArchiveAnchor = {
    schema_version: ARCHIVE_ANCHOR_VERSION,
    anchor_id: `${entry.archive_id}:${entry.sequence}:${entry.entry_digest}`,
    provider_id: providerDoc.provider_id,
    archive_id: entry.archive_id,
    sequence: entry.sequence,
    entry_digest: entry.entry_digest,
    previous_entry_digest: entry.previous_entry_digest,
    receipt_digest: entry.receipt_digest,
    archived_at: entry.archived_at,
    trust_anchor: structuredClone(providerDoc.trust_anchor),
    trusted_time: structuredClone(providerDoc.trusted_time),
    provider_audit_ref: entry.provider_audit_ref,
  }
  const shaped = validateArchiveAnchor(anchor)
  if (!shaped.ok) {
    throw new EvidenceError(
      EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISSING,
      'archive anchor is not valid',
      { errors: shaped.errors },
    )
  }
  return anchor
}

export function archiveAnchorDigest(anchor: unknown): string {
  return canonicalDigest(anchor)
}

export interface VerifyArchiveChainOptions {
  archiveId?: string
  providerId?: string
  expectedHead?: ExpectedHead | null
  requireAttestationPair?: boolean
  verifyProviderSignature?: (entry: unknown) => boolean
  verificationId?: string
  verifiedAt?: string
  limitations?: string[]
}

/**
 * Verify a chain of archive entries. Pure: no I/O, no keys.
 */
export function verifyArchiveChain(
  entries: unknown[],
  options: VerifyArchiveChainOptions = {},
): { verification: ArchiveChainVerification; ok: boolean } {
  const reasonCodes: string[] = []
  const checks: CheckEntry[] = []
  const list = Array.isArray(entries) ? entries : []
  const expectedHead = options.expectedHead ?? null

  if (!Array.isArray(entries)) {
    addReason(reasonCodes, EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE)
    checks.push(makeCheck('chain-readable', false, EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE))
  } else {
    checks.push(makeCheck('chain-readable', true, null))
  }

  let invalidSchema = false
  for (const [index, entry] of list.entries()) {
    const shaped = validateArchiveEntry(entry)
    if (!shaped.ok) {
      invalidSchema = true
      checks.push(makeCheck(`schema-${index + 1}`, false, EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE))
    }
  }
  if (invalidSchema) addReason(reasonCodes, EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE)
  checks.push(makeCheck('schema', !invalidSchema, EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE))

  // ---- sequence contiguity / replay --------------------------------------
  let sequenceOk = true
  let replay = false
  for (let index = 0; index < list.length; index += 1) {
    const entry = view(list[index])
    if (entry.sequence !== index + 1) sequenceOk = false
    if (index > 0 && (entry.sequence ?? 0) <= (view(list[index - 1]).sequence ?? 0)) replay = true
  }
  if (!sequenceOk) addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_SEQUENCE_GAP)
  if (replay) addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_REPLAY_DETECTED)
  checks.push(makeCheck('sequence-contiguity', sequenceOk, EVIDENCE_REASON_CODES.ARCHIVE_SEQUENCE_GAP))
  checks.push(makeCheck('sequence-order', !replay, EVIDENCE_REASON_CODES.ARCHIVE_REPLAY_DETECTED))

  // ---- previous-digest chain + entry digest + archive id -----------------
  let chainOk = true
  let digestOk = true
  let archiveIdOk = true
  let timeOk = true
  let previous: Partial<ArchiveEntry> | null = null
  for (const raw of list) {
    const entry = view(raw)
    const expectedPrevious = previous === null ? null : (previous.entry_digest ?? null)
    if ((entry.previous_entry_digest ?? null) !== expectedPrevious) chainOk = false
    let recomputed: string | null
    try {
      recomputed = archiveEntryDigest(raw)
    } catch {
      recomputed = null
    }
    if (recomputed !== entry.entry_digest) digestOk = false
    if (options.archiveId !== undefined && entry.archive_id !== options.archiveId) archiveIdOk = false
    if (previous !== null && typeof entry.archived_at === 'string' && typeof previous.archived_at === 'string') {
      if (Date.parse(entry.archived_at) < Date.parse(previous.archived_at)) timeOk = false
    }
    previous = entry
  }
  if (!chainOk) addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED)
  if (!digestOk) addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED)
  if (!archiveIdOk) addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISMATCH)
  if (!timeOk) addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_TIME_REVERSED)
  checks.push(makeCheck('previous-digest-chain', chainOk, EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED))
  checks.push(makeCheck('entry-digest', digestOk, EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED))
  checks.push(makeCheck('archive-id', archiveIdOk, EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISMATCH))
  checks.push(makeCheck('monotonic-archived-at', timeOk, EVIDENCE_REASON_CODES.ARCHIVE_TIME_REVERSED))

  // ---- duplicate digest (replay of identical entry) ----------------------
  const digests = new Set<string>()
  let duplicateDigest = false
  for (const raw of list) {
    const entry = view(raw)
    const digest = entry.entry_digest
    if (typeof digest === 'string') {
      if (digests.has(digest)) duplicateDigest = true
      digests.add(digest)
    }
  }
  if (duplicateDigest) addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_REPLAY_DETECTED)
  checks.push(makeCheck('duplicate-entry-digest', !duplicateDigest, EVIDENCE_REASON_CODES.ARCHIVE_REPLAY_DETECTED))

  // ---- entry N / N+1 pair semantics -------------------------------------
  let pairOk = true
  for (let index = 0; index < list.length; index += 1) {
    const entry = view(list[index])
    const hasAttestation = typeof entry.attestation_digest === 'string'
    const hasEligibility = typeof entry.eligibility_digest === 'string'
    if (hasAttestation !== hasEligibility) pairOk = false
    if (hasAttestation) {
      const subject = index === 0 ? null : view(list[index - 1])
      if (subject === null) pairOk = false
      else if (subject.attestation_digest !== null || subject.receipt_digest !== entry.receipt_digest) pairOk = false
    }
  }
  if (!pairOk) addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED)
  checks.push(makeCheck('attestation-pair', pairOk, EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED))

  if (options.requireAttestationPair === true) {
    const [previousRaw, lastRaw] = list.slice(-2)
    const previousEntry = view(previousRaw)
    const last = view(lastRaw)
    const complete = Boolean(
      lastRaw !== undefined && previousRaw !== undefined &&
      typeof last.attestation_digest === 'string' &&
      typeof last.eligibility_digest === 'string' &&
      previousEntry.attestation_digest === null &&
      previousEntry.receipt_digest === last.receipt_digest,
    )
    if (!complete) addReason(reasonCodes, EVIDENCE_REASON_CODES.MARKET_EVIDENCE_INCOMPLETE)
    checks.push(makeCheck('last-pair-complete', complete, EVIDENCE_REASON_CODES.MARKET_EVIDENCE_INCOMPLETE))
  }

  // ---- provider signature (delegated; e.g. HMAC for the dev provider) ----
  if (typeof options.verifyProviderSignature === 'function') {
    let providerSignatureOk = true
    for (const entry of list) {
      let valid = false
      try {
        valid = options.verifyProviderSignature(entry) === true
      } catch {
        valid = false
      }
      if (!valid) providerSignatureOk = false
    }
    if (!providerSignatureOk) addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED)
    checks.push(makeCheck('provider-signature', providerSignatureOk, EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED))
  }

  // ---- expected head: truncation / rollback / replay of old anchor -------
  const lastRaw = list.length === 0 ? undefined : list[list.length - 1]
  const last = view(lastRaw)
  const headSequence = list.length === 0 ? 0 : (last.sequence ?? 0)
  const headDigest = list.length === 0 ? null : (last.entry_digest ?? null)
  let headOk = true
  if (expectedHead !== null) {
    if (expectedHead.sequence > headSequence) {
      headOk = false
      addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_ROLLBACK_DETECTED)
      addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_TRUNCATION_DETECTED)
    } else if (expectedHead.sequence === headSequence && expectedHead.entry_digest !== headDigest) {
      headOk = false
      addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED)
      addReason(reasonCodes, EVIDENCE_REASON_CODES.ARCHIVE_ROLLBACK_DETECTED)
    }
    checks.push(makeCheck(
      'expected-head',
      headOk,
      headOk ? null : EVIDENCE_REASON_CODES.ARCHIVE_ROLLBACK_DETECTED,
    ))
  } else {
    checks.push(makeCheck('expected-head', true, null))
  }

  const result = reasonCodes.length === 0 ? 'valid' : 'invalid'
  const verification: ArchiveChainVerification = {
    schema_version: ARCHIVE_CHAIN_VERIFICATION_VERSION,
    verification_id: options.verificationId ?? `chain-verify:${options.archiveId ?? 'archive'}:${headSequence}`,
    archive_id: options.archiveId ?? (list.length > 0 ? (view(list[0]).archive_id ?? 'unknown') : 'unknown'),
    provider_id: options.providerId ?? 'unknown',
    sequence_head: headSequence,
    head_entry_digest: headDigest,
    expected_head: expectedHead,
    result,
    checks,
    reason_codes: unique(reasonCodes),
    verified_at: options.verifiedAt ?? new Date().toISOString(),
    limitations: options.limitations ?? [],
  }
  return { verification, ok: result === 'valid' }
}

/**
 * Construct a subject archive entry draft (entry N). Sequence/previous/entry
 * digest/archived_at are owned by the provider; the caller supplies digests.
 */
export function buildSubjectEntryDraft(input: {
  receiptDigest: string
  isolationAttestationDigest?: string | null
  policyDigest?: string | null
  approvalDigests?: string[]
}): ArchiveEntryDraft {
  return {
    receipt_digest: input.receiptDigest,
    isolation_attestation_digest: input.isolationAttestationDigest ?? null,
    policy_digest: input.policyDigest ?? null,
    approval_digests: [...(input.approvalDigests ?? [])],
    attestation_digest: null,
    eligibility_digest: null,
  }
}

/**
 * Construct the attestation archive entry draft (entry N+1).
 */
export function buildAttestationEntryDraft(input: {
  receiptDigest: string
  eligibilityDigest: string
  attestationDigest: string
}): ArchiveEntryDraft {
  return {
    receipt_digest: input.receiptDigest,
    isolation_attestation_digest: null,
    policy_digest: null,
    approval_digests: [],
    attestation_digest: input.attestationDigest,
    eligibility_digest: input.eligibilityDigest,
  }
}

/**
 * Conventional `archive-entry/v1` digest input check for external callers.
 */
export function verifyEntryDigest(entry: unknown): { ok: boolean; expected: string; actual: string } {
  const expected = archiveEntryDigest(entry)
  const actual = view(entry).entry_digest
  return { ok: expected === actual, expected, actual: typeof actual === 'string' ? actual : '' }
}
