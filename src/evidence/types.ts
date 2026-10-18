/**
 * Type model for market evidence (signing, attestation, archive).
 *
 * Runtime authority for field shapes remains the JSON Schemas in
 * `../protocol/market-schemas.js`; these interfaces exist only to give the
 * TypeScript implementation a strict, `any`-free view of already-validated
 * documents. Every trust boundary takes `unknown` and narrows explicitly.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/evidence/types
 */
import type { JsonValue, UnknownRecord, ValidationResult } from '../protocol/types.js'

export type { JsonValue, UnknownRecord, ValidationResult }

// ---------------------------------------------------------------------------
// Shared result shapes
// ---------------------------------------------------------------------------

export interface CheckEntry {
  id: string
  status: string
  reason_code: string | null
  evidence_ref: string | null
}

export interface ReasonResult {
  ok: boolean
  reason_codes: string[]
  errors: string[]
}

export interface ExpectedHead {
  sequence: number
  entry_digest?: string | null
  previous_entry_digest?: string | null
}

export interface VersionRef {
  id: string
  version: string
  digest: string
}

export interface PolicyReference {
  allowed_signers?: Array<{ key_id: string; alg: string; state?: string }>
  allowed_archives?: Array<{ provider_id: string; mode?: string }>
  minimum_isolation?: string
}

// ---------------------------------------------------------------------------
// Signing provider / request / response
// ---------------------------------------------------------------------------

export interface SigningRequester {
  control_plane_id: string
  authorization_ref: string
}

export interface SigningKeyDoc {
  key_id: string
  alg: string
  public_key: string
  public_key_digest: string
  state: string
  created_at: string
  expires_at: string | null
  rotated_at?: string | null
  revoked_at?: string | null
  revocation_reason?: string | null
  attestation_ref?: string | null
}

export interface SigningGuarantees {
  private_key_export: string
  signing_op: string
  audit: string
  blind_sign: string
}

export interface ProviderAttestation {
  schema_version: string
  digest: string
}

export interface SigningProviderDoc {
  schema_version: string
  provider_id: string
  provider_version: string
  provider_kind: string
  trust_domain: string
  algorithms: string[]
  keys: SigningKeyDoc[]
  guarantees: SigningGuarantees
  trust_class: string
  availability: string
  limitations: string[]
  attestation: ProviderAttestation | null
}

export interface SigningRequestDoc {
  schema_version: string
  request_id: string
  key_id: string
  alg: string
  domain_separation: string
  payload_digest: string
  payload_kind: string
  audit_ref: string
  requested_at: string
  requester: SigningRequester
}

export interface SigningResponseDoc {
  schema_version: string
  request_id: string
  key_id: string
  alg: string
  signature: string
  signed_payload_digest: string
  signed_at: string
  provider_audit_ref: string
}

export interface ProviderOperationResult {
  status: string
  reason_codes?: string[]
  errors?: string[]
  detail?: string
  old_key_id?: string
  new_key_id?: string
  key_id?: string
}

export interface SigningProviderResult extends ProviderOperationResult {
  response?: SigningResponseDoc
}

export interface SigningAudit {
  status: string
  trust_class?: string
  entries?: UnknownRecord[]
  reason_codes?: string[]
  detail?: string
}

export interface SigningProvider {
  describe(): SigningProviderDoc
  sign(request: SigningRequestDoc, payload: unknown): SigningProviderResult
  rotateKey(input: { keyId: string; alg?: string }): ProviderOperationResult
  revokeKey(input: { keyId: string; reason?: string }): ProviderOperationResult
  audit(): SigningAudit
  activeKeyIds?(): string[]
}

/** Minimal injected provider surface accepted by the signing flow. */
export interface SigningProviderLike {
  describe(): unknown
  sign(request: unknown, payload: unknown): unknown | Promise<unknown>
}

// ---------------------------------------------------------------------------
// market-attestation/v1
// ---------------------------------------------------------------------------

export interface AttestationSubject {
  receipt_schema_version: string
  run_id: string
  plan_id: string
  record_digest: string
}

export interface AttestationEligibilityRef {
  schema_version: string
  decision_digest: string
}

export interface AttestationControlPlane {
  id: string
  version: string
  policy_ref: VersionRef
}

export interface AttestationIsolation {
  level: string
  attestation_digest: string
  verification_digest: string
}

export interface AttestationRuntime {
  cordis_version: string
  dsh_version: string
  anchor_digest: string
  contract_suite_digest: string
}

export interface AttestationSigning {
  provider_id: string
  key_id: string
  alg: string
  signature?: string
  signed_at: string
  provider_audit_ref: string
}

export interface AttestationArchiveRef {
  provider_id: string
  anchor_id: string
  sequence: number
  entry_digest: string
  archived_at: string
}

export interface MarketAttestation {
  schema_version: string
  attestation_id: string
  subject: AttestationSubject
  eligibility: AttestationEligibilityRef
  control_plane: AttestationControlPlane
  isolation: AttestationIsolation
  runtime: AttestationRuntime
  signing: AttestationSigning
  archive: AttestationArchiveRef
  limitations: string[]
}

export interface AttestationVerification {
  schema_version: string
  verification_id: string
  attestation_digest: string
  attestation_archive_entry_digest: string | null
  signature_verified: boolean
  archive_chain_verified: boolean
  checks: CheckEntry[]
  result: string
  verified_by: string
  verified_at: string
  reason_codes: string[]
  limitations: string[]
}

/** Injected `market-eligibility/v1` input (market gate owns its semantics). */
export interface MarketEligibility {
  schema_version: string
  decision?: string
  evidence_manifest_digest?: string
  reason_codes?: string[]
  [key: string]: unknown
}

// ---------------------------------------------------------------------------
// Archive provider / entry / anchor / chain verification
// ---------------------------------------------------------------------------

export interface ProviderSignature {
  alg: string
  key_id: string
  value: string
}

export interface EntryTimeSource {
  source: string
  trusted: boolean
  reference: string | null
}

export interface TrustAnchor {
  type: string
  key_id: string | null
  verification_ref: string | null
}

export interface TrustedTimeDeclaration {
  source: string
  verified: boolean
  reference: string | null
}

export interface MarketArchiveProviderDoc {
  schema_version: string
  provider_id: string
  provider_version: string
  provider_kind: string
  mode: string
  immutability: {
    append_only: boolean
    delete_forbidden: boolean
    retention_days: number
    legal_hold: boolean
  }
  trust_anchor: TrustAnchor
  trusted_time: TrustedTimeDeclaration
  sequence_head: number
  trust_class: string
  availability: string
  limitations: string[]
}

export interface ArchiveEntry {
  schema_version: string
  archive_id: string
  sequence: number
  previous_entry_digest: string | null
  receipt_digest: string
  isolation_attestation_digest: string | null
  policy_digest: string | null
  approval_digests: string[]
  attestation_digest: string | null
  eligibility_digest: string | null
  entry_digest: string
  archived_at: string
  time_source: EntryTimeSource
  provider_signature: ProviderSignature | null
  provider_audit_ref: string
}

export interface ArchiveEntryDraft {
  receipt_digest: string
  isolation_attestation_digest: string | null
  policy_digest: string | null
  approval_digests: string[]
  attestation_digest: string | null
  eligibility_digest: string | null
  expected?: ExpectedHead
}

export interface ArchiveAnchor {
  schema_version: string
  anchor_id: string
  provider_id: string
  archive_id: string
  sequence: number
  entry_digest: string
  previous_entry_digest: string | null
  receipt_digest: string
  archived_at: string
  trust_anchor: TrustAnchor
  trusted_time: TrustedTimeDeclaration
  provider_audit_ref: string
}

export interface ArchiveChainVerification {
  schema_version: string
  verification_id: string
  archive_id: string
  provider_id: string
  sequence_head: number
  head_entry_digest: string | null
  expected_head: ExpectedHead | null
  result: string
  checks: CheckEntry[]
  reason_codes: string[]
  verified_at: string
  limitations: string[]
}

export interface ArchiveHead {
  status: string
  sequence?: number
  entry_digest?: string | null
  archived_at?: string | null
  provider_audit_ref?: string | null
  time_source?: EntryTimeSource
  reason_codes?: string[]
  errors?: string[]
  detail?: string
}

export interface ArchiveAppendResult {
  status: string
  entry?: ArchiveEntry
  anchor?: ArchiveAnchor
  reason_codes?: string[]
  detail?: string
}

export interface ArchiveGetResult {
  status: string
  entry?: ArchiveEntry
  reason_codes?: string[]
  errors?: string[]
}

export interface ArchiveChainResult {
  status: string
  verification: ArchiveChainVerification
  entries: ArchiveEntry[]
}

export interface ArchiveProvider {
  describe(): MarketArchiveProviderDoc
  append(draft: ArchiveEntryDraft): Promise<ArchiveAppendResult> | ArchiveAppendResult
  get(sequence: number): ArchiveGetResult
  head(): ArchiveHead
  verifyChain(options?: UnknownRecord): Promise<ArchiveChainResult> | ArchiveChainResult
  audit(): UnknownRecord
  storageDir?: string | null
  verifyEntrySignature?(entry: unknown): boolean
}

/** Minimal injected archive provider surface accepted by the sequence. */
export interface ArchiveProviderLike {
  describe(): unknown
  append(draft: unknown): unknown | Promise<unknown>
  get(sequence: number): unknown | Promise<unknown>
  head(): unknown | Promise<unknown>
}

export interface TrustedTimeReading {
  status: string
  time?: string
  source?: string
  trusted?: boolean
  trust_class?: string
  reference?: string | null
  reason_codes?: string[]
  detail?: string
}

export interface TrustedTimeProvider {
  describe(): UnknownRecord
  now(): TrustedTimeReading
}
