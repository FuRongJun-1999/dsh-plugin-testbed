/**
 * Signing protocol: request construction, response binding, key lifecycle
 * checks, cryptographic verification and the sign-one-attestation flow.
 *
 * SIG-02 separation is structural: this module never sees a private key. It
 * talks to an injected `signing-provider/v1` object (`sign`, `describe`,
 * `rotateKey`, `revokeKey`, `audit`). The development provider in
 * `signing-provider.js` is the only implementation in this repository and is
 * permanently `development-only` (`E1`); the KMS/HSM/OS-keystore providers are
 * declared interfaces that return `blocked` because this environment has no
 * key custody (§4.6, §5.4.3).
 *
 * Blind signing is forbidden: the provider must receive the canonical payload
 * and re-derive its digest. A digest-only request is rejected.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/evidence/signing
 */
import type { KeyObject } from 'node:crypto'
import { createPublicKey, verify as cryptoVerify } from 'node:crypto'

import {
  EVIDENCE_REASON_CODES,
  MARKET_ATTESTATION_VERSION,
  PROVIDER_TRUST_CLASSES,
  SIGNING_ALGORITHMS,
  SIGNING_DOMAIN_MARKET_ATTESTATION,
  SIGNING_PAYLOAD_KINDS,
  SIGNING_REQUEST_VERSION,
  SIGNING_RESPONSE_VERSION,
  isSigningRequestVersion,
  isSigningResponseVersion,
} from '../protocol/market-schemas.js'
import {
  attestationSigningBytes,
  attestationSigningDigest,
  base64urlDecode,
  canonicalDigest,
  digestBytes,
  pushSchemaErrors,
  validateAttestationVerification,
  validateMarketAttestation,
  validateSigningProvider,
  validateSigningRequest,
  validateSigningResponse,
} from './canonical.js'
import type {
  CheckEntry,
  MarketAttestation,
  ReasonResult,
  SigningKeyDoc,
  SigningProviderDoc,
  SigningProviderLike,
  SigningRequestDoc,
  SigningRequester,
  SigningResponseDoc,
  UnknownRecord,
  ValidationResult,
} from './types.js'

/**
 * Failure carrying a stable market reason code. Used only for callers that
 * build malformed evidence locally (never for a remote provider verdict).
 */
export class EvidenceError extends Error {
  readonly reason_code: string
  readonly errors: string[]

  constructor(reasonCode: string, message: string, options: { errors?: string[] } = {}) {
    super(message)
    this.name = 'EvidenceError'
    this.reason_code = reasonCode
    this.errors = options.errors ?? []
  }
}

function isPlainObject(value: unknown): value is UnknownRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

/**
 * Payload digest for a signing request. `market-attestation/v1` uses the
 * documented signing input; other registered kinds use plain canonical JSON.
 */
export function signingPayloadDigest(payloadKind: string, payload: unknown): string {
  if (payloadKind === MARKET_ATTESTATION_VERSION) return attestationSigningDigest(payload)
  return canonicalDigest(payload)
}

/** Derive the stable `key_id` from an algorithm and SPKI DER public key. */
export function deriveKeyId(alg: string, publicKeyDer: Buffer): string {
  const hex = digestBytes(publicKeyDer).slice('sha256:'.length)
  return `key-${alg}-${hex.slice(0, 32)}`
}

/**
 * Public key view used in provider documents: base64url SPKI DER plus digest.
 */
export function encodePublicKey(publicKey: KeyObject): { public_key: string; public_key_digest: string } {
  const der = publicKey.export({ format: 'der', type: 'spki' })
  return {
    public_key: der.toString('base64url'),
    public_key_digest: digestBytes(der),
  }
}

export interface ImportedPublicKey {
  ok: boolean
  keyObject: KeyObject | null
  reason_codes: string[]
  errors: string[]
}

/**
 * Parse a pinned `public_key` (base64url SPKI DER) and assert it matches the
 * pinned `public_key_digest`.
 */
export function importPinnedPublicKey(key: unknown): ImportedPublicKey {
  const reasonCodes: string[] = []
  const errors: string[] = []
  if (!isPlainObject(key)) {
    return {
      ok: false,
      keyObject: null,
      reason_codes: [EVIDENCE_REASON_CODES.SIGNING_KEY_UNKNOWN],
      errors: ['key-not-object'],
    }
  }
  const der = base64urlDecode(key.public_key)
  if (der === null) {
    return {
      ok: false,
      keyObject: null,
      reason_codes: [EVIDENCE_REASON_CODES.SIGNING_KEY_UNKNOWN],
      errors: ['public-key-not-canonical-base64url'],
    }
  }
  if (digestBytes(der) !== key.public_key_digest) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_KEY_UNKNOWN)
    errors.push('public-key-digest-mismatch')
  }
  let keyObject: KeyObject | null = null
  try {
    keyObject = createPublicKey({ key: der, format: 'der', type: 'spki' })
  } catch {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_KEY_UNKNOWN)
    errors.push('public-key-not-importable')
  }
  return {
    ok: reasonCodes.length === 0 && keyObject !== null,
    keyObject,
    reason_codes: reasonCodes,
    errors,
  }
}

/**
 * Check key state/validity at a point in time (SIG-04).
 *
 * `rotated` keys are accepted only when `allowRotatedKeys` is true and the
 * signature predates the rotation. Revoked keys are never accepted.
 */
export function checkKeyValidity(
  key: unknown,
  options: { at: string; allowRotatedKeys?: boolean },
): ReasonResult {
  const reasonCodes: string[] = []
  const errors: string[] = []
  if (!isPlainObject(key)) {
    return {
      ok: false,
      reason_codes: [EVIDENCE_REASON_CODES.SIGNING_KEY_UNKNOWN],
      errors: ['key-not-object'],
    }
  }
  const at = options.at
  if (key.state === 'revoked') {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_KEY_REVOKED)
    errors.push('key-revoked')
  } else if (key.state === 'rotated') {
    const allowed = options.allowRotatedKeys === true
    const signedBeforeRotation =
      typeof key.rotated_at === 'string' && typeof at === 'string' && at <= key.rotated_at
    if (!allowed || !signedBeforeRotation) {
      reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_KEY_INACTIVE)
      errors.push('key-rotated')
    }
  } else if (key.state !== 'active') {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_KEY_INACTIVE)
    errors.push(`key-state-${String(key.state)}`)
  }
  if (typeof key.created_at === 'string' && typeof at === 'string' && at < key.created_at) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_KEY_INACTIVE)
    errors.push('key-not-yet-valid')
  }
  if (key.expires_at !== null && typeof key.expires_at === 'string' && typeof at === 'string') {
    if (at >= key.expires_at) {
      reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_KEY_EXPIRED)
      errors.push('key-expired')
    }
  }
  return { ok: reasonCodes.length === 0, reason_codes: reasonCodes, errors }
}

/**
 * Market trust issues for a signing provider document (SIG-02/SIG-03/SIG-10).
 *
 * A provider that is unavailable, unverified or development-only always yields
 * issues, so it can never support a market-eligible claim. The audit also
 * reports `development-only-not-market-evidence` explicitly.
 */
export function signingProviderTrustIssues(providerDoc: unknown): ReasonResult {
  const reasonCodes: string[] = []
  const errors: string[] = []
  const shaped = validateSigningProvider(providerDoc)
  if (!shaped.ok) {
    return {
      ok: false,
      reason_codes: [EVIDENCE_REASON_CODES.SIGNING_PROVIDER_UNTRUSTED, EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE],
      errors: shaped.errors.map((error) => `schema:${error}`),
    }
  }
  const doc = providerDoc as SigningProviderDoc
  if (doc.availability !== 'available') {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_PROVIDER_MISSING)
    errors.push('provider-unavailable')
  }
  if (!(PROVIDER_TRUST_CLASSES as readonly string[]).includes(doc.trust_class)) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_PROVIDER_UNTRUSTED)
    errors.push('provider-trust-class-unknown')
  }
  if (doc.trust_class === 'development-only') {
    reasonCodes.push(
      EVIDENCE_REASON_CODES.DEVELOPMENT_ONLY_NOT_MARKET,
      EVIDENCE_REASON_CODES.SIGNING_PROVIDER_UNTRUSTED,
      EVIDENCE_REASON_CODES.SIGNING_KEY_CUSTODY_UNVERIFIED,
    )
    errors.push('provider-development-only')
  } else if (doc.trust_class !== 'market-independent') {
    reasonCodes.push(
      EVIDENCE_REASON_CODES.SIGNING_PROVIDER_UNTRUSTED,
      EVIDENCE_REASON_CODES.SIGNING_KEY_CUSTODY_UNVERIFIED,
    )
    errors.push(`provider-trust-class-${doc.trust_class}`)
  }
  const guarantees = doc.guarantees
  if (guarantees.private_key_export !== 'never') {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_KEY_CUSTODY_UNVERIFIED)
    errors.push('private-key-export-allowed')
  }
  if (guarantees.signing_op !== 'remote') {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_KEY_CUSTODY_UNVERIFIED)
    errors.push('signing-op-not-remote')
  }
  if (guarantees.audit !== 'append-only') {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_PROVIDER_UNTRUSTED)
    errors.push('provider-audit-not-append-only')
  }
  if (guarantees.blind_sign !== 'forbidden') {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_PROVIDER_UNTRUSTED)
    errors.push('blind-sign-not-forbidden')
  }
  if (doc.attestation === null) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_PROVIDER_UNTRUSTED)
    errors.push('provider-attestation-missing')
  }
  if (doc.keys.length === 0) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_KEY_UNKNOWN)
    errors.push('provider-has-no-keys')
  }
  return { ok: reasonCodes.length === 0, reason_codes: unique(reasonCodes), errors }
}

export interface SigningRequestEvaluation extends ReasonResult {
  key: SigningKeyDoc | null
}

/**
 * Evaluate a `signing-request/v1` against a provider document. This is the
 * executable guard used by providers before they touch key material; it is
 * intentionally shared with tests so the provider cannot relax it silently.
 */
export function evaluateSigningRequest(input: {
  request: unknown
  payload: unknown
  providerDoc: unknown
  now: string
  authorizedRequesters?: SigningRequester[]
  allowedDomains?: string[]
  maxRequestAgeMs?: number
}): SigningRequestEvaluation {
  const reasonCodes: string[] = []
  const errors: string[] = []
  const { payload, now } = input

  const shaped = validateSigningRequest(input.request)
  if (!shaped.ok) {
    return {
      ok: false,
      reason_codes: [EVIDENCE_REASON_CODES.SIGNING_REQUEST_INVALID],
      errors: shaped.errors.map((error) => `schema:${error}`),
      key: null,
    }
  }
  const request = input.request as SigningRequestDoc
  if (!isSigningRequestVersion(request.schema_version)) {
    return {
      ok: false,
      reason_codes: [EVIDENCE_REASON_CODES.SIGNING_REQUEST_INVALID],
      errors: [`unknown-version:${String(request.schema_version)}`],
      key: null,
    }
  }

  if (!isPlainObject(payload)) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_BLIND_SIGN_FORBIDDEN)
    errors.push('payload-required-for-signing')
  } else {
    if (payload.schema_version !== request.payload_kind) {
      reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_PAYLOAD_KIND_MISMATCH)
      errors.push('payload-kind-mismatch')
    }
    const computed = signingPayloadDigest(request.payload_kind, payload)
    if (computed !== request.payload_digest) {
      reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_PAYLOAD_DIGEST_MISMATCH)
      errors.push('payload-digest-mismatch')
    }
  }

  const providerDoc = input.providerDoc as SigningProviderDoc
  if (!(SIGNING_ALGORITHMS as readonly string[]).includes(request.alg)) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_ALGORITHM_NOT_ALLOWED)
    errors.push('request-alg-not-allowed')
  }
  if (!providerDoc.algorithms.includes(request.alg)) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_ALGORITHM_NOT_ALLOWED)
    errors.push('provider-alg-not-supported')
  }
  const domains = input.allowedDomains ?? [SIGNING_DOMAIN_MARKET_ATTESTATION]
  if (!domains.includes(request.domain_separation)) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_DOMAIN_SEPARATION_MISMATCH)
    errors.push('domain-separation-not-allowed')
  }

  const key = providerDoc.keys.find((candidate) => candidate.key_id === request.key_id) ?? null
  if (key === null) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_KEY_UNKNOWN)
    errors.push('key-unknown')
  } else {
    if (key.alg !== request.alg) {
      reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_ALGORITHM_NOT_ALLOWED)
      errors.push('key-alg-mismatch')
    }
    const validity = checkKeyValidity(key, { at: now })
    reasonCodes.push(...validity.reason_codes)
    errors.push(...validity.errors)
  }

  const authorized = input.authorizedRequesters ?? []
  const requester = request.requester
  if (!authorized.some((candidate) => candidate.control_plane_id === requester.control_plane_id &&
    candidate.authorization_ref === requester.authorization_ref)) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_REQUEST_UNAUTHORIZED)
    errors.push('requester-not-authorized')
  }

  const requestedAtMs = Date.parse(request.requested_at)
  const nowMs = Date.parse(now)
  const maxAge = input.maxRequestAgeMs ?? 5 * 60 * 1000
  if (!Number.isFinite(requestedAtMs) || !Number.isFinite(nowMs) || Math.abs(nowMs - requestedAtMs) > maxAge) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_REQUEST_STALE)
    errors.push('request-timestamp-outside-window')
  }

  return {
    ok: reasonCodes.length === 0,
    reason_codes: unique(reasonCodes),
    errors,
    key,
  }
}

/**
 * Build a `signing-request/v1`. Throws on malformed local input; the request
 * is still schema-validated by the provider before signing.
 */
export function buildSigningRequest(input: {
  requestId: string
  keyId: string
  alg: string
  payload: unknown
  payloadKind?: string
  auditRef: string
  requestedAt: string
  requester: SigningRequester
  domainSeparation?: string
}): SigningRequestDoc {
  const payloadKind = input.payloadKind ?? MARKET_ATTESTATION_VERSION
  if (!(SIGNING_PAYLOAD_KINDS as readonly string[]).includes(payloadKind)) {
    throw new EvidenceError(
      EVIDENCE_REASON_CODES.SIGNING_PAYLOAD_KIND_MISMATCH,
      `unsupported payload kind: ${String(payloadKind)}`,
    )
  }
  const request: SigningRequestDoc = {
    schema_version: SIGNING_REQUEST_VERSION,
    request_id: input.requestId,
    key_id: input.keyId,
    alg: input.alg,
    domain_separation: input.domainSeparation ?? SIGNING_DOMAIN_MARKET_ATTESTATION,
    payload_digest: signingPayloadDigest(payloadKind, input.payload),
    payload_kind: payloadKind,
    audit_ref: input.auditRef,
    requested_at: input.requestedAt,
    requester: {
      control_plane_id: input.requester.control_plane_id,
      authorization_ref: input.requester.authorization_ref,
    },
  }
  const shaped = validateSigningRequest(request)
  if (!shaped.ok) {
    throw new EvidenceError(
      EVIDENCE_REASON_CODES.SIGNING_REQUEST_INVALID,
      'signing request is not valid',
      { errors: shaped.errors },
    )
  }
  return request
}

/**
 * Verify that a `signing-response/v1` is bound to its request. This does NOT
 * verify the signature; `verifyAttestationSignature` does that.
 */
export function verifySigningResponseBinding(request: unknown, response: unknown): ReasonResult {
  const reasonCodes: string[] = []
  const errors: string[] = []
  const shapedRequest = validateSigningRequest(request)
  const shapedResponse = validateSigningResponse(response)
  if (!shapedRequest.ok || !shapedResponse.ok) {
    return {
      ok: false,
      reason_codes: [EVIDENCE_REASON_CODES.SIGNING_RESPONSE_BINDING_MISMATCH],
      errors: [
        ...shapedRequest.errors.map((error) => `request:schema:${error}`),
        ...shapedResponse.errors.map((error) => `response:schema:${error}`),
      ],
    }
  }
  const req = request as SigningRequestDoc
  const res = response as SigningResponseDoc
  if (!isSigningResponseVersion(res.schema_version)) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_RESPONSE_BINDING_MISMATCH)
    errors.push(`unknown-version:${String(res.schema_version)}`)
  }
  for (const field of ['request_id', 'key_id', 'alg'] as const) {
    if (req[field] !== res[field]) {
      reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_RESPONSE_BINDING_MISMATCH)
      errors.push(`binding-mismatch:${field}`)
    }
  }
  if (req.payload_digest !== res.signed_payload_digest) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_PAYLOAD_DIGEST_MISMATCH)
    errors.push('signed-payload-digest-mismatch')
  }
  if (req.requested_at !== res.signed_at) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_RESPONSE_BINDING_MISMATCH)
    errors.push('signed-at-not-request-time')
  }
  if (req.audit_ref !== res.provider_audit_ref) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_RESPONSE_BINDING_MISMATCH)
    errors.push('provider-audit-ref-mismatch')
  }
  return { ok: reasonCodes.length === 0, reason_codes: unique(reasonCodes), errors }
}

export interface SignatureVerification extends ReasonResult {
  checks: CheckEntry[]
}

/**
 * Cryptographically verify a signed `market-attestation/v1` against one pinned
 * public key. Callers must separately decide whether that key/provider is
 * trusted for market (see `signingProviderTrustIssues` and
 * `verifyMarketAttestation`).
 */
export function verifyAttestationSignature(input: {
  attestation: unknown
  key: unknown
  algorithmAllowlist?: readonly string[]
  allowRotatedKeys?: boolean
}): SignatureVerification {
  const reasonCodes: string[] = []
  const errors: string[] = []
  const checks: CheckEntry[] = []
  const attestation = input.attestation
  const allowlist = input.algorithmAllowlist ?? SIGNING_ALGORITHMS
  const signing = isPlainObject(attestation) && isPlainObject(attestation.signing)
    ? attestation.signing
    : null

  if (signing === null) {
    return failSignature(reasonCodes, errors, checks, 'attestation-signing-missing')
  }
  const shaped = validateMarketAttestation(attestation)
  if (!shaped.ok) {
    return failSignature(reasonCodes, errors, checks, ...shaped.errors.map((error) => `schema:${error}`))
  }
  const doc = attestation as MarketAttestation
  if (doc.schema_version !== MARKET_ATTESTATION_VERSION) {
    return failSignature(reasonCodes, errors, checks, `unknown-version:${String(doc.schema_version)}`)
  }
  const signed = doc.signing

  if (!allowlist.includes(signed.alg)) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_ALGORITHM_NOT_ALLOWED)
    errors.push('algorithm-not-allowlisted')
  }
  if (!isPlainObject(input.key) || input.key.key_id !== signed.key_id) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_KEY_UNKNOWN)
    errors.push('pinned-key-does-not-match-signing-key')
  }
  if (isPlainObject(input.key) && input.key.alg !== signed.alg) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNING_ALGORITHM_NOT_ALLOWED)
    errors.push('pinned-key-alg-mismatch')
  }
  if (isPlainObject(input.key)) {
    const validity = checkKeyValidity(input.key, {
      at: signed.signed_at,
      allowRotatedKeys: input.allowRotatedKeys === true,
    })
    reasonCodes.push(...validity.reason_codes)
    errors.push(...validity.errors)
  }

  const imported = importPinnedPublicKey(input.key)
  if (!imported.ok) {
    reasonCodes.push(...imported.reason_codes)
    errors.push(...imported.errors)
  }

  const signature = base64urlDecode(signed.signature)
  if (signature === null) {
    reasonCodes.push(EVIDENCE_REASON_CODES.SIGNATURE_VERIFICATION_FAILED)
    errors.push('signature-not-canonical-base64url')
  }

  if (reasonCodes.length === 0 && imported.keyObject !== null && signature !== null) {
    const bytes = attestationSigningBytes(doc)
    let valid = false
    try {
      if (signed.alg === 'ed25519') {
        valid = imported.keyObject.asymmetricKeyType === 'ed25519' &&
          cryptoVerify(null, bytes, imported.keyObject, signature)
      } else if (signed.alg === 'ecdsa-p256-sha256') {
        valid = imported.keyObject.asymmetricKeyType === 'ec' &&
          imported.keyObject.asymmetricKeyDetails?.namedCurve === 'prime256v1' &&
          cryptoVerify('sha256', bytes, { key: imported.keyObject, dsaEncoding: 'ieee-p1363' }, signature)
      }
    } catch {
      valid = false
    }
    if (!valid) {
      reasonCodes.push(EVIDENCE_REASON_CODES.SIGNATURE_VERIFICATION_FAILED)
      errors.push('signature-invalid')
    }
  }

  checks.push(check('signature', reasonCodes.length === 0, EVIDENCE_REASON_CODES.SIGNATURE_VERIFICATION_FAILED))
  return {
    ok: reasonCodes.length === 0,
    reason_codes: unique(reasonCodes),
    errors,
    checks,
  }
}

export interface SigningFlowResult {
  status: string
  reason_codes: string[]
  detail?: string
  attestation?: MarketAttestation
  request?: SigningRequestDoc
  response?: SigningResponseDoc
}

/**
 * Sign a fully-prepared but unsigned `market-attestation/v1`.
 *
 * Preconditions enforced here (SIG-05/SIG-08):
 *  - the attestation references an existing archive anchor (entry N);
 *  - `signing.signed_at` and `signing.provider_audit_ref` are already fixed so
 *    they are covered by the signature;
 *  - the signature field is absent (signing a signed object would be blind
 *    double-signing).
 */
export async function signMarketAttestation(input: {
  attestation: unknown
  signingProvider: SigningProviderLike
  requester: SigningRequester
  requestId: string
  domainSeparation?: string
}): Promise<SigningFlowResult> {
  if (!isPlainObject(input.attestation)) {
    return reject([EVIDENCE_REASON_CODES.SIGNING_REQUEST_INVALID], 'attestation-not-object')
  }
  const attestation: UnknownRecord = structuredClone(input.attestation)
  if (!isPlainObject(attestation.signing)) {
    return reject([EVIDENCE_REASON_CODES.SIGNING_REQUEST_INVALID], 'attestation-signing-missing')
  }
  const signing = attestation.signing
  if (signing.signature !== undefined) {
    return reject([EVIDENCE_REASON_CODES.SIGNING_BLIND_SIGN_FORBIDDEN], 'attestation-already-signed')
  }
  if (!isPlainObject(attestation.archive) || typeof attestation.archive.entry_digest !== 'string') {
    return reject([EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISSING], 'signing-requires-subject-anchor')
  }
  if (!isPlainObject(attestation.eligibility)) {
    return reject([EVIDENCE_REASON_CODES.MARKET_EVIDENCE_INCOMPLETE], 'signing-requires-eligibility')
  }
  if (typeof signing.signed_at !== 'string' || typeof signing.provider_audit_ref !== 'string') {
    return reject([EVIDENCE_REASON_CODES.SIGNING_REQUEST_INVALID], 'signing-time-and-audit-ref-required')
  }

  let providerDocValue: unknown
  try {
    providerDocValue = input.signingProvider.describe()
  } catch {
    providerDocValue = null
  }
  if (!isPlainObject(providerDocValue) || providerDocValue.availability !== 'available') {
    return {
      status: 'blocked',
      reason_codes: [EVIDENCE_REASON_CODES.SIGNING_PROVIDER_MISSING],
      detail: 'signing provider is unavailable',
    }
  }
  const providerDoc = providerDocValue as unknown as SigningProviderDoc
  const keyId = signing.key_id
  const key = Array.isArray(providerDoc.keys)
    ? providerDoc.keys.find((candidate) => candidate.key_id === keyId)
    : undefined
  if (key === undefined) {
    return reject([EVIDENCE_REASON_CODES.SIGNING_KEY_UNKNOWN], 'signing-key-unknown')
  }

  const request = buildSigningRequest({
    requestId: input.requestId,
    keyId: String(keyId),
    alg: String(signing.alg),
    payload: attestation,
    auditRef: String(signing.provider_audit_ref),
    requestedAt: String(signing.signed_at),
    requester: input.requester,
    domainSeparation: input.domainSeparation,
  })

  let result: unknown
  try {
    result = await input.signingProvider.sign(request, attestation)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    return reject([EVIDENCE_REASON_CODES.SIGNING_PROVIDER_UNTRUSTED], `provider-error:${message}`)
  }
  if (!isPlainObject(result) || result.status !== 'signed') {
    const codes = isPlainObject(result) && Array.isArray(result.reason_codes)
      ? result.reason_codes.filter((code): code is string => typeof code === 'string')
      : [EVIDENCE_REASON_CODES.SIGNING_PROVIDER_UNTRUSTED]
    return {
      status: isPlainObject(result) && result.status === 'blocked' ? 'blocked' : 'rejected',
      reason_codes: unique(codes),
      detail: isPlainObject(result) && typeof result.detail === 'string' ? result.detail : undefined,
    }
  }
  const response = result.response
  if (!isPlainObject(response)) {
    return reject([EVIDENCE_REASON_CODES.SIGNING_PROVIDER_UNTRUSTED], 'provider-returned-no-response')
  }

  const binding = verifySigningResponseBinding(request, response)
  if (!binding.ok) return reject(binding.reason_codes, binding.errors.join('; '))

  attestation.signing.signature = response.signature

  const shaped = validateMarketAttestation(attestation)
  if (!shaped.ok) {
    return reject(
      [EVIDENCE_REASON_CODES.MARKET_EVIDENCE_INCOMPLETE],
      shaped.errors.map((error) => `schema:${error}`).join('; '),
    )
  }
  const signedAttestation = attestation as unknown as MarketAttestation
  const signatureCheck = verifyAttestationSignature({ attestation: signedAttestation, key })
  if (!signatureCheck.ok) return reject(signatureCheck.reason_codes, signatureCheck.errors.join('; '))

  return {
    status: 'signed',
    reason_codes: [],
    attestation: signedAttestation,
    request,
    response: response as unknown as SigningResponseDoc,
  }
}

/**
 * Validate an independent verification record's self-consistency.
 */
export function validateVerificationRecord(verification: unknown): ValidationResult {
  const errors: string[] = []
  const shaped = validateAttestationVerification(verification)
  pushSchemaErrors(errors, shaped.errors)
  if (isPlainObject(verification)) {
    const checks = Array.isArray(verification.checks) ? verification.checks : []
    if (verification.result === 'valid' &&
      (verification.signature_verified !== true || verification.archive_chain_verified !== true)) {
      errors.push('valid-result-requires-signature-and-chain')
    }
    if (verification.result === 'valid' &&
      checks.some((entry) => !isPlainObject(entry) || entry.status !== 'pass')) {
      errors.push('valid-result-requires-all-checks-pass')
    }
    const codes = verification.reason_codes
    if (verification.result === 'valid' && Array.isArray(codes) && codes.length > 0) {
      errors.push('valid-result-with-reason-codes')
    }
    if (verification.result === 'invalid' && Array.isArray(codes) && codes.length === 0) {
      errors.push('invalid-result-requires-reason-codes')
    }
  }
  return { ok: errors.length === 0, errors }
}

// ---------------------------------------------------------------------------

function check(id: string, ok: boolean, reasonCode: string): CheckEntry {
  return {
    id,
    status: ok ? 'pass' : 'fail',
    reason_code: ok ? null : reasonCode,
    evidence_ref: null,
  }
}

function reject(reasonCodes: string[], detail: string): SigningFlowResult {
  return { status: 'rejected', reason_codes: unique(reasonCodes), detail }
}

function failSignature(
  reasonCodes: string[],
  errors: string[],
  checks: CheckEntry[],
  ...messages: string[]
): SignatureVerification {
  reasonCodes.push(EVIDENCE_REASON_CODES.SIGNATURE_VERIFICATION_FAILED)
  errors.push(...messages)
  checks.push(check('signature', false, EVIDENCE_REASON_CODES.SIGNATURE_VERIFICATION_FAILED))
  return { ok: false, reason_codes: unique(reasonCodes), errors, checks }
}

export function unique<T>(values: T[]): T[] {
  return [...new Set(values)]
}
