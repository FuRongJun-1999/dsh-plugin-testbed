/**
 * Canonical byte/digest helpers for market evidence documents.
 *
 * SIG-01 fixes the encoding: RFC 8785 canonical JSON, SHA-256 digests rendered
 * as `sha256:<lowercase hex>`, signatures as unpadded base64url. The same
 * canonicalisation is used by providers, verifiers and tests so a signature
 * cannot depend on JSON key order.
 *
 * The signing-input rule (§6.5) is implemented here and only here:
 * `market-attestation/v1` is canonicalised with `signing.signature` removed.
 * No other field is dropped, so the archive anchor (entry N) and the provider
 * audit ref are covered by the signature.
 *
 * This module never holds a private key or credential.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/evidence/canonical
 */
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { canonicalJson, sha256Hex } from '../protocol/digest.js';
import { ARCHIVE_ANCHOR_V1_SCHEMA, ARCHIVE_ENTRY_V1_SCHEMA, MARKET_ATTESTATION_V1_SCHEMA, MARKET_ATTESTATION_VERIFICATION_V1_SCHEMA, SIGNING_PROVIDER_V1_SCHEMA, SIGNING_REQUEST_V1_SCHEMA, SIGNING_RESPONSE_V1_SCHEMA, validateMarketDocument, } from '../protocol/market-schemas.js';
function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
/** RFC 8785 canonical JSON bytes (UTF-8). */
export function canonicalBytes(value) {
    return Buffer.from(canonicalJson(value), 'utf8');
}
/** `sha256:<hex>` over canonical JSON for any JSON value. */
export function canonicalDigest(value) {
    return 'sha256:' + sha256Hex(canonicalJson(value));
}
/** `sha256:<hex>` over raw bytes. */
export function digestBytes(bytes) {
    return 'sha256:' + createHash('sha256').update(bytes).digest('hex');
}
/** Unpadded base64url (SIG-01). */
export function base64urlEncode(bytes) {
    return Buffer.from(bytes).toString('base64url');
}
/**
 * Strict unpadded base64url decode. Returns `null` for padded, empty or
 * non-canonical input so callers can fail closed instead of accepting a
 * re-encoded alias.
 */
export function base64urlDecode(text) {
    if (typeof text !== 'string' || text.length === 0)
        return null;
    if (!/^[A-Za-z0-9_-]+$/.test(text))
        return null;
    const bytes = Buffer.from(text, 'base64url');
    if (bytes.length === 0)
        return null;
    return base64urlEncode(bytes) === text ? bytes : null;
}
// ---------------------------------------------------------------------------
// Schema validation wrappers (all fail closed)
// ---------------------------------------------------------------------------
export function validateSigningProvider(value) {
    return validateMarketDocument(value, SIGNING_PROVIDER_V1_SCHEMA);
}
export function validateSigningRequest(value) {
    return validateMarketDocument(value, SIGNING_REQUEST_V1_SCHEMA);
}
export function validateSigningResponse(value) {
    return validateMarketDocument(value, SIGNING_RESPONSE_V1_SCHEMA);
}
export function validateMarketAttestation(value) {
    return validateMarketDocument(value, MARKET_ATTESTATION_V1_SCHEMA);
}
export function validateAttestationVerification(value) {
    return validateMarketDocument(value, MARKET_ATTESTATION_VERIFICATION_V1_SCHEMA);
}
export function validateArchiveEntry(value) {
    return validateMarketDocument(value, ARCHIVE_ENTRY_V1_SCHEMA);
}
export function validateArchiveAnchor(value) {
    return validateMarketDocument(value, ARCHIVE_ANCHOR_V1_SCHEMA);
}
export function pushSchemaErrors(errors, add) {
    for (const error of add)
        errors.push(`schema:${error}`);
}
// ---------------------------------------------------------------------------
// Signing input / digests
// ---------------------------------------------------------------------------
/**
 * Build the exact bytes signed for a `market-attestation/v1`.
 *
 * §6.5: the signing input is the RFC 8785 canonicalisation of the document with
 * only `signing.signature` excluded. The input may be an unsigned draft (no
 * `signing.signature` key) or a signed document (signature stripped here).
 */
export function attestationSigningBytes(attestation) {
    if (!isPlainObject(attestation))
        return Buffer.alloc(0);
    const body = structuredClone(attestation);
    if (isPlainObject(body.signing))
        delete body.signing.signature;
    // Reserved future field: never part of the signing input (§6.5).
    delete body.attestation_archive;
    return canonicalBytes(body);
}
/** Digest of the exact bytes a signer must sign. */
export function attestationSigningDigest(attestation) {
    return digestBytes(attestationSigningBytes(attestation));
}
/**
 * Digest of the complete signed attestation (including `signing.signature`);
 * this is the value archived as `archive-entry/v1.attestation_digest`.
 */
export function marketAttestationDigest(attestation) {
    return canonicalDigest(attestation);
}
/** Digest of a verification record (saved as evidence). */
export function attestationVerificationDigest(verification) {
    return canonicalDigest(verification);
}
/**
 * Fields excluded from `archive-entry/v1.entry_digest`.
 *
 * `provider_audit_ref` and `provider_signature` are assigned by the archive
 * provider; `entry_digest` is the value being computed. Everything else —
 * including `archived_at` and `time_source` — is covered by the chain digest.
 */
export const ENTRY_DIGEST_EXCLUDED_FIELDS = Object.freeze([
    'entry_digest',
    'provider_signature',
    'provider_audit_ref',
]);
/**
 * Canonical entry body used for the chain digest.
 */
export function archiveEntryDigestBody(entry) {
    if (!isPlainObject(entry))
        return {};
    const body = structuredClone(entry);
    for (const field of ENTRY_DIGEST_EXCLUDED_FIELDS)
        delete body[field];
    return body;
}
/** Compute the append-only chain digest of an archive entry. */
export function archiveEntryDigest(entry) {
    return canonicalDigest(archiveEntryDigestBody(entry));
}
