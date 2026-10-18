/**
 * RFC 8785 (JCS) canonicalization + SHA-256 receipts.
 * Only `integrity.record_digest` is excluded; `integrity.signed` is retained.
 * No external trust anchor: a local digest detects mismatch only, and cannot
 * prove the body was not rewritten and re-hashed in lockstep (architecture §11.2.1).
 *
 * Migration phase `protocol/types`: the digest boundary is typed (`unknown` in,
 * `string`/`DigestVerification` out). The canonicalization algorithm and the
 * fixed vector are byte-for-byte the JavaScript baseline; the emitted
 * `digest.js` build artifact is what the runtime loads.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/protocol/digest
 */
import { createHash } from 'node:crypto'
import type { DigestVerification, UnknownRecord } from './types.js'

/**
 * Canonicalize a JSON value: object keys sorted by UTF-16 code unit, no
 * insignificant whitespace, ECMAScript number/string escaping rules, UTF-8 output.
 * Matches RFC 8785 for the legal JSON values a receipt may contain.
 *
 * `JSON.stringify` types as `string | undefined` only because it also covers
 * non-JSON inputs (undefined/function/symbol); those never enter the protocol,
 * and the cast preserves the baseline behavior exactly for legal JSON values.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value) as string
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJson).join(',') + ']'
  }
  const record = value as UnknownRecord
  const entries = Object.entries(record)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  return '{' + entries.map(([k, v]) => JSON.stringify(k) + ':' + canonicalJson(v)).join(',') + '}'
}

/** Hash a UTF-8 string with SHA-256 and return the lowercase hex digest. */
export function sha256Hex(utf8: string): string {
  return createHash('sha256').update(utf8, 'utf8').digest('hex')
}

/**
 * Compute a receipt `record_digest` = `sha256:<hex>` over the canonicalized
 * receipt body with `integrity.record_digest` excluded (and `signed` kept).
 */
export function recordDigest(receipt: unknown): string {
  const body = structuredClone(receipt)
  if (body && typeof body === 'object') {
    const integrity = (body as UnknownRecord).integrity
    if (integrity && typeof integrity === 'object') {
      delete (integrity as UnknownRecord).record_digest
    }
  }
  return 'sha256:' + sha256Hex(canonicalJson(body))
}

/**
 * Verify that a persisted receipt's `record_digest` matches a recomputation.
 */
export function verifyRecordDigest(receipt: unknown): DigestVerification {
  const record = receipt !== null && typeof receipt === 'object' ? (receipt as UnknownRecord) : undefined
  const integrity = record?.integrity
  const actual = integrity && typeof integrity === 'object'
    ? (integrity as UnknownRecord).record_digest
    : integrity
  const expected = recordDigest(receipt)
  return { ok: typeof actual === 'string' && actual === expected, expected, actual }
}

/**
 * Fixed vector from architecture §11.2.1 (field exclusion only; NOT a legal
 * full receipt). Expected digest: sha256:c3b6ee…cc2fb.
 */
export const FIXED_VECTOR_INPUT = Object.freeze({
  receipt_schema_version: 'receipt/v1',
  integrity: { record_digest: 'ignored', signed: false },
})
export const FIXED_VECTOR_DIGEST = 'sha256:c3b6ee97857bfdb5a83d46fc51aec09e9fb82e6da82a2e21d6101329d88cc2fb'
