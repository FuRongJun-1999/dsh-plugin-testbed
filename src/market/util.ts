/**
 * Small, strict helpers shared by the market gate.
 *
 * Everything here is deliberately fail-closed: a malformed value produces
 * `null`/`false` and the caller records a stable reason code instead of
 * throwing or silently defaulting.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/market/util
 */

import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { isAbsolute, resolve } from 'node:path'
import { canonicalJson, sha256Hex } from '../protocol/digest.js'
import type { UnknownRecord } from '../protocol/types.js'

/** @param {unknown} value @returns {value is UnknownRecord} */
export function isPlainRecord(value: unknown): value is UnknownRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

/** @param {unknown} value @returns {value is string} */
export function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 4096 && !value.includes('\0')
}

/** @param {unknown} value @returns {value is unknown[]} */
export function isArray(value: unknown): value is unknown[] {
  return Array.isArray(value)
}

/** @param {unknown} value @returns {UnknownRecord | null} */
export function asRecord(value: unknown): UnknownRecord | null {
  return isPlainRecord(value) ? value : null
}

/** @param {unknown} value @returns {string | null} */
export function asString(value: unknown): string | null {
  return isNonEmptyString(value) ? value : null
}

/** @param {unknown} value @returns {number | null} */
export function asFiniteNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

/** @param {unknown} value @returns {boolean} */
export function isDigest(value: unknown): value is string {
  return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value)
}

/** @param {unknown} value @returns {boolean} */
export function isRfc3339(value: unknown): value is string {
  if (typeof value !== 'string') return false
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) return false
  return Number.isFinite(Date.parse(value))
}

/** @param {unknown} value @returns {number | null} */
export function parseTimeMs(value: unknown): number | null {
  if (!isRfc3339(value)) return null
  const ms = Date.parse(value)
  return Number.isFinite(ms) ? ms : null
}

/** @param {Date | string | number | undefined} value @returns {number} */
export function resolveNowMs(value: Date | string | number | undefined): number {
  if (value instanceof Date && Number.isFinite(value.getTime())) return value.getTime()
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value === 'string') {
    const parsed = Date.parse(value)
    if (Number.isFinite(parsed)) return parsed
  }
  return Date.now()
}

/** Canonical digest (`sha256(canonicalJson(value))`) used by every sidecar. */
export function canonicalDigest(value: unknown): string {
  return `sha256:${sha256Hex(canonicalJson(value))}`
}

/** Raw SHA-256 of file bytes (archive entry files, provider docs, …). */
export function sha256Bytes(bytes: Uint8Array): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`
}

/**
 * Resolve an option that may be an inline JSON object or a path to a JSON file.
 * A path is resolved against `baseDir` (defaults to `process.cwd()`); reading
 * never follows a URL scheme and never touches `app.asar`.
 */
export async function loadJsonOption(
  value: unknown,
  baseDir: string = process.cwd(),
): Promise<{ ok: true; value: unknown; path: string | null } | { ok: false; reason: string; detail: string; path: string | null }> {
  if (value === undefined || value === null) return { ok: false, reason: 'input-missing', detail: 'no input supplied', path: null }
  if (typeof value === 'object') return { ok: true, value, path: null }
  if (typeof value !== 'string' || value.length === 0) {
    return { ok: false, reason: 'input-invalid', detail: 'input must be a JSON object or path', path: null }
  }
  const path = isAbsolute(value) ? value : resolve(baseDir, value)
  let text: string
  try {
    text = await readFile(path, 'utf8')
  } catch {
    return { ok: false, reason: 'input-unreadable', detail: `cannot read ${path}`, path }
  }
  try {
    return { ok: true, value: JSON.parse(text), path }
  } catch {
    return { ok: false, reason: 'input-invalid-json', detail: `invalid JSON in ${path}`, path }
  }
}

/** Deterministic id helper for sidecars (`decision:`, `attestation:`, …). */
export function contentId(prefix: string, digest: string): string {
  return `${prefix}:${digest.slice('sha256:'.length, 'sha256:'.length + 32)}`
}
