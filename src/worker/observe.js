/**
 * Worker observation assembly — bounded, redacted, provenance-labelled output.
 *
 * Rules enforced here (architecture §5.1/§8.2/§11.1, implementation-design-worker §5):
 *   - secret-looking material is replaced *inside the worker* before any frame is
 *     written; the worker never relies on a later control-plane mask;
 *   - oversized values are summarized to a digest instead of silently truncated;
 *   - structures are depth/key/array bounded so a PUT or tool cannot exhaust the
 *     transport frame;
 *   - authority fields (`verdict`, `gate_decision`, `required`, `expected`,
 *     `not_applicable`, `invocation_status`, authoritative `started_at`, signing
 *     shapes) are never produced by the worker.
 *
 * This module is not a security boundary; it is a data-quality/provenance guard
 * inside the L1 worker (L1 itself only provides fault isolation).
 *
 * @module @deepseek-ai/dsh-plugin-testbed/worker/observe
 */
import { sha256Hex } from '../protocol/digest.js'

export const REDACTED = '[redacted]'
export const MAX_OBSERVATION_BYTES = 512 * 1024
export const MAX_TEXT_BYTES = 16 * 1024
export const MAX_ERROR_STACK_BYTES = 4 * 1024
export const MAX_VALUE_DEPTH = 12
export const MAX_VALUE_KEYS = 256
export const MAX_VALUE_ARRAY = 256
const TRUNCATED_SUFFIX = '…[truncated]'

/**
 * Keys that belong to the trusted control face. A worker record carrying any of
 * them is malformed by construction (even when the value "looks right").
 */
export const FORBIDDEN_AUTHORITY_KEYS = Object.freeze([
  'verification',
  'verdict',
  'gate_decision',
  'required',
  'expected',
  'not_applicable',
  'not_applicable_when',
  'invocation_status',
  'invocation_evidence_verified',
  'started_at',
  'signature',
  'signed',
  'key_id',
  'signing_key',
  'plan_id',
  'run_status',
])

const SECRET_PATTERNS = Object.freeze([
  // Provider-prefixed keys (OpenAI/DeepSeek style, GitHub, Slack, Google, Stripe).
  /\bsk-[A-Za-z0-9_-]{16,}\b/g,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bAIza[0-9A-Za-z_-]{30,}\b/g,
  /\bsk_live_[A-Za-z0-9]{16,}\b/g,
  /\bnpm_[A-Za-z0-9]{20,}\b/g,
  // JWTs and bearer credentials.
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{10,}/gi,
  // PEM private keys (multi-line).
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  // Credentials embedded in URLs.
  /\/\/[^/\s:@]+:[^/\s@]+@/g,
  // Generic `name=value` / `name: value` credential assignments.
  /(\b(?:api[_-]?key|apikey|secret|token|password|passwd|credential|authorization|auth[_-]?token|access[_-]?key|private[_-]?key)\b\s*[:=]\s*)(["']?)([^\s"',;]{3,})\2/gi,
])

/** @param {unknown} value @returns {boolean} */
export function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

/** @param {unknown} value */
export function jsonByteLength(value) {
  try {
    const text = JSON.stringify(value)
    return typeof text === 'string' ? Buffer.byteLength(text, 'utf8') : Infinity
  } catch {
    return Infinity
  }
}

/**
 * Replace secret-looking material in a string. Pure and idempotent enough for
 * repeated assembly; never throws.
 * @param {string} text
 * @returns {string}
 */
export function redactText(text) {
  if (typeof text !== 'string' || text.length === 0) return text
  let out = text
  for (const pattern of SECRET_PATTERNS) {
    pattern.lastIndex = 0
    out = out.replace(pattern, (match, prefix, quote) => {
      if (typeof prefix === 'string' && prefix.length > 0 && match.startsWith(prefix)) {
        return `${prefix}${quote ?? ''}${REDACTED}${quote ?? ''}`
      }
      return REDACTED
    })
    pattern.lastIndex = 0
  }
  return out
}

/**
 * Truncate a string to a UTF-8 byte budget without splitting a surrogate pair.
 * @param {string} text
 * @param {number} maxBytes
 * @returns {{text:string, truncated:boolean}}
 */
export function truncateUtf8(text, maxBytes) {
  if (typeof text !== 'string') return { text: '', truncated: false }
  if (Buffer.byteLength(text, 'utf8') <= maxBytes) return { text, truncated: false }
  let out = ''
  let used = 0
  for (const char of text) {
    const size = Buffer.byteLength(char, 'utf8')
    if (used + size > Math.max(0, maxBytes - Buffer.byteLength(TRUNCATED_SUFFIX, 'utf8'))) break
    out += char
    used += size
  }
  return { text: out + TRUNCATED_SUFFIX, truncated: true }
}

/**
 * Recursively redact and bound a JSON-like value.
 * @param {unknown} value
 * @param {{maxDepth?:number, maxKeys?:number, maxArray?:number,
 *   maxStringBytes?:number}} [options]
 * @returns {{value:unknown, redacted:boolean, truncated:boolean}}
 */
export function redactValue(value, options = {}) {
  const maxDepth = options.maxDepth ?? MAX_VALUE_DEPTH
  const maxKeys = options.maxKeys ?? MAX_VALUE_KEYS
  const maxArray = options.maxArray ?? MAX_VALUE_ARRAY
  const maxStringBytes = options.maxStringBytes ?? MAX_TEXT_BYTES
  const state = { redacted: false, truncated: false }
  const seen = new Set()

  const visit = (node, depth) => {
    if (node === null || typeof node === 'number' || typeof node === 'boolean') return node
    if (typeof node === 'string') {
      // Bound work on enormous strings before running the secret patterns, then
      // truncate to the real budget. Four times the budget leaves room for a
      // pattern that consumes surrounding context.
      const capped = truncateUtf8(node, maxStringBytes * 4)
      if (capped.truncated) state.truncated = true
      const redacted = redactText(capped.text)
      if (redacted !== capped.text) state.redacted = true
      const cut = truncateUtf8(redacted, maxStringBytes)
      if (cut.truncated) state.truncated = true
      return cut.text
    }
    if (typeof node === 'undefined') return null
    if (typeof node !== 'object') {
      state.truncated = true
      return '[unsupported]'
    }
    if (seen.has(node)) {
      state.truncated = true
      return '[circular]'
    }
    if (depth >= maxDepth) {
      state.truncated = true
      return '[max-depth]'
    }
    seen.add(node)
    let result
    if (Array.isArray(node)) {
      const sliced = node.slice(0, maxArray)
      if (node.length > maxArray) state.truncated = true
      result = sliced.map((item) => visit(item, depth + 1))
      if (node.length > maxArray) result.push(`[truncated:${node.length - maxArray}]`)
    } else {
      // Plain objects keep downstream strict deep-equality and JSON behaviour;
      // dangerous prototype keys are filtered above.
      result = {}
      const entries = Object.entries(node)
        .filter(([key]) => !['__proto__', 'constructor', 'prototype'].includes(key))
        .slice(0, maxKeys)
      if (Object.keys(node).length > maxKeys) state.truncated = true
      for (const [key, item] of entries) result[key] = visit(item, depth + 1)
      if (Object.keys(node).length > maxKeys) result[`[truncated:${Object.keys(node).length - maxKeys}]`] = true
    }
    seen.delete(node)
    return result
  }

  return { value: visit(value, 0), redacted: state.redacted, truncated: state.truncated }
}

/**
 * Assemble one observation value inside the worker: redact → bound → summarize.
 * The returned limitations are appended to the observation so the control face
 * can see that content was redacted/truncated instead of assuming completeness.
 *
 * @param {unknown} rawValue
 * @param {{maxBytes?:number, maxDepth?:number}} [options]
 * @returns {{value:unknown, limitations:string[], redacted:boolean, truncated:boolean, size_bytes:number}}
 */
export function boundObservationValue(rawValue, options = {}) {
  const maxBytes = options.maxBytes ?? MAX_OBSERVATION_BYTES
  const redacted = redactValue(rawValue, {
    maxDepth: options.maxDepth,
    maxStringBytes: options.maxStringBytes ?? maxBytes,
  })
  const limitations = []
  if (redacted.redacted) limitations.push('value-redacted')
  let value = redacted.value
  let size = jsonByteLength(value)
  if (!Number.isFinite(size) || size > maxBytes) {
    const digest = createDigestForValue(value)
    value = { digest, size_bytes: Number.isFinite(size) ? size : null, truncated: true }
    limitations.push('value-summarized')
    size = jsonByteLength(value)
  } else if (redacted.truncated) {
    limitations.push('value-truncated')
  }
  return { value, limitations, redacted: redacted.redacted, truncated: redacted.truncated, size_bytes: size }
}

function createDigestForValue(value) {
  try {
    return 'sha256:' + sha256Hex(JSON.stringify(value) ?? '')
  } catch {
    return null
  }
}

/**
 * Sanitize a caught error for worker output: redacted message/stack, bounded.
 * Ambient values (paths, env names) are not treated as secrets here, but any
 * secret-looking substring is removed before the text reaches stdout.
 *
 * @param {unknown} error
 * @param {{phase?:string|null}} [options]
 * @returns {{phase:string|null, name:string, message:string, stack:string, code:string|null}}
 */
export function sanitizeError(error, options = {}) {
  const name = typeof error?.name === 'string' && error.name.length > 0
    ? truncateUtf8(redactText(error.name), 128).text
    : 'Error'
  const rawMessage = error instanceof Error ? error.message : String(error ?? 'unknown error')
  const message = truncateUtf8(redactText(truncateUtf8(rawMessage, MAX_TEXT_BYTES * 4).text), MAX_TEXT_BYTES).text
  const rawStack = typeof error?.stack === 'string' ? error.stack : ''
  const stack = truncateUtf8(redactText(truncateUtf8(rawStack, MAX_ERROR_STACK_BYTES * 4).text), MAX_ERROR_STACK_BYTES).text
  const code = typeof error?.code === 'string' && error.code.length > 0
    ? truncateUtf8(redactText(error.code), 128).text
    : null
  return { phase: options.phase ?? null, name, message, stack, code }
}

/**
 * Find forbidden authority keys in a worker record/snapshot.
 * @param {unknown} value
 * @param {{deep?:boolean, ignore?:string[]}} [options]
 * @returns {string[]} dotted paths; empty means clean
 */
export function findForbiddenAuthorityKeys(value, options = {}) {
  const deep = options.deep ?? true
  const ignore = new Set(options.ignore ?? [])
  const found = []
  const walk = (node, path, depth) => {
    if (!node || typeof node !== 'object') return
    if (depth > 32) return
    if (Array.isArray(node)) {
      node.forEach((item, index) => walk(item, `${path}[${index}]`, depth + 1))
      return
    }
    for (const [key, item] of Object.entries(node)) {
      const childPath = path ? `${path}.${key}` : key
      if (!ignore.has(key) && FORBIDDEN_AUTHORITY_KEYS.includes(key)) found.push(childPath)
      if (deep) walk(item, childPath, depth + 1)
    }
  }
  walk(value, '', 0)
  return found
}

/**
 * Fail-closed guard for worker-produced records. Throws when an authority field
 * would leave the worker boundary.
 * @param {unknown} value
 * @param {{deep?:boolean, label?:string, ignore?:string[]}} [options]
 */
export function assertNoAuthorityFields(value, options = {}) {
  const found = findForbiddenAuthorityKeys(value, options)
  if (found.length > 0) {
    const label = options.label ?? 'worker record'
    throw new TypeError(`${label} must not carry control-face authority fields: ${found.join(', ')}`)
  }
}
