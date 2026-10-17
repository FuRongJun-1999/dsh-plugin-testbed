/**
 * `test-tool-manifest/v1` static validation + tool pinning (CONTRACT-m5 §2,
 * architecture §8.4.1).
 *
 * A manifest is an input *declaration*, not a permission proof (§8.4.1); the
 * launcher records the actually-enforceable subset (incl. `unenforced`)
 * separately and lives in adapters/worker — not here. This module only does
 * static, fail-closed checks: no shell strings, no floating-tag digests, no
 * filesystem path escape (`..`/drive-letter/`file://`/absolute), bounded JSON
 * Schema, and the §8.4.1 manifest field table.
 *
 * Admission stages follow architecture §8.4.1: `draft` (hard error) →
 * `validated` (static checks pass) → `pinned` (bound to a specific digest).
 *
 * @module @deepseek-ai/dsh-plugin-testbed/protocol/tool-manifest
 */
import { TEST_TOOL_MANIFEST_VERSION } from './enums.js'
import { validateSchemaMeta } from './jsonschema.js'

const MANIFEST_ROLES = Object.freeze(['probe', 'fixture', 'transform'])
const DETERMINISM_VALUES = Object.freeze(['deterministic', 'seeded', 'environment-bound', 'best-effort'])
const PERMISSION_KEYS = Object.freeze(['filesystem', 'network', 'subprocess', 'devices', 'secrets'])

// Known top-level manifest fields (§8.4.1). Anything outside this set is a
// warning, not a hard error (CONTRACT-m5 §2).
const KNOWN_TOP_LEVEL = new Set([
  'schema_version', 'tool_id', 'tool_version', 'artifact_digest', 'role', 'tags',
  'runner', 'input_schema', 'observation_schema', 'requires', 'permissions',
  'limits', 'determinism', 'retry', 'evidence', 'compatibility',
])

// Static ceiling for manifest requests. Runner-enforced bounds follow its
// MAX_TIMEOUT_MS / MAX_OUTPUT_BYTES; fields without L1 enforcement use the
// existing adapter grant examples. A declaration ceiling is not an OS limit.
export const MAX_MANIFEST_LIMITS = Object.freeze({
  timeout_ms: 5 * 60 * 1000,
  cpu_ms: 15_000,
  memory_mb: 256,
  temp_bytes: 8 * 1024 * 1024,
  output_bytes: 1024 * 1024,
  attachment_bytes: 1024 * 1024,
  processes: 1,
  concurrency: 1,
})
export const MAX_RETRY_ATTEMPTS = 3
const LIMIT_FIELDS = Object.keys(MAX_MANIFEST_LIMITS)

// Shell metacharacters + whitespace, banned inside runner.adapter/entrypoint.
const SHELL_META = /[\s;&|><$`'"\\]/

/** @param {unknown} v */
function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

/** @param {unknown} v */
function nonEmptyString(v) {
  return typeof v === 'string' && v.length > 0
}

/**
 * Assert a content digest is a fixed `sha256:<64 hex>`. Floating tags
 * (`latest`, `main`, semver ranges) are rejected — §8.4.1「不可用浮动 tag」.
 * @param {unknown} dg
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function assertArtifactDigest(dg) {
  const errors = []
  if (typeof dg !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(dg)) {
    errors.push(`artifact-digest-invalid:${String(dg)}`)
  }
  return { ok: errors.length === 0, errors }
}

/** @param {unknown} runner @param {string[]} errors */
function validateRunner(runner, errors) {
  if (!isPlainObject(runner)) { errors.push('runner-invalid'); return }
  for (const forbidden of ['command', 'args', 'shell']) {
    if (forbidden in runner) errors.push(`runner-${forbidden}-forbidden`)
  }
  for (const field of ['adapter', 'entrypoint']) {
    const v = runner[field]
    if (!nonEmptyString(v)) errors.push(`runner-${field}-invalid`)
    else if (SHELL_META.test(v)) errors.push(`runner-${field}-shell-metachar`)
  }
}

/**
 * A filesystem entry is an escape if it is not a capability token
 * (`workspace:read`) and is a drive reference / absolute path / UNC / `file://`
 * / contains a `..` segment.
 * @param {unknown} entry
 * @returns {boolean} true when the entry must be rejected
 */
function isFilesystemEntryEscape(entry) {
  if (typeof entry !== 'string' || entry.length === 0) return true
  // capability token: <namespace>:<cap> (namespace ≥ 2 chars so single-letter
  // drive forms like `C:` never match this branch)
  if (/^[a-zA-Z][a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+$/.test(entry)) return false
  if (/^[a-zA-Z]:/.test(entry)) return true // Windows drive (absolute or drive-relative)
  if (/^(?:\/|\\\\|\/\/|file:)/i.test(entry)) return true // POSIX abs / UNC / file://
  return entry.split(/[\\/]+/).includes('..')
}

/** @param {unknown} permissions @param {string[]} errors */
function validatePermissions(permissions, errors) {
  if (!isPlainObject(permissions)) { errors.push('permissions-invalid'); return }
  for (const key of Object.keys(permissions)) {
    if (!PERMISSION_KEYS.includes(key)) { errors.push(`permissions-unknown-key:${key}`); continue }
    const val = permissions[key]
    if (!Array.isArray(val)) { errors.push(`permissions-${key}-not-array`); continue }
    if (!val.every((x) => typeof x === 'string')) { errors.push(`permissions-${key}-not-strings`); continue }
    if (key === 'filesystem') {
      for (const entry of val) {
        if (isFilesystemEntryEscape(entry)) errors.push(`permissions-filesystem-escape:${entry}`)
      }
    }
  }
}

/** @param {unknown} limits @param {string[]} errors */
function validateLimits(limits, errors) {
  if (!isPlainObject(limits)) { errors.push('limits-invalid'); return }
  for (const field of LIMIT_FIELDS) {
    const v = limits[field]
    if (!Number.isSafeInteger(v) || v < 1) {
      errors.push(`limits-${field}-invalid`)
    } else if (v > MAX_MANIFEST_LIMITS[field]) {
      errors.push(`limits-${field}-exceeds-limit`)
    }
  }
}

/** @param {unknown} retry @param {string[]} errors */
function validateRetry(retry, errors) {
  if (!isPlainObject(retry)) { errors.push('retry-invalid'); return }
  if (typeof retry.safe !== 'boolean') errors.push('retry-safe-invalid')
  if (!Number.isSafeInteger(retry.max_attempts) || retry.max_attempts < 1) {
    errors.push('retry-max-attempts-invalid')
  } else if (retry.max_attempts > MAX_RETRY_ATTEMPTS) {
    errors.push('retry-max-attempts-exceeds-limit')
  }
}

/**
 * Validate a `test-tool-manifest/v1` manifest against §8.4.1 (CONTRACT-m5 §2).
 * Unknown top-level fields are warnings, not hard errors.
 * @param {unknown} manifest
 * @returns {{ ok: boolean, errors: string[], warnings: string[], admission_stage: 'draft'|'validated' }}
 */
export function validateToolManifest(manifest) {
  if (!isPlainObject(manifest)) {
    return { ok: false, errors: ['manifest-not-object'], warnings: [], admission_stage: 'draft' }
  }
  const errors = []
  const warnings = []

  for (const key of Object.keys(manifest)) {
    if (!KNOWN_TOP_LEVEL.has(key)) warnings.push(`unknown-top-level-field:${key}`)
  }

  if (manifest.schema_version !== TEST_TOOL_MANIFEST_VERSION) errors.push('schema-version-invalid')
  if (!nonEmptyString(manifest.tool_id)) errors.push('tool-id-invalid')
  if (!nonEmptyString(manifest.tool_version)) errors.push('tool-version-invalid')

  const dg = assertArtifactDigest(manifest.artifact_digest)
  errors.push(...dg.errors)

  if (!MANIFEST_ROLES.includes(manifest.role)) errors.push('role-invalid')

  validateRunner(manifest.runner, errors)

  for (const field of ['input_schema', 'observation_schema']) {
    const meta = validateSchemaMeta(manifest[field])
    for (const e of meta.errors) errors.push(`${field}-${e}`)
  }

  if (!Array.isArray(manifest.requires) || !manifest.requires.every((x) => typeof x === 'string')) {
    errors.push('requires-invalid')
  }

  validatePermissions(manifest.permissions, errors)
  validateLimits(manifest.limits, errors)

  if (!DETERMINISM_VALUES.includes(manifest.determinism)) errors.push('determinism-invalid')

  validateRetry(manifest.retry, errors)

  return { ok: errors.length === 0, errors, warnings, admission_stage: errors.length === 0 ? 'validated' : 'draft' }
}

/**
 * Pin a validated manifest to a specific artifact digest (architecture §8.4.1
 * `pinned`:「已解析到具体版本、摘要、adapter 和环境能力快照」).
 *
 * The resolved `artifactDigest` must be a fixed `sha256:<hex>` and must equal
 * the manifest-declared `artifact_digest`; otherwise pinning fails (draft).
 * `env` is an optional environment/capability snapshot recorded as-is
 * (its validation is `adapters-owner`'s responsibility, not the manifest's).
 *
 * @param {unknown} manifest
 * @param {unknown} artifactDigest
 * @param {unknown} env
 * @returns {{ ok: boolean, errors: string[], admission_stage: 'draft'|'pinned',
 *   tool_ref?: { tool_id: string, version: string, artifact_digest: string },
 *   adapter?: string, entrypoint?: string, env?: unknown }}
 */
export function pinTool(manifest, artifactDigest, env) {
  const check = validateToolManifest(manifest)
  if (!check.ok) return { ok: false, errors: check.errors, admission_stage: 'draft' }

  const dg = assertArtifactDigest(artifactDigest)
  if (!dg.ok) return { ok: false, errors: dg.errors, admission_stage: 'draft' }

  if (artifactDigest !== manifest.artifact_digest) {
    return { ok: false, errors: ['pin-digest-mismatch'], admission_stage: 'draft' }
  }

  return {
    ok: true,
    errors: [],
    admission_stage: 'pinned',
    tool_ref: { tool_id: manifest.tool_id, version: manifest.tool_version, artifact_digest: artifactDigest },
    adapter: manifest.runner.adapter,
    entrypoint: manifest.runner.entrypoint,
    env: env ?? null,
  }
}