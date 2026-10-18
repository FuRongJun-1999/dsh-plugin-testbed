/**
 * Locked runtime anchor resolution (DSH/Cordis entry + observed provenance).
 *
 * The worker must never guess or hard-code a private checkout path. The locked
 * runtime is **injected or resolved** from the environment:
 *   1. an explicit anchor object / anchor-file injection (adapter → worker),
 *   2. `DSH_TESTBED_RUNTIME_ANCHOR` (path to a JSON descriptor, or inline JSON),
 *   3. `DSH_TESTBED_CORDIS_ENTRY` (+ optional version/commit/kind),
 *   4. an installed `@deepseek-ai/cordis` package resolved from this module.
 *
 * A descriptor is a *claim* until the entry really exists; the version is only
 * `verified` when it can be read back from the package next to the built entry.
 * A DSH commit cannot be observed from a built runtime, so it is always kept as
 * an explicitly unverified injection — never reported as a runtime observation.
 * When no usable runtime exists the result is `unavailable`; callers must record
 * `unknown`/`blocked`, never a fabricated `present` or `pass`.
 *
 * Two anchor schemas are recognised:
 *   - `testbed-runtime-anchor/v1` (local L1 profiles) via `resolveRuntimeAnchor`;
 *   - `testbed-runtime-anchor/v2` (market-grade, integrity-bound) via
 *     `verifyRuntimeAnchorV2` / `resolveRuntimeAnchorV2`. The v2 path additionally
 *     checks the lockfile digest, the installed package integrity, the exact
 *     entry-file digest, an exact package version, and rejects `app.asar` and
 *     `test-fixture` descriptors with stable reason codes. v1 semantics are kept
 *     byte-compatible for existing L1 callers; a v2 descriptor is *not* silently
 *     accepted by the v1 resolver and vice versa.
 *
 * No absolute host path is embedded in this module. Nothing here is a security
 * boundary; it anchors evidence provenance for the L1 worker.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/worker/runtime
 */
import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import { readFile, stat } from 'node:fs/promises'
import { dirname, isAbsolute, join, resolve, win32 } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { canonicalJson, sha256Hex } from '../protocol/digest.js'
import { captureRuntimeEnvironment } from './environment.js'
import { isPlainRecord, redactText } from './observe.js'

export const RUNTIME_ANCHOR_VERSION = 'testbed-runtime-anchor/v1'
export const RUNTIME_KINDS = Object.freeze(['locked-runtime', 'injected-runtime', 'test-fixture'])
export const MAX_ANCHOR_BYTES = 64 * 1024
export const MAX_RUNTIME_ENTRY_BYTES = 8 * 1024 * 1024

export const RUNTIME_REASONS = Object.freeze([
  'runtime-anchor-missing',
  'runtime-anchor-invalid',
  'runtime-anchor-read-failed',
  'runtime-entry-missing',
  'runtime-entry-invalid',
  'runtime-environment-mismatch',
  'runtime-version-mismatch',
])

const ANCHOR_FIELDS = Object.freeze([
  'schema_version',
  'cordis_entry',
  'cordis_version',
  'dsh_commit',
  'node_version',
  'platform',
  'arch',
  'runtime_kind',
  'notes',
])
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/
const COMMIT = /^[0-9a-f]{40}$/

/** @param {string} path */
async function pathIsFile(path) {
  try {
    const info = await stat(path)
    return info.isFile()
  } catch {
    return false
  }
}

/** @param {unknown} entry @param {string|null} baseDir */
function normalizeEntry(entry, baseDir) {
  if (typeof entry !== 'string' || entry.length === 0 || entry.includes('\0')) {
    return { ok: false, reason: 'runtime-anchor-invalid' }
  }
  let entryPath
  if (entry.startsWith('file:')) {
    try {
      entryPath = fileURLToPath(entry)
    } catch {
      return { ok: false, reason: 'runtime-anchor-invalid' }
    }
  } else if (isAbsolute(entry) || win32.isAbsolute(entry)) {
    entryPath = entry
  } else if (entry.startsWith('/')) {
    entryPath = entry
  } else if (baseDir) {
    entryPath = resolve(baseDir, entry)
  } else {
    return { ok: false, reason: 'runtime-anchor-invalid' }
  }
  return { ok: true, entry_path: resolve(entryPath), entry_url: pathToFileURL(resolve(entryPath)).href }
}

/** Read the installed package name/version next to a Cordis entry (bounded walk). */
async function observePackageVersion(entryPath) {
  let dir = dirname(entryPath)
  for (let depth = 0; depth < 4; depth += 1) {
    const candidate = join(dir, 'package.json')
    try {
      const info = await stat(candidate)
      if (info.isFile() && info.size <= MAX_ANCHOR_BYTES) {
        const raw = JSON.parse(await readFile(candidate, 'utf8'))
        if (isPlainRecord(raw) && typeof raw.version === 'string' && SEMVER.test(raw.version) &&
            (typeof raw.name !== 'string' || raw.name.includes('cordis'))) {
          return { name: typeof raw.name === 'string' ? raw.name : null, version: raw.version, package_path: candidate }
        }
      }
    } catch {
      // Keep walking: a missing/invalid package.json is not an anchor failure.
    }
    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return null
}

/** Validate one anchor descriptor; unknown fields are rejected (fail-closed). */
function validateDescriptor(raw, { baseDir, defaultKind }) {
  if (!isPlainRecord(raw)) return { ok: false, errors: ['runtime-anchor-invalid'] }
  const unknown = Object.keys(raw).filter((key) => !ANCHOR_FIELDS.includes(key))
  if (unknown.length > 0) return { ok: false, errors: [`runtime-anchor-unknown-field:${unknown[0]}`] }
  if (raw.schema_version !== RUNTIME_ANCHOR_VERSION) {
    return { ok: false, errors: ['runtime-anchor-version-unknown'] }
  }
  const entry = normalizeEntry(raw.cordis_entry, baseDir)
  if (!entry.ok) return { ok: false, errors: [entry.reason] }
  if (raw.cordis_version != null && (typeof raw.cordis_version !== 'string' || !SEMVER.test(raw.cordis_version))) {
    return { ok: false, errors: ['runtime-anchor-version-invalid'] }
  }
  if (raw.dsh_commit != null && (typeof raw.dsh_commit !== 'string' || !COMMIT.test(raw.dsh_commit))) {
    return { ok: false, errors: ['runtime-anchor-commit-invalid'] }
  }
  for (const key of ['node_version', 'platform', 'arch', 'notes']) {
    if (raw[key] != null && (typeof raw[key] !== 'string' || raw[key].length === 0 || raw[key].length > 256)) {
      return { ok: false, errors: [`runtime-anchor-field-invalid:${key}`] }
    }
  }
  const kind = raw.runtime_kind ?? defaultKind
  if (!RUNTIME_KINDS.includes(kind)) return { ok: false, errors: ['runtime-anchor-kind-invalid'] }
  return {
    ok: true,
    descriptor: {
      schema_version: RUNTIME_ANCHOR_VERSION,
      cordis_entry: entry.entry_url,
      entry_path: entry.entry_path,
      cordis_version: raw.cordis_version ?? null,
      dsh_commit: raw.dsh_commit ?? null,
      node_version: raw.node_version ?? null,
      platform: raw.platform ?? null,
      arch: raw.arch ?? null,
      runtime_kind: kind,
      notes: raw.notes == null ? null : redactText(String(raw.notes)).slice(0, 256),
    },
  }
}

async function loadAnchorDescriptor(source, { baseDir, defaultKind }) {
  try {
    const info = await stat(source)
    if (!info.isFile()) return { ok: false, errors: ['runtime-anchor-read-failed'] }
    if (info.size > MAX_ANCHOR_BYTES) return { ok: false, errors: ['runtime-anchor-read-failed'] }
    const text = await readFile(source, 'utf8')
    const raw = JSON.parse(text)
    return validateDescriptor(raw, { baseDir: dirname(source), defaultKind })
  } catch {
    return { ok: false, errors: ['runtime-anchor-read-failed'] }
  }
}

async function parseAnchorValue(value, { baseDir, defaultKind }) {
  if (typeof value !== 'string' || value.length === 0) return { ok: false, errors: ['runtime-anchor-invalid'] }
  const trimmed = value.trim()
  if (trimmed.startsWith('{')) {
    try {
      return validateDescriptor(JSON.parse(trimmed), { baseDir, defaultKind })
    } catch {
      return { ok: false, errors: ['runtime-anchor-read-failed'] }
    }
  }
  return loadAnchorDescriptor(trimmed, { baseDir, defaultKind })
}

/** Resolve an installed Cordis package from this module (no hard-coded paths). */
function resolveInstalledCordis() {
  const attempts = ['@deepseek-ai/cordis', '@deepseek-ai/cordis/lib/index.js']
  for (const specifier of attempts) {
    try {
      // ESM resolution is preferred; the require fallback covers CJS-only packages.
      const url = import.meta.resolve(specifier)
      if (typeof url === 'string' && url.startsWith('file:')) return { entry_url: url }
    } catch {
      // fall through
    }
    try {
      const require = createRequire(import.meta.url)
      const resolvedPath = require.resolve(specifier)
      return { entry_url: pathToFileURL(resolvedPath).href }
    } catch {
      // try the next specifier
    }
  }
  return null
}

function environmentFingerprint(fields) {
  return 'sha256:' + sha256Hex(canonicalJson(fields))
}

function unavailable(reason, { source = 'none', descriptor = null, limitations = [] } = {}) {
  const provenance = {
    cordis_version: null,
    dsh_commit: null,
    cordis_version_observed: null,
    cordis_version_verified: false,
    dsh_commit_verified: false,
    cordis_entry: descriptor?.cordis_entry ?? null,
    source,
    runtime_kind: descriptor?.runtime_kind ?? null,
    node_version: process.version,
    os_platform: process.platform,
    os_arch: process.arch,
    environment_fingerprint: environmentFingerprint({
      anchor_status: 'unavailable',
      reason,
      node_version: process.version,
      os_platform: process.platform,
      os_arch: process.arch,
    }),
  }
  return {
    status: 'unavailable',
    reason,
    anchor: descriptor,
    provenance,
    limitations: [...new Set([...limitations, `runtime-unavailable:${reason}`])],
  }
}

/**
 * Resolve the locked runtime anchor and observe its real provenance.
 *
 * @param {{injection?:object|string|null, env?:Record<string,string|undefined>,
 *   cwd?:string, baseDir?:string}} [options]
 * @returns {Promise<{status:'available'|'unavailable', reason:string|null,
 *   anchor:object|null, provenance:object, limitations:string[]}>}
 */
export async function resolveRuntimeAnchor(options = {}) {
  const env = options.env ?? process.env
  const baseDir = options.baseDir ?? options.cwd ?? process.cwd()
  const captured = captureRuntimeEnvironment(env)

  /** @type {{descriptor:object, source:string}|null} */
  let selected = null
  let failure = null

  // 1. Explicit injection (object descriptor or anchor-file path/JSON).
  if (options.injection != null) {
    if (typeof options.injection === 'string') {
      const loaded = await parseAnchorValue(options.injection, { baseDir, defaultKind: 'injected-runtime' })
      if (loaded.ok) selected = { descriptor: loaded.descriptor, source: 'injection-file' }
      else failure = loaded.errors[0]
    } else if (isPlainRecord(options.injection)) {
      const candidate = options.injection.cordis_entry !== undefined
        ? options.injection
        : (options.injection.runtime_anchor ?? options.injection.anchor_path)
      if (candidate !== undefined) {
        if (typeof candidate === 'object') {
          const loaded = validateDescriptor({ schema_version: RUNTIME_ANCHOR_VERSION, ...candidate }, {
            baseDir,
            defaultKind: 'injected-runtime',
          })
          if (loaded.ok) selected = { descriptor: loaded.descriptor, source: 'injection' }
          else failure = loaded.errors[0]
        } else {
          const loaded = await parseAnchorValue(candidate, { baseDir, defaultKind: 'injected-runtime' })
          if (loaded.ok) selected = { descriptor: loaded.descriptor, source: 'injection-file' }
          else failure = loaded.errors[0]
        }
      } else {
        failure = 'runtime-anchor-invalid'
      }
    } else {
      failure = 'runtime-anchor-invalid'
    }
  }

  // 2. Environment anchor descriptor (the locked runner may inject this).
  if (!selected && captured.runtime_anchor) {
    const loaded = await parseAnchorValue(captured.runtime_anchor, {
      baseDir,
      defaultKind: captured.runtime_kind ?? 'locked-runtime',
    })
    if (loaded.ok) selected = { descriptor: loaded.descriptor, source: 'env-anchor' }
    else failure = loaded.errors[0]
  }

  // 3. Environment entry + optional version/commit.
  if (!selected && captured.cordis_entry) {
    const loaded = validateDescriptor({
      schema_version: RUNTIME_ANCHOR_VERSION,
      cordis_entry: captured.cordis_entry,
      cordis_version: captured.cordis_version ?? null,
      dsh_commit: captured.dsh_commit ?? null,
      runtime_kind: captured.runtime_kind ?? 'locked-runtime',
    }, { baseDir, defaultKind: 'locked-runtime' })
    if (loaded.ok) selected = { descriptor: loaded.descriptor, source: 'env-entry' }
    else failure = loaded.errors[0]
  }

  // 4. Installed package resolution.
  if (!selected && options.resolveInstalled !== false) {
    const installed = resolveInstalledCordis()
    if (installed) {
      const loaded = validateDescriptor({
        schema_version: RUNTIME_ANCHOR_VERSION,
        cordis_entry: installed.entry_url,
        runtime_kind: 'locked-runtime',
      }, { baseDir, defaultKind: 'locked-runtime' })
      if (loaded.ok) selected = { descriptor: loaded.descriptor, source: 'resolved-package' }
      else failure = loaded.errors[0]
    }
  }

  if (!selected) return unavailable(failure ?? 'runtime-anchor-missing')

  const { descriptor, source } = selected

  // Environment pins are fail-closed: a mismatched locked environment is not the
  // runtime the caller claims, so probing must report unknown rather than use it.
  if (descriptor.node_version !== null && descriptor.node_version !== process.version) {
    return unavailable('runtime-environment-mismatch', { source, descriptor })
  }
  if (descriptor.platform !== null && descriptor.platform !== process.platform) {
    return unavailable('runtime-environment-mismatch', { source, descriptor })
  }
  if (descriptor.arch !== null && descriptor.arch !== process.arch) {
    return unavailable('runtime-environment-mismatch', { source, descriptor })
  }

  const entryInfo = await pathIsFile(descriptor.entry_path)
  if (!entryInfo) return unavailable('runtime-entry-missing', { source, descriptor })

  const observed = await observePackageVersion(descriptor.entry_path)
  if (observed?.version && descriptor.cordis_version && observed.version !== descriptor.cordis_version) {
    return unavailable('runtime-version-mismatch', {
      source,
      descriptor,
      limitations: [`runtime-version-declared:${descriptor.cordis_version}`, `runtime-version-observed:${observed.version}`],
    })
  }

  const cordisVersion = observed?.version ?? descriptor.cordis_version ?? null
  const versionVerified = observed?.version != null &&
    (descriptor.cordis_version == null || observed.version === descriptor.cordis_version)
  const dshCommit = descriptor.dsh_commit
  const limitations = []
  if (cordisVersion === null) limitations.push('cordis-version-unknown')
  else if (!versionVerified) limitations.push('cordis-version-unverified')
  if (dshCommit !== null) limitations.push('dsh-commit-injected-unverified')
  if (descriptor.runtime_kind !== 'locked-runtime') limitations.push('non-locked-runtime')

  const provenance = {
    cordis_version: cordisVersion,
    dsh_commit: dshCommit,
    cordis_version_observed: observed?.version ?? null,
    cordis_version_verified: versionVerified,
    dsh_commit_verified: false,
    cordis_entry: descriptor.cordis_entry,
    source,
    runtime_kind: descriptor.runtime_kind,
    node_version: process.version,
    os_platform: process.platform,
    os_arch: process.arch,
    environment_fingerprint: environmentFingerprint({
      anchor_status: 'available',
      node_version: process.version,
      os_platform: process.platform,
      os_arch: process.arch,
      cordis_version: cordisVersion,
      cordis_version_verified: versionVerified,
      dsh_commit: dshCommit,
      runtime_kind: descriptor.runtime_kind,
    }),
  }
  return {
    status: 'available',
    reason: null,
    anchor: descriptor,
    provenance,
    limitations,
  }
}

/**
 * Project a resolved runtime anchor onto the closed set of receipt/v1
 * provenance fields (architecture §11.2.1; protocol schema
 * `PROVENANCE.additionalProperties=false`). Values that cannot be observed stay
 * explicitly null — never invented.
 *
 * @param {Awaited<ReturnType<typeof resolveRuntimeAnchor>>} resolved
 * @param {{workerRef?:string, isolation?:string}} [options]
 * @returns {{dsh_commit:string|null, cordis_version:string|null, node_version:string,
 *   os_platform:string, os_arch:string, environment_fingerprint:string,
 *   worker_ref:string, isolation:string, redaction_status:string}}
 */
export function runtimeProvenanceForReceipt(resolved, options = {}) {
  return {
    dsh_commit: resolved?.provenance?.dsh_commit ?? null,
    cordis_version: resolved?.provenance?.cordis_version ?? null,
    node_version: resolved?.provenance?.node_version ?? process.version,
    os_platform: resolved?.provenance?.os_platform ?? process.platform,
    os_arch: resolved?.provenance?.os_arch ?? process.arch,
    environment_fingerprint: resolved?.provenance?.environment_fingerprint ?? null,
    worker_ref: options.workerRef ?? 'worker/l1-subprocess@0.1.0',
    isolation: options.isolation ?? 'L1-subprocess',
    redaction_status: 'worker-redaction/v1',
  }
}

/**
 * Immutable anchor descriptor for callers that inject an already-known runtime
 * (adapter launcher, tests). Being a function keeps the schema version in one place.
 * @param {{cordis_entry:string, cordis_version?:string|null, dsh_commit?:string|null,
 *   runtime_kind?:string, node_version?:string|null, platform?:string|null,
 *   arch?:string|null}} fields
 */
export function makeRuntimeAnchor(fields) {
  return { schema_version: RUNTIME_ANCHOR_VERSION, ...fields }
}

/* -------------------------------------------------------------------------- *
 * testbed-runtime-anchor/v2 — market-grade, integrity-bound runtime anchor.
 *
 * v1 above is the local L1 descriptor. v2 is the document required for a
 * market-grade claim (NEXT-PHASE-REQUIREMENTS.md §6.10): it binds the exact
 * package name/version/integrity, the real entry file digest, the pnpm
 * lockfile digest, the DSH version, the Node/OS environment and an API-catalog
 * reference. Verification is fail-closed: every mismatch yields an explicit
 * `runtime-*` reason and an `unavailable` status; `test-fixture` and
 * `app.asar` descriptors can never verify as `locked-runtime`.
 * -------------------------------------------------------------------------- */

export const RUNTIME_ANCHOR_V2_VERSION = 'testbed-runtime-anchor/v2'
export const MAX_RUNTIME_LOCKFILE_BYTES = 16 * 1024 * 1024
export const MAX_V2_EVIDENCE_REFS = 32

export const RUNTIME_V2_REASONS = Object.freeze([
  'runtime-anchor-missing',
  'runtime-anchor-invalid',
  'runtime-anchor-read-failed',
  'runtime-anchor-version-unknown',
  'runtime-anchor-app-asar-rejected',
  'runtime-anchor-fixture-rejected',
  'runtime-package-unlockable',
  'runtime-integrity-mismatch',
  'runtime-version-mismatch',
  'runtime-environment-mismatch',
  'runtime-entry-missing',
  'runtime-entry-invalid',
  'runtime-entry-digest-mismatch',
  'runtime-lockfile-mismatch',
])

const ANCHOR_V2_FIELDS = Object.freeze([
  'schema_version',
  'package_name',
  'package_version',
  'integrity',
  'entry',
  'entry_digest',
  'lockfile',
  'dsh_version',
  'node_version',
  'platform',
  'arch',
  'runtime_kind',
  'catalog_ref',
  'evidence_refs',
  'notes',
])
const EXACT_VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/
const INTEGRITY_TOKEN = /^sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}$/
const DIGEST = /^sha256:[0-9a-f]{64}$/
const APP_ASAR_SEGMENT = /(?:^|[\\/])app\.asar(?:[\\/]|$)/i

/** @param {unknown} value @returns {value is string} */
function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 2048 && !value.includes('\0')
}

/** @param {unknown} value @returns {boolean} */
function isExactVersion(value) {
  return typeof value === 'string' && EXACT_VERSION.test(value)
}

/** @param {unknown} value @returns {boolean} */
function isIntegrity(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 1024) return false
  return value.split(/\s+/).every((token) => INTEGRITY_TOKEN.test(token))
}

/** @param {unknown} value @returns {boolean} */
function isDigest(value) {
  return typeof value === 'string' && DIGEST.test(value)
}

/** @param {unknown} value @returns {boolean} */
function isRuntimeKindV2(value) {
  return value === 'locked-runtime' || value === 'test-fixture'
}

/** Normalized filesystem form of an entry (URL-decoded, forward slashes). */
function entryPathForm(entry) {
  let decoded = entry
  try {
    decoded = decodeURIComponent(entry)
  } catch {
    // Keep the raw form; the explicit parser below still rejects it.
  }
  return decoded.replace(/\\/g, '/')
}

/** Explicit `app.asar` rejection — an archive is never a real runtime entry. */
function isAppAsarEntry(entry) {
  return APP_ASAR_SEGMENT.test(entryPathForm(entry))
}

/** Read a file that must exist and fit a byte budget; never follows app.asar. */
async function readBoundedFileBytes(path, { maxBytes, missingReason, invalidReason }) {
  let info
  try {
    info = await stat(path)
  } catch {
    return { ok: false, reason: missingReason }
  }
  if (!info.isFile()) return { ok: false, reason: missingReason }
  if (info.size > maxBytes) return { ok: false, reason: invalidReason }
  try {
    return { ok: true, bytes: await readFile(path) }
  } catch {
    return { ok: false, reason: invalidReason }
  }
}

/** @param {Buffer|Uint8Array} bytes */
function sha256Bytes(bytes) {
  return 'sha256:' + createHash('sha256').update(bytes).digest('hex')
}

/** Digest of a v2 anchor document (canonical JSON, no self-digest field). */
export function runtimeAnchorV2Digest(anchor) {
  return 'sha256:' + sha256Hex(canonicalJson(anchor))
}

function v2Unavailable(reason, { detail = null, anchor = null } = {}) {
  return {
    status: 'unavailable',
    reason,
    detail,
    anchor,
    verification: null,
    limitations: [`runtime-unavailable:${reason}`],
  }
}

function invalidLockfileShape(value) {
  return !isPlainRecord(value) || !isNonEmptyString(value.path) || !isDigest(value.digest) ||
    Object.keys(value).some((key) => key !== 'path' && key !== 'digest')
}

function invalidCatalogShape(value) {
  return !isPlainRecord(value) || !isNonEmptyString(value.id) || !isExactVersion(value.version) ||
    !isDigest(value.digest) || Object.keys(value).some((key) => !['id', 'version', 'digest'].includes(key))
}

/**
 * Verify a `testbed-runtime-anchor/v2` document against the real filesystem.
 *
 * All checks are fail-closed and side-effect free. The function never imports
 * the entry; it only proves the anchor matches the installed artifacts and the
 * current environment. Import + behavior proof is `cordis-contract-suite/v1`.
 *
 * @param {unknown} anchor
 * @param {{baseDir?:string, expectedPackageName?:string,
 *   expectedPackageVersion?:string|null, expectedIntegrity?:string|null,
 *   expectedDshVersion?:string|null}} [options]
 * @returns {Promise<{status:'available'|'unavailable', reason:string|null,
 *   detail:string|null, anchor:object|null, verification:object|null,
 *   limitations:string[]}>}
 */
export async function verifyRuntimeAnchorV2(anchor, options = {}) {
  if (!isPlainRecord(anchor)) return v2Unavailable('runtime-anchor-invalid', { detail: 'anchor must be an object' })
  const unknownFields = Object.keys(anchor).filter((key) => !ANCHOR_V2_FIELDS.includes(key))
  if (unknownFields.length > 0) {
    return v2Unavailable('runtime-anchor-invalid', { detail: `unknown fields: ${unknownFields.slice(0, 4).join(',')}` })
  }
  if (anchor.schema_version !== RUNTIME_ANCHOR_V2_VERSION) {
    return v2Unavailable('runtime-anchor-version-unknown', { detail: 'expected testbed-runtime-anchor/v2' })
  }

  const expectedName = options.expectedPackageName ?? '@deepseek-ai/cordis'
  if (anchor.package_name !== expectedName) {
    return v2Unavailable('runtime-package-unlockable', { detail: `package_name must be ${expectedName}` })
  }
  if (!isExactVersion(anchor.package_version)) {
    return v2Unavailable('runtime-package-unlockable', { detail: 'package_version must be an exact semver, never a tag or range' })
  }
  if (!isIntegrity(anchor.integrity)) {
    return v2Unavailable('runtime-package-unlockable', { detail: 'integrity must be an SRI sha256/sha384/sha512 value' })
  }
  if (!isRuntimeKindV2(anchor.runtime_kind)) {
    return v2Unavailable('runtime-anchor-invalid', { detail: 'unknown runtime_kind' })
  }
  if (anchor.runtime_kind !== 'locked-runtime') {
    return v2Unavailable('runtime-anchor-fixture-rejected', {
      detail: 'runtime_kind=test-fixture can only support E0 local evidence, never a market claim',
    })
  }
  if (!isNonEmptyString(anchor.entry)) {
    return v2Unavailable('runtime-anchor-invalid', { detail: 'entry must be a non-empty string' })
  }
  if (isAppAsarEntry(anchor.entry)) {
    return v2Unavailable('runtime-anchor-app-asar-rejected', { detail: 'app.asar is an archive, not an importable runtime' })
  }
  let entryUrl
  let entryPath
  try {
    entryUrl = new URL(anchor.entry)
    if (entryUrl.protocol !== 'file:') {
      return v2Unavailable('runtime-anchor-invalid', { detail: 'entry must be a file: URL' })
    }
    entryPath = fileURLToPath(entryUrl)
  } catch {
    return v2Unavailable('runtime-anchor-invalid', { detail: 'entry is not a valid file: URL' })
  }
  if (isAppAsarEntry(entryPath)) {
    return v2Unavailable('runtime-anchor-app-asar-rejected', { detail: 'app.asar is an archive, not an importable runtime' })
  }
  if (!isDigest(anchor.entry_digest)) {
    return v2Unavailable('runtime-anchor-invalid', { detail: 'entry_digest must be sha256:<64 lowercase hex>' })
  }
  if (invalidLockfileShape(anchor.lockfile)) {
    return v2Unavailable('runtime-anchor-invalid', { detail: 'lockfile must be {path,digest}' })
  }
  if (isAppAsarEntry(anchor.lockfile.path)) {
    return v2Unavailable('runtime-anchor-app-asar-rejected', { detail: 'lockfile path must not point into app.asar' })
  }
  if (!isExactVersion(anchor.dsh_version)) {
    return v2Unavailable('runtime-anchor-invalid', { detail: 'dsh_version must be an exact semver' })
  }
  if (!isNonEmptyString(anchor.node_version) || !anchor.node_version.startsWith('v')) {
    return v2Unavailable('runtime-anchor-invalid', { detail: 'node_version must be a v-prefixed version' })
  }
  if (!isNonEmptyString(anchor.platform) || !isNonEmptyString(anchor.arch)) {
    return v2Unavailable('runtime-anchor-invalid', { detail: 'platform/arch must be non-empty strings' })
  }
  if (invalidCatalogShape(anchor.catalog_ref)) {
    return v2Unavailable('runtime-anchor-invalid', { detail: 'catalog_ref must be {id,version,digest}' })
  }
  if (!Array.isArray(anchor.evidence_refs) || anchor.evidence_refs.length > MAX_V2_EVIDENCE_REFS ||
      anchor.evidence_refs.some((ref) => !isNonEmptyString(ref)) ||
      anchor.evidence_refs.some((ref) => isAppAsarEntry(ref))) {
    return v2Unavailable('runtime-anchor-invalid', { detail: 'evidence_refs must be bounded non-empty strings' })
  }
  if (anchor.notes !== null && (typeof anchor.notes !== 'string' || anchor.notes.length > 512)) {
    return v2Unavailable('runtime-anchor-invalid', { detail: 'notes must be null or a bounded string' })
  }

  const baseDir = options.baseDir ?? process.cwd()
  const entryBytes = await readBoundedFileBytes(entryPath, {
    maxBytes: MAX_RUNTIME_ENTRY_BYTES,
    missingReason: 'runtime-entry-missing',
    invalidReason: 'runtime-entry-invalid',
  })
  if (!entryBytes.ok) return v2Unavailable(entryBytes.reason, { detail: 'entry file is missing or too large' })
  const computedEntryDigest = sha256Bytes(entryBytes.bytes)
  if (computedEntryDigest !== anchor.entry_digest) {
    return v2Unavailable('runtime-entry-digest-mismatch', {
      detail: `entry_digest mismatch (declared ${anchor.entry_digest}, observed ${computedEntryDigest})`,
    })
  }

  const observed = await observePackageVersion(entryPath)
  if (observed?.version && observed.version !== anchor.package_version) {
    return v2Unavailable('runtime-version-mismatch', {
      detail: `package_version mismatch (declared ${anchor.package_version}, observed ${observed.version})`,
    })
  }
  if (observed?.name && observed.name !== anchor.package_name) {
    return v2Unavailable('runtime-version-mismatch', {
      detail: `package_name mismatch (declared ${anchor.package_name}, observed ${observed.name})`,
    })
  }
  if (
    (options.expectedPackageVersion != null && anchor.package_version !== options.expectedPackageVersion) ||
    (options.expectedDshVersion != null && anchor.dsh_version !== options.expectedDshVersion)
  ) {
    return v2Unavailable('runtime-version-mismatch', { detail: 'anchor version does not match the required version' })
  }
  if (options.expectedIntegrity != null && anchor.integrity !== options.expectedIntegrity) {
    return v2Unavailable('runtime-integrity-mismatch', { detail: 'anchor integrity does not match the required SRI value' })
  }
  if (anchor.node_version !== process.version) {
    return v2Unavailable('runtime-environment-mismatch', {
      detail: `node_version mismatch (declared ${anchor.node_version}, current ${process.version})`,
    })
  }
  if (anchor.platform !== process.platform || anchor.arch !== process.arch) {
    return v2Unavailable('runtime-environment-mismatch', {
      detail: `platform/arch mismatch (declared ${anchor.platform}/${anchor.arch}, current ${process.platform}/${process.arch})`,
    })
  }

  const lockfilePath = resolve(baseDir, anchor.lockfile.path)
  if (isAppAsarEntry(lockfilePath)) {
    return v2Unavailable('runtime-anchor-app-asar-rejected', { detail: 'lockfile path must not point into app.asar' })
  }
  const lockfileBytes = await readBoundedFileBytes(lockfilePath, {
    maxBytes: MAX_RUNTIME_LOCKFILE_BYTES,
    missingReason: 'runtime-lockfile-mismatch',
    invalidReason: 'runtime-lockfile-mismatch',
  })
  if (!lockfileBytes.ok) return v2Unavailable('runtime-lockfile-mismatch', { detail: 'lockfile is missing or too large' })
  const computedLockfileDigest = sha256Bytes(lockfileBytes.bytes)
  if (computedLockfileDigest !== anchor.lockfile.digest) {
    return v2Unavailable('runtime-lockfile-mismatch', {
      detail: `lockfile digest mismatch (declared ${anchor.lockfile.digest}, observed ${computedLockfileDigest})`,
    })
  }

  const normalizedAnchor = {
    schema_version: RUNTIME_ANCHOR_V2_VERSION,
    package_name: anchor.package_name,
    package_version: anchor.package_version,
    integrity: anchor.integrity,
    entry: pathToFileURL(entryPath).href,
    entry_digest: anchor.entry_digest,
    lockfile: { path: anchor.lockfile.path, digest: anchor.lockfile.digest },
    dsh_version: anchor.dsh_version,
    node_version: anchor.node_version,
    platform: anchor.platform,
    arch: anchor.arch,
    runtime_kind: anchor.runtime_kind,
    catalog_ref: { id: anchor.catalog_ref.id, version: anchor.catalog_ref.version, digest: anchor.catalog_ref.digest },
    evidence_refs: [...anchor.evidence_refs],
    notes: anchor.notes,
  }
  return {
    status: 'available',
    reason: null,
    detail: null,
    anchor: normalizedAnchor,
    verification: {
      anchor_digest: runtimeAnchorV2Digest(normalizedAnchor),
      entry_digest: computedEntryDigest,
      entry_path: entryPath,
      entry_url: pathToFileURL(entryPath).href,
      lockfile_path: lockfilePath,
      lockfile_digest: computedLockfileDigest,
      package_observed: observed
        ? { name: observed.name, version: observed.version, package_path: observed.package_path }
        : null,
      node_version: process.version,
      node_abi: process.versions.modules ?? null,
      platform: process.platform,
      arch: process.arch,
      runtime_kind: anchor.runtime_kind,
    },
    limitations: [],
  }
}

/**
 * Resolve a v2 anchor from an explicit injection or `DSH_TESTBED_RUNTIME_ANCHOR`.
 * The env value may be a path to a JSON anchor file or inline JSON. Any failure
 * is an explicit `unavailable`; callers must map that to `blocked`/`unknown`.
 *
 * @param {{injection?:object|string|null, env?:Record<string,string|undefined>,
 *   cwd?:string, baseDir?:string}} [options]
 * @returns {Promise<{status:'available'|'unavailable', reason:string|null,
 *   detail:string|null, anchor:object|null, verification:object|null,
 *   limitations:string[], source:string|null}>}
 */
export async function resolveRuntimeAnchorV2(options = {}) {
  const env = options.env ?? process.env
  let raw = null
  let source = null
  let baseDir = options.baseDir ?? options.cwd ?? process.cwd()

  if (options.injection != null) {
    if (typeof options.injection === 'string') {
      const trimmed = options.injection.trim()
      if (trimmed.startsWith('{')) {
        try {
          raw = JSON.parse(trimmed)
          source = 'injection'
        } catch {
          return { ...v2Unavailable('runtime-anchor-read-failed', { detail: 'injected JSON does not parse' }), source: 'injection' }
        }
      } else {
        const loaded = await loadV2AnchorFile(trimmed, baseDir)
        if (!loaded.ok) return { ...v2Unavailable(loaded.reason, { detail: loaded.detail }), source: 'injection-file' }
        raw = loaded.raw
        baseDir = loaded.baseDir
        source = 'injection-file'
      }
    } else if (isPlainRecord(options.injection)) {
      raw = options.injection
      source = 'injection'
    } else {
      return { ...v2Unavailable('runtime-anchor-invalid', { detail: 'unsupported injection' }), source: null }
    }
  } else if (isNonEmptyString(env?.DSH_TESTBED_RUNTIME_ANCHOR)) {
    const value = env.DSH_TESTBED_RUNTIME_ANCHOR.trim()
    if (value.startsWith('{')) {
      try {
        raw = JSON.parse(value)
        source = 'env-anchor'
      } catch {
        return { ...v2Unavailable('runtime-anchor-read-failed', { detail: 'env anchor JSON does not parse' }), source: 'env-anchor' }
      }
    } else {
      const loaded = await loadV2AnchorFile(value, baseDir)
      if (!loaded.ok) return { ...v2Unavailable(loaded.reason, { detail: loaded.detail }), source: 'env-anchor' }
      raw = loaded.raw
      baseDir = loaded.baseDir
      source = 'env-anchor'
    }
  } else {
    return { ...v2Unavailable('runtime-anchor-missing', { detail: 'no v2 anchor injection or DSH_TESTBED_RUNTIME_ANCHOR' }), source: null }
  }

  const verified = await verifyRuntimeAnchorV2(raw, { ...options, baseDir })
  return { ...verified, source }
}

/** @param {string} path @param {string} baseDir */
async function loadV2AnchorFile(path, baseDir) {
  const anchorPath = isAbsolute(path) || win32.isAbsolute(path) ? path : resolve(baseDir, path)
  const loaded = await readBoundedFileBytes(anchorPath, {
    maxBytes: MAX_ANCHOR_BYTES,
    missingReason: 'runtime-anchor-missing',
    invalidReason: 'runtime-anchor-read-failed',
  })
  if (!loaded.ok) return { ok: false, reason: loaded.reason, detail: `cannot read anchor file ${anchorPath}` }
  try {
    return { ok: true, raw: JSON.parse(loaded.bytes.toString('utf8')), baseDir: dirname(anchorPath) }
  } catch {
    return { ok: false, reason: 'runtime-anchor-read-failed', detail: 'anchor file is not valid JSON' }
  }
}
