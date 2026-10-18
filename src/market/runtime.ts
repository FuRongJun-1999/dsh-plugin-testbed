/**
 * Real locked-runtime evidence verification (MKT-C03, CRD-02/CRD-04/CRD-05).
 *
 * This module independently verifies the t7 handoff artifacts:
 *  - `cordis-runtime/runtime-anchor.json` (`testbed-runtime-anchor/v2`);
 *  - `tests/integration/cordis-contract/evidence/cordis-contract-results.v1.json`;
 *  - the materialized suite and API catalog.
 *
 * The market gate deliberately re-implements the v2 anchor check instead of
 * importing the worker-side JS (P4 is not migrated): the check is side-effect
 * free, never imports the entry, recomputes every digest with
 * `canonicalJson + sha256`, and rejects `app.asar`, `test-fixture`, floating
 * versions, stale copies and environment drift.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/market/runtime
 */

import { readFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { type as osType, release as osRelease, version as osVersion } from 'node:os'
import type { MarketPolicyView, RuntimeEvidence, UnknownRecord } from './types.js'
import {
  asRecord,
  asString,
  canonicalDigest,
  isArray,
  isDigest,
  isNonEmptyString,
  loadJsonOption,
  parseTimeMs,
  sha256Bytes,
} from './util.js'

export const CORDIS_PACKAGE = '@deepseek-ai/cordis'
export const DSH_PACKAGE = '@deepseek-ai/dsh'
export const EXPECTED_DSH_VERSION = '0.2.1-rc.2'
export const EXPECTED_NODE_VERSION = 'v24.21.0'
export const CONTRACT_SUITE_ID = 'cordis-runtime-contract'
export const CONTRACT_RESULTS_FILE = 'cordis-contract-results.v1.json'
export const CONTRACT_SUITE_FILE = 'cordis-contract-suite.v1.json'
export const CONTRACT_CATALOG_FILE = 'cordis-api-catalog.v1.json'

/** Stable reason codes owned by this module (§9.2 runtime group). */
export const RUNTIME_MARKET_REASONS = Object.freeze({
  ANCHOR_MISSING: 'runtime-anchor-missing',
  ANCHOR_INVALID: 'runtime-anchor-invalid',
  ANCHOR_READ_FAILED: 'runtime-anchor-read-failed',
  ANCHOR_VERSION_UNKNOWN: 'runtime-anchor-version-unknown',
  APP_ASAR: 'runtime-anchor-app-asar-rejected',
  FIXTURE: 'runtime-anchor-fixture-rejected',
  PACKAGE_UNLOCKABLE: 'runtime-package-unlockable',
  INTEGRITY_MISMATCH: 'runtime-integrity-mismatch',
  VERSION_MISMATCH: 'runtime-version-mismatch',
  ENVIRONMENT: 'runtime-environment-mismatch',
  ENTRY_MISSING: 'runtime-entry-missing',
  ENTRY_INVALID: 'runtime-entry-invalid',
  ENTRY_DIGEST_MISMATCH: 'runtime-entry-digest-mismatch',
  LOCKFILE_MISMATCH: 'runtime-lockfile-mismatch',
  CONTRACT_MISSING: 'runtime-contract-suite-missing',
  CONTRACT_FAILED: 'runtime-contract-suite-failed',
  EVIDENCE_STALE: 'market-evidence-stale',
})

export interface RuntimeEvidenceOptions {
  /** Anchor object, anchor path, or undefined (blocked). */
  anchor?: unknown
  /** Directory holding the contract evidence files. */
  contractEvidenceDir?: string
  /** Base directory for an injected anchor object (lockfile resolution). */
  runtimeBaseDir?: string
  policy: MarketPolicyView
  nowMs: number
}

const EXACT_VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/
const INTEGRITY_TOKEN = /^sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}$/
const APP_ASAR_SEGMENT = /(?:^|[\\/])app\.asar(?:[\\/]|$)/i
const ANCHOR_V2_FIELDS = [
  'schema_version', 'package_name', 'package_version', 'integrity', 'entry',
  'entry_digest', 'lockfile', 'dsh_version', 'node_version', 'platform', 'arch',
  'runtime_kind', 'catalog_ref', 'evidence_refs', 'notes',
]

function blocked(reason: string, detail: string, evidenceRefs: string[] = []): RuntimeEvidence {
  return {
    status: 'blocked',
    reasonCodes: [reason],
    detail,
    anchor: null,
    anchorDigest: null,
    cordisVersion: null,
    dshVersion: null,
    contractSuiteDigest: null,
    catalogDigest: null,
    lockfileDigest: null,
    entryDigest: null,
    environmentDigest: null,
    contractPassed: false,
    evidenceRefs,
  }
}

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, 'utf8'))
}

function deepEqual(a: unknown, b: unknown): boolean {
  return canonicalDigest(a) === canonicalDigest(b)
}

function currentEnvironment(): UnknownRecord {
  return {
    node_version: process.version,
    node_abi: process.versions.modules ?? null,
    platform: process.platform,
    arch: process.arch,
    os_type: osType(),
    os_release: osRelease(),
    os_version: osVersion(),
  }
}

function allowedRuntimeFor(policy: MarketPolicyView, pkg: string): { version: string; integrity: string } | null {
  const entry = policy.allowedRuntimes.find((runtime) => runtime.package === pkg)
  return entry ?? null
}

function isAppAsarEntry(value: string): boolean {
  let decoded = value
  try {
    decoded = decodeURIComponent(value)
  } catch {
    // Keep the raw form; the explicit rejection below still applies.
  }
  return APP_ASAR_SEGMENT.test(decoded.replace(/\\/g, '/'))
}

function isIntegrity(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 1024) return false
  return value.split(/\s+/).every((token) => INTEGRITY_TOKEN.test(token))
}

function isExactVersion(value: unknown): value is string {
  return typeof value === 'string' && EXACT_VERSION.test(value)
}

/** Canonical digest of a `testbed-runtime-anchor/v2` document. */
export function runtimeAnchorDigest(anchor: unknown): string {
  return canonicalDigest(anchor)
}

interface AnchorVerification {
  ok: boolean
  reason: string | null
  detail: string | null
  anchor: UnknownRecord | null
  anchorDigest: string | null
  entryDigest: string | null
  lockfileDigest: string | null
}

async function observePackage(entryPath: string): Promise<{ name: string | null; version: string | null }> {
  let dir = dirname(entryPath)
  for (let depth = 0; depth < 6; depth += 1) {
    try {
      const parsed = asRecord(JSON.parse(await readFile(join(dir, 'package.json'), 'utf8')))
      if (parsed !== null && isNonEmptyString(parsed.name)) {
        return {
          name: parsed.name,
          version: isExactVersion(parsed.version) ? parsed.version : asString(parsed.version),
        }
      }
    } catch {
      // Keep walking up; the node_modules layout has several package.json files.
    }
    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return { name: null, version: null }
}

/**
 * Independent `testbed-runtime-anchor/v2` verification. Fail-closed: every
 * branch returns an explicit reason, never a default pass.
 */
async function verifyAnchorV2(
  anchorRaw: unknown,
  options: {
    baseDir: string
    expectedPackageVersion: string
    expectedIntegrity: string
    expectedDshVersion: string
  },
): Promise<AnchorVerification> {
  const fail = (reason: string, detail: string): AnchorVerification => ({
    ok: false, reason, detail, anchor: null, anchorDigest: null, entryDigest: null, lockfileDigest: null,
  })
  const anchor = asRecord(anchorRaw)
  if (anchor === null) return fail(RUNTIME_MARKET_REASONS.ANCHOR_INVALID, 'anchor must be an object')
  const unknownFields = Object.keys(anchor).filter((key) => !ANCHOR_V2_FIELDS.includes(key))
  if (unknownFields.length > 0) {
    return fail(RUNTIME_MARKET_REASONS.ANCHOR_INVALID, `unknown fields: ${unknownFields.slice(0, 4).join(',')}`)
  }
  if (anchor.schema_version !== 'testbed-runtime-anchor/v2') {
    return fail(RUNTIME_MARKET_REASONS.ANCHOR_VERSION_UNKNOWN, 'expected testbed-runtime-anchor/v2')
  }
  if (anchor.package_name !== CORDIS_PACKAGE) {
    return fail(RUNTIME_MARKET_REASONS.PACKAGE_UNLOCKABLE, `package_name must be ${CORDIS_PACKAGE}`)
  }
  if (!isExactVersion(anchor.package_version)) {
    return fail(RUNTIME_MARKET_REASONS.PACKAGE_UNLOCKABLE, 'package_version must be an exact semver')
  }
  if (!isIntegrity(anchor.integrity)) {
    return fail(RUNTIME_MARKET_REASONS.PACKAGE_UNLOCKABLE, 'integrity must be an SRI value')
  }
  if (anchor.runtime_kind === 'test-fixture') {
    return fail(RUNTIME_MARKET_REASONS.FIXTURE, 'test-fixture can only support E0 evidence')
  }
  if (anchor.runtime_kind !== 'locked-runtime') {
    return fail(RUNTIME_MARKET_REASONS.ANCHOR_INVALID, 'runtime_kind must be locked-runtime')
  }
  const entry = asString(anchor.entry)
  if (entry === null) return fail(RUNTIME_MARKET_REASONS.ANCHOR_INVALID, 'entry must be a non-empty string')
  if (isAppAsarEntry(entry)) return fail(RUNTIME_MARKET_REASONS.APP_ASAR, 'app.asar is not an importable runtime')
  let entryPath: string
  try {
    const url = new URL(entry)
    if (url.protocol !== 'file:') return fail(RUNTIME_MARKET_REASONS.ANCHOR_INVALID, 'entry must be a file: URL')
    entryPath = fileURLToPath(url)
  } catch {
    return fail(RUNTIME_MARKET_REASONS.ANCHOR_INVALID, 'entry is not a valid file: URL')
  }
  if (isAppAsarEntry(entryPath)) return fail(RUNTIME_MARKET_REASONS.APP_ASAR, 'entry points into app.asar')
  const lockfile = asRecord(anchor.lockfile)
  const catalog = asRecord(anchor.catalog_ref)
  if (!isDigest(anchor.entry_digest)) return fail(RUNTIME_MARKET_REASONS.ANCHOR_INVALID, 'entry_digest invalid')
  if (lockfile === null || !isNonEmptyString(lockfile.path) || !isDigest(lockfile.digest)) {
    return fail(RUNTIME_MARKET_REASONS.ANCHOR_INVALID, 'lockfile must be {path,digest}')
  }
  if (isAppAsarEntry(lockfile.path)) return fail(RUNTIME_MARKET_REASONS.APP_ASAR, 'lockfile path inside app.asar')
  if (!isExactVersion(anchor.dsh_version)) return fail(RUNTIME_MARKET_REASONS.ANCHOR_INVALID, 'dsh_version invalid')
  if (!isNonEmptyString(anchor.node_version) || !anchor.node_version.startsWith('v')) {
    return fail(RUNTIME_MARKET_REASONS.ANCHOR_INVALID, 'node_version invalid')
  }
  if (catalog === null || !isNonEmptyString(catalog.id) || !isExactVersion(catalog.version) ||
      !isDigest(catalog.digest) || Object.keys(catalog).some((key) => !['id', 'version', 'digest'].includes(key))) {
    return fail(RUNTIME_MARKET_REASONS.ANCHOR_INVALID, 'catalog_ref invalid')
  }
  if (!isArray(anchor.evidence_refs) || anchor.evidence_refs.some((ref) => !isNonEmptyString(ref) || isAppAsarEntry(ref))) {
    return fail(RUNTIME_MARKET_REASONS.ANCHOR_INVALID, 'evidence_refs invalid')
  }
  if (anchor.notes !== null && (typeof anchor.notes !== 'string' || anchor.notes.length > 512)) {
    return fail(RUNTIME_MARKET_REASONS.ANCHOR_INVALID, 'notes invalid')
  }
  if (anchor.package_version !== options.expectedPackageVersion) {
    return fail(RUNTIME_MARKET_REASONS.VERSION_MISMATCH, 'anchor version does not match policy')
  }
  if (anchor.integrity !== options.expectedIntegrity) {
    return fail(RUNTIME_MARKET_REASONS.INTEGRITY_MISMATCH, 'anchor integrity does not match policy')
  }
  if (anchor.dsh_version !== options.expectedDshVersion) {
    return fail(RUNTIME_MARKET_REASONS.VERSION_MISMATCH, 'anchor dsh_version does not match policy')
  }
  if (anchor.node_version !== process.version) {
    return fail(RUNTIME_MARKET_REASONS.ENVIRONMENT, `node_version ${anchor.node_version} != ${process.version}`)
  }
  if (anchor.platform !== process.platform || anchor.arch !== process.arch) {
    return fail(RUNTIME_MARKET_REASONS.ENVIRONMENT, 'platform/arch mismatch')
  }
  let entryBytes: Uint8Array
  try {
    entryBytes = await readFile(entryPath)
  } catch {
    return fail(RUNTIME_MARKET_REASONS.ENTRY_MISSING, 'entry file is missing')
  }
  if (entryBytes.byteLength > 8 * 1024 * 1024) {
    return fail(RUNTIME_MARKET_REASONS.ENTRY_INVALID, 'entry file is too large')
  }
  const observedEntryDigest = sha256Bytes(entryBytes)
  if (observedEntryDigest !== anchor.entry_digest) {
    return fail(RUNTIME_MARKET_REASONS.ENTRY_DIGEST_MISMATCH, 'entry_digest mismatch')
  }
  const observedPackage = await observePackage(entryPath)
  if (observedPackage.version !== null && observedPackage.version !== anchor.package_version) {
    return fail(RUNTIME_MARKET_REASONS.VERSION_MISMATCH, 'package.json version mismatch')
  }
  if (observedPackage.name !== null && observedPackage.name !== anchor.package_name) {
    return fail(RUNTIME_MARKET_REASONS.VERSION_MISMATCH, 'package.json name mismatch')
  }
  const lockfilePath = resolve(options.baseDir, lockfile.path)
  if (isAppAsarEntry(lockfilePath)) return fail(RUNTIME_MARKET_REASONS.APP_ASAR, 'lockfile inside app.asar')
  let lockfileBytes: Uint8Array
  try {
    lockfileBytes = await readFile(lockfilePath)
  } catch {
    return fail(RUNTIME_MARKET_REASONS.LOCKFILE_MISMATCH, 'lockfile is missing')
  }
  if (lockfileBytes.byteLength > 16 * 1024 * 1024) {
    return fail(RUNTIME_MARKET_REASONS.LOCKFILE_MISMATCH, 'lockfile too large')
  }
  const observedLockfileDigest = sha256Bytes(lockfileBytes)
  if (observedLockfileDigest !== lockfile.digest) {
    return fail(RUNTIME_MARKET_REASONS.LOCKFILE_MISMATCH, 'lockfile digest mismatch')
  }
  const normalized: UnknownRecord = {
    schema_version: 'testbed-runtime-anchor/v2',
    package_name: anchor.package_name,
    package_version: anchor.package_version,
    integrity: anchor.integrity,
    entry: pathToFileURL(entryPath).href,
    entry_digest: anchor.entry_digest,
    lockfile: { path: lockfile.path, digest: lockfile.digest },
    dsh_version: anchor.dsh_version,
    node_version: anchor.node_version,
    platform: anchor.platform,
    arch: anchor.arch,
    runtime_kind: anchor.runtime_kind,
    catalog_ref: { id: catalog.id, version: catalog.version, digest: catalog.digest },
    evidence_refs: [...(anchor.evidence_refs as string[])],
    notes: anchor.notes,
  }
  return {
    ok: true,
    reason: null,
    detail: null,
    anchor: normalized,
    anchorDigest: runtimeAnchorDigest(normalized),
    entryDigest: observedEntryDigest,
    lockfileDigest: observedLockfileDigest,
  }
}

/**
 * Verify anchor + contract evidence against the current machine.
 *
 * @param {RuntimeEvidenceOptions} options
 * @returns {Promise<RuntimeEvidence>}
 */
export async function verifyRuntimeEvidence(options: RuntimeEvidenceOptions): Promise<RuntimeEvidence> {
  const { policy, nowMs } = options
  const cordisAllowed = allowedRuntimeFor(policy, CORDIS_PACKAGE)
  if (cordisAllowed === null) {
    return blocked(RUNTIME_MARKET_REASONS.ANCHOR_INVALID, 'policy does not allow @deepseek-ai/cordis')
  }
  const dshAllowed = allowedRuntimeFor(policy, DSH_PACKAGE)
  const expectedDshVersion = dshAllowed?.version ?? EXPECTED_DSH_VERSION

  if (options.anchor === undefined || options.anchor === null) {
    return blocked(RUNTIME_MARKET_REASONS.ANCHOR_MISSING, 'no runtime anchor supplied')
  }
  const baseDir = options.runtimeBaseDir ?? process.cwd()
  const loaded = await loadJsonOption(options.anchor, baseDir)
  if (!loaded.ok) {
    return blocked(
      loaded.reason === 'input-unreadable' || loaded.reason === 'input-missing'
        ? RUNTIME_MARKET_REASONS.ANCHOR_MISSING
        : RUNTIME_MARKET_REASONS.ANCHOR_INVALID,
      loaded.detail,
    )
  }
  const anchorBaseDir = loaded.path === null ? resolve(baseDir) : dirname(loaded.path)
  const verified = await verifyAnchorV2(loaded.value, {
    baseDir: anchorBaseDir,
    expectedPackageVersion: cordisAllowed.version,
    expectedIntegrity: cordisAllowed.integrity,
    expectedDshVersion,
  })
  if (!verified.ok || verified.anchor === null || verified.anchorDigest === null) {
    return blocked(verified.reason ?? RUNTIME_MARKET_REASONS.ANCHOR_INVALID, verified.detail ?? 'anchor failed')
  }
  const anchor = verified.anchor
  const anchorDigest = verified.anchorDigest
  const evidenceRefs = [loaded.path ?? 'injected-anchor']

  if (!isNonEmptyString(options.contractEvidenceDir)) {
    return blocked(RUNTIME_MARKET_REASONS.CONTRACT_MISSING, 'no contract evidence directory')
  }
  const evidenceDir = options.contractEvidenceDir as string
  const resultsPath = join(evidenceDir, CONTRACT_RESULTS_FILE)
  const suitePath = join(evidenceDir, CONTRACT_SUITE_FILE)
  const catalogPath = join(evidenceDir, CONTRACT_CATALOG_FILE)
  evidenceRefs.push(CONTRACT_RESULTS_FILE, CONTRACT_SUITE_FILE, CONTRACT_CATALOG_FILE)

  let results: UnknownRecord
  let suite: UnknownRecord
  let catalogDoc: UnknownRecord
  try {
    const [resultsRaw, suiteRaw, catalogRaw] = await Promise.all([
      readJson(resultsPath),
      readJson(suitePath),
      readJson(catalogPath),
    ])
    const resultsRecord = asRecord(resultsRaw)
    const suiteRecord = asRecord(suiteRaw)
    const catalogRecord = asRecord(catalogRaw)
    if (!resultsRecord || !suiteRecord || !catalogRecord) {
      return blocked(RUNTIME_MARKET_REASONS.CONTRACT_FAILED, 'contract evidence is not a JSON object', evidenceRefs)
    }
    results = resultsRecord
    suite = suiteRecord
    catalogDoc = catalogRecord
  } catch {
    return blocked(RUNTIME_MARKET_REASONS.CONTRACT_MISSING, 'contract evidence files are missing or unreadable', evidenceRefs)
  }

  const fail = (detail: string): RuntimeEvidence =>
    blocked(RUNTIME_MARKET_REASONS.CONTRACT_FAILED, detail, evidenceRefs)

  if (results.schema_version !== 'cordis-contract-results/v1') return fail('results schema_version')
  if (results.suite_id !== CONTRACT_SUITE_ID) return fail('results suite_id')
  if (suite.schema_version !== 'cordis-contract-suite/v1') return fail('suite schema_version')
  if (suite.suite_id !== CONTRACT_SUITE_ID) return fail('suite suite_id')
  if (results.suite_version !== suite.suite_version) return fail('suite version mismatch')
  if (results.runtime_anchor_digest !== anchorDigest) return fail('results anchor digest mismatch')
  if (suite.runtime_anchor_digest !== anchorDigest) return fail('suite anchor digest mismatch')
  if (results.suite_digest !== canonicalDigest(suite)) return fail('suite digest mismatch')
  if (results.runtime_kind !== 'locked-runtime') return fail('results runtime_kind')
  const anchorCatalog = asRecord(anchor.catalog_ref)
  if (!isDigest(results.catalog_digest) || results.catalog_digest !== anchorCatalog?.digest) {
    return fail('catalog digest mismatch')
  }
  if (canonicalDigest(catalogDoc) !== results.catalog_digest) return fail('catalog file digest mismatch')
  const suiteCatalog = asRecord(suite.catalog_ref)
  if (!suiteCatalog || canonicalDigest(suiteCatalog) !== canonicalDigest(anchorCatalog)) {
    return fail('suite catalog_ref mismatch')
  }
  if (results.entry_digest !== anchor.entry_digest) return fail('entry digest mismatch')
  const anchorLockfile = asRecord(anchor.lockfile)
  if (results.lockfile_digest !== anchorLockfile?.digest) return fail('lockfile digest mismatch')
  const resultsPackage = asRecord(results.package)
  if (!resultsPackage ||
      resultsPackage.name !== anchor.package_name ||
      resultsPackage.version !== anchor.package_version ||
      resultsPackage.integrity !== anchor.integrity) {
    return fail('package binding mismatch')
  }
  if (results.dsh_version !== anchor.dsh_version) return fail('dsh version mismatch')

  const summary = asRecord(results.summary)
  if (!summary || summary.required_failed !== 0 || summary.failed !== 0 ||
      summary.total !== summary.passed || !isArray(results.cases) || !isArray(suite.cases)) {
    return fail('contract cases did not all pass')
  }
  const suiteCases = suite.cases as unknown[]
  const resultCases = results.cases as unknown[]
  if (resultCases.length !== suiteCases.length || resultCases.length === 0) {
    return fail('contract case count mismatch')
  }
  for (const suiteCase of suiteCases) {
    const suiteCaseRecord = asRecord(suiteCase)
    const caseId = asString(suiteCaseRecord?.case_id)
    if (caseId === null) return fail('suite case id missing')
    const resultCase = resultCases
      .map((item) => asRecord(item))
      .find((item) => item?.case_id === caseId)
    if (!resultCase || resultCase.status !== 'pass') {
      return fail(`required contract case not passing: ${caseId}`)
    }
  }

  const environment = asRecord(results.environment)
  if (!environment || !deepEqual(environment, currentEnvironment())) {
    return blocked(RUNTIME_MARKET_REASONS.ENVIRONMENT, 'contract environment does not match current host', evidenceRefs)
  }
  if (results.environment_digest !== canonicalDigest(environment)) {
    return fail('environment digest mismatch')
  }
  const endedAtMs = parseTimeMs(results.ended_at)
  if (endedAtMs === null || endedAtMs > nowMs + 60_000 || nowMs - endedAtMs > policy.evidenceMaxAgeMs) {
    return blocked(RUNTIME_MARKET_REASONS.EVIDENCE_STALE, 'contract results are stale or time-inconsistent', evidenceRefs)
  }

  return {
    status: 'available',
    reasonCodes: [],
    detail: null,
    anchor,
    anchorDigest,
    cordisVersion: asString(anchor.package_version),
    dshVersion: asString(anchor.dsh_version),
    contractSuiteDigest: asString(results.suite_digest),
    catalogDigest: asString(results.catalog_digest),
    lockfileDigest: asString(results.lockfile_digest),
    entryDigest: asString(results.entry_digest),
    environmentDigest: asString(results.environment_digest),
    contractPassed: true,
    evidenceRefs,
  }
}
