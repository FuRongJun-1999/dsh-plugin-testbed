/**
 * Shared helpers for the real-Cordis contract suite.
 *
 * Nothing here substitutes for the locked runtime: every helper either reads the
 * installed artifacts under `cordis-runtime/`, verifies their digests with the
 * production `src/worker/runtime.js` v2 verifier, or imports the real package
 * entry recorded in the anchor. A missing/mismatched runtime throws a
 * `blocked`-style error; it is never converted into a fixture or a skip.
 */
import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import { mkdir, readFile, realpath, rename, rm, stat, writeFile } from 'node:fs/promises'
import { builtinModules } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import os from 'node:os'
import { canonicalJson, sha256Hex } from '../../../src/protocol/digest.js'
import { runtimeAnchorV2Digest, verifyRuntimeAnchorV2 } from '../../../src/worker/runtime.js'

export const HERE = dirname(fileURLToPath(import.meta.url))
export const TESTBED_ROOT = resolve(HERE, '../../..')
export const RUNTIME_DIR = join(TESTBED_ROOT, 'cordis-runtime')
export const EVIDENCE_DIR = join(HERE, 'evidence')
export const CONTRACT_DIR = join(HERE, 'contract')
export const FIXTURES_DIR = join(HERE, 'fixtures')
export const ANCHOR_PATH = join(RUNTIME_DIR, 'runtime-anchor.json')
export const ANCHOR_EVIDENCE_DIR = RUNTIME_DIR

export const REQUIRED_PACKAGES = Object.freeze({
  '@deepseek-ai/cordis': '4.0.5',
  '@deepseek-ai/dsh': '0.2.1-rc.2',
  '@deepseek-ai/dsh-cordis-host-runner': '0.2.1-rc.2',
})
export const REQUIRED_PEERS = Object.freeze({
  '@deepseek-ai/cordis-plugin-loader': '1.0.6',
  '@deepseek-ai/cordis-plugin-include': '1.0.10',
  '@deepseek-ai/cordis-plugin-timer': '1.1.7',
})
const EXACT_SPEC = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/
const DIGEST = /^sha256:[0-9a-f]{64}$/

export class RuntimeBlockedError extends Error {
  constructor(reason, detail) {
    super(`[blocked:${reason}] ${detail}`)
    this.name = 'RuntimeBlockedError'
    this.reason = reason
    this.detail = detail
  }
}

/** @param {string} path */
export async function readJson(path) {
  return JSON.parse(await readFile(path, 'utf8'))
}

/** @param {string} path @returns {Promise<string>} `sha256:<hex>` over raw bytes */
export async function sha256File(path) {
  const bytes = await readFile(path)
  return 'sha256:' + createHash('sha256').update(bytes).digest('hex')
}

export function sha256Value(value) {
  return 'sha256:' + sha256Hex(canonicalJson(value))
}

export function environmentSummary() {
  return {
    node_version: process.version,
    node_abi: process.versions.modules ?? null,
    platform: process.platform,
    arch: process.arch,
    os_type: os.type(),
    os_release: os.release(),
    os_version: typeof os.version === 'function' ? os.version() : null,
  }
}

/** Read the isolated runtime manifest (cordis-runtime/package.json). */
export async function readRuntimeManifest() {
  const manifestPath = join(RUNTIME_DIR, 'package.json')
  let manifest
  try {
    manifest = await readJson(manifestPath)
  } catch {
    throw new RuntimeBlockedError('runtime-package-unlockable', `missing ${manifestPath}; run: pnpm --dir cordis-runtime install --frozen-lockfile`)
  }
  return { manifest, manifestPath }
}

/**
 * Assert the isolated manifest pins every required package/peer to one exact
 * version (no ranges, tags, or workspace protocols).
 */
export function assertExactManifest(manifest) {
  const dependencies = manifest?.dependencies ?? {}
  for (const [name, expected] of Object.entries({ ...REQUIRED_PACKAGES, ...REQUIRED_PEERS })) {
    const spec = dependencies[name]
    if (spec !== expected) {
      throw new RuntimeBlockedError('runtime-package-unlockable', `${name} must be exactly "${expected}" in cordis-runtime/package.json, found ${JSON.stringify(spec)}`)
    }
    if (!EXACT_SPEC.test(spec)) {
      throw new RuntimeBlockedError('runtime-package-unlockable', `${name} specifier ${JSON.stringify(spec)} is not an exact version`)
    }
  }
  for (const [name, spec] of Object.entries(dependencies)) {
    if (typeof spec !== 'string' || !EXACT_SPEC.test(spec)) {
      throw new RuntimeBlockedError('runtime-package-unlockable', `dependency ${name} uses a floating specifier ${JSON.stringify(spec)}`)
    }
  }
  return dependencies
}

/**
 * Extract the lockfile `resolution.integrity` for one exact pnpm package key.
 * Deliberately a narrow parser over the lockfile's deterministic layout: adding
 * a YAML dependency to the testbed just to read two fields is not justified.
 */
export function lockfileIntegrity(lockfileText, name, version) {
  const key = `${name}@${version}`
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const block = new RegExp(`^  '${escaped}':\\r?\\n((?:    \\S.*\\r?\\n|      .*\\r?\\n)+)`, 'm')
  const match = block.exec(lockfileText)
  if (!match) return null
  const integrity = /resolution: \{integrity: (sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2})\}/.exec(match[1])
  return integrity?.[1] ?? null
}

/** Read installed package metadata and the real Cordis entry path. */
export async function readInstalledRuntime() {
  const { manifest, manifestPath } = await readRuntimeManifest()
  assertExactManifest(manifest)
  const lockfilePath = join(RUNTIME_DIR, 'pnpm-lock.yaml')
  let lockfileText
  try {
    lockfileText = await readFile(lockfilePath, 'utf8')
  } catch {
    throw new RuntimeBlockedError('runtime-package-unlockable', `missing lockfile ${lockfilePath}; run: pnpm --dir cordis-runtime install --frozen-lockfile`)
  }

  const installed = {}
  for (const [name, expected] of Object.entries({ ...REQUIRED_PACKAGES, ...REQUIRED_PEERS })) {
    const packagePath = join(RUNTIME_DIR, 'node_modules', ...name.split('/'), 'package.json')
    let pkg
    try {
      pkg = await readJson(packagePath)
    } catch {
      throw new RuntimeBlockedError('runtime-package-unlockable', `missing installed package ${name}; run: pnpm --dir cordis-runtime install --frozen-lockfile`)
    }
    if (pkg.version !== expected) {
      throw new RuntimeBlockedError('runtime-version-mismatch', `${name} installed version ${pkg.version} != locked ${expected}`)
    }
    const integrity = lockfileIntegrity(lockfileText, name, expected)
    if (integrity === null) {
      throw new RuntimeBlockedError('runtime-integrity-mismatch', `lockfile records no integrity for ${name}@${expected}`)
    }
    installed[name] = { package: pkg, packagePath, integrity }
  }

  const cordisRoot = await realpath(join(RUNTIME_DIR, 'node_modules', '@deepseek-ai', 'cordis'))
  const cordisMain = installed['@deepseek-ai/cordis'].package.main ?? 'lib/index.js'
  const cordisEntry = join(cordisRoot, cordisMain)
  const info = await stat(cordisEntry).catch(() => null)
  if (!info?.isFile()) {
    throw new RuntimeBlockedError('runtime-entry-missing', `Cordis entry ${cordisEntry} does not exist`)
  }
  if (/app\.asar/i.test(cordisEntry)) {
    throw new RuntimeBlockedError('runtime-anchor-app-asar-rejected', `Cordis entry resolves into app.asar: ${cordisEntry}`)
  }

  return {
    manifest,
    manifestPath,
    lockfilePath,
    lockfileText,
    lockfileDigest: 'sha256:' + createHash('sha256').update(lockfileText).digest('hex'),
    installed,
    cordisEntry,
    cordisEntryUrl: pathToFileURL(cordisEntry).href,
  }
}

/** Build the API catalog that the anchor/results bind (static shape only, no claims). */
export function buildApiCatalog(cordis, version) {
  const names = Object.keys(cordis).sort()
  const listMethods = (value) => {
    if (typeof value !== 'function') return []
    const proto = value.prototype
    const fromProto = proto && typeof proto === 'object' ? Object.getOwnPropertyNames(proto) : []
    const fromCtor = Object.getOwnPropertyNames(value)
    return [...new Set([...fromCtor, ...fromProto])]
      .filter((name) => !['length', 'name', 'prototype', 'arguments', 'caller'].includes(name))
      .sort()
  }
  const catalog = {
    schema_version: 'cordis-api-catalog/v1',
    catalog_id: 'cordis-runtime-api-catalog',
    catalog_version: '1.0.0',
    package: { name: '@deepseek-ai/cordis', version },
    exports: names,
    api: {
      Context: { static: listMethods(cordis.Context), instance: listMethods(cordis.Context) },
      EventsService: { instance: listMethods(cordis.EventsService) },
      RegistryService: { instance: listMethods(cordis.RegistryService) },
      Service: { static: listMethods(cordis.Service), instance: listMethods(cordis.Service) },
      Fiber: { instance: listMethods(cordis.Fiber) },
      ValidationError: typeof cordis.ValidationError,
      CordisError: typeof cordis.CordisError,
    },
    fiber_states: {
      PENDING: 0,
      LOADING: 1,
      ACTIVE: 2,
      FAILED: 3,
      DISPOSED: 4,
      UNLOADING: 5,
      source: 'lib/types/fiber.d.ts (locked package)',
    },
    node_builtins_used: ['node:crypto', 'node:fs', 'node:module', 'node:path', 'node:url'].filter((name) => builtinModules.includes(name.replace(/^node:/, ''))),
    observed_at: null,
  }
  return { catalog, digest: sha256Value(catalog) }
}

/** Materialize `testbed-runtime-anchor/v2` from verified installed artifacts. */
export async function buildRuntimeAnchor({ catalogRef, nodeVersion = process.version } = {}) {
  const runtime = await readInstalledRuntime()
  const cordis = runtime.installed['@deepseek-ai/cordis']
  const dsh = runtime.installed['@deepseek-ai/dsh']
  const entryDigest = await sha256File(runtime.cordisEntry)
  if (!catalogRef || typeof catalogRef.digest !== 'string' || !DIGEST.test(catalogRef.digest)) {
    throw new RuntimeBlockedError('runtime-anchor-invalid', 'a digested API catalog is required before building the anchor')
  }
  const anchor = {
    schema_version: 'testbed-runtime-anchor/v2',
    package_name: '@deepseek-ai/cordis',
    package_version: cordis.package.version,
    integrity: cordis.integrity,
    entry: runtime.cordisEntryUrl,
    entry_digest: entryDigest,
    lockfile: { path: 'pnpm-lock.yaml', digest: runtime.lockfileDigest },
    dsh_version: dsh.package.version,
    node_version: nodeVersion,
    platform: process.platform,
    arch: process.arch,
    runtime_kind: 'locked-runtime',
    catalog_ref: { id: catalogRef.id, version: catalogRef.version, digest: catalogRef.digest },
    evidence_refs: [
      'tests/integration/cordis-contract/evidence/cordis-api-catalog.v1.json',
      'tests/integration/cordis-contract/evidence/cordis-contract-results.v1.json',
    ],
    notes: 'Isolated pnpm install under cordis-runtime/; lifecycle scripts disabled by pnpm-workspace.yaml ignoreScripts:true + allowBuilds:false.',
  }
  const verified = await verifyRuntimeAnchorV2(anchor, {
    baseDir: ANCHOR_EVIDENCE_DIR,
    expectedPackageVersion: REQUIRED_PACKAGES['@deepseek-ai/cordis'],
    expectedDshVersion: REQUIRED_PACKAGES['@deepseek-ai/dsh'],
    expectedIntegrity: cordis.integrity,
  })
  if (verified.status !== 'available') {
    throw new RuntimeBlockedError(verified.reason, verified.detail ?? 'runtime anchor verification failed')
  }
  return { anchor: verified.anchor, anchorDigest: runtimeAnchorV2Digest(verified.anchor), verified, runtime }
}

/**
 * Import the real Cordis entry plus the pinned peer packages. The anchor is
 * verified before import; a missing package throws a blocked error.
 */
export async function loadRealRuntime(anchor) {
  const require = createRequire(join(RUNTIME_DIR, 'package.json'))
  const resolveEntry = (name) => {
    try {
      return require.resolve(name)
    } catch {
      throw new RuntimeBlockedError('runtime-package-unlockable', `cannot resolve ${name} from cordis-runtime/`)
    }
  }
  const entryPath = fileURLToPath(anchor.entry)
  let cordis
  try {
    cordis = await import(pathToFileURL(entryPath).href)
  } catch (error) {
    throw new RuntimeBlockedError('runtime-entry-invalid', `real Cordis import failed: ${error?.message ?? String(error)}`)
  }
  const load = async (name) => {
    const resolved = resolveEntry(name)
    if (/app\.asar/i.test(resolved)) {
      throw new RuntimeBlockedError('runtime-anchor-app-asar-rejected', `${name} resolves into app.asar`)
    }
    return import(pathToFileURL(resolved).href)
  }
  const loader = await load('@deepseek-ai/cordis-plugin-loader')
  const timer = await load('@deepseek-ai/cordis-plugin-timer')
  const hostRunner = await load('@deepseek-ai/dsh-cordis-host-runner')
  const include = await load('@deepseek-ai/cordis-plugin-include')
  return { cordis, loader, timer, hostRunner, include, entryPath }
}

/** Read the static suite definition from cordis-runtime/contract/. */
export async function readSuiteDefinition() {
  const path = join(CONTRACT_DIR, 'cordis-contract-suite.v1.json')
  try {
    return await readJson(path)
  } catch {
    throw new RuntimeBlockedError('runtime-anchor-invalid', `missing contract suite definition ${path}`)
  }
}

/** Materialize the suite document: definition + anchor digest + catalog reference. */
export function materializeSuite(definition, { anchor, anchorDigest }) {
  const suite = {
    schema_version: 'cordis-contract-suite/v1',
    suite_id: definition.suite_id,
    suite_version: definition.suite_version,
    runtime_anchor_digest: anchorDigest,
    catalog_ref: { ...anchor.catalog_ref },
    cases: definition.cases.map((entry) => ({
      case_id: entry.case_id,
      area: entry.area,
      required: entry.required !== false,
      actions: [...entry.actions],
      expected: [...entry.expected],
      evidence_kind: entry.evidence_kind,
    })),
  }
  return { suite, suiteDigest: sha256Value(suite) }
}

export function resultsDocument({ suite, suiteDigest, anchor, anchorDigest, cases, startedAt, endedAt, environment }) {
  return {
    schema_version: 'cordis-contract-results/v1',
    suite_id: suite.suite_id,
    suite_version: suite.suite_version,
    suite_digest: suiteDigest,
    runtime_anchor_digest: anchorDigest,
    runtime_kind: anchor.runtime_kind,
    catalog_ref: { ...anchor.catalog_ref },
    catalog_digest: anchor.catalog_ref.digest,
    lockfile_digest: anchor.lockfile.digest,
    entry_digest: anchor.entry_digest,
    package: { name: anchor.package_name, version: anchor.package_version, integrity: anchor.integrity },
    dsh_version: anchor.dsh_version,
    environment,
    environment_digest: sha256Value(environment),
    cases,
    summary: {
      total: cases.length,
      passed: cases.filter((item) => item.status === 'pass').length,
      failed: cases.filter((item) => item.status !== 'pass').length,
      required_failed: cases.filter((item) => item.required && item.status !== 'pass').length,
    },
    started_at: startedAt,
    ended_at: endedAt,
  }
}

/** Atomic evidence write (temp + rename), creating the evidence directory. */
export async function writeEvidence(fileName, value) {
  await mkdir(EVIDENCE_DIR, { recursive: true })
  const target = join(EVIDENCE_DIR, fileName)
  const temp = `${target}.${process.pid}.${Date.now()}.tmp`
  await writeFile(temp, JSON.stringify(value, null, 2) + '\n', 'utf8')
  await rename(temp, target)
  return target
}

/** Write the generated anchor to its stable deliverable path. */
export async function writeRuntimeAnchor(anchor) {
  const temp = `${ANCHOR_PATH}.${process.pid}.${Date.now()}.tmp`
  await writeFile(temp, JSON.stringify(anchor, null, 2) + '\n', 'utf8')
  await rename(temp, ANCHOR_PATH)
  return ANCHOR_PATH
}

/** Best-effort redaction of evidence detail strings (never include secrets). */
export function evidenceError(error) {
  const message = error instanceof Error ? error.message : String(error)
  return message
    .replace(/(?:token|secret|password|api[_-]?key)\s*[:=]\s*\S+/gi, '[redacted]')
    .slice(0, 2000)
}

/** JSON-safe value for embedded error objects. */
export function errorDetail(error) {
  if (!(error instanceof Error)) return { message: evidenceError(error) }
  return {
    name: error.name,
    code: typeof error.code === 'string' ? error.code : null,
    message: evidenceError(error),
  }
}

/** Remove stale temporary files from interrupted evidence writes. */
export async function cleanupEvidenceTemps() {
  for (const path of [ANCHOR_PATH, join(EVIDENCE_DIR, 'cordis-contract-results.v1.json')]) {
    await rm(`${path}.tmp`, { force: true })
  }
}
