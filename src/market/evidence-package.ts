/**
 * `market-evidence-package/v1` builder/verifier (§6.12, MKT-C07).
 *
 * The package is a bounded, digest-verified inventory. Paths must stay inside
 * the package root, every listed file must match its digest/size, and (when
 * scanning a directory) unregistered files are rejected. `package_digest`
 * covers the whole manifest except itself, so it binds the final inventory
 * without a circular dependency.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/market/evidence-package
 */

import { mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises'
import { dirname, join, relative, resolve, sep } from 'node:path'
import {
  MARKET_EVIDENCE_PACKAGE_VERSION,
  MARKET_REASON_CODES,
  validateMarketEvidencePackage,
} from '../protocol/market-schemas.js'
import type { EvidencePackage, UnknownRecord } from './types.js'
import { canonicalDigest, isArray, isNonEmptyString, sha256Bytes } from './util.js'

const SHA256 = /^sha256:[0-9a-f]{64}$/

export interface ArtifactInput {
  path: string
  kind: string
  digest: string
  size_bytes: number
}

export interface BuildEvidencePackageInput {
  packageId: string
  runId: string
  receiptDigest: string
  artifacts: ArtifactInput[]
  createdAt: string
  retention?: { until: string | null; policy_ref: string | null }
  redaction?: { status: 'reviewed' | 'not-reviewed'; notes: string | null }
}

/**
 * Normalized package-relative path. Rejects absolute paths, `..` traversal,
 * backslash forms and `app.asar` segments.
 */
export function safeRelativePath(value: unknown): string | null {
  if (!isNonEmptyString(value)) return null
  if (value.includes('\\') || value.includes('\0')) return null
  if (value.startsWith('/') || /^[A-Za-z]:/.test(value)) return null
  if (/(?:^|\/)app\.asar(?:\/|$)/i.test(value)) return null
  const parts = value.split('/')
  if (parts.some((part) => part === '' || part === '.' || part === '..')) return null
  return value
}

/** Compute digest + size for a file that must stay inside `root`. */
export async function describeArtifact(
  root: string,
  relativePath: string,
  kind: string,
): Promise<{ ok: true; artifact: ArtifactInput; absolutePath: string } | { ok: false; reason: string; detail: string }> {
  const safe = safeRelativePath(relativePath)
  if (safe === null) {
    return { ok: false, reason: MARKET_REASON_CODES.MARKET_EVIDENCE_PATH_ESCAPE, detail: `unsafe path: ${String(relativePath)}` }
  }
  const rootAbs = resolve(root)
  const absolutePath = resolve(rootAbs, safe)
  const rel = relative(rootAbs, absolutePath)
  if (rel.startsWith('..') || rel.startsWith(sep) || resolve(absolutePath) !== absolutePath) {
    return { ok: false, reason: MARKET_REASON_CODES.MARKET_EVIDENCE_PATH_ESCAPE, detail: `path escapes root: ${safe}` }
  }
  try {
    const info = await stat(absolutePath)
    if (!info.isFile()) return { ok: false, reason: MARKET_REASON_CODES.MARKET_EVIDENCE_INCOMPLETE, detail: `not a file: ${safe}` }
    const bytes = await readFile(absolutePath)
    return {
      ok: true,
      artifact: { path: safe, kind, digest: sha256Bytes(bytes), size_bytes: bytes.byteLength },
      absolutePath,
    }
  } catch {
    return { ok: false, reason: MARKET_REASON_CODES.MARKET_EVIDENCE_INCOMPLETE, detail: `missing file: ${safe}` }
  }
}

/** Build a schema-valid `market-evidence-package/v1` manifest. */
export function buildEvidencePackage(input: BuildEvidencePackageInput): EvidencePackage {
  const artifacts: ArtifactInput[] = []
  const seen = new Set<string>()
  for (const artifact of input.artifacts) {
    const safe = safeRelativePath(artifact.path)
    if (safe === null) throw new TypeError(`unsafe evidence path: ${artifact.path}`)
    if (!SHA256.test(artifact.digest)) throw new TypeError(`invalid artifact digest: ${artifact.path}`)
    if (!Number.isSafeInteger(artifact.size_bytes) || artifact.size_bytes < 0) {
      throw new TypeError(`invalid artifact size: ${artifact.path}`)
    }
    if (seen.has(safe)) throw new TypeError(`duplicate evidence path: ${safe}`)
    seen.add(safe)
    artifacts.push({
      path: safe,
      kind: artifact.kind,
      digest: artifact.digest,
      size_bytes: artifact.size_bytes,
    })
  }
  artifacts.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
  const body: UnknownRecord = {
    schema_version: MARKET_EVIDENCE_PACKAGE_VERSION,
    package_id: input.packageId,
    run_id: input.runId,
    receipt_digest: input.receiptDigest,
    artifacts,
    created_at: input.createdAt,
    retention: input.retention ?? { until: null, policy_ref: null },
    redaction: input.redaction ?? { status: 'not-reviewed', notes: null },
  }
  const packageDigest = canonicalDigest(body)
  const manifest: UnknownRecord = { ...body, package_digest: packageDigest }
  const shaped = validateMarketEvidencePackage(manifest)
  if (!shaped.ok) throw new TypeError(`market-evidence-package/v1 invalid: ${shaped.errors.slice(0, 5).join(', ')}`)
  return { manifest, digest: packageDigest, artifactPaths: artifacts.map((artifact) => artifact.path) }
}

/** Verify a saved package manifest's schema, digest and (optionally) files. */
export async function verifyEvidencePackage(
  manifestRaw: unknown,
  options: { root?: string; rejectUnregistered?: boolean } = {},
): Promise<{ ok: boolean; reasonCodes: string[]; errors: string[]; artifactPaths: string[] }> {
  const reasonCodes = new Set<string>()
  const errors: string[] = []
  const shaped = validateMarketEvidencePackage(manifestRaw)
  if (!shaped.ok) {
    reasonCodes.add(MARKET_REASON_CODES.MARKET_EVIDENCE_INCOMPLETE)
    return { ok: false, reasonCodes: [...reasonCodes], errors: shaped.errors.slice(0, 10), artifactPaths: [] }
  }
  const manifest = manifestRaw as UnknownRecord
  const body = { ...manifest }
  delete body.package_digest
  if (manifest.package_digest !== canonicalDigest(body)) {
    reasonCodes.add(MARKET_REASON_CODES.MARKET_EVIDENCE_DIGEST_MISMATCH)
    errors.push('package-digest-mismatch')
  }
  const artifacts = isArray(manifest.artifacts) ? manifest.artifacts : []
  const paths: string[] = []
  for (const raw of artifacts) {
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
      errors.push('artifact-not-object')
      reasonCodes.add(MARKET_REASON_CODES.MARKET_EVIDENCE_INCOMPLETE)
      continue
    }
    const artifact = raw as UnknownRecord
    const safe = safeRelativePath(artifact.path)
    if (safe === null) {
      reasonCodes.add(MARKET_REASON_CODES.MARKET_EVIDENCE_PATH_ESCAPE)
      errors.push(`unsafe-artifact-path:${String(artifact.path)}`)
      continue
    }
    paths.push(safe)
  }
  if (options.root !== undefined) {
    const rootAbs = resolve(options.root)
    for (const artifact of artifacts) {
      if (artifact === null || typeof artifact !== 'object' || Array.isArray(artifact)) continue
      const record = artifact as UnknownRecord
      const safe = safeRelativePath(record.path)
      if (safe === null) continue
      const described = await describeArtifact(rootAbs, safe, isNonEmptyString(record.kind) ? record.kind : 'unknown')
      if (!described.ok) {
        reasonCodes.add(described.reason)
        errors.push(described.detail)
        continue
      }
      if (described.artifact.digest !== record.digest) {
        reasonCodes.add(MARKET_REASON_CODES.MARKET_EVIDENCE_DIGEST_MISMATCH)
        errors.push(`artifact-digest-mismatch:${safe}`)
      }
      if (described.artifact.size_bytes !== record.size_bytes) {
        reasonCodes.add(MARKET_REASON_CODES.MARKET_EVIDENCE_DIGEST_MISMATCH)
        errors.push(`artifact-size-mismatch:${safe}`)
      }
    }
    if (options.rejectUnregistered === true) {
      const registered = new Set(paths)
      for (const found of await listFiles(rootAbs)) {
        if (found === 'package.json') continue
        if (!registered.has(found)) {
          reasonCodes.add(MARKET_REASON_CODES.MARKET_EVIDENCE_UNREGISTERED)
          errors.push(`unregistered-file:${found}`)
        }
      }
    }
  }
  return { ok: errors.length === 0, reasonCodes: [...reasonCodes], errors, artifactPaths: paths }
}

async function listFiles(root: string, prefix = ''): Promise<string[]> {
  const out: string[] = []
  const entries = await readdir(join(root, prefix), { withFileTypes: true })
  for (const entry of entries) {
    const rel = prefix === '' ? entry.name : `${prefix}/${entry.name}`
    if (entry.isDirectory()) out.push(...await listFiles(root, rel))
    else if (entry.isFile()) out.push(rel)
  }
  return out.sort()
}

/** Write a package manifest (and parent directories) as `package.json`. */
export async function writeEvidencePackage(root: string, manifest: UnknownRecord): Promise<string> {
  const target = join(resolve(root), 'package.json')
  await mkdir(dirname(target), { recursive: true })
  await writeFile(target, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
  return target
}
