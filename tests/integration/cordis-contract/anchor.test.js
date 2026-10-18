/**
 * `testbed-runtime-anchor/v2` generation and fail-closed verification.
 *
 * Positive cases are built from the real isolated install; every negative case
 * mutates exactly one trust input and asserts the stable rejection reason. No
 * fixture, live-profile path or app.asar entry can verify as a locked runtime.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import {
  ANCHOR_EVIDENCE_DIR,
  ANCHOR_PATH,
  buildApiCatalog,
  buildRuntimeAnchor,
  EVIDENCE_DIR,
  environmentSummary,
  readInstalledRuntime,
  REQUIRED_PACKAGES,
  RUNTIME_DIR,
  sha256Value,
  TESTBED_ROOT,
  writeEvidence,
} from './_runtime.js'
import {
  resolveRuntimeAnchorV2,
  runtimeAnchorV2Digest,
  verifyRuntimeAnchorV2,
} from '../../../src/worker/runtime.js'

const EXPECTED = {
  cordis: REQUIRED_PACKAGES['@deepseek-ai/cordis'],
  dsh: REQUIRED_PACKAGES['@deepseek-ai/dsh'],
}

async function buildVerifiedAnchor() {
  const runtime = await readInstalledRuntime()
  const cordis = await import(runtime.cordisEntryUrl)
  const catalog = buildApiCatalog(cordis, runtime.installed['@deepseek-ai/cordis'].package.version)
  const built = await buildRuntimeAnchor({
    catalogRef: { id: catalog.catalog.catalog_id, version: catalog.catalog.catalog_version, digest: catalog.digest },
  })
  return { ...built, runtime, catalog }
}

function mutate(anchor, changes = {}, { drop = [] } = {}) {
  const copy = structuredClone(anchor)
  Object.assign(copy, changes)
  for (const key of drop) delete copy[key]
  return copy
}

test('testbed-runtime-anchor/v2 verifies against the isolated locked install', async () => {
  const { anchor, anchorDigest, verified, runtime } = await buildVerifiedAnchor()
  assert.equal(anchor.schema_version, 'testbed-runtime-anchor/v2')
  assert.equal(anchor.package_name, '@deepseek-ai/cordis')
  assert.equal(anchor.package_version, EXPECTED.cordis)
  assert.equal(anchor.dsh_version, EXPECTED.dsh)
  assert.equal(anchor.runtime_kind, 'locked-runtime')
  assert.equal(anchor.node_version, process.version)
  assert.equal(anchor.platform, process.platform)
  assert.equal(anchor.arch, process.arch)
  assert.match(anchor.entry, /^file:\/\//)
  assert.equal(anchor.entry.toLowerCase().includes('app.asar'), false)
  assert.equal(anchor.entry, pathToFileURL(verified.verification.entry_path).href)
  assert.match(anchor.entry_digest, /^sha256:[0-9a-f]{64}$/)
  assert.equal(anchor.lockfile.path, 'pnpm-lock.yaml')
  assert.equal(anchor.lockfile.digest, runtime.lockfileDigest)
  assert.equal(anchor.integrity, runtime.installed['@deepseek-ai/cordis'].integrity, 'integrity must come from the lockfile')
  assert.equal(verified.status, 'available')
  assert.equal(verified.reason, null)
  assert.equal(verified.verification.anchor_digest, anchorDigest)
  assert.equal(verified.verification.entry_digest, anchor.entry_digest)
  assert.equal(verified.verification.lockfile_digest, anchor.lockfile.digest)
  assert.equal(verified.verification.package_observed?.version, EXPECTED.cordis)
  assert.equal(runtimeAnchorV2Digest(anchor), anchorDigest)

  const env = environmentSummary()
  await writeEvidence('runtime-anchor-verification.v1.json', {
    schema_version: 'runtime-anchor-verification/v1',
    status: 'pass',
    anchor_digest: anchorDigest,
    runtime_anchor: anchor,
    checks: verified.verification,
    environment: env,
    environment_digest: sha256Value(env),
    catalog_digest: anchor.catalog_ref.digest,
    lockfile_digest: anchor.lockfile.digest,
    suite_binding: {
      suite_id: 'cordis-runtime-contract',
      suite_version: '1.0.0',
      results_path: 'evidence/cordis-contract-results.v1.json',
    },
  })
})

test('fixture and app.asar runtimes are rejected before any market claim', async (t) => {
  const { anchor } = await buildVerifiedAnchor()
  await t.test('test-fixture runtime_kind', async () => {
    const fixture = mutate(anchor, { runtime_kind: 'test-fixture' })
    const result = await verifyRuntimeAnchorV2(fixture, { baseDir: ANCHOR_EVIDENCE_DIR })
    assert.equal(result.status, 'unavailable')
    assert.equal(result.reason, 'runtime-anchor-fixture-rejected')
  })
  await t.test('app.asar entry', async () => {
    const asarEntry = mutate(anchor, {
      entry: pathToFileURL(join(TESTBED_ROOT, 'resources', 'app.asar', 'node_modules', '@deepseek-ai', 'cordis', 'lib', 'index.js')).href,
    })
    const result = await verifyRuntimeAnchorV2(asarEntry, { baseDir: ANCHOR_EVIDENCE_DIR })
    assert.equal(result.status, 'unavailable')
    assert.equal(result.reason, 'runtime-anchor-app-asar-rejected')
  })
  await t.test('non-file entry scheme', async () => {
    const remote = mutate(anchor, { entry: 'https://example.invalid/cordis/lib/index.js' })
    const result = await verifyRuntimeAnchorV2(remote, { baseDir: ANCHOR_EVIDENCE_DIR })
    assert.equal(result.status, 'unavailable')
    assert.equal(result.reason, 'runtime-anchor-invalid')
  })
})

test('floating versions, tags and ranges are rejected', async (t) => {
  const { anchor } = await buildVerifiedAnchor()
  for (const spec of ['latest', 'next', '^4.0.5', '~4.0.5', '>=4.0.5', '4.x', '*']) {
    await t.test(`package_version ${JSON.stringify(spec)}`, async () => {
      const result = await verifyRuntimeAnchorV2(mutate(anchor, { package_version: spec }), { baseDir: ANCHOR_EVIDENCE_DIR })
      assert.equal(result.status, 'unavailable')
      assert.equal(result.reason, 'runtime-package-unlockable')
    })
  }
  const dshTag = mutate(anchor, { dsh_version: 'next' })
  assert.equal((await verifyRuntimeAnchorV2(dshTag, { baseDir: ANCHOR_EVIDENCE_DIR })).reason, 'runtime-anchor-invalid')
})

test('integrity, digest, lockfile and entry mismatches fail closed', async (t) => {
  const { anchor } = await buildVerifiedAnchor()
  const cases = [
    ['entry missing', mutate(anchor, { entry: pathToFileURL(join(RUNTIME_DIR, 'no-such-cordis-entry.js')).href }), 'runtime-entry-missing'],
    ['entry digest mismatch', mutate(anchor, { entry_digest: 'sha256:' + '0'.repeat(64) }), 'runtime-entry-digest-mismatch'],
    ['lockfile digest mismatch', mutate(anchor, { lockfile: { ...anchor.lockfile, digest: 'sha256:' + '1'.repeat(64) } }), 'runtime-lockfile-mismatch'],
    ['declared version mismatch', mutate(anchor, { package_version: '4.0.4' }), 'runtime-version-mismatch'],
    ['declared node mismatch', mutate(anchor, { node_version: 'v0.0.0' }), 'runtime-environment-mismatch'],
    ['declared platform mismatch', mutate(anchor, { platform: 'plan9' }), 'runtime-environment-mismatch'],
    ['unknown field', mutate(anchor, { surprise: true }), 'runtime-anchor-invalid'],
    ['missing lockfile field', mutate(anchor, {}, { drop: ['lockfile'] }), 'runtime-anchor-invalid'],
    ['missing entry digest', mutate(anchor, {}, { drop: ['entry_digest'] }), 'runtime-anchor-invalid'],
    ['bad catalog digest', mutate(anchor, { catalog_ref: { ...anchor.catalog_ref, digest: 'md5:abc' } }), 'runtime-anchor-invalid'],
    ['v1 schema', mutate(anchor, { schema_version: 'testbed-runtime-anchor/v1' }), 'runtime-anchor-version-unknown'],
  ]
  for (const [label, candidate, expectedReason] of cases) {
    await t.test(label, async () => {
      const result = await verifyRuntimeAnchorV2(candidate, { baseDir: ANCHOR_EVIDENCE_DIR })
      assert.equal(result.status, 'unavailable', label)
      assert.equal(result.reason, expectedReason, label)
    })
  }
  await t.test('integrity vs expected requirement', async () => {
    const result = await verifyRuntimeAnchorV2(anchor, {
      baseDir: ANCHOR_EVIDENCE_DIR,
      expectedIntegrity: 'sha512-' + 'A'.repeat(86) + '==',
    })
    assert.equal(result.status, 'unavailable')
    assert.equal(result.reason, 'runtime-integrity-mismatch')
  })
})

test('resolveRuntimeAnchorV2 honours an injected anchor and DSH_TESTBED_RUNTIME_ANCHOR', async () => {
  const { anchor, anchorDigest } = await buildVerifiedAnchor()
  const injected = await resolveRuntimeAnchorV2({ injection: anchor, baseDir: ANCHOR_EVIDENCE_DIR, env: {} })
  assert.equal(injected.status, 'available')
  assert.equal(injected.source, 'injection')
  assert.equal(injected.verification.anchor_digest, anchorDigest)

  const dir = await mkdtemp(join(tmpdir(), 'testbed-anchor-v2-'))
  try {
    const portable = mutate(anchor, {
      lockfile: { path: join(RUNTIME_DIR, 'pnpm-lock.yaml'), digest: anchor.lockfile.digest },
    })
    const anchorPath = join(dir, 'anchor.json')
    await writeFile(anchorPath, JSON.stringify(portable, null, 2), 'utf8')
    const resolved = await resolveRuntimeAnchorV2({
      env: { DSH_TESTBED_RUNTIME_ANCHOR: anchorPath },
      baseDir: process.cwd(),
    })
    assert.equal(resolved.status, 'available')
    assert.equal(resolved.source, 'env-anchor')
    assert.equal(resolved.anchor.entry, anchor.entry)

    const missing = await resolveRuntimeAnchorV2({ env: {}, baseDir: dir })
    assert.equal(missing.status, 'unavailable')
    assert.equal(missing.reason, 'runtime-anchor-missing')

    const invalid = await resolveRuntimeAnchorV2({ env: { DSH_TESTBED_RUNTIME_ANCHOR: '{not json' }, baseDir: dir })
    assert.equal(invalid.status, 'unavailable')
    assert.equal(invalid.reason, 'runtime-anchor-read-failed')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('the committed evidence anchor, when present, matches a fresh build', async () => {
  const { anchor } = await buildVerifiedAnchor()
  let committed
  try {
    committed = JSON.parse(await readFile(ANCHOR_PATH, 'utf8'))
  } catch {
    // First run: the contract test or this run writes it; nothing stale to compare.
    return
  }
  assert.equal(runtimeAnchorV2Digest(committed), runtimeAnchorV2Digest(anchor))
})
