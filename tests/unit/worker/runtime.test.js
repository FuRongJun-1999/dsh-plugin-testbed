/** Locked runtime anchor resolution tests (no hard-coded host paths). */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import {
  MAX_ANCHOR_BYTES,
  RUNTIME_ANCHOR_VERSION,
  makeRuntimeAnchor,
  resolveRuntimeAnchor,
  runtimeProvenanceForReceipt,
} from '../../../src/worker/runtime.js'

const STUB = pathToFileURL(fileURLToPath(new URL('../../fixtures/fake-cordis-stub.mjs', import.meta.url))).href
const COMMIT = '86a402200d95fecef4529d969836f1fe13c6cb0d'
const WORKER_SRC = fileURLToPath(new URL('../../../src/worker/', import.meta.url))

function tmpDir(t) {
  const dir = mkdtempSync(join(tmpdir(), 'testbed-runtime-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function writeStub(dir, { version = null, entryName = 'cordis-entry.mjs' } = {}) {
  const entryPath = join(dir, entryName)
  writeFileSync(entryPath, 'export class Context {}\n')
  if (version !== null) {
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: '@deepseek-ai/cordis', version }))
  }
  return { entryPath, entryUrl: pathToFileURL(entryPath).href }
}

test('injection resolves an existing entry and observes the package version', async (t) => {
  const dir = tmpDir(t)
  const { entryUrl } = writeStub(dir, { version: '4.0.5-alpha.2' })
  const resolved = await resolveRuntimeAnchor({
    injection: makeRuntimeAnchor({
      cordis_entry: entryUrl,
      cordis_version: '4.0.5-alpha.2',
      dsh_commit: COMMIT,
      runtime_kind: 'locked-runtime',
    }),
    env: {},
    resolveInstalled: false,
  })
  assert.equal(resolved.status, 'available')
  assert.equal(resolved.reason, null)
  assert.equal(resolved.provenance.source, 'injection')
  assert.equal(resolved.provenance.cordis_version, '4.0.5-alpha.2')
  assert.equal(resolved.provenance.cordis_version_observed, '4.0.5-alpha.2')
  assert.equal(resolved.provenance.cordis_version_verified, true)
  assert.equal(resolved.provenance.dsh_commit, COMMIT)
  assert.equal(resolved.provenance.dsh_commit_verified, false, 'a built runtime cannot verify a commit')
  assert.ok(resolved.limitations.includes('dsh-commit-injected-unverified'))
  assert.match(resolved.provenance.environment_fingerprint, /^sha256:[0-9a-f]{64}$/)
})

test('an anchor file injected by the locked runner is honoured and binds relative entries', async (t) => {
  const dir = tmpDir(t)
  const { entryPath } = writeStub(dir, { version: '4.0.5-alpha.2' })
  const anchorPath = join(dir, 'anchor.json')
  writeFileSync(anchorPath, JSON.stringify({
    schema_version: RUNTIME_ANCHOR_VERSION,
    cordis_entry: entryPath,
    cordis_version: '4.0.5-alpha.2',
    runtime_kind: 'locked-runtime',
  }))
  const resolved = await resolveRuntimeAnchor({
    env: { DSH_TESTBED_RUNTIME_ANCHOR: anchorPath },
    resolveInstalled: false,
  })
  assert.equal(resolved.status, 'available')
  assert.equal(resolved.provenance.source, 'env-anchor')
  assert.equal(resolved.provenance.runtime_kind, 'locked-runtime')
  assert.equal(resolved.provenance.cordis_version_verified, true)
})

test('inline JSON anchor and env-entry injection both resolve', async (t) => {
  const dir = tmpDir(t)
  const { entryUrl } = writeStub(dir, { version: '4.0.5-alpha.2' })
  const inline = await resolveRuntimeAnchor({
    env: {
      DSH_TESTBED_RUNTIME_ANCHOR: JSON.stringify(makeRuntimeAnchor({
        cordis_entry: entryUrl,
        runtime_kind: 'locked-runtime',
      })),
    },
    resolveInstalled: false,
  })
  assert.equal(inline.status, 'available')
  assert.equal(inline.provenance.source, 'env-anchor')

  const envEntry = await resolveRuntimeAnchor({
    env: { DSH_TESTBED_CORDIS_ENTRY: entryUrl, DSH_TESTBED_CORDIS_VERSION: '4.0.5-alpha.2' },
    resolveInstalled: false,
  })
  assert.equal(envEntry.status, 'available')
  assert.equal(envEntry.provenance.source, 'env-entry')
  assert.equal(envEntry.provenance.cordis_version_verified, true)
})

test('missing runtime is explicit: no anchor, missing entry, or version mismatch', async (t) => {
  const dir = tmpDir(t)
  const missing = await resolveRuntimeAnchor({ env: {}, resolveInstalled: false })
  assert.equal(missing.status, 'unavailable')
  assert.equal(missing.reason, 'runtime-anchor-missing')
  assert.equal(missing.provenance.cordis_version, null)
  assert.equal(missing.provenance.dsh_commit, null)
  assert.match(missing.provenance.environment_fingerprint, /^sha256:[0-9a-f]{64}$/)

  const missingEntry = await resolveRuntimeAnchor({
    injection: makeRuntimeAnchor({ cordis_entry: pathToFileURL(join(dir, 'nope.mjs')).href }),
    env: {},
    resolveInstalled: false,
  })
  assert.equal(missingEntry.status, 'unavailable')
  assert.equal(missingEntry.reason, 'runtime-entry-missing')

  const { entryUrl } = writeStub(dir, { version: '4.0.5-alpha.2' })
  const mismatch = await resolveRuntimeAnchor({
    injection: makeRuntimeAnchor({ cordis_entry: entryUrl, cordis_version: '9.9.9' }),
    env: {},
    resolveInstalled: false,
  })
  assert.equal(mismatch.status, 'unavailable')
  assert.equal(mismatch.reason, 'runtime-version-mismatch')
  assert.ok(mismatch.limitations.some((item) => item.startsWith('runtime-version-observed:')))
})

test('invalid descriptors and locked-environment mismatches fail closed', async (t) => {
  const dir = tmpDir(t)
  const { entryUrl } = writeStub(dir)
  const cases = [
    [{ ...makeRuntimeAnchor({ cordis_entry: entryUrl }), schema_version: 'testbed-runtime-anchor/v2' }, 'runtime-anchor-version-unknown'],
    [{ ...makeRuntimeAnchor({ cordis_entry: entryUrl }), extra: true }, 'runtime-anchor-unknown-field:extra'],
    [{ ...makeRuntimeAnchor({ cordis_entry: entryUrl }), cordis_version: 'latest' }, 'runtime-anchor-version-invalid'],
    [{ ...makeRuntimeAnchor({ cordis_entry: entryUrl }), dsh_commit: 'abc' }, 'runtime-anchor-commit-invalid'],
    [{ ...makeRuntimeAnchor({ cordis_entry: entryUrl }), runtime_kind: 'sandbox' }, 'runtime-anchor-kind-invalid'],
    [{ ...makeRuntimeAnchor({ cordis_entry: entryUrl }), node_version: 'v0.0.0' }, 'runtime-environment-mismatch'],
    [{ ...makeRuntimeAnchor({ cordis_entry: entryUrl }), platform: 'not-a-platform' }, 'runtime-environment-mismatch'],
  ]
  for (const [descriptor, expected] of cases) {
    const resolved = await resolveRuntimeAnchor({ injection: descriptor, env: {}, resolveInstalled: false })
    assert.equal(resolved.status, 'unavailable', JSON.stringify(descriptor))
    assert.equal(resolved.reason, expected)
  }

  const badEntry = await resolveRuntimeAnchor({
    injection: makeRuntimeAnchor({ cordis_entry: 'bad\u0000path' }),
    env: {},
    resolveInstalled: false,
  })
  assert.equal(badEntry.status, 'unavailable')
  assert.equal(badEntry.reason, 'runtime-anchor-invalid')

  const relativeEntry = await resolveRuntimeAnchor({
    injection: makeRuntimeAnchor({ cordis_entry: 'relative/no-scheme.mjs' }),
    env: {},
    resolveInstalled: false,
  })
  assert.equal(relativeEntry.status, 'unavailable')
  assert.equal(relativeEntry.reason, 'runtime-entry-missing', 'relative entries resolve against baseDir but must still exist')
})

test('oversized anchor files are rejected', async (t) => {
  const dir = tmpDir(t)
  const anchorPath = join(dir, 'big.json')
  writeFileSync(anchorPath, ' '.repeat(MAX_ANCHOR_BYTES + 1))
  const resolved = await resolveRuntimeAnchor({
    env: { DSH_TESTBED_RUNTIME_ANCHOR: anchorPath },
    resolveInstalled: false,
  })
  assert.equal(resolved.status, 'unavailable')
  assert.equal(resolved.reason, 'runtime-anchor-read-failed')
})

test('environment fingerprint is stable per environment and changes with runtime version', async (t) => {
  const a = await resolveRuntimeAnchor({ env: {}, resolveInstalled: false })
  const b = await resolveRuntimeAnchor({ env: {}, resolveInstalled: false })
  assert.equal(a.provenance.environment_fingerprint, b.provenance.environment_fingerprint)

  const dir = tmpDir(t)
  const v1Dir = join(dir, 'v1')
  const v2Dir = join(dir, 'v2')
  mkdirSync(v1Dir)
  mkdirSync(v2Dir)
  const v1 = writeStub(v1Dir, { version: '1.0.0' })
  const v2 = writeStub(v2Dir, { version: '2.0.0' })
  const first = await resolveRuntimeAnchor({
    injection: makeRuntimeAnchor({ cordis_entry: v1.entryUrl, runtime_kind: 'locked-runtime' }),
    env: {},
    resolveInstalled: false,
  })
  const second = await resolveRuntimeAnchor({
    injection: makeRuntimeAnchor({ cordis_entry: v2.entryUrl, runtime_kind: 'locked-runtime' }),
    env: {},
    resolveInstalled: false,
  })
  assert.notEqual(first.provenance.environment_fingerprint, second.provenance.environment_fingerprint)
})

test('runtimeProvenanceForReceipt keeps only receipt/v1 provenance fields', async (t) => {
  const dir = tmpDir(t)
  const versionedDir = join(dir, 'versioned')
  mkdirSync(versionedDir)
  const { entryUrl } = writeStub(versionedDir, { version: '4.0.5-alpha.2' })
  const resolved = await resolveRuntimeAnchor({
    injection: makeRuntimeAnchor({
      cordis_entry: entryUrl,
      dsh_commit: COMMIT,
      runtime_kind: 'locked-runtime',
    }),
    env: {},
    resolveInstalled: false,
  })
  const provenance = runtimeProvenanceForReceipt(resolved)
  assert.deepEqual(Object.keys(provenance).sort(), [
    'cordis_version', 'dsh_commit', 'environment_fingerprint', 'isolation',
    'node_version', 'os_arch', 'os_platform', 'redaction_status', 'worker_ref',
  ])
  assert.equal(provenance.cordis_version, '4.0.5-alpha.2')
  assert.equal(provenance.dsh_commit, COMMIT)
  assert.equal(provenance.isolation, 'L1-subprocess')
})

test('worker sources contain no hard-coded host runtime path', () => {
  const files = readdirSync(WORKER_SRC).filter((name) => name.endsWith('.js'))
  assert.ok(files.length >= 5)
  for (const file of files) {
    const source = readFileSync(join(WORKER_SRC, file), 'utf8')
    assert.equal(/deepseek-harness/i.test(source), false, `${file} must not hard-code a DSH checkout path`)
    assert.equal(/file:\/\/\/[A-Za-z]:\//.test(source), false, `${file} must not hard-code a Windows file URL`)
    assert.equal(/[A-Za-z]:\\\\deepseek/i.test(source), false, `${file} must not hard-code a Windows checkout path`)
  }
})
