/**
 * Install-layer evidence for the isolated Cordis/DSH runtime anchor.
 *
 * This test proves the lockfile is the integrity source for the anchor:
 * exact versions in `cordis-runtime/package.json`, matching lockfile importer
 * specifiers and resolution integrity, no lifecycle scripts, no Electron /
 * app.asar dependency, and an install location outside any live DSH profile.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { isAbsolute, join, relative, resolve, sep } from 'node:path'
import { homedir } from 'node:os'
import {
  buildApiCatalog,
  buildRuntimeAnchor,
  environmentSummary,
  lockfileIntegrity,
  readInstalledRuntime,
  REQUIRED_PACKAGES,
  REQUIRED_PEERS,
  RUNTIME_DIR,
  sha256File,
  sha256Value,
  TESTBED_ROOT,
  writeEvidence,
} from './_runtime.js'

const PUBLISHED_INTEGRITY = Object.freeze({
  '@deepseek-ai/cordis@4.0.5': 'sha512-Sktq5axy0owk9PdnivBRNOJjHEVEibCt0+TDDZcv0+UH2KS1M910fX4kn5y45YFsrpZIi1mJf/1s5VzywMUnyg==',
  '@deepseek-ai/dsh@0.2.1-rc.2': 'sha512-tvY+yhfKRifthbqPe/OK0AYxM5ZkvqfYq/jMYgJcEUxiRRL1Vwra3Ti5TB6AXgSWQdiPHYh/Vp6SJa9yHwMNuw==',
})
const LOCKED_NODE = 'v24.21.0'

function isInside(parent, child) {
  const rel = relative(parent, child)
  return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel)
}

test('cordis-runtime is an isolated, exactly locked install (never a live profile)', async () => {
  const runtime = await readInstalledRuntime()
  const { manifest } = runtime

  // 1. Exact dependency pins — no ranges, tags, or workspace links.
  for (const [name, version] of Object.entries({ ...REQUIRED_PACKAGES, ...REQUIRED_PEERS })) {
    assert.equal(manifest.dependencies[name], version, `${name} must be exactly pinned`)
  }
  for (const [name, spec] of Object.entries(manifest.dependencies)) {
    assert.match(spec, /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/, `${name} must not use a floating specifier`)
  }
  assert.equal(manifest.engines?.node, LOCKED_NODE.replace(/^v/, ''), 'Node is part of the locked runtime matrix')
  assert.equal(process.version, LOCKED_NODE, `this evidence is only valid for the locked Node ${LOCKED_NODE}; re-anchor for a different Node`)

  // 2. Install location isolation: under this repo's cordis-runtime, not a live profile.
  const runtimePath = resolve(RUNTIME_DIR)
  assert.equal(resolve(runtimePath).startsWith(resolve(TESTBED_ROOT) + sep), true)
  assert.equal(runtimePath.includes(`${sep}.dsh${sep}profiles${sep}`), false, 'must not touch a live DSH profile')
  assert.equal(runtimePath.includes('app.asar'), false)
  const home = homedir()
  assert.equal(isInside(resolve(home, '.dsh', 'profiles'), runtimePath), false, 'must not be installed into the live profile tree')

  // 3. Lockfile integrity: importer specifiers and resolved SRI for every required package.
  assert.match(runtime.lockfileText, /^lockfileVersion: '9\.0'$/m)
  for (const [name, version] of Object.entries({ ...REQUIRED_PACKAGES, ...REQUIRED_PEERS })) {
    const importerBlock = new RegExp(`^      '${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}':\\r?\\n        specifier: [^\\n]+\\r?\\n        version: `, 'm')
    assert.match(runtime.lockfileText, importerBlock, `lockfile importer must pin ${name}`)
    const integrity = lockfileIntegrity(runtime.lockfileText, name, version)
    assert.match(integrity ?? '', /^sha(?:256|384|512)-/, `lockfile must record integrity for ${name}@${version}`)
    assert.equal(integrity, runtime.installed[name].integrity)
  }
  for (const [packageKey, published] of Object.entries(PUBLISHED_INTEGRITY)) {
    const [name, version] = packageKey.split(/@(?=\d)/)
    assert.equal(lockfileIntegrity(runtime.lockfileText, name, version), published, `${packageKey} integrity must match the published registry SRI`)
  }

  // 4. Lifecycle scripts are disabled for this supply chain.
  const workspace = await readFile(join(RUNTIME_DIR, 'pnpm-workspace.yaml'), 'utf8')
  assert.match(workspace, /^ignoreScripts: true$/m)
  for (const packageName of ['@deepseek-ai/dsh-subprocess-local', '@google/genai', 'koffi', 'node-pty', 'protobufjs']) {
    assert.match(workspace, new RegExp(`^  '?${packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}'?: false$`, 'm'), `${packageName} build scripts must be explicitly denied`)
  }

  // 5. No Electron / app.asar package can be part of the runtime.
  assert.equal(/\belectron\b/i.test(runtime.lockfileText), false, 'Electron must not be a runtime dependency')
  assert.equal(/app\.asar/i.test(runtime.lockfileText), false, 'app.asar must not appear in the lockfile')
  const violated = []
  for (const name of Object.keys({ ...REQUIRED_PACKAGES, ...REQUIRED_PEERS })) {
    const packageJson = runtime.installed[name].package
    if (/electron/i.test(packageJson.name)) violated.push(name)
  }
  assert.deepEqual(violated, [])

  // 6. The anchor must verify from this install, binding entry/lockfile/digests.
  const cordisModule = await import(runtime.cordisEntryUrl)
  const catalog = buildApiCatalog(cordisModule, REQUIRED_PACKAGES['@deepseek-ai/cordis'])
  const catalogRef = { id: catalog.catalog.catalog_id, version: catalog.catalog.catalog_version, digest: catalog.digest }
  const anchorBuild = await buildRuntimeAnchor({ catalogRef })
  assert.equal(anchorBuild.verified.status, 'available')
  assert.equal(anchorBuild.anchor.integrity, PUBLISHED_INTEGRITY['@deepseek-ai/cordis@4.0.5'])
  assert.equal(anchorBuild.anchor.dsh_version, REQUIRED_PACKAGES['@deepseek-ai/dsh'])
  assert.equal(anchorBuild.anchor.package_version, REQUIRED_PACKAGES['@deepseek-ai/cordis'])
  assert.equal(anchorBuild.anchor.lockfile.digest, runtime.lockfileDigest)
  assert.equal(anchorBuild.anchor.entry_digest, await sha256File(runtime.cordisEntry))
  assert.equal(isInside(resolve(TESTBED_ROOT), resolve(anchorBuild.verified.verification.entry_path)), true)
  assert.equal(anchorBuild.verified.verification.entry_path.includes('app.asar'), false)

  const dshPackage = runtime.installed['@deepseek-ai/dsh'].package
  assert.equal(dshPackage.name, '@deepseek-ai/dsh')
  assert.equal(dshPackage.version, REQUIRED_PACKAGES['@deepseek-ai/dsh'])
  const hostRunnerPackage = runtime.installed['@deepseek-ai/dsh-cordis-host-runner'].package
  assert.equal(hostRunnerPackage.version, REQUIRED_PACKAGES['@deepseek-ai/dsh-cordis-host-runner'])

  await writeEvidence('runtime-install-evidence.v1.json', {
    schema_version: 'runtime-install-evidence/v1',
    status: 'pass',
    isolated_root: 'cordis-runtime',
    no_live_profile_mutation: true,
    package_manager: 'pnpm',
    lockfile: { path: 'pnpm-lock.yaml', digest: runtime.lockfileDigest, lockfile_version: '9.0' },
    pinned: { ...REQUIRED_PACKAGES, ...REQUIRED_PEERS },
    integrity: Object.fromEntries(
      Object.entries({ ...REQUIRED_PACKAGES, ...REQUIRED_PEERS })
        .map(([name, version]) => [`${name}@${version}`, runtime.installed[name].integrity]),
    ),
    published_integrity_cross_check: PUBLISHED_INTEGRITY,
    lifecycle_scripts: 'disabled (pnpm-workspace.yaml ignoreScripts:true + allowBuilds:false)',
    electron_dependency: false,
    app_asar_dependency: false,
    entry: {
      path: runtime.cordisEntry,
      digest: anchorBuild.anchor.entry_digest,
      package: '@deepseek-ai/cordis',
      version: REQUIRED_PACKAGES['@deepseek-ai/cordis'],
    },
    anchor: { path: 'cordis-runtime/runtime-anchor.json', digest: anchorBuild.anchorDigest },
    catalog_digest: anchorBuild.anchor.catalog_ref.digest,
    environment: environmentSummary(),
    environment_digest: sha256Value(environmentSummary()),
  })
})
