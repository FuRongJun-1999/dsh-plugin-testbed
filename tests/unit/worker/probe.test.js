/**
 * Worker two-phase capability probe tests.
 *
 * The runtime here is an explicit TEST DOUBLE (`fake-cordis-stub.mjs`) injected
 * with `runtime_kind: 'test-fixture'`; the probe must report it as a non-locked
 * injected runtime with an unverified version. Real-runtime absence is covered
 * separately and must yield explicit unknown/absent, never `present`.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import {
  CAPABILITY_PROBE_VERSION,
  CAPABILITY_SNAPSHOT_VERSION,
  caseRecordsFromSnapshot,
  probeCapabilities,
  probeWorkerCapabilities,
  workerFingerprint,
} from '../../../src/worker/probe.js'
import { findForbiddenAuthorityKeys } from '../../../src/worker/observe.js'
import { CAPABILITY_CLAIM, CAPABILITY_OBSERVED } from '../../../src/protocol/enums.js'

const STUB_URL = pathToFileURL(fileURLToPath(new URL('../../fixtures/fake-cordis-stub.mjs', import.meta.url))).href
const DECLARED_PUT = pathToFileURL(fileURLToPath(new URL('../../fixtures/put-declared.mjs', import.meta.url))).href
const FAILING_PUT = pathToFileURL(fileURLToPath(new URL('../../fixtures/put-failing.js', import.meta.url))).href
const PROBE_TIME = '2026-01-01T00:00:00.000Z'

function fixtureRuntime(overrides = {}) {
  return {
    cordis_entry: STUB_URL,
    cordis_version: '0.0.0-fixture',
    runtime_kind: 'test-fixture',
    ...overrides,
  }
}

function tmpDir(t) {
  const dir = mkdtempSync(join(tmpdir(), 'testbed-probe-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function assertNoAuthoritySnapshot(snapshot) {
  assert.deepEqual(findForbiddenAuthorityKeys(snapshot), [], 'worker snapshot must not carry authority fields')
  assert.equal(findForbiddenAuthorityKeys(snapshot).includes('verification'), false)
  for (const record of snapshot.cases) {
    assert.equal(Object.hasOwn(record, 'verification'), false)
    assert.equal(Object.hasOwn(record, 'verdict'), false)
    assert.equal(CAPABILITY_CLAIM.includes(record.claim), true)
    assert.equal(CAPABILITY_OBSERVED.includes(record.observed), true)
  }
}

test('phase 1 preflight records runtime, host limits and credential state', async () => {
  const result = await probeWorkerCapabilities({
    cases: [{ test_id: 'case.echo', probe: { op: 'echo' } }],
    runtime: fixtureRuntime(),
    env: {},
    environmentAudit: { credential_name_count: 1, removed_count: 3 },
    probe_time: PROBE_TIME,
  })
  assert.equal(result.ok, true)
  const snapshot = result.snapshot
  assertNoAuthoritySnapshot(snapshot)
  assert.equal(snapshot.snapshot_version, CAPABILITY_SNAPSHOT_VERSION)
  assert.equal(snapshot.source, 'worker')
  assert.equal(snapshot.probe_version, CAPABILITY_PROBE_VERSION)
  assert.equal(snapshot.phase, 'env', 'no PUT supplied → only the environment phase ran')
  assert.equal(snapshot.probe_time, PROBE_TIME)
  assert.equal(snapshot.probe_time_source, 'caller')
  assert.match(snapshot.environment_fingerprint, /^sha256:[0-9a-f]{64}$/)
  assert.match(snapshot.worker_fingerprint, /^sha256:[0-9a-f]{64}$/)
  assert.equal(snapshot.worker_fingerprint, workerFingerprint())
  assert.equal(snapshot.runtime.status, 'available')
  assert.equal(snapshot.runtime.runtime_kind, 'test-fixture')
  assert.equal(snapshot.runtime.cordis_version_verified, false)

  const byKey = Object.fromEntries(snapshot.phases.env.records.map((record) => [record.capability_key, record]))
  assert.equal(byKey['host:cordis-runtime'].claim, 'declared')
  assert.equal(byKey['host:cordis-runtime'].observed, 'present')
  assert.equal(byKey['host:cordis-import'].observed, 'present', 'preflight really imports the runtime')
  assert.equal(byKey['host:host-services'].observed, 'unknown',
    'the known-service catalog is not exhaustive, so an empty result is unknown')
  assert.equal(byKey['host:node-runtime'].observed, 'present')
  assert.equal(byKey['host:os'].observed, 'present')
  assert.equal(byKey['host:network-enforcement'].observed, 'unknown', 'L1 cannot enforce network')
  assert.equal(byKey['host:filesystem-enforcement'].observed, 'unknown')
  assert.equal(byKey['host:resource-limits'].observed, 'unknown')
  assert.equal(byKey['host:temp-dir'].observed, 'present')
  assert.equal(byKey['host:ambient-credentials'].observed, 'absent')
  assert.ok(byKey['host:ambient-credentials'].limitations.includes('ambient-credentials-removed-before-probe'))
  assert.equal(byKey['host:worker-entry'].observed, 'present')
  assert.ok(snapshot.limitations.includes('l1-fault-isolation-not-a-security-boundary'))
  assert.ok(snapshot.limitations.includes('ambient-credentials-removed-before-probe'))
})

test('phase 2 loads the PUT, separates declarations from measurements, and disposes', async () => {
  const result = await probeWorkerCapabilities({
    cases: [
      { test_id: 'case.echo', probe: { op: 'echo' } },
      { test_id: 'case.load-put', probe: { op: 'load-put' } },
      { test_id: 'case.tool', tool: { manifest: { requires: ['target:plugin', 'host:event-loop'] } } },
    ],
    put: { entry: DECLARED_PUT },
    runtime: fixtureRuntime(),
    env: {},
    probe_time: PROBE_TIME,
  })
  assert.equal(result.ok, true)
  const snapshot = result.snapshot
  assertNoAuthoritySnapshot(snapshot)
  assert.equal(snapshot.phase, 'put')
  assert.match(snapshot.put_digest, /^sha256:[0-9a-f]{64}$/)
  assert.deepEqual(snapshot.declarations.requires, ['target:plugin', 'host:event-loop'])
  assert.deepEqual(snapshot.declarations.capabilities, ['effect', 'service:example'])

  const putRecords = Object.fromEntries(snapshot.phases.put.records.map((record) => [record.capability_key, record]))
  assert.equal(putRecords['put:artifact-digest'].observed, 'present')
  assert.equal(putRecords['put:plugin-shape'].observed, 'present')
  assert.equal(putRecords['put:cordis-context'].observed, 'present')
  assert.equal(putRecords['put:apply'].observed, 'present')
  assert.equal(putRecords['put:effect-registration'].claim, 'declared')
  assert.equal(putRecords['put:effect-registration'].observed, 'present')
  assert.equal(putRecords['put:lifecycle-dispose'].observed, 'present')
  assert.equal(putRecords['put:declared:service:example'].claim, 'declared')
  assert.equal(putRecords['put:declared:service:example'].observed, 'unknown',
    'an undefined measurement stays unknown, never absent')
  assert.equal(snapshot.phases.put.state_after_load, 'ACTIVE')
  assert.equal(snapshot.phases.put.state_after_dispose, 'DISPOSED')
  assert.equal(snapshot.phases.put.effects_count, 2)
  assert.equal(snapshot.phases.put.put_state, 'put-worker-declared: loaded')

  const cases = Object.fromEntries(snapshot.cases.map((record) => [record.test_id, record]))
  assert.equal(cases['case.echo'].claim, 'declared')
  assert.equal(cases['case.echo'].observed, 'present')
  assert.equal(cases['case.load-put'].observed, 'present')
  assert.equal(cases['case.tool'].observed, 'present', 'worker-side runner capability is present')
  const target = cases['case.tool'].capabilities.find((record) => record.capability_key === 'target:plugin')
  assert.equal(target.claim, 'declared')
  assert.equal(target.observed, 'unknown', 'target capability is never measured by the worker')
  assert.equal(target.external, true)
  assert.ok(cases['case.tool'].limitations.includes('target-capability-not-observed-by-worker'))
  for (const record of snapshot.cases) {
    assert.equal(record.put_digest, snapshot.put_digest)
    assert.equal(record.environment_fingerprint, snapshot.environment_fingerprint)
    assert.equal(record.worker_fingerprint, snapshot.worker_fingerprint)
  }
})

test('syntax-error and non-plugin PUTs are measured as absent, never present', async () => {
  const syntaxPut = pathToFileURL(fileURLToPath(new URL('../../fixtures/put-syntax-error.mjs', import.meta.url))).href
  const nonPluginPut = pathToFileURL(fileURLToPath(new URL('../../fixtures/put-not-plugin.mjs', import.meta.url))).href
  const syntax = await probeWorkerCapabilities({
    cases: [{ test_id: 'case.load', probe: { op: 'load-put' } }],
    put: { entry: syntaxPut },
    runtime: fixtureRuntime(),
    env: {},
    probe_time: PROBE_TIME,
  })
  assert.equal(syntax.ok, true)
  const importRecord = syntax.snapshot.phases.put.records.find((record) => record.capability_key === 'put:import')
  assert.equal(importRecord.observed, 'absent')
  assert.equal(importRecord.limitations.includes('put-import-failed'), true)
  assert.equal(syntax.snapshot.cases[0].observed, 'absent')

  const notPlugin = await probeWorkerCapabilities({
    cases: [{ test_id: 'case.load', probe: { op: 'load-put' } }],
    put: { entry: nonPluginPut },
    runtime: fixtureRuntime(),
    env: {},
    probe_time: PROBE_TIME,
  })
  assert.equal(notPlugin.ok, true)
  const shape = notPlugin.snapshot.phases.put.records.find((record) => record.capability_key === 'put:plugin-shape')
  assert.equal(shape.observed, 'absent')
  assert.equal(notPlugin.snapshot.cases[0].observed, 'absent')
})

test('a failing PUT is measured as absent apply evidence while the harness capability stays present', async () => {
  const result = await probeWorkerCapabilities({
    cases: [{ test_id: 'case.load-put', probe: { op: 'load-put' } }],
    put: { entry: FAILING_PUT },
    runtime: fixtureRuntime(),
    env: {},
    probe_time: PROBE_TIME,
  })
  assert.equal(result.ok, true)
  const snapshot = result.snapshot
  const putRecords = Object.fromEntries(snapshot.phases.put.records.map((record) => [record.capability_key, record]))
  assert.equal(putRecords['put:apply'].claim, 'declared')
  assert.equal(putRecords['put:apply'].observed, 'absent')
  assert.equal(putRecords['put:apply'].limitations.includes('put-apply-failed'), true)
  assert.match(snapshot.phases.put.error.message, /intentional/)
  assert.equal(snapshot.phases.put.load_phase, 'host-apply')
  assert.equal(snapshot.phases.put.state_after_load, 'FAILED')
  assert.equal(snapshot.phases.put.state_after_dispose, 'DISPOSED')
  // The worker can still load a PUT; the failing apply is an observation value,
  // not a missing harness capability.
  assert.equal(snapshot.cases[0].observed, 'present')
  assert.equal(Object.hasOwn(snapshot.cases[0], 'verification'), false)
})

test('runtime unavailable produces explicit absent/unknown evidence, never fabricated present', async (t) => {
  const dir = tmpDir(t)
  const missingEntry = pathToFileURL(join(dir, 'missing-cordis.mjs')).href
  const missing = await probeWorkerCapabilities({
    cases: [{ test_id: 'case.load-put', probe: { op: 'load-put' } }, { test_id: 'case.echo', probe: { op: 'echo' } }],
    runtime: { cordis_entry: missingEntry, runtime_kind: 'locked-runtime' },
    env: {},
    probe_time: PROBE_TIME,
  })
  assert.equal(missing.ok, true)
  assert.equal(missing.snapshot.runtime.status, 'unavailable')
  assert.equal(missing.snapshot.runtime.reason, 'runtime-entry-missing')
  const envByKey = Object.fromEntries(missing.snapshot.phases.env.records.map((record) => [record.capability_key, record]))
  assert.equal(envByKey['host:cordis-runtime'].observed, 'absent')
  const loadCase = missing.snapshot.cases.find((record) => record.test_id === 'case.load-put')
  assert.equal(loadCase.observed, 'absent')
  assert.equal(loadCase.claim, 'declared')

  const unresolved = await probeWorkerCapabilities({
    cases: [{ test_id: 'case.load-put', probe: { op: 'load-put' } }],
    runtime: 'not-a-real-anchor-descriptor',
    env: {},
    probe_time: PROBE_TIME,
  })
  assert.equal(unresolved.ok, true)
  assert.equal(unresolved.snapshot.runtime.status, 'unavailable')
  assert.equal(unresolved.snapshot.runtime.reason, 'runtime-anchor-read-failed')
  const unresolvedCordis = unresolved.snapshot.phases.env.records
    .find((record) => record.capability_key === 'host:cordis-runtime')
  assert.equal(unresolvedCordis.observed, 'unknown', 'unverifiable runtime is unknown, not absent')
  assert.equal(unresolved.snapshot.cases[0].observed, 'unknown')
})

test('declared capability without a defined measurement stays unknown; observations stay bounded', async () => {
  const result = await probeWorkerCapabilities({
    cases: [{ test_id: 'case.echo', probe: { op: 'echo' } }],
    put: { entry: DECLARED_PUT },
    runtime: fixtureRuntime(),
    env: {},
    probe_time: PROBE_TIME,
  })
  const snapshot = result.snapshot
  assert.ok(result.ok)
  assert.ok(snapshot.limitations.some((item) => item.startsWith('capability-measurement-not-defined:service:example')))
  const record = snapshot.capability_records.find((item) => item.capability_key === 'put:declared:service:example')
  assert.equal(record.observed, 'unknown')
  assert.equal(snapshot.capability_records.some((item) => item.observed === 'not-applicable'), false)
})

test('environment audit reports removed credentials but never their values', async () => {
  const result = await probeWorkerCapabilities({
    cases: [{ test_id: 'case.echo', probe: { op: 'echo' } }],
    runtime: fixtureRuntime(),
    env: { OPENAI_API_KEY: 'sk-do-not-report-this-value', TEMP: 'C:\\Temp' },
    environmentAudit: { credential_name_count: 1, removed_count: 1 },
    probe_time: PROBE_TIME,
  })
  assert.equal(result.ok, true)
  const credentialRecord = result.snapshot.phases.env.records
    .find((record) => record.capability_key === 'host:ambient-credentials')
  assert.equal(credentialRecord.observed, 'present', 'a credential still visible to the probe is reported as present')
  assert.equal(JSON.stringify(result.snapshot).includes('sk-do-not-report-this-value'), false)

  const scrubbed = await probeWorkerCapabilities({
    cases: [{ test_id: 'case.echo', probe: { op: 'echo' } }],
    runtime: fixtureRuntime(),
    env: { TEMP: 'C:\\Temp' },
    environmentAudit: { credential_name_count: 2, removed_count: 2 },
    probe_time: PROBE_TIME,
  })
  const scrubbedRecord = scrubbed.snapshot.phases.env.records
    .find((record) => record.capability_key === 'host:ambient-credentials')
  assert.equal(scrubbedRecord.observed, 'absent')
  assert.equal(scrubbedRecord.evidence.scrubbed_credential_name_count, 2)
})

test('probe rejects malformed case lists and unknown ops stay absent', async () => {
  assert.deepEqual(await probeWorkerCapabilities({ cases: null }), { ok: false, errors: ['probe-cases-not-array'] })
  assert.deepEqual(await probeWorkerCapabilities({ cases: [{ node_id: 'no-test-id' }] }), { ok: false, errors: ['probe-case-invalid'] })
  assert.equal((await probeWorkerCapabilities({ cases: Array.from({ length: 257 }, (_, index) => ({ test_id: `t${index}` })) })).ok, false)

  const result = await probeWorkerCapabilities({
    cases: [{ test_id: 'case.unknown', probe: { op: 'rm-rf' } }],
    runtime: fixtureRuntime(),
    env: {},
    probe_time: PROBE_TIME,
  })
  assert.equal(result.ok, true)
  assert.equal(result.snapshot.cases[0].observed, 'absent')
  assert.ok(result.snapshot.cases[0].limitations.includes('worker-op-unsupported'))
})

test('caseRecordsFromSnapshot validates and derives freeze-compatible records', async () => {
  const result = await probeWorkerCapabilities({
    cases: [{ test_id: 'case.echo', probe: { op: 'echo' } }],
    runtime: fixtureRuntime(),
    env: {},
    probe_time: PROBE_TIME,
  })
  const derived = caseRecordsFromSnapshot(result.snapshot)
  assert.equal(derived.ok, true)
  assert.deepEqual(Object.keys(derived.records), ['case.echo'])
  assert.equal(derived.records['case.echo'].source, 'worker')
  assert.equal(derived.records['case.echo'].claim, 'declared')

  const forged = structuredClone(result.snapshot)
  forged.cases[0].verification = 'corroborated'
  const rejected = caseRecordsFromSnapshot(forged)
  assert.equal(rejected.ok, false)
  assert.ok(rejected.errors.some((item) => item.includes('verification')))

  const badVersion = caseRecordsFromSnapshot({ ...result.snapshot, snapshot_version: 'capability-snapshot/v2' })
  assert.deepEqual(badVersion, { ok: false, errors: ['snapshot-version-unknown'] })
  const badSource = caseRecordsFromSnapshot({ ...result.snapshot, source: 'control-plane' })
  assert.deepEqual(badSource, { ok: false, errors: ['snapshot-source-not-worker'] })
})

test('legacy probeCapabilities never trusts caller claims and binds a real snapshot', async () => {
  const fallback = probeCapabilities([
    {
      test_id: 'contract.login.schema',
      capability: { claim: 'declared', observed: 'present', verification: 'corroborated' },
    },
  ], { probe_version: 'capability-probe/test' })
  const record = fallback['contract.login.schema']
  assert.equal(record.claim, 'not-declared')
  assert.equal(record.observed, 'unknown')
  assert.equal(record.probe_version, 'capability-probe/test')
  assert.equal(Object.hasOwn(record, 'verification'), false)
  assert.ok(record.limitations.includes('probe-snapshot-not-supplied'))

  const result = await probeWorkerCapabilities({
    cases: [{ test_id: 'case.echo', probe: { op: 'echo' } }],
    runtime: fixtureRuntime(),
    env: {},
    probe_time: PROBE_TIME,
  })
  const measured = probeCapabilities([{ test_id: 'case.echo' }, { test_id: 'case.missing' }], {
    snapshot: result.snapshot,
    environment_fingerprint: result.snapshot.environment_fingerprint,
    put_digest: result.snapshot.put_digest,
  })
  assert.equal(measured['case.echo'].observed, 'present')
  assert.equal(measured['case.echo'].probe_time, PROBE_TIME)
  assert.equal(measured['case.missing'].observed, 'unknown')
  assert.ok(measured['case.missing'].limitations.includes('case-not-in-probe-snapshot'))
})

test('legacy probeCapabilities keeps reserved ids and empty/malformed input defensive', () => {
  const reserved = probeCapabilities([{ test_id: '__proto__' }, { test_id: 'constructor' }])
  assert.equal(Object.hasOwn(reserved, '__proto__'), true)
  assert.equal(Object.hasOwn(reserved, 'constructor'), true)
  assert.equal(reserved['__proto__'].observed, 'unknown')
  assert.equal(reserved.constructor.observed, 'unknown')
  assert.equal(Object.keys(probeCapabilities([])).length, 0)
  assert.equal(Object.keys(probeCapabilities(null)).length, 0)
  assert.equal(Object.keys(probeCapabilities(undefined)).length, 0)
  assert.equal(Object.keys(probeCapabilities([{ node_id: 'missing-test-id' }])).length, 0)
})

test('probe snapshot stays within the transport budget for the maximum case count', async () => {
  const cases = Array.from({ length: 256 }, (_, index) => ({
    test_id: `chunk.case.${index}`,
    probe: { op: index % 2 === 0 ? 'echo' : 'load-put' },
    tool: index % 3 === 0 ? { manifest: { requires: ['target:plugin'] } } : undefined,
  }))
  const result = await probeWorkerCapabilities({
    cases,
    put: { entry: DECLARED_PUT },
    runtime: fixtureRuntime(),
    env: {},
    probe_time: PROBE_TIME,
  })
  assert.equal(result.ok, true)
  assert.equal(result.snapshot.cases.length, 256)
  const bytes = Buffer.byteLength(JSON.stringify(result.snapshot), 'utf8')
  assert.ok(bytes < 900 * 1024, `snapshot must fit the bounded probe observation budget (got ${bytes} bytes)`)
})
