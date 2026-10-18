/** Provider catalog / selection / launch fail-closed tests. */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  PROVIDER_IDS,
  PROVIDER_LAUNCHER_VERSION,
  candidateProviderSpecs,
  createExternalIsolationProvider,
  createProviderCatalog,
  selectIsolationProvider,
  validateAvailabilityRecord,
  validateLauncherLaunchRequest,
} from '../../../src/isolation/providers.js'
import {
  baseHostFacts,
  externalDescriptor,
  highIntegrityHostFacts,
  planId,
  sha,
} from './fixtures.js'
import { hostFingerprint } from '../../../src/isolation/host-capabilities.js'

function launchRequest(overrides = {}) {
  return {
    schema_version: 'launcher-launch-request/v1',
    run_id: 'run-provider-1',
    plan_id: planId(),
    test_id: 'iso.launch',
    attempt: 1,
    artifact_digest: sha('a'),
    input_dir: 'C:/tmp/input',
    output_dir: 'C:/tmp/output',
    budget: { cpu_ms: 1000, memory_mb: 128, processes: 4, temp_bytes: 1048576, output_bytes: 1048576 },
    deadline: '2026-10-19T01:00:00Z',
    network_allowlist: [],
    required_level: 'L2',
    cancel_token: 'c'.repeat(32),
    nonce: 'n'.repeat(32),
    ...overrides,
  }
}

test('providers: catalog covers Windows L2 candidates and L3 runtimes', () => {
  const specIds = candidateProviderSpecs().map((spec) => spec.provider_id)
  assert.ok(specIds.includes(PROVIDER_IDS.windowsRestrictedTokenL2))
  assert.ok(specIds.includes(PROVIDER_IDS.windowsAppContainerL2))
  assert.ok(specIds.includes(PROVIDER_IDS.rootlessContainerL3))
  assert.ok(specIds.includes(PROVIDER_IDS.microVmL3))
  assert.ok(specIds.includes(PROVIDER_IDS.remoteRunnerL3))
  const appContainer = candidateProviderSpecs().find((spec) => spec.provider_id === PROVIDER_IDS.windowsAppContainerL2)
  assert.ok(appContainer.mechanisms.includes('appcontainer-lowbox'))
  assert.ok(appContainer.mechanisms.includes('job-object'))
  const restricted = candidateProviderSpecs().find((spec) => spec.provider_id === PROVIDER_IDS.windowsRestrictedTokenL2)
  assert.ok(restricted.mechanisms.includes('restricted-token'))
  assert.ok(restricted.mechanisms.includes('job-object'))
})

test('providers: built-in candidates are never available and never hold signing keys', () => {
  const catalog = createProviderCatalog({ hostFacts: baseHostFacts() })
  assert.equal(catalog.length, 6)
  for (const provider of catalog) {
    assert.equal(provider.availability.available, false, provider.provider_id)
    assert.equal(provider.holds_signing_key, false)
    assert.equal(provider.availability.evidence.grade, 'E0')
    assert.ok(provider.availability.reason_codes.includes('isolation-provider-missing'))
    for (const dimension of ['filesystem', 'network', 'subprocess', 'devices', 'cpu_ms', 'memory_mb', 'secrets']) {
      assert.equal(provider.descriptor.capabilities[dimension].enforced, false)
    }
  }
})

test('providers: missing prerequisites produce structured blocked diagnostics', () => {
  const catalog = createProviderCatalog({ hostFacts: highIntegrityHostFacts() })
  const appContainer = catalog.find((provider) => provider.provider_id === PROVIDER_IDS.windowsAppContainerL2)
  assert.equal(appContainer.availability.available, false)
  assert.ok(appContainer.availability.reason_codes.includes('worker-identity-not-low-privilege'))
  assert.ok(appContainer.availability.reason_codes.includes('isolation-provider-not-measured'))
  assert.ok(appContainer.availability.reason_codes.includes('adversarial-suite-missing'))
  const profile = appContainer.availability.prerequisites.find((item) => item.id === 'appcontainer-profile')
  assert.equal(profile.status, 'unavailable')

  const linux = catalog.find((provider) => provider.provider_id === PROVIDER_IDS.rootlessContainerL3)
  assert.ok(linux.availability.reason_codes.includes('isolation-provider-platform-mismatch'))
  const remote = catalog.find((provider) => provider.provider_id === PROVIDER_IDS.remoteRunnerL3)
  assert.ok(remote.availability.reason_codes.includes('isolation-provider-not-measured'))
  assert.ok(remote.availability.reason_codes.includes('adversarial-suite-missing'))
})

test('providers: selection blocks L2 and L3 without a real provider', () => {
  const hostFacts = baseHostFacts()
  const catalog = createProviderCatalog({ hostFacts })
  const l2 = selectIsolationProvider({ requiredLevel: 'L2', hostFacts, catalog })
  assert.equal(l2.status, 'blocked')
  assert.equal(l2.selected_provider, null)
  assert.ok(l2.reason_codes.includes('isolation-provider-missing'))
  assert.equal(l2.downgrade_forbidden, true)
  assert.equal(l2.no_fallback, true)

  const l3 = selectIsolationProvider({ requiredLevel: 'L3', hostFacts, catalog })
  assert.equal(l3.status, 'blocked')
  assert.ok(l3.reason_codes.includes('isolation-provider-missing'))
})

test('providers: L0/L1 requirements are rejected as downgrade', () => {
  const hostFacts = baseHostFacts()
  for (const level of ['L0-in-process', 'L1-subprocess']) {
    const selection = selectIsolationProvider({ requiredLevel: level, hostFacts, catalog: createProviderCatalog({ hostFacts }) })
    assert.equal(selection.status, 'blocked')
    assert.ok(selection.reason_codes.includes('isolation-level-downgrade-forbidden'))
  }
})

test('providers: launch on an unavailable provider starts nothing and never falls back', async () => {
  const catalog = createProviderCatalog({ hostFacts: baseHostFacts() })
  const provider = catalog.find((item) => item.provider_id === PROVIDER_IDS.windowsAppContainerL2)
  const result = await provider.launch(launchRequest())
  assert.equal(result.status, 'blocked')
  assert.equal(result.launch_attempted, false)
  assert.equal(result.fallback_used, false)
  assert.equal(result.pid, null)
  assert.ok(result.reason_codes.includes('isolation-provider-missing'))

  const cancel = await provider.cancel({ pid: 1 })
  assert.equal(cancel.acknowledged, false)
  const reap = await provider.reap({ pid: 1 })
  assert.equal(reap.reaped, false)
  assert.equal(reap.pid_alive, null)
  const attest = await provider.attest({ pid: 1 })
  assert.equal(attest.status, 'blocked')
  assert.equal(attest.attestation, null)
})

test('providers: invalid launch requests are rejected before any provider decision', async () => {
  const provider = createProviderCatalog({ hostFacts: baseHostFacts() })[0]
  for (const request of [
    launchRequest({ required_level: 'L1-subprocess' }),
    launchRequest({ unknown: true }),
    launchRequest({ attempt: 0 }),
    launchRequest({ artifact_digest: 'sha256:short' }),
    launchRequest({ cancel_token: 'short' }),
    launchRequest({ budget: { cpu_ms: 1 } }),
  ]) {
    const validation = validateLauncherLaunchRequest(request)
    assert.equal(validation.ok, false)
    const result = await provider.launch(request)
    assert.equal(result.status, 'blocked')
    assert.equal(result.launch_attempted, false)
  }
})

test('providers: availability records must be external, E2/E3 and host/provider bound', () => {
  const descriptor = externalDescriptor()
  const hostFacts = baseHostFacts()
  const binding = {
    providerDigest: descriptor.provider_digest,
    launcherVersion: descriptor.launcher_version,
    hostFingerprint: hostFingerprint(hostFacts),
  }
  const good = {
    schema_version: 'isolation-availability/v1',
    provider_digest: descriptor.provider_digest,
    launcher_version: descriptor.launcher_version,
    grade: 'E2',
    provenance: 'external-environment',
    host_fingerprint: binding.hostFingerprint,
    measured_by: 'external-qa',
    measured_at: '2026-10-19T00:00:00Z',
    evidence_refs: ['ev-availability-1'],
    a2_suite: { result: 'pass', digest: sha('9') },
  }
  assert.equal(validateAvailabilityRecord(good, binding).ok, true)
  for (const patch of [
    { grade: 'E0' },
    { provenance: 'test-double' },
    { provider_digest: sha('0') },
    { host_fingerprint: sha('0') },
    { measured_by: '' },
    { evidence_refs: [] },
    { a2_suite: { result: 'blocked' } },
    { a2_suite: undefined },
    { unknown: true },
  ]) {
    assert.equal(validateAvailabilityRecord({ ...good, ...patch }, binding).ok, false, JSON.stringify(patch))
  }
})

test('providers: a fully measured external environment can make the native L2 provider available', () => {
  const hostFacts = baseHostFacts()
  const nativeBackend = { native_backend_compiled: true, userenv_exports: true, job_object_ready: true, profile_exists: true }
  const probeCatalog = createProviderCatalog({ hostFacts, nativeBackend })
  const probeProvider = probeCatalog.find((provider) => provider.provider_id === PROVIDER_IDS.windowsAppContainerL2)
  const transport = {
    launch: async () => ({ status: 'blocked' }),
    cancel: async () => ({ acknowledged: false }),
    reap: async () => ({ reaped: false }),
    attest: async () => ({ status: 'blocked' }),
    runAdversarialCase: async () => ({ status: 'blocked' }),
  }
  const catalog = createProviderCatalog({
    hostFacts,
    nativeBackend,
    external: {
      enabled: true,
      transport,
      availabilityRecord: {
        schema_version: 'isolation-availability/v1',
        provider_digest: probeProvider.descriptor.provider_digest,
        launcher_version: probeProvider.descriptor.launcher_version,
        grade: 'E2',
        provenance: 'external-environment',
        host_fingerprint: hostFingerprint(hostFacts),
        measured_by: 'external-qa',
        measured_at: '2026-10-19T00:00:00Z',
        evidence_refs: ['ev-availability-1'],
        a2_suite: { result: 'pass', digest: sha('9') },
      },
    },
  })
  const appContainer = catalog.find((provider) => provider.provider_id === PROVIDER_IDS.windowsAppContainerL2)
  assert.equal(appContainer.availability.available, true, JSON.stringify(appContainer.availability))
  assert.equal(appContainer.availability.evidence.grade, 'E2')
  assert.equal(appContainer.provenance, 'external-environment')
  const selection = selectIsolationProvider({ requiredLevel: 'L2', hostFacts, catalog })
  assert.equal(selection.status, 'available')
  assert.equal(selection.selected_provider, PROVIDER_IDS.windowsAppContainerL2)
})

test('providers: test doubles cannot become external providers', () => {
  const hostFacts = baseHostFacts()
  const provider = createExternalIsolationProvider({
    provider_id: PROVIDER_IDS.windowsAppContainerL2,
    hostFacts,
    externalEnvironment: true,
    test_double: true,
    availabilityRecord: {
      schema_version: 'isolation-availability/v1',
      provider_digest: sha('a'),
      launcher_version: PROVIDER_LAUNCHER_VERSION,
      grade: 'E3',
      provenance: 'external-environment',
      host_fingerprint: sha('b'),
      measured_by: 'test',
      measured_at: '2026-10-19T00:00:00Z',
      evidence_refs: ['ev-1'],
    },
  })
  assert.equal(provider.availability.available, false)
  assert.equal(provider.provenance, 'test-double')
  assert.ok(provider.availability.reason_codes.includes('fixture-not-market-evidence'))
  assert.throws(() => createExternalIsolationProvider({ provider_id: 'not-a-provider' }), /unknown provider_id/)
})
