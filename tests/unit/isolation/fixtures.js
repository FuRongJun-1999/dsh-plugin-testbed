/**
 * Shared fixtures for isolation unit/security tests.
 *
 * These are E0 test doubles: they exercise code paths only. Nothing here is
 * market evidence, and tests that use them are named accordingly.
 */
import { createHash } from 'node:crypto'

import {
  A2_CASES,
  A2_EVIDENCE_VERSION,
  A2_SUITE_VERSION,
  A3_CASES,
  A3_EVIDENCE_VERSION,
  A3_SUITE_VERSION,
  buildIsolationAttestation,
  buildLauncherDescriptor,
  createProviderCatalog,
  hostFingerprint,
  policyDigestOf,
} from '../../../src/isolation/index.js'

export const FIXED_NOW = '2026-10-19T00:05:00Z'

export function sha(char = 'a') {
  return 'sha256:' + char.repeat(64)
}

export function hex(char = 'a') {
  return char.repeat(64)
}

export function planId(char = 'a') {
  return 'plan-sha256:' + char.repeat(64)
}

export function clone(value) {
  return JSON.parse(JSON.stringify(value))
}

export function baseHostFacts(overrides = {}) {
  const facts = {
    schema_version: 'host-facts/v1',
    platform: 'win32',
    arch: 'x64',
    os_release: '10.0.26200',
    session: {
      user: 'redacted',
      sid: 'redacted',
      elevated: false,
      admin: false,
      integrity: 'low',
      source: 'test-fixture',
    },
    privileges: { status: 'probed', enabled: [], disabled: [] },
    dedicated_worker_identity: { status: 'available', detail: 'fixture dedicated identity' },
    isolation_primitives: {
      windows_restricted_token: 'os-supported-privileges-unavailable',
      windows_appcontainer: 'os-supported-no-profile-verified',
      windows_job_object: 'os-supported-unmeasured',
      windows_firewall_per_user: 'not-configured',
      user_namespace: 'platform-mismatch',
      cgroup_v2: 'platform-mismatch',
      rootless_container: 'unavailable',
      micro_vm: 'unavailable',
      remote_runner: 'unavailable',
    },
    container_runtimes: [],
    vm_tools: [],
    ambient_credentials: { status: 'absent', count: 0, cloud: false, vcs: false, values_read: false },
    evidence_grade: 'E0',
    market_evidence: false,
    limitations: [],
    collected_at: FIXED_NOW,
  }
  return deepMerge(facts, overrides)
}

export function highIntegrityHostFacts(overrides = {}) {
  return baseHostFacts(deepMerge({
    session: { elevated: true, admin: true, integrity: 'high', source: 'test-fixture' },
    dedicated_worker_identity: { status: 'unavailable', detail: 'fixture no identity' },
  }, overrides))
}

export function deepMerge(base, overrides) {
  if (!overrides || typeof overrides !== 'object' || Array.isArray(overrides)) return overrides === undefined ? base : overrides
  const out = Array.isArray(base) ? [...base] : { ...base }
  for (const [key, value] of Object.entries(overrides)) {
    if (value && typeof value === 'object' && !Array.isArray(value) &&
        out[key] && typeof out[key] === 'object' && !Array.isArray(out[key])) {
      out[key] = deepMerge(out[key], value)
    } else {
      out[key] = value
    }
  }
  return out
}

export function validPolicy(overrides = {}) {
  return deepMerge({
    schema_version: 'market-gate-policy/v1',
    policy_id: 'policy-iso-fixture',
    version: '1.0.0',
    isolation: { required_level: 'L2', max_attestation_age_ms: 300000 },
  }, overrides)
}

export function externalDescriptor(overrides = {}) {
  return buildLauncherDescriptor(deepMerge({
    launcher_id: 'windows-appcontainer-l2',
    launcher_version: '0.1.0-isolation-candidate',
    isolation: {
      level: 'L2',
      mechanisms: ['appcontainer-lowbox', 'job-object', 'acl-temp-root', 'reparse-deny', 'env-allowlist'],
      platform: 'win32',
      arch: 'x64',
      os_build: '10.0.26200',
    },
    capabilities: Object.fromEntries([
      'filesystem', 'network', 'subprocess', 'devices', 'cpu_ms', 'memory_mb', 'secrets',
    ].map((dimension) => [dimension, {
      enforced: true,
      mechanism: `fixture-${dimension}`,
      ...(dimension === 'network' ? { default: 'deny' } : {}),
      ...(dimension === 'subprocess' ? { max_processes: 8 } : {}),
      ...(dimension === 'secrets' ? { ambient_credentials: 'none' } : {}),
    }])),
    limitations: [],
    attestation: { method: 'control-plane-measured', schema_version: 'isolation-attestation/v1' },
    declared_at: FIXED_NOW,
  }, overrides))
}

export function fixtureAttestation(overrides = {}) {
  const descriptor = externalDescriptor()
  const attestation = buildIsolationAttestation(deepMerge({
    attestation_id: 'iso-' + 'a'.repeat(32),
    issuer: {
      launcher_id: descriptor.launcher_id,
      version: descriptor.launcher_version,
      trust: 'control-plane-measured',
      provider_digest: descriptor.provider_digest,
    },
    run_id: 'run-fixture-1',
    plan_id: planId('a'),
    test_id: 'iso.test',
    attempt: 1,
    worker: { worker_id: 'worker-1', pid: 4242, started_at: FIXED_NOW },
    isolation: { level: 'L2', mechanisms: ['appcontainer-lowbox', 'job-object'], elevated: false },
    identity: { sid: 'S-1-15-2-1-2-3', user: 'DshTestbedL2', integrity: 'low', appcontainer_sid: 'S-1-15-2-1-2-3' },
    filesystem: {
      root: 'C:/Users/redacted/AppData/Local/Packages/DshTestbedL2/TempState/attempt-1',
      acl_digest: sha('a'),
      read_only_inputs: ['input-' + 'b'.repeat(64)],
      reparse_follow: 'deny',
    },
    network: { default: 'deny', allowlist: [], mechanism: 'appcontainer-no-capability', rules_digest: sha('c') },
    resources: {
      cpu_ms: 5000, memory_mb: 256, processes: 8, temp_bytes: 1048576, output_bytes: 1048576,
      job_object: 'windows-job-object', limits_digest: sha('d'),
    },
    process_tree: { kill_on_close: true, observed_pids: [4242] },
    devices: { enforced: true, denied: ['device-access-not-granted'] },
    secrets: {
      enforced: true, ambient_credentials: 'none', env_allowlist_digest: sha('e'), handle_inheritance: 'deny',
    },
    evidence_refs: ['ev-launcher-' + '1'.repeat(64), 'ev-jobobject-' + '2'.repeat(64)],
    issued_at: FIXED_NOW,
    nonce: 'n'.repeat(32),
    policy: { policy_version: 'market-gate-policy/v1', policy_digest: sha('f') },
    signature: null,
  }, overrides))
  return { attestation, descriptor }
}

export function fixtureExpected(attestation, descriptor, overrides = {}) {
  return deepMerge({
    run_id: attestation.run_id,
    plan_id: attestation.plan_id,
    test_id: attestation.test_id,
    attempt: attestation.attempt,
    launcher_id: descriptor.launcher_id,
    launcher_version: descriptor.launcher_version,
    provider_digest: descriptor.provider_digest,
    policy_version: 'market-gate-policy/v1',
    policy_digest: attestation.policy.policy_digest,
    required_level: 'L2',
    max_age_ms: 300000,
    denied_roots: ['C:/workspace', 'C:/Users/redacted/.dsh'],
    network_allowlist: [],
    limits: {
      cpu_ms: 10000, memory_mb: 512, processes: 16, temp_bytes: 2097152, output_bytes: 2097152,
    },
    required_evidence_refs: [...attestation.evidence_refs],
  }, overrides)
}

export function fixtureProvider(options = {}) {
  const descriptor = options.descriptor ?? externalDescriptor()
  const hostFacts = options.hostFacts ?? baseHostFacts()
  const availability = {
    provider_id: descriptor.launcher_id,
    level: descriptor.isolation.level,
    available: true,
    provenance: 'external-environment',
    evidence: { grade: 'E2', measured_by: 'external-qa-fixture', evidence_refs: ['ev-availability-' + '3'.repeat(64)] },
    prerequisites: [],
    problems: [],
    reason_codes: [],
    host_fingerprint: hostFingerprint(hostFacts),
    a2_suite_present: true,
    checked_at: FIXED_NOW,
    ...(options.availability ?? {}),
  }
  return {
    provider_id: descriptor.launcher_id,
    level: descriptor.isolation.level,
    schema_version: 'worker-launcher/v1',
    provenance: options.provenance ?? 'external-environment',
    holds_signing_key: false,
    descriptor,
    availability,
    probe: () => availability,
    describe: () => descriptor,
    launch: async () => ({
      schema_version: 'launcher-launch-result/v1',
      provider_id: descriptor.launcher_id,
      status: 'blocked',
      worker_id: null,
      pid: null,
      attestation: null,
      launch_attempted: false,
      fallback_used: false,
      reason_codes: ['isolation-launch-blocked'],
      detail: 'fixture-transport-not-used',
    }),
    cancel: async () => ({ acknowledged: false }),
    reap: async () => ({ reaped: false }),
    attest: async () => ({ status: 'blocked', attestation: null }),
    runAdversarialCase: async (caseSpec) => ({ case_id: caseSpec.id, status: 'blocked', reason_codes: ['adversarial-suite-missing'] }),
  }
}

function suiteEvidence(caseSpecs, options) {
  const provider = options.provider ?? fixtureProvider()
  const hostFacts = options.hostFacts ?? baseHostFacts()
  const descriptor = provider.descriptor
  const profile = hostFingerprint(hostFacts)
  return {
    schema_version: options.schemaVersion,
    suite_version: options.suiteVersion,
    suite_id: options.suiteId,
    executor: {
      identity: { sid: 'S-1-15-2-1-2-3', user: 'DshTestbedL2', elevated: false, integrity: 'low' },
      executed_under_low_privilege: true,
      environment_fingerprint: profile,
      host_fingerprint: profile,
    },
    provider: {
      provider_id: provider.provider_id,
      provider_digest: descriptor.provider_digest,
      launcher_version: descriptor.launcher_version,
      level: provider.level,
      provenance: provider.provenance,
      evidence_grade: provider.availability.evidence.grade,
    },
    started_at: FIXED_NOW,
    completed_at: FIXED_NOW,
    cases: caseSpecs.map((spec) => ({
      case_id: spec.id,
      category: spec.category,
      status: 'pass',
      command: `fixture-a2 --case ${spec.id}`,
      expected: spec.expectation,
      observed: 'blocked-as-expected',
      evidence_refs: ['ev-case-' + spec.id.toLowerCase()],
      reason_codes: [],
      at: FIXED_NOW,
    })),
  }
}

export function fixtureA2Evidence(options = {}) {
  return suiteEvidence(A2_CASES, {
    schemaVersion: A2_EVIDENCE_VERSION,
    suiteVersion: A2_SUITE_VERSION,
    suiteId: 'A2',
    ...options,
  })
}

export function fixtureA3Evidence(options = {}) {
  return suiteEvidence(A3_CASES, {
    schemaVersion: A3_EVIDENCE_VERSION,
    suiteVersion: A3_SUITE_VERSION,
    suiteId: 'A3',
    ...options,
  })
}

export function catalogFor(hostFacts = baseHostFacts()) {
  return createProviderCatalog({ hostFacts })
}

export function policyDigest(policy = validPolicy()) {
  return policyDigestOf(policy)
}

export function runtimeSha(text) {
  return 'sha256:' + createHash('sha256').update(text).digest('hex')
}
