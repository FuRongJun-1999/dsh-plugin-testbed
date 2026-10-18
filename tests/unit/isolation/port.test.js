/** Control-plane isolation port fail-closed tests. */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  FORBIDDEN_PORT_OPTIONS,
  createIsolationPort,
  makeIsolationPort,
} from '../../../src/adapters/isolation-port.js'
import {
  FIXED_NOW,
  baseHostFacts,
  externalDescriptor,
  fixtureAttestation,
  fixtureExpected,
  fixtureProvider,
  planId,
  policyDigest,
  validPolicy,
} from './fixtures.js'

function binding(overrides = {}) {
  return {
    run_id: 'run-port-1',
    plan_id: planId(),
    test_id: 'iso.port',
    attempt: 1,
    attestation_expected: {
      denied_roots: ['C:/workspace', 'C:/Users/redacted/.dsh'],
      limits: { cpu_ms: 10000, memory_mb: 512, processes: 16, temp_bytes: 2097152, output_bytes: 2097152 },
      network_allowlist: [],
    },
    ...overrides,
  }
}

test('port: construction requires a market isolation level and no L1 fallback options', () => {
  for (const level of ['L0-in-process', 'L1-subprocess']) {
    assert.throws(() => makeIsolationPort({ requiredLevel: level, hostFacts: baseHostFacts() }), /market isolation requires L2 or L3/)
  }
  for (const key of FORBIDDEN_PORT_OPTIONS) {
    assert.throws(
      () => makeIsolationPort({ hostFacts: baseHostFacts(), [key]: true }),
      new RegExp(`option "${key}" is forbidden`),
      key,
    )
  }
  assert.equal(typeof createIsolationPort, 'function')
})

test('port: current host precheck is blocked and never claims an isolation level', () => {
  const port = makeIsolationPort({ hostFacts: baseHostFacts(), requiredLevel: 'L2', now: () => new Date(FIXED_NOW) })
  const precheck = port.precheck()
  assert.equal(precheck.status, 'blocked')
  assert.equal(precheck.claims.isolation_level, null)
  assert.equal(precheck.claims.worker_started, false)
  assert.equal(precheck.claims.market_usable, false)
  assert.equal(precheck.market_eligibility, 'non-eligible')
  assert.equal(precheck.fallback.allowed, false)
  assert.ok(precheck.reason_codes.length > 0)
  assert.equal(precheck.selection.status, 'blocked')
})

test('port: env variables cannot promote a local run', () => {
  const previous = process.env.DSH_TESTBED_ISOLATION_ALLOW_L1
  process.env.DSH_TESTBED_ISOLATION_ALLOW_L1 = '1'
  try {
    const port = makeIsolationPort({ hostFacts: baseHostFacts(), requiredLevel: 'L2', now: () => new Date(FIXED_NOW) })
    assert.equal(port.precheck().status, 'blocked')
  } finally {
    if (previous === undefined) delete process.env.DSH_TESTBED_ISOLATION_ALLOW_L1
    else process.env.DSH_TESTBED_ISOLATION_ALLOW_L1 = previous
  }
})

test('port: admit without a launchable provider returns blocked and starts nothing', async () => {
  const port = makeIsolationPort({ hostFacts: baseHostFacts(), requiredLevel: 'L2', policy: validPolicy(), now: () => new Date(FIXED_NOW) })
  const admission = await port.admit(binding())
  assert.equal(admission.result, 'blocked')
  assert.equal(admission.gate_decision, 'blocked')
  assert.equal(admission.market_eligibility, 'non-eligible')
  assert.equal(admission.market_usable, false)
  assert.equal(admission.no_fallback, true)
  assert.equal(port.status().launch_attempted, false)
  assert.equal(port.launchRecord().isolation_level, null)
})

test('port: malformed binding is rejected before any provider decision', async () => {
  const port = makeIsolationPort({ hostFacts: baseHostFacts(), requiredLevel: 'L2', policy: validPolicy(), now: () => new Date(FIXED_NOW) })
  for (const bad of [null, {}, { run_id: 'r', plan_id: 'bad', test_id: 't', attempt: 1 }]) {
    const admission = await port.admit(bad)
    assert.equal(admission.result, 'blocked')
    assert.equal(admission.reason_codes.includes('isolation-unverified'), true)
  }
  const missingExpected = await port.admit(binding({ attestation_expected: undefined }))
  assert.equal(missingExpected.result, 'blocked')
  assert.equal(missingExpected.reason_codes.includes('isolation-unverified'), true)
})

test('port: verifyAttestation uses the expected binding and policy', () => {
  const policy = validPolicy()
  const { attestation, descriptor } = fixtureAttestation({
    policy: { policy_version: 'market-gate-policy/v1', policy_digest: policyDigest(policy) },
  })
  const port = makeIsolationPort({
    hostFacts: baseHostFacts(),
    requiredLevel: 'L2',
    policy,
    provider: fixtureProvider({ descriptor, hostFacts: baseHostFacts() }),
    externalEnvironment: true,
    authorization: {
      schema_version: 'windows-l2-authorization/v1',
      approved_by: 'fixture',
      approval_ref: 'fixture',
      profile_name: 'DshTestbedL2',
      scope: ['create-appcontainer-profile', 'launch-appcontainer-process', 'assign-job-object', 'create-temp-root', 'delete-attempt-temp'],
      issued_at: '2026-10-18T00:00:00Z',
      expires_at: '2030-10-19T00:00:00Z',
      acknowledged_risks: ['fixture'],
    },
    attestationExpected: fixtureExpected(attestation, descriptor),
    now: () => new Date(FIXED_NOW),
  })
  const verification = port.verifyAttestation(attestation)
  assert.equal(verification.result, 'valid')
  assert.equal(verification.nonce_consumed, true)
})

test('port: cancel/reap before launch are blocked, not fake success', async () => {
  const port = makeIsolationPort({ hostFacts: baseHostFacts(), requiredLevel: 'L2', now: () => new Date(FIXED_NOW) })
  const cancel = await port.cancel()
  assert.equal(cancel.acknowledged, false)
  assert.equal(cancel.launch_attempted, false)
  assert.ok(cancel.reason_codes.includes('isolation-launch-blocked'))
  const reap = await port.reap()
  assert.equal(reap.reaped, false)
  assert.equal(reap.pid_alive, null)
  assert.equal(reap.temp_removed, null)
})

test('port: injected providers require an explicit external environment', () => {
  const hostFacts = baseHostFacts()
  const descriptor = externalDescriptor()
  const provider = fixtureProvider({ descriptor, hostFacts })
  const blocked = makeIsolationPort({ hostFacts, requiredLevel: 'L2', provider, now: () => new Date(FIXED_NOW) })
  const blockedPrecheck = blocked.precheck()
  assert.equal(blockedPrecheck.status, 'blocked')
  assert.ok(blockedPrecheck.reason_codes.includes('fixture-not-market-evidence'))

  const external = makeIsolationPort({
    hostFacts,
    requiredLevel: 'L2',
    provider,
    externalEnvironment: true,
    policy: validPolicy(),
    now: () => new Date(FIXED_NOW),
  })
  // Even with an injected provider the precheck needs the native authorization
  // and the admission needs A2 evidence; it must not claim L2 from an injected
  // fixture alone.
  assert.equal(external.precheck().claims.market_usable, false)
})

test('port: L3 requirement is not satisfied by an injected L2 provider', () => {
  const hostFacts = baseHostFacts()
  const provider = fixtureProvider({ descriptor: externalDescriptor(), hostFacts })
  const port = makeIsolationPort({
    hostFacts,
    requiredLevel: 'L3',
    provider,
    externalEnvironment: true,
    policy: validPolicy(),
    now: () => new Date(FIXED_NOW),
  })
  const precheck = port.precheck()
  assert.equal(precheck.status, 'blocked')
  assert.ok(precheck.reason_codes.includes('isolation-level-insufficient'))
})
