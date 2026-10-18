/** Isolation admission fail-closed matrix. */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { createNonceRegistry } from '../../../src/isolation/attestation.js'
import { evaluateIsolationAdmission } from '../../../src/isolation/admission.js'
import { evaluateA2Evidence } from '../../../src/isolation/a2.js'
import {
  FIXED_NOW,
  baseHostFacts,
  externalDescriptor,
  fixtureA2Evidence,
  fixtureAttestation,
  fixtureExpected,
  fixtureProvider,
  highIntegrityHostFacts,
  policyDigest,
  validPolicy,
} from './fixtures.js'

function setup(overrides = {}) {
  const policy = 'policy' in overrides ? overrides.policy : validPolicy()
  const hostFacts = overrides.hostFacts ?? baseHostFacts()
  const descriptor = overrides.descriptor ?? externalDescriptor()
  const provider = overrides.provider ?? fixtureProvider({ descriptor, hostFacts })
  const { attestation } = fixtureAttestation({
    issuer: {
      launcher_id: descriptor.launcher_id,
      version: descriptor.launcher_version,
      trust: 'control-plane-measured',
      provider_digest: descriptor.provider_digest,
    },
    policy: { policy_version: 'market-gate-policy/v1', policy_digest: policyDigest(policy ?? validPolicy()) },
    ...(overrides.attestation ?? {}),
  })
  const expected = fixtureExpected(attestation, descriptor, overrides.expected)
  const a2Evidence = overrides.a2Evidence ?? fixtureA2Evidence({ provider, hostFacts })
  return evaluateIsolationAdmission({
    required_level: overrides.requiredLevel ?? 'L2',
    provider,
    host_facts: hostFacts,
    policy,
    attestation,
    attestation_expected: expected,
    nonce_registry: createNonceRegistry({ now: () => Date.parse(FIXED_NOW) }),
    a2_evidence: a2Evidence,
    a3_evidence: overrides.a3Evidence,
    runner_attestation: overrides.runnerAttestation,
    test_double: overrides.test_double,
    now: FIXED_NOW,
    ...(overrides.input ?? {}),
  })
}

function assertBlocked(admission, reason) {
  assert.equal(admission.result, 'blocked')
  assert.equal(admission.gate_decision, 'blocked')
  assert.equal(admission.market_eligibility, 'non-eligible')
  assert.equal(admission.market_usable, false)
  assert.equal(admission.no_fallback, true)
  if (reason) assert.ok(admission.reason_codes.includes(reason), `expected ${reason}, got ${admission.reason_codes.join(',')}`)
}

test('admission: no provider on this host => blocked/non-eligible', () => {
  const hostFacts = highIntegrityHostFacts()
  const admission = evaluateIsolationAdmission({
    required_level: 'L2',
    provider: null,
    host_facts: hostFacts,
    policy: validPolicy(),
    attestation: null,
    now: FIXED_NOW,
  })
  assertBlocked(admission, 'isolation-provider-missing')
  assert.ok(admission.reason_codes.includes('worker-identity-not-low-privilege'))
  assert.equal(admission.provider, undefined)
})

test('admission: low-priv host but no measured provider => blocked', () => {
  const admission = evaluateIsolationAdmission({
    required_level: 'L2',
    provider: null,
    host_facts: baseHostFacts(),
    policy: validPolicy(),
    attestation: null,
    now: FIXED_NOW,
  })
  assertBlocked(admission, 'isolation-provider-missing')
})

test('admission: synthetic external condition matrix can admit the isolation input only', () => {
  const admission = setup()
  assert.equal(admission.result, 'admitted')
  assert.equal(admission.gate_decision, 'pass')
  assert.equal(admission.market_eligibility, 'eligible-input')
  assert.equal(admission.market_usable, true)
  assert.deepEqual(admission.reason_codes, [])
  assert.ok(admission.evidence_refs.length > 0)
  // Full market eligibility still needs runtime/signing/archive/approval; this
  // module only admits the isolation input.
  assert.equal(admission.schema_version, 'isolation-admission/v1')
})

test('admission: test doubles are never market-usable', () => {
  const admission = setup({ test_double: true })
  assertBlocked(admission, 'fixture-not-market-evidence')
})

test('admission: incomplete/failed A2 evidence blocks', () => {
  const provider = fixtureProvider()
  const hostFacts = baseHostFacts()
  const blockedCase = fixtureA2Evidence({ provider, hostFacts })
  blockedCase.cases[0] = { ...blockedCase.cases[0], status: 'blocked', reason_codes: ['isolation-provider-missing'] }
  assertBlocked(setup({ provider, hostFacts, a2Evidence: blockedCase }), 'adversarial-suite-missing')

  const failedCase = fixtureA2Evidence({ provider, hostFacts })
  failedCase.cases[0] = { ...failedCase.cases[0], status: 'fail', reason_codes: ['attack-succeeded'] }
  assertBlocked(setup({ provider, hostFacts, a2Evidence: failedCase }), 'adversarial-suite-failed')

  const missingEvidence = fixtureA2Evidence({ provider, hostFacts })
  missingEvidence.cases[1] = { ...missingEvidence.cases[1], status: 'pass', command: null }
  assertBlocked(setup({ provider, hostFacts, a2Evidence: missingEvidence }), 'adversarial-suite-missing')
})

test('admission: A2 evidence from a fixture provider cannot be market evidence', () => {
  const provider = fixtureProvider()
  const hostFacts = baseHostFacts()
  const evidence = fixtureA2Evidence({ provider, hostFacts })
  evidence.provider = { ...evidence.provider, provenance: 'test-fixture' }
  const evaluation = evaluateA2Evidence(evidence, { providerDescriptor: provider.descriptor, now: FIXED_NOW })
  assert.equal(evaluation.market_evidence, false)
  assertBlocked(setup({ provider, hostFacts, a2Evidence: evidence }), 'fixture-not-market-evidence')
})

test('admission: stale attestation blocks with an explicit reason', () => {
  const admission = setup({ input: { now: '2026-10-19T01:00:00Z' } })
  assertBlocked(admission, 'isolation-attestation-expired')
})

test('admission: missing policy is fail-closed', () => {
  const admission = setup({ policy: null })
  assertBlocked(admission, 'market-policy-missing')
})

test('admission: L3 requirement is not satisfied by an L2 provider', () => {
  const admission = evaluateIsolationAdmission({
    required_level: 'L3',
    provider: fixtureProvider(),
    host_facts: baseHostFacts(),
    policy: validPolicy(),
    attestation: null,
    now: FIXED_NOW,
  })
  assertBlocked(admission, 'isolation-level-insufficient')
})

test('admission: L0/L1 requirement can never admit', () => {
  const admission = setup({ requiredLevel: 'L1-subprocess' })
  assertBlocked(admission, 'isolation-level-downgrade-forbidden')
  assert.equal(admission.required_level, 'L1-subprocess')
  assert.equal(admission.achieved_level, null)
})

test('admission: high-integrity A2 executor blocks', () => {
  const provider = fixtureProvider()
  const hostFacts = baseHostFacts()
  const evidence = fixtureA2Evidence({ provider, hostFacts })
  evidence.executor.identity.integrity = 'high'
  evidence.executor.identity.elevated = true
  assertBlocked(setup({ provider, hostFacts, a2Evidence: evidence }), 'worker-identity-not-low-privilege')
})
