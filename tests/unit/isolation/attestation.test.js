/** Verification tests for `isolation-attestation/v1`. */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  DEFAULT_MAX_ATTESTATION_AGE_MS,
  MAX_FUTURE_SKEW_MS,
  createNonceRegistry,
  pathInsideOrEqual,
  verifyIsolationAttestation,
} from '../../../src/isolation/attestation.js'
import { isolationAttestationDigest as attestationDigest } from '../../../src/isolation/contracts.js'
import {
  FIXED_NOW,
  fixtureAttestation,
  fixtureExpected,
  planId,
  sha,
} from './fixtures.js'

function verify(overrides = {}, expectedOverrides = {}, options = {}) {
  const { attestation, descriptor } = fixtureAttestation(overrides.attestation ?? {})
  const expected = fixtureExpected(attestation, descriptor, expectedOverrides)
  return {
    verification: verifyIsolationAttestation(attestation, expected, {
      now: FIXED_NOW,
      nonceRegistry: createNonceRegistry({ now: () => Date.parse(FIXED_NOW) }),
      ...options,
    }),
    attestation,
    expected,
  }
}

function expectInvalid(result, reason) {
  assert.equal(result.result, 'invalid')
  assert.ok(result.reason_codes.includes(reason), `expected ${reason}, got ${result.reason_codes.join(',')}`)
}

test('attestation: a measured, bound, fresh attestation verifies', () => {
  const { verification } = verify()
  assert.equal(verification.result, 'valid')
  assert.deepEqual(verification.reason_codes, [])
  assert.equal(verification.nonce_consumed, true)
  assert.match(verification.attestation_digest, /^sha256:[0-9a-f]{64}$/)
  assert.equal(verification.verified_by, 'control-plane:isolation-verifier')
})

test('attestation: worker self-report and bare launcher declaration are never evidence', () => {
  for (const trust of ['worker-self-reported', 'launcher-declared']) {
    const { attestation, descriptor } = fixtureAttestation({
      issuer: { ...fixtureAttestation().attestation.issuer, trust },
    })
    const result = verifyIsolationAttestation(attestation, fixtureExpected(attestation, descriptor), {
      now: FIXED_NOW,
      nonceRegistry: createNonceRegistry({ now: () => Date.parse(FIXED_NOW) }),
    })
    expectInvalid(result, 'isolation-unverified')
  }
})

test('attestation: run/plan/test/attempt/pid binding mismatches are rejected', () => {
  const { attestation, descriptor } = fixtureAttestation()
  const expected = fixtureExpected(attestation, descriptor)
  for (const field of ['run_id', 'plan_id', 'test_id', 'attempt', 'worker_pid']) {
    const wrong = { ...expected, [field]: field === 'attempt' || field === 'worker_pid' ? 999 : (field === 'plan_id' ? planId('b') : 'wrong-value') }
    const result = verifyIsolationAttestation(attestation, wrong, {
      now: FIXED_NOW,
      nonceRegistry: createNonceRegistry({ now: () => Date.parse(FIXED_NOW) }),
    })
    expectInvalid(result, 'isolation-attestation-binding-mismatch')
  }
})

test('attestation: launcher/provider/policy mismatches are rejected', () => {
  const { attestation, descriptor } = fixtureAttestation()
  const base = fixtureExpected(attestation, descriptor)
  for (const overrides of [
    { launcher_id: 'other-launcher' },
    { launcher_version: '9.9.9' },
    { provider_digest: sha('0') },
    { policy_version: 'market-gate-policy/v2' },
    { policy_digest: sha('0') },
  ]) {
    const result = verifyIsolationAttestation(attestation, { ...base, ...overrides }, {
      now: FIXED_NOW,
      nonceRegistry: createNonceRegistry({ now: () => Date.parse(FIXED_NOW) }),
    })
    expectInvalid(result, overrides.policy_version ? 'isolation-attestation-binding-mismatch' : 'isolation-attestation-binding-mismatch')
  }
})

test('attestation: stale/future attestations are rejected', () => {
  const stale = verify({}, {}, { now: new Date(Date.parse(FIXED_NOW) + DEFAULT_MAX_ATTESTATION_AGE_MS + 1000) })
  expectInvalid(stale.verification, 'isolation-attestation-expired')

  const future = verify({}, {}, { now: new Date(Date.parse(FIXED_NOW) - MAX_FUTURE_SKEW_MS - 1000) })
  expectInvalid(future.verification, 'isolation-attestation-expired')
})

test('attestation: nonce is single-use and replay is rejected', () => {
  const { attestation, descriptor } = fixtureAttestation()
  const expected = fixtureExpected(attestation, descriptor)
  const registry = createNonceRegistry({ now: () => Date.parse(FIXED_NOW) })
  const first = verifyIsolationAttestation(attestation, expected, { now: FIXED_NOW, nonceRegistry: registry })
  assert.equal(first.result, 'valid')
  const second = verifyIsolationAttestation(attestation, expected, { now: FIXED_NOW, nonceRegistry: registry })
  expectInvalid(second, 'isolation-attestation-replay')
  assert.equal(second.nonce_consumed, false)
})

test('attestation: nonce registry is mandatory for market verification', () => {
  const { verification } = verify({}, {}, { nonceRegistry: undefined })
  expectInvalid(verification, 'isolation-unverified')
})

test('attestation: elevated/high-integrity identity is rejected', () => {
  for (const patch of [
    { isolation: { elevated: true } },
    { identity: { integrity: 'high' } },
    { identity: { integrity: 'system' } },
  ]) {
    const { verification } = verify({ attestation: patch })
    expectInvalid(verification, 'worker-identity-not-low-privilege')
  }
})

test('attestation: unenforced dimensions are rejected', () => {
  for (const patch of [
    { filesystem: { reparse_follow: 'unknown' } },
    { network: { default: 'allowlist' } },
    { devices: { enforced: false } },
    { secrets: { ambient_credentials: 'present' } },
    { process_tree: { kill_on_close: false } },
  ]) {
    const { verification } = verify({ attestation: patch })
    expectInvalid(verification, 'isolation-dimension-unenforced')
  }
})

test('attestation: limits above the frozen policy are rejected', () => {
  const { verification } = verify({}, { limits: { cpu_ms: 1, memory_mb: 1, processes: 1, temp_bytes: 1, output_bytes: 1 } })
  expectInvalid(verification, 'isolation-dimension-unenforced')
})

test('attestation: denied workspace/DSH roots cannot be the worker root', () => {
  const { attestation, descriptor } = fixtureAttestation()
  const expected = fixtureExpected(attestation, descriptor, { denied_roots: ['C:/Users/redacted/AppData/Local/Packages'] })
  const result = verifyIsolationAttestation(attestation, expected, {
    now: FIXED_NOW,
    nonceRegistry: createNonceRegistry({ now: () => Date.parse(FIXED_NOW) }),
  })
  expectInvalid(result, 'isolation-dimension-unenforced')
  assert.equal(pathInsideOrEqual('C:/a/b', 'C:/a'), true)
  assert.equal(pathInsideOrEqual('C:/ab', 'C:/a'), false)
})

test('attestation: control-plane-measured needs external evidence refs', () => {
  const { attestation, descriptor } = fixtureAttestation({ evidence_refs: ['ev-only-one'] })
  const result = verifyIsolationAttestation(attestation, fixtureExpected(attestation, descriptor), {
    now: FIXED_NOW,
    nonceRegistry: createNonceRegistry({ now: () => Date.parse(FIXED_NOW) }),
  })
  expectInvalid(result, 'isolation-unverified')
})

test('attestation: externally signed attestation requires pinned key + verifier', () => {
  const signature = { alg: 'ed25519', key_id: 'operator-key-1', value: 'c2lnbmF0dXJl' }
  const { attestation, descriptor } = fixtureAttestation({
    issuer: { trust: 'external-provider-signed' },
    signature,
  })
  const expected = fixtureExpected(attestation, descriptor)
  const registry = createNonceRegistry({ now: () => Date.parse(FIXED_NOW) })
  const noVerifier = verifyIsolationAttestation(attestation, expected, { now: FIXED_NOW, nonceRegistry: registry })
  expectInvalid(noVerifier, 'isolation-unverified')

  const accepted = verifyIsolationAttestation(attestation, expected, {
    now: FIXED_NOW,
    nonceRegistry: createNonceRegistry({ now: () => Date.parse(FIXED_NOW) }),
    pinnedKeys: { 'operator-key-1': { alg: 'ed25519', public_key: 'cHVibGlj' } },
    verifySignature: ({ payload_digest }) => payload_digest === verificationDigest(attestation),
  })
  assert.equal(accepted.result, 'valid')
})

test('attestation: a failed signature verification rejects the attestation', () => {
  const { attestation, descriptor } = fixtureAttestation({
    issuer: { trust: 'external-provider-signed' },
    signature: { alg: 'ecdsa-p256-sha256', key_id: 'operator-key-2', value: 'c2ln' },
  })
  const result = verifyIsolationAttestation(attestation, fixtureExpected(attestation, descriptor), {
    now: FIXED_NOW,
    nonceRegistry: createNonceRegistry({ now: () => Date.parse(FIXED_NOW) }),
    pinnedKeys: { 'operator-key-2': { alg: 'ecdsa-p256-sha256', public_key: 'cHVibGlj' } },
    verifySignature: () => false,
  })
  expectInvalid(result, 'isolation-unverified')
})

function verificationDigest(attestation) {
  return attestationDigest(attestation)
}
