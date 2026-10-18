/** Remote L3 runner-attestation tests. */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  buildRunnerAttestation,
  validateRunnerAttestation,
  verifyRunnerAttestation,
} from '../../../src/isolation/runner-attestation.js'
import { createNonceRegistry } from '../../../src/isolation/attestation.js'
import { FIXED_NOW, sha } from './fixtures.js'

function runnerAttestation(overrides = {}) {
  return buildRunnerAttestation({
    attestation_id: 'runner-att-' + 'a'.repeat(32),
    runner_id: 'runner-l3-1',
    operator: { org: 'external-qa', principal: 'operator@example.test' },
    runner_version: '1.2.3',
    image: { name: 'ghcr.io/example/testbed', digest: sha('a'), platform: 'linux/amd64' },
    runtime: { engine: 'rootless-podman', version: '5.0.0', kernel: '6.6.0', hypervisor: null },
    host: { os: 'linux', patch_level: '2026-10' },
    network: { default: 'deny', allowlist: [], policy_digest: sha('b') },
    credential_scope: 'none',
    issued_at: FIXED_NOW,
    expires_at: '2026-10-19T01:05:00Z',
    nonce: 'r'.repeat(32),
    revocation_ref: 'crl-2026-10',
    signature: { alg: 'ed25519', key_id: 'operator-key-1', value: 'c2lnbmF0dXJl' },
    ...overrides,
  })
}

const allowlist = {
  runner_ids: ['runner-l3-1'],
  image_digests: [sha('a')],
  operators: [{ org: 'external-qa', principal: 'operator@example.test' }],
}

const pinnedKeys = { 'operator-key-1': { alg: 'ed25519', public_key: 'cHVibGlj' } }

function verify(overrides = {}, expectedOverrides = {}, options = {}) {
  const attestation = runnerAttestation(overrides)
  return verifyRunnerAttestation(attestation, {
    allowlist,
    max_age_ms: 600000,
    ...expectedOverrides,
  }, {
    now: FIXED_NOW,
    nonceRegistry: createNonceRegistry({ now: () => Date.parse(FIXED_NOW) }),
    pinnedKeys,
    verifySignature: () => true,
    isRevoked: () => false,
    ...options,
  })
}

function expectInvalid(result, reason) {
  assert.equal(result.result, 'invalid')
  assert.ok(result.reason_codes.includes(reason), `expected ${reason}, got ${result.reason_codes.join(',')}`)
}

test('runner-attestation: a signed, allowlisted, fresh runner verifies', () => {
  const verification = verify()
  assert.equal(verification.result, 'valid')
  assert.deepEqual(verification.reason_codes, [])
  assert.equal(verification.nonce_consumed, true)
  assert.match(verification.runner_attestation_digest, /^sha256:[0-9a-f]{64}$/)
})

test('runner-attestation: signature verifier and pinned key are mandatory', () => {
  expectInvalid(verify({}, {}, { verifySignature: undefined }), 'isolation-unverified')
  expectInvalid(verify({}, {}, { pinnedKeys: {} }), 'isolation-unverified')
  expectInvalid(verify({}, {}, { verifySignature: () => false }), 'isolation-unverified')
})

test('runner-attestation: revocation source is mandatory and revocation is rejected', () => {
  expectInvalid(verify({}, {}, { isRevoked: undefined }), 'runner-not-allowed')
  expectInvalid(verify({}, {}, { isRevoked: () => true }), 'runner-not-allowed')
})

test('runner-attestation: stale and expired attestations are rejected', () => {
  expectInvalid(verify({}, {}, { now: '2026-10-19T00:30:00Z' }), 'runner-attestation-invalid')
  expectInvalid(verify({}, {}, { now: '2026-10-19T02:00:00Z' }), 'runner-attestation-expired')
})

test('runner-attestation: nonce replay and missing registry are rejected', () => {
  const attestation = runnerAttestation()
  const registry = createNonceRegistry({ now: () => Date.parse(FIXED_NOW) })
  const options = {
    now: FIXED_NOW,
    nonceRegistry: registry,
    pinnedKeys,
    verifySignature: () => true,
    isRevoked: () => false,
  }
  assert.equal(verifyRunnerAttestation(attestation, { allowlist }, options).result, 'valid')
  expectInvalid(verifyRunnerAttestation(attestation, { allowlist }, options), 'runner-attestation-replay')
  expectInvalid(verifyRunnerAttestation(attestation, { allowlist }, { ...options, nonceRegistry: undefined }), 'isolation-unverified')
})

test('runner-attestation: runner/image/operator allowlists are enforced', () => {
  expectInvalid(verify({}, { allowlist: { ...allowlist, runner_ids: ['other'] } }), 'runner-not-allowed')
  expectInvalid(verify({}, { allowlist: { ...allowlist, image_digests: [sha('0')] } }), 'runner-not-allowed')
  expectInvalid(verify({}, { allowlist: { ...allowlist, operators: [] } }), 'runner-not-allowed')
  expectInvalid(verify({}, { required_image_digest: sha('0') }), 'runner-not-allowed')
})

test('runner-attestation: L3 invariants are structural', () => {
  assert.equal(validateRunnerAttestation({ ...runnerAttestation(), isolation_level: 'L2' }).ok, false)
  assert.throws(() => runnerAttestation({ credential_scope: 'host' }), /credential-scope-must-be-none/)
  assert.throws(() => runnerAttestation({ network: { default: 'allowlist', allowlist: [], policy_digest: sha('b') } }), /network-deny-required/)
  assert.throws(() => runnerAttestation({ runtime: { engine: 'docker', version: '1', kernel: '1', hypervisor: null } }), /l3-runtime-engine-invalid/)
  const unsignedShape = runnerAttestation()
  const validation = validateRunnerAttestation({ ...unsignedShape, signature: null })
  assert.equal(validation.ok, false)
})
