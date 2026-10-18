/** Contract validation tests for `src/isolation/contracts.js`. */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  ISOLATION_LEVEL_RANK,
  ISOLATION_REASON,
  MARKET_ISOLATION_LEVELS,
  assertIsolationAttestation,
  buildIsolationAttestation,
  buildLauncherDescriptor,
  deepFreeze,
  digestDocument,
  findSecretMaterial,
  isolationAttestationDigest,
  isolationLevelRank,
  isMarketIsolationLevel,
  policyDigestOf,
  providerDigestOf,
  validateIsolationAttestation,
  validateLauncherDescriptor,
} from '../../../src/isolation/contracts.js'
import {
  externalDescriptor,
  fixtureAttestation,
  planId,
  sha,
  validPolicy,
} from './fixtures.js'

test('isolation contracts: valid fixture attestation validates and freezes', () => {
  const { attestation } = fixtureAttestation()
  assert.deepEqual(validateIsolationAttestation(attestation), { ok: true, errors: [] })
  assert.equal(assertIsolationAttestation(attestation), attestation)
  assert.ok(Object.isFrozen(attestation))
  assert.ok(Object.isFrozen(attestation.resources))
  assert.match(isolationAttestationDigest(attestation), /^sha256:[0-9a-f]{64}$/)
})

test('isolation contracts: unknown fields/versions/levels are rejected', () => {
  const { attestation } = fixtureAttestation()
  const extra = { ...attestation, unexpected: true }
  assert.equal(validateIsolationAttestation(extra).ok, false)

  const badVersion = { ...attestation, schema_version: 'isolation-attestation/v2' }
  assert.equal(validateIsolationAttestation(badVersion).ok, false)

  const badLevel = { ...attestation, isolation: { ...attestation.isolation, level: 'L4' } }
  assert.equal(validateIsolationAttestation(badLevel).ok, false)

  // L1 is structurally a known isolation label (so a verifier can explain why
  // it is insufficient); it is never market-grade.
  const l1 = { ...attestation, isolation: { ...attestation.isolation, level: 'L1-subprocess' } }
  assert.equal(validateIsolationAttestation(l1).ok, true)
  assert.ok(isolationLevelRank(l1.isolation.level) < 2)

  const missingPolicy = { ...attestation }
  delete missingPolicy.policy
  assert.equal(validateIsolationAttestation(missingPolicy).ok, false)
})

test('isolation contracts: builder rejects worker self-report and private key material', () => {
  const { attestation } = fixtureAttestation()
  const source = { ...attestation, issuer: { ...attestation.issuer, trust: 'worker-self-reported' } }
  // Building is structurally allowed (so verifier can report the trust failure),
  // but a signing private key must never be accepted.
  assert.throws(
    () => buildIsolationAttestation({ ...source, signature: { alg: 'ed25519', key_id: 'k1', value: 'c2ln' }, signing_private_key: 'x' }),
    /must not receive a signing private key/,
  )
  assert.throws(
    () => buildIsolationAttestation({ ...attestation, evidence_refs: ['-----BEGIN PRIVATE KEY-----'] }),
    /secret-material-forbidden|invalid/,
  )
})

test('isolation contracts: secret scanning finds private-key/credential shapes only', () => {
  assert.deepEqual(findSecretMaterial({ ok: true, secrets_enforced: true, network: { default: 'deny' } }), [])
  const hits = findSecretMaterial({
    private_key: 'x',
    nested: { api_key: 'y', value: 'sk-' + 'a'.repeat(24) },
  })
  assert.ok(hits.includes('$.private_key'))
  assert.ok(hits.includes('$.nested.api_key'))
  assert.ok(hits.some((hit) => hit === '$.nested.value'))
})

test('isolation contracts: canonical digest excludes only documented fields', () => {
  const value = { b: 2, a: 1, signature: { value: 'x' } }
  assert.equal(digestDocument(value, ['signature']), digestDocument({ a: 1, b: 2 }, []))
  assert.notEqual(digestDocument(value, []), digestDocument(value, ['signature']))
  const policy = validPolicy()
  assert.match(policyDigestOf(policy), /^sha256:[0-9a-f]{64}$/)
})

test('isolation contracts: launcher descriptor is deterministic and self-digesting', () => {
  const descriptor = externalDescriptor()
  assert.deepEqual(validateLauncherDescriptor(descriptor), { ok: true, errors: [] })
  assert.equal(providerDigestOf(descriptor), descriptor.provider_digest)
  const tampered = { ...descriptor, provider_digest: sha('0') }
  assert.equal(validateLauncherDescriptor(tampered).ok, false)
  const extraCap = {
    ...descriptor,
    capabilities: { ...descriptor.capabilities, unknown: { enforced: true } },
  }
  assert.equal(validateLauncherDescriptor(extraCap).ok, false)
})

test('isolation contracts: L1/L0 can never satisfy a market level', () => {
  assert.equal(isMarketIsolationLevel('L1-subprocess'), false)
  assert.equal(isMarketIsolationLevel('L0-in-process'), false)
  assert.equal(isMarketIsolationLevel('L2'), true)
  assert.equal(isMarketIsolationLevel('L3'), true)
  assert.equal(isolationLevelRank('L1-subprocess'), 1)
  assert.equal(isolationLevelRank('unknown'), -1)
  assert.deepEqual([...MARKET_ISOLATION_LEVELS], ['L2', 'L3'])
  assert.equal(ISOLATION_LEVEL_RANK.L3, 3)
})

test('isolation contracts: descriptor builder computes digest and defaults enforced=false', () => {
  const descriptor = buildLauncherDescriptor({
    launcher_id: 'candidate-x',
    launcher_version: '1.0.0',
    isolation: { level: 'L2', mechanisms: ['job-object'], platform: 'win32', arch: 'x64', os_build: '10' },
    capabilities: { filesystem: { mechanism: 'acl' } },
    limitations: ['candidate'],
    attestation: { method: 'control-plane-measured' },
    declared_at: '2026-10-19T00:00:00Z',
  })
  assert.equal(descriptor.capabilities.filesystem.enforced, false)
  assert.equal(descriptor.capabilities.network.enforced, false)
  assert.match(descriptor.provider_digest, /^sha256:[0-9a-f]{64}$/)
})

test('isolation contracts: reason registry exposes stable fail-closed codes', () => {
  assert.equal(ISOLATION_REASON.providerMissing, 'isolation-provider-missing')
  assert.equal(ISOLATION_REASON.levelInsufficient, 'isolation-level-insufficient')
  assert.equal(ISOLATION_REASON.dimensionUnenforced, 'isolation-dimension-unenforced')
  assert.equal(ISOLATION_REASON.workerIdentityNotLowPrivilege, 'worker-identity-not-low-privilege')
  assert.match(ISOLATION_REASON.launchBlocked, /^isolation-/)
})

test('isolation contracts: deepFreeze protects evidence from mutation', () => {
  const value = deepFreeze({ a: { b: [1, 2] } })
  assert.ok(Object.isFrozen(value))
  assert.ok(Object.isFrozen(value.a))
  assert.ok(Object.isFrozen(value.a.b))
})

test('isolation contracts: plan id format is bound to plan-sha256', () => {
  const { attestation } = fixtureAttestation()
  const bad = { ...attestation, plan_id: 'plan-1' }
  assert.equal(validateIsolationAttestation(bad).ok, false)
  const good = { ...attestation, plan_id: planId('9') }
  assert.equal(validateIsolationAttestation(good).ok, true)
})
