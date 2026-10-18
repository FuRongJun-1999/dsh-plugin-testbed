/**
 * Security gate: isolation must stay fail-closed and must never become a
 * disguised L1 path. Source scans are intentionally conservative.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  createNonceRegistry,
  verifyIsolationAttestation,
} from '../../src/isolation/attestation.js'
import { evaluateIsolationAdmission } from '../../src/isolation/admission.js'
import { collectHostFacts } from '../../src/isolation/host-capabilities.js'
import {
  FIXED_NOW,
  baseHostFacts,
  fixtureAttestation,
  fixtureExpected,
  fixtureProvider,
  planId,
  policyDigest,
  sha,
  validPolicy,
} from '../unit/isolation/fixtures.js'
import { makeIsolationPort } from '../../src/adapters/isolation-port.js'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')

function walk(dir, acc = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    const stat = statSync(path)
    if (stat.isDirectory()) walk(path, acc)
    else if (name.endsWith('.js')) acc.push(path)
  }
  return acc
}

const isolationSources = [...walk(join(ROOT, 'src', 'isolation')), join(ROOT, 'src', 'adapters', 'isolation-port.js')]

test('security: isolation runtime never holds or creates signing private keys', () => {
  const forbidden = [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
    /createPrivateKey\s*\(/,
    /generateKeyPair(?:Sync)?\s*\(/,
    /privateEncrypt\s*\(/,
    /createSign\s*\(/,
  ]
  for (const file of isolationSources) {
    const source = readFileSync(file, 'utf8')
    for (const pattern of forbidden) {
      assert.equal(pattern.test(source), false, `${file} matches ${pattern}`)
    }
  }
})

test('security: isolation modules never import the L1/L0 adapters', () => {
  for (const file of isolationSources) {
    const source = readFileSync(file, 'utf8')
    assert.equal(/from\s+['"][^'"]*adapters\/(?:subprocess|inprocess)\.js['"]/.test(source), false, file)
    assert.equal(/from\s+['"][^'"]*worker\/(?:host|runner)\.js['"]/.test(source), false, file)
  }
})

test('security: worker self-reported isolation facts are rejected', () => {
  const { attestation, descriptor } = fixtureAttestation({
    issuer: { trust: 'worker-self-reported' },
  })
  const result = verifyIsolationAttestation(attestation, fixtureExpected(attestation, descriptor), {
    now: FIXED_NOW,
    nonceRegistry: createNonceRegistry({ now: () => Date.parse(FIXED_NOW) }),
  })
  assert.equal(result.result, 'invalid')
  assert.ok(result.reason_codes.includes('isolation-unverified'))
})

test('security: forged/stale/replayed attestations are rejected', () => {
  const { attestation, descriptor } = fixtureAttestation({ issuer: { trust: 'external-provider-signed' }, signature: { alg: 'ed25519', key_id: 'k1', value: 'Zm9yZ2Vk' } })
  const expected = fixtureExpected(attestation, descriptor)
  const forged = verifyIsolationAttestation(attestation, expected, {
    now: FIXED_NOW,
    nonceRegistry: createNonceRegistry({ now: () => Date.parse(FIXED_NOW) }),
    pinnedKeys: { k1: { alg: 'ed25519', public_key: 'cHVibGlj' } },
    verifySignature: () => false,
  })
  assert.equal(forged.result, 'invalid')

  const registry = createNonceRegistry({ now: () => Date.parse(FIXED_NOW) })
  const { attestation: measured, descriptor: measuredDescriptor } = fixtureAttestation()
  const measuredExpected = fixtureExpected(measured, measuredDescriptor)
  assert.equal(verifyIsolationAttestation(measured, measuredExpected, { now: FIXED_NOW, nonceRegistry: registry }).result, 'valid')
  const replay = verifyIsolationAttestation(measured, measuredExpected, { now: FIXED_NOW, nonceRegistry: registry })
  assert.equal(replay.result, 'invalid')
  assert.ok(replay.reason_codes.includes('isolation-attestation-replay'))
})

test('security: L1 cannot be admitted as L2 even when all other inputs look valid', () => {
  const policy = validPolicy()
  const hostFacts = baseHostFacts()
  const descriptor = fixtureProvider().descriptor
  const { attestation } = fixtureAttestation({
    isolation: { level: 'L1-subprocess' },
    policy: { policy_version: 'market-gate-policy/v1', policy_digest: policyDigest(policy) },
  })
  const admission = evaluateIsolationAdmission({
    required_level: 'L2',
    provider: fixtureProvider(),
    host_facts: hostFacts,
    policy,
    attestation,
    attestation_expected: fixtureExpected(attestation, descriptor),
    nonce_registry: createNonceRegistry({ now: () => Date.parse(FIXED_NOW) }),
    now: FIXED_NOW,
  })
  assert.equal(admission.result, 'blocked')
  assert.equal(admission.market_eligibility, 'non-eligible')
  assert.ok(admission.reason_codes.includes('isolation-attestation-invalid'))
})

test('security: fixture provider without external provenance cannot be admitted', () => {
  const policy = validPolicy()
  const provider = fixtureProvider({ provenance: 'test-fixture', availability: { provenance: 'test-fixture' } })
  const { attestation } = fixtureAttestation({
    policy: { policy_version: 'market-gate-policy/v1', policy_digest: policyDigest(policy) },
  })
  const admission = evaluateIsolationAdmission({
    required_level: 'L2',
    provider,
    host_facts: baseHostFacts(),
    policy,
    attestation,
    attestation_expected: fixtureExpected(attestation, provider.descriptor),
    nonce_registry: createNonceRegistry({ now: () => Date.parse(FIXED_NOW) }),
    now: FIXED_NOW,
  })
  assert.equal(admission.result, 'blocked')
  assert.ok(admission.reason_codes.includes('fixture-not-market-evidence'))
})

test('security: real current host is High-IL administrator and cannot claim L2', () => {
  const hostFacts = collectHostFacts()
  assert.equal(hostFacts.session.elevated, true)
  assert.equal(hostFacts.session.integrity, 'high')
  assert.equal(hostFacts.market_evidence, false)
  assert.equal(hostFacts.evidence_grade, 'E0')
  const port = makeIsolationPort({ hostFacts, requiredLevel: 'L2', policy: validPolicy() })
  const precheck = port.precheck()
  assert.equal(precheck.status, 'blocked')
  assert.equal(precheck.claims.isolation_level, null)
  assert.equal(precheck.claims.market_usable, false)
  assert.ok(precheck.reason_codes.includes('worker-identity-not-low-privilege'))
})

test('security: provider availability record is required before any L2 launch', async () => {
  const port = makeIsolationPort({ hostFacts: baseHostFacts(), requiredLevel: 'L2', policy: validPolicy(), now: () => new Date(FIXED_NOW) })
  const admission = await port.admit({
    run_id: 'run-sec-1',
    plan_id: planId(),
    test_id: 'iso.sec',
    attempt: 1,
    attestation_expected: {
      denied_roots: ['C:/workspace'],
      limits: { cpu_ms: 1, memory_mb: 1, processes: 1, temp_bytes: 1, output_bytes: 1 },
      network_allowlist: [],
    },
  })
  assert.equal(admission.result, 'blocked')
  assert.equal(port.status().launch_attempted, false)
  assert.equal(port.launchRecord().isolation_level, null)
  assert.equal(port.launchRecord().market_usable, false)
  assert.equal(port.launchRecord().no_fallback, true)
})

test('security: attestation digest is content-addressed; a changed field changes the digest', () => {
  const { attestation } = fixtureAttestation()
  const { descriptor } = fixtureAttestation()
  const expected = fixtureExpected(attestation, descriptor)
  const registry = createNonceRegistry({ now: () => Date.parse(FIXED_NOW) })
  const before = verifyIsolationAttestation(attestation, expected, { now: FIXED_NOW, nonceRegistry: registry })
  const tampered = { ...attestation, resources: { ...attestation.resources, memory_mb: 999 } }
  const after = verifyIsolationAttestation(tampered, expected, {
    now: FIXED_NOW,
    nonceRegistry: createNonceRegistry({ now: () => Date.parse(FIXED_NOW) }),
  })
  assert.notEqual(before.attestation_digest, after.attestation_digest)
  assert.equal(after.result, 'invalid')
  assert.ok(after.reason_codes.includes('isolation-dimension-unenforced'))
})

test('security: source set scan is non-empty', () => {
  assert.ok(isolationSources.length >= 10)
  assert.ok(isolationSources.every((file) => file.endsWith('.js')))
})
