/**
 * A2 adversarial-suite security acceptance.
 *
 * No case may be reported as pass when it was not executed under a measured L2
 * provider and a low-privilege identity. On this host every A2 case is blocked.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  A2_CASES,
  A2_REQUIRED_CATEGORIES,
  evaluateA2Evidence,
  runA2Suite,
} from '../../src/isolation/a2.js'
import { createProviderCatalog } from '../../src/isolation/providers.js'
import { collectHostFacts } from '../../src/isolation/host-capabilities.js'
import { makeIsolationPort } from '../../src/adapters/isolation-port.js'
import {
  FIXED_NOW,
  baseHostFacts,
  fixtureA2Evidence,
  fixtureProvider,
  highIntegrityHostFacts,
  validPolicy,
} from '../unit/isolation/fixtures.js'

test('security-a2: covers files, credentials, network, process, resources, reap, forged attestation and downgrade', () => {
  const categories = new Set(A2_CASES.map((spec) => spec.category))
  for (const required of ['filesystem', 'credentials', 'network', 'process', 'resources', 'reap', 'forged-attestation', 'downgrade']) {
    assert.ok(categories.has(required), `missing A2 category: ${required}`)
    assert.ok(A2_REQUIRED_CATEGORIES.includes(required))
  }
  assert.equal(A2_CASES.length, 18)
})

test('security-a2: current host cannot pass A2 or use L1 as L2', async () => {
  const hostFacts = collectHostFacts()
  const catalog = createProviderCatalog({ hostFacts })
  const provider = catalog.find((item) => item.provider_id === 'windows-appcontainer-l2')
  const suite = await runA2Suite({ provider, hostFacts, now: () => new Date(FIXED_NOW) })
  assert.equal(suite.result, 'blocked')
  assert.equal(suite.market_evidence, false)
  assert.equal(suite.executed, false)
  assert.equal(suite.cases.length, 18)
  assert.ok(suite.cases.every((item) => item.status === 'blocked'))
  assert.ok(suite.reason_codes.includes('worker-identity-not-low-privilege'))

  const port = makeIsolationPort({ hostFacts, requiredLevel: 'L2', policy: validPolicy() })
  assert.equal(port.precheck().status, 'blocked')
  assert.equal(port.launchRecord().isolation_level, null)
})

test('security-a2: a blocked case cannot be relabeled as pass without reproducible evidence', () => {
  const provider = fixtureProvider()
  const hostFacts = baseHostFacts()
  const evidence = fixtureA2Evidence({ provider, hostFacts })
  evidence.cases[0] = { ...evidence.cases[0], status: 'pass', command: null, observed: null, evidence_refs: [], at: null }
  const evaluation = evaluateA2Evidence(evidence, { providerDescriptor: provider.descriptor, now: FIXED_NOW })
  assert.equal(evaluation.result, 'blocked')
  assert.equal(evaluation.market_evidence, false)
})

test('security-a2: A2 evidence from an elevated/high-IL executor is blocked', () => {
  const provider = fixtureProvider()
  const evidence = fixtureA2Evidence({ provider, hostFacts: baseHostFacts() })
  evidence.executor.identity.elevated = true
  evidence.executor.identity.integrity = 'high'
  const evaluation = evaluateA2Evidence(evidence, { providerDescriptor: provider.descriptor, now: FIXED_NOW })
  assert.equal(evaluation.result, 'blocked')
  assert.ok(evaluation.reason_codes.includes('worker-identity-not-low-privilege'))
})

test('security-a2: A2 evidence with a fixture/test-double provider is not market evidence', () => {
  const provider = fixtureProvider()
  const evidence = fixtureA2Evidence({ provider, hostFacts: baseHostFacts() })
  evidence.provider = { ...evidence.provider, provenance: 'test-fixture' }
  const evaluation = evaluateA2Evidence(evidence, { providerDescriptor: provider.descriptor, now: FIXED_NOW })
  assert.equal(evaluation.result, 'blocked')
  assert.equal(evaluation.market_evidence, false)
})

test('security-a2: A2-13 forged worker self-report cannot influence admission', async () => {
  const port = makeIsolationPort({ hostFacts: highIntegrityHostFacts(), requiredLevel: 'L2', policy: validPolicy(), now: () => new Date(FIXED_NOW) })
  const admission = await port.admit({
    run_id: 'run-a2-forged',
    plan_id: 'plan-sha256:' + 'a'.repeat(64),
    test_id: 'iso.a2-13',
    attempt: 1,
    attestation_expected: {
      denied_roots: ['C:/workspace'],
      limits: { cpu_ms: 1, memory_mb: 1, processes: 1, temp_bytes: 1, output_bytes: 1 },
      network_allowlist: [],
    },
    attestation: { schema_version: 'isolation-attestation/v1', isolation: { level: 'L2', elevated: false } },
  })
  assert.equal(admission.result, 'blocked')
  assert.equal(admission.market_eligibility, 'non-eligible')
})

test('security-a2: A2-18 downgrade path is blocked at every layer', () => {
  assert.throws(() => makeIsolationPort({ requiredLevel: 'L1-subprocess', hostFacts: baseHostFacts() }), /market isolation requires L2 or L3/)
  const catalog = createProviderCatalog({ hostFacts: baseHostFacts() })
  assert.ok(catalog.every((provider) => provider.level === 'L2' || provider.level === 'L3'))
  assert.ok(catalog.every((provider) => provider.availability.available === false))
})
