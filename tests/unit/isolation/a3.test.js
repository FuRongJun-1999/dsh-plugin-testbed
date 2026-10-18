/** A3 adversarial suite structure and fail-closed runner tests. */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  A3_CASES,
  A3_REQUIRED_CATEGORIES,
  evaluateA3Evidence,
  runA3Suite,
} from '../../../src/isolation/a3.js'
import {
  FIXED_NOW,
  baseHostFacts,
  fixtureA3Evidence,
  fixtureProvider,
  highIntegrityHostFacts,
} from './fixtures.js'

function l3Provider(overrides = {}) {
  const base = fixtureProvider({ availability: { level: 'L3' } })
  return {
    ...base,
    level: 'L3',
    descriptor: { ...base.descriptor, isolation: { ...base.descriptor.isolation, level: 'L3' } },
    ...overrides,
  }
}

test('a3: matrix covers the L3-07 attack families', () => {
  assert.equal(A3_CASES.length, 12)
  assert.equal(new Set(A3_CASES.map((spec) => spec.id)).size, 12)
  for (const category of A3_REQUIRED_CATEGORIES) {
    assert.ok(A3_CASES.some((spec) => spec.category === category), `missing category ${category}`)
  }
})

test('a3: current host run is all-blocked and not market evidence', async () => {
  const result = await runA3Suite({ provider: l3Provider({ availability: { available: false } }), hostFacts: highIntegrityHostFacts(), now: () => new Date(FIXED_NOW) })
  assert.equal(result.result, 'blocked')
  assert.equal(result.market_evidence, false)
  assert.equal(result.cases.length, 12)
  assert.ok(result.cases.every((item) => item.status === 'blocked'))
  assert.ok(result.reason_codes.includes('worker-identity-not-low-privilege'))
})

test('a3: L2 provider can never pass an L3 suite', async () => {
  const result = await runA3Suite({ provider: fixtureProvider(), hostFacts: baseHostFacts(), now: () => new Date(FIXED_NOW) })
  assert.equal(result.result, 'blocked')
  assert.ok(result.reason_codes.includes('isolation-level-insufficient'))
})

test('a3: fully evidenced synthetic suite evaluates as pass for the condition matrix', () => {
  const provider = l3Provider()
  const hostFacts = baseHostFacts()
  const evaluation = evaluateA3Evidence(fixtureA3Evidence({ provider, hostFacts }), {
    providerDescriptor: provider.descriptor,
    now: FIXED_NOW,
  })
  assert.equal(evaluation.result, 'pass')
  assert.equal(evaluation.market_evidence, true)
  assert.equal(evaluation.cases.length, 12)
})

test('a3: test-double provenance is never market evidence', () => {
  const provider = l3Provider()
  const hostFacts = baseHostFacts()
  const evidence = fixtureA3Evidence({ provider, hostFacts })
  evidence.provider = { ...evidence.provider, provenance: 'test-double', evidence_grade: 'E0' }
  const evaluation = evaluateA3Evidence(evidence, { providerDescriptor: provider.descriptor, now: FIXED_NOW })
  assert.equal(evaluation.result, 'blocked')
  assert.equal(evaluation.market_evidence, false)
  assert.ok(evaluation.reason_codes.includes('fixture-not-market-evidence'))
})
