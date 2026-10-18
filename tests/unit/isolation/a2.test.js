/** A2 adversarial suite structure and fail-closed runner tests. */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  A2_CASES,
  A2_REQUIRED_CATEGORIES,
  evaluateA2Evidence,
  runA2Suite,
} from '../../../src/isolation/a2.js'
import {
  FIXED_NOW,
  baseHostFacts,
  fixtureA2Evidence,
  fixtureProvider,
  highIntegrityHostFacts,
} from './fixtures.js'

test('a2: matrix covers A2-01..A2-18 exactly once', () => {
  assert.equal(A2_CASES.length, 18)
  assert.deepEqual(A2_CASES.map((spec) => spec.id), Array.from({ length: 18 }, (_, index) => `A2-${String(index + 1).padStart(2, '0')}`))
  assert.equal(new Set(A2_CASES.map((spec) => spec.id)).size, 18)
  for (const category of A2_REQUIRED_CATEGORIES) {
    assert.ok(A2_CASES.some((spec) => spec.category === category), `missing category ${category}`)
  }
})

test('a2: current host run is all-blocked, never pass and never market evidence', async () => {
  const result = await runA2Suite({ provider: fixtureProvider({ availability: { available: false, reason_codes: ['isolation-provider-missing'] } }), hostFacts: highIntegrityHostFacts(), now: () => new Date(FIXED_NOW) })
  assert.equal(result.result, 'blocked')
  assert.equal(result.market_evidence, false)
  assert.equal(result.executed, false)
  assert.equal(result.cases.length, 18)
  assert.ok(result.cases.every((item) => item.status === 'blocked'))
  assert.ok(result.reason_codes.includes('worker-identity-not-low-privilege'))
})

test('a2: unavailable provider blocks every case regardless of host facts', async () => {
  const result = await runA2Suite({ provider: fixtureProvider({ availability: { available: false } }), hostFacts: baseHostFacts(), now: () => new Date(FIXED_NOW) })
  assert.equal(result.result, 'blocked')
  assert.ok(result.cases.every((item) => item.status === 'blocked'))
  assert.equal(result.market_evidence, false)
})

test('a2: provider-derived blocked cases stay blocked and are not summarized as pass', async () => {
  const provider = fixtureProvider()
  provider.runAdversarialCase = async (spec) => ({ case_id: spec.id, status: 'blocked', reason_codes: ['precondition-missing'] })
  const result = await runA2Suite({ provider, hostFacts: baseHostFacts(), now: () => new Date(FIXED_NOW) })
  assert.equal(result.result, 'blocked')
  assert.equal(result.market_evidence, false)
})

test('a2: fully evidenced synthetic suite evaluates as pass for the condition matrix', () => {
  const provider = fixtureProvider()
  const hostFacts = baseHostFacts()
  const evaluation = evaluateA2Evidence(fixtureA2Evidence({ provider, hostFacts }), {
    providerDescriptor: provider.descriptor,
    now: FIXED_NOW,
  })
  assert.equal(evaluation.result, 'pass')
  assert.equal(evaluation.market_evidence, true)
  assert.equal(evaluation.cases.length, 18)
  assert.deepEqual(evaluation.diagnostics, [])
})

test('a2: pass cases without reproducible evidence are downgraded to blocked', () => {
  const provider = fixtureProvider()
  const hostFacts = baseHostFacts()
  const evidence = fixtureA2Evidence({ provider, hostFacts })
  evidence.cases[0] = { ...evidence.cases[0], command: null, observed: null, evidence_refs: [] }
  const evaluation = evaluateA2Evidence(evidence, { providerDescriptor: provider.descriptor, now: FIXED_NOW })
  assert.equal(evaluation.result, 'blocked')
  assert.equal(evaluation.market_evidence, false)
  assert.ok(evaluation.diagnostics.some((item) => item.includes('case-pass-without-evidence')))
})

test('a2: missing and unknown cases invalidate the suite', () => {
  const provider = fixtureProvider()
  const hostFacts = baseHostFacts()
  const missing = fixtureA2Evidence({ provider, hostFacts })
  missing.cases = missing.cases.slice(0, 17)
  assert.equal(evaluateA2Evidence(missing, { providerDescriptor: provider.descriptor, now: FIXED_NOW }).result, 'blocked')

  const unknown = fixtureA2Evidence({ provider, hostFacts })
  unknown.cases.push({ ...unknown.cases[0], case_id: 'A2-99' })
  const result = evaluateA2Evidence(unknown, { providerDescriptor: provider.descriptor, now: FIXED_NOW })
  assert.equal(result.result, 'blocked')
  assert.ok(result.diagnostics.some((item) => item.includes('case-unknown:A2-99')))
})
