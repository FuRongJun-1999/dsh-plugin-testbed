/** Public control barrel export smoke test. */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as control from '../../../src/control/index.js'

test('control: public surface exposes the six-step trusted-kernel API', () => {
  for (const name of [
    'compilePlanCandidate', 'verifyCapabilitySnapshot', 'freezePlan', 'executeFrozenPlan',
    'reconcile', 'reconcileAdoptedAttempts', 'aggregateGateDecision',
    'validateRunSpec', 'validateGatePolicy', 'validateScenario', 'verifyFrozenPlan', 'rejectPlanMutation',
    'decideAdmission', 'deriveVerification', 'applyAssertion',
  ]) {
    assert.equal(typeof control[name], 'function', name)
  }
  assert.equal(control.CAPABILITY_PREDICATE_VERSION, 'capability-predicate/v1')
  assert.ok(Array.isArray(control.AUTHORITY_FIELDS))
  assert.ok(Array.isArray(control.SUPPORTED_NODE_TYPES))
})
