import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildReceipt, verifyReceipt } from '../../../src/reports/shape.js'
import { RECEIPT_SCHEMA_VERSION } from '../../../src/protocol/enums.js'
import { compilePlanCandidate, freezePlan } from '../../../src/control/plan.js'
import { recordDigest } from '../../../src/protocol/digest.js'

const compiled = compilePlanCandidate([
  { test_id: 'req.one', node_id: 'req.one', classification: 'required', needs: [] },
  { test_id: 'opt.two', node_id: 'opt.two', classification: 'optional', needs: [] },
])
if (!compiled.ok) throw new Error(`fixture compile failed: ${compiled.errors.join(',')}`)
const frozen = freezePlan(compiled.candidate)

const frozenParts = (overrides = {}) => ({
  shape: 'frozen',
  runId: 'run-1',
  targetRef: { kind: 'plugin', owner_put_digest: 'sha256:' + 'ab'.repeat(32), origin: 'run-spec-unverified' },
  provenance: {},
  limitations: ['local-only'],
  planResolution: {
    plan_id: frozen.plan_id,
    test_cases: frozen.testCases,
    not_applicable: [],
    capability_snapshot: {},
  },
  reconciliation: {
    expected: ['req.one', 'opt.two'],
    executed: ['req.one', 'opt.two'],
    missing: [],
    waived: [],
    missing_required: [],
  },
  testCases: [
    { test_id: 'req.one', classification: 'required', verdict: 'pass', admission_status: 'accepted', execution_status: 'completed', invocation_status: 'unknown', invocation_evidence_verified: false },
    { test_id: 'opt.two', classification: 'optional', verdict: 'pass', admission_status: 'accepted', execution_status: 'completed', invocation_status: 'unknown', invocation_evidence_verified: false },
  ],
  observations: [],
  artifacts: [],
  gateDecision: 'blocked',
  runStatus: 'completed',
  ...overrides,
})

function rehash(receipt) {
  receipt.integrity.record_digest = recordDigest(receipt)
  return receipt
}

test('buildReceipt: frozen form has integrity + verify ok', () => {
  const r = buildReceipt(frozenParts())
  assert.equal(r.receipt_schema_version, RECEIPT_SCHEMA_VERSION)
  assert.equal(r.trust_scope, 'local-only')
  assert.equal(r.market_eligible, false)
  assert.equal(r.integrity.signed, false)
  assert.ok(r.integrity.record_digest.startsWith('sha256:'))
  assert.equal(verifyReceipt(r).status, 'ok')
})

test('buildReceipt: pre-plan-blocked form (null plan, no forged fields)', () => {
  const r = buildReceipt({ shape: 'pre-plan-blocked', runId: 'run-2', blockedStage: 'intake', reasonCodes: ['x'], limitations: ['local-only'] })
  assert.equal(r.run_status, 'blocked')
  assert.equal(r.plan_id, null)
  assert.equal(r.reconciliation, null)
  assert.deepEqual(r.test_cases, [])
  assert.equal(r.gate_decision, 'blocked')
  assert.equal(r.blocked_stage, 'intake')
  assert.equal(verifyReceipt(r).status, 'ok')
})

test('buildReceipt: pre-plan-cancelled form', () => {
  const r = buildReceipt({ shape: 'pre-plan-cancelled', runId: 'run-3', cancelledStage: 'execute', reasonCodes: [], limitations: [] })
  assert.equal(r.run_status, 'cancelled')
  assert.equal(r.gate_decision, 'blocked')
  assert.equal(r.plan_id, null)
  assert.equal(verifyReceipt(r).status, 'ok')
})

test('verifyReceipt: digest-mismatch on tamper', () => {
  const r = buildReceipt(frozenParts())
  r.limitations.push('tampered')
  assert.equal(verifyReceipt(r).status, 'digest-mismatch')
})

test('verifyReceipt: schema-invalid on unknown version / market_eligible true', () => {
  const r = buildReceipt(frozenParts())
  r.receipt_schema_version = 'receipt/v2'
  assert.equal(verifyReceipt(r).status, 'schema-invalid')

  const r2 = buildReceipt(frozenParts())
  r2.market_eligible = true
  assert.equal(verifyReceipt(r2).status, 'schema-invalid')
})

test('verifyReceipt: shape-invalid (plan null but reconciliation present)', () => {
  const r = buildReceipt(frozenParts())
  r.plan_id = null
  assert.equal(verifyReceipt(r).status, 'shape-invalid')
})

test('verifyReceipt: a required pass verdict without independent invocation evidence cannot forge a passing gate', () => {
  const r = buildReceipt(frozenParts({ gateDecision: 'pass' }))
  assert.equal(verifyReceipt(r).status, 'shape-invalid')
  assert.equal(verifyReceipt(r).detail, 'gate-decision-incompatible-required-pass')
})

test('verifyReceipt: an unverified started attempt is rejected', () => {
  const parts = frozenParts()
  parts.testCases[0] = {
    ...parts.testCases[0],
    attempts: [{ attempt: 1, verdict: 'pass', invocation_status: 'started', invocation_evidence_verified: false }],
  }
  const r = buildReceipt(parts)
  assert.equal(verifyReceipt(r).status, 'shape-invalid')
  assert.equal(verifyReceipt(r).detail, 'started-attempt-unverified')
})

test('verifyReceipt: cleanup failure must force a blocked gate', () => {
  const r = buildReceipt(frozenParts({
    gateDecision: 'pass',
    provenance: {
      cleanup: { pid_alive: true, temp_removed: false },
      cleanup_failure: { reason: 'cleanup-failed' },
    },
  }))
  assert.equal(verifyReceipt(r).status, 'shape-invalid')
  assert.equal(verifyReceipt(r).detail, 'cleanup-failure-gate-not-blocked')
})

test('buildReceipt: guards throw on market_eligible/trust_scope/unknown shape', () => {
  assert.throws(() => buildReceipt(frozenParts({ market_eligible: true })))
  assert.throws(() => buildReceipt({ shape: 'frozen', market_eligible: true }))
  assert.throws(() => buildReceipt({ shape: 'nope' }))
  assert.throws(() => buildReceipt(frozenParts({ trust_scope: 'market' })))
})