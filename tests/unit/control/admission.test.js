/** Independent control-plane admission decision tests. */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { decideAdmission, ADMISSION_REASONS } from '../../../src/control/admission.js'
import { createBudgetLedger, DEFAULT_RUN_BUDGET } from '../../../src/control/budget.js'

const sha = (c) => 'sha256:' + c.repeat(64)
const toolBinding = (digest = sha('a')) => ({
  toolRef: { tool_id: 't', version: '1.0.0', artifact_digest: digest },
})

test('admission: caller-supplied admission field is not authoritative', () => {
  const caseSpec = { test_id: 'a', classification: 'required', probe: {}, admission: 'rejected' }
  const decision = decideAdmission(caseSpec, {})
  assert.equal(decision.admission_status, 'accepted')
  assert.deepEqual(decision.reason_codes, [])
  assert.equal(decision.source, 'control-plane')
})

test('admission: no observation producer is rejected by the control face', () => {
  const decision = decideAdmission({ test_id: 'a', classification: 'required', admission: 'accepted' }, {})
  assert.equal(decision.admission_status, 'rejected')
  assert.deepEqual(decision.reason_codes, [ADMISSION_REASONS.noObservationProducer])
})

test('admission: tool case without a pinned artifact binding is rejected', () => {
  const caseSpec = {
    test_id: 'a',
    classification: 'required',
    tool: { manifest: { artifact_digest: sha('a') }, input: {} },
  }
  const decision = decideAdmission(caseSpec, {})
  assert.equal(decision.admission_status, 'rejected')
  assert.ok(decision.reason_codes.includes(ADMISSION_REASONS.toolNotPinned))
})

test('admission: manifest digest mismatch against pinned tool_ref is rejected', () => {
  const caseSpec = {
    test_id: 'a',
    classification: 'required',
    tool: { manifest: { artifact_digest: sha('b') }, input: {} },
  }
  const decision = decideAdmission(caseSpec, { toolBindings: { a: toolBinding(sha('a')) } })
  assert.equal(decision.admission_status, 'rejected')
  assert.ok(decision.reason_codes.includes(ADMISSION_REASONS.toolDigestMismatch))
})

test('admission: missing/untrusted target reference is rejected for tool dispatch', () => {
  const caseSpec = {
    test_id: 'a',
    classification: 'required',
    tool: { manifest: { artifact_digest: sha('a') }, input: {} },
  }
  const nullTarget = decideAdmission(caseSpec, { toolBindings: { a: toolBinding() }, targetRef: null })
  assert.equal(nullTarget.admission_status, 'rejected')
  assert.ok(nullTarget.reason_codes.includes(ADMISSION_REASONS.targetMissing))

  const badTarget = decideAdmission(caseSpec, { toolBindings: { a: toolBinding() }, targetRef: 'C:/escape' })
  assert.equal(badTarget.admission_status, 'rejected')
  assert.ok(badTarget.reason_codes.includes(ADMISSION_REASONS.targetUnauthorized))

  const accepted = decideAdmission(caseSpec, {
    toolBindings: { a: toolBinding() },
    targetRef: { kind: 'plugin', owner_put_digest: sha('c'), origin: 'x' },
  })
  assert.equal(accepted.admission_status, 'accepted')
})

test('admission: exhausted aggregate budget is a control rejection, not a worker verdict', () => {
  const caseSpec = { test_id: 'a', classification: 'required', probe: {} }
  const ledger = createBudgetLedger({ ...DEFAULT_RUN_BUDGET, max_total_attempts: 1 })
  assert.equal(ledger.reserveAttempt(), null)
  const decision = decideAdmission(caseSpec, { budgetLedger: ledger })
  assert.equal(decision.admission_status, 'rejected')
  assert.deepEqual(decision.reason_codes, [ADMISSION_REASONS.budgetExhausted])
})

test('admission: frozen plan membership and cancellation are control facts', () => {
  const caseSpec = { test_id: 'a', classification: 'required', probe: {} }
  const outside = decideAdmission(caseSpec, { expectedSet: new Set(['b']) })
  assert.deepEqual(outside.reason_codes, [ADMISSION_REASONS.notInFrozenPlan])

  const controller = new AbortController()
  controller.abort()
  const cancelled = decideAdmission(caseSpec, { signal: controller.signal })
  assert.deepEqual(cancelled.reason_codes, [ADMISSION_REASONS.cancelled])
})
