import { test } from 'node:test'
import assert from 'node:assert/strict'
import { resolveExitCode } from '../../../src/reports/exit.js'
import { buildReceipt } from '../../../src/reports/shape.js'

const receiptWithGate = (gateDecision) =>
  buildReceipt({
    shape: 'frozen',
    runId: 'run-1',
    targetRef: null,
    provenance: {},
    limitations: [],
    planResolution: { plan_id: 'plan-sha256:x', test_cases: [], capability_snapshot: {} },
    reconciliation: { expected: [], executed: [], missing: [], waived: [] },
    testCases: [],
    observations: [],
    artifacts: [],
    gateDecision,
    runStatus: 'completed',
  })

test('exit: write-failure → 3', () => {
  assert.equal(resolveExitCode({ kind: 'write-failure' }, 'local-selfcheck/v1'), 3)
})

test('exit: invalid receipt → 3 (any profile)', () => {
  const r = receiptWithGate('pass')
  r.receipt_schema_version = 'receipt/v2'
  assert.equal(resolveExitCode({ kind: 'receipt', receipt: r }, 'local-selfcheck/v1'), 3)
  assert.equal(resolveExitCode({ kind: 'receipt', receipt: r }, 'market-required/v1'), 3)
})

test('exit: market-required valid receipt → always 2 (even pass)', () => {
  assert.equal(resolveExitCode({ kind: 'receipt', receipt: receiptWithGate('pass') }, 'market-required/v1'), 2)
  assert.equal(resolveExitCode({ kind: 'receipt', receipt: receiptWithGate('reject') }, 'market-required/v1'), 2)
})

test('exit: local profile pass/reject/blocked → 0/1/2', () => {
  assert.equal(resolveExitCode({ kind: 'receipt', receipt: receiptWithGate('pass') }, 'local-selfcheck/v1'), 0)
  assert.equal(resolveExitCode({ kind: 'receipt', receipt: receiptWithGate('reject') }, 'local-selfcheck/v1'), 1)
  assert.equal(resolveExitCode({ kind: 'receipt', receipt: receiptWithGate('blocked') }, 'local-selfcheck/v1'), 2)
})

test('exit: unknown profile → 3', () => {
  assert.equal(resolveExitCode({ kind: 'receipt', receipt: receiptWithGate('pass') }, 'bogus/v1'), 3)
})