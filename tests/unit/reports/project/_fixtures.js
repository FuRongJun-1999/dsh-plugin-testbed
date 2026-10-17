import { buildReceipt } from '../../../../src/reports/shape.js'

// A frozen receipt with one case per verdict kind + a reconciliation "missing" gap.
export function makeReceipt(overrides = {}) {
  const pass = tc('t.case-pass', 'pass', { invocation_status: 'unknown', invocation_evidence_verified: false, attempts: [attempt(1, 'pass', 'unknown', false)] })
  const fail = tc('t.case-fail', 'fail', {
    criteria_ref: 'assert/contract@1.0.0',
    reason_codes: ['equals-mismatch'],
  })
  const skip = tc('t.case-skip', 'skip', {
    admission_status: 'rejected',
    execution_status: 'skipped',
    invocation_status: 'not-started',
    reason_codes: ['policy_rejected'],
  })
  const error = tc('t.case-error', 'error', { execution_status: 'error', reason_codes: ['boom'] })
  const inconclusive = tc('t.case-inconclusive', 'inconclusive', { invocation_status: 'unknown' })

  const cases = [pass, fail, skip, error, inconclusive]
  const expected = ['t.case-pass', 't.case-fail', 't.case-skip', 't.case-error', 't.case-inconclusive', 't.case-missing']
  const executed = ['t.case-pass', 't.case-fail', 't.case-skip', 't.case-error', 't.case-inconclusive']
  const missing = ['t.case-missing']

  return buildReceipt({
    shape: 'frozen',
    runId: 'run-project',
    targetRef: { kind: 'plugin', owner_put_digest: 'sha256:' + 'ab'.repeat(32), origin: 'run-spec-unverified' },
    provenance: { put_digest: null, policy_ref: { id: 'gate-policy', version: '1.0.0' } },
    limitations: ['local-only', 'l0', 'no-signature'],
    planResolution: {
      plan_id: 'plan-sha256:proj',
      test_cases: [
        { test_id: 't.case-pass', classification: 'optional' },
        { test_id: 't.case-fail', classification: 'optional' },
        { test_id: 't.case-skip', classification: 'optional' },
        { test_id: 't.case-error', classification: 'optional' },
        { test_id: 't.case-inconclusive', classification: 'optional' },
        { test_id: 't.case-missing', classification: 'optional' },
      ],
      capability_snapshot: {},
    },
    reconciliation: { expected, executed, missing, waived: [], missing_required: [] },
    testCases: cases,
    observations: [],
    artifacts: [],
    gateDecision: 'blocked',
    gateReason: null,
    runStatus: 'completed',
    ...overrides,
  })
}

function tc(test_id, verdict, extra = {}) {
  return {
    test_id,
    classification: 'optional',
    verdict,
    admission_status: 'accepted',
    execution_status: 'completed',
    invocation_status: extra.invocation_status ?? 'unknown',
    invocation_evidence_verified: extra.invocation_evidence_verified ?? false,
    reason_codes: [],
    attempts: extra.attempts ?? [attempt(1, verdict, extra.invocation_status ?? 'unknown', extra.invocation_evidence_verified ?? false)],
    observation_refs: [],
    ...extra,
  }
}

function attempt(n, verdict, invocation_status, invocation_evidence_verified = false) {
  return {
    attempt: n,
    admission_status: 'accepted',
    execution_status: 'completed',
    invocation_status,
    invocation_evidence_verified,
    verdict,
  }
}