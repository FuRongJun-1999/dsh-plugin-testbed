/**
 * Shared fixtures for the market evidence unit tests.
 *
 * Everything here is E0/E1 test data (`controlled-fixture`, `development-only`).
 * It is used to exercise code paths and negative tests — never as market
 * evidence. The receipt is built with a locally recomputed `record_digest`
 * exactly like the existing protocol tests do.
 */
import { recordDigest } from '../../../src/protocol/digest.js'
import { buildMarketAttestation } from '../../../src/evidence/attestation.js'

export const DIGEST = (ch) => 'sha256:' + ch.repeat(64)
export const PLAN_ID = 'plan-sha256:' + '6'.repeat(64)
export const FIXED_TIME = '2026-01-01T00:00:00.000Z'
export const ARCHIVE_ID = 'run-evidence-001'
export const ARCHIVE_PROVIDER_ID = 'development-archive-local-file'

/**
 * Build a strictly valid `receipt/v1` frozen-form document (local-only,
 * unsigned). Its `record_digest` is recomputed over the canonical body.
 * @returns {object}
 */
export function makeValidReceipt() {
  const receipt = {
    receipt_schema_version: 'receipt/v1',
    run_id: 'run-evidence-001',
    plan_id: PLAN_ID,
    scenario_ref: { id: 'plugin-baseline', version: '1.0.0', digest: DIGEST('2') },
    profile_ref: { id: 'smoke', version: '1.0.0', digest: DIGEST('8') },
    target_ref: { kind: 'api', owner_put_digest: DIGEST('3'), origin: 'http://127.0.0.1:4001' },
    trust_scope: 'local-only',
    market_eligible: false,
    run_status: 'completed',
    gate_decision: 'pass',
    plan_candidate_ref: {
      digest: DIGEST('b'),
      baseline_test_ids: ['contract.login.schema'],
      required_test_ids: ['contract.login.schema'],
    },
    provenance: {
      put_digest: DIGEST('3'),
      dsh_commit: '0123456789abcdef0123456789abcdef01234567',
      cordis_version: '4.0.5',
      adapter_ref: 'local-worker-json@1.0.0',
      tool_refs: [{ tool_id: 'example.api-contract', version: '1.0.0', artifact_digest: DIGEST('1') }],
      assertion_refs: ['assert/login-contract@1.0.0'],
      policy_ref: { id: 'gate-policy', version: '1.0.0', digest: DIGEST('a') },
      environment_fingerprint: DIGEST('4'),
    },
    limitations: ['local-only', 'l1-local-only', 'no-external-trust-anchor'],
    integrity: { record_digest: DIGEST('0'), signed: false },
    plan_resolution: [{ test_id: 'contract.login.schema', classification: 'required' }],
    reconciliation: {
      expected: ['contract.login.schema'],
      executed: ['contract.login.schema'],
      missing: [],
      waived: [],
      missing_required: [],
    },
    test_cases: [{
      test_id: 'contract.login.schema',
      dimensions: {
        test_level: 'component-integration',
        test_type: ['functional'],
        test_technique: ['contract'],
        trigger: 'manual',
        suite_profile: 'smoke',
        target_kind: 'api',
        execution_mode: 'mock',
        repeatability: 'environment-bound',
        evidence_kind: ['assertion', 'artifact'],
      },
      attempts: [{
        attempt: 1,
        admission_status: 'accepted',
        execution_status: 'completed',
        invocation_status: 'started',
        started_at: '2026-10-16T04:29:01Z',
        ended_at: '2026-10-16T04:29:03Z',
        verdict: 'pass',
        observation_refs: ['obs-001'],
      }],
      verdict: 'pass',
      criteria_ref: 'assert/login-contract@1.0.0',
      reason_codes: [],
    }],
    observations: [{
      observation_id: 'obs-001',
      schema_ref: 'urn:example:tool:api-contract:observation:v1',
      value: { status_code: 200, body: { user_id: 'fixture-user-001' } },
      source: 'worker',
      limitations: ['controlled-fixture'],
    }],
    artifacts: [{ kind: 'log', digest: DIGEST('5'), size_bytes: 412 }],
  }
  receipt.integrity.record_digest = recordDigest(receipt)
  return receipt
}

/**
 * Build an eligibility record *for tests* — this is an injected control-plane
 * stand-in, not the market gate. The final evidence sequence still rejects it
 * because the providers are development-only.
 * @param {{
 *   manifestDigest: string,
 *   decision?: 'eligible'|'non-eligible',
 *   reasonCodes?: string[],
 * }} input
 * @returns {object}
 */
export function makeEligibility(input) {
  const decision = input.decision ?? 'eligible'
  return {
    schema_version: 'market-eligibility/v1',
    decision_id: `decision-${input.manifestDigest.slice(-12)}`,
    decision,
    run_id: 'run-evidence-001',
    receipt_digest: DIGEST('9'),
    policy: { id: 'market-gate-policy', version: '1.0.0', digest: DIGEST('a') },
    evaluated_at: '2026-01-01T00:00:00Z',
    conditions: [{
      id: 'MKT-C01',
      status: decision === 'eligible' ? 'pass' : 'fail',
      evidence_refs: ['fixture:controlled'],
      reason_code: decision === 'eligible' ? null : 'isolation-provider-missing',
    }],
    reason_codes: decision === 'eligible' ? [] : (input.reasonCodes ?? ['isolation-provider-missing']),
    blockers: decision === 'eligible' ? [] : [{ condition_id: 'MKT-C01', reason_code: 'isolation-provider-missing' }],
    approvals: [],
    evidence_manifest_digest: input.manifestDigest,
    limitations: ['controlled-fixture', 'not-market-evidence'],
  }
}

/** Shared control plane / runtime / isolation evidence inputs (fixture). */
export const CONTROL_PLANE = Object.freeze({
  id: 'control-plane-development',
  version: '0.0.1-development',
  policy_ref: {
    id: 'market-gate-policy',
    version: '1.0.0',
    digest: DIGEST('a'),
  },
})

export const RUNTIME_REF = Object.freeze({
  cordis_version: '4.0.5',
  dsh_version: '0.2.1-rc.2',
  anchor_digest: DIGEST('7'),
  contract_suite_digest: DIGEST('d'),
})

export const ISOLATION_REF = Object.freeze({
  level: 'L1',
  attestation_digest: DIGEST('e'),
  verification_digest: DIGEST('f'),
})

export const POLICY_REF = Object.freeze({
  id: 'market-gate-policy',
  version: '1.0.0',
  digest: DIGEST('a'),
})

/**
 * Build a valid `archive-anchor/v1` for signing/attestation tests. This is a
 * synthetic anchor for code-path tests only (no real archive provider exists).
 * @param {object} receipt
 * @param {object} [overrides]
 * @returns {object}
 */
export function makeSubjectAnchor(receipt, overrides = {}) {
  return {
    schema_version: 'archive-anchor/v1',
    anchor_id: `${ARCHIVE_ID}:1:${DIGEST('1')}`,
    provider_id: ARCHIVE_PROVIDER_ID,
    archive_id: ARCHIVE_ID,
    sequence: 1,
    entry_digest: DIGEST('1'),
    previous_entry_digest: null,
    receipt_digest: recordDigest(receipt),
    archived_at: FIXED_TIME,
    trust_anchor: { type: 'none-development-only', key_id: null, verification_ref: null },
    trusted_time: {
      source: 'host-clock-development-only',
      verified: false,
      reference: 'development-trusted-time',
    },
    provider_audit_ref: 'dev-archive:run-evidence-001:1:anchor',
    ...overrides,
  }
}

/**
 * Build an unsigned `market-attestation/v1` draft for signing tests.
 * @param {{
 *   receipt?: object,
 *   signing: object,
 *   subjectAnchor?: object,
 *   eligibility?: object,
 *   overrides?: object,
 * }} input
 * @returns {object}
 */
export function makeAttestationDraft(input) {
  const receipt = input.receipt ?? makeValidReceipt()
  const subjectAnchor = input.subjectAnchor ?? makeSubjectAnchor(receipt)
  const eligibility = input.eligibility ?? makeEligibility({
    manifestDigest: DIGEST('b'),
  })
  const draft = buildMarketAttestation({
    attestationId: 'attestation-fixture-001',
    receipt,
    eligibility,
    controlPlane: CONTROL_PLANE,
    isolation: ISOLATION_REF,
    runtime: RUNTIME_REF,
    subjectAnchor,
    signing: input.signing,
    limitations: ['controlled-fixture'],
    ...input.overrides,
  })
  return { draft, receipt, subjectAnchor, eligibility }
}
