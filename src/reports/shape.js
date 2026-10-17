/**
 * Receipt shapes: three mutually-exclusive forms (frozen | pre-plan-blocked |
 * pre-plan-cancelled), build + verify. Guards forbid forged fields and any
 * market-eligible/signed/trust-scope violation (architecture §11.2.1;
 * plugin-reports §3 shapes).
 * @module @deepseek-ai/dsh-plugin-testbed/reports/shape
 */
import {
  ADMISSION_STATUS,
  EXECUTION_STATUS,
  GATE_DECISION,
  INVOCATION_STATUS,
  RECEIPT_SCHEMA_VERSION,
  RUN_STATUS,
  VERDICT,
} from '../protocol/enums.js'
import { recordDigest, verifyRecordDigest } from '../protocol/digest.js'

/**
 * Assemble a receipt/v1 object (incl. `integrity.record_digest` + `signed:false`).
 *
 * @param {object} parts
 * @param {'frozen'|'pre-plan-blocked'|'pre-plan-cancelled'} parts.shape
 * @param {string} [parts.runId]
 * @param {object|null} [parts.profileRef] [parts.scenarioRef] [parts.targetRef]
 * @param {object} [parts.provenance]
 * @param {string[]} [parts.limitations]
 * @param {object|null} [parts.planCandidateRef]
 * @param {object|null} [parts.planResolution]
 * @param {object|null} [parts.reconciliation]
 * @param {Array} [parts.testCases] [parts.observations] [parts.artifacts]
 * @param {string} [parts.gateDecision] [parts.gateReason] [parts.runStatus]
 * @param {string} [parts.blockedStage] [parts.cancelledStage]
 * @param {string[]} [parts.reasonCodes]
 * @returns {object} receipt/v1
 */
export function buildReceipt(parts) {
  if (!parts || typeof parts !== 'object') throw new Error('buildReceipt: parts required')
  const shape = parts.shape
  if (shape !== 'frozen' && shape !== 'pre-plan-blocked' && shape !== 'pre-plan-cancelled') {
    throw new Error(`buildReceipt: unknown shape ${String(shape)}`)
  }

  // Guards — MVP invariants; violation is a construction failure (never written).
  if (parts.trust_scope != null && parts.trust_scope !== 'local-only') {
    throw new Error('buildReceipt: trust_scope must be local-only')
  }
  if (parts.market_eligible != null && parts.market_eligible !== false) {
    throw new Error('buildReceipt: market_eligible must be false')
  }
  if (parts.signed != null && parts.signed !== false) {
    throw new Error('buildReceipt: signed must be false')
  }

  const base = {
    receipt_schema_version: RECEIPT_SCHEMA_VERSION,
    run_id: parts.runId ?? null,
    scenario_ref: parts.scenarioRef ?? null,
    profile_ref: parts.profileRef ?? null,
    trust_scope: 'local-only',
    market_eligible: false,
    target_ref: parts.targetRef ?? null,
    provenance: parts.provenance ?? {},
    limitations: parts.limitations ?? [],
  }

  let form
  if (shape === 'frozen') {
    const planId = parts.planResolution?.plan_id ?? parts.plan_id ?? null
    form = {
      run_status: parts.runStatus ?? 'completed',
      plan_id: planId,
      plan_candidate_ref: parts.planCandidateRef ?? null,
      plan_resolution: parts.planResolution ?? null,
      reconciliation: parts.reconciliation ?? null,
      test_cases: parts.testCases ?? [],
      observations: parts.observations ?? [],
      artifacts: parts.artifacts ?? [],
      gate_decision: parts.gateDecision ?? null,
    }
    if (parts.gateReason != null) form.gate_reason = parts.gateReason
  } else if (shape === 'pre-plan-blocked') {
    form = {
      run_status: 'blocked',
      plan_id: null,
      plan_candidate_ref: parts.planCandidateRef ?? null,
      reconciliation: null,
      test_cases: [],
      gate_decision: 'blocked',
      blocked_stage: parts.blockedStage ?? null,
      reason_codes: parts.reasonCodes ?? [],
    }
  } else {
    form = {
      run_status: 'cancelled',
      plan_id: null,
      plan_candidate_ref: parts.planCandidateRef ?? null,
      reconciliation: null,
      test_cases: [],
      gate_decision: 'blocked',
      cancelled_stage: parts.cancelledStage ?? null,
      reason_codes: parts.reasonCodes ?? [],
    }
  }

  const body = { ...base, ...form, integrity: { signed: false } }
  body.integrity.record_digest = recordDigest(body)
  return body
}

/**
 * Verify a persisted receipt: schema → shape → digest, in that order.
 *
 * @param {object} receipt
 * @returns {{status:'ok'|'digest-mismatch'|'shape-invalid'|'schema-invalid', detail:string}}
 */
export function verifyReceipt(receipt) {
  if (!receipt || typeof receipt !== 'object') {
    return { status: 'schema-invalid', detail: 'not-an-object' }
  }
  if (receipt.receipt_schema_version !== RECEIPT_SCHEMA_VERSION) {
    return { status: 'schema-invalid', detail: 'unknown-receipt-schema-version' }
  }
  if (typeof receipt.run_id !== 'string' || receipt.run_id.length === 0) {
    return { status: 'schema-invalid', detail: 'missing-run-id' }
  }
  if (receipt.trust_scope !== 'local-only') {
    return { status: 'schema-invalid', detail: 'trust-scope-not-local-only' }
  }
  if (receipt.market_eligible !== false) {
    return { status: 'schema-invalid', detail: 'market-eligible-not-false' }
  }
  if (!RUN_STATUS.includes(receipt.run_status)) {
    return { status: 'schema-invalid', detail: 'invalid-run-status' }
  }
  if (!GATE_DECISION.includes(receipt.gate_decision)) {
    return { status: 'schema-invalid', detail: 'invalid-gate-decision' }
  }
  const integrity = receipt.integrity
  if (
    !integrity ||
    typeof integrity !== 'object' ||
    integrity.signed !== false ||
    typeof integrity.record_digest !== 'string'
  ) {
    return { status: 'schema-invalid', detail: 'invalid-integrity' }
  }

  // Shape: the three forms are mutually exclusive.
  if (receipt.plan_id == null) {
    if (receipt.reconciliation != null) {
      return { status: 'shape-invalid', detail: 'pre-plan-must-have-null-reconciliation' }
    }
    if (!Array.isArray(receipt.test_cases) || receipt.test_cases.length !== 0) {
      return { status: 'shape-invalid', detail: 'pre-plan-must-have-empty-test-cases' }
    }
    if (receipt.gate_decision !== 'blocked') {
      return { status: 'shape-invalid', detail: 'pre-plan-must-be-blocked' }
    }
    if (receipt.plan_resolution != null) {
      return { status: 'shape-invalid', detail: 'pre-plan-must-have-null-plan-resolution' }
    }
    if (receipt.run_status === 'blocked' && receipt.cancelled_stage != null) {
      return { status: 'shape-invalid', detail: 'blocked-cannot-have-cancelled-stage' }
    }
    if (receipt.run_status === 'cancelled' && receipt.blocked_stage != null) {
      return { status: 'shape-invalid', detail: 'cancelled-cannot-have-blocked-stage' }
    }
  } else {
    const consistency = verifyFrozenCrossFields(receipt)
    if (consistency) return { status: 'shape-invalid', detail: consistency }
  }

  if (!verifyRecordDigest(receipt).ok) {
    return { status: 'digest-mismatch', detail: 'record-digest-mismatch' }
  }

  return { status: 'ok', detail: 'valid' }
}

function verifyFrozenCrossFields(receipt) {
  const plan = receipt.plan_resolution
  if (!plan || typeof plan !== 'object' || Array.isArray(plan)) return 'frozen-must-have-plan-resolution'
  if (plan.plan_id !== receipt.plan_id) return 'plan-id-mismatch'
  if (!Array.isArray(plan.test_cases)) return 'plan-test-cases-not-array'

  const planById = new Map()
  for (const item of plan.test_cases) {
    if (!item || typeof item !== 'object' || Array.isArray(item) || typeof item.test_id !== 'string' || item.test_id.length === 0) return 'plan-test-case-invalid'
    if (!['required', 'optional'].includes(item.classification)) return 'plan-test-case-classification-invalid'
    if (planById.has(item.test_id)) return 'plan-test-case-duplicate'
    planById.set(item.test_id, item)
  }

  const naIds = extractNotApplicableIds(plan.not_applicable)
  if (naIds === null || new Set(naIds).size !== naIds.length || naIds.some((id) => !planById.has(id))) return 'not-applicable-id-invalid'
  const expectedFromPlan = [...planById.keys()].filter((id) => !naIds.includes(id))

  const rec = receipt.reconciliation
  if (!rec || typeof rec !== 'object' || Array.isArray(rec)) return 'frozen-must-have-reconciliation'
  for (const key of ['expected', 'executed', 'missing', 'waived']) {
    if (!uniqueStrings(rec[key])) return `reconciliation-${key}-invalid`
  }
  if (!uniqueStrings(rec.missing_required)) return 'reconciliation-missing-required-invalid'
  if (!sameIdSet(rec.expected, expectedFromPlan)) return 'reconciliation-expected-plan-mismatch'

  const expectedSet = new Set(rec.expected)
  const partitions = [rec.executed, rec.missing, rec.waived]
  if (partitions.some((ids) => ids.some((id) => !expectedSet.has(id)))) return 'reconciliation-id-not-expected'
  if (hasOverlap(partitions)) return 'reconciliation-partitions-overlap'
  const union = [...new Set(partitions.flat())]
  if (!sameIdSet(union, rec.expected)) return 'reconciliation-partitions-incomplete'
  const requiredSet = new Set(rec.expected.filter((id) => planById.get(id)?.classification === 'required'))
  const expectedMissingRequired = rec.missing.filter((id) => requiredSet.has(id))
  if (!sameIdSet(rec.missing_required, expectedMissingRequired)) return 'missing-required-mismatch'

  if (!Array.isArray(receipt.test_cases)) return 'frozen-test-cases-not-array'
  const caseIds = []
  for (const item of receipt.test_cases) {
    if (!item || typeof item !== 'object' || Array.isArray(item) || typeof item.test_id !== 'string' || item.test_id.length === 0) return 'test-case-invalid'
    if (caseIds.includes(item.test_id)) return 'test-case-duplicate'
    caseIds.push(item.test_id)
    if (!expectedSet.has(item.test_id)) return 'test-case-id-not-expected'
    if (item.classification !== planById.get(item.test_id)?.classification) return 'test-case-classification-mismatch'
    if (!VERDICT.includes(item.verdict)) return 'test-case-verdict-invalid'
    if (item.admission_status !== undefined && !ADMISSION_STATUS.includes(item.admission_status)) return 'test-case-admission-status-invalid'
    if (item.execution_status !== undefined && !EXECUTION_STATUS.includes(item.execution_status)) return 'test-case-execution-status-invalid'
    if (!INVOCATION_STATUS.includes(item.invocation_status)) return 'test-case-invocation-status-invalid'
    if (typeof item.invocation_evidence_verified !== 'boolean') return 'test-case-invocation-evidence-invalid'
    if (item.invocation_evidence_verified && item.invocation_status !== 'started') return 'verified-invocation-not-started'
    if (item.invocation_status === 'started' && !item.invocation_evidence_verified) return 'started-invocation-unverified'
    if (item.attempts !== undefined) {
      if (!Array.isArray(item.attempts) || item.attempts.length === 0) return 'test-case-attempts-invalid'
      let priorAttempt = 0
      for (const attempt of item.attempts) {
        if (!attempt || typeof attempt !== 'object' || Array.isArray(attempt) ||
            !Number.isSafeInteger(attempt.attempt) || attempt.attempt !== priorAttempt + 1 ||
            !VERDICT.includes(attempt.verdict) || !INVOCATION_STATUS.includes(attempt.invocation_status) ||
            typeof attempt.invocation_evidence_verified !== 'boolean') return 'test-case-attempt-invalid'
        if (attempt.invocation_evidence_verified && attempt.invocation_status !== 'started') return 'verified-attempt-not-started'
        if (attempt.invocation_status === 'started' && !attempt.invocation_evidence_verified) return 'started-attempt-unverified'
        priorAttempt = attempt.attempt
      }
      const finalAttempt = item.attempts[item.attempts.length - 1]
      if (finalAttempt.verdict !== item.verdict ||
          finalAttempt.invocation_status !== item.invocation_status ||
          finalAttempt.invocation_evidence_verified !== item.invocation_evidence_verified) return 'test-case-final-attempt-mismatch'
    }
  }
  const provenance = receipt.provenance
  if (provenance && typeof provenance === 'object' && provenance.put_digest != null) return 'caller-target-digest-is-unverified'
  const cleanupFailure = provenance?.cleanup_failure ?? null
  const cleanup = provenance?.cleanup ?? null
  if (cleanupFailure !== null && (!cleanupFailure || typeof cleanupFailure !== 'object' || Array.isArray(cleanupFailure))) return 'cleanup-failure-invalid'
  if (cleanup !== null) {
    if (!cleanup || typeof cleanup !== 'object' || Array.isArray(cleanup) ||
        typeof cleanup.pid_alive !== 'boolean' || typeof cleanup.temp_removed !== 'boolean') return 'cleanup-report-invalid'
    const cleanupOk = cleanup.pid_alive === false && cleanup.temp_removed === true
    if (cleanupOk && cleanupFailure !== null) return 'cleanup-success-with-failure'
    if (!cleanupOk && cleanupFailure === null) return 'cleanup-failure-missing'
  }
  if (cleanupFailure !== null && receipt.gate_decision !== 'blocked') return 'cleanup-failure-gate-not-blocked'
  if (receipt.gate_reason === 'cleanup-failed' && cleanupFailure === null) return 'cleanup-gate-reason-without-failure'
  if (!sameIdSet(caseIds, rec.executed)) return 'test-cases-executed-mismatch'
  // Cleanup is a control-plane veto, including when a required case failed.
  if (cleanupFailure !== null) return null

  const required = rec.expected.filter((id) => planById.get(id)?.classification === 'required' && !rec.waived.includes(id))
  const records = new Map(receipt.test_cases.map((item) => [item.test_id, item]))
  if (required.length === 0) return receipt.gate_decision === 'blocked' ? null : 'gate-decision-incompatible-zero-required'
  if (rec.missing_required.length > 0) return receipt.gate_decision === 'blocked' ? null : 'gate-decision-incompatible-missing-required'
  if (required.some((id) => ['skip', 'error', 'inconclusive'].includes(records.get(id)?.verdict))) return receipt.gate_decision === 'blocked' ? null : 'gate-decision-incompatible-required-nonterminal'
  if (required.some((id) => records.get(id)?.verdict === 'fail')) return receipt.gate_decision === 'reject' ? null : 'gate-decision-incompatible-required-fail'
  if (required.every((id) => records.get(id)?.verdict === 'pass')) {
    const verifiedStartedPass = required.some((id) => {
      const record = records.get(id)
      return record?.verdict === 'pass' && record?.invocation_status === 'started' && record?.invocation_evidence_verified === true
    })
    const expectedGate = verifiedStartedPass ? 'pass' : 'blocked'
    return receipt.gate_decision === expectedGate ? null : 'gate-decision-incompatible-required-pass'
  }
  return receipt.gate_decision === 'blocked' ? null : 'gate-decision-incompatible-incomplete'
}

function extractNotApplicableIds(value) {
  if (value == null) return []
  if (!Array.isArray(value)) return null
  const ids = []
  for (const item of value) {
    if (typeof item === 'string') ids.push(item)
    else if (item && typeof item === 'object' && !Array.isArray(item) && typeof item.test_id === 'string') ids.push(item.test_id)
    else return null
  }
  return ids
}
function uniqueStrings(value) {
  return Array.isArray(value) && value.every((id) => typeof id === 'string' && id.length > 0) && new Set(value).size === value.length
}
function sameIdSet(a, b) {
  return uniqueStrings(a) && uniqueStrings(b) && a.length === b.length && a.every((id) => b.includes(id))
}
function hasOverlap(parts) {
  const seen = new Set()
  for (const ids of parts) for (const id of ids) {
    if (seen.has(id)) return true
    seen.add(id)
  }
  return false
}