/**
 * GatePolicy aggregation (`gate/` in implementation-design-control §9,
 * architecture §6.1). Pure control-plane function; the same frozen inputs can
 * be recomputed offline and must produce the same decision.
 *
 * Fixed precedence:
 *   1. missing/invalid plan or reconciliation, empty plan / zero required,
 *      `missing_required` non-empty          → blocked
 *   2. any unwaived required skip/error/inconclusive → blocked
 *   3. otherwise any required fail              → reject
 *   4. all unwaived required pass **and** at least one required has a
 *      control-verified `invocation_status=started` + `verdict=pass` → pass
 *   5. everything else                          → blocked
 *
 * The record set is a control-plane artifact: worker/caller authority fields
 * (`gate_decision`, `required`, `expected`, `plan`, …) are rejected, a
 * caller-supplied `admission` field on the frozen plan is rejected, and a bare
 * adapter `started` report without independent evidence never counts.
 *
 * Migration phase `pure control`: untrusted inputs stay `unknown`, the
 * validated projection is typed, and every decision/reason remains identical.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/control/gate
 */
import { ADMISSION_STATUS, EXECUTION_STATUS, INVOCATION_STATUS, VERDICT, inSet } from '../protocol/enums.js'
import { hasVerifiedStartedPass } from './state.js'
import type { UnknownRecord } from '../protocol/types.js'

/** Final aggregated gate decision (never a verdict). */
export interface GateResult {
  gate_decision: 'pass' | 'reject' | 'blocked'
  reason: string
  optional_issues?: Array<{ test_id: string; verdict: unknown; issue: string }>
}

interface AdoptedRecord {
  verdict?: unknown
  invocation_status?: unknown
  admission_status?: unknown
  execution_status?: unknown
  invocation_evidence_verified?: unknown
  [key: string]: unknown
}

interface ValidatedInputs {
  error: null
  expected: string[]
  required: string[]
  records: Record<string, AdoptedRecord>
  waived: string[]
  startedClaim: boolean
}

interface InvalidInputs {
  error: string
}

const AUTHORITY_FIELDS: readonly string[] = Object.freeze([
  'gate_decision', 'required', 'expected', 'plan', 'plan_resolution', 'run_status',
  'gate', 'worker_verdict', 'admission_decision', 'admission_source',
])

/**
 * Aggregate a GateDecision from the frozen plan, the control reconciliation and
 * the control-plane adopted records.
 */
export function aggregateGateDecision(
  frozenPlan: unknown,
  reconciliation: unknown,
  recordsByTestId: unknown,
): GateResult {
  const validation = validateInputs(frozenPlan, reconciliation, recordsByTestId)
  if (validation.error !== null) return { gate_decision: 'blocked', reason: validation.error }

  const { expected, required, records, waived, startedClaim } = validation
  const requiredSet = new Set(required)
  const waivedSet = new Set(waived)
  const unwaivedRequired = required.filter((id) => !waivedSet.has(id))
  const recon = reconciliation as UnknownRecord
  const missingRequired = recon.missing_required as string[]
  const optionalIssues = expected
    .filter((id) => !requiredSet.has(id))
    .map((id) => {
      const record = records[id]
      if (!record) return { test_id: id, verdict: null, issue: 'missing' }
      if (record.verdict === 'pass') return null
      return { test_id: id, verdict: record.verdict, issue: 'non-pass' }
    })
    .filter((issue): issue is { test_id: string; verdict: unknown; issue: string } => issue !== null)
  const result = (gateDecision: 'pass' | 'reject' | 'blocked', reason: string): GateResult =>
    ({ gate_decision: gateDecision, reason, optional_issues: optionalIssues })

  if (unwaivedRequired.length === 0) return result('blocked', 'zero-required')
  if (missingRequired.length > 0) return result('blocked', 'missing-required')

  for (const id of unwaivedRequired) {
    const record = records[id]
    if (!record || record.verdict === 'skip' || record.verdict === 'error' || record.verdict === 'inconclusive') {
      return result('blocked', record ? `required-${String(record.verdict)}` : 'required-incomplete')
    }
  }
  for (const id of unwaivedRequired) {
    if (records[id].verdict === 'fail') return result('reject', 'required-fail')
  }

  const allPass = unwaivedRequired.every((id) => records[id].verdict === 'pass')
  if (allPass) {
    const verifiedStartedPass = unwaivedRequired.some((id) => hasVerifiedStartedPass(records[id]))
    if (verifiedStartedPass) return result('pass', 'all-required-pass-started')
    const claimedStartedPass = unwaivedRequired.some((id) =>
      records[id].verdict === 'pass' && records[id].invocation_status === 'started')
    if (claimedStartedPass || startedClaim) {
      return result('blocked', 'invocation-evidence-unverified')
    }
    return result('blocked', 'no-required-started-pass')
  }

  return result('blocked', 'required-incomplete')
}

/**
 * Validate all inputs and derive the reconciliation-relevant sets.
 */
function validateInputs(
  frozenPlan: unknown,
  reconciliation: unknown,
  recordsByTestId: unknown,
): ValidatedInputs | InvalidInputs {
  if (!frozenPlan || typeof frozenPlan !== 'object' || Array.isArray(frozenPlan) ||
      !Array.isArray((frozenPlan as UnknownRecord).required) ||
      !reconciliation || typeof reconciliation !== 'object' ||
      Array.isArray(reconciliation) || !Array.isArray((reconciliation as UnknownRecord).missing_required) ||
      !recordsByTestId || typeof recordsByTestId !== 'object' || Array.isArray(recordsByTestId)) {
    return { error: 'inconsistent-reconciliation' }
  }
  const plan = frozenPlan as UnknownRecord
  const recon = reconciliation as UnknownRecord
  const recordSet = recordsByTestId as UnknownRecord
  if (Array.isArray(plan.testCases)) {
    for (const raw of plan.testCases) {
      if (!raw || typeof raw !== 'object') continue
      const caseSpec = raw as UnknownRecord
      if (Object.hasOwn(caseSpec, 'admission')) return { error: 'caller-admission-not-authoritative' }
      for (const field of AUTHORITY_FIELDS) {
        if (Object.hasOwn(caseSpec, field)) return { error: 'inconsistent-reconciliation' }
      }
    }
  }

  const expected = plan.expected ?? plan.required
  if (!uniqueStringArray(expected) || !uniqueStringArray(plan.required)) {
    return { error: 'inconsistent-reconciliation' }
  }
  const expectedIds = expected as string[]
  const requiredIds = plan.required as string[]
  const expectedSet = new Set(expectedIds)
  const requiredSet = new Set(requiredIds)
  if ([...requiredSet].some((id) => !expectedSet.has(id))) return { error: 'inconsistent-reconciliation' }

  const waived = recon.waived ?? []
  if (!uniqueStringArray(waived)) return { error: 'inconsistent-reconciliation' }
  const allowlist = plan.waiverAllowlist ?? []
  if (!uniqueStringArray(allowlist)) return { error: 'inconsistent-reconciliation' }
  const waivedIds = waived as string[]
  const allowSet = new Set(allowlist as string[])
  if (waivedIds.some((id) => !expectedSet.has(id) || !allowSet.has(id))) return { error: 'inconsistent-reconciliation' }

  const resultIds = Object.keys(recordSet)
  if (resultIds.some((id) => !expectedSet.has(id))) return { error: 'inconsistent-reconciliation' }
  let startedClaim = false
  for (const id of resultIds) {
    const rawRecord = recordSet[id]
    if (!rawRecord || typeof rawRecord !== 'object' || Array.isArray(rawRecord)) return { error: 'inconsistent-reconciliation' }
    const record = rawRecord as UnknownRecord
    for (const field of AUTHORITY_FIELDS) {
      if (Object.hasOwn(record, field)) return { error: `worker-authority-field:${field}` }
    }
    if (!inSet(VERDICT, record.verdict) || !inSet(INVOCATION_STATUS, record.invocation_status)) {
      return { error: 'inconsistent-reconciliation' }
    }
    if (record.admission_status !== undefined && !inSet(ADMISSION_STATUS, record.admission_status)) {
      return { error: 'inconsistent-reconciliation' }
    }
    if (record.execution_status !== undefined && !inSet(EXECUTION_STATUS, record.execution_status)) {
      return { error: 'inconsistent-reconciliation' }
    }
    if (record.invocation_evidence_verified !== undefined && typeof record.invocation_evidence_verified !== 'boolean') {
      return { error: 'inconsistent-reconciliation' }
    }
    if (record.invocation_evidence_verified === true && record.invocation_status !== 'started') {
      return { error: 'inconsistent-reconciliation' }
    }
    if (record.invocation_status === 'started' && record.invocation_evidence_verified !== true) {
      startedClaim = true
    }
    if (record.admission_status === 'rejected') {
      if (record.execution_status !== 'skipped' || record.verdict !== 'skip' ||
          record.invocation_status !== 'not-started') {
        return { error: 'inconsistent-reconciliation' }
      }
    }
  }

  const executed = expectedIds.filter((id) => Object.hasOwn(recordSet, id))
  const waivedSet = new Set(waivedIds)
  const missing = expectedIds.filter((id) => !Object.hasOwn(recordSet, id) && !waivedSet.has(id))
  const missingRequired = missing.filter((id) => requiredSet.has(id))
  if (!sameOptionalSet(recon.expected, expectedIds)) return { error: 'inconsistent-reconciliation' }
  if (!sameOptionalSet(recon.executed, executed)) return { error: 'inconsistent-reconciliation' }
  if (!sameOptionalSet(recon.missing, missing)) return { error: 'inconsistent-reconciliation' }
  if (!sameOptionalSet(recon.missing_required, missingRequired)) return { error: 'inconsistent-reconciliation' }
  if (recon.waived !== undefined && !sameOptionalSet(recon.waived, waivedIds)) {
    return { error: 'inconsistent-reconciliation' }
  }
  return { error: null, expected: expectedIds, required: requiredIds, records: recordSet as Record<string, AdoptedRecord>, waived: waivedIds, startedClaim }
}

function uniqueStringArray(value: unknown): boolean {
  return Array.isArray(value) && value.every((item) => typeof item === 'string' && item.length > 0) && new Set(value).size === value.length
}

function sameOptionalSet(actual: unknown, expected: string[]): boolean {
  if (actual === undefined) return true // legacy partial reconciliation; missing_required is still verified
  if (!uniqueStringArray(actual)) return false
  const actualIds = actual as string[]
  if (actualIds.length !== expected.length) return false
  const expectedSet = new Set(expected)
  return actualIds.every((id) => expectedSet.has(id))
}
