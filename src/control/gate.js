/**
 * GatePolicy aggregation (blocked > reject > pass). Pure control-plane function.
 * The supplied reconciliation is treated as a claim and checked against the
 * frozen plan and actual adopted records before it can affect the decision.
 * @module @deepseek-ai/dsh-plugin-testbed/control/gate
 */
import { VERDICT, INVOCATION_STATUS } from '../protocol/enums.js'

/**
 * @param {{expected?:string[], required:string[], waiverAllowlist?:string[]}} frozenPlan
 * @param {{expected?:string[], executed?:string[], missing?:string[], waived?:string[], missing_required:string[]}} reconciliation
 * @param {Record<string, {verdict:string, invocation_status:string}>} recordsByTestId
 * @param {{invocationEvidenceVerified?:boolean}} [options] Control-plane-only
 *   evidence that at least one started invocation was independently observed by
 *   the adapter. Caller-provided `invocation_status` is never sufficient.
 */
export function aggregateGateDecision(frozenPlan, reconciliation, recordsByTestId, options = {}) {
  const invocationEvidenceVerified = options?.invocationEvidenceVerified === true
  const consistencyError = validateReconciliation(frozenPlan, reconciliation, recordsByTestId)
  if (consistencyError) return { gate_decision: 'blocked', reason: 'inconsistent-reconciliation' }

  const expected = frozenPlan.expected ?? frozenPlan.required
  const requiredSet = new Set(frozenPlan.required)
  const waivedSet = new Set(reconciliation.waived ?? [])
  const required = frozenPlan.required.filter((id) => !waivedSet.has(id))
  const missingRequired = reconciliation.missing_required

  if (required.length === 0) return { gate_decision: 'blocked', reason: 'zero-required' }
  if (missingRequired.length > 0) return { gate_decision: 'blocked', reason: 'missing-required' }

  const records = recordsByTestId
  for (const id of required) {
    const rec = records[id]
    if (rec.verdict === 'skip' || rec.verdict === 'error' || rec.verdict === 'inconclusive') {
      return { gate_decision: 'blocked', reason: `required-${rec.verdict}` }
    }
  }
  for (const id of required) {
    if (records[id].verdict === 'fail') return { gate_decision: 'reject', reason: 'required-fail' }
  }

  const allPass = required.length > 0 && required.every((id) => records[id]?.verdict === 'pass')
  if (allPass) {
    const anyStartedPass = required.some((id) =>
      records[id]?.invocation_status === 'started' && records[id]?.verdict === 'pass')
    if (!anyStartedPass) return { gate_decision: 'blocked', reason: 'no-required-started-pass' }
    if (!invocationEvidenceVerified) return { gate_decision: 'blocked', reason: 'invocation-evidence-unverified' }
    return { gate_decision: 'pass', reason: 'all-required-pass-started' }
  }
  return { gate_decision: 'blocked', reason: 'required-incomplete' }
}

function validateReconciliation(frozenPlan, reconciliation, recordsByTestId) {
  if (!frozenPlan || typeof frozenPlan !== 'object' || Array.isArray(frozenPlan) ||
      !Array.isArray(frozenPlan.required) || !reconciliation || typeof reconciliation !== 'object' ||
      Array.isArray(reconciliation) || !Array.isArray(reconciliation.missing_required) ||
      !recordsByTestId || typeof recordsByTestId !== 'object' || Array.isArray(recordsByTestId)) return true

  const expected = frozenPlan.expected ?? frozenPlan.required
  if (!uniqueStringArray(expected) || !uniqueStringArray(frozenPlan.required)) return true
  const expectedSet = new Set(expected)
  const requiredSet = new Set(frozenPlan.required)
  if ([...requiredSet].some((id) => !expectedSet.has(id))) return true

  const waived = reconciliation.waived ?? []
  if (!uniqueStringArray(waived)) return true
  const allowlist = frozenPlan.waiverAllowlist ?? []
  if (!uniqueStringArray(allowlist)) return true
  const allowSet = new Set(allowlist)
  if (waived.some((id) => !expectedSet.has(id) || !allowSet.has(id))) return true

  const resultIds = Object.keys(recordsByTestId)
  if (resultIds.some((id) => !expectedSet.has(id))) return true
  for (const id of resultIds) {
    const record = recordsByTestId[id]
    if (!record || typeof record !== 'object' || Array.isArray(record) ||
        !VERDICT.includes(record.verdict) || !INVOCATION_STATUS.includes(record.invocation_status)) return true
  }

  const executed = expected.filter((id) => Object.hasOwn(recordsByTestId, id))
  const waivedSet = new Set(waived)
  const missing = expected.filter((id) => !Object.hasOwn(recordsByTestId, id) && !waivedSet.has(id))
  const missingRequired = missing.filter((id) => requiredSet.has(id))
  if (!sameOptionalSet(reconciliation.expected, expected)) return true
  if (!sameOptionalSet(reconciliation.executed, executed)) return true
  if (!sameOptionalSet(reconciliation.missing, missing)) return true
  if (!sameOptionalSet(reconciliation.missing_required, missingRequired)) return true
  if (reconciliation.waived !== undefined && !sameOptionalSet(reconciliation.waived, waived)) return true
  return false
}

function uniqueStringArray(value) {
  return Array.isArray(value) && value.every((item) => typeof item === 'string' && item.length > 0) && new Set(value).size === value.length
}
function sameOptionalSet(actual, expected) {
  if (actual === undefined) return true // legacy partial reconciliation; missing_required is still verified
  if (!uniqueStringArray(actual) || actual.length !== expected.length) return false
  const expectedSet = new Set(expected)
  return actual.every((id) => expectedSet.has(id))
}
