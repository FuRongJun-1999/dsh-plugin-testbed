/**
 * Plan reconciliation: `expected / executed / missing / waived` computed
 * independently by the control face from a frozen Plan.
 * @module @deepseek-ai/dsh-plugin-testbed/control/reconcile
 */
import { VERDICT } from '../protocol/enums.js'

/**
 * Reconcile a frozen plan against recorded terminal results.
 * Unknown results and unapproved/duplicate waivers are protocol errors rather
 * than silently ignored input.
 *
 * @param {{expected:string[], required:string[], waiverAllowlist?:string[]}} frozenPlan
 * @param {Record<string, {verdict:string}>} resultsByTestId
 * @param {string[]} [waived] valid pre-approved waived test_ids
 */
export function reconcile(frozenPlan, resultsByTestId, waived = []) {
  if (!frozenPlan || typeof frozenPlan !== 'object' || Array.isArray(frozenPlan)) {
    throw new TypeError('reconcile frozenPlan must be an object')
  }
  const expected = validateIds(frozenPlan.expected, 'frozenPlan.expected')
  const required = validateIds(frozenPlan.required, 'frozenPlan.required')
  const expectedSet = new Set(expected)
  for (const id of required) {
    if (!expectedSet.has(id)) throw new TypeError(`reconcile required ID is not expected: ${id}`)
  }
  if (!resultsByTestId || typeof resultsByTestId !== 'object' || Array.isArray(resultsByTestId)) {
    throw new TypeError('reconcile resultsByTestId must be an object')
  }

  const resultIds = Object.keys(resultsByTestId)
  const resultSet = new Set(resultIds)
  for (const id of resultIds) {
    if (!expectedSet.has(id)) throw new TypeError(`reconcile result ID is not expected: ${id}`)
    const record = resultsByTestId[id]
    if (!record || typeof record !== 'object' || Array.isArray(record) || !VERDICT.includes(record.verdict)) {
      throw new TypeError(`reconcile result is malformed: ${id}`)
    }
  }

  const waiverIds = validateIds(waived, 'waived')
  const allowlist = validateIds(frozenPlan.waiverAllowlist ?? [], 'frozenPlan.waiverAllowlist')
  const allowSet = new Set(allowlist)
  for (const id of waiverIds) {
    if (!expectedSet.has(id)) throw new TypeError(`reconcile waiver ID is not expected: ${id}`)
    if (!allowSet.has(id)) throw new TypeError(`reconcile waiver is not pre-approved: ${id}`)
  }
  const waivedSet = new Set(waiverIds)
  const executed = expected.filter((id) => resultSet.has(id))
  const missing = expected.filter((id) => !resultSet.has(id) && !waivedSet.has(id))
  const missing_required = missing.filter((id) => required.includes(id))

  return { expected, executed, missing, waived: waiverIds, missing_required }
}

function validateIds(value, field) {
  if (!Array.isArray(value)) throw new TypeError(`reconcile ${field} must be an array`)
  const seen = new Set()
  for (const id of value) {
    if (typeof id !== 'string' || id.length === 0) throw new TypeError(`reconcile ${field} contains malformed ID`)
    if (seen.has(id)) throw new TypeError(`reconcile ${field} contains duplicate ID: ${id}`)
    seen.add(id)
  }
  return [...value]
}
