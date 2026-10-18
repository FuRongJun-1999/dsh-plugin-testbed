/**
 * Plan reconciliation: `expected / executed / missing / waived` computed
 * independently by the control face from a frozen Plan (`reconcile/` in
 * implementation-design-control §8, architecture §6.1).
 *
 * `executed` means the control face adopted a terminal state for that frozen
 * item; it does not mean the tool logic actually started (that fact lives only
 * in `invocation_status`). Unknown/extra IDs, malformed records, unapproved
 * waivers and caller/worker authority fields are protocol errors, not silently
 * ignored input.
 *
 * Migration phase `pure control`: untrusted plan/result inputs stay `unknown`,
 * the reconciliation result is typed, and malformed input still throws the same
 * `TypeError` messages.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/control/reconcile
 */
import { VERDICT, inSet } from '../protocol/enums.js'
import { AUTHORITY_FIELDS } from './state.js'
import type { UnknownRecord } from '../protocol/types.js'

/** Control-plane reconciliation result (all arrays of test ids, order preserved). */
export interface Reconciliation {
  expected: string[]
  executed: string[]
  missing: string[]
  waived: string[]
  missing_required: string[]
}

/**
 * Control-plane result/attempt records legitimately carry `verdict` (the
 * control assertion produces it). They may still never carry gate/plan
 * authority fields.
 */
const RESULT_AUTHORITY_FIELDS: readonly string[] = AUTHORITY_FIELDS.filter((field) => field !== 'verdict')

/**
 * Reconcile a frozen plan against adopted terminal results.
 */
export function reconcile(frozenPlan: unknown, resultsByTestId: unknown, waived: unknown = []): Reconciliation {
  if (!frozenPlan || typeof frozenPlan !== 'object' || Array.isArray(frozenPlan)) {
    throw new TypeError('reconcile frozenPlan must be an object')
  }
  const plan = frozenPlan as UnknownRecord
  if (Array.isArray(plan.testCases)) {
    for (const raw of plan.testCases) {
      const caseSpec = raw !== null && typeof raw === 'object' ? (raw as UnknownRecord) : undefined
      assertNoAuthorityFields(raw, `frozen case ${String(caseSpec?.test_id)}`)
      if (caseSpec && Object.hasOwn(caseSpec, 'admission')) {
        throw new TypeError(`frozen case ${String(caseSpec.test_id)} carries caller authority field: admission`)
      }
    }
  }
  const expected = validateIds(plan.expected, 'frozenPlan.expected')
  const required = validateIds(plan.required, 'frozenPlan.required')
  const expectedSet = new Set(expected)
  for (const id of required) {
    if (!expectedSet.has(id)) throw new TypeError(`reconcile required ID is not expected: ${id}`)
  }
  if (!resultsByTestId || typeof resultsByTestId !== 'object' || Array.isArray(resultsByTestId)) {
    throw new TypeError('reconcile resultsByTestId must be an object')
  }
  const results = resultsByTestId as UnknownRecord

  const resultIds = Object.keys(results)
  const resultSet = new Set(resultIds)
  for (const id of resultIds) {
    if (!expectedSet.has(id)) throw new TypeError(`reconcile result ID is not expected: ${id}`)
    const record = results[id]
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      throw new TypeError(`reconcile result is malformed: ${id}`)
    }
    assertNoAuthorityFields(record, `result ${id}`)
    if (!inSet(VERDICT, (record as UnknownRecord).verdict)) throw new TypeError(`reconcile result is malformed: ${id}`)
  }

  const waiverIds = validateIds(waived, 'waived')
  const allowlist = validateIds(plan.waiverAllowlist ?? [], 'frozenPlan.waiverAllowlist')
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

/**
 * Reconcile from adopted attempt records (`executeFrozenPlan().adoptedAttempts`).
 * The final verdict per test_id is the last adopted attempt; retry attempts
 * append and never overwrite earlier history.
 */
export function reconcileAdoptedAttempts(
  frozenPlan: unknown,
  adoptedAttempts: unknown,
  waived: unknown = [],
): Reconciliation {
  if (!Array.isArray(adoptedAttempts)) throw new TypeError('reconcileAdoptedAttempts adoptedAttempts must be an array')
  const plan = frozenPlan !== null && typeof frozenPlan === 'object' ? (frozenPlan as UnknownRecord) : undefined
  const expectedSet = new Set(Array.isArray(plan?.expected) ? plan.expected as string[] : [])
  const byTest = new Map<string, UnknownRecord[]>()
  const seenAttempts = new Set<string>()

  for (const raw of adoptedAttempts) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new TypeError('reconcileAdoptedAttempts attempt is malformed')
    }
    const adopted = raw as UnknownRecord
    if (typeof adopted.test_id !== 'string' || adopted.test_id.length === 0) {
      throw new TypeError('reconcileAdoptedAttempts attempt test_id is malformed')
    }
    if (!expectedSet.has(adopted.test_id)) {
      throw new TypeError(`reconcileAdoptedAttempts attempt ID is not expected: ${adopted.test_id}`)
    }
    const attempt = adopted.attempt
    if (!attempt || typeof attempt !== 'object' || Array.isArray(attempt) || !inSet(VERDICT, (attempt as UnknownRecord).verdict)) {
      throw new TypeError(`reconcileAdoptedAttempts attempt is malformed: ${adopted.test_id}`)
    }
    assertNoAuthorityFields(attempt, `attempt ${adopted.test_id}`)
    const key = `${adopted.test_id}#${String((attempt as UnknownRecord).attempt)}`
    if (seenAttempts.has(key)) throw new TypeError(`reconcileAdoptedAttempts duplicate attempt: ${key}`)
    seenAttempts.add(key)
    const list = byTest.get(adopted.test_id) ?? []
    list.push(attempt as UnknownRecord)
    byTest.set(adopted.test_id, list)
  }

  const resultsByTestId: Record<string, { verdict: unknown }> = Object.create(null)
  for (const [testId, attempts] of byTest) {
    const ordered = [...attempts].sort((a, b) =>
      Number((a.attempt as number | undefined) ?? 0) - Number((b.attempt as number | undefined) ?? 0))
    resultsByTestId[testId] = { verdict: ordered[ordered.length - 1].verdict }
  }
  return reconcile(frozenPlan, resultsByTestId, waived)
}

function assertNoAuthorityFields(record: unknown, what: string): void {
  if (!record || typeof record !== 'object' || Array.isArray(record)) return
  const value = record as UnknownRecord
  for (const field of RESULT_AUTHORITY_FIELDS) {
    if (Object.hasOwn(value, field)) {
      throw new TypeError(`${what} carries caller/worker authority field: ${field}`)
    }
  }
}

function validateIds(value: unknown, field: string): string[] {
  if (!Array.isArray(value)) throw new TypeError(`reconcile ${field} must be an array`)
  const seen = new Set<string>()
  for (const id of value) {
    if (typeof id !== 'string' || id.length === 0) throw new TypeError(`reconcile ${field} contains malformed ID`)
    if (seen.has(id)) throw new TypeError(`reconcile ${field} contains duplicate ID: ${id}`)
    seen.add(id)
  }
  return [...value as string[]]
}
