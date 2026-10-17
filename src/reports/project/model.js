/**
 * Read-only projection model: the single transform point from `receipt/v1` to a
 * renderer-neutral intermediate. Pure; no imports. Never mutates the receipt,
 * never invents verdicts — `missing` entries are synthesized only from
 * `reconciliation.missing` and never carry `pass`.
 * @module @deepseek-ai/dsh-plugin-testbed/reports/project/model
 */

/**
 * Build the projection model from an already-verified receipt.
 *
 * @param {object} receipt receipt/v1 (assumed verified by caller)
 * @returns {{meta:object, reconciliation:object|null, cases:Array, missing:string[], entries:Array}}
 */
export function buildModel(receipt) {
  const src = receipt?.integrity ?? {}
  const meta = {
    run_id: receipt?.run_id ?? null,
    receipt_schema_version: receipt?.receipt_schema_version ?? null,
    run_status: receipt?.run_status ?? null,
    trust_scope: receipt?.trust_scope ?? null,
    market_eligible: receipt?.market_eligible ?? null,
    gate_decision: receipt?.gate_decision ?? null,
    gate_reason: receipt?.gate_reason ?? null,
    plan_id: receipt?.plan_id ?? null,
    target_ref: receipt?.target_ref ?? null,
    provenance: receipt?.provenance ?? null,
    limitations: Array.isArray(receipt?.limitations) ? [...receipt.limitations] : [],
    scenario_ref: receipt?.scenario_ref ?? null,
    profile_ref: receipt?.profile_ref ?? null,
    blocked_stage: receipt?.blocked_stage ?? null,
    cancelled_stage: receipt?.cancelled_stage ?? null,
    reason_codes: Array.isArray(receipt?.reason_codes) ? [...receipt.reason_codes] : [],
    source_receipt_digest: src?.record_digest ?? null,
    integrity_signed: src?.signed ?? null,
    observation_count: Array.isArray(receipt?.observations) ? receipt.observations.length : 0,
    artifact_count: Array.isArray(receipt?.artifacts) ? receipt.artifacts.length : 0,
  }

  const rec = receipt?.reconciliation
  const reconciliation = rec
    ? {
        expected: [...(rec.expected ?? [])],
        executed: [...(rec.executed ?? [])],
        missing: [...(rec.missing ?? [])],
        waived: [...(rec.waived ?? [])],
      }
    : null

  const cases = (receipt?.test_cases ?? []).map(normalizeCase)
  const caseIds = new Set(cases.map((c) => c.test_id))

  // missing = reconciliation.missing NOT already represented by an adopted case
  const missingIds = (reconciliation?.missing ?? []).filter((id) => !caseIds.has(id))
  const missingEntries = missingIds.map((test_id) => ({
    test_id,
    verdict: 'missing',
    isMissing: true,
    classification: null,
    admission_status: null,
    execution_status: null,
    invocation_status: null,
    reason_codes: [],
    criteria_ref: null,
    attempts: [],
    observation_refs: [],
    dimensions: null,
  }))

  const entries = [...cases.map((c) => ({ ...c, isMissing: false })), ...missingEntries].sort(
    (a, b) => (a.test_id < b.test_id ? -1 : a.test_id > b.test_id ? 1 : 0),
  )

  return { meta, reconciliation, cases, missing: missingIds, entries }
}

function normalizeCase(tc) {
  return {
    test_id: tc?.test_id ?? null,
    classification: tc?.classification ?? null,
    verdict: tc?.verdict ?? null,
    admission_status: tc?.admission_status ?? null,
    execution_status: tc?.execution_status ?? null,
    invocation_status: tc?.invocation_status ?? null,
    reason_codes: Array.isArray(tc?.reason_codes) ? [...tc.reason_codes] : [],
    criteria_ref: tc?.criteria_ref ?? null,
    observation_refs: Array.isArray(tc?.observation_refs) ? [...tc.observation_refs] : [],
    dimensions: tc?.dimensions ?? null,
    attempts: Array.isArray(tc?.attempts)
      ? tc.attempts.map((a) => ({
          attempt: a?.attempt ?? null,
          admission_status: a?.admission_status ?? null,
          execution_status: a?.execution_status ?? null,
          invocation_status: a?.invocation_status ?? null,
          verdict: a?.verdict ?? null,
        }))
      : [],
  }
}

/**
 * Deterministic JSON encoding (sorted object keys) so projection bytes never
 * depend on object-key insertion order.
 * @param {unknown} value
 * @returns {string}
 */
export function stableJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(stableJson).join(',') + ']'
  const keys = Object.keys(value).sort()
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + stableJson(value[k])).join(',') + '}'
}