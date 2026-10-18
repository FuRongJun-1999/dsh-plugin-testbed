/**
 * Executable fail-closed validators for the versioned protocol artifacts.
 *
 * `schemas.js` declares the contract; this module turns it into `{ok, errors}`
 * checks and adds the cross-field guards a pure JSON Schema cannot express
 * (three mutually-exclusive receipt forms, illegal signature shapes, fixed
 * `market_eligible=false` / `integrity.signed=false`, optional digest
 * recomputation). Nothing here computes a verdict, gate decision, plan or
 * reconciliation — those are control-plane algorithms.
 *
 * Rejection is always explicit: unknown document major versions and unknown
 * fields fail; there is no implicit downgrade (architecture §8.4.1, §11.2.1;
 * development-plan「版本边界」).
 *
 * @module @deepseek-ai/dsh-plugin-testbed/protocol/contracts
 */
import { verifyRecordDigest } from './digest.js'
import { validateValue } from './jsonschema.js'
import type { ReceiptForm, UnknownRecord } from './types.js'
import {
  GATE_POLICY_V1_SCHEMA,
  PLAN_CANDIDATE_V1_SCHEMA,
  PLAN_V1_SCHEMA,
  RECEIPT_V1_SCHEMA,
  RUN_SPEC_V1_SCHEMA,
  TEST_TOOL_REQUEST_V1_SCHEMA,
  TEST_TOOL_RESPONSE_V1_SCHEMA,
  isGatePolicyVersion,
  isPlanCandidateVersion,
  isPlanVersion,
  isReceiptSchemaVersion,
  isRunSpecVersion,
  isTestToolProtocolVersion,
} from './schemas.js'

/**
 * Keys that would introduce a signing/anchoring form. MVP `receipt/v1` has no
 * signing shape at all; only `integrity.signed === false` is tolerated
 * (architecture §11.2.1「拒绝未在 schema 中声明的签名字段」).
 */
const FORBIDDEN_SIGNATURE_KEYS: readonly string[] = Object.freeze([
  'signed', 'signature', 'signatures', 'sig', 'jws', 'jwk', 'protected',
  'protected_headers', 'key_id', 'keyid', 'signing_key', 'signing_key_id',
  'signing_key_ref', 'archive_anchor', 'trust_anchor', 'anchor', 'anchors',
  'certificate', 'cert', 'tlog', 'transparency_log',
])

function isPlainObject(v: unknown): v is UnknownRecord {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

function pushSchemaErrors(errors: string[], add: string[]): void {
  for (const error of add) errors.push(`schema:${error}`)
}

/**
 * Recursively reject any signing-form key. The only legal occurrence is
 * `integrity.signed === false`; every other `signed|signature|key_id|anchor…`
 * occurrence fails closed.
 * @param {unknown} value
 * @param {string} path
 * @param {string[]} errors
 */
function scanSignatureForms(value: unknown, path: string, errors: string[]): void {
  if (value === null || typeof value !== 'object') return
  if (Array.isArray(value)) {
    value.forEach((item, index) => scanSignatureForms(item, `${path}[${index}]`, errors))
    return
  }
  for (const [key, child] of Object.entries(value)) {
    const childPath = path === '' ? key : `${path}.${key}`
    if (FORBIDDEN_SIGNATURE_KEYS.includes(key)) {
      const isLocalUnsignedMarker = path === 'integrity' && key === 'signed' && child === false
      if (!isLocalUnsignedMarker) errors.push(`forbidden-signature-form:${childPath}`)
      continue
    }
    scanSignatureForms(child, childPath, errors)
  }
}

/**
 * Detect the receipt form. Discriminator: `plan_id === null` means pre-plan;
 * `run_status` distinguishes blocked from cancelled (§11.2.1).
 * @param {object} receipt
 * @returns {'frozen'|'pre-plan-blocked'|'pre-plan-cancelled'|null}
 */
function receiptForm(receipt: UnknownRecord): ReceiptForm {
  if (receipt.plan_id !== null && receipt.plan_id !== undefined) return 'frozen'
  if (receipt.run_status === 'blocked') return 'pre-plan-blocked'
  if (receipt.run_status === 'cancelled') return 'pre-plan-cancelled'
  return null
}

/**
 * Cross-field fail-closed guards for the three mutually-exclusive forms.
 * `plan_id === null` ⇔ `reconciliation === null` is the primary invariant; a
 * pre-plan receipt additionally may not forge expected/missing/waived or any
 * per-test terminal state.
 * @param {object} receipt
 * @param {'frozen'|'pre-plan-blocked'|'pre-plan-cancelled'|null} form
 * @returns {string[]}
 */
function receiptFormErrors(receipt: UnknownRecord, form: 'frozen' | 'pre-plan-blocked' | 'pre-plan-cancelled' | null): string[] {
  const errors = []
  const has = (key: string): boolean => receipt[key] !== undefined

  if (form === 'frozen') {
    if (receipt.reconciliation == null) errors.push('frozen-must-have-reconciliation')
    if (!Array.isArray(receipt.plan_resolution)) errors.push('frozen-must-have-plan-resolution')
    for (const key of ['blocked_stage', 'cancelled_stage', 'reason_codes']) {
      if (has(key)) errors.push(`frozen-form-forbidden-field:${key}`)
    }
    return errors
  }

  if (form === 'pre-plan-blocked' || form === 'pre-plan-cancelled') {
    if (receipt.reconciliation !== null) errors.push('pre-plan-must-have-null-reconciliation')
    if (receipt.plan_resolution !== null) errors.push('pre-plan-must-have-null-plan-resolution')
    if (!Array.isArray(receipt.test_cases) || receipt.test_cases.length !== 0) {
      errors.push('pre-plan-must-have-empty-test-cases')
    }
    if (!Array.isArray(receipt.observations) || receipt.observations.length !== 0) {
      errors.push('pre-plan-must-have-empty-observations')
    }
    if (!Array.isArray(receipt.artifacts) || receipt.artifacts.length !== 0) {
      errors.push('pre-plan-must-have-empty-artifacts')
    }
    if (receipt.gate_decision !== 'blocked') errors.push('pre-plan-gate-decision-must-be-blocked')
    if (!Array.isArray(receipt.reason_codes) || receipt.reason_codes.length === 0) {
      errors.push('pre-plan-requires-reason-codes')
    }
    if (form === 'pre-plan-blocked') {
      if (has('cancelled_stage')) errors.push('blocked-form-forbidden-field:cancelled_stage')
      if (typeof receipt.blocked_stage !== 'string' || receipt.blocked_stage.length === 0) {
        errors.push('blocked-form-must-have-blocked-stage')
      }
    } else {
      if (has('blocked_stage')) errors.push('cancelled-form-forbidden-field:blocked_stage')
      if (typeof receipt.cancelled_stage !== 'string' || receipt.cancelled_stage.length === 0) {
        errors.push('cancelled-form-must-have-cancelled-stage')
      }
    }
    // The A-group nullable refs are allowed, but a pre-plan receipt must never
    // carry frozen-only reconciliation content or case-level terminal state.
    if (receipt.run_status !== (form === 'pre-plan-blocked' ? 'blocked' : 'cancelled')) {
      errors.push('pre-plan-run-status-form-mismatch')
    }
    return errors
  }

  errors.push('receipt-form-indeterminate')
  return errors
}

/**
 * Validate a `receipt/v1` document strictly and fail closed.
 *
 * @param {unknown} receipt
 * @param {{ verifyDigest?: boolean }} [options] `verifyDigest:true` also
 *   recomputes `integrity.record_digest` over the RFC 8785 canonical body
 *   (excluding only `integrity.record_digest`, keeping `signed:false`).
 * @returns {{ ok: boolean, errors: string[],
 *   form: 'frozen'|'pre-plan-blocked'|'pre-plan-cancelled'|null }}
 */
export function validateReceiptV1(receipt: unknown, options: { verifyDigest?: boolean } = {}): { ok: boolean; errors: string[]; form: ReceiptForm } {
  if (!isPlainObject(receipt)) return { ok: false, errors: ['not-object'], form: null }
  const errors = []

  if (!isReceiptSchemaVersion(receipt.receipt_schema_version)) {
    errors.push(`unknown-version:${String(receipt.receipt_schema_version)}`)
  }
  scanSignatureForms(receipt, '', errors)

  // MVP trust invariants are absolute, independent of schema evolution.
  if (receipt.trust_scope !== 'local-only') errors.push('trust-scope-must-be-local-only')
  if (receipt.market_eligible !== false) errors.push('market-eligible-must-be-false')
  if (!isPlainObject(receipt.integrity) || receipt.integrity.signed !== false) {
    errors.push('integrity-signed-must-be-false')
  }

  const shaped = validateValue(receipt, RECEIPT_V1_SCHEMA)
  pushSchemaErrors(errors, shaped.errors)

  const form = receiptForm(receipt)
  errors.push(...receiptFormErrors(receipt, form))

  if (options.verifyDigest === true && !verifyRecordDigest(receipt).ok) {
    errors.push('record-digest-mismatch')
  }

  return { ok: errors.length === 0, errors, form }
}

/**
 * Validate a `run-spec/v1` document. Version and fields are closed; scenario
 * case DAG/budget/authorization checks remain control-plane responsibilities.
 * @param {unknown} runSpec
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validateRunSpecV1(runSpec: unknown): { ok: boolean; errors: string[] } {
  if (!isPlainObject(runSpec)) return { ok: false, errors: ['not-object'] }
  const errors = []
  if (!isRunSpecVersion(runSpec.schema_version)) {
    errors.push(`unknown-version:${String(runSpec.schema_version)}`)
  }
  pushSchemaErrors(errors, validateValue(runSpec, RUN_SPEC_V1_SCHEMA).errors)
  return { ok: errors.length === 0, errors }
}

/**
 * Validate a `gate-policy/v1` declaration (required/optional baseline,
 * applicability predicates, pre-approved waiver rules, aggregation order).
 * @param {unknown} policy
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validateGatePolicyV1(policy: unknown): { ok: boolean; errors: string[] } {
  if (!isPlainObject(policy)) return { ok: false, errors: ['not-object'] }
  const errors = []
  if (!isGatePolicyVersion(policy.schema_version)) {
    errors.push(`unknown-version:${String(policy.schema_version)}`)
  }
  pushSchemaErrors(errors, validateValue(policy, GATE_POLICY_V1_SCHEMA).errors)
  return { ok: errors.length === 0, errors }
}

/**
 * Validate a serialized `plan-candidate/v1` declaration.
 * @param {unknown} candidate
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validatePlanCandidateV1(candidate: unknown): { ok: boolean; errors: string[] } {
  if (!isPlainObject(candidate)) return { ok: false, errors: ['not-object'] }
  const errors = []
  if (!isPlanCandidateVersion(candidate.schema_version)) {
    errors.push(`unknown-version:${String(candidate.schema_version)}`)
  }
  pushSchemaErrors(errors, validateValue(candidate, PLAN_CANDIDATE_V1_SCHEMA).errors)
  return { ok: errors.length === 0, errors }
}

/**
 * Validate an immutable `plan/v1` document.
 * @param {unknown} plan
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validatePlanV1(plan: unknown): { ok: boolean; errors: string[] } {
  if (!isPlainObject(plan)) return { ok: false, errors: ['not-object'] }
  const errors = []
  if (!isPlanVersion(plan.schema_version)) {
    errors.push(`unknown-version:${String(plan.schema_version)}`)
  }
  pushSchemaErrors(errors, validateValue(plan, PLAN_V1_SCHEMA).errors)
  return { ok: errors.length === 0, errors }
}

/**
 * Validate a `test-tool/v1` ToolRequest envelope structurally. Correlation,
 * deadline and size checks are additionally enforced by `transport.js`.
 * @param {unknown} frame
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validateTestToolRequestV1(frame: unknown): { ok: boolean; errors: string[] } {
  if (!isPlainObject(frame)) return { ok: false, errors: ['not-object'] }
  const errors = []
  if (!isTestToolProtocolVersion(frame.protocol_version)) {
    errors.push(`unknown-version:${String(frame.protocol_version)}`)
  }
  if ('kind' in frame) errors.push('tool-request-must-not-carry-kind')
  pushSchemaErrors(errors, validateValue(frame, TEST_TOOL_REQUEST_V1_SCHEMA).errors)
  return { ok: errors.length === 0, errors }
}

/**
 * Validate a `test-tool/v1` ToolResponse envelope structurally. The response
 * may not carry verdict, GateDecision, required/expected or plan changes: all
 * such keys are unknown to the closed schema and therefore rejected.
 * @param {unknown} frame
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validateTestToolResponseV1(frame: unknown): { ok: boolean; errors: string[] } {
  if (!isPlainObject(frame)) return { ok: false, errors: ['not-object'] }
  const errors = []
  if (!isTestToolProtocolVersion(frame.protocol_version)) {
    errors.push(`unknown-version:${String(frame.protocol_version)}`)
  }
  for (const forbidden of ['verdict', 'gate_decision', 'required', 'expected', 'plan', 'plan_resolution']) {
    if (forbidden in frame) errors.push(`tool-response-forbidden-field:${forbidden}`)
  }
  pushSchemaErrors(errors, validateValue(frame, TEST_TOOL_RESPONSE_V1_SCHEMA).errors)
  return { ok: errors.length === 0, errors }
}
