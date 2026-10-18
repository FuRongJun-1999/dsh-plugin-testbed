/**
 * Independent, control-plane admission decision (`state/` in
 * implementation-design-control §10, architecture §8.4.1 / §9.5).
 *
 * `admission_status` records whether the *trusted control face* permits a test
 * case attempt to be dispatched. It is never read from caller-supplied RunSpec
 * fields, worker messages, probe payloads or tool responses: a RunSpec
 * `admission: 'rejected'` simulation has no authority here (and `spec.js`
 * rejects it outright). Rejections always carry a reason code and never
 * masquerade as a worker success.
 *
 * Migration phase `pure control`: trusted context is typed as an explicit
 * interface, the case is `unknown`, and every reason code is unchanged.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/control/admission
 */
import type { UnknownRecord } from '../protocol/types.js'

/** Trusted control-plane context; caller-supplied fields are not accepted. */
export interface AdmissionContext {
  signal?: { aborted?: unknown }
  frozenPlan?: unknown
  expectedSet?: Set<string>
  toolBindings?: UnknownRecord
  budgetLedger?: unknown
  targetRef?: unknown
}

/** Frozen control-plane admission decision. */
export interface AdmissionDecision {
  admission_status: 'accepted' | 'rejected'
  reason_codes: readonly string[]
  source: 'control-plane'
}

function isPlainRecord(v: unknown): v is UnknownRecord {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

function nonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0
}

/** Reason codes emitted by the control-plane admission decision. */
export const ADMISSION_REASONS = Object.freeze({
  noObservationProducer: 'no-observation-producer',
  toolNotPinned: 'tool-ref-unpinned',
  toolDigestMismatch: 'tool-artifact-digest-mismatch',
  targetMissing: 'target-reference-missing',
  targetUnauthorized: 'unauthorized_target',
  budgetExhausted: 'budget_exhausted',
  notInFrozenPlan: 'not-in-frozen-plan',
  cancelled: 'cancelled',
} as const)

/**
 * Decide whether one attempt of `caseSpec` may be dispatched.
 *
 * The decision is derived only from trusted control-plane context:
 * frozen plan membership, pinned tool bindings (artifact digest), a trusted
 * target reference and the aggregate budget ledger. `caseSpec.admission` is
 * deliberately never consulted.
 */
export function decideAdmission(caseSpec: unknown, context: AdmissionContext = {}): AdmissionDecision {
  const reasons: string[] = []
  const caseRecord = isPlainRecord(caseSpec) ? caseSpec : undefined
  const testId = caseRecord?.test_id

  if (context.signal?.aborted === true) {
    return decision('rejected', [ADMISSION_REASONS.cancelled])
  }
  if (context.frozenPlan !== undefined || context.expectedSet !== undefined) {
    const frozenPlan = isPlainRecord(context.frozenPlan) ? context.frozenPlan : undefined
    const expected = context.expectedSet ?? new Set((frozenPlan?.expected ?? []) as string[])
    if (!expected.has(testId as string)) return decision('rejected', [ADMISSION_REASONS.notInFrozenPlan])
  }

  const tool = caseRecord?.tool
  if (isPlainRecord(tool)) {
    const binding = context.toolBindings?.[String(testId)]
    if (!isPlainRecord(binding) || !isPlainRecord(binding.toolRef) || !nonEmptyString(binding.toolRef.artifact_digest)) {
      reasons.push(ADMISSION_REASONS.toolNotPinned)
    } else {
      const manifest = isPlainRecord(tool.manifest) ? tool.manifest : undefined
      const manifestDigest = manifest?.artifact_digest
      if (manifestDigest !== undefined && manifestDigest !== binding.toolRef.artifact_digest) {
        reasons.push(ADMISSION_REASONS.toolDigestMismatch)
      }
    }
    if (context.targetRef === null) reasons.push(ADMISSION_REASONS.targetMissing)
    else if (context.targetRef !== undefined && !isPlainRecord(context.targetRef)) {
      reasons.push(ADMISSION_REASONS.targetUnauthorized)
    }
  } else if (!isPlainRecord(caseRecord?.probe)) {
    // No tool and no in-process probe means there is no observation producer at
    // all; dispatching would be a guaranteed no-op, so the control face rejects.
    reasons.push(ADMISSION_REASONS.noObservationProducer)
  }

  const ledger = context.budgetLedger
  if (ledger && typeof ledger === 'object' &&
      typeof (ledger as UnknownRecord).canReserveAttempt === 'function' &&
      (ledger as { canReserveAttempt: () => unknown }).canReserveAttempt() !== true) {
    reasons.push(ADMISSION_REASONS.budgetExhausted)
  }

  if (reasons.length > 0) return decision('rejected', reasons)
  return decision('accepted', [])
}

function decision(status: 'accepted' | 'rejected', reasons: string[]): AdmissionDecision {
  return Object.freeze({
    admission_status: status,
    reason_codes: Object.freeze([...reasons]),
    source: 'control-plane',
  })
}
