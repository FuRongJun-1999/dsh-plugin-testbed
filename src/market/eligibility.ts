/**
 * `market-eligibility/v1` engine (MKT-02/MKT-03/MKT-09, §6.7).
 *
 * The decision is a pure AND over the policy-required conditions. Any
 * `fail`/`unknown`/missing condition yields `non-eligible`; there is no default
 * value, historical shortcut or verbal approval that can turn it into
 * `eligible`. A valid waiver is recorded but never changes a status.
 *
 * The engine computes the decision only from verified inputs: receipt/v1
 * (strict), the t7 runtime anchor/contract, the t4 isolation admission, the t5
 * provider documents and the approval ledger. It never writes receipt/v1.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/market/eligibility
 */

import { validateReceiptV1 } from '../protocol/contracts.js'
import { recordDigest } from '../protocol/digest.js'
import {
  MARKET_CONDITION_IDS,
  MARKET_REASON_CODES,
  validateMarketEligibility,
} from '../protocol/market-schemas.js'
import type { ApprovalLedgerResult } from './approvals.js'
import type {
  ConditionId,
  ConditionStatus,
  IsolationEvidence,
  MarketBlocker,
  MarketCondition,
  MarketPolicyView,
  ProviderAssessment,
  ReceiptAssessment,
  RuntimeEvidence,
  UnknownRecord,
} from './types.js'
import { canonicalDigest, contentId, isArray, isNonEmptyString, parseTimeMs } from './util.js'

export interface SchedulerAssessment {
  present: boolean
  ok: boolean
  reasonCodes: string[]
  evidenceRefs: string[]
  limitations: string[]
}

export interface EligibilityInput {
  policy: MarketPolicyView
  receipt: ReceiptAssessment
  runtime: RuntimeEvidence
  isolation: IsolationEvidence
  providers: ProviderAssessment
  approvals: ApprovalLedgerResult
  scheduler: SchedulerAssessment
  /** Availability of a trusted time source for audit events (C10). */
  trustedTime: { verified: boolean; source: string | null; reasonCodes: string[] }
  nowMs: number
  /** Optional `archive-anchor/v1` produced as entry N by the evidence sequence. */
  subjectAnchor?: UnknownRecord | null
  subjectAnchorDigest?: string | null
  /**
   * Caller-computed manifest digest. The evidence sequence verifies that the
   * decision binds its own subject manifest digest, so the gate passes the t5
   * digest explicitly; standalone engine calls fall back to the richer digest.
   */
  evidenceManifestDigest?: string | null
}

export interface EligibilityComputation {
  eligibility: UnknownRecord | null
  digest: string | null
  conditions: MarketCondition[]
  reasonCodes: string[]
  blockers: MarketBlocker[]
  decision: 'eligible' | 'non-eligible'
}

function condition(
  id: ConditionId,
  status: ConditionStatus,
  reasonCode: string | null,
  evidenceRefs: string[],
  detail?: string,
): MarketCondition {
  return detail === undefined
    ? { id, status, reason_code: reasonCode, evidence_refs: [...new Set(evidenceRefs)] }
    : { id, status, reason_code: reasonCode, evidence_refs: [...new Set(evidenceRefs)], detail }
}

function isolationRank(level: string | null): number {
  if (level === 'L3') return 3
  if (level === 'L2') return 2
  if (level === 'L1-subprocess') return 1
  if (level === 'L0-in-process') return 0
  return -1
}

function firstReason(codes: string[], fallback: string): string {
  return codes.length > 0 ? codes[0] : fallback
}

/**
 * Strict receipt/v1 assessment for MKT-C04.
 *
 * Invariants: frozen form, `pass` gate, required verdicts all pass, at least one
 * control-verified `started` attempt, no missing/unknown/waived required and no
 * unverified `not-applicable`. The receipt digest is recomputed before use.
 */
export function assessReceipt(receiptRaw: unknown): ReceiptAssessment {
  const empty: ReceiptAssessment = {
    ok: false,
    form: null,
    errors: [],
    reasonCodes: [],
    receipt: null,
    digest: null,
    runId: null,
    targetDigest: null,
    targetKind: null,
    earliestStartedAtMs: null,
    requiredTestIds: [],
  }
  const receipt = receiptRaw !== null && typeof receiptRaw === 'object' && !Array.isArray(receiptRaw)
    ? (receiptRaw as UnknownRecord)
    : null
  if (receipt === null) {
    return { ...empty, errors: ['receipt-not-object'], reasonCodes: [MARKET_REASON_CODES.MARKET_RECEIPT_INVALID] }
  }
  const validation = validateReceiptV1(receipt, { verifyDigest: true })
  if (!validation.ok) {
    return {
      ...empty,
      receipt,
      form: validation.form,
      errors: validation.errors.slice(0, 20),
      reasonCodes: [MARKET_REASON_CODES.MARKET_RECEIPT_INVALID],
    }
  }
  const digest = recordDigest(receipt)
  const targetRef = receipt.target_ref !== null && typeof receipt.target_ref === 'object' && !Array.isArray(receipt.target_ref)
    ? (receipt.target_ref as UnknownRecord)
    : null
  const targetDigest = isNonEmptyString(targetRef?.owner_put_digest) ? targetRef.owner_put_digest : null
  const targetKind = isNonEmptyString(targetRef?.kind) ? targetRef.kind : null
  const errors: string[] = []
  const reasonCodes = new Set<string>()

  if (validation.form !== 'frozen') errors.push(`receipt-form-not-frozen:${String(validation.form)}`)
  if (receipt.gate_decision !== 'pass') errors.push(`gate-decision-not-pass:${String(receipt.gate_decision)}`)
  if (receipt.run_status !== 'completed') errors.push(`run-status-not-completed:${String(receipt.run_status)}`)
  if (!isNonEmptyString(receipt.plan_id)) errors.push('plan-id-missing')
  if (targetDigest === null) errors.push('target-ref-missing')

  const reconciliation = receipt.reconciliation !== null && typeof receipt.reconciliation === 'object' &&
    !Array.isArray(receipt.reconciliation) ? (receipt.reconciliation as UnknownRecord) : null
  if (reconciliation === null) {
    errors.push('reconciliation-missing')
  } else {
    const missing = isArray(reconciliation.missing) ? reconciliation.missing : []
    const executed = isArray(reconciliation.executed) ? reconciliation.executed : []
    const waived = isArray(reconciliation.waived) ? reconciliation.waived : []
    const missingRequired = isArray(reconciliation.missing_required) ? reconciliation.missing_required : []
    if (missing.length > 0) errors.push(`reconciliation-missing:${missing.length}`)
    if (missingRequired.length > 0) errors.push(`reconciliation-missing-required:${missingRequired.length}`)
    if (!executed.every(isNonEmptyString)) errors.push('reconciliation-executed-invalid')
    if (!waived.every(isNonEmptyString)) errors.push('reconciliation-waived-invalid')
  }

  const planResolution = isArray(receipt.plan_resolution) ? receipt.plan_resolution : []
  const requiredTestIds: string[] = []
  const notApplicable = new Map<string, UnknownRecord>()
  for (const entry of planResolution) {
    const record = entry !== null && typeof entry === 'object' && !Array.isArray(entry) ? (entry as UnknownRecord) : null
    const testId = isNonEmptyString(record?.test_id) ? record.test_id : null
    if (record === null || testId === null) {
      errors.push('plan-resolution-entry-invalid')
      continue
    }
    if (record.classification === 'required') requiredTestIds.push(testId)
    if (record.classification === 'not-applicable') {
      const details = record.not_applicable !== null && typeof record.not_applicable === 'object' &&
        !Array.isArray(record.not_applicable) ? (record.not_applicable as UnknownRecord) : null
      const verified = details !== null &&
        isNonEmptyString(details.predicate_version) &&
        isNonEmptyString(details.capability_snapshot_ref) &&
        isNonEmptyString(details.reason)
      if (!verified) errors.push(`not-applicable-not-verified:${testId}`)
      else notApplicable.set(testId, details)
    }
  }
  if (requiredTestIds.length === 0) errors.push('no-required-tests')

  const caseMap = new Map<string, UnknownRecord>()
  let earliestStartedAtMs: number | null = null
  let startedPassCount = 0
  const testCases = isArray(receipt.test_cases) ? receipt.test_cases : []
  for (const rawCase of testCases) {
    const record = rawCase !== null && typeof rawCase === 'object' && !Array.isArray(rawCase)
      ? (rawCase as UnknownRecord)
      : null
    const testId = isNonEmptyString(record?.test_id) ? record.test_id : null
    if (record === null || testId === null) {
      errors.push('test-case-invalid')
      continue
    }
    caseMap.set(testId, record)
    if (record.invocation_status === 'unknown') errors.push(`test-invocation-unknown:${testId}`)
    if (record.invocation_evidence_verified === false) errors.push(`test-invocation-unverified:${testId}`)
    const attempts = isArray(record.attempts) ? record.attempts : []
    for (const rawAttempt of attempts) {
      const attempt = rawAttempt !== null && typeof rawAttempt === 'object' && !Array.isArray(rawAttempt)
        ? (rawAttempt as UnknownRecord)
        : null
      if (attempt === null) {
        errors.push(`attempt-invalid:${testId}`)
        continue
      }
      if (attempt.invocation_status === 'unknown') errors.push(`attempt-invocation-unknown:${testId}`)
      if (attempt.invocation_evidence_verified === false) errors.push(`attempt-invocation-unverified:${testId}`)
      const started = parseTimeMs(attempt.started_at)
      if (started !== null && (earliestStartedAtMs === null || started < earliestStartedAtMs)) {
        earliestStartedAtMs = started
      }
      if (attempt.invocation_status === 'started' && attempt.verdict === 'pass') startedPassCount += 1
    }
  }
  if (startedPassCount === 0) errors.push('no-control-verified-started-pass')

  const waived = reconciliation !== null && isArray(reconciliation.waived)
    ? (reconciliation.waived as unknown[]).filter(isNonEmptyString)
    : []
  for (const testId of requiredTestIds) {
    const testCase = caseMap.get(testId)
    if (testCase === undefined) {
      errors.push(`required-test-missing-case:${testId}`)
      continue
    }
    if (testCase.verdict !== 'pass') errors.push(`required-test-not-pass:${testId}:${String(testCase.verdict)}`)
    if (waived.includes(testId)) errors.push(`required-test-waived:${testId}`)
  }

  if (errors.length > 0) reasonCodes.add(MARKET_REASON_CODES.MARKET_RECEIPT_INVALID)
  return {
    ok: errors.length === 0,
    form: validation.form,
    errors,
    reasonCodes: [...reasonCodes],
    receipt,
    digest,
    runId: isNonEmptyString(receipt.run_id) ? receipt.run_id : null,
    targetDigest,
    targetKind,
    earliestStartedAtMs,
    requiredTestIds,
  }
}

/** Digest over the eligibility *input* manifest (no eligibility/attestation output). */
export function marketManifestDigest(input: {
  receiptDigest: string | null
  isolationAttestationDigest: string | null
  isolationVerificationDigest: string | null
  policyDigest: string | null
  runtimeAnchorDigest: string | null
  contractSuiteDigest: string | null
  approvalDigests: string[]
  waiverDigests: string[]
  archiveAnchorDigest: string | null
}): string {
  return canonicalDigest({
    receipt_digest: input.receiptDigest,
    isolation_attestation_digest: input.isolationAttestationDigest,
    isolation_verification_digest: input.isolationVerificationDigest,
    policy_digest: input.policyDigest,
    runtime_anchor_digest: input.runtimeAnchorDigest,
    contract_suite_digest: input.contractSuiteDigest,
    approval_digests: [...input.approvalDigests].sort(),
    waiver_digests: [...input.waiverDigests].sort(),
    archive_anchor_digest: input.archiveAnchorDigest,
  })
}

function buildConditions(input: EligibilityInput): MarketCondition[] {
  const { policy, receipt, runtime, isolation, providers, approvals, scheduler, trustedTime } = input
  const conditions: MarketCondition[] = []

  // C01 — isolation level + verified attestation (L2/L3, no fallback).
  const isolationAdmitted = isolation.status === 'admitted' &&
    isolationRank(isolation.achievedLevel) >= isolationRank(policy.requiredIsolation)
  conditions.push(condition(
    'MKT-C01',
    isolationAdmitted ? 'pass' : 'fail',
    isolationAdmitted ? null : firstReason(isolation.reasonCodes, 'isolation-provider-missing'),
    isolation.evidenceRefs,
    `required:${policy.requiredIsolation},achieved:${String(isolation.achievedLevel)}`,
  ))

  // C02 — no unenforced dimension / low-privilege worker / no ambient credentials.
  const isolationChecks = isolation.admission !== null && isArray(isolation.admission.checks)
    ? isolation.admission.checks
    : []
  const lowPrivilegeBlocker = isolation.reasonCodes.find((code) =>
    code === 'worker-identity-not-low-privilege' ||
    code === 'worker-ambient-credentials-present' ||
    code === 'isolation-dimension-unenforced' ||
    code.startsWith('isolation-dimension-unenforced:'))
  const noUnenforced = isolationAdmitted && lowPrivilegeBlocker === undefined && isolationChecks.length > 0
  conditions.push(condition(
    'MKT-C02',
    noUnenforced ? 'pass' : 'fail',
    noUnenforced ? null : firstReason(isolation.reasonCodes, 'isolation-unverified'),
    isolation.evidenceRefs,
    isolationAdmitted ? 'dimensions-enforced-and-low-privilege' : 'isolation-not-admitted',
  ))

  // C03 — real locked Cordis/DSH runtime + contract suite.
  const runtimeOk = runtime.status === 'available' && runtime.contractPassed
  conditions.push(condition(
    'MKT-C03',
    runtimeOk ? 'pass' : 'fail',
    runtimeOk ? null : firstReason(runtime.reasonCodes, 'runtime-anchor-missing'),
    runtime.evidenceRefs,
    runtime.detail ?? undefined,
  ))

  // C04 — strict receipt/v1 + reconciliation.
  conditions.push(condition(
    'MKT-C04',
    receipt.ok ? 'pass' : 'fail',
    receipt.ok ? null : firstReason(receipt.reasonCodes, 'market-receipt-invalid'),
    receipt.digest === null ? [] : [`receipt:${receipt.digest}`],
    receipt.errors.length > 0 ? receipt.errors.slice(0, 3).join(';') : undefined,
  ))

  // C05 — signing provider trust (pre-sign gate; signature itself is verified later).
  const signingOk = providers.signingTrusted && providers.signingKeyId !== null
  conditions.push(condition(
    'MKT-C05',
    signingOk ? 'pass' : 'fail',
    signingOk ? null : firstReason(providers.signingReasonCodes, 'signing-provider-missing'),
    providers.signingKeyId === null ? [] : [`signer-key:${providers.signingKeyId}`],
  ))

  // C06 — independent append-only archive + trusted time.
  const archiveOk = providers.archiveTrusted && trustedTime.verified
  conditions.push(condition(
    'MKT-C06',
    archiveOk ? 'pass' : 'fail',
    archiveOk ? null : firstReason(
      [...providers.archiveReasonCodes, ...trustedTime.reasonCodes],
      'archive-provider-missing',
    ),
    input.subjectAnchorDigest === null || input.subjectAnchorDigest === undefined
      ? []
      : [`archive-anchor:${input.subjectAnchorDigest}`],
  ))

  // C07 — complete, fresh evidence package inputs.
  const evidenceRefs: string[] = []
  if (receipt.digest !== null) evidenceRefs.push(`receipt:${receipt.digest}`)
  if (runtime.anchorDigest !== null) evidenceRefs.push(`runtime-anchor:${runtime.anchorDigest}`)
  if (isolation.attestationDigest !== null) evidenceRefs.push(`isolation:${isolation.attestationDigest}`)
  if (policy.digest.length > 0) evidenceRefs.push(`policy:${policy.digest}`)
  const evidenceOk = receipt.digest !== null && runtime.anchorDigest !== null &&
    isolation.attestationDigest !== null && approvals.ok
  conditions.push(condition(
    'MKT-C07',
    evidenceOk ? 'pass' : 'fail',
    evidenceOk ? null : 'market-evidence-incomplete',
    evidenceRefs,
  ))

  // C08 — frozen policy, approvals and waivers with separation of duties.
  const approvalsOk = approvals.ok && policy.failClosed && policy.separationOfDuties
  const approvalReasons = approvals.reasonCodes.length > 0
    ? approvals.reasonCodes
    : ['market-approval-missing']
  conditions.push(condition(
    'MKT-C08',
    approvalsOk ? 'pass' : 'fail',
    approvalsOk ? null : firstReason(approvalReasons, 'market-approval-missing'),
    approvals.approvalDigests.map((digest) => `approval:${digest}`),
    approvals.errors.length > 0 ? approvals.errors.slice(0, 3).join(';') : undefined,
  ))

  // C09 — target authorization/scoped approval for this exact PUT + run.
  const targetAuthorized = approvals.ok && receipt.targetDigest !== null &&
    approvals.approvals.some((approval) => approval.targetDigest === receipt.targetDigest)
  conditions.push(condition(
    'MKT-C09',
    targetAuthorized ? 'pass' : 'fail',
    targetAuthorized ? null : 'market-approval-missing',
    receipt.targetDigest === null ? [] : [`target:${receipt.targetDigest}`],
  ))

  // C10 — audit/trusted time; governed scheduler evidence when policy requires.
  const schedulerOk = !policy.schedulerRequired || scheduler.ok
  const auditOk = trustedTime.verified && schedulerOk
  const auditReasons = [
    ...(schedulerOk ? [] : scheduler.reasonCodes.length > 0 ? scheduler.reasonCodes : ['market-scheduler-evidence-required']),
    ...(trustedTime.verified ? [] : trustedTime.reasonCodes.length > 0 ? trustedTime.reasonCodes : ['trusted-time-unavailable']),
  ]
  conditions.push(condition(
    'MKT-C10',
    auditOk ? 'pass' : 'fail',
    auditOk ? null : firstReason(auditReasons, 'trusted-time-unavailable'),
    [...(trustedTime.source === null ? [] : [`trusted-time:${trustedTime.source}`]), ...scheduler.evidenceRefs],
  ))

  return conditions
}

/**
 * Compute the immutable `market-eligibility/v1` decision.
 *
 * The decision is an AND over the **fixed** `MKT-C01..C10` set
 * (`MARKET_CONDITION_IDS`), never a caller/policy subset. `C05` is treated as a
 * pre-sign trust input here (provider/key state), while the actual signature is
 * independently verified after signing by the evidence sequence.
 */
export function computeEligibility(input: EligibilityInput): EligibilityComputation {
  const conditions = buildConditions(input)
  const conditionMap = new Map(conditions.map((entry) => [entry.id, entry]))
  const required = MARKET_CONDITION_IDS as readonly ConditionId[]
  const blockers: MarketBlocker[] = []
  const reasonCodes = new Set<string>()
  let decision: 'eligible' | 'non-eligible' = 'eligible'
  for (const conditionId of required) {
    const entry = conditionMap.get(conditionId)
    if (entry === undefined || entry.status !== 'pass') {
      decision = 'non-eligible'
      const reason = entry?.reason_code ??
        MARKET_REASON_CODES.MARKET_CONDITION_UNKNOWN_PREFIX + conditionId
      blockers.push({ condition_id: conditionId, reason_code: reason })
      reasonCodes.add(reason)
      if (entry === undefined || entry.status === 'unknown') {
        reasonCodes.add(MARKET_REASON_CODES.MARKET_CONDITION_UNKNOWN_PREFIX + conditionId)
      }
    }
  }
  if (decision === 'eligible' && input.approvals.approvals.length === 0) {
    decision = 'non-eligible'
    blockers.push({ condition_id: 'MKT-C08', reason_code: 'market-approval-missing' })
    reasonCodes.add('market-approval-missing')
  }

  const manifestInput = {
    receiptDigest: input.receipt.digest,
    isolationAttestationDigest: input.isolation.attestationDigest,
    isolationVerificationDigest: input.isolation.verificationDigest,
    policyDigest: input.policy.digest,
    runtimeAnchorDigest: input.runtime.anchorDigest,
    contractSuiteDigest: input.runtime.contractSuiteDigest,
    approvalDigests: input.approvals.approvalDigests,
    waiverDigests: input.approvals.waiverDigests,
    archiveAnchorDigest: input.subjectAnchorDigest ?? null,
  }
  const evidenceManifestDigest = input.evidenceManifestDigest ??
    marketManifestDigest(manifestInput)
  const decisionDigestMaterial = {
    run_id: input.receipt.runId,
    receipt_digest: input.receipt.digest,
    policy: input.policy.ref,
    decision,
    conditions,
    reason_codes: [...reasonCodes].sort(),
    evidence_manifest_digest: evidenceManifestDigest,
    evaluated_at: new Date(input.nowMs).toISOString(),
    approvals: input.approvals.approvals.map((approval) => ({
      principal: typeof approval.principal === 'string' && approval.principal.length > 0 ? approval.principal : 'unknown',
      role: typeof approval.role === 'string' && approval.role.length > 0 ? approval.role : 'reviewer',
      at: new Date(Number.isFinite(approval.atMs) ? approval.atMs : input.nowMs).toISOString(),
      scope: `target:${typeof approval.targetDigest === 'string' ? approval.targetDigest : 'unknown'}`,
      decision: typeof approval.decision === 'string' && approval.decision.length > 0 ? approval.decision : 'unknown',
      signature_ref: typeof approval.signatureRef === 'string' && approval.signatureRef.length > 0
        ? approval.signatureRef
        : null,
    })),
  }
  const decisionId = contentId('market-eligibility', canonicalDigest(decisionDigestMaterial))
  const limitations: string[] = [
    ...input.isolation.limitations,
    ...input.approvals.limitations,
    ...input.scheduler.limitations,
    ...(input.providers.signingLimitations ?? []),
    ...(input.providers.archiveLimitations ?? []),
  ]
  if (decision === 'non-eligible') limitations.push('market-conditions-not-all-pass')
  const eligibility: UnknownRecord = {
    schema_version: 'market-eligibility/v1',
    decision_id: decisionId,
    decision,
    run_id: input.receipt.runId as string,
    receipt_digest: input.receipt.digest as string,
    policy: input.policy.ref,
    evaluated_at: new Date(input.nowMs).toISOString(),
    conditions: conditions.map((entry) => ({
      id: entry.id,
      status: entry.status,
      evidence_refs: entry.evidence_refs,
      reason_code: entry.reason_code,
    })),
    reason_codes: [...reasonCodes].sort(),
    blockers,
    approvals: decisionDigestMaterial.approvals,
    evidence_manifest_digest: evidenceManifestDigest,
    limitations: [...new Set(limitations)],
  }
  const shaped = validateMarketEligibility(eligibility)
  if (!shaped.ok) {
    throw new TypeError(`market-eligibility/v1 invalid: ${shaped.errors.slice(0, 5).join(', ')}`)
  }
  const digest = canonicalDigest(eligibility)
  return {
    eligibility,
    digest,
    conditions,
    reasonCodes: [...reasonCodes].sort(),
    blockers,
    decision,
  }
}

/** Condition ids exported for tests and docs. */
export { MARKET_CONDITION_IDS }

/** Helper for callers that need the ordered condition ids. */
export function conditionIds(): readonly string[] {
  return MARKET_CONDITION_IDS
}
