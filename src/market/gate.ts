/**
 * Market-gate orchestration (t8 integration entry).
 *
 * This is an independent entry: it never rewrites `receipt/v1`, never touches
 * the local selfcheck profile, and never publishes from a local/L1 result. The
 * flow is:
 *
 *   receipt strict validation
 *     → frozen policy validation
 *     → real runtime anchor/contract (C03)
 *     → isolation admission (C01/C02)
 *     → approvals/waivers (C08/C09)
 *     → provider trust (C05/C06) + trusted time (C10)
 *     → (only when inputs pass and a real archive/signer exists, or an
 *        explicit API-only development-provider test switch is set)
 *       archive subject entry N → market-eligibility/v1 → sign → entry N+1 →
 *       independent verification
 *
 * In the current environment the signer/archive factories are blocked and the
 * A2 suite is partial, so the gate returns `blocked` / `non-eligible` with
 * stable reason codes and exit code 2. Exit 0 is only possible after a fully
 * verified publish path.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/market/gate
 */

import { writeFile, mkdir } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { recordDigest } from '../protocol/digest.js'
import { validateReceiptV1 } from '../protocol/contracts.js'
import { MARKET_CONDITION_IDS, MARKET_REASON_CODES } from '../protocol/market-schemas.js'
import {
  evidenceManifestDigest,
  runMarketEvidenceSequence,
} from '../evidence/index.js'
import type { ArchiveProviderLike, SigningProviderLike } from '../evidence/types.js'
import { validateLease, verifyEventChain } from '../scheduler/index.js'
import { validateApprovalLedger } from './approvals.js'
import { assessIsolation } from './isolation.js'
import { assessReceipt, computeEligibility, type EligibilityComputation, type SchedulerAssessment } from './eligibility.js'
import { assessProviders } from './providers.js'
import { validateMarketPolicy } from './policy.js'
import { verifyRuntimeEvidence } from './runtime.js'
import {
  buildEvidencePackage,
  describeArtifact,
  verifyEvidencePackage,
  writeEvidencePackage,
} from './evidence-package.js'
import type {
  ConditionId,
  EvidencePackage,
  IsolationEvidence,
  MarketCondition,
  MarketGateResult,
  MarketPolicyView,
  ProviderAssessment,
  RunMarketGateOptions,
  RuntimeEvidence,
  UnknownRecord,
} from './types.js'
import {
  asRecord,
  canonicalDigest,
  contentId,
  isArray,
  isNonEmptyString,
  loadJsonOption,
  resolveNowMs,
} from './util.js'

const GATE_VERSION = '1.0.0'

function nowIso(ms: number): string {
  return new Date(ms).toISOString()
}

function emptyRuntime(): RuntimeEvidence {
  return {
    status: 'blocked',
    reasonCodes: ['runtime-anchor-missing'],
    detail: 'runtime not evaluated',
    anchor: null,
    anchorDigest: null,
    cordisVersion: null,
    dshVersion: null,
    contractSuiteDigest: null,
    catalogDigest: null,
    lockfileDigest: null,
    entryDigest: null,
    environmentDigest: null,
    contractPassed: false,
    evidenceRefs: [],
  }
}

function emptyIsolation(): IsolationEvidence {
  return {
    status: 'blocked',
    reasonCodes: ['isolation-attestation-missing'],
    requiredLevel: null,
    achievedLevel: null,
    attestationDigest: null,
    verificationDigest: null,
    attestation: null,
    admission: null,
    evidenceRefs: [],
    limitations: [],
  }
}

function emptyProviders(): ProviderAssessment {
  return {
    signingProviderDoc: null,
    archiveProviderDoc: null,
    signingTrusted: false,
    archiveTrusted: false,
    signingKeyId: null,
    signingAlg: null,
    signingReasonCodes: ['signing-provider-missing'],
    archiveReasonCodes: ['archive-provider-missing'],
    signingLimitations: [],
    archiveLimitations: [],
  }
}

function emptyScheduler(): SchedulerAssessment {
  return { present: false, ok: true, reasonCodes: [], evidenceRefs: [], limitations: [] }
}

function baseResult(): MarketGateResult {
  return {
    schema_version: 'market-gate-result/v1',
    status: 'blocked',
    market_eligible: false,
    publish: false,
    exit_code: 2,
    failure_stage: 'intake',
    reason_codes: [],
    run_id: null,
    receipt_digest: null,
    receipt_unchanged: false,
    policy_digest: null,
    runtime: emptyRuntime(),
    isolation: emptyIsolation(),
    providers: emptyProviders(),
    conditions: [],
    eligibility: null,
    eligibility_digest: null,
    attestation: null,
    attestation_digest: null,
    verification: null,
    evidence_package: null,
    sidecars: {},
    limitations: [],
  }
}

function stageForCondition(conditionId: ConditionId): string {
  switch (conditionId) {
    case 'MKT-C01':
    case 'MKT-C02':
      return 'isolation-admission'
    case 'MKT-C03':
      return 'runtime-anchor'
    case 'MKT-C04':
      return 'receipt-validation'
    case 'MKT-C05':
      return 'sign'
    case 'MKT-C06':
      return 'archive-subject'
    case 'MKT-C07':
      return 'evidence-package'
    case 'MKT-C08':
    case 'MKT-C09':
      return 'approval'
    case 'MKT-C10':
      return 'trusted-time'
    default:
      return 'eligibility'
  }
}

function failingReasons(conditions: MarketCondition[], required: readonly ConditionId[]): string[] {
  const map = new Map(conditions.map((entry) => [entry.id, entry]))
  const out: string[] = []
  for (const id of required) {
    const entry = map.get(id)
    if (entry === undefined || entry.status === 'pass') continue
    if (entry.reason_code !== null) out.push(entry.reason_code)
  }
  return [...new Set(out)]
}

function schedulerAssessment(raw: unknown, policy: MarketPolicyView): SchedulerAssessment {
  if (raw === undefined || raw === null) {
    return policy.schedulerRequired
      ? {
          present: false,
          ok: false,
          reasonCodes: ['scheduler-disabled'],
          evidenceRefs: [],
          limitations: ['scheduler-disabled-by-default'],
        }
      : {
          present: false,
          ok: true,
          reasonCodes: [],
          evidenceRefs: [],
          limitations: ['scheduler-disabled-by-default'],
        }
  }
  const record = asRecord(raw)
  const lease = asRecord(record?.lease)
  const events = isArray(record?.events) ? record.events : null
  if (lease === null || events === null) {
    return {
      present: true,
      ok: false,
      reasonCodes: ['market-scheduler-evidence-invalid'],
      evidenceRefs: [],
      limitations: ['scheduler-evidence-shape-invalid'],
    }
  }
  const leaseCheck = validateLease(lease)
  const chainCheck = verifyEventChain(events)
  const ok = leaseCheck.ok && chainCheck.ok && chainCheck.count > 0
  const evidenceRefs = [`scheduler-lease:${canonicalDigest(lease)}`, `scheduler-events:${canonicalDigest(events)}`]
  if (!ok) {
    return {
      present: true,
      ok: false,
      reasonCodes: ['market-scheduler-evidence-invalid'],
      evidenceRefs,
      limitations: [
        ...(leaseCheck.ok ? [] : leaseCheck.errors.slice(0, 3)),
        ...(chainCheck.ok ? [] : chainCheck.errors.slice(0, 3)),
      ],
    }
  }
  return { present: true, ok: true, reasonCodes: [], evidenceRefs, limitations: [] }
}

function trustedTimeAssessment(providers: ProviderAssessment): {
  verified: boolean
  source: string | null
  reasonCodes: string[]
} {
  const archiveDoc = asRecord(providers.archiveProviderDoc)
  const trustedTime = archiveDoc === null ? null : asRecord(archiveDoc.trusted_time)
  const source = trustedTime !== null && isNonEmptyString(trustedTime.source) ? trustedTime.source : null
  const verified = trustedTime !== null && trustedTime.verified === true &&
    source !== null && source !== 'host-clock-development-only'
  return {
    verified,
    source,
    reasonCodes: verified ? [] : ['trusted-time-unavailable'],
  }
}

function pickString(record: UnknownRecord | null, key: string): string | null {
  const value = record === null ? undefined : record[key]
  return isNonEmptyString(value) ? value : null
}

async function writeSidecars(
  result: MarketGateResult,
  eligibility: EligibilityComputation | null,
  evidenceOutDir: string | undefined,
): Promise<void> {
  if (evidenceOutDir === undefined) return
  const out = resolve(evidenceOutDir)
  await mkdir(out, { recursive: true })
  const artifacts: Array<{ path: string; kind: string }> = []
  const sidecarPaths: Record<string, string> = {}
  const writeJson = async (relPath: string, kind: string, value: unknown): Promise<void> => {
    const target = join(out, relPath)
    await mkdir(dirname(target), { recursive: true })
    await writeFile(target, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
    sidecarPaths[kind] = relPath
    artifacts.push({ path: relPath, kind })
  }
  if (eligibility?.eligibility != null) {
    await writeJson('market/eligibility.json', 'market-eligibility/v1', eligibility.eligibility)
  }
  if (result.attestation !== null) {
    await writeJson('market/attestation.json', 'market-attestation/v1', result.attestation)
  }
  if (result.verification !== null) {
    await writeJson('market/verification.json', 'market-attestation-verification/v1', result.verification)
  }
  const resultForDisk = { ...result, evidence_package: null, sidecars: sidecarPaths }
  await writeJson('market-gate-result.json', 'market-gate-result/v1', resultForDisk)
  result.sidecars = sidecarPaths
  if (artifacts.length === 0) return
  const described: Array<{ path: string; kind: string; digest: string; size_bytes: number }> = []
  for (const artifact of artifacts) {
    const info = await describeArtifact(out, artifact.path, artifact.kind)
    if (!info.ok) {
      result.limitations.push(`evidence-package-incomplete:${info.detail}`)
      return
    }
    described.push(info.artifact)
  }
  if (result.run_id === null || result.receipt_digest === null) return
  const built: EvidencePackage = buildEvidencePackage({
    packageId: contentId('market-evidence', canonicalDigest({ run: result.run_id, receipt: result.receipt_digest })),
    runId: result.run_id,
    receiptDigest: result.receipt_digest,
    artifacts: described,
    createdAt: nowIso(Date.now()),
    retention: { until: null, policy_ref: null },
    redaction: { status: 'not-reviewed', notes: 'no-secrets-reviewed-by-gate' },
  })
  await writeEvidencePackage(out, built.manifest)
  const verified = await verifyEvidencePackage(built.manifest, { root: out, rejectUnregistered: true })
  if (!verified.ok) {
    result.limitations.push(`evidence-package-verification-failed:${verified.errors.slice(0, 3).join(';')}`)
    return
  }
  result.evidence_package = built.manifest
}

/**
 * Run the independent market gate.
 *
 * The function never throws for verification failures: a blocked task is a
 * result, not an exception. Programming errors (invalid schema built by this
 * module) still throw so tests catch them.
 */
export async function runMarketGate(options: RunMarketGateOptions): Promise<MarketGateResult> {
  if (options === null || typeof options !== 'object') {
    throw new TypeError('runMarketGate requires an options object')
  }
  const nowMs = resolveNowMs(options.now)
  const result = baseResult()
  const limitations: string[] = []
  let finalEligibility: EligibilityComputation | null = null

  const finish = async (patch: Partial<MarketGateResult>, exitCode: 0 | 2 | 3): Promise<MarketGateResult> => {
    Object.assign(result, patch)
    result.exit_code = exitCode
    const publish = result.publish === true
    if (publish) {
      result.status = 'published'
      result.market_eligible = true
      result.exit_code = 0
    } else if (result.status !== 'blocked' && result.status !== 'non-eligible') {
      result.status = 'non-eligible'
    }
    result.limitations = [...new Set([...result.limitations, ...limitations])]
    await writeSidecars(result, finalEligibility, options.evidenceOutDir)
    return result
  }

  // -------------------------------------------------------------------------
  // 1. Receipt intake: schema/digest failure is a control-plane failure (3).
  // -------------------------------------------------------------------------
  const receiptLoad = await loadJsonOption(options.receipt)
  if (!receiptLoad.ok) {
    result.reason_codes = [MARKET_REASON_CODES.MARKET_RECEIPT_INVALID]
    result.failure_stage = 'receipt-validation'
    return finish({ receipt_unchanged: false }, 3)
  }
  const receiptRaw = receiptLoad.value
  const receiptRecord = asRecord(receiptRaw)
  if (receiptRecord === null) {
    result.reason_codes = [MARKET_REASON_CODES.MARKET_RECEIPT_INVALID]
    result.failure_stage = 'receipt-validation'
    return finish({}, 3)
  }
  const receiptValidation = validateReceiptV1(receiptRecord, { verifyDigest: true })
  if (!receiptValidation.ok) {
    result.reason_codes = [MARKET_REASON_CODES.MARKET_RECEIPT_INVALID, ...receiptValidation.errors.slice(0, 5)]
    result.failure_stage = 'receipt-validation'
    return finish({}, 3)
  }
  const receiptDigest = recordDigest(receiptRecord)
  result.receipt_digest = receiptDigest
  result.run_id = pickString(receiptRecord, 'run_id')
  const receipt = assessReceipt(receiptRecord)
  result.receipt_unchanged = receiptDigest === recordDigest(receiptRecord)

  // -------------------------------------------------------------------------
  // 2. Frozen policy intake. Missing/invalid policy is blocked (2), never 3.
  // -------------------------------------------------------------------------
  const policyLoad = await loadJsonOption(options.policy)
  if (!policyLoad.ok) {
    result.reason_codes = [
      policyLoad.reason === 'input-missing'
        ? MARKET_REASON_CODES.MARKET_POLICY_MISSING
        : MARKET_REASON_CODES.MARKET_POLICY_INVALID,
      policyLoad.reason,
    ]
    result.failure_stage = 'policy-freeze'
    result.conditions = receipt.ok
      ? []
      : [{ id: 'MKT-C04', status: 'fail', reason_code: 'market-receipt-invalid', evidence_refs: [] }]
    return finish({ status: 'blocked' }, 2)
  }
  const policyCheck = validateMarketPolicy(policyLoad.value, nowMs)
  if (!policyCheck.ok || policyCheck.policy === null) {
    result.reason_codes = [...policyCheck.reasonCodes, ...policyCheck.errors.slice(0, 5)]
    result.failure_stage = 'policy-freeze'
    return finish({ status: 'blocked' }, 2)
  }
  const policy = policyCheck.policy
  result.policy_digest = policy.digest

  // -------------------------------------------------------------------------
  // 3. Evidence intake (runtime, isolation, approvals, providers, scheduler).
  // -------------------------------------------------------------------------
  const runtime = await verifyRuntimeEvidence({
    anchor: options.runtimeAnchor,
    contractEvidenceDir: options.contractEvidenceDir,
    runtimeBaseDir: options.runtimeBaseDir,
    policy,
    nowMs,
  })
  const isolationLoad = await loadJsonOption(options.isolationAttestation)
  const a2Load = await loadJsonOption(options.a2Evidence)
  const hostFactsLoad = await loadJsonOption(options.hostFacts)
  const isolation = assessIsolation({
    attestation: options.isolationAttestation === undefined
      ? undefined
      : isolationLoad.ok ? isolationLoad.value : undefined,
    a2Evidence: options.a2Evidence === undefined ? undefined : a2Load.ok ? a2Load.value : undefined,
    provider: options.isolationProvider,
    hostFacts: options.hostFacts === undefined ? undefined : hostFactsLoad.ok ? hostFactsLoad.value : undefined,
    policy,
    runId: receipt.runId,
    planId: pickString(receiptRecord, 'plan_id'),
    nowMs,
  })
  const providers = await assessProviders({
    policy,
    signingProvider: options.signingProvider,
    archiveProvider: options.archiveProvider,
  })
  const scheduler = schedulerAssessment(options.schedulerEvidence, policy)
  const trustedTime = trustedTimeAssessment(providers)
  const ledgerRecord = await loadJsonOption(options.approvals)
  const waiverRecord = await loadJsonOption(options.waivers)
  const approvalDocs = ledgerRecord.ok ? ledgerRecord.value : ledgerRecord.reason === 'input-missing' ? undefined : []
  const waiverDocs = waiverRecord.ok ? waiverRecord.value : undefined
  const approvals = validateApprovalLedger(approvalDocs, waiverDocs, {
    policy,
    receiptDigest: receipt.digest,
    runId: receipt.runId,
    targetDigest: receipt.targetDigest,
    requiredIsolation: policy.requiredIsolation,
    earliestStartedAtMs: receipt.earliestStartedAtMs,
    nowMs,
    forbiddenPrincipals: [
      ...(providers.signingProviderDoc && isNonEmptyString(providers.signingProviderDoc.provider_id)
        ? [providers.signingProviderDoc.provider_id as string]
        : []),
      ...(providers.archiveProviderDoc && isNonEmptyString(providers.archiveProviderDoc.provider_id)
        ? [providers.archiveProviderDoc.provider_id as string]
        : []),
    ],
  })

  const eligibilityInputBase = {
    policy,
    receipt,
    runtime,
    isolation,
    providers,
    approvals,
    scheduler,
    trustedTime,
    nowMs,
  }
  const preflight = computeEligibility({ ...eligibilityInputBase, subjectAnchor: null, subjectAnchorDigest: null })
  result.runtime = runtime
  result.isolation = isolation
  result.providers = providers
  result.conditions = preflight.conditions

  // -------------------------------------------------------------------------
  // 4. Pre-sequence block: missing/failed inputs stop before any evidence write.
  // -------------------------------------------------------------------------
  const sequenceExempt = new Set(['MKT-C05', 'MKT-C06', 'MKT-C10'])
  const inputRequired = (MARKET_CONDITION_IDS as readonly ConditionId[])
    .filter((id) => !sequenceExempt.has(id))
  const inputFailures = inputRequired.filter((id) => {
    const entry = preflight.conditions.find((condition) => condition.id === id)
    return entry === undefined || entry.status !== 'pass'
  })
  const providersReady = providers.signingTrusted && providers.archiveTrusted
  const mayRunSequence = inputFailures.length === 0 &&
    (providersReady || options.allowDevelopmentProviders === true)
  if (!mayRunSequence) {
    const reasonCodes = failingReasons(preflight.conditions, MARKET_CONDITION_IDS as readonly ConditionId[])
    if (reasonCodes.length === 0) reasonCodes.push(MARKET_REASON_CODES.MARKET_RUN_NOT_ELIGIBLE)
    result.reason_codes = reasonCodes
    result.failure_stage = inputFailures.length > 0
      ? stageForCondition(inputFailures[0])
      : 'sign'
    result.status = 'non-eligible'
    if (!receipt.ok) result.status = 'blocked'
    limitations.push('market-gate-preflight-blocked-no-evidence-written')
    if (!providersReady) {
      if (!providers.signingTrusted) limitations.push('signing-provider-not-market-independent')
      if (!providers.archiveTrusted) limitations.push('archive-provider-not-market-independent')
    }
    return finish({}, 2)
  }

  // -------------------------------------------------------------------------
  // 5. Ordered evidence sequence with the injected eligibility engine.
  // -------------------------------------------------------------------------
  const signingProvider = (options.signingProvider ?? null) as SigningProviderLike | null
  const archiveProvider = (options.archiveProvider ?? null) as ArchiveProviderLike | null
  if (signingProvider === null || archiveProvider === null) {
    result.reason_codes = ['signing-provider-missing', 'archive-provider-missing']
    result.failure_stage = 'archive-subject'
    return finish({ status: 'blocked' }, 2)
  }
  const controlPlane = options.controlPlane ?? { id: 'market-gate', version: GATE_VERSION }
  const verifierId = options.verifierId ?? `market-gate-verifier/${GATE_VERSION}`
  const now = nowIso(nowMs)
  const sequence = await runMarketEvidenceSequence({
    receipt: receiptRecord,
    isolation: {
      level: policy.requiredIsolation,
      attestation_digest: isolation.attestationDigest as string,
      verification_digest: isolation.verificationDigest as string,
    },
    policy: policy.ref,
    approvalDigests: approvals.approvalDigests,
    controlPlane: { id: controlPlane.id, version: controlPlane.version, policy_ref: policy.ref },
    runtime: {
      cordis_version: runtime.cordisVersion as string,
      dsh_version: runtime.dshVersion as string,
      anchor_digest: runtime.anchorDigest as string,
      contract_suite_digest: runtime.contractSuiteDigest as string,
    },
    archiveProvider,
    signingProvider,
    computeEligibility: async (sequenceInput) => {
      const subjectDigest = canonicalDigest(sequenceInput.subjectAnchor)
      const sequenceManifestDigest = evidenceManifestDigest({
        receiptDigest: receiptDigest,
        isolationAttestationDigest: isolation.attestationDigest,
        isolationVerificationDigest: isolation.verificationDigest,
        policyDigest: policy.digest,
        approvalDigests: approvals.approvalDigests,
        archiveAnchorDigest: subjectDigest,
      })
      const computation = computeEligibility({
        ...eligibilityInputBase,
        subjectAnchor: sequenceInput.subjectAnchor as unknown as UnknownRecord,
        subjectAnchorDigest: subjectDigest,
        evidenceManifestDigest: sequenceManifestDigest,
      })
      finalEligibility = computation
      return computation.eligibility
    },
    requester: {
      control_plane_id: controlPlane.id,
      authorization_ref: `market-gate:${receiptDigest}`,
    },
    attestationId: contentId('market-attestation', canonicalDigest({ run: receipt.runId, policy: policy.digest, at: now })),
    requestId: contentId('market-request', canonicalDigest({ run: receipt.runId, policy: policy.digest })),
    signing: {
      key_id: providers.signingKeyId ?? 'unknown',
      alg: providers.signingAlg ?? 'ed25519',
      signed_at: now,
      provider_audit_ref: `market-gate-audit:${policy.digest}`,
    },
    verifier: { id: verifierId, verifiedAt: now },
    expectedMinimumIsolation: policy.requiredIsolation,
  })

  result.eligibility = (sequence.eligibility as unknown as UnknownRecord | undefined) ?? null
  result.eligibility_digest = sequence.eligibility_digest ?? null
  result.attestation = (sequence.attestation as unknown as UnknownRecord | undefined) ?? null
  result.attestation_digest = sequence.attestation_digest ?? null
  result.verification = (sequence.verification as unknown as UnknownRecord | undefined) ?? null
  result.reason_codes = [...sequence.reason_codes]
  result.failure_stage = sequence.failure_stage ?? null
  const verified = sequence.verification?.result === 'valid' &&
    sequence.evidence_class === 'E3' && sequence.market_eligible === true && sequence.publish === true
  result.publish = verified
  result.market_eligible = verified
  if (verified) {
    result.status = 'published'
  } else if (sequence.status === 'blocked') {
    result.status = 'blocked'
  } else {
    result.status = 'non-eligible'
  }
  if (!result.receipt_unchanged) {
    result.publish = false
    result.market_eligible = false
    result.status = 'blocked'
    result.reason_codes = [...new Set([...result.reason_codes, MARKET_REASON_CODES.INTERNAL_ERROR])]
    result.failure_stage = 'verification'
  }
  return finish({}, verified ? 0 : 2)
}

/** Re-exported for API consumers (src/index.js). */
export { MARKET_REASON_CODES }

/** Convert a scheduler evidence object into the `validateLease`-checked shape. */
export function schedulerEvidenceFrom(value: unknown): SchedulerAssessment {
  const raw = asRecord(value)
  if (raw === null) return emptyScheduler()
  return {
    present: true,
    ok: true,
    reasonCodes: [],
    evidenceRefs: [`scheduler:${canonicalDigest(raw)}`],
    limitations: [],
  }
}
