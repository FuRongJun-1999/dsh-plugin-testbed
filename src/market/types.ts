/**
 * Market-gate integration types (t8).
 *
 * The market gate is an independent control-plane entry. It never rewrites
 * `receipt/v1`; every market conclusion lives in a sidecar
 * (`market-eligibility/v1`, `market-attestation/v1`,
 * `market-attestation-verification/v1`, `market-evidence-package/v1`) and is
 * only produced from verified evidence inputs.
 *
 * All types are strict and closed; no `any` escape is allowed by the migration
 * gate. JSON documents are modelled as `UnknownRecord` and narrowed explicitly
 * at the trust boundary.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/market/types
 */

import type { UnknownRecord, ValidationResult } from '../protocol/types.js'

export type { UnknownRecord, ValidationResult }

/** Status of one `market-eligibility/v1` condition (never widened). */
export type ConditionStatus = 'pass' | 'fail' | 'unknown' | 'not-applicable'

/** Fixed condition ids, `MKT-C01`..`MKT-C10` (§5.1.3). */
export type ConditionId =
  | 'MKT-C01'
  | 'MKT-C02'
  | 'MKT-C03'
  | 'MKT-C04'
  | 'MKT-C05'
  | 'MKT-C06'
  | 'MKT-C07'
  | 'MKT-C08'
  | 'MKT-C09'
  | 'MKT-C10'

/** One eligibility condition record. */
export interface MarketCondition {
  id: ConditionId
  status: ConditionStatus
  reason_code: string | null
  evidence_refs: string[]
  detail?: string
}

/** One structured eligibility blocker. */
export interface MarketBlocker {
  condition_id: ConditionId
  reason_code: string
}

/** `{id, version, digest}` reference used by the market protocol. */
export interface VersionRef {
  id: string
  version: string
  digest: string
}

/** Approval ledger entry embedded in `market-eligibility/v1`. */
export interface EligibilityApprovalRef {
  principal: string
  role: string
  at: string
  scope: string
  decision: string
  signature_ref: string | null
}

/** Frozen policy view consumed by the gate (derived from the JSON document). */
export interface MarketPolicyView {
  raw: UnknownRecord
  digest: string
  policyId: string
  policyVersion: string
  ref: VersionRef
  effectiveFromMs: number
  effectiveUntilMs: number | null
  evidenceMaxAgeMs: number
  maxAttestationAgeMs: number
  requiredIsolation: 'L2' | 'L3'
  requireL3For: string[]
  deniedRoots: string[]
  networkAllowlist: string[]
  isolationLimits: {
    cpu_ms: number
    memory_mb: number
    processes: number
    temp_bytes: number
    output_bytes: number
  }
  allowedRuntimes: Array<{ package: string; version: string; integrity: string }>
  allowedLaunchers: Array<{ launcher_id: string; attestation_required: boolean }>
  allowedSigners: Array<{ key_id: string; alg: string; state: string }>
  allowedArchives: Array<{ provider_id: string; mode: string }>
  requiredSuites: string[]
  waiverRules: {
    preApprovedOnly: boolean
    maxTtlHours: number
    forbiddenFor: string[]
    approverRoles: string[]
  }
  separationOfDuties: boolean
  failClosed: boolean
  approvalRoles: string[]
  schedulerRequired: boolean
  requiredConditions: ConditionId[]
}

/** Approval document validated by the market gate. */
export interface ApprovalRecord {
  raw: UnknownRecord
  approvalId: string
  principal: string
  role: string
  decision: string
  atMs: number
  expiresAtMs: number | null
  targetDigest: string
  isolationLevel: string
  policyDigest: string
  signatureRef: string | null
}

/** Waiver document validated by the market gate. */
export interface WaiverRecord {
  raw: UnknownRecord
  waiverId: string
  conditionId: ConditionId
  policyDigest: string
  runId: string
  targetDigest: string
  approvedAtMs: number
  expiresAtMs: number
  approvedBy: string
  approverRole: string
  status: string
}

/** Scheduler fencing evidence read by the gate (optional, policy-gated). */
export interface SchedulerEvidenceInput {
  lease: UnknownRecord
  events: UnknownRecord[]
}

/** Runtime (real Cordis/DSH) evidence summary. */
export interface RuntimeEvidence {
  status: 'available' | 'blocked'
  reasonCodes: string[]
  detail: string | null
  anchor: UnknownRecord | null
  anchorDigest: string | null
  cordisVersion: string | null
  dshVersion: string | null
  contractSuiteDigest: string | null
  catalogDigest: string | null
  lockfileDigest: string | null
  entryDigest: string | null
  environmentDigest: string | null
  contractPassed: boolean
  evidenceRefs: string[]
}

/** Isolation evidence summary supplied to the admission evaluator. */
export interface IsolationEvidence {
  status: 'admitted' | 'blocked'
  reasonCodes: string[]
  requiredLevel: 'L2' | 'L3' | null
  achievedLevel: string | null
  attestationDigest: string | null
  verificationDigest: string | null
  attestation: UnknownRecord | null
  admission: UnknownRecord | null
  evidenceRefs: string[]
  limitations: string[]
}

/** Evidence package manifest built by the gate. */
export interface EvidencePackage {
  manifest: UnknownRecord
  digest: string
  artifactPaths: string[]
}

/** Signing/archive provider trust assessment. */
export interface ProviderAssessment {
  signingProviderDoc: UnknownRecord | null
  archiveProviderDoc: UnknownRecord | null
  signingTrusted: boolean
  archiveTrusted: boolean
  signingKeyId: string | null
  signingAlg: string | null
  signingReasonCodes: string[]
  archiveReasonCodes: string[]
  signingLimitations: string[]
  archiveLimitations: string[]
}

/** Options accepted by `runMarketGate`. */
export interface RunMarketGateOptions {
  receipt: unknown
  policy: unknown
  /** Directory holding the materialized `cordis-contract-*` evidence. */
  contractEvidenceDir?: string
  /** Anchor document or path; a path is loaded with the v2 resolver. */
  runtimeAnchor?: unknown
  /** Base directory for an injected anchor object (lockfile resolution). */
  runtimeBaseDir?: string
  /** Raw `isolation-attestation/v1` document or path. */
  isolationAttestation?: unknown
  /** Raw `a2-suite/v1` evidence document or path. */
  a2Evidence?: unknown
  /** Optional isolation provider object (API injection only; CLI never sets it). */
  isolationProvider?: unknown
  /** Host facts object or path (default: explicit absence => blocked). */
  hostFacts?: unknown
  approvals?: unknown
  waivers?: unknown
  schedulerEvidence?: unknown
  /** Signing provider object; default: blocked provider from src/evidence. */
  signingProvider?: unknown
  /** Archive provider object; default: blocked provider from src/evidence. */
  archiveProvider?: unknown
  /** API-only switch used by provider-contract tests; CLI never enables it. */
  allowDevelopmentProviders?: boolean
  controlPlane?: { id: string; version: string; authorizationRef?: string }
  verifierId?: string
  now?: Date | string | number
  evidenceOutDir?: string
}

/** Final market-gate result returned to the API/CLI. */
export interface MarketGateResult {
  schema_version: 'market-gate-result/v1'
  status: 'blocked' | 'non-eligible' | 'published'
  market_eligible: boolean
  publish: boolean
  exit_code: 0 | 2 | 3
  failure_stage: string | null
  reason_codes: string[]
  run_id: string | null
  receipt_digest: string | null
  receipt_unchanged: boolean
  policy_digest: string | null
  runtime: RuntimeEvidence
  isolation: IsolationEvidence
  providers: ProviderAssessment
  conditions: MarketCondition[]
  eligibility: UnknownRecord | null
  eligibility_digest: string | null
  attestation: UnknownRecord | null
  attestation_digest: string | null
  verification: UnknownRecord | null
  evidence_package: UnknownRecord | null
  sidecars: Record<string, string>
  limitations: string[]
}

/** Receipt assessment for MKT-C04. */
export interface ReceiptAssessment {
  ok: boolean
  form: string | null
  errors: string[]
  reasonCodes: string[]
  receipt: UnknownRecord | null
  digest: string | null
  runId: string | null
  targetDigest: string | null
  targetKind: string | null
  earliestStartedAtMs: number | null
  requiredTestIds: string[]
}
