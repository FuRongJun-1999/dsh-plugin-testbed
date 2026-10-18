/**
 * `market-gate-policy/v1` validation and frozen-policy view (§6.8, MKT-02).
 *
 * A policy is a closed document: unknown versions/fields and any relaxation
 * (`fail_closed=false`, `separation_of_duties=false`, waivable hard conditions)
 * are rejected. The gate never mutates the policy after validation; the digest
 * is computed over the original document.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/market/policy
 */

import {
  MARKET_APPROVAL_ROLES,
  MARKET_CONDITION_IDS,
  MARKET_REASON_CODES,
  NON_WAIVABLE_CONDITIONS,
  validateMarketGatePolicy,
} from '../protocol/market-schemas.js'
import type { ConditionId, MarketPolicyView, UnknownRecord, VersionRef } from './types.js'
import {
  asFiniteNumber,
  asRecord,
  asString,
  canonicalDigest,
  isArray,
  isNonEmptyString,
  parseTimeMs,
} from './util.js'

const SEMVER = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/

/** Stable policy digest used by attestations, approvals and eligibility. */
export function policyDigest(policy: unknown): string {
  return canonicalDigest(policy)
}

/** The policy reference embedded in eligibility/approval/attestation docs. */
export function policyRef(policy: MarketPolicyView): VersionRef {
  return { id: policy.policyId, version: policy.policyVersion, digest: policy.digest }
}

function strings(value: unknown): string[] | null {
  if (!isArray(value)) return null
  const out: string[] = []
  for (const item of value) {
    if (!isNonEmptyString(item)) return null
    out.push(item)
  }
  return out
}

function readAllowedRuntimes(value: unknown): MarketPolicyView['allowedRuntimes'] | null {
  if (!isArray(value)) return null
  const out: MarketPolicyView['allowedRuntimes'] = []
  for (const item of value) {
    const record = asRecord(item)
    const pkg = asString(record?.package)
    const version = asString(record?.version)
    const integrity = asString(record?.integrity)
    if (!record || !pkg || !version || !integrity) return null
    out.push({ package: pkg, version, integrity })
  }
  return out
}

function readAllowedLaunchers(value: unknown): MarketPolicyView['allowedLaunchers'] | null {
  if (!isArray(value)) return null
  const out: MarketPolicyView['allowedLaunchers'] = []
  for (const item of value) {
    const record = asRecord(item)
    const launcherId = asString(record?.launcher_id)
    const attestationRequired = record?.attestation_required
    if (!record || !launcherId || typeof attestationRequired !== 'boolean') return null
    out.push({ launcher_id: launcherId, attestation_required: attestationRequired })
  }
  return out
}

function readAllowedSigners(value: unknown): MarketPolicyView['allowedSigners'] | null {
  if (!isArray(value)) return null
  const out: MarketPolicyView['allowedSigners'] = []
  for (const item of value) {
    const record = asRecord(item)
    const keyId = asString(record?.key_id)
    const alg = asString(record?.alg)
    const state = asString(record?.state)
    if (!record || !keyId || !alg || !state) return null
    out.push({ key_id: keyId, alg, state })
  }
  return out
}

function readAllowedArchives(value: unknown): MarketPolicyView['allowedArchives'] | null {
  if (!isArray(value)) return null
  const out: MarketPolicyView['allowedArchives'] = []
  for (const item of value) {
    const record = asRecord(item)
    const providerId = asString(record?.provider_id)
    const mode = asString(record?.mode)
    if (!record || !providerId || !mode) return null
    out.push({ provider_id: providerId, mode })
  }
  return out
}

function readWaiverRules(value: unknown): MarketPolicyView['waiverRules'] | null {
  const record = asRecord(value)
  if (!record) return null
  const maxTtlHours = asFiniteNumber(record.max_ttl_hours)
  const approverRoles = strings(record.approver_roles)
  const forbiddenFor = strings(record.forbidden_for)
  if (typeof record.pre_approved_only !== 'boolean' || maxTtlHours === null || !approverRoles || !forbiddenFor) return null
  return {
    preApprovedOnly: record.pre_approved_only,
    maxTtlHours,
    forbiddenFor,
    approverRoles,
  }
}

function dedupe(values: string[]): string[] {
  return [...new Set(values)]
}

export interface PolicyValidationResult {
  ok: boolean
  errors: string[]
  reasonCodes: string[]
  policy: MarketPolicyView | null
  digest: string | null
}

/**
 * Validate a frozen `market-gate-policy/v1` document against the wall clock and
 * derive the typed view used by every downstream condition.
 */
export function validateMarketPolicy(policyRaw: unknown, nowMs: number): PolicyValidationResult {
  const reasonCodes = new Set<string>()
  const fail = (reason: string, errors: string[]): PolicyValidationResult => {
    reasonCodes.add(reason)
    return { ok: false, errors, reasonCodes: [...reasonCodes], policy: null, digest: null }
  }

  const schema = validateMarketGatePolicy(policyRaw)
  if (!schema.ok) {
    return fail(MARKET_REASON_CODES.MARKET_POLICY_INVALID, schema.errors.slice(0, 20))
  }
  if (!asRecord(policyRaw)) return fail(MARKET_REASON_CODES.MARKET_POLICY_INVALID, ['policy-not-object'])
  const doc = policyRaw as UnknownRecord

  const errors: string[] = []
  const policyId = asString(doc.policy_id)
  const policyVersion = asString(doc.policy_version)
  if (!policyId) errors.push('policy-id-missing')
  if (!policyVersion || !SEMVER.test(policyVersion)) errors.push('policy-version-not-exact-semver')

  const effectiveFromMs = parseTimeMs(doc.effective_from)
  const effectiveUntilRaw = doc.effective_until
  const effectiveUntilMs = effectiveUntilRaw === null ? null : parseTimeMs(effectiveUntilRaw)
  if (effectiveFromMs === null) errors.push('effective-from-invalid')
  if (effectiveUntilRaw !== null && effectiveUntilMs === null) errors.push('effective-until-invalid')
  if (effectiveFromMs !== null && nowMs < effectiveFromMs) {
    errors.push('policy-not-yet-effective')
    reasonCodes.add(MARKET_REASON_CODES.MARKET_POLICY_NOT_EFFECTIVE)
  }
  if (effectiveUntilMs !== null && nowMs > effectiveUntilMs) {
    errors.push('policy-expired')
    reasonCodes.add(MARKET_REASON_CODES.MARKET_POLICY_EXPIRED)
  }
  if (effectiveFromMs !== null && effectiveUntilMs !== null && effectiveUntilMs < effectiveFromMs) {
    errors.push('effective-window-reversed')
  }

  const requiredIsolation = asRecord(doc.required_isolation)
  const minimum = asString(requiredIsolation?.minimum)
  const requireL3For = strings(requiredIsolation?.require_l3_for)
  if (!requiredIsolation || (minimum !== 'L2' && minimum !== 'L3') || !requireL3For) {
    errors.push('required-isolation-invalid')
  }
  const isolation = asRecord(doc.isolation)
  const isolationLevel = asString(isolation?.required_level)
  const maxAttestationAgeMs = asFiniteNumber(isolation?.max_attestation_age_ms)
  const deniedRoots = isolation === null ? null : strings(isolation.denied_roots)
  const networkAllowlist = isolation === null ? null : strings(isolation.network_allowlist)
  const limitsRecord = isolation === null ? null : asRecord(isolation.limits)
  const isolationLimitKeys = ['cpu_ms', 'memory_mb', 'processes', 'temp_bytes', 'output_bytes'] as const
  const isolationLimits = limitsRecord === null
    ? null
    : Object.fromEntries(isolationLimitKeys.map((key) => [key, asFiniteNumber(limitsRecord[key])])) as
      Record<(typeof isolationLimitKeys)[number], number | null>
  const limitsValid = isolationLimits !== null &&
    isolationLimitKeys.every((key) => isolationLimits[key] !== null && (isolationLimits[key] as number) > 0)
  if (!isolation || (isolationLevel !== 'L2' && isolationLevel !== 'L3') || maxAttestationAgeMs === null || maxAttestationAgeMs <= 0) {
    errors.push('isolation-policy-invalid')
  }
  if (!deniedRoots || deniedRoots.length === 0) errors.push('isolation-denied-roots-missing')
  if (!networkAllowlist) errors.push('isolation-network-allowlist-invalid')
  if (!limitsValid) errors.push('isolation-limits-invalid')
  if (minimum && isolationLevel && minimum !== isolationLevel) {
    errors.push('isolation-policy-inconsistent')
    reasonCodes.add(MARKET_REASON_CODES.MARKET_POLICY_INVALID)
  }

  const allowedRuntimes = readAllowedRuntimes(doc.allowed_runtimes)
  const allowedLaunchers = readAllowedLaunchers(doc.allowed_launchers)
  const allowedSigners = readAllowedSigners(doc.allowed_signers)
  const allowedArchives = readAllowedArchives(doc.allowed_archives)
  const requiredSuites = strings(doc.required_suites)
  const waiverRules = readWaiverRules(doc.waiver_rules)
  if (!allowedRuntimes || allowedRuntimes.length === 0) errors.push('allowed-runtimes-empty')
  if (!allowedLaunchers || allowedLaunchers.length === 0) errors.push('allowed-launchers-empty')
  if (!allowedSigners || allowedSigners.length === 0) errors.push('allowed-signers-empty')
  if (!allowedArchives || allowedArchives.length === 0) errors.push('allowed-archives-empty')
  if (!requiredSuites || requiredSuites.length === 0) errors.push('required-suites-empty')
  if (!waiverRules) errors.push('waiver-rules-invalid')

  const separationOfDuties = doc.separation_of_duties
  if (separationOfDuties !== true) errors.push('separation-of-duties-must-be-true')
  if (doc.fail_closed !== true) errors.push('fail-closed-must-be-true')
  if (waiverRules && waiverRules.preApprovedOnly !== true) errors.push('waiver-must-be-pre-approved-only')
  if (waiverRules) {
    for (const conditionId of NON_WAIVABLE_CONDITIONS) {
      if (!waiverRules.forbiddenFor.includes(conditionId)) {
        errors.push(`waiver-rules-must-forbid:${conditionId}`)
      }
    }
    const badRoles = waiverRules.approverRoles.filter(
      (role) => !(MARKET_APPROVAL_ROLES as readonly string[]).includes(role),
    )
    if (badRoles.length > 0) errors.push(`waiver-approver-role-unknown:${badRoles.join(',')}`)
  }
  if (requiredSuites) {
    const normalized = requiredSuites.map((suite) => suite.toLowerCase())
    for (const required of ['cordis-contract-suite/v1', 'a2']) {
      if (!normalized.includes(required)) errors.push(`required-suite-missing:${required}`)
    }
  }
  const activeSigner = allowedSigners !== null && allowedSigners.some((signer) => signer.state === 'active')
  if (allowedSigners !== null && !activeSigner) errors.push('no-active-allowed-signer')

  let approvalRoles = ['reviewer', 'security', 'release']
  if (doc.approval_roles !== undefined) {
    const roles = strings(doc.approval_roles)
    if (!roles || roles.length < 2) errors.push('approval-roles-invalid')
    else {
      const bad = roles.filter((role) => !(MARKET_APPROVAL_ROLES as readonly string[]).includes(role))
      if (bad.length > 0) errors.push(`approval-role-unknown:${bad.join(',')}`)
      approvalRoles = dedupe(roles)
    }
  }

  // The condition set is fixed: the policy must enumerate all ten MKT-C01..C10
  // exactly, and the gate/eligibility engine never trusts a caller subset.
  // Omitted, partial, duplicate or unknown sets are policy-invalid.
  const requiredConditions = [...MARKET_CONDITION_IDS] as ConditionId[]
  const declaredConditions = strings(doc.required_conditions)
  if (declaredConditions === null) {
    errors.push('required-conditions-invalid')
  } else {
    const unknown = declaredConditions.filter((id) => !(MARKET_CONDITION_IDS as readonly string[]).includes(id))
    if (unknown.length > 0) errors.push(`required-condition-unknown:${unknown.join(',')}`)
    const declared = dedupe(declaredConditions)
    const complete = declared.length === MARKET_CONDITION_IDS.length &&
      MARKET_CONDITION_IDS.every((id) => declared.includes(id))
    if (!complete) errors.push('required-conditions-must-be-all-c01..c10')
  }

  const evidenceMaxAgeHours = asFiniteNumber(doc.evidence_max_age_hours)
  if (evidenceMaxAgeHours === null || evidenceMaxAgeHours <= 0) errors.push('evidence-max-age-invalid')

  if (errors.length > 0) {
    reasonCodes.add(MARKET_REASON_CODES.MARKET_POLICY_INVALID)
    return { ok: false, errors, reasonCodes: [...reasonCodes], policy: null, digest: null }
  }

  const digest = policyDigest(doc)
  const view: MarketPolicyView = {
    raw: doc,
    digest,
    policyId: policyId as string,
    policyVersion: policyVersion as string,
    ref: { id: policyId as string, version: policyVersion as string, digest },
    effectiveFromMs: effectiveFromMs as number,
    effectiveUntilMs,
    evidenceMaxAgeMs: (evidenceMaxAgeHours as number) * 3_600_000,
    maxAttestationAgeMs: maxAttestationAgeMs as number,
    requiredIsolation: minimum as 'L2' | 'L3',
    requireL3For: requireL3For as string[],
    deniedRoots: deniedRoots as string[],
    networkAllowlist: networkAllowlist as string[],
    isolationLimits: isolationLimits as MarketPolicyView['isolationLimits'],
    allowedRuntimes: allowedRuntimes as MarketPolicyView['allowedRuntimes'],
    allowedLaunchers: allowedLaunchers as MarketPolicyView['allowedLaunchers'],
    allowedSigners: allowedSigners as MarketPolicyView['allowedSigners'],
    allowedArchives: allowedArchives as MarketPolicyView['allowedArchives'],
    requiredSuites: requiredSuites as string[],
    waiverRules: waiverRules as MarketPolicyView['waiverRules'],
    separationOfDuties: true,
    failClosed: true,
    approvalRoles,
    schedulerRequired: doc.scheduler_required === true,
    requiredConditions,
  }
  return { ok: true, errors: [], reasonCodes: [], policy: view, digest }
}
