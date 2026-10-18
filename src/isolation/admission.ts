/**
 * Isolation admission — the fail-closed bridge between isolation providers,
 * `isolation-attestation/v1`, A2/A3 evidence and the market gate.
 *
 * Admission can return `admitted` **only if all of the following are true**:
 *   - the host itself is a verified low-privilege session with no ambient
 *     credentials;
 *   - an externally measured L2 (or L3) provider is available at grade E2/E3;
 *   - every isolation dimension is attested as enforced;
 *   - the attestation binds run/plan/test/attempt/launcher/provider/policy,
 *     is fresh and its nonce is single-use;
 *   - the A2 suite (L2) or A3 suite (L3) passed with externally measured,
 *     low-privilege evidence — never a fixture/test double;
 *   - for a remote L3 runner, a signed `runner-attestation/v1` passes pinned-key,
 *     allowlist, freshness, nonce and revocation checks.
 *
 * On the current host the provider catalog is empty of available providers, so
 * admission is blocked and reports `market_eligibility="non-eligible"`. This
 * module never launches a worker and never falls back to L1. Full market
 * eligibility additionally requires runtime anchor, receipt validation, signing,
 * independent archive and approvals (implemented outside this module).
 *
 * @module @deepseek-ai/dsh-plugin-testbed/isolation/admission
 */
import {
  ISOLATION_ADMISSION_SCHEMA_VERSION,
  ISOLATION_REASON,
  MARKET_GATE_POLICY_VERSION,
  MARKET_ISOLATION_LEVELS,
  LOW_PRIVILEGE_INTEGRITY,
  deepFreeze,
  isMarketIsolationLevel,
  isPlainRecord,
  isolationLevelRank,
  policyDigestOf,
  suiteEvidenceDigest,
  validateLauncherDescriptor,
  type LauncherDescriptor,
  type MarketIsolationLevel,
} from './contracts.js'
import {
  verifyIsolationAttestation,
  type AttestationExpected,
  type AttestationVerification,
  type NonceRegistryLike,
  type PinnedKey,
  type SignatureVerifier,
} from './attestation.js'
import {
  verifyRunnerAttestation,
  type RevocationCheckInput,
  type RunnerAttestationExpected,
  type RunnerAttestationVerification,
} from './runner-attestation.js'
import { evaluateA2Evidence } from './a2.js'
import { evaluateA3Evidence } from './a3.js'
import { hostFingerprint, type HostFacts } from './host-capabilities.js'
import {
  PROVIDER_IDS,
  selectIsolationProvider,
  type IsolationProvider,
  type ProviderSelection,
} from './providers.js'
import type { SuiteEvaluation } from './suite-evidence.js'

export interface IsolationAdmissionInput {
  required_level: string
  provider?: IsolationProvider | null
  provider_selection?: ProviderSelection | null
  host_facts?: HostFacts | null
  policy?: unknown
  attestation?: unknown
  attestation_expected?: AttestationExpected
  nonce_registry?: NonceRegistryLike
  verify_signature?: SignatureVerifier
  pinned_keys?: Record<string, PinnedKey>
  a2_evidence?: unknown
  a3_evidence?: unknown
  runner_attestation?: unknown
  runner_expected?: RunnerAttestationExpected
  runner_verify_signature?: SignatureVerifier
  runner_pinned_keys?: Record<string, PinnedKey>
  is_revoked?: (input: RevocationCheckInput) => boolean
  test_double?: boolean
  now?: Date | string | number
  verified_by?: string
}

export interface IsolationAdmissionCheck {
  id: string
  status: 'pass' | 'fail'
  detail?: string
}

export interface IsolationAdmissionProviderRef {
  provider_id: string | null
  level: string | null
  provider_digest: string | null
  launcher_version: string | null
  available: boolean
  evidence_grade: string
  provenance: string
}

export interface IsolationAdmission {
  schema_version: string
  result: 'admitted' | 'blocked'
  gate_decision: 'pass' | 'blocked'
  market_eligibility: 'eligible-input' | 'non-eligible'
  market_usable: boolean
  required_level: string
  achieved_level: string | null
  no_fallback: true
  downgrade_forbidden: true
  reason_codes: string[]
  checks: IsolationAdmissionCheck[]
  decided_at: string
  verification?: AttestationVerification | null
  provider?: IsolationAdmissionProviderRef
  a2?: SuiteEvaluation | null
  a3?: SuiteEvaluation | null
  runner_verification?: RunnerAttestationVerification | null
  policy?: { policy_version: string; policy_digest: string | null }
  evidence_refs?: string[]
}

/**
 * @param {IsolationAdmissionInput} input
 * @returns {Readonly<IsolationAdmission>}
 */
export function evaluateIsolationAdmission(input: IsolationAdmissionInput): Readonly<IsolationAdmission> {
  const nowMs = resolveNowMs(input.now)
  const decidedAt = new Date(nowMs).toISOString()
  const checks: IsolationAdmissionCheck[] = []
  const reasonCodes = new Set<string>()
  const evidenceRefs = new Set<string>()
  const check = (id: string, condition: boolean, reason: string | null = null, detail?: string): boolean => {
    checks.push(detail === undefined ? { id, status: condition ? 'pass' : 'fail' } : { id, status: condition ? 'pass' : 'fail', detail })
    if (!condition && reason) reasonCodes.add(reason)
    return condition
  }

  const requiredLevel = input.required_level
  const finish = (extra: Partial<IsolationAdmission> = {}): Readonly<IsolationAdmission> => deepFreeze({
    schema_version: ISOLATION_ADMISSION_SCHEMA_VERSION,
    result: 'blocked',
    gate_decision: 'blocked',
    market_eligibility: 'non-eligible',
    market_usable: false,
    required_level: String(requiredLevel),
    achieved_level: null,
    no_fallback: true,
    downgrade_forbidden: true,
    reason_codes: orderReasons(reasonCodes),
    checks,
    decided_at: decidedAt,
    ...extra,
  }) as unknown as Readonly<IsolationAdmission>

  if (!isMarketIsolationLevel(requiredLevel)) {
    check('required-level', false, ISOLATION_REASON.downgradeForbidden, `required:${String(requiredLevel)}`)
    return finish()
  }

  // --- policy binding ------------------------------------------------------
  const policy = isPlainRecord(input.policy) ? input.policy : null
  const policyOk = policy !== null &&
    policy.schema_version === MARKET_GATE_POLICY_VERSION &&
    typeof policyDigestOf(policy) === 'string'
  check('policy.market-gate', policyOk, 'market-policy-missing', 'market-gate-policy/v1 required')
  const policyDigest = policyOk && policy !== null ? policyDigestOf(policy) : null
  if (policyOk && policy !== null) {
    const isolationPolicy = isPlainRecord(policy.isolation) ? policy.isolation : {}
    const policyLevel = isolationPolicy.required_level ?? requiredLevel
    check('policy.level-consistent', policyLevel === requiredLevel, ISOLATION_REASON.downgradeForbidden, `policy:${String(policyLevel)}`)
  }

  // --- host integrity ------------------------------------------------------
  const hostFacts = input.host_facts ?? null
  const hostLowPrivilege = hostFacts !== null &&
    hostFacts.session.elevated === false &&
    (LOW_PRIVILEGE_INTEGRITY as readonly string[]).includes(hostFacts.session.integrity)
  check('host.low-privilege-session', hostLowPrivilege, ISOLATION_REASON.workerIdentityNotLowPrivilege,
    `elevated:${String(hostFacts?.session.elevated)},integrity:${String(hostFacts?.session.integrity)}`)
  const ambientAbsent = hostFacts !== null && hostFacts.ambient_credentials.status === 'absent'
  check('host.no-ambient-credentials', ambientAbsent, ISOLATION_REASON.ambientCredentialsPresent,
    `status:${String(hostFacts?.ambient_credentials.status)}`)

  // --- provider ------------------------------------------------------------
  const provider = input.provider ?? null
  const selection: ProviderSelection | null = input.provider_selection ?? (provider === null
    ? selectIsolationProvider({
        requiredLevel: requiredLevel as MarketIsolationLevel,
        hostFacts: hostFacts ?? undefined,
        now: () => new Date(nowMs),
      })
    : null)
  if (selection && selection.status !== 'available') {
    for (const reason of selection.reason_codes) reasonCodes.add(reason)
    check('provider.selection', false, null, selection.reason_codes.join(','))
  }

  if (!provider) {
    check('provider.present', false, ISOLATION_REASON.providerMissing, 'no measured provider')
    return finish()
  }

  if (input.test_double === true) {
    check('provider.not-test-double', false, ISOLATION_REASON.fixtureNotMarketEvidence, 'test-double')
  }
  const providerProvenance = provider.provenance === 'external-environment'
  check('provider.external-provenance', providerProvenance, ISOLATION_REASON.fixtureNotMarketEvidence,
    `provenance:${String(provider.provenance)}`)
  const availability = provider.availability
  const availabilityOk = isPlainRecord(availability) &&
    availability.available === true &&
    ['E2', 'E3'].includes(availability.evidence.grade) &&
    availability.provenance === 'external-environment'
  check('provider.available', availabilityOk, ISOLATION_REASON.providerMissing,
    `available:${String(availability.available)},grade:${String(availability.evidence.grade)}`)
  check('provider.no-signing-key', provider.holds_signing_key === false, ISOLATION_REASON.unverified, 'provider-must-not-hold-signing-key')

  const descriptorValidation = validateLauncherDescriptor(provider.descriptor)
  const descriptor: LauncherDescriptor | null = descriptorValidation.ok ? provider.descriptor : null
  check('provider.descriptor', descriptor !== null, ISOLATION_REASON.providerNotMeasured,
    descriptorValidation.ok ? undefined : descriptorValidation.errors[0]?.detail)

  if (descriptor) {
    const levelOk = isolationLevelRank(descriptor.isolation.level) >= isolationLevelRank(requiredLevel)
    check('provider.level', levelOk, ISOLATION_REASON.levelInsufficient,
      `provider:${descriptor.isolation.level},required:${requiredLevel}`)
    const providerPlatformOk = descriptor.isolation.platform === hostFacts?.platform
    check('provider.platform', providerPlatformOk, ISOLATION_REASON.providerPlatformMismatch,
      `provider:${descriptor.isolation.platform},host:${String(hostFacts?.platform)}`)
    const allEnforced = ['filesystem', 'network', 'subprocess', 'devices', 'cpu_ms', 'memory_mb', 'secrets']
      .every((dimension) => descriptor.capabilities[dimension as keyof typeof descriptor.capabilities]?.enforced === true)
    check('provider.dimensions-enforced', allEnforced, ISOLATION_REASON.providerNotMeasured,
      'descriptor-capabilities-not-all-enforced')
    if (hostFacts) {
      const bound = availability.host_fingerprint === hostFingerprint(hostFacts)
      check('provider.host-fingerprint', bound, ISOLATION_REASON.providerNotMeasured, 'availability-record-host-mismatch')
    }
  }

  // --- attestation ---------------------------------------------------------
  const attestation = input.attestation
  if (!isPlainRecord(attestation)) {
    check('attestation.present', false, ISOLATION_REASON.attestationMissing, 'no isolation-attestation/v1')
    return finish({ verification: null, provider: providerRef(provider, descriptor, availability) })
  }

  const baseExpected: AttestationExpected = isPlainRecord(input.attestation_expected)
    ? input.attestation_expected
    : {}
  const expected: AttestationExpected = {
    ...baseExpected,
    required_level: requiredLevel as MarketIsolationLevel,
    launcher_id: descriptor?.launcher_id,
    launcher_version: descriptor?.launcher_version,
    provider_digest: descriptor?.provider_digest,
    policy_version: policyOk ? MARKET_GATE_POLICY_VERSION : undefined,
    policy_digest: policyDigest ?? undefined,
    launcher_descriptor: descriptor ?? undefined,
  }
  const verification = verifyIsolationAttestation(attestation, expected, {
    now: new Date(nowMs),
    nonceRegistry: input.nonce_registry,
    verifySignature: input.verify_signature,
    pinnedKeys: input.pinned_keys,
    verified_by: input.verified_by,
  })
  check('attestation.verified', verification.result === 'valid', null,
    verification.result === 'valid' ? undefined : verification.reason_codes.join(','))
  for (const reason of verification.reason_codes) reasonCodes.add(reason)
  const levelAchieved = descriptor?.isolation.level ?? null
  if (verification.result === 'valid' && isPlainRecord(attestation)) {
    const refs = attestation.evidence_refs
    if (Array.isArray(refs)) {
      for (const ref of refs) {
        if (typeof ref === 'string') evidenceRefs.add(ref)
      }
    }
  }

  // --- A2 (L2) -------------------------------------------------------------
  let a2Evaluation: SuiteEvaluation | null = null
  if (requiredLevel === 'L2') {
    if (!isPlainRecord(input.a2_evidence)) {
      check('a2.present', false, ISOLATION_REASON.adversarialSuiteMissing, 'no A2 evidence')
    } else {
      a2Evaluation = evaluateA2Evidence(input.a2_evidence, {
        providerDescriptor: descriptor ?? undefined,
        now: new Date(nowMs),
      })
      check('a2.passed', a2Evaluation.result === 'pass' && a2Evaluation.market_evidence === true,
        a2Evaluation.result === 'fail' ? ISOLATION_REASON.adversarialSuiteFailed : ISOLATION_REASON.adversarialSuiteMissing,
        `result:${a2Evaluation.result}`)
      for (const reason of a2Evaluation.reason_codes) reasonCodes.add(reason)
      if (a2Evaluation.market_evidence && isPlainRecord(input.a2_evidence)) {
        evidenceRefs.add('suite-digest:' + suiteEvidenceDigest(input.a2_evidence))
      }
    }
  }

  // --- A3 / runner attestation (L3) ---------------------------------------
  let a3Evaluation: SuiteEvaluation | null = null
  let runnerVerification: RunnerAttestationVerification | null = null
  if (requiredLevel === 'L3') {
    if (!isPlainRecord(input.a3_evidence)) {
      check('a3.present', false, ISOLATION_REASON.a3SuiteMissing, 'no A3 evidence')
    } else {
      a3Evaluation = evaluateA3Evidence(input.a3_evidence, {
        providerDescriptor: descriptor ?? undefined,
        now: new Date(nowMs),
      })
      check('a3.passed', a3Evaluation.result === 'pass' && a3Evaluation.market_evidence === true,
        a3Evaluation.result === 'fail' ? ISOLATION_REASON.a3SuiteFailed : ISOLATION_REASON.a3SuiteMissing,
        `result:${a3Evaluation.result}`)
      for (const reason of a3Evaluation.reason_codes) reasonCodes.add(reason)
      if (a3Evaluation.market_evidence && isPlainRecord(input.a3_evidence)) {
        evidenceRefs.add('suite-digest:' + suiteEvidenceDigest(input.a3_evidence))
      }
    }

    if (provider.provider_id === PROVIDER_IDS.remoteRunnerL3) {
      if (!isPlainRecord(input.runner_attestation)) {
        check('runner.attestation', false, ISOLATION_REASON.runnerAttestationInvalid, 'remote-runner-attestation-required')
      } else {
        runnerVerification = verifyRunnerAttestation(input.runner_attestation, input.runner_expected ?? {}, {
          now: new Date(nowMs),
          nonceRegistry: input.nonce_registry,
          verifySignature: input.runner_verify_signature,
          pinnedKeys: input.runner_pinned_keys,
          isRevoked: input.is_revoked,
          verified_by: input.verified_by,
        })
        check('runner.verified', runnerVerification.result === 'valid',
          ISOLATION_REASON.runnerAttestationInvalid,
          runnerVerification.result === 'valid' ? undefined : runnerVerification.reason_codes.join(','))
        for (const reason of runnerVerification.reason_codes) reasonCodes.add(reason)
        if (runnerVerification.result === 'valid' && isPlainRecord(input.runner_attestation)) {
          const ref = input.runner_attestation.revocation_ref
          if (typeof ref === 'string') evidenceRefs.add(ref)
        }
      }
    }
  }

  const valid = checks.every((entry) => entry.status === 'pass') && reasonCodes.size === 0
  if (!valid) {
    return finish({
      verification,
      provider: providerRef(provider, descriptor, availability),
      a2: a2Evaluation,
      a3: a3Evaluation,
      runner_verification: runnerVerification,
    })
  }

  // Every check passed. NOTE: this admits the *isolation input* only; the full
  // market gate still requires runtime anchor, receipt, signing, archive and
  // approval.
  return deepFreeze({
    schema_version: ISOLATION_ADMISSION_SCHEMA_VERSION,
    result: 'admitted',
    gate_decision: 'pass',
    market_eligibility: 'eligible-input',
    market_usable: true,
    required_level: requiredLevel,
    achieved_level: levelAchieved,
    no_fallback: true,
    downgrade_forbidden: true,
    reason_codes: [],
    checks,
    decided_at: decidedAt,
    verification,
    provider: providerRef(provider, descriptor, availability),
    a2: a2Evaluation,
    a3: a3Evaluation,
    runner_verification: runnerVerification,
    policy: { policy_version: MARKET_GATE_POLICY_VERSION, policy_digest: policyDigest },
    evidence_refs: [...evidenceRefs],
  }) as unknown as Readonly<IsolationAdmission>
}

function providerRef(
  provider: IsolationProvider,
  descriptor: LauncherDescriptor | null,
  availability: IsolationProvider['availability'],
): IsolationAdmissionProviderRef {
  return {
    provider_id: provider.provider_id ?? descriptor?.launcher_id ?? null,
    level: descriptor?.isolation.level ?? provider.level ?? null,
    provider_digest: descriptor?.provider_digest ?? null,
    launcher_version: descriptor?.launcher_version ?? null,
    available: availability.available === true,
    evidence_grade: availability.evidence.grade ?? 'E0',
    provenance: availability.provenance ?? provider.provenance ?? 'unknown',
  }
}

function orderReasons(reasonCodes: Set<string>): string[] {
  const priority = [
    ISOLATION_REASON.downgradeForbidden,
    ISOLATION_REASON.levelInsufficient,
    ISOLATION_REASON.providerMissing,
    ISOLATION_REASON.providerPlatformMismatch,
    ISOLATION_REASON.providerNotMeasured,
    ISOLATION_REASON.workerIdentityNotLowPrivilege,
    ISOLATION_REASON.ambientCredentialsPresent,
    ISOLATION_REASON.attestationMissing,
    ISOLATION_REASON.attestationInvalid,
    ISOLATION_REASON.attestationBindingMismatch,
    ISOLATION_REASON.attestationExpired,
    ISOLATION_REASON.attestationReplay,
    ISOLATION_REASON.unverified,
    ISOLATION_REASON.dimensionUnenforced,
    ISOLATION_REASON.adversarialSuiteMissing,
    ISOLATION_REASON.adversarialSuiteFailed,
    ISOLATION_REASON.fixtureNotMarketEvidence,
  ]
  const out: string[] = []
  for (const code of priority) {
    if (reasonCodes.has(code)) out.push(code)
  }
  for (const code of reasonCodes) {
    if (!out.includes(code)) out.push(code)
  }
  return out
}

function resolveNowMs(value: Date | string | number | undefined): number {
  if (value instanceof Date) return value.getTime()
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value === 'string') {
    const parsed = Date.parse(value)
    if (Number.isFinite(parsed)) return parsed
  }
  return Date.now()
}

/** Guard against accidentally treating unknown isolation levels as market. */
export function assertMarketIsolationRequired(level: unknown): MarketIsolationLevel {
  if (typeof level !== 'string' || !(MARKET_ISOLATION_LEVELS as readonly string[]).includes(level)) {
    throw new TypeError(`market isolation requires L2 or L3, got ${String(level)}`)
  }
  return level as MarketIsolationLevel
}
