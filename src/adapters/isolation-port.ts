/**
 * Control-plane isolation port for the market-stage gate.
 *
 * This is the *only* adapter surface the market integration should call. It is
 * capability-driven and fail-closed:
 *   - it accepts only `L2`/`L3` requirements; `L0`/`L1` throw (a local run must
 *     not use this port at all);
 *   - it never imports or falls back to the L1 subprocess adapter;
 *   - flags/env cannot promote a local run: forbidden option keys throw and no
 *     environment variable is consulted for isolation enablement;
 *   - `precheck()` returns `blocked` (with structured reasons) on the current
 *     Windows host because no measured provider/profile/A2 evidence exists;
 *   - `admit()` returns `isolation-admission/v1` with `gate_decision=blocked`
 *     and `market_eligibility=non-eligible` unless a real external provider,
 *     fresh bound attestation and A2/A3 evidence all verify.
 *
 * The port does not launch anything by itself: it delegates to a provider
 * transport only after `precheck()` is ready. Built-in providers are unavailable
 * on this host, so `launch_attempted` remains false.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/adapters/isolation-port
 */
import { randomBytes } from 'node:crypto'

import {
  ISOLATION_PRECHECK_SCHEMA_VERSION,
  ISOLATION_REASON,
  ISOLATION_PORT_SCHEMA_VERSION,
  MARKET_ISOLATION_LEVELS,
  deepFreeze,
  isMarketIsolationLevel,
  isPlainRecord,
  isolationLevelRank,
  policyDigestOf,
  type MarketIsolationLevel,
} from '../isolation/contracts.js'
import {
  createNonceRegistry,
  verifyIsolationAttestation,
  type AttestationExpected,
  type AttestationLimits,
  type AttestationVerification,
  type AttestationVerifyOptions,
  type NonceRegistryLike,
  type PinnedKey,
  type SignatureVerifier,
} from '../isolation/attestation.js'
import {
  createProviderCatalog,
  selectIsolationProvider,
  validateLauncherLaunchRequest,
  type IsolationProvider,
  type ProviderSelection,
} from '../isolation/providers.js'
import { collectHostFacts, hostFingerprint, type HostFacts } from '../isolation/host-capabilities.js'
import {
  evaluateIsolationAdmission,
  type IsolationAdmission,
} from '../isolation/admission.js'
import type { RunnerAttestationExpected } from '../isolation/runner-attestation.js'
import { validateWindowsL2Authorization } from '../isolation/backends/windows-l2.js'

export const ISOLATION_PORT_REF = 'isolation-port@1.0.0'
export const ISOLATION_PORT_VERSION = 'isolation-port/v1'

/** Options that would promote a local run or bypass evidence; rejected loudly. */
export const FORBIDDEN_PORT_OPTIONS = Object.freeze([
  'allowL1Fallback',
  'fallbackToL1',
  'fallback',
  'forceProvider',
  'skipAttestation',
  'skipAdmission',
  'fixtureProvider',
  'mockProvider',
  'providerKind',
  'localFallback',
  'trustLocal',
] as const)

export interface IsolationPortOptions {
  requiredLevel?: string
  required_level?: string
  hostFacts?: HostFacts
  catalog?: readonly IsolationProvider[]
  provider?: IsolationProvider
  externalEnvironment?: boolean
  policy?: unknown
  attestation?: unknown
  attestationExpected?: AttestationExpected
  a2Evidence?: unknown
  a3Evidence?: unknown
  runnerAttestation?: unknown
  runnerExpected?: RunnerAttestationExpected
  runnerVerifySignature?: SignatureVerifier
  runnerPinnedKeys?: Record<string, PinnedKey>
  isRevoked?: (input: { runner_id: string; attestation_id: string; revocation_ref: string; image_digest: string }) => boolean
  authorization?: unknown
  nonceRegistry?: NonceRegistryLike
  verifySignature?: SignatureVerifier
  pinnedKeys?: Record<string, PinnedKey>
  verified_by?: string
  now?: () => Date
}

export interface IsolationPortAdmissionBinding {
  run_id: string
  plan_id: string
  test_id: string
  attempt: number
  policy?: unknown
  attestation_expected?: AttestationExpected & {
    denied_roots?: string[]
    limits?: AttestationLimits
    network_allowlist?: string[]
  }
  artifact_digest?: string
  input_dir?: string
  output_dir?: string
  deadline?: string
  launch_request?: unknown
  attestation?: unknown
  a2_evidence?: unknown
  a3_evidence?: unknown
  runner_attestation?: unknown
}

export interface IsolationPortPrecheck {
  schema_version: string
  status: 'blocked' | 'ready'
  required_level: string
  provider_id: string | null
  provider_level: string | null
  availability: object | null
  selection: ProviderSelection | null
  reason_codes: string[]
  checks: Array<{ id: string; status: 'pass' | 'fail'; detail?: string }>
  claims: {
    isolation_level: string | null
    worker_started: false
    market_usable: false
  }
  fallback: { allowed: false; levels: string[] }
  no_fallback: true
  market_eligibility: 'non-eligible'
  checked_at: string
}

interface PortState {
  phase: 'idle' | 'launched' | 'exited'
  handle: unknown
  attestation: unknown
  admission: Readonly<IsolationAdmission> | null
  launchAttempted: boolean
}

/**
 * @param {IsolationPortOptions} [options]
 */
export function makeIsolationPort(options: IsolationPortOptions = {}): Readonly<Record<string, unknown>> {
  assertNoForbiddenOptions(options)
  const requiredLevel = options.requiredLevel ?? options.required_level ?? 'L2'
  if (!isMarketIsolationLevel(requiredLevel)) {
    throw new TypeError(`isolation-port: market isolation requires L2 or L3, got ${String(requiredLevel)}`)
  }
  const now = typeof options.now === 'function' ? options.now : () => new Date()
  const hostFacts = options.hostFacts ?? collectHostFacts()
  const nonceRegistry = options.nonceRegistry ?? createNonceRegistry({ now: () => now().getTime() })
  const policy = isPlainRecord(options.policy) ? options.policy : null
  const hostLowPrivilege = hostFacts.session.elevated === false &&
    ['low', 'medium', 'medium-plus', 'appcontainer', 'lowbox'].includes(hostFacts.session.integrity)
  const ambientAbsent = hostFacts.ambient_credentials.status === 'absent'
  const authorizationValidation = options.authorization === undefined
    ? { ok: false, errors: ['authorization-not-provided'] }
    : validateWindowsL2Authorization(options.authorization, { now: now() })

  let provider: IsolationProvider | null = null
  let injectedProblem: string | null = null
  if (options.provider !== undefined) {
    if (options.externalEnvironment === true &&
        options.provider.provenance === 'external-environment' &&
        options.provider.holds_signing_key === false) {
      provider = options.provider
    } else {
      injectedProblem = ISOLATION_REASON.fixtureNotMarketEvidence
    }
  }
  const catalog = provider !== null
    ? Object.freeze([provider])
    : (options.catalog ?? createProviderCatalog({ hostFacts, now }))
  const selection: ProviderSelection = provider !== null
    ? selectionForProvider(provider, requiredLevel, now)
    : selectIsolationProvider({ requiredLevel: requiredLevel as MarketIsolationLevel, hostFacts, catalog, now })

  const state: PortState = { phase: 'idle', handle: null, attestation: null, admission: null, launchAttempted: false }

  function precheck(): Readonly<IsolationPortPrecheck> {
    const checks: Array<{ id: string; status: 'pass' | 'fail'; detail?: string }> = []
    const reasons = new Set<string>()
    const check = (id: string, condition: boolean, reason: string | null = null, detail?: string): boolean => {
      checks.push(detail === undefined ? { id, status: condition ? 'pass' : 'fail' } : { id, status: condition ? 'pass' : 'fail', detail })
      if (!condition && reason) reasons.add(reason)
      return condition
    }
    check('host.low-privilege-session', hostLowPrivilege, ISOLATION_REASON.workerIdentityNotLowPrivilege,
      `elevated:${String(hostFacts.session.elevated)},integrity:${hostFacts.session.integrity}`)
    check('host.no-ambient-credentials', ambientAbsent, ISOLATION_REASON.ambientCredentialsPresent,
      `status:${hostFacts.ambient_credentials.status}`)
    check('provider.selection', selection.status === 'available', ISOLATION_REASON.providerMissing,
      selection.reason_codes.join(',') || undefined)
    if (provider !== null) {
      check('provider.level', isolationLevelRank(provider.level) >= isolationLevelRank(requiredLevel),
        ISOLATION_REASON.levelInsufficient, `provider:${provider.level},required:${requiredLevel}`)
    }
    for (const reason of selection.reason_codes) reasons.add(reason)
    if (injectedProblem) check('provider.not-test-double', false, injectedProblem, 'injected-provider-not-external')
    if (policy === null) check('policy.present', false, 'market-policy-missing', 'market-gate-policy/v1 required')
    if (provider?.provider_id === 'windows-appcontainer-l2') {
      check('native.authorization', authorizationValidation.ok, ISOLATION_REASON.launchBlocked,
        authorizationValidation.errors[0])
    }
    const ready = checks.every((entry) => entry.status === 'pass') && reasons.size === 0
    return deepFreeze({
      schema_version: ISOLATION_PRECHECK_SCHEMA_VERSION,
      status: ready ? 'ready' : 'blocked',
      required_level: requiredLevel,
      provider_id: provider?.provider_id ?? null,
      provider_level: provider?.level ?? null,
      availability: provider?.availability ?? null,
      selection,
      reason_codes: [...reasons],
      checks,
      claims: {
        isolation_level: ready && provider ? provider.level : null,
        worker_started: false,
        market_usable: false,
      },
      fallback: { allowed: false, levels: ['L0-in-process', 'L1-subprocess'] },
      no_fallback: true,
      market_eligibility: 'non-eligible',
      checked_at: now().toISOString(),
    }) as unknown as Readonly<IsolationPortPrecheck>
  }

  function blockedAdmission(reasonCodes: string[], detail: string, extra: Partial<IsolationAdmission> = {}): Readonly<IsolationAdmission> {
    return deepFreeze({
      schema_version: 'isolation-admission/v1',
      result: 'blocked',
      gate_decision: 'blocked',
      market_eligibility: 'non-eligible',
      market_usable: false,
      required_level: requiredLevel,
      achieved_level: null,
      no_fallback: true,
      downgrade_forbidden: true,
      reason_codes: [...new Set(reasonCodes)],
      checks: [{ id: 'port.admission', status: 'fail', detail }],
      decided_at: now().toISOString(),
      ...extra,
    }) as unknown as Readonly<IsolationAdmission>
  }

  function buildLaunchRequest(binding: IsolationPortAdmissionBinding): Record<string, unknown> {
    return {
      schema_version: 'launcher-launch-request/v1',
      run_id: binding.run_id,
      plan_id: binding.plan_id,
      test_id: binding.test_id,
      attempt: binding.attempt,
      artifact_digest: binding.artifact_digest ?? 'sha256:' + '0'.repeat(64),
      input_dir: binding.input_dir ?? 'input',
      output_dir: binding.output_dir ?? 'output',
      budget: binding.attestation_expected?.limits ?? {
        cpu_ms: 1, memory_mb: 1, processes: 1, temp_bytes: 1, output_bytes: 1,
      },
      deadline: binding.deadline ?? now().toISOString(),
      network_allowlist: binding.attestation_expected?.network_allowlist ?? [],
      required_level: requiredLevel,
      cancel_token: randomToken(),
      nonce: randomToken(),
    }
  }

  return deepFreeze({
    port_ref: ISOLATION_PORT_REF,
    schema_version: ISOLATION_PORT_VERSION,
    required_level: requiredLevel,
    no_fallback: true,

    describe(): Readonly<Record<string, unknown>> {
      return deepFreeze({
        schema_version: ISOLATION_PORT_SCHEMA_VERSION,
        port_ref: ISOLATION_PORT_REF,
        required_level: requiredLevel,
        provider: provider?.descriptor ?? null,
        availability: provider?.availability ?? null,
        selection,
        fallback: { allowed: false, levels: ['L0-in-process', 'L1-subprocess'] },
        no_fallback: true,
        host_fingerprint: hostFingerprint(hostFacts),
        market_gate: { isolation_input: 'pending', market_usable: false },
        checked_at: now().toISOString(),
      })
    },

    precheck,

    verifyAttestation(attestation: unknown, expectedOverride: AttestationExpected = {}): Readonly<AttestationVerification> {
      const expected: AttestationExpected = {
        ...(options.attestationExpected ?? {}),
        ...expectedOverride,
        required_level: requiredLevel as MarketIsolationLevel,
        launcher_id: provider?.descriptor.launcher_id,
        launcher_version: provider?.descriptor.launcher_version,
        provider_digest: provider?.descriptor.provider_digest,
        policy_version: policy?.schema_version === 'market-gate-policy/v1' ? 'market-gate-policy/v1' : undefined,
        policy_digest: policy !== null ? digestPolicy(policy) : undefined,
      }
      const verifyOptions: AttestationVerifyOptions = {
        now: now(),
        nonceRegistry,
        verifySignature: options.verifySignature,
        pinnedKeys: options.pinnedKeys,
        verified_by: options.verified_by,
      }
      return verifyIsolationAttestation(attestation, expected, verifyOptions)
    },

    async admit(binding: unknown): Promise<Readonly<IsolationAdmission>> {
      if (!isPlainRecord(binding)) {
        return blockedAdmission([ISOLATION_REASON.unverified], 'admission-binding-required')
      }
      const admissionBinding = binding as unknown as IsolationPortAdmissionBinding
      const bindingErrors = validateAdmissionBinding(admissionBinding)
      if (bindingErrors.length > 0) {
        return blockedAdmission([ISOLATION_REASON.unverified], `admission-binding-invalid:${bindingErrors[0]}`)
      }
      const currentPrecheck = precheck()
      if (currentPrecheck.status !== 'ready') {
        return blockedAdmission(currentPrecheck.reason_codes, 'precheck-blocked', {
          checks: currentPrecheck.checks,
        })
      }
      if (provider === null) {
        return blockedAdmission([ISOLATION_REASON.providerMissing], 'no-provider')
      }
      const launchRequest = admissionBinding.launch_request ?? buildLaunchRequest(admissionBinding)
      const launchValidation = validateLauncherLaunchRequest(launchRequest)
      if (!launchValidation.ok) {
        return blockedAdmission([ISOLATION_REASON.launchBlocked], `launch-request-invalid:${launchValidation.errors[0]}`)
      }
      const launchResult = await provider.launch(launchRequest)
      state.launchAttempted = true
      if (launchResult.status !== 'launched') {
        return blockedAdmission(launchResult.reason_codes, launchResult.detail ?? 'launch-blocked')
      }
      state.phase = 'launched'
      const handle = (launchResult as unknown as { handle?: unknown }).handle ?? null
      state.handle = handle
      let attestation: unknown = admissionBinding.attestation ?? null
      if (attestation === null || attestation === undefined) {
        const attestationResult = await provider.attest(handle)
        if (isPlainRecord(attestationResult) && isPlainRecord(attestationResult.attestation)) {
          attestation = attestationResult.attestation
        } else {
          return blockedAdmission([ISOLATION_REASON.attestationMissing], 'attestation-not-produced')
        }
      }
      state.attestation = attestation
      const admission = evaluateIsolationAdmission({
        required_level: requiredLevel,
        provider,
        provider_selection: selection,
        host_facts: hostFacts,
        policy,
        attestation,
        attestation_expected: {
          ...(options.attestationExpected ?? {}),
          ...(admissionBinding.attestation_expected ?? {}),
          run_id: admissionBinding.run_id,
          plan_id: admissionBinding.plan_id,
          test_id: admissionBinding.test_id,
          attempt: admissionBinding.attempt,
        },
        nonce_registry: nonceRegistry,
        verify_signature: options.verifySignature,
        pinned_keys: options.pinnedKeys,
        a2_evidence: admissionBinding.a2_evidence ?? options.a2Evidence,
        a3_evidence: admissionBinding.a3_evidence ?? options.a3Evidence,
        runner_attestation: admissionBinding.runner_attestation ?? options.runnerAttestation,
        runner_expected: options.runnerExpected,
        runner_verify_signature: options.runnerVerifySignature,
        runner_pinned_keys: options.runnerPinnedKeys,
        is_revoked: options.isRevoked,
        verified_by: options.verified_by,
        now: now(),
      })
      state.admission = admission
      if (admission.gate_decision === 'blocked') state.phase = 'idle'
      return admission
    },

    async cancel(): Promise<unknown> {
      if (state.handle === null || state.phase !== 'launched') {
        return deepFreeze({
          schema_version: 'isolation-cancel-result/v1',
          acknowledged: false,
          launch_attempted: state.launchAttempted,
          reason_codes: [ISOLATION_REASON.launchBlocked],
          detail: 'nothing-was-launched',
        })
      }
      const result = await provider?.cancel(state.handle)
      state.phase = 'exited'
      return result
    },

    async reap(): Promise<unknown> {
      if (state.handle === null) {
        return deepFreeze({
          schema_version: 'launcher-reap-result/v1',
          reaped: false,
          pid_alive: null,
          temp_removed: null,
          launch_attempted: state.launchAttempted,
          reason_codes: [ISOLATION_REASON.launchBlocked],
          detail: 'nothing-was-launched',
        })
      }
      const result = await provider?.reap(state.handle)
      state.phase = 'exited'
      return result
    },

    status(): Readonly<Record<string, unknown>> {
      return deepFreeze({
        port_ref: ISOLATION_PORT_REF,
        required_level: requiredLevel,
        phase: state.phase,
        launch_attempted: state.launchAttempted,
        provider_id: provider?.provider_id ?? null,
        admission_result: state.admission?.result ?? null,
        market_eligible_input: state.admission?.market_eligibility === 'eligible-input',
        no_fallback: true,
      })
    },

    /** Adapter-style record; blocked state never claims an isolation level. */
    launchRecord(): Readonly<Record<string, unknown>> {
      const admitted = state.admission?.gate_decision === 'pass'
      return deepFreeze({
        adapter_ref: ISOLATION_PORT_REF,
        required_level: requiredLevel,
        isolation_level: admitted ? (provider?.level ?? null) : null,
        provider_id: provider?.provider_id ?? null,
        launched: state.phase === 'launched',
        market_usable: admitted,
        no_fallback: true,
        limitations: [
          'isolation-port-only-admits-after-external-provider-attestation-a2-a3',
          'l1-subprocess-is-never-a-fallback',
        ],
      })
    },
  })
}

/** Alias used by integration code. */
export const createIsolationPort = makeIsolationPort

function assertNoForbiddenOptions(options: object): void {
  for (const key of FORBIDDEN_PORT_OPTIONS) {
    if (Object.hasOwn(options, key)) {
      throw new TypeError(`isolation-port: option "${key}" is forbidden (no L1 fallback, no evidence bypass)`)
    }
  }
  const record = options as Record<string, unknown>
  const level = record.requiredLevel ?? record.required_level
  if (level !== undefined && !(MARKET_ISOLATION_LEVELS as readonly string[]).includes(String(level))) {
    throw new TypeError(`isolation-port: market isolation requires L2 or L3, got ${String(level)}`)
  }
}

function selectionForProvider(provider: IsolationProvider, requiredLevel: string, now: () => Date): ProviderSelection {
  const available = provider.availability.available === true &&
    provider.provenance === 'external-environment' &&
    isolationLevelRank(provider.level) >= isolationLevelRank(requiredLevel)
  return deepFreeze({
    schema_version: 'provider-selection/v1',
    status: available ? 'available' : 'blocked',
    required_level: requiredLevel,
    selected_provider: available ? provider.provider_id : null,
    candidates: [{
      provider_id: provider.provider_id,
      level: provider.level,
      available,
      reason_codes: [...provider.availability.reason_codes],
    }],
    reason_codes: available ? [] : [...provider.availability.reason_codes, ISOLATION_REASON.providerMissing],
    downgrade_forbidden: true,
    no_fallback: true,
    checked_at: now().toISOString(),
  }) as unknown as ProviderSelection
}

function validateAdmissionBinding(binding: IsolationPortAdmissionBinding): string[] {
  const errors: string[] = []
  if (typeof binding.run_id !== 'string' || binding.run_id.length === 0) errors.push('run_id-required')
  if (typeof binding.plan_id !== 'string' || !/^plan-sha256:[0-9a-f]{64}$/.test(binding.plan_id)) errors.push('plan_id-invalid')
  if (typeof binding.test_id !== 'string' || binding.test_id.length === 0) errors.push('test_id-required')
  if (!Number.isSafeInteger(binding.attempt) || binding.attempt < 1) errors.push('attempt-invalid')
  if (!isPlainRecord(binding.attestation_expected)) {
    errors.push('attestation_expected-required')
  } else {
    const expected = binding.attestation_expected
    if (!Array.isArray(expected.denied_roots) || expected.denied_roots.length === 0) errors.push('denied_roots-required')
    if (!isPlainRecord(expected.limits)) errors.push('limits-required')
    if (!Array.isArray(expected.network_allowlist)) errors.push('network_allowlist-required')
  }
  return errors
}

function digestPolicy(policy: Record<string, unknown>): string {
  return policyDigestOf(policy)
}

function randomToken(): string {
  return randomBytes(32).toString('base64url')
}
