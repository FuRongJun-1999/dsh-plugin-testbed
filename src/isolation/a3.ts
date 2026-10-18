/**
 * A3 adversarial suite (L3) — case registry and fail-closed runner.
 *
 * L3 is only satisfied by a rootless container, micro-VM or dedicated signed
 * remote runner (L3-01). No such runtime, image, pinned operator key or runner
 * attestation exists on the current host, so all A3 cases are `blocked` and can
 * never be summarized as a passing suite.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/isolation/a3
 */
import {
  A3_EVIDENCE_VERSION,
  A3_SUITE_VERSION,
  ISOLATION_REASON,
  MARKET_EVIDENCE_GRADES,
  deepFreeze,
} from './contracts.js'
import { hostFingerprint, type HostFacts } from './host-capabilities.js'
import {
  DEFAULT_MAX_SUITE_AGE_MS,
  buildSuiteCaseResult,
  evaluateSuiteEvidence,
  type AdversarialProvider,
  type SuiteCaseOutcome,
  type SuiteCaseResult,
  type SuiteCaseSpec,
  type SuiteEvaluation,
} from './suite-evidence.js'
import type { SuiteRun } from './a2.js'

const REQUIRED_PRECONDITIONS = Object.freeze(['provider-measured', 'l3-runtime', 'signed-runner-attestation', 'low-privilege-identity'])

/** L3-07 attack matrix. */
export const A3_CASES: readonly SuiteCaseSpec[] = deepFreeze([
  { id: 'A3-01', category: 'image', attack: 'substitute a different/floating image', expectation: 'image digest mismatch rejected; only pinned digest runs', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A3-02', category: 'escape', attack: 'privileged container / runtime escape', expectation: 'rootless+no-new-privs+seccomp prevents privileged mode', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A3-03', category: 'host-mount', attack: 'mount host filesystem/socket/secret path', expectation: 'host mounts denied; read-only pinned inputs only', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A3-04', category: 'network', attack: 'egress to host network/DNS/cloud metadata', expectation: 'network namespace default deny; only allowlist/proxy', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A3-05', category: 'credentials', attack: 'read runner/operator/publishing credentials', expectation: 'credential scope none; no host secret mounted', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A3-06', category: 'cross-tenant', attack: 'reach another tenant run/storage/network', expectation: 'independent namespace/VM/storage/network/quota', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A3-07', category: 'resources', attack: 'exhaust CPU/memory/disk/PIDs', expectation: 'cgroup/VM quota enforced; verifiable failure', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A3-08', category: 'forged-attestation', attack: 'replay a previous signed runner attestation', expectation: 'nonce replay rejected', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A3-09', category: 'forged-attestation', attack: 'present an expired runner attestation', expectation: 'freshness/expiry rejected', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A3-10', category: 'forged-attestation', attack: 'forge signature/operator/runner identity', expectation: 'pinned key verification fails; not allowlisted', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A3-11', category: 'reap', attack: 'leave processes/volumes/network resources after cancel', expectation: 'cgroup/VM killed; volumes/network reaped', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A3-12', category: 'supply-chain', attack: 'tamper image/runner binary/dependency', expectation: 'digest/signature/allowlist detects tampering', preconditions: [...REQUIRED_PRECONDITIONS] },
] as const)

export const A3_REQUIRED_CATEGORIES = Object.freeze([
  'image', 'escape', 'host-mount', 'network', 'credentials', 'cross-tenant',
  'resources', 'forged-attestation', 'reap', 'supply-chain',
] as const)

export interface A3RunInput {
  provider?: AdversarialProvider | null
  hostFacts?: HostFacts | null
  now?: () => Date
  maxAgeMs?: number
}

/**
 * @param {unknown} evidence
 * @param {{providerDescriptor?:object, now?:Date|string|number, maxAgeMs?:number}} [options]
 */
export function evaluateA3Evidence(
  evidence: unknown,
  options: { providerDescriptor?: object; now?: Date | string | number; maxAgeMs?: number } = {},
): SuiteEvaluation {
  return evaluateSuiteEvidence(evidence, {
    schemaVersion: A3_EVIDENCE_VERSION,
    suiteVersion: A3_SUITE_VERSION,
    caseSpecs: A3_CASES,
    requiredCategories: A3_REQUIRED_CATEGORIES,
    providerDescriptor: options.providerDescriptor as never,
    now: options.now,
    maxAgeMs: options.maxAgeMs,
  })
}

/**
 * Run A3 against an L3 provider. Built-in providers are unavailable; the result
 * is fully blocked and never market evidence.
 *
 * @param {A3RunInput} [input]
 */
export async function runA3Suite(input: A3RunInput = {}): Promise<Readonly<SuiteRun>> {
  const now = typeof input.now === 'function' ? input.now : () => new Date()
  const startedAt = now()
  const reasons = new Set<string>()
  const provider = input.provider ?? null
  const hostFacts = input.hostFacts ?? null

  const providerIsL3 = provider?.level === 'L3'
  if (!providerIsL3) reasons.add(ISOLATION_REASON.levelInsufficient)
  const providerAvailable = provider !== null &&
    provider.availability.available === true &&
    provider.provenance === 'external-environment' &&
    (MARKET_EVIDENCE_GRADES as readonly string[]).includes(provider.availability.evidence?.grade ?? '') &&
    providerIsL3
  const lowPrivilegeHost = hostFacts !== null &&
    hostFacts.session.elevated === false &&
    ['low', 'medium', 'medium-plus', 'appcontainer', 'lowbox'].includes(hostFacts.session.integrity)

  if (!providerAvailable) {
    reasons.add(ISOLATION_REASON.providerMissing)
    reasons.add(ISOLATION_REASON.adversarialSuiteMissing)
  }
  if (!lowPrivilegeHost) reasons.add(ISOLATION_REASON.workerIdentityNotLowPrivilege)

  const cases: Readonly<SuiteCaseResult>[] = []
  if (providerAvailable && provider !== null && lowPrivilegeHost) {
    for (const spec of A3_CASES) {
      let outcome: SuiteCaseOutcome
      try {
        outcome = await provider.runAdversarialCase(spec)
      } catch {
        outcome = { status: 'blocked', reason_codes: [ISOLATION_REASON.adversarialSuiteMissing] }
      }
      const normalized = normalizeCaseOutcome(spec, outcome, now)
      cases.push(normalized)
      if (normalized.status === 'fail') reasons.add(ISOLATION_REASON.adversarialSuiteFailed)
      if (normalized.status === 'blocked') reasons.add(ISOLATION_REASON.adversarialSuiteMissing)
    }
  } else {
    for (const spec of A3_CASES) {
      cases.push(buildSuiteCaseResult(spec, {
        status: 'blocked',
        reason_codes: [...reasons],
        detail: 'a3-not-executed:no-measured-L3-provider-or-low-privilege-identity',
        at: now().toISOString(),
      }))
    }
  }

  const completedAt = now()
  const noFingerprint = 'sha256:' + '0'.repeat(64)
  const evidence: Record<string, unknown> = {
    schema_version: A3_EVIDENCE_VERSION,
    suite_version: A3_SUITE_VERSION,
    suite_id: 'A3',
    executor: {
      identity: {
        sid: hostFacts?.session.sid ?? 'redacted',
        user: hostFacts?.session.user ?? 'redacted',
        elevated: hostFacts?.session.elevated ?? null,
        integrity: hostFacts?.session.integrity ?? 'unknown',
      },
      executed_under_low_privilege: lowPrivilegeHost,
      environment_fingerprint: hostFacts ? hostFingerprint(hostFacts) : noFingerprint,
      host_fingerprint: hostFacts ? hostFingerprint(hostFacts) : noFingerprint,
    },
    provider: providerAvailable && provider !== null
      ? {
          provider_id: provider.provider_id,
          provider_digest: provider.descriptor.provider_digest,
          launcher_version: provider.descriptor.launcher_version,
          level: provider.level,
          provenance: provider.provenance,
          evidence_grade: provider.availability.evidence.grade,
        }
      : {
          provider_id: provider?.provider_id ?? null,
          provider_digest: provider?.descriptor.provider_digest ?? null,
          launcher_version: provider?.descriptor.launcher_version ?? null,
          level: provider?.level ?? null,
          provenance: provider?.provenance ?? 'candidate',
          evidence_grade: provider?.availability.evidence?.grade ?? 'E0',
        },
    started_at: startedAt.toISOString(),
    completed_at: completedAt.toISOString(),
    cases: cases.map((item) => ({ ...item })),
  }
  const evaluation = evaluateA3Evidence(evidence, {
    providerDescriptor: provider?.descriptor,
    now: completedAt,
    maxAgeMs: input.maxAgeMs ?? DEFAULT_MAX_SUITE_AGE_MS,
  })
  return deepFreeze({
    suite_id: 'A3',
    suite_version: A3_SUITE_VERSION,
    schema_version: 'a3-run/v1',
    provider_id: provider?.provider_id ?? null,
    executed: providerAvailable && lowPrivilegeHost,
    result: evaluation.result,
    market_evidence: evaluation.market_evidence,
    reason_codes: [...new Set([...evaluation.reason_codes, ...reasons])],
    cases: evaluation.cases.map((item) => ({ ...item })),
    evaluation: { diagnostics: evaluation.diagnostics, coverage: evaluation.coverage },
    executed_at: completedAt.toISOString(),
  }) as unknown as Readonly<SuiteRun>
}

function normalizeCaseOutcome(spec: SuiteCaseSpec, outcome: SuiteCaseOutcome, now: () => Date): Readonly<SuiteCaseResult> {
  if (!outcome || typeof outcome !== 'object') {
    return buildSuiteCaseResult(spec, {
      status: 'blocked',
      reason_codes: [ISOLATION_REASON.adversarialSuiteMissing],
      detail: 'provider-returned-no-outcome',
      at: now().toISOString(),
    })
  }
  const status = (['pass', 'fail', 'blocked'] as const).includes(outcome.status) ? outcome.status : 'blocked'
  return buildSuiteCaseResult(spec, {
    status,
    command: typeof outcome.command === 'string' ? outcome.command : null,
    observed: typeof outcome.observed === 'string' ? outcome.observed : null,
    expected: typeof outcome.expected === 'string' ? outcome.expected : spec.expectation,
    evidence_refs: Array.isArray(outcome.evidence_refs) ? outcome.evidence_refs : [],
    reason_codes: Array.isArray(outcome.reason_codes) ? outcome.reason_codes : [],
    at: typeof outcome.at === 'string' ? outcome.at : now().toISOString(),
    detail: typeof outcome.detail === 'string' ? outcome.detail : null,
  })
}
