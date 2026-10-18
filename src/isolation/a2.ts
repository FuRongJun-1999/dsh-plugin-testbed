/**
 * A2 adversarial suite (L2) — case registry and fail-closed runner.
 *
 * The suite matrix follows NEXT-PHASE-REQUIREMENTS §5.2.4 (A2-01 … A2-18).
 * Every case is an attack that must be **actually executed** against a measured
 * L2 launcher by a low-privilege identity. On the current host there is no L2
 * launcher, no dedicated identity and the session is High-IL administrator, so
 * every case is reported `blocked` — never `pass`. A blocked case cannot be
 * summarized as a passing A2 suite (`market_evidence=false`).
 *
 * The case definitions are also used by `suite-evidence.ts` to reject a suite
 * report that omits a case, invents a case, lacks a reproducible command, or was
 * produced by a fixture/test double.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/isolation/a2
 */
import {
  A2_EVIDENCE_VERSION,
  A2_SUITE_VERSION,
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

const REQUIRED_PRECONDITIONS = Object.freeze(['provider-measured', 'low-privilege-identity', 'os-isolation'])

/**
 * Complete A2 suite. Categories cover file, credentials, network, process,
 * resources, reap, forged attestation and downgrade as required by the task and
 * §5.2.4.
 */
export const A2_CASES: readonly SuiteCaseSpec[] = deepFreeze([
  { id: 'A2-01', category: 'filesystem', attack: 'read control-plane/workspace/<DSH_HOME>/host user profile files', expectation: 'denied (EACCES/ENOENT), no content leakage', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A2-02', category: 'credentials', attack: 'read token/key/secret environment variables', expectation: 'invisible; env allowlist only', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A2-03', category: 'credentials', attack: 'access Credential Manager / DPAPI user secrets / SSH agent', expectation: 'denied or unreachable', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A2-04', category: 'filesystem', attack: 'write outside worker root (dot-dot, absolute, UNC, \\\\?\\)', expectation: 'denied', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A2-05', category: 'filesystem', attack: 'symlink/junction/reparse point to a host-sensitive path', expectation: 'not followed / access denied', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A2-06', category: 'network', attack: 'direct connect, DNS, loopback, cloud metadata address', expectation: 'default deny; only frozen allowlist passes', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A2-07', category: 'process', attack: 'child_process/native addon/dynamic import spawns a new process', expectation: 'bounded by process limit; child stays in isolation domain and is reaped', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A2-08', category: 'process', attack: 'fork bomb / recursive processes / thread explosion', expectation: 'process limit enforced; worker terminated; control plane records it', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A2-09', category: 'resources', attack: 'exhaust memory/CPU/disk/temp/output', expectation: 'OS limits enforced; verifiable terminal state; host remains usable', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A2-10', category: 'reap', attack: 'grandchild process, port/temp-file leftovers after cancel/timeout', expectation: 'full process tree reaped; temp_removed=true; pid_alive=false', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A2-11', category: 'network', attack: 'read/connect control-plane IPC/port/named pipe', expectation: 'denied or unreachable', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A2-12', category: 'process', attack: 'device/driver/registry/service access (high risk)', expectation: 'denied or explicitly out of L2 scope per policy', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A2-13', category: 'forged-attestation', attack: 'forge worker self-report of started/verdict/isolation claims', expectation: 'control plane ignores it; missing/mismatched attestation => blocked', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A2-14', category: 'resources', attack: 'log injection/control chars/oversized output', expectation: 'length-limited/redacted/digested; verdict unchanged', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A2-15', category: 'reap', attack: 'post-exit residue / double instance / concurrent run sharing directories', expectation: 'independent directory+process group per attempt; no interference', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A2-16', category: 'process', attack: 'bypass Node restrictions through a Rust/Go/native binary', expectation: 'OS boundary still applies; at least one native binary tested', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A2-17', category: 'process', attack: 'time/timezone/random-source manipulation', expectation: 'deadline/evidence time unaffected; monotonic clock', preconditions: [...REQUIRED_PRECONDITIONS] },
  { id: 'A2-18', category: 'downgrade', attack: 'fall back to L1 or direct-run when L2 fails', expectation: 'forbidden; must be blocked', preconditions: [...REQUIRED_PRECONDITIONS] },
] as const)

export const A2_REQUIRED_CATEGORIES = Object.freeze([
  'filesystem', 'credentials', 'network', 'process', 'resources', 'reap', 'forged-attestation', 'downgrade',
] as const)

export interface A2RunInput {
  provider?: AdversarialProvider | null
  hostFacts?: HostFacts | null
  now?: () => Date
  maxAgeMs?: number
}

export interface SuiteRun {
  suite_id: 'A2' | 'A3'
  suite_version: string
  schema_version: string
  provider_id: string | null
  executed: boolean
  result: 'pass' | 'fail' | 'blocked'
  market_evidence: boolean
  reason_codes: string[]
  cases: Array<Record<string, unknown>>
  evaluation: { diagnostics: string[]; coverage: Record<string, number> }
  executed_at: string
}

/**
 * Evaluate a *reported* A2 suite against the fixed matrix. The caller must have
 * executed the cases; this function only validates the evidence shape/binding.
 *
 * @param {unknown} evidence
 * @param {{providerDescriptor?:object, now?:Date|string|number, maxAgeMs?:number}} [options]
 */
export function evaluateA2Evidence(
  evidence: unknown,
  options: { providerDescriptor?: object; now?: Date | string | number; maxAgeMs?: number } = {},
): SuiteEvaluation {
  return evaluateSuiteEvidence(evidence, {
    schemaVersion: A2_EVIDENCE_VERSION,
    suiteVersion: A2_SUITE_VERSION,
    caseSpecs: A2_CASES,
    requiredCategories: A2_REQUIRED_CATEGORIES,
    providerDescriptor: options.providerDescriptor as never,
    now: options.now,
    maxAgeMs: options.maxAgeMs,
  })
}

/**
 * Run the A2 suite against a provider. Built-in providers are unavailable, so
 * this returns all-blocked evidence with `market_evidence=false`.
 *
 * @param {A2RunInput} [input]
 */
export async function runA2Suite(input: A2RunInput = {}): Promise<Readonly<SuiteRun>> {
  const now = typeof input.now === 'function' ? input.now : () => new Date()
  const startedAt = now()
  const reasons = new Set<string>()
  const provider = input.provider ?? null
  const hostFacts = input.hostFacts ?? null

  const providerAvailable = provider !== null &&
    provider.availability.available === true &&
    provider.provenance === 'external-environment' &&
    (MARKET_EVIDENCE_GRADES as readonly string[]).includes(provider.availability.evidence?.grade ?? '')
  const lowPrivilegeHost = hostFacts !== null &&
    hostFacts.session.elevated === false &&
    ['low', 'medium', 'medium-plus', 'appcontainer', 'lowbox'].includes(hostFacts.session.integrity)

  if (!providerAvailable) {
    reasons.add(ISOLATION_REASON.providerMissing)
    reasons.add(ISOLATION_REASON.adversarialSuiteMissing)
  }
  if (!lowPrivilegeHost) {
    reasons.add(ISOLATION_REASON.workerIdentityNotLowPrivilege)
  }

  const cases: Readonly<SuiteCaseResult>[] = []
  if (providerAvailable && provider !== null && lowPrivilegeHost) {
    for (const spec of A2_CASES) {
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
    for (const spec of A2_CASES) {
      cases.push(buildSuiteCaseResult(spec, {
        status: 'blocked',
        reason_codes: [...reasons],
        detail: 'a2-not-executed:no-measured-L2-provider-or-low-privilege-identity',
        at: now().toISOString(),
      }))
    }
  }

  const completedAt = now()
  const noFingerprint = 'sha256:' + '0'.repeat(64)
  const evidence: Record<string, unknown> = {
    schema_version: A2_EVIDENCE_VERSION,
    suite_version: A2_SUITE_VERSION,
    suite_id: 'A2',
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
  const evaluation = evaluateA2Evidence(evidence, {
    providerDescriptor: provider?.descriptor,
    now: completedAt,
    maxAgeMs: input.maxAgeMs ?? DEFAULT_MAX_SUITE_AGE_MS,
  })
  return deepFreeze({
    suite_id: 'A2',
    suite_version: A2_SUITE_VERSION,
    schema_version: 'a2-run/v1',
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
