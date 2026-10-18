/**
 * Control-plane verification of `isolation-attestation/v1`.
 *
 * The verifier is deliberately conservative:
 *   - worker self-report (`worker-self-reported`) and bare launcher declarations
 *     (`launcher-declared`) are never accepted;
 *   - all four correlation fields (`run_id`/`plan_id`/`test_id`/`attempt`) and
 *     the launcher identity, provider digest and frozen policy digest must match
 *     the expected values;
 *   - every market isolation dimension must be attested as enforced;
 *   - the worker identity must be a non-elevated low/medium integrity identity;
 *   - the nonce is single-use (replay rejected) and the attestation must be
 *     fresh within the policy window;
 *   - an externally signed attestation requires the caller to provide a
 *     signature-verification callback and pinned key metadata. This module never
 *     generates, imports or stores a private key.
 *
 * A failed verification returns `result="invalid"` plus stable reason codes; the
 * caller (admission / market gate) must map that to blocked/non-eligible. The
 * verification result itself is not a trustworthy proof: it must be produced by
 * the control plane and recorded append-only.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/isolation/attestation
 */
import {
  ATTESTATION_SIGNATURE_ALGORITHMS,
  ATTESTATION_TRUST_LEVELS,
  ATTESTATION_VERIFICATION_SCHEMA_VERSION,
  ISOLATION_REASON,
  MARKET_GATE_POLICY_VERSION,
  LOW_PRIVILEGE_INTEGRITY,
  deepFreeze,
  isEvidenceRef,
  isNonce,
  isPlainRecord,
  isPositiveSafeInteger,
  isSha256Digest,
  isolationAttestationDigest,
  isolationLevelRank,
  validateIsolationAttestation,
  validateLauncherDescriptor,
  type IsolationAttestation,
  type LauncherDescriptor,
} from './contracts.js'

/** Default freshness window for a market run (policy may shorten it). */
export const DEFAULT_MAX_ATTESTATION_AGE_MS = 5 * 60 * 1000
/** Tolerated clock skew for `issued_at` in the future. */
export const MAX_FUTURE_SKEW_MS = 60 * 1000
/** Upper bound accepted from a policy to avoid absurd freshness windows. */
export const MAX_POLICY_ATTESTATION_AGE_MS = 60 * 60 * 1000

const PACKAGED_INPUT_REF_RE = /^(sha256:[0-9a-f]{64}|(?:artifact|input|put|tool)-[A-Za-z0-9][A-Za-z0-9._:-]{0,126})$/

export interface NonceConsumeOptions {
  nowMs?: number
  expiresAtMs?: number
}

export type NonceConsumeResult = { ok: true } | { ok: false; reason: 'replay' | 'full' | 'invalid' }

export interface NonceRegistryLike {
  consume(nonce: unknown, options?: NonceConsumeOptions): NonceConsumeResult
  size(): number
}

export interface PinnedKey {
  alg?: string
  public_key?: string
}

export interface SignatureVerificationInput {
  alg: string
  key_id: string
  signature: string
  payload_digest: string
  payload: unknown
}

export type SignatureVerifier = (input: SignatureVerificationInput) => boolean | { valid: boolean }

export interface AttestationLimits {
  cpu_ms: number
  memory_mb: number
  processes: number
  temp_bytes: number
  output_bytes: number
}

export interface AttestationExpected {
  run_id?: string
  plan_id?: string
  test_id?: string
  attempt?: number
  launcher_id?: string
  launcher_version?: string
  provider_digest?: string
  policy_version?: string
  policy_digest?: string
  required_level?: 'L2' | 'L3'
  max_age_ms?: number
  denied_roots?: string[]
  network_allowlist?: string[]
  limits?: AttestationLimits
  worker_pid?: number
  launcher_descriptor?: LauncherDescriptor
  required_evidence_refs?: string[]
}

export interface AttestationVerifyOptions {
  now?: Date | string | number
  nonceRegistry?: NonceRegistryLike
  verifySignature?: SignatureVerifier
  pinnedKeys?: Record<string, PinnedKey>
  verified_by?: string
  requireMarketPolicy?: boolean
}

export interface AttestationVerificationCheck {
  id: string
  status: 'pass' | 'fail'
  detail?: string
}

export interface AttestationVerification {
  schema_version: string
  attestation_digest: string | null
  verified_by: string
  verified_at: string
  result: 'valid' | 'invalid'
  checks: AttestationVerificationCheck[]
  reason_codes: string[]
  nonce_consumed: boolean
}

/**
 * Bounded in-memory single-use nonce registry. A durable implementation can be
 * supplied by the caller as long as it implements `consume(nonce, options)`.
 *
 * @param {{maxEntries?:number, now?:()=>number}} [options]
 */
export function createNonceRegistry(options: { maxEntries?: number; now?: () => number } = {}): NonceRegistryLike {
  const maxEntries = Number.isSafeInteger(options.maxEntries) && (options.maxEntries as number) > 0
    ? (options.maxEntries as number)
    : 10_000
  const now = typeof options.now === 'function' ? options.now : () => Date.now()
  const consumed = new Map<string, number>()

  function prune(nowMs: number): void {
    for (const [nonce, expiresAt] of consumed) {
      if (expiresAt <= nowMs) consumed.delete(nonce)
    }
  }

  return Object.freeze({
    consume(nonce: unknown, consumeOptions: NonceConsumeOptions = {}): NonceConsumeResult {
      if (!isNonce(nonce)) return { ok: false, reason: 'invalid' }
      const nowMs = typeof consumeOptions.nowMs === 'number' && Number.isFinite(consumeOptions.nowMs)
        ? consumeOptions.nowMs
        : now()
      const expiresAtMs = typeof consumeOptions.expiresAtMs === 'number' && Number.isFinite(consumeOptions.expiresAtMs)
        ? consumeOptions.expiresAtMs
        : nowMs + DEFAULT_MAX_ATTESTATION_AGE_MS + MAX_FUTURE_SKEW_MS
      prune(nowMs)
      if (consumed.has(nonce)) return { ok: false, reason: 'replay' }
      if (consumed.size >= maxEntries) return { ok: false, reason: 'full' }
      consumed.set(nonce, expiresAtMs)
      return { ok: true }
    },
    size(): number {
      return consumed.size
    },
  })
}

/**
 * Verify an `isolation-attestation/v1` against frozen expectations.
 *
 * @param {unknown} attestation
 * @param {AttestationExpected} expected
 * @param {AttestationVerifyOptions} options
 * @returns {Readonly<AttestationVerification>}
 */
export function verifyIsolationAttestation(
  attestation: unknown,
  expected: AttestationExpected = {},
  options: AttestationVerifyOptions = {},
): Readonly<AttestationVerification> {
  const nowMs = resolveNowMs(options.now)
  const verifiedAt = new Date(nowMs).toISOString()
  const checks: AttestationVerificationCheck[] = []
  const reasonCodes = new Set<string>()
  let nonceConsumed = false

  const check = (id: string, condition: boolean, reason: string | null = null, detail?: string): boolean => {
    checks.push(detail === undefined ? { id, status: condition ? 'pass' : 'fail' } : { id, status: condition ? 'pass' : 'fail', detail })
    if (!condition && reason) reasonCodes.add(reason)
    return condition
  }

  const finish = (result: 'valid' | 'invalid', digest: string | null = null): Readonly<AttestationVerification> => deepFreeze({
    schema_version: ATTESTATION_VERIFICATION_SCHEMA_VERSION,
    attestation_digest: digest,
    verified_by: typeof options.verified_by === 'string' && options.verified_by.length > 0
      ? options.verified_by
      : 'control-plane:isolation-verifier',
    verified_at: verifiedAt,
    result,
    checks,
    reason_codes: [...reasonCodes],
    nonce_consumed: nonceConsumed,
  })

  const structural = validateIsolationAttestation(attestation)
  if (!structural.ok) {
    const first = structural.errors[0]
    check('contract', false, ISOLATION_REASON.attestationInvalid, `${first.path}:${first.detail}`)
    let digest: string | null = null
    try {
      digest = isolationAttestationDigest(attestation as object)
    } catch {
      digest = null
    }
    return finish('invalid', digest)
  }

  const doc = attestation as unknown as IsolationAttestation
  let attestationDigest: string | null = null
  try {
    attestationDigest = isolationAttestationDigest(doc)
    check('digest', true)
  } catch {
    check('digest', false, ISOLATION_REASON.attestationInvalid, 'digest-uncomputable')
    return finish('invalid', null)
  }

  // --- trust + signature ---------------------------------------------------
  const trustOk = (ATTESTATION_TRUST_LEVELS as readonly string[]).includes(doc.issuer.trust) &&
    doc.issuer.trust !== 'worker-self-reported' &&
    doc.issuer.trust !== 'launcher-declared'
  check('issuer-trust', trustOk, ISOLATION_REASON.unverified, `trust:${doc.issuer.trust}`)

  if (doc.issuer.trust === 'external-provider-signed') {
    const signature = doc.signature
    const signatureShapeOk = signature !== null &&
      (ATTESTATION_SIGNATURE_ALGORITHMS as readonly string[]).includes(signature.alg) &&
      typeof signature.key_id === 'string' && signature.key_id.length > 0 &&
      typeof signature.value === 'string' && signature.value.length > 0
    check('signature-shape', signatureShapeOk, ISOLATION_REASON.attestationInvalid, 'external-attestation-requires-signature')
    if (signature !== null && signatureShapeOk) {
      let pinnedOk = true
      if (isPlainRecord(options.pinnedKeys)) {
        const pinned = options.pinnedKeys[signature.key_id]
        pinnedOk = isPlainRecord(pinned) && (pinned.alg === undefined || pinned.alg === signature.alg) &&
          typeof pinned.public_key === 'string' && pinned.public_key.length > 0
      }
      check('pinned-key', pinnedOk, ISOLATION_REASON.unverified, 'pinned-key-unknown')
      if (typeof options.verifySignature !== 'function') {
        check('signature-verify', false, ISOLATION_REASON.unverified, 'signature-verifier-missing')
      } else {
        let verified = false
        try {
          const outcome = options.verifySignature({
            alg: signature.alg,
            key_id: signature.key_id,
            signature: signature.value,
            payload_digest: attestationDigest,
            payload: doc,
          })
          verified = outcome === true || (isPlainRecord(outcome) && outcome.valid === true)
        } catch {
          verified = false
        }
        check('signature-verify', verified, ISOLATION_REASON.unverified, 'signature-verification-failed')
      }
    }
  } else if (doc.issuer.trust === 'control-plane-measured') {
    // A local measured attestation is not signed; it must reference auditable
    // control-plane/OS evidence (no self-report).
    const evidenceOk = doc.signature === null && Array.isArray(doc.evidence_refs) && doc.evidence_refs.length >= 2
    check('control-plane-evidence', evidenceOk, ISOLATION_REASON.unverified, 'need-at-least-two-external-evidence-refs')
  }

  // --- level ---------------------------------------------------------------
  const requiredLevel = expected.required_level ?? 'L2'
  const levelOk = isolationLevelRank(doc.isolation.level) >= isolationLevelRank(requiredLevel) &&
    isolationLevelRank(requiredLevel) >= 2
  check('isolation-level', levelOk, requiredLevel === 'L3' || doc.isolation.level === 'L3'
    ? ISOLATION_REASON.levelInsufficient
    : ISOLATION_REASON.attestationInvalid, `attested:${doc.isolation.level},required:${requiredLevel}`)

  // --- correlation / binding ----------------------------------------------
  const bindingChecks: Array<[string, unknown, unknown]> = [
    ['run_id', expected.run_id, doc.run_id],
    ['plan_id', expected.plan_id, doc.plan_id],
    ['test_id', expected.test_id, doc.test_id],
    ['attempt', expected.attempt, doc.attempt],
  ]
  let bindingOk = true
  for (const [field, want, got] of bindingChecks) {
    const ok = want !== undefined && want === got
    if (!ok) bindingOk = false
    check(`binding.${field}`, ok, ISOLATION_REASON.attestationBindingMismatch, `expected:${String(want)},attested:${String(got)}`)
  }
  if (expected.worker_pid !== undefined) {
    const ok = isPositiveSafeInteger(expected.worker_pid) && expected.worker_pid === doc.worker.pid
    if (!ok) bindingOk = false
    check('binding.worker_pid', ok, ISOLATION_REASON.attestationBindingMismatch, 'worker-pid-mismatch')
  }
  check('binding.correlation', bindingOk)

  const launcherOk = typeof expected.launcher_id === 'string' && expected.launcher_id === doc.issuer.launcher_id &&
    typeof expected.launcher_version === 'string' && expected.launcher_version === doc.issuer.version &&
    isSha256Digest(expected.provider_digest) && expected.provider_digest === doc.issuer.provider_digest
  check('binding.launcher', launcherOk, ISOLATION_REASON.attestationBindingMismatch, 'launcher-identity-or-provider-digest-mismatch')

  const policyOk = expected.policy_version !== undefined && expected.policy_digest !== undefined &&
    expected.policy_version === doc.policy.policy_version &&
    expected.policy_digest === doc.policy.policy_digest
  check('binding.policy', policyOk, ISOLATION_REASON.attestationBindingMismatch, 'policy-version-or-digest-mismatch')
  if (options.requireMarketPolicy !== false) {
    check('policy.market-version', doc.policy.policy_version === MARKET_GATE_POLICY_VERSION,
      'market-policy-version-unknown', `policy:${doc.policy.policy_version}`)
  }

  if (expected.launcher_descriptor !== undefined) {
    const descriptorValidation = validateLauncherDescriptor(expected.launcher_descriptor)
    const descriptor = descriptorValidation.ok ? expected.launcher_descriptor : null
    const descriptorOk = descriptor !== null &&
      descriptor.launcher_id === doc.issuer.launcher_id &&
      descriptor.launcher_version === doc.issuer.version &&
      descriptor.provider_digest === doc.issuer.provider_digest
    check('launcher-descriptor', descriptorOk, ISOLATION_REASON.attestationBindingMismatch, 'launcher-descriptor-invalid-or-mismatch')
  }

  // --- identity ------------------------------------------------------------
  const identityOk = doc.isolation.elevated === false &&
    (LOW_PRIVILEGE_INTEGRITY as readonly string[]).includes(doc.identity.integrity)
  check('identity.low-privilege', identityOk, ISOLATION_REASON.workerIdentityNotLowPrivilege,
    `elevated:${String(doc.isolation.elevated)},integrity:${doc.identity.integrity}`)

  const appContainerClaimed = doc.isolation.mechanisms.includes('appcontainer-lowbox')
  const appContainerOk = appContainerClaimed
    ? typeof doc.identity.appcontainer_sid === 'string' && doc.identity.appcontainer_sid.length > 0
    : true
  check('identity.appcontainer', appContainerOk, ISOLATION_REASON.dimensionUnenforced, 'appcontainer-sid-missing')

  // --- filesystem ----------------------------------------------------------
  const readOnlyRefsOk = Array.isArray(doc.filesystem.read_only_inputs) &&
    doc.filesystem.read_only_inputs.length > 0 &&
    doc.filesystem.read_only_inputs.every((item) => typeof item === 'string' && PACKAGED_INPUT_REF_RE.test(item))
  check('filesystem.read-only-inputs', readOnlyRefsOk, ISOLATION_REASON.dimensionUnenforced, 'filesystem:read-only-inputs-invalid')

  let rootsOk = true
  const deniedRoots = expected.denied_roots
  if (!Array.isArray(deniedRoots) || deniedRoots.length === 0) {
    rootsOk = false
  } else if (typeof doc.filesystem.root === 'string') {
    for (const denied of deniedRoots) {
      if (typeof denied !== 'string' || denied.length === 0) {
        rootsOk = false
        break
      }
      if (pathInsideOrEqual(doc.filesystem.root, denied)) {
        rootsOk = false
        break
      }
    }
  }
  check('filesystem.root-not-denied', rootsOk, ISOLATION_REASON.dimensionUnenforced, 'filesystem:root-inside-denied-tree')

  const fsEnforced = doc.filesystem.reparse_follow === 'deny' && isSha256Digest(doc.filesystem.acl_digest)
  check('filesystem.enforced', fsEnforced, ISOLATION_REASON.dimensionUnenforced, 'isolation-dimension-unenforced:filesystem')

  // --- network -------------------------------------------------------------
  const networkModeOk = doc.network.default === 'deny' && isSha256Digest(doc.network.rules_digest)
  check('network.deny-default', networkModeOk, ISOLATION_REASON.dimensionUnenforced, 'isolation-dimension-unenforced:network')

  let allowlistOk = Array.isArray(expected.network_allowlist)
  if (allowlistOk) {
    const policySet = new Set(expected.network_allowlist)
    allowlistOk = doc.network.allowlist.every((entry) => policySet.has(entry))
  }
  check('network.allowlist-subset', allowlistOk, ISOLATION_REASON.dimensionUnenforced, 'network:allowlist-outside-policy')

  // --- resources -----------------------------------------------------------
  const limitKeys = ['cpu_ms', 'memory_mb', 'processes', 'temp_bytes', 'output_bytes'] as const
  const limitsRecord = isPlainRecord(expected.limits) ? expected.limits : null
  let limitsOk = limitsRecord !== null
  if (limitsRecord) {
    for (const key of limitKeys) {
      if (!isPositiveSafeInteger(limitsRecord[key])) {
        limitsOk = false
        break
      }
    }
  }
  if (limitsRecord) {
    limitsOk = limitKeys.every((key) => isPositiveSafeInteger(doc.resources[key]) && doc.resources[key] <= (limitsRecord[key] as number))
  }
  check('resources.within-policy', limitsOk, ISOLATION_REASON.dimensionUnenforced, 'isolation-dimension-unenforced:resources')

  const resourceMechanismOk = typeof doc.resources.job_object === 'string' &&
    doc.resources.job_object.length > 0 &&
    isSha256Digest(doc.resources.limits_digest)
  check('resources.os-mechanism', resourceMechanismOk, ISOLATION_REASON.dimensionUnenforced, 'resources:os-mechanism-missing')

  // --- process tree --------------------------------------------------------
  const processOk = doc.process_tree.kill_on_close === true &&
    doc.process_tree.observed_pids.includes(doc.worker.pid)
  check('process-tree.kill-on-close', processOk, ISOLATION_REASON.dimensionUnenforced, 'isolation-dimension-unenforced:subprocess')

  // --- devices / secrets ---------------------------------------------------
  const devicesOk = doc.devices.enforced === true && Array.isArray(doc.devices.denied)
  check('devices.enforced', devicesOk, ISOLATION_REASON.dimensionUnenforced, 'isolation-dimension-unenforced:devices')

  const secretsOk = doc.secrets.enforced === true &&
    doc.secrets.ambient_credentials === 'none' &&
    doc.secrets.handle_inheritance === 'deny' &&
    isSha256Digest(doc.secrets.env_allowlist_digest)
  check('secrets.isolated', secretsOk, ISOLATION_REASON.dimensionUnenforced, 'isolation-dimension-unenforced:secrets')
  if (doc.secrets.ambient_credentials !== 'none') {
    reasonCodes.add(ISOLATION_REASON.ambientCredentialsPresent)
  }

  // --- evidence refs -------------------------------------------------------
  const requiredRefs = expected.required_evidence_refs
  let refsOk = doc.evidence_refs.every(isEvidenceRef)
  if (Array.isArray(requiredRefs) && requiredRefs.length > 0) {
    const present = new Set(doc.evidence_refs)
    refsOk = refsOk && requiredRefs.every((ref) => present.has(ref))
  }
  check('evidence.refs', refsOk, ISOLATION_REASON.unverified, 'evidence-ref-missing-or-malformed')

  // --- freshness -----------------------------------------------------------
  const maxAgeMs = typeof expected.max_age_ms === 'number' && Number.isFinite(expected.max_age_ms)
    ? expected.max_age_ms
    : DEFAULT_MAX_ATTESTATION_AGE_MS
  const issuedAtMs = Date.parse(doc.issued_at)
  const freshnessOk = Number.isFinite(issuedAtMs) &&
    issuedAtMs <= nowMs + MAX_FUTURE_SKEW_MS &&
    nowMs - issuedAtMs <= maxAgeMs
  check('freshness.issued-at', freshnessOk, ISOLATION_REASON.attestationExpired,
    `age_ms:${Number.isFinite(issuedAtMs) ? nowMs - issuedAtMs : 'unparsable'},max_age_ms:${maxAgeMs}`)

  if (Object.hasOwn(doc, 'expires_at') && typeof doc.expires_at === 'string') {
    const expiresAtMs = Date.parse(doc.expires_at)
    const notExpired = Number.isFinite(expiresAtMs) && nowMs <= expiresAtMs
    check('freshness.expires-at', notExpired, ISOLATION_REASON.attestationExpired, 'attestation-expired')
  }

  // --- single-use nonce ----------------------------------------------------
  if (!isNonce(doc.nonce)) {
    check('nonce.shape', false, ISOLATION_REASON.attestationInvalid, 'nonce-invalid')
  } else if (!options.nonceRegistry || typeof options.nonceRegistry.consume !== 'function') {
    check('nonce.consume', false, ISOLATION_REASON.unverified, 'nonce-registry-required')
  } else {
    let outcome: NonceConsumeResult
    try {
      outcome = options.nonceRegistry.consume(doc.nonce, {
        nowMs,
        expiresAtMs: Number.isFinite(Date.parse(doc.expires_at ?? ''))
          ? Date.parse(doc.expires_at as string)
          : nowMs + maxAgeMs + MAX_FUTURE_SKEW_MS,
      })
    } catch {
      outcome = { ok: false, reason: 'invalid' }
    }
    if (outcome.ok === true) {
      nonceConsumed = true
      check('nonce.consume', true)
    } else if (outcome.reason === 'replay') {
      check('nonce.consume', false, ISOLATION_REASON.attestationReplay, 'nonce-replayed')
    } else if (outcome.reason === 'full') {
      check('nonce.consume', false, ISOLATION_REASON.unverified, 'nonce-registry-full')
    } else {
      check('nonce.consume', false, ISOLATION_REASON.attestationInvalid, 'nonce-registry-rejected')
    }
  }

  const valid = checks.every((entry) => entry.status === 'pass') && reasonCodes.size === 0
  return finish(valid ? 'valid' : 'invalid', attestationDigest)
}

/**
 * Normalize a Windows/POSIX path for containment checks without touching disk.
 * @param {string} value
 */
export function normalizePathForComparison(value: string): string {
  let normalized = String(value).trim().replace(/\\/g, '/')
  while (normalized.length > 1 && normalized.endsWith('/')) normalized = normalized.slice(0, -1)
  if (/^[A-Za-z]:/.test(normalized) || normalized.startsWith('//')) normalized = normalized.toLowerCase()
  return normalized
}

/**
 * @param {string} candidate
 * @param {string} root
 */
export function pathInsideOrEqual(candidate: string, root: string): boolean {
  const candidatePath = normalizePathForComparison(candidate)
  const rootPath = normalizePathForComparison(root)
  if (rootPath === '' || candidatePath === '') return false
  return candidatePath === rootPath || candidatePath.startsWith(rootPath.endsWith('/') ? rootPath : rootPath + '/')
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
