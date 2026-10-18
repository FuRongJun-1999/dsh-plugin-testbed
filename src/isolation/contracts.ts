/**
 * Versioned isolation contracts shared by the L2/L3 provider, attestation
 * verifier and control-plane isolation port.
 *
 * ## Scope / non-goals
 * This module **describes and verifies** isolation facts. It never launches a
 * worker, never holds a signing key, and never turns a declaration into
 * evidence: a `worker-launcher/v1` capability entry with `enforced=true` is a
 * claim only. Market use requires a separate, externally measured
 * `isolation-attestation/v1` plus a passing A2/A3 suite
 * (see `admission.ts` and `a2.ts`).
 *
 * ## Versions
 *   - `worker-launcher/v1`          launcher descriptor (§6.1)
 *   - `isolation-attestation/v1`    per-attempt measured facts (§6.2)
 *   - `attestation-verification/v1` control-plane verification result
 *   - `runner-attestation/v1`       remote L3 runner facts (§6.3)
 *
 * Unknown major versions, unknown fields and unknown enum values are rejected
 * (fail-closed). `contracts.ts` is deliberately pure data validation; command
 * execution and environment probing live in `host-capabilities.ts`.
 *
 * ## Extension over the §6.2 example
 * §8.3 requires the attestation to bind the *policy* as well. The document
 * therefore carries a top-level `policy` object. §5.2.2 L2-05 (credentials)
 * and A2-03 also require an explicit credential statement, hence `secrets`.
 * Both additions are part of `isolation-attestation/v1`; the verifier rejects
 * documents without them. This is a documented superset, not a silent change
 * of the example's semantics.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/isolation/contracts
 */
import { canonicalJson, sha256Hex } from '../protocol/digest.js'

// ---------------------------------------------------------------------------
// Schema versions (closed set; unknown versions are rejected, never downgraded)
// ---------------------------------------------------------------------------
export const WORKER_LAUNCHER_SCHEMA_VERSION = 'worker-launcher/v1'
export const ISOLATION_ATTESTATION_SCHEMA_VERSION = 'isolation-attestation/v1'
export const ATTESTATION_VERIFICATION_SCHEMA_VERSION = 'attestation-verification/v1'
export const RUNNER_ATTESTATION_SCHEMA_VERSION = 'runner-attestation/v1'
export const ISOLATION_ADMISSION_SCHEMA_VERSION = 'isolation-admission/v1'
export const ISOLATION_PRECHECK_SCHEMA_VERSION = 'isolation-precheck/v1'
export const ISOLATION_PORT_SCHEMA_VERSION = 'isolation-port/v1'
export const HOST_FACTS_SCHEMA_VERSION = 'host-facts/v1'
export const A2_SUITE_VERSION = 'a2-suite/v1'
export const A2_EVIDENCE_VERSION = 'a2-evidence/v1'
export const A3_SUITE_VERSION = 'a3-suite/v1'
export const A3_EVIDENCE_VERSION = 'a3-evidence/v1'
export const MARKET_GATE_POLICY_VERSION = 'market-gate-policy/v1'

/**
 * Isolation levels. Only `L2`/`L3` are market-grade. `L0`/`L1` exist here only
 * so that mislabelled input can be rejected explicitly: this module must never
 * upgrade them.
 */
export const ISOLATION_LEVELS = Object.freeze(['L0-in-process', 'L1-subprocess', 'L2', 'L3'] as const)
export const MARKET_ISOLATION_LEVELS = Object.freeze(['L2', 'L3'] as const)
export const ISOLATION_LEVEL_RANK = Object.freeze({
  'L0-in-process': 0,
  'L1-subprocess': 1,
  L2: 2,
  L3: 3,
} as const)

export type IsolationLevel = (typeof ISOLATION_LEVELS)[number]
export type MarketIsolationLevel = (typeof MARKET_ISOLATION_LEVELS)[number]

/** Trust levels from NEXT-PHASE-REQUIREMENTS §8.2. AT-0 is observation only. */
export const ATTESTATION_TRUST_LEVELS = Object.freeze([
  'worker-self-reported', // AT-0 — never evidence
  'launcher-declared', // AT-1 — not enough without OS measurement
  'control-plane-measured', // AT-2 — E2
  'external-provider-signed', // AT-3 — E3
] as const)
export type AttestationTrust = (typeof ATTESTATION_TRUST_LEVELS)[number]

export const MARKET_ATTESTATION_TRUST = Object.freeze(['control-plane-measured', 'external-provider-signed'] as const)
export const EVIDENCE_GRADES = Object.freeze(['E0', 'E1', 'E2', 'E3'] as const)
export const MARKET_EVIDENCE_GRADES = Object.freeze(['E2', 'E3'] as const)
export type EvidenceGrade = (typeof EVIDENCE_GRADES)[number]
export type MarketEvidenceGrade = (typeof MARKET_EVIDENCE_GRADES)[number]

/** Capability dimensions a market launcher must enforce (§6.1, MKT-C02). */
export const ISOLATION_DIMENSIONS = Object.freeze([
  'filesystem', 'network', 'subprocess', 'devices', 'cpu_ms', 'memory_mb', 'secrets',
] as const)
export type IsolationDimension = (typeof ISOLATION_DIMENSIONS)[number]

/** An attestation also has to state identity and lifecycle facts, separately. */
export const ISOLATION_ATTESTATION_DIMENSIONS = Object.freeze([
  'identity', 'filesystem', 'network', 'subprocess', 'devices', 'cpu_ms', 'memory_mb', 'secrets',
] as const)

/** Mechanisms are descriptive; acceptance is decided by A2/A3 evidence. */
export const L2_MECHANISMS = Object.freeze([
  'dedicated-user', 'restricted-token', 'appcontainer-lowbox', 'job-object',
  'firewall-per-user', 'acl-temp-root', 'reparse-deny', 'env-allowlist',
  'user-namespace', 'cgroup-v2', 'network-namespace',
] as const)
export const L3_MECHANISMS = Object.freeze([
  'rootless-container', 'micro-vm', 'remote-runner', 'readonly-rootfs',
  'no-new-privs', 'seccomp', 'network-namespace', 'pinned-image-digest',
  'signed-runner-attestation', 'credential-isolation',
] as const)

/** Signing algorithms allowed for externally signed attestations (§6.0). */
export const ATTESTATION_SIGNATURE_ALGORITHMS = Object.freeze(['ed25519', 'ecdsa-p256-sha256'] as const)
export type AttestationSignatureAlgorithm = (typeof ATTESTATION_SIGNATURE_ALGORITHMS)[number]

/** Integrity labels that may appear on a low-privilege worker identity. */
export const LOW_PRIVILEGE_INTEGRITY = Object.freeze(['low', 'medium', 'appcontainer', 'lowbox'] as const)
/** Explicitly forbidden integrity labels; `unknown` is also rejected. */
export const FORBIDDEN_INTEGRITY = Object.freeze(['high', 'system', 'protected', 'unknown'] as const)

/** L3 runtime engines that can never be satisfied by a same-privilege child. */
export const L3_RUNTIME_ENGINES = Object.freeze([
  'rootless-podman', 'rootless-docker', 'containerd-userns', 'crun-userns',
  'firecracker', 'cloud-hypervisor', 'qemu-microvm', 'remote-runner',
] as const)

/**
 * Stable reason codes. The first block is registered by
 * NEXT-PHASE-REQUIREMENTS §9.2; codes marked `extension` are versioned here and
 * are safe to add because a blocked result only ever becomes *more* explicit.
 */
export const ISOLATION_REASON = Object.freeze({
  providerMissing: 'isolation-provider-missing',
  levelInsufficient: 'isolation-level-insufficient',
  unverified: 'isolation-unverified',
  attestationMissing: 'isolation-attestation-missing',
  attestationInvalid: 'isolation-attestation-invalid',
  attestationExpired: 'isolation-attestation-expired',
  attestationBindingMismatch: 'isolation-attestation-binding-mismatch',
  attestationReplay: 'isolation-attestation-replay', // extension
  dimensionUnenforced: 'isolation-dimension-unenforced',
  workerIdentityNotLowPrivilege: 'worker-identity-not-low-privilege',
  ambientCredentialsPresent: 'worker-ambient-credentials-present',
  adversarialSuiteMissing: 'adversarial-suite-missing',
  adversarialSuiteFailed: 'adversarial-suite-failed',
  fixtureNotMarketEvidence: 'fixture-not-market-evidence',
  providerPlatformMismatch: 'isolation-provider-platform-mismatch', // extension
  providerNotMeasured: 'isolation-provider-not-measured', // extension
  downgradeForbidden: 'isolation-level-downgrade-forbidden', // extension
  launchBlocked: 'isolation-launch-blocked', // extension
  runnerAttestationInvalid: 'runner-attestation-invalid', // extension
  runnerAttestationExpired: 'runner-attestation-expired', // extension
  runnerAttestationReplay: 'runner-attestation-replay', // extension
  runnerNotAllowed: 'runner-not-allowed', // extension
  a3SuiteMissing: 'a3-suite-missing', // extension
  a3SuiteFailed: 'a3-suite-failed', // extension
} as const)
export type IsolationReasonCode = (typeof ISOLATION_REASON)[keyof typeof ISOLATION_REASON]

export const ISOLATION_REASON_MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  [ISOLATION_REASON.providerMissing]: 'no isolation provider is available/measured for the required level',
  [ISOLATION_REASON.levelInsufficient]: 'available isolation level is below the required level',
  [ISOLATION_REASON.unverified]: 'isolation facts could not be independently verified',
  [ISOLATION_REASON.attestationMissing]: 'no isolation-attestation/v1 was produced',
  [ISOLATION_REASON.attestationInvalid]: 'isolation-attestation/v1 is malformed or self-contradictory',
  [ISOLATION_REASON.attestationExpired]: 'isolation-attestation/v1 is stale',
  [ISOLATION_REASON.attestationBindingMismatch]: 'isolation-attestation/v1 does not match the frozen run/plan/test/attempt',
  [ISOLATION_REASON.attestationReplay]: 'isolation-attestation/v1 nonce was already consumed',
  [ISOLATION_REASON.dimensionUnenforced]: 'an isolation dimension is unenforced or unmeasured',
  [ISOLATION_REASON.workerIdentityNotLowPrivilege]: 'worker identity is not a verified low-privilege identity',
  [ISOLATION_REASON.ambientCredentialsPresent]: 'ambient credentials are reachable from the worker context',
  [ISOLATION_REASON.adversarialSuiteMissing]: 'the A2 adversarial suite has not been executed with complete evidence',
  [ISOLATION_REASON.adversarialSuiteFailed]: 'the A2 adversarial suite failed',
  [ISOLATION_REASON.fixtureNotMarketEvidence]: 'fixtures/mocks/test doubles are not market isolation evidence',
  [ISOLATION_REASON.providerPlatformMismatch]: 'the isolation provider cannot run on this platform',
  [ISOLATION_REASON.providerNotMeasured]: 'the isolation provider has not been measured/attested',
  [ISOLATION_REASON.downgradeForbidden]: 'downgrading isolation level is forbidden',
  [ISOLATION_REASON.launchBlocked]: 'no isolated worker was launched',
  [ISOLATION_REASON.runnerAttestationInvalid]: 'runner-attestation/v1 is missing, malformed or untrusted',
  [ISOLATION_REASON.runnerAttestationExpired]: 'runner-attestation/v1 is stale',
  [ISOLATION_REASON.runnerAttestationReplay]: 'runner-attestation/v1 nonce was already consumed',
  [ISOLATION_REASON.runnerNotAllowed]: 'runner/image/operator is not in the allowlist',
  [ISOLATION_REASON.a3SuiteMissing]: 'the A3 adversarial suite has not been executed with complete evidence',
  [ISOLATION_REASON.a3SuiteFailed]: 'the A3 adversarial suite failed',
})

// ---------------------------------------------------------------------------
// Document interfaces (post-validation view)
// ---------------------------------------------------------------------------
export interface IsolationSignature {
  alg: AttestationSignatureAlgorithm
  key_id: string
  value: string
}

export interface IsolationAttestationIssuer {
  launcher_id: string
  version: string
  trust: AttestationTrust
  provider_digest: string
}

export interface IsolationAttestationWorker {
  worker_id: string
  pid: number
  started_at: string
}

export interface IsolationAttestationIsolation {
  level: IsolationLevel
  mechanisms: string[]
  elevated: boolean
}

export interface IsolationAttestationIdentity {
  sid: string
  user: string
  integrity: string
  appcontainer_sid: string | null
}

export interface IsolationAttestationFilesystem {
  root: string
  acl_digest: string
  read_only_inputs: string[]
  reparse_follow: string
}

export interface IsolationAttestationNetwork {
  default: string
  allowlist: string[]
  mechanism: string
  rules_digest: string
}

export interface IsolationAttestationResources {
  cpu_ms: number
  memory_mb: number
  processes: number
  temp_bytes: number
  output_bytes: number
  job_object: string
  limits_digest: string
}

export interface IsolationAttestationProcessTree {
  kill_on_close: boolean
  observed_pids: number[]
}

export interface IsolationAttestationDevices {
  enforced: boolean
  denied: string[]
}

export interface IsolationAttestationSecrets {
  enforced: boolean
  ambient_credentials: string
  env_allowlist_digest: string
  handle_inheritance: string
}

export interface IsolationAttestationPolicy {
  policy_version: string
  policy_digest: string
}

/** `isolation-attestation/v1` document (validated). */
export interface IsolationAttestation {
  schema_version: string
  attestation_id: string
  issuer: IsolationAttestationIssuer
  run_id: string
  plan_id: string
  test_id: string
  attempt: number
  worker: IsolationAttestationWorker
  isolation: IsolationAttestationIsolation
  identity: IsolationAttestationIdentity
  filesystem: IsolationAttestationFilesystem
  network: IsolationAttestationNetwork
  resources: IsolationAttestationResources
  process_tree: IsolationAttestationProcessTree
  devices: IsolationAttestationDevices
  secrets: IsolationAttestationSecrets
  evidence_refs: string[]
  issued_at: string
  expires_at?: string
  nonce: string
  policy: IsolationAttestationPolicy
  signature: IsolationSignature | null
}

export interface LauncherCapability {
  enforced: boolean
  mechanism?: string
  default?: 'deny' | 'allowlist'
  max_processes?: number
  ambient_credentials?: 'none' | 'present' | 'unknown'
  evidence?: string
}

export interface LauncherDescriptor {
  schema_version: string
  launcher_id: string
  launcher_version: string
  provider_digest: string
  isolation: {
    level: MarketIsolationLevel
    mechanisms: string[]
    platform: string
    arch: string
    os_build: string
  }
  capabilities: Record<IsolationDimension, LauncherCapability>
  limitations: string[]
  attestation: {
    method: 'control-plane-measured' | 'external-provider-signed'
    schema_version: string
  }
  declared_at: string
}

export interface ContractValidationError {
  path: string
  detail: string
}

export interface ContractValidationResult {
  ok: boolean
  errors: ContractValidationError[]
}

// ---------------------------------------------------------------------------
// Low-level shape helpers
// ---------------------------------------------------------------------------
const SHA256_RE = /^sha256:[0-9a-f]{64}$/
const HEX64_RE = /^[0-9a-f]{64}$/
const PLAN_ID_RE = /^plan-sha256:[0-9a-f]{64}$/
const ATTESTATION_ID_RE = /^iso-[0-9a-f]{32}$/
const RUNNER_ATTESTATION_ID_RE = /^runner-att-[0-9a-f]{32}$/
const SID_RE = /^S-1-[0-9-]+$/
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const TEST_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/
const VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9._:+-]{0,63}$/
const POLICY_VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9._:+\/-]{0,63}$/
const NONCE_RE = /^[A-Za-z0-9_-]{16,128}$/
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/
const RFC3339_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/
const EVIDENCE_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._:/#+-]{0,255}$/

const MAX_ARRAY_ITEMS = 128
const MAX_STRING_CHARS = 4096

const SECRET_KEY_RE = /^(private[_-]?key|privatekey|password|passwd|client[_-]?secret|api[_-]?key|access[_-]?token|refresh[_-]?token|secret[_-]?key|signing[_-]?key)$/i
const SECRET_VALUE_RES = Object.freeze([
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /^\s*sk-[A-Za-z0-9]{20,}\s*$/,
  /^\s*ghp_[A-Za-z0-9]{20,}\s*$/,
  /^\s*AKIA[0-9A-Z]{16}\s*$/,
])

/** Thrown for programming errors / malformed contract input. */
export class IsolationContractError extends Error {
  readonly code: string
  readonly path: string | null

  constructor(code: string, message: string, path: string | null = null) {
    super(message)
    this.name = 'IsolationContractError'
    this.code = code
    this.path = path
  }
}

/** @param {unknown} value */
export function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

/** @param {unknown} value */
export function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0
}

/** @param {unknown} value */
export function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0
}

/** @param {unknown} value */
export function isSha256Digest(value: unknown): value is string {
  return typeof value === 'string' && SHA256_RE.test(value)
}

/** @param {unknown} value */
export function isHex64(value: unknown): value is string {
  return typeof value === 'string' && HEX64_RE.test(value)
}

/** @param {unknown} value */
export function isRfc3339Utc(value: unknown): value is string {
  return typeof value === 'string' && RFC3339_UTC_RE.test(value) && Number.isFinite(Date.parse(value))
}

/** @param {unknown} value */
export function isNonce(value: unknown): value is string {
  return typeof value === 'string' && NONCE_RE.test(value)
}

/** @param {unknown} value */
export function isAttestationId(value: unknown): value is string {
  return typeof value === 'string' && ATTESTATION_ID_RE.test(value)
}

/** @param {unknown} value */
export function isRunnerAttestationId(value: unknown): value is string {
  return typeof value === 'string' && RUNNER_ATTESTATION_ID_RE.test(value)
}

/** @param {unknown} value */
export function isRunId(value: unknown): value is string {
  return typeof value === 'string' && ID_RE.test(value)
}

/** @param {unknown} value */
export function isPlanId(value: unknown): value is string {
  return typeof value === 'string' && PLAN_ID_RE.test(value)
}

/** @param {unknown} value */
export function isTestId(value: unknown): value is string {
  return typeof value === 'string' && TEST_ID_RE.test(value)
}

/** @param {unknown} value */
export function isVersionString(value: unknown): value is string {
  return typeof value === 'string' && VERSION_RE.test(value)
}

/** @param {unknown} value */
export function isSid(value: unknown): value is string {
  return typeof value === 'string' && SID_RE.test(value)
}

/** @param {unknown} value */
export function isEvidenceRef(value: unknown): value is string {
  return typeof value === 'string' && EVIDENCE_REF_RE.test(value)
}

/** @param {unknown} value */
export function isMarketIsolationLevel(value: unknown): value is MarketIsolationLevel {
  return typeof value === 'string' && (MARKET_ISOLATION_LEVELS as readonly string[]).includes(value)
}

/** @param {unknown} level */
export function isolationLevelRank(level: unknown): number {
  if (typeof level !== 'string' || !Object.hasOwn(ISOLATION_LEVEL_RANK, level)) return -1
  return ISOLATION_LEVEL_RANK[level as IsolationLevel]
}

/** @param {unknown} value */
export function deepFreeze<T>(value: T): T {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  Object.freeze(value)
  for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child)
  return value
}

/**
 * Find secret material in a contract document (keys and obvious values).
 * Evidence documents must never contain private keys or credentials.
 *
 * @param {unknown} value
 * @param {string} [path]
 * @param {string[]} [found]
 * @returns {string[]} dotted paths of secret-looking fields
 */
export function findSecretMaterial(value: unknown, path = '$', found: string[] = []): string[] {
  if (typeof value === 'string') {
    if (SECRET_VALUE_RES.some((re) => re.test(value))) found.push(path)
    return found
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) findSecretMaterial(value[i], `${path}[${i}]`, found)
    return found
  }
  if (!isPlainRecord(value)) return found
  for (const [key, child] of Object.entries(value)) {
    const childPath = `${path}.${key}`
    if (SECRET_KEY_RE.test(key)) found.push(childPath)
    findSecretMaterial(child, childPath, found)
  }
  return found
}

/**
 * Canonical digest of a document with selected top-level fields removed.
 * Used for attestation signatures (signature excluded) and provider identity
 * (`provider_digest` / `declared_at` excluded).
 *
 * @param {object} document
 * @param {string[]} [excludedTopLevelFields]
 * @returns {string} `sha256:<64hex>`
 */
export function digestDocument(document: object, excludedTopLevelFields: string[] = []): string {
  if (!isPlainRecord(document)) throw new IsolationContractError('document-invalid', 'document must be a plain object')
  const body: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(document)) {
    if (excludedTopLevelFields.includes(key)) continue
    body[key] = value
  }
  return 'sha256:' + sha256Hex(canonicalJson(body))
}

/** Digest of an `isolation-attestation/v1` payload (signature excluded). */
export function isolationAttestationDigest(attestation: object): string {
  return digestDocument(attestation, ['signature'])
}

/** Digest of a `runner-attestation/v1` payload (signature excluded). */
export function runnerAttestationDigest(attestation: object): string {
  return digestDocument(attestation, ['signature'])
}

/** Digest that identifies a launcher descriptor independent of its timestamp. */
export function providerDigestOf(descriptor: object): string {
  return digestDocument(descriptor, ['provider_digest', 'declared_at'])
}

/** Digest a frozen market-gate-policy document for binding into attestations. */
export function policyDigestOf(policy: object): string {
  return digestDocument(policy, [])
}

/** Digest a suite evidence document for append-only references. */
export function suiteEvidenceDigest(evidence: object): string {
  return digestDocument(evidence, [])
}

// ---------------------------------------------------------------------------
// Structural validation primitives
// ---------------------------------------------------------------------------
function push(errors: ContractValidationError[], path: string, detail: string): ContractValidationError[] {
  errors.push({ path, detail })
  return errors
}

function checkExactFields(record: unknown, allowed: readonly string[], path: string, errors: ContractValidationError[]): boolean {
  if (!isPlainRecord(record)) {
    push(errors, path, 'expected-object')
    return false
  }
  for (const key of Object.keys(record)) {
    if (!allowed.includes(key)) push(errors, `${path}.${key}`, 'unknown-field')
  }
  return true
}

interface StringCheck {
  max?: number
  pattern?: RegExp
  label?: string
}

function checkString(value: unknown, path: string, errors: ContractValidationError[], options: StringCheck = {}): boolean {
  const max = options.max ?? MAX_STRING_CHARS
  const label = options.label ?? 'string'
  if (!isNonEmptyString(value)) {
    push(errors, path, `${label}-required`)
    return false
  }
  if (value.length > max) push(errors, path, `${label}-too-long`)
  if (options.pattern && !options.pattern.test(value)) push(errors, path, `${label}-invalid`)
  return true
}

function checkBoolean(value: unknown, path: string, errors: ContractValidationError[]): boolean {
  if (typeof value !== 'boolean') {
    push(errors, path, 'boolean-required')
    return false
  }
  return true
}

function checkPositiveInteger(value: unknown, path: string, errors: ContractValidationError[], max = 2 ** 31 - 1): boolean {
  if (!isPositiveSafeInteger(value) || value > max) {
    push(errors, path, 'positive-integer-required')
    return false
  }
  return true
}

interface StringArrayCheck {
  maxItems?: number
  pattern?: RegExp
  minItems?: number
}

function checkStringArray(value: unknown, path: string, errors: ContractValidationError[], options: StringArrayCheck = {}): boolean {
  const maxItems = options.maxItems ?? MAX_ARRAY_ITEMS
  const minItems = options.minItems ?? 0
  if (!Array.isArray(value)) {
    push(errors, path, 'array-required')
    return false
  }
  if (value.length < minItems) push(errors, path, 'array-too-short')
  if (value.length > maxItems) push(errors, path, 'array-too-long')
  const seen = new Set<string>()
  for (let i = 0; i < value.length; i += 1) {
    const item: unknown = value[i]
    if (!checkString(item, `${path}[${i}]`, errors, { max: 256, pattern: options.pattern })) continue
    const itemString = item as string
    if (seen.has(itemString)) push(errors, `${path}[${i}]`, 'duplicate-value')
    seen.add(itemString)
  }
  return true
}

function checkTimestamp(value: unknown, path: string, errors: ContractValidationError[]): boolean {
  if (!isRfc3339Utc(value)) {
    push(errors, path, 'rfc3339-utc-required')
    return false
  }
  return true
}

function checkSecretFree(document: unknown, path: string, errors: ContractValidationError[]): void {
  const hits = findSecretMaterial(document, path)
  for (const hit of hits) push(errors, hit, 'secret-material-forbidden')
}

export function assertNoSecretMaterial(document: unknown, label = 'document'): void {
  const hits = findSecretMaterial(document)
  if (hits.length > 0) {
    throw new IsolationContractError('secret-material-forbidden', `${label} contains secret-looking fields: ${hits.join(', ')}`, hits[0])
  }
}

// ---------------------------------------------------------------------------
// Isolation attestation
// ---------------------------------------------------------------------------
const ATTESTATION_FIELDS = Object.freeze([
  'schema_version', 'attestation_id', 'issuer', 'run_id', 'plan_id', 'test_id', 'attempt',
  'worker', 'isolation', 'identity', 'filesystem', 'network', 'resources', 'process_tree',
  'devices', 'secrets', 'evidence_refs', 'issued_at', 'expires_at', 'nonce', 'policy', 'signature',
] as const)
const ISSUER_FIELDS = Object.freeze(['launcher_id', 'version', 'trust', 'provider_digest'] as const)
const WORKER_FIELDS = Object.freeze(['worker_id', 'pid', 'started_at'] as const)
const ISOLATION_FIELDS = Object.freeze(['level', 'mechanisms', 'elevated'] as const)
const IDENTITY_FIELDS = Object.freeze(['sid', 'user', 'integrity', 'appcontainer_sid'] as const)
const FILESYSTEM_FIELDS = Object.freeze(['root', 'acl_digest', 'read_only_inputs', 'reparse_follow'] as const)
const NETWORK_FIELDS = Object.freeze(['default', 'allowlist', 'mechanism', 'rules_digest'] as const)
const RESOURCE_FIELDS = Object.freeze(['cpu_ms', 'memory_mb', 'processes', 'temp_bytes', 'output_bytes', 'job_object', 'limits_digest'] as const)
const PROCESS_TREE_FIELDS = Object.freeze(['kill_on_close', 'observed_pids'] as const)
const DEVICES_FIELDS = Object.freeze(['enforced', 'denied'] as const)
const SECRETS_FIELDS = Object.freeze(['enforced', 'ambient_credentials', 'env_allowlist_digest', 'handle_inheritance'] as const)
const POLICY_FIELDS = Object.freeze(['policy_version', 'policy_digest'] as const)
const SIGNATURE_FIELDS = Object.freeze(['alg', 'key_id', 'value'] as const)

/**
 * Validate an `isolation-attestation/v1` document without trusting it.
 *
 * @param {unknown} value
 * @returns {ContractValidationResult}
 */
export function validateIsolationAttestation(value: unknown): ContractValidationResult {
  const errors: ContractValidationError[] = []
  if (!checkExactFields(value, ATTESTATION_FIELDS, '$', errors)) return { ok: false, errors }
  const doc = value as Record<string, unknown>

  if (doc.schema_version !== ISOLATION_ATTESTATION_SCHEMA_VERSION) {
    push(errors, '$.schema_version', 'unknown-schema-version')
  }
  checkString(doc.attestation_id, '$.attestation_id', errors, { max: 64, pattern: ATTESTATION_ID_RE, label: 'attestation-id' })

  if (checkExactFields(doc.issuer, ISSUER_FIELDS, '$.issuer', errors)) {
    const issuer = doc.issuer as Record<string, unknown>
    checkString(issuer.launcher_id, '$.issuer.launcher_id', errors, { max: 128, pattern: ID_RE, label: 'launcher-id' })
    checkString(issuer.version, '$.issuer.version', errors, { max: 64, pattern: VERSION_RE, label: 'launcher-version' })
    if (typeof issuer.trust !== 'string' || !(ATTESTATION_TRUST_LEVELS as readonly string[]).includes(issuer.trust)) {
      push(errors, '$.issuer.trust', 'unknown-trust-level')
    }
    checkString(issuer.provider_digest, '$.issuer.provider_digest', errors, { max: 80, pattern: SHA256_RE, label: 'provider-digest' })
  }

  checkString(doc.run_id, '$.run_id', errors, { max: 128, pattern: ID_RE, label: 'run-id' })
  if (!isPlanId(doc.plan_id)) push(errors, '$.plan_id', 'plan-id-invalid')
  checkString(doc.test_id, '$.test_id', errors, { max: 128, pattern: TEST_ID_RE, label: 'test-id' })
  checkPositiveInteger(doc.attempt, '$.attempt', errors)

  if (checkExactFields(doc.worker, WORKER_FIELDS, '$.worker', errors)) {
    const worker = doc.worker as Record<string, unknown>
    checkString(worker.worker_id, '$.worker.worker_id', errors, { max: 128, pattern: ID_RE, label: 'worker-id' })
    checkPositiveInteger(worker.pid, '$.worker.pid', errors)
    checkTimestamp(worker.started_at, '$.worker.started_at', errors)
  }

  if (checkExactFields(doc.isolation, ISOLATION_FIELDS, '$.isolation', errors)) {
    const isolation = doc.isolation as Record<string, unknown>
    if (typeof isolation.level !== 'string' || !(ISOLATION_LEVELS as readonly string[]).includes(isolation.level)) {
      push(errors, '$.isolation.level', 'unknown-isolation-level')
    }
    checkStringArray(isolation.mechanisms, '$.isolation.mechanisms', errors, { minItems: 1 })
    checkBoolean(isolation.elevated, '$.isolation.elevated', errors)
  }

  if (checkExactFields(doc.identity, IDENTITY_FIELDS, '$.identity', errors)) {
    const identity = doc.identity as Record<string, unknown>
    checkString(identity.sid, '$.identity.sid', errors, { max: 184, pattern: SID_RE, label: 'sid' })
    checkString(identity.user, '$.identity.user', errors, { max: 128, label: 'user' })
    const integrity = identity.integrity
    if (typeof integrity !== 'string' ||
        (!(LOW_PRIVILEGE_INTEGRITY as readonly string[]).includes(integrity) &&
         !(FORBIDDEN_INTEGRITY as readonly string[]).includes(integrity))) {
      push(errors, '$.identity.integrity', 'unknown-integrity-level')
    }
    if (identity.appcontainer_sid === null) {
      // allowed: non-AppContainer mechanism
    } else if (identity.appcontainer_sid === undefined) {
      push(errors, '$.identity.appcontainer_sid', 'field-required')
    } else {
      checkString(identity.appcontainer_sid, '$.identity.appcontainer_sid', errors, { max: 184, pattern: SID_RE, label: 'appcontainer-sid' })
    }
  }

  if (checkExactFields(doc.filesystem, FILESYSTEM_FIELDS, '$.filesystem', errors)) {
    const filesystem = doc.filesystem as Record<string, unknown>
    checkString(filesystem.root, '$.filesystem.root', errors, { max: 1024, label: 'fs-root' })
    checkString(filesystem.acl_digest, '$.filesystem.acl_digest', errors, { max: 80, pattern: SHA256_RE, label: 'acl-digest' })
    checkStringArray(filesystem.read_only_inputs, '$.filesystem.read_only_inputs', errors, { minItems: 1 })
    if (filesystem.reparse_follow !== 'deny' && filesystem.reparse_follow !== 'unknown') {
      push(errors, '$.filesystem.reparse_follow', 'reparse-follow-invalid')
    }
  }

  if (checkExactFields(doc.network, NETWORK_FIELDS, '$.network', errors)) {
    const network = doc.network as Record<string, unknown>
    if (network.default !== 'deny' && network.default !== 'allowlist' && network.default !== 'unknown') {
      push(errors, '$.network.default', 'network-default-invalid')
    }
    checkStringArray(network.allowlist, '$.network.allowlist', errors)
    checkString(network.mechanism, '$.network.mechanism', errors, { max: 128, label: 'network-mechanism' })
    checkString(network.rules_digest, '$.network.rules_digest', errors, { max: 80, pattern: SHA256_RE, label: 'rules-digest' })
  }

  if (checkExactFields(doc.resources, RESOURCE_FIELDS, '$.resources', errors)) {
    const resources = doc.resources as Record<string, unknown>
    checkPositiveInteger(resources.cpu_ms, '$.resources.cpu_ms', errors)
    checkPositiveInteger(resources.memory_mb, '$.resources.memory_mb', errors)
    checkPositiveInteger(resources.processes, '$.resources.processes', errors)
    checkPositiveInteger(resources.temp_bytes, '$.resources.temp_bytes', errors)
    checkPositiveInteger(resources.output_bytes, '$.resources.output_bytes', errors)
    checkString(resources.job_object, '$.resources.job_object', errors, { max: 256, label: 'resource-mechanism' })
    checkString(resources.limits_digest, '$.resources.limits_digest', errors, { max: 80, pattern: SHA256_RE, label: 'limits-digest' })
  }

  if (checkExactFields(doc.process_tree, PROCESS_TREE_FIELDS, '$.process_tree', errors)) {
    const processTree = doc.process_tree as Record<string, unknown>
    checkBoolean(processTree.kill_on_close, '$.process_tree.kill_on_close', errors)
    if (!Array.isArray(processTree.observed_pids)) {
      push(errors, '$.process_tree.observed_pids', 'array-required')
    } else {
      if (processTree.observed_pids.length < 1) push(errors, '$.process_tree.observed_pids', 'array-too-short')
      if (processTree.observed_pids.length > MAX_ARRAY_ITEMS) push(errors, '$.process_tree.observed_pids', 'array-too-long')
      for (let i = 0; i < processTree.observed_pids.length; i += 1) {
        checkPositiveInteger(processTree.observed_pids[i], `$.process_tree.observed_pids[${i}]`, errors)
      }
    }
  }

  if (checkExactFields(doc.devices, DEVICES_FIELDS, '$.devices', errors)) {
    const devices = doc.devices as Record<string, unknown>
    checkBoolean(devices.enforced, '$.devices.enforced', errors)
    checkStringArray(devices.denied, '$.devices.denied', errors)
  }

  if (checkExactFields(doc.secrets, SECRETS_FIELDS, '$.secrets', errors)) {
    const secrets = doc.secrets as Record<string, unknown>
    checkBoolean(secrets.enforced, '$.secrets.enforced', errors)
    if (secrets.ambient_credentials !== 'none' && secrets.ambient_credentials !== 'present' && secrets.ambient_credentials !== 'unknown') {
      push(errors, '$.secrets.ambient_credentials', 'ambient-credentials-invalid')
    }
    checkString(secrets.env_allowlist_digest, '$.secrets.env_allowlist_digest', errors, { max: 80, pattern: SHA256_RE, label: 'env-allowlist-digest' })
    if (secrets.handle_inheritance !== 'deny' && secrets.handle_inheritance !== 'inherit' && secrets.handle_inheritance !== 'unknown') {
      push(errors, '$.secrets.handle_inheritance', 'handle-inheritance-invalid')
    }
  }

  checkStringArray(doc.evidence_refs, '$.evidence_refs', errors, { minItems: 1, pattern: EVIDENCE_REF_RE })
  checkTimestamp(doc.issued_at, '$.issued_at', errors)
  if (Object.hasOwn(doc, 'expires_at')) checkTimestamp(doc.expires_at, '$.expires_at', errors)
  if (!isNonce(doc.nonce)) push(errors, '$.nonce', 'nonce-invalid')

  if (checkExactFields(doc.policy, POLICY_FIELDS, '$.policy', errors)) {
    const policy = doc.policy as Record<string, unknown>
    checkString(policy.policy_version, '$.policy.policy_version', errors, { max: 64, pattern: POLICY_VERSION_RE, label: 'policy-version' })
    checkString(policy.policy_digest, '$.policy.policy_digest', errors, { max: 80, pattern: SHA256_RE, label: 'policy-digest' })
  }

  if (doc.signature === null) {
    // unsigned local control-plane-measured attestation is allowed
  } else if (!Object.hasOwn(doc, 'signature')) {
    push(errors, '$.signature', 'field-required')
  } else if (checkExactFields(doc.signature, SIGNATURE_FIELDS, '$.signature', errors)) {
    const signature = doc.signature as Record<string, unknown>
    if (typeof signature.alg !== 'string' || !(ATTESTATION_SIGNATURE_ALGORITHMS as readonly string[]).includes(signature.alg)) {
      push(errors, '$.signature.alg', 'algorithm-not-allowed')
    }
    checkString(signature.key_id, '$.signature.key_id', errors, { max: 128, pattern: ID_RE, label: 'key-id' })
    checkString(signature.value, '$.signature.value', errors, { max: 2048, pattern: BASE64URL_RE, label: 'signature-value' })
  }

  checkSecretFree(value, '$', errors)
  return { ok: errors.length === 0, errors }
}

export function assertIsolationAttestation(value: unknown, label = 'isolation-attestation/v1'): IsolationAttestation {
  const { ok, errors } = validateIsolationAttestation(value)
  if (!ok) {
    const first = errors[0]
    throw new IsolationContractError('isolation-attestation-invalid', `${label} invalid at ${first.path}: ${first.detail}`, first.path)
  }
  return value as IsolationAttestation
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return isPlainRecord(value) ? value : null
}

/**
 * Keep unknown values in a draft JSON object; validation runs immediately
 * after construction and rejects anything that is not a legal contract value.
 */
function j(value: unknown): unknown {
  return value
}

/**
 * Build a frozen `isolation-attestation/v1` from facts measured **outside** the
 * worker. Worker self-report is rejected; no signing key is accepted here.
 *
 * @param {unknown} input
 * @returns {Readonly<IsolationAttestation>}
 */
export function buildIsolationAttestation(input: unknown): Readonly<IsolationAttestation> {
  const source = asRecord(input)
  if (!source) throw new IsolationContractError('isolation-attestation-invalid', 'attestation input must be a plain object')
  const issuer = asRecord(source.issuer)
  const worker = asRecord(source.worker)
  const isolation = asRecord(source.isolation)
  const identity = asRecord(source.identity)
  const filesystem = asRecord(source.filesystem)
  const network = asRecord(source.network)
  const resources = asRecord(source.resources)
  const processTree = asRecord(source.process_tree)
  const devices = asRecord(source.devices)
  const secrets = asRecord(source.secrets)
  const policy = asRecord(source.policy)
  const attestation: Record<string, unknown> = {
    schema_version: ISOLATION_ATTESTATION_SCHEMA_VERSION,
    attestation_id: j(source.attestation_id),
    issuer: {
      launcher_id: j(issuer?.launcher_id),
      version: j(issuer?.version),
      trust: j(issuer?.trust),
      provider_digest: j(issuer?.provider_digest),
    },
    run_id: j(source.run_id),
    plan_id: j(source.plan_id),
    test_id: j(source.test_id),
    attempt: j(source.attempt),
    worker: {
      worker_id: j(worker?.worker_id),
      pid: j(worker?.pid),
      started_at: j(worker?.started_at),
    },
    isolation: {
      level: j(isolation?.level),
      mechanisms: Array.isArray(isolation?.mechanisms) ? [...isolation.mechanisms] : j(isolation?.mechanisms),
      elevated: j(isolation?.elevated),
    },
    identity: {
      sid: j(identity?.sid),
      user: j(identity?.user),
      integrity: j(identity?.integrity),
      appcontainer_sid: j(identity?.appcontainer_sid ?? null),
    },
    filesystem: {
      root: j(filesystem?.root),
      acl_digest: j(filesystem?.acl_digest),
      read_only_inputs: Array.isArray(filesystem?.read_only_inputs) ? [...filesystem.read_only_inputs] : j(filesystem?.read_only_inputs),
      reparse_follow: j(filesystem?.reparse_follow),
    },
    network: {
      default: j(network?.default),
      allowlist: Array.isArray(network?.allowlist) ? [...network.allowlist] : j(network?.allowlist),
      mechanism: j(network?.mechanism),
      rules_digest: j(network?.rules_digest),
    },
    resources: {
      cpu_ms: j(resources?.cpu_ms),
      memory_mb: j(resources?.memory_mb),
      processes: j(resources?.processes),
      temp_bytes: j(resources?.temp_bytes),
      output_bytes: j(resources?.output_bytes),
      job_object: j(resources?.job_object),
      limits_digest: j(resources?.limits_digest),
    },
    process_tree: {
      kill_on_close: j(processTree?.kill_on_close),
      observed_pids: Array.isArray(processTree?.observed_pids) ? [...processTree.observed_pids] : j(processTree?.observed_pids),
    },
    devices: {
      enforced: j(devices?.enforced),
      denied: Array.isArray(devices?.denied) ? [...devices.denied] : j(devices?.denied),
    },
    secrets: {
      enforced: j(secrets?.enforced),
      ambient_credentials: j(secrets?.ambient_credentials),
      env_allowlist_digest: j(secrets?.env_allowlist_digest),
      handle_inheritance: j(secrets?.handle_inheritance),
    },
    evidence_refs: Array.isArray(source.evidence_refs) ? [...source.evidence_refs] : j(source.evidence_refs),
    issued_at: j(source.issued_at),
    nonce: j(source.nonce),
    policy: {
      policy_version: j(policy?.policy_version),
      policy_digest: j(policy?.policy_digest),
    },
    signature: j(source.signature ?? null),
  }
  if (Object.hasOwn(source, 'expires_at')) attestation.expires_at = j(source.expires_at)
  if (source.signature !== null && source.signing_private_key !== undefined) {
    throw new IsolationContractError('secret-material-forbidden', 'the isolation module must not receive a signing private key')
  }
  assertIsolationAttestation(attestation, 'buildIsolationAttestation')
  return deepFreeze(attestation) as unknown as Readonly<IsolationAttestation>
}

// ---------------------------------------------------------------------------
// Launcher descriptor (worker-launcher/v1)
// ---------------------------------------------------------------------------
const DESCRIPTOR_FIELDS = Object.freeze([
  'schema_version', 'launcher_id', 'launcher_version', 'provider_digest',
  'isolation', 'capabilities', 'limitations', 'attestation', 'declared_at',
] as const)
const DESCRIPTOR_ISOLATION_FIELDS = Object.freeze(['level', 'mechanisms', 'platform', 'arch', 'os_build'] as const)
const DESCRIPTOR_CAPABILITY_FIELDS = Object.freeze([
  'enforced', 'mechanism', 'default', 'max_processes', 'ambient_credentials', 'evidence',
] as const)
const DESCRIPTOR_ATTESTATION_FIELDS = Object.freeze(['method', 'schema_version'] as const)

/**
 * Validate a `worker-launcher/v1` descriptor. `enforced=true` is only a claim;
 * `admission.ts` requires separately measured attestation + A2/A3 evidence.
 *
 * @param {unknown} value
 * @returns {ContractValidationResult}
 */
export function validateLauncherDescriptor(value: unknown): ContractValidationResult {
  const errors: ContractValidationError[] = []
  if (!checkExactFields(value, DESCRIPTOR_FIELDS, '$', errors)) return { ok: false, errors }
  const doc = value as Record<string, unknown>

  if (doc.schema_version !== WORKER_LAUNCHER_SCHEMA_VERSION) push(errors, '$.schema_version', 'unknown-schema-version')
  checkString(doc.launcher_id, '$.launcher_id', errors, { max: 128, pattern: ID_RE, label: 'launcher-id' })
  checkString(doc.launcher_version, '$.launcher_version', errors, { max: 64, pattern: VERSION_RE, label: 'launcher-version' })
  checkString(doc.provider_digest, '$.provider_digest', errors, { max: 80, pattern: SHA256_RE, label: 'provider-digest' })

  if (checkExactFields(doc.isolation, DESCRIPTOR_ISOLATION_FIELDS, '$.isolation', errors)) {
    const isolation = doc.isolation as Record<string, unknown>
    if (typeof isolation.level !== 'string' || !(MARKET_ISOLATION_LEVELS as readonly string[]).includes(isolation.level)) {
      push(errors, '$.isolation.level', 'market-isolation-level-required')
    }
    checkStringArray(isolation.mechanisms, '$.isolation.mechanisms', errors, { minItems: 1 })
    if (isolation.platform !== 'win32' && isolation.platform !== 'linux' && isolation.platform !== 'darwin') {
      push(errors, '$.isolation.platform', 'platform-invalid')
    }
    checkString(isolation.arch, '$.isolation.arch', errors, { max: 32, label: 'arch' })
    checkString(isolation.os_build, '$.isolation.os_build', errors, { max: 128, label: 'os-build' })
  }

  if (!isPlainRecord(doc.capabilities)) {
    push(errors, '$.capabilities', 'expected-object')
  } else {
    const capabilities = doc.capabilities
    for (const dimension of ISOLATION_DIMENSIONS) {
      if (!Object.hasOwn(capabilities, dimension)) {
        push(errors, `$.capabilities.${dimension}`, 'field-required')
        continue
      }
      const capability = capabilities[dimension]
      if (checkExactFields(capability, DESCRIPTOR_CAPABILITY_FIELDS, `$.capabilities.${dimension}`, errors)) {
        const entry = capability as Record<string, unknown>
        checkBoolean(entry.enforced, `$.capabilities.${dimension}.enforced`, errors)
        if (entry.mechanism !== undefined) checkString(entry.mechanism, `$.capabilities.${dimension}.mechanism`, errors, { max: 128, label: 'mechanism' })
        if (entry.default !== undefined && entry.default !== 'deny' && entry.default !== 'allowlist') {
          push(errors, `$.capabilities.${dimension}.default`, 'default-invalid')
        }
        if (entry.max_processes !== undefined) checkPositiveInteger(entry.max_processes, `$.capabilities.${dimension}.max_processes`, errors)
        if (entry.ambient_credentials !== undefined &&
            entry.ambient_credentials !== 'none' && entry.ambient_credentials !== 'present' && entry.ambient_credentials !== 'unknown') {
          push(errors, `$.capabilities.${dimension}.ambient_credentials`, 'ambient-credentials-invalid')
        }
        if (entry.evidence !== undefined) checkString(entry.evidence, `$.capabilities.${dimension}.evidence`, errors, { max: 256, label: 'evidence' })
      }
    }
    for (const key of Object.keys(capabilities)) {
      if (!(ISOLATION_DIMENSIONS as readonly string[]).includes(key)) push(errors, `$.capabilities.${key}`, 'unknown-dimension')
    }
  }

  checkStringArray(doc.limitations, '$.limitations', errors)
  if (checkExactFields(doc.attestation, DESCRIPTOR_ATTESTATION_FIELDS, '$.attestation', errors)) {
    const attestation = doc.attestation as Record<string, unknown>
    if (attestation.method !== 'control-plane-measured' && attestation.method !== 'external-provider-signed') {
      push(errors, '$.attestation.method', 'attestation-method-invalid')
    }
    if (attestation.schema_version !== ISOLATION_ATTESTATION_SCHEMA_VERSION) {
      push(errors, '$.attestation.schema_version', 'unknown-schema-version')
    }
  }
  checkTimestamp(doc.declared_at, '$.declared_at', errors)

  if (isSha256Digest(doc.provider_digest)) {
    try {
      if (providerDigestOf(doc) !== doc.provider_digest) push(errors, '$.provider_digest', 'provider-digest-mismatch')
    } catch {
      push(errors, '$.provider_digest', 'provider-digest-uncomputable')
    }
  }

  checkSecretFree(value, '$', errors)
  return { ok: errors.length === 0, errors }
}

export function assertLauncherDescriptor(value: unknown, label = 'worker-launcher/v1'): LauncherDescriptor {
  const { ok, errors } = validateLauncherDescriptor(value)
  if (!ok) {
    const first = errors[0]
    throw new IsolationContractError('worker-launcher-invalid', `${label} invalid at ${first.path}: ${first.detail}`, first.path)
  }
  return value as LauncherDescriptor
}

/**
 * Build a frozen launcher descriptor with a deterministic `provider_digest`.
 *
 * @param {unknown} input
 * @returns {Readonly<LauncherDescriptor>}
 */
export function buildLauncherDescriptor(input: unknown): Readonly<LauncherDescriptor> {
  const source = asRecord(input)
  if (!source) throw new IsolationContractError('worker-launcher-invalid', 'descriptor input must be a plain object')
  const isolation = asRecord(source.isolation)
  const attestation = asRecord(source.attestation)
  const capabilities: Record<string, unknown> = {}
  const sourceCapabilities = asRecord(source.capabilities)
  for (const dimension of ISOLATION_DIMENSIONS) {
    const capability = asRecord(sourceCapabilities?.[dimension])
    if (!capability) {
      capabilities[dimension] = { enforced: false }
      continue
    }
    const entry: Record<string, unknown> = {}
    for (const field of DESCRIPTOR_CAPABILITY_FIELDS) {
      if (capability[field] !== undefined) entry[field] = capability[field]
    }
    if (entry.enforced === undefined) entry.enforced = false
    capabilities[dimension] = entry
  }
  const descriptor: Record<string, unknown> = {
    schema_version: WORKER_LAUNCHER_SCHEMA_VERSION,
    launcher_id: j(source.launcher_id),
    launcher_version: j(source.launcher_version),
    provider_digest: null,
    isolation: {
      level: j(isolation?.level),
      mechanisms: Array.isArray(isolation?.mechanisms) ? [...isolation.mechanisms] : j(isolation?.mechanisms),
      platform: j(isolation?.platform),
      arch: j(isolation?.arch),
      os_build: j(isolation?.os_build),
    },
    capabilities,
    limitations: Array.isArray(source.limitations) ? [...source.limitations] : j(source.limitations),
    attestation: {
      method: j(attestation?.method),
      schema_version: j(attestation?.schema_version ?? ISOLATION_ATTESTATION_SCHEMA_VERSION),
    },
    declared_at: j(source.declared_at),
  }
  descriptor.provider_digest = providerDigestOf(descriptor)
  assertLauncherDescriptor(descriptor, 'buildLauncherDescriptor')
  return deepFreeze(descriptor) as unknown as Readonly<LauncherDescriptor>
}
