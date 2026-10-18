/**
 * RunSpec / GatePolicy static admission checks (`spec/` in
 * implementation-design-control §2).
 *
 * This module consumes the protocol-owned `run-spec/v1` and `gate-policy/v1`
 * field names and closed enums; it never redefines them. Validation is
 * fail-closed and happens *before* any PUT code is loaded. A failure returns a
 * `CompileRejection`-shaped `{ ok:false, errors }` that the kernel records on a
 * pre-plan `blocked` receipt (`plan_id=null`, `reconciliation=null`).
 *
 * Migration phase `pure control`: `unknown` document boundary, typed helpers,
 * identical error order and rejection codes.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/control/spec
 */
import { isAbsolute, relative, resolve, sep } from 'node:path'
import { validateGatePolicyV1, validateRunSpecV1 } from '../protocol/contracts.js'
import { validateRunBudget } from './budget.js'
import { AUTHORITY_FIELDS } from './state.js'
import type { UnknownRecord } from '../protocol/types.js'

/** Fixed GatePolicy aggregation precedence (§6.1): blocked > reject > pass. */
export const AGGREGATION_PRECEDENCE = Object.freeze(['blocked', 'reject', 'pass'] as const)

const FLOATING_TAG = /^(latest|next|canary|main|master|head|snapshot)$/i
const FLOATING_RANGE = /^[\^~<>=*]|[xX*]$/
const SHA256 = /^sha256:[0-9a-f]{64}$/

/** Static intake result; `stage:'intake'` precedes any plan compilation. */
export interface IntakeResult {
  ok: boolean
  errors: string[]
  stage: 'intake'
}

/** GatePolicy validation result; `policy` is the original document when valid. */
export interface GatePolicyResult {
  ok: boolean
  errors: string[]
  policy: UnknownRecord | null
}

function isPlainObject(value: unknown): value is UnknownRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0
}

function uniqueStrings(value: unknown): boolean {
  return Array.isArray(value) && value.every(nonEmptyString) && new Set(value).size === value.length
}

/**
 * Accept only a pinned version string. Floating tags and semver ranges are
 * rejected (architecture §9.4 step 1: 拒绝浮动 tag 和未锁定依赖).
 */
export function isPinnedVersion(version: unknown): boolean {
  if (!nonEmptyString(version)) return false
  if (FLOATING_TAG.test(version)) return false
  if (FLOATING_RANGE.test(version)) return false
  return true
}

/**
 * Check a path stays inside the declared workspace. Relative paths are
 * rejected by themselves (`artifact_unresolved`); escaping `..` is
 * `path_escape`.
 */
export function pathContainment(workspaceRoot: unknown, artifactPath: unknown): 'ok' | 'unresolved' | 'escape' {
  if (!nonEmptyString(workspaceRoot) || !nonEmptyString(artifactPath)) return 'unresolved'
  if (!isAbsolute(workspaceRoot) || !isAbsolute(artifactPath)) return 'unresolved'
  const rel = relative(resolve(workspaceRoot), resolve(artifactPath))
  if (rel === '') return 'ok'
  if (rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) return 'escape'
  return 'ok'
}

function validateVersionRef(ref: unknown, field: string, errors: string[]): void {
  if (ref === undefined || ref === null) return
  if (!isPlainObject(ref)) {
    errors.push(`version_unpinned:${field}`)
    return
  }
  if (!isPinnedVersion(ref.version)) errors.push(`floating_ref:${field}`)
}

/**
 * Validate a `run-spec/v1` document for control-plane admission. The protocol
 * validator owns version/field/enum closure; this layer adds pinning, target
 * path, budget and caller-authority checks.
 */
export function validateRunSpec(runSpec: unknown): IntakeResult {
  const authorityErrors: string[] = []
  const specRecord = isPlainObject(runSpec) ? runSpec : undefined
  const scenario = isPlainObject(specRecord?.scenario) ? specRecord.scenario : undefined
  if (Array.isArray(scenario?.cases)) {
    for (const caseSpec of scenario.cases) {
      if (!isPlainObject(caseSpec)) continue
      for (const field of AUTHORITY_FIELDS) {
        if (Object.hasOwn(caseSpec, field)) authorityErrors.push(`untrusted-caller-field:${field}:${String(caseSpec.test_id)}`)
      }
      if (caseSpec.admission !== undefined) {
        authorityErrors.push(`untrusted-caller-field:admission:${String(caseSpec.test_id)}`)
      }
    }
  }

  const protocol = validateRunSpecV1(runSpec)
  if (!protocol.ok) {
    return { ok: false, errors: [...protocol.errors.map((e) => `run-spec:${e}`), ...authorityErrors], stage: 'intake' }
  }

  const spec = runSpec as UnknownRecord
  const errors = [...authorityErrors]
  validateVersionRef(spec.profile_ref, 'profile_ref', errors)
  validateVersionRef(spec.scenario_ref, 'scenario_ref', errors)
  validateVersionRef(spec.policy_ref, 'policy_ref', errors)

  const policy = isPlainObject(spec.policy) ? spec.policy : undefined
  if (spec.policy_ref == null && spec.policy == null) {
    errors.push('version_unpinned:policy')
  }
  if (policy?.budget !== undefined) {
    const budget = validateRunBudget(policy.budget)
    if (!budget.ok) errors.push(...budget.errors.map((e) => `budget:${e}`))
  }

  const target = spec.target
  if (!isPlainObject(target) || typeof target.put_digest !== 'string' || !SHA256.test(target.put_digest)) {
    errors.push('artifact_unresolved:target')
  }

  const finalScenario = isPlainObject(spec.scenario) ? spec.scenario : undefined
  const cases = finalScenario?.cases
  if (Array.isArray(cases)) {
    for (const caseSpec of cases) {
      if (!isPlainObject(caseSpec)) continue
      const tool = caseSpec.tool
      if (isPlainObject(tool)) {
        if (typeof tool.workspaceRoot === 'string' || typeof tool.artifactPath === 'string') {
          if (!nonEmptyString(tool.workspaceRoot) || !nonEmptyString(tool.artifactPath)) {
            errors.push(`artifact_unresolved:${String(caseSpec.test_id)}`)
          } else {
            const containment = pathContainment(tool.workspaceRoot, tool.artifactPath)
            if (containment === 'escape') errors.push(`path_escape:${String(caseSpec.test_id)}`)
            if (containment === 'unresolved') errors.push(`artifact_unresolved:${String(caseSpec.test_id)}`)
          }
        }
      }
    }
  }

  return { ok: errors.length === 0, errors, stage: 'intake' }
}

/**
 * Validate a `gate-policy/v1` declaration. Besides the protocol schema, the
 * control face enforces the frozen precedence, disjoint baselines, resolvable
 * predicates/waivers and the fail-closed "at least one required" rule.
 */
export function validateGatePolicy(policy: unknown, options: { caseTestIds?: unknown } = {}): GatePolicyResult {
  const protocol = validateGatePolicyV1(policy)
  if (!protocol.ok) return { ok: false, errors: protocol.errors.map((e) => `gate-policy:${e}`), policy: null }

  const document = policy as UnknownRecord
  const errors: string[] = []
  const required = document.required_baseline as string[]
  const optional = document.optional_baseline as string[]
  const requiredSet = new Set(required)
  const optionalSet = new Set(optional)

  if (required.length === 0) errors.push('empty-required-baseline')
  for (const id of required) if (optionalSet.has(id)) errors.push(`baseline-overlap:${id}`)

  const aggregation = isPlainObject(document.aggregation) ? document.aggregation : undefined
  const precedence = aggregation?.precedence
  if (!Array.isArray(precedence) || precedence.length !== 3 ||
      precedence[0] !== AGGREGATION_PRECEDENCE[0] ||
      precedence[1] !== AGGREGATION_PRECEDENCE[1] ||
      precedence[2] !== AGGREGATION_PRECEDENCE[2]) {
    errors.push('aggregation-precedence-invalid')
  }

  const predicateIds = new Set<string>()
  const predicates = Array.isArray(document.not_applicable_predicates) ? document.not_applicable_predicates : []
  for (const raw of predicates) {
    const predicate = raw as UnknownRecord
    if (predicateIds.has(predicate.test_id as string)) errors.push(`duplicate-not-applicable-predicate:${predicate.test_id}`)
    predicateIds.add(predicate.test_id as string)
    if (!requiredSet.has(predicate.test_id as string) && !optionalSet.has(predicate.test_id as string)) {
      errors.push(`not-applicable-predicate-unknown-test:${predicate.test_id}`)
    }
    if (predicate.observed === 'unknown') {
      errors.push(`not-applicable-predicate-unknown-observed:${predicate.test_id}`)
    }
  }

  const waiverIds = new Set<string>()
  const waivers = Array.isArray(document.waiver_rules) ? document.waiver_rules : []
  for (const raw of waivers) {
    const rule = raw as UnknownRecord
    if (waiverIds.has(rule.test_id as string)) errors.push(`duplicate-waiver-rule:${rule.test_id}`)
    waiverIds.add(rule.test_id as string)
    if (!requiredSet.has(rule.test_id as string) && !optionalSet.has(rule.test_id as string)) {
      errors.push(`waiver-rule-unknown-test:${rule.test_id}`)
    }
  }

  if (Array.isArray(options.caseTestIds)) {
    const caseIds = new Set(options.caseTestIds as string[])
    for (const id of required) if (!caseIds.has(id)) errors.push(`candidate-missing-required-baseline:${id}`)
    for (const id of optional) if (!caseIds.has(id)) errors.push(`candidate-missing-optional-baseline:${id}`)
  }

  if (!uniqueStrings(required) || !uniqueStrings(optional)) errors.push('baseline-invalid')

  return { ok: errors.length === 0, errors, policy: errors.length === 0 ? document : null }
}
