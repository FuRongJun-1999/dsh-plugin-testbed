/**
 * Control-face plan compilation and freeze.
 * Pure functions; only import from `../protocol/*` (architecture §9.1, §9.4).
 * @module @deepseek-ai/dsh-plugin-testbed/control/plan
 */
import { sha256Hex, canonicalJson } from '../protocol/digest.js'
import { CAPABILITY_CLAIM, CAPABILITY_OBSERVED, inSet } from '../protocol/enums.js'
import { MAX_RETRY_ATTEMPTS } from '../protocol/tool-manifest.js'

const CLASSIFICATIONS = ['required', 'optional']
const SHA256 = /^sha256:[0-9a-f]{64}$/
export const MAX_PLAN_CASES = 256
export const MAX_CASE_ATTEMPTS = MAX_RETRY_ATTEMPTS
export const MAX_PLAN_TOTAL_ATTEMPTS = MAX_PLAN_CASES * MAX_CASE_ATTEMPTS

/**
 * Statically compile a scenario's cases into a non-removable `PlanCandidate`.
 *
 * @param {Array<object>} cases scenario cases
 * @returns {{ok:true, candidate:object} | {ok:false, errors:string[]}}
 */
export function compilePlanCandidate(cases) {
  if (!Array.isArray(cases)) return { ok: false, errors: ['cases-not-array'] }
  if (cases.length > MAX_PLAN_CASES) {
    return { ok: false, errors: [`case-count-exceeds-limit:${MAX_PLAN_CASES}`] }
  }

  const errors = []
  const nodeById = Object.create(null)
  const seenNode = new Set()
  const seenTest = new Set()
  let totalAttempts = 0

  for (const c of cases) {
    const nid = c?.node_id
    const tid = c?.test_id
    if (!nonEmptyString(tid) || !nonEmptyString(nid)) {
      errors.push(`missing-or-invalid-id:test_id=${String(tid)},node_id=${String(nid)}`)
      continue
    }
    const retryError = caseRetryError(c)
    if (retryError) errors.push(`${retryError}:${tid}`)
    else {
      totalAttempts += c.retry?.max_attempts ?? 1
      if (!Number.isSafeInteger(totalAttempts) || totalAttempts > MAX_PLAN_TOTAL_ATTEMPTS) {
        errors.push(`candidate-attempt-total-exceeds-limit:${MAX_PLAN_TOTAL_ATTEMPTS}`)
      }
    }
    if (seenTest.has(tid)) errors.push(`duplicate-test-id:${tid}`)
    seenTest.add(tid)
    if (seenNode.has(nid)) errors.push(`duplicate-node-id:${nid}`)
    seenNode.add(nid)
    if (!CLASSIFICATIONS.includes(c?.classification)) errors.push(`invalid-classification:${tid}`)
    if (c?.needs !== undefined && (!Array.isArray(c.needs) || c.needs.some((dep) => !nonEmptyString(dep)))) {
      errors.push(`invalid-needs:${tid}`)
    }
    nodeById[nid] = c
  }

  for (const c of cases) {
    if (!nonEmptyString(c?.test_id) || !nonEmptyString(c?.node_id)) continue
    for (const dep of Array.isArray(c?.needs) ? c.needs : []) {
      if (!seenNode.has(dep)) errors.push(`unknown-needs-reference:${c.test_id}->${dep}`)
    }
  }
  if (errors.length > 0) return { ok: false, errors }

  const topo = stableTopo(cases)
  if (topo.length !== cases.length) return { ok: false, errors: ['cycle-detected'] }

  const orderedNodeIds = topo.map((c) => c.node_id)
  const orderedTestIds = topo.map((c) => c.test_id)
  const requiredTestIds = topo.filter((c) => c.classification === 'required').map((c) => c.test_id)
  return {
    ok: true,
    candidate: {
      nodeIds: orderedNodeIds,
      nodeById,
      testIds: orderedTestIds,
      baselineTestIds: orderedTestIds,
      requiredTestIds,
      topoOrder: orderedNodeIds,
      cases: topo,
    },
  }
}

/**
 * Freeze a validated candidate into an immutable Plan.
 *
 * A not-applicable item is accepted only when its candidate has a predeclared
 * predicate and a control-facing, corroborated worker snapshot bound to the
 * trusted plan context. Invalid/unavailable evidence leaves the case expected
 * and required. Untrusted capability data embedded in a case is rejected;
 * snapshots and binding context must come from trusted control-plane options.
 * The current MVP probe cannot prove N/A: it emits unknown, never corroborated.
 *
 * `plan_id` hashes complete JSON case semantics, plan context, every capability
 * snapshot and its ref (including unknown records), accepted NA evidence, and
 * the frozen waiver allowlist. Digest binding is not capability verification.
 *
 * @param {object} candidate output of {@link compilePlanCandidate}
 * @param {{notApplicable?:string[], capabilitySnapshots?:object,
 *   planContext?:object, preapprovedWaivers?:string[]}} [opts]
 * @returns {{plan_id:string, testCases:Array, expected:string[], required:string[],
 *   notApplicable:string[], notApplicableDiagnostics:Array, notApplicableEvidence:object,
 *   planContext:object|null, waiverAllowlist:string[]}}
 */
export function freezePlan(candidate, opts = {}) {
  if (!opts || typeof opts !== 'object' || Array.isArray(opts)) throw new TypeError('freezePlan options must be an object')
  const cases = candidate?.cases
  if (!Array.isArray(cases)) throw new TypeError('freezePlan candidate.cases must be an array')
  if (cases.length > MAX_PLAN_CASES) throw new TypeError(`freezePlan candidate case-count-exceeds-limit:${MAX_PLAN_CASES}`)

  const caseById = new Map()
  const nodeIds = new Set()
  for (const c of cases) {
    if (!c || typeof c !== 'object' || !nonEmptyString(c.test_id) || !nonEmptyString(c.node_id)) {
      throw new TypeError('freezePlan candidate contains malformed test/node IDs')
    }
    if (Object.hasOwn(c, 'capability')) {
      throw new TypeError(`freezePlan case-embedded capability is untrusted: ${c.test_id}`)
    }
    const retryError = caseRetryError(c)
    if (retryError) throw new TypeError(`freezePlan ${retryError}:${c.test_id}`)
    if (caseById.has(c.test_id)) throw new TypeError(`freezePlan duplicate test_id: ${c.test_id}`)
    if (nodeIds.has(c.node_id)) throw new TypeError(`freezePlan duplicate node_id: ${c.node_id}`)
    if (!CLASSIFICATIONS.includes(c.classification)) throw new TypeError(`freezePlan invalid classification: ${c.test_id}`)
    caseById.set(c.test_id, c)
    nodeIds.add(c.node_id)
  }

  const caseOrder = cases.map((c) => c.test_id)
  const allTestIds = validatedCandidateIds(candidate, 'testIds', caseOrder, caseById)
  const baselineTestIds = validatedCandidateIds(candidate, 'baselineTestIds', allTestIds, caseById)
  const requiredTestIds = validatedCandidateIds(
    candidate,
    'requiredTestIds',
    cases.filter((c) => c.classification === 'required').map((c) => c.test_id),
    caseById,
  )
  if (!sameOrder(allTestIds, caseOrder) || !sameOrder(baselineTestIds, caseOrder)) {
    throw new TypeError('freezePlan testIds/baselineTestIds out of candidate order')
  }
  const derivedRequired = cases.filter((c) => c.classification === 'required').map((c) => c.test_id)
  if (!sameOrder(requiredTestIds, derivedRequired)) throw new TypeError('freezePlan requiredTestIds out of candidate order or inconsistent')

  const planContext = opts.planContext == null ? null : cloneJson(opts.planContext, 'planContext')
  const rawCapabilitySnapshots = opts.capabilitySnapshots == null
    ? null
    : cloneJson(opts.capabilitySnapshots, 'capabilitySnapshots')
  const snapshotRecords = extractCapabilitySnapshotRecords(rawCapabilitySnapshots)
  const capabilitySnapshots = rawCapabilitySnapshots === null ? null : snapshotRecords
  // Null-prototype maps keep reserved IDs (`__proto__`, `constructor`) as
  // ordinary own keys and prevent prototype mutation while deriving refs.
  const capabilitySnapshotRefs = Object.create(null)
  const capabilitySnapshotDiagnostics = []
  for (const [id, snapshot] of Object.entries(snapshotRecords)) {
    capabilitySnapshotRefs[id] = 'cap-sha256:' + sha256Hex(canonicalJson(snapshot))
    if (!caseById.has(id)) capabilitySnapshotDiagnostics.push({ test_id: id, reason: 'capability-snapshot-id-not-in-plan' })
    if (snapshot.test_id !== id) capabilitySnapshotDiagnostics.push({ test_id: id, reason: 'capability-snapshot-test-id-mismatch' })
  }
  const notApplicableInput = opts.notApplicable ?? []
  if (!Array.isArray(notApplicableInput)) throw new TypeError('freezePlan notApplicable must be an array')

  const requested = new Set()
  const requestedDuplicates = new Set()
  for (const id of notApplicableInput) {
    if (!nonEmptyString(id)) throw new TypeError('freezePlan notApplicable contains malformed test_id')
    if (requested.has(id)) requestedDuplicates.add(id)
    requested.add(id)
  }

  const notApplicable = []
  const notApplicableDiagnostics = []
  const notApplicableEvidence = Object.create(null)
  for (const id of requested) {
    if (requestedDuplicates.has(id)) {
      notApplicableDiagnostics.push({ test_id: id, reason: 'duplicate-not-applicable-id' })
      continue
    }
    const caseSpec = caseById.get(id)
    if (!caseSpec) {
      notApplicableDiagnostics.push({ test_id: id, reason: 'not-applicable-id-not-in-plan' })
      continue
    }
    const predicate = caseSpec.not_applicable_when
    if (!predicate || !inSet(CAPABILITY_OBSERVED, predicate.observed) ||
        (predicate.verification !== undefined && predicate.verification !== 'corroborated')) {
      notApplicableDiagnostics.push({ test_id: id, reason: 'not-applicable-predicate-missing-or-invalid' })
      continue
    }
    const snapshot = snapshotRecords[id] ?? null
    const evidenceFailure = validateCapabilityEvidence(snapshot, predicate, planContext)
    if (evidenceFailure) {
      notApplicableDiagnostics.push({ test_id: id, reason: evidenceFailure })
      continue
    }
    notApplicable.push(id)
    notApplicableEvidence[id] = cloneJson(snapshot, `capabilitySnapshots.${id}`)
  }

  const waiverAllowlist = validateWaiverAllowlist(opts.preapprovedWaivers ?? [], caseById)
  const testCases = cases.map((c) => cloneJson(c, `cases.${c.test_id}`))
  const expected = allTestIds.filter((id) => !notApplicable.includes(id))
  const required = expected.filter((id) => caseById.get(id).classification === 'required')
  const digestInput = {
    testCases,
    planContext,
    capabilitySnapshots,
    capabilitySnapshotRefs,
    not_applicable: notApplicable,
    not_applicable_evidence: notApplicableEvidence,
    waiver_allowlist: waiverAllowlist,
  }
  const plan_id = 'plan-sha256:' + sha256Hex(canonicalJson(digestInput))

  return {
    plan_id,
    testCases,
    expected,
    required,
    notApplicable,
    notApplicableDiagnostics,
    notApplicableEvidence,
    planContext,
    capabilitySnapshots,
    capabilitySnapshotRefs,
    capabilitySnapshotDiagnostics,
    waiverAllowlist,
  }
}

function validateCapabilityEvidence(snapshot, predicate, planContext) {
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) return 'capability-snapshot-missing'
  if (snapshot.source !== 'worker') return 'capability-snapshot-source-invalid'
  if (!inSet(CAPABILITY_CLAIM, snapshot.claim) || !inSet(CAPABILITY_OBSERVED, snapshot.observed) ||
      snapshot.verification !== 'corroborated') return 'capability-snapshot-not-corroborated'
  if (snapshot.observed !== predicate.observed ||
      (predicate.verification !== undefined && snapshot.verification !== predicate.verification)) {
    return 'capability-snapshot-does-not-match-predicate'
  }
  if (typeof snapshot.probe_time !== 'string' || !Number.isFinite(Date.parse(snapshot.probe_time))) {
    return 'capability-probe-time-invalid'
  }
  if (!planContext || typeof planContext !== 'object') return 'trusted-plan-context-missing'
  const trustedPutDigest = planContext.put_digest ?? planContext.target?.put_digest ?? null
  const trustedEnv = planContext.environment_fingerprint ?? planContext.environment?.fingerprint ?? null
  const trustedProbeVersion = planContext.probe_version ?? null
  if (typeof trustedPutDigest !== 'string' || !SHA256.test(trustedPutDigest) || snapshot.put_digest !== trustedPutDigest) {
    return 'capability-put-digest-mismatch'
  }
  if (typeof trustedEnv !== 'string' || !SHA256.test(trustedEnv) || snapshot.environment_fingerprint !== trustedEnv) {
    return 'capability-environment-mismatch'
  }
  if (typeof trustedProbeVersion !== 'string' || trustedProbeVersion.length === 0 || snapshot.probe_version !== trustedProbeVersion) {
    return 'capability-probe-version-mismatch'
  }
  return null
}

/**
 * Normalize all worker/control capability snapshots into a null-prototype map.
 * A map key and record.test_id are both part of the binding; mismatches are
 * rejected rather than allowing evidence to be attributed to another case.
 * The records-envelope form is accepted for protocol compatibility and its
 * envelope metadata is copied into each record before hashing.
 */
function extractCapabilitySnapshotRecords(raw) {
  if (raw === null) return Object.create(null)
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new TypeError('freezePlan capabilitySnapshots must be a record or records envelope')
  }

  const out = Object.create(null)
  if (Array.isArray(raw.records)) {
    const envelope = Object.create(null)
    for (const [key, value] of Object.entries(raw)) {
      if (key !== 'records') envelope[key] = value
    }
    for (const record of raw.records) {
      if (!record || typeof record !== 'object' || Array.isArray(record) || !nonEmptyString(record.test_id)) {
        throw new TypeError('freezePlan capabilitySnapshots.records contains malformed test_id')
      }
      const id = record.test_id
      if (Object.hasOwn(out, id)) throw new TypeError(`freezePlan duplicate capability snapshot test_id: ${id}`)
      const normalized = Object.assign(Object.create(null), envelope, record)
      normalized.test_id = id
      out[id] = normalized
    }
    return out
  }
  if (Object.hasOwn(raw, 'records')) {
    throw new TypeError('freezePlan capabilitySnapshots.records must be an array')
  }

  for (const [id, value] of Object.entries(raw)) {
    if (!nonEmptyString(id)) throw new TypeError('freezePlan capabilitySnapshots contains malformed test_id')
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new TypeError(`freezePlan capability snapshot is malformed: ${id}`)
    }
    if (value.test_id !== undefined && value.test_id !== id) {
      throw new TypeError(`freezePlan capability snapshot test_id mismatch: ${id}`)
    }
    const normalized = Object.assign(Object.create(null), value)
    normalized.test_id = id
    out[id] = normalized
  }
  return out
}

function validateWaiverAllowlist(values, caseById) {
  if (!Array.isArray(values)) throw new TypeError('freezePlan preapprovedWaivers must be an array')
  const seen = new Set()
  for (const id of values) {
    if (!nonEmptyString(id)) throw new TypeError('freezePlan preapprovedWaivers contains malformed test_id')
    if (seen.has(id)) throw new TypeError(`freezePlan duplicate preapproved waiver: ${id}`)
    if (!caseById.has(id)) throw new TypeError(`freezePlan preapproved waiver is not in plan: ${id}`)
    seen.add(id)
  }
  return [...seen]
}

function validatedCandidateIds(candidate, field, fallback, caseById) {
  const ids = candidate[field] === undefined ? fallback : candidate[field]
  if (!Array.isArray(ids)) throw new TypeError(`freezePlan candidate.${field} must be an array`)
  const seen = new Set()
  for (const id of ids) {
    if (!nonEmptyString(id)) throw new TypeError(`freezePlan candidate.${field} contains malformed test_id`)
    if (seen.has(id)) throw new TypeError(`freezePlan candidate.${field} contains duplicate test_id: ${id}`)
    if (!caseById.has(id)) throw new TypeError(`freezePlan candidate.${field} contains unknown test_id: ${id}`)
    seen.add(id)
  }
  return [...ids]
}

function sameOrder(a, b) {
  return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((id, index) => id === b[index])
}
function nonEmptyString(value) {
  return typeof value === 'string' && value.length > 0
}

function caseRetryError(caseSpec) {
  const retry = caseSpec?.retry
  if (retry === undefined || retry === null) return null
  if (!retry || typeof retry !== 'object' || Array.isArray(retry) ||
      (Object.getPrototypeOf(retry) !== Object.prototype && Object.getPrototypeOf(retry) !== null)) {
    return 'retry-invalid'
  }
  if (!Number.isSafeInteger(retry.max_attempts) || retry.max_attempts < 1) return 'retry-max-attempts-invalid'
  if (retry.max_attempts > MAX_CASE_ATTEMPTS) return 'retry-max-attempts-exceeds-limit'
  if (Object.hasOwn(retry, 'safe') && typeof retry.safe !== 'boolean') return 'retry-safe-invalid'
  return null
}

/** Clone JSON-compatible values so the frozen digest cannot follow later mutation. */
function cloneJson(value, path) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (Array.isArray(value)) return value.map((item, index) => {
    if (item === undefined) throw new TypeError(`non-JSON plan value at ${path}[${index}]`)
    return cloneJson(item, `${path}[${index}]`)
  })
  if (value && typeof value === 'object' && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)) {
    const out = Object.create(null)
    for (const [key, item] of Object.entries(value)) {
      if (item !== undefined) out[key] = cloneJson(item, `${path}.${key}`)
    }
    return out
  }
  throw new TypeError(`non-JSON plan value at ${path}`)
}

/** Kahn topological sort; ready set always sorted by `node_id` (lexicographic). */
function stableTopo(cases) {
  const byId = new Map(cases.map((c) => [c.node_id, c]))
  const inDegree = new Map()
  const successors = new Map()
  for (const c of cases) {
    inDegree.set(c.node_id, 0)
    successors.set(c.node_id, [])
  }
  for (const c of cases) {
    for (const dep of Array.isArray(c.needs) ? c.needs : []) {
      if (byId.has(dep)) {
        inDegree.set(c.node_id, inDegree.get(c.node_id) + 1)
        successors.get(dep).push(c.node_id)
      }
    }
  }
  const ready = []
  for (const c of cases) if (inDegree.get(c.node_id) === 0) ready.push(c.node_id)
  ready.sort()
  const order = []
  while (ready.length) {
    const id = ready.shift()
    order.push(byId.get(id))
    for (const succ of successors.get(id)) {
      const degree = inDegree.get(succ) - 1
      inDegree.set(succ, degree)
      if (degree === 0) {
        ready.push(succ)
        ready.sort()
      }
    }
  }
  return order
}
