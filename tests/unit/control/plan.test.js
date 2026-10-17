import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  compilePlanCandidate,
  freezePlan,
  MAX_PLAN_CASES,
  MAX_CASE_ATTEMPTS,
  MAX_PLAN_TOTAL_ATTEMPTS,
} from '../../../src/control/plan.js'
import { canonicalJson, sha256Hex } from '../../../src/protocol/digest.js'

const mk = (test_id, node_id, classification = 'required', needs = []) => ({
  test_id,
  node_id,
  classification,
  needs,
})
const digest = 'sha256:' + 'a'.repeat(64)
const context = {
  put_digest: digest,
  environment_fingerprint: digest,
  probe_version: 'capability-probe/v1',
}
const corroboratedSnapshot = (test_id, observed = 'absent') => ({
  test_id,
  source: 'worker',
  claim: 'not-declared',
  observed,
  verification: 'corroborated',
  probe_version: context.probe_version,
  probe_time: '2026-01-01T00:00:00.000Z',
  environment_fingerprint: digest,
  put_digest: digest,
  worker_fingerprint: null,
  evidence_ref: null,
  limitations: [],
})

function candidate(cases) {
  const result = compilePlanCandidate(cases)
  assert.equal(result.ok, true)
  return result.candidate
}

test('compilePlanCandidate: valid acyclic graph → stable topo', () => {
  const cases = [
    mk('t.z', 'nZ', 'required', ['nA']),
    mk('t.a', 'nA', 'required'),
    mk('t.m', 'nM', 'optional', ['nA']),
  ]
  const r = compilePlanCandidate(cases)
  assert.equal(r.ok, true)
  assert.deepEqual(r.candidate.topoOrder, ['nA', 'nM', 'nZ'])
  assert.deepEqual(r.candidate.testIds, ['t.a', 't.m', 't.z'])
  assert.deepEqual(r.candidate.baselineTestIds, ['t.a', 't.m', 't.z'])
  assert.deepEqual(r.candidate.requiredTestIds, ['t.a', 't.z'])
})

test('compilePlanCandidate: same-layer node_id lexicographic tie-break', () => {
  const r = compilePlanCandidate([mk('b', 'n9'), mk('a', 'n1'), mk('c', 'n2')])
  assert.equal(r.ok, true)
  assert.deepEqual(r.candidate.topoOrder, ['n1', 'n2', 'n9'])
})

test('compilePlanCandidate: case count is bounded without truncation', () => {
  const within = compilePlanCandidate(Array.from({ length: MAX_PLAN_CASES }, (_, i) => mk(`t${i}`, `n${i}`)))
  assert.equal(within.ok, true)
  assert.equal(within.candidate.cases.length, MAX_PLAN_CASES)
  const over = compilePlanCandidate(Array.from({ length: MAX_PLAN_CASES + 1 }, (_, i) => mk(`t${i}`, `n${i}`)))
  assert.equal(over.ok, false)
  assert.deepEqual(over.errors, [`case-count-exceeds-limit:${MAX_PLAN_CASES}`])
})

test('compilePlanCandidate: retry attempts are bounded and safe integers', () => {
  assert.equal(compilePlanCandidate([{ ...mk('a', 'n1'), retry: { max_attempts: MAX_CASE_ATTEMPTS } }]).ok, true)
  for (const value of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, MAX_CASE_ATTEMPTS + 1]) {
    const result = compilePlanCandidate([{ ...mk('a', 'n1'), retry: { max_attempts: value } }])
    assert.equal(result.ok, false)
    assert.ok(result.errors.some((error) => error.startsWith('retry-max-attempts-')))
  }
  const worstCase = Array.from({ length: MAX_PLAN_CASES }, (_, i) => ({
    ...mk(`t${i}`, `n${i}`), retry: { max_attempts: MAX_CASE_ATTEMPTS },
  }))
  const aggregate = compilePlanCandidate(worstCase)
  assert.equal(aggregate.ok, true)
  const total = aggregate.candidate.cases.reduce((sum, c) => sum + c.retry.max_attempts, 0)
  assert.ok(Number.isSafeInteger(total))
  assert.equal(total, MAX_PLAN_TOTAL_ATTEMPTS)
})

test('compilePlanCandidate rejects malformed/duplicate IDs and invalid classification', () => {
  const malformed = compilePlanCandidate([mk('', 'n1')])
  assert.equal(malformed.ok, false)
  assert.ok(malformed.errors.some((e) => e.includes('missing-or-invalid-id')))
  const dup = compilePlanCandidate([mk('x', 'n1'), mk('x', 'n2')])
  assert.equal(dup.ok, false)
  assert.ok(dup.errors.some((e) => e.includes('duplicate-test-id')))
  const invalidClass = compilePlanCandidate([mk('x', 'n1', 'bogus')])
  assert.equal(invalidClass.ok, false)
  assert.ok(invalidClass.errors.some((e) => e.includes('invalid-classification')))
})

test('compilePlanCandidate rejects duplicate nodes, unknown needs, and cycles', () => {
  assert.ok(compilePlanCandidate([mk('a', 'n1'), mk('b', 'n1')]).errors.some((e) => e.includes('duplicate-node-id')))
  assert.ok(compilePlanCandidate([mk('a', 'n1', 'required', ['ghost'])]).errors.some((e) => e.includes('unknown-needs-reference')))
  assert.ok(compilePlanCandidate([mk('a', 'n1', 'required', ['n2']), mk('b', 'n2', 'required', ['n1'])]).errors.some((e) => e.includes('cycle')))
})

test('freezePlan rejects caller-embedded capability and out-of-order candidate arrays', () => {
  const embedded = candidate([{ ...mk('a', 'n1'), capability: { observed: 'absent', verification: 'corroborated' } }])
  assert.throws(() => freezePlan(embedded), /case-embedded capability/)

  const c = candidate([mk('a', 'n1'), mk('b', 'n2')])
  assert.throws(() => freezePlan({ ...c, testIds: ['b', 'a'] }), /out of candidate order/)
  assert.throws(() => freezePlan({ ...c, baselineTestIds: ['b', 'a'] }), /out of candidate order/)
  assert.throws(() => freezePlan({ ...c, requiredTestIds: ['b', 'a'] }), /out of candidate order|inconsistent/)
})

test('freezePlan independently rejects forged over-limit count and retry', () => {
  const c = candidate([mk('a', 'n1')])
  const tooMany = Array.from({ length: MAX_PLAN_CASES + 1 }, (_, i) => mk(`t${i}`, `n${i}`))
  assert.throws(() => freezePlan({ ...c, cases: tooMany }), /case-count-exceeds-limit/)
  const badRetry = { ...c, cases: [{ ...c.cases[0], retry: { max_attempts: MAX_CASE_ATTEMPTS + 1 } }] }
  assert.throws(() => freezePlan(badRetry), /retry-max-attempts-exceeds-limit/)
})

test('freezePlan retains unknown snapshots in plan identity but never accepts unknown N/A evidence', () => {
  const c = candidate([mk('t.a', 'nA'), { ...mk('t.m', 'nM', 'optional'), not_applicable_when: { observed: 'absent', verification: 'corroborated' } }])
  const unknown = {
    't.m': {
      test_id: 't.m', source: 'worker', claim: 'not-declared', observed: 'unknown',
      probe_version: 'capability-probe/v1', probe_time: '2026-01-01T00:00:00.000Z',
      environment_fingerprint: digest, put_digest: digest, limitations: ['capability-not-measured-by-mvp-probe'],
    },
  }
  const f = freezePlan(c, { capabilitySnapshots: unknown, planContext: context, notApplicable: ['t.m'] })
  assert.deepEqual(f.notApplicable, [])
  assert.equal(f.notApplicableDiagnostics[0].reason, 'capability-snapshot-not-corroborated')
  assert.equal(f.expected.includes('t.m'), true)
  assert.equal(f.capabilitySnapshotRefs['t.m'], 'cap-sha256:' + sha256Hex(canonicalJson(f.capabilitySnapshots['t.m'])))

  const changedSnapshot = freezePlan(c, {
    capabilitySnapshots: { 't.m': { ...unknown['t.m'], limitations: ['changed'] } },
    planContext: context,
  })
  const changedContext = freezePlan(c, {
    capabilitySnapshots: unknown,
    planContext: { ...context, environment_fingerprint: 'sha256:' + 'b'.repeat(64) },
  })
  assert.notEqual(changedSnapshot.plan_id, f.plan_id)
  assert.notEqual(changedContext.plan_id, f.plan_id)
})

test('freezePlan accepts only corroborated trusted snapshot for N/A and binds all snapshots', () => {
  const c = candidate([mk('t.a', 'nA'), { ...mk('t.m', 'nM', 'optional'), not_applicable_when: { observed: 'absent', verification: 'corroborated' } }])
  const snapshot = corroboratedSnapshot('t.m')
  const f = freezePlan(c, { capabilitySnapshots: { 't.m': snapshot }, planContext: context, notApplicable: ['t.m'] })
  assert.deepEqual(f.notApplicable, ['t.m'])
  assert.deepEqual(f.expected, ['t.a'])
  assert.equal(canonicalJson(f.notApplicableEvidence['t.m']), canonicalJson(snapshot))
  assert.equal(f.capabilitySnapshotRefs['t.m'], 'cap-sha256:' + sha256Hex(canonicalJson(snapshot)))
  const changed = freezePlan(c, { capabilitySnapshots: { 't.m': { ...snapshot, limitations: ['changed'] } }, planContext: context, notApplicable: ['t.m'] })
  assert.notEqual(changed.plan_id, f.plan_id)
})

test('freezePlan preserves reserved snapshot IDs as own keys', () => {
  const c = candidate([mk('__proto__', 'n1'), mk('constructor', 'n2')])
  const snapshots = Object.create(null)
  snapshots.__proto__ = { test_id: '__proto__', source: 'worker', observed: 'unknown' }
  snapshots.constructor = { test_id: 'constructor', source: 'worker', observed: 'unknown' }
  const f = freezePlan(c, { capabilitySnapshots: snapshots })
  assert.equal(Object.hasOwn(f.capabilitySnapshots, '__proto__'), true)
  assert.equal(Object.hasOwn(f.capabilitySnapshotRefs, 'constructor'), true)
})

test('freezePlan rejects malformed, duplicate, and mismatched capability snapshot IDs', () => {
  const c = candidate([mk('a', 'n1')])
  assert.throws(() => freezePlan(c, { capabilitySnapshots: { a: null } }), /capability snapshot is malformed/)
  assert.throws(() => freezePlan(c, { capabilitySnapshots: { a: { test_id: 'b' } } }), /test_id mismatch/)
  assert.throws(() => freezePlan(c, { capabilitySnapshots: { records: [{ test_id: 'a' }, { test_id: 'a' }] } }), /duplicate capability snapshot/)
  assert.throws(() => freezePlan(c, { capabilitySnapshots: { records: [{ observed: 'unknown' }] } }), /malformed test_id/)
})

test('freezePlan no N/A request keeps all expected cases and deterministic identity', () => {
  const c = candidate([mk('t.a', 'nA'), mk('t.m', 'nM', 'optional')])
  const f1 = freezePlan(c)
  const f2 = freezePlan(c)
  assert.ok(f1.plan_id.startsWith('plan-sha256:'))
  assert.equal(f1.plan_id, f2.plan_id)
  assert.deepEqual(f1.expected, ['t.a', 't.m'])
  assert.deepEqual(f1.required, ['t.a'])
  assert.deepEqual(f1.notApplicable, [])
  assert.equal(f1.testCases.length, 2)
})
