/** RunSpec / GatePolicy static admission tests (control/spec.js). */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { join } from 'node:path'
import { validateGatePolicy, validateRunSpec, isPinnedVersion, pathContainment } from '../../../src/control/spec.js'
import { RUN_BUDGET_VERSION, PLATFORM_BUDGET_CEILINGS } from '../../../src/control/budget.js'

const sha = (c) => 'sha256:' + c.repeat(64)

function runSpec(overrides = {}) {
  return {
    schema_version: 'run-spec/v1',
    target: { kind: 'plugin', put_digest: sha('a') },
    profile_ref: { id: 'smoke', version: '1.0.0' },
    policy_ref: { id: 'gate-policy', version: '1.0.0' },
    scenario: {
      cases: [{ test_id: 'a', node_id: 'a', classification: 'required', probe: { value: 1 } }],
    },
    ...overrides,
  }
}

function gatePolicy(overrides = {}) {
  return {
    schema_version: 'gate-policy/v1',
    required_baseline: ['a'],
    optional_baseline: ['b'],
    not_applicable_predicates: [],
    waiver_rules: [],
    aggregation: { precedence: ['blocked', 'reject', 'pass'] },
    ...overrides,
  }
}

const budget = {
  schema_version: RUN_BUDGET_VERSION,
  ...PLATFORM_BUDGET_CEILINGS,
}

test('spec: valid run-spec/v1 passes static admission', () => {
  const result = validateRunSpec(runSpec())
  assert.equal(result.ok, true, JSON.stringify(result.errors))
  assert.equal(result.stage, 'intake')
})

test('spec: unknown fields / unknown version fail closed', () => {
  assert.equal(validateRunSpec(runSpec({ extra: true })).ok, false)
  assert.equal(validateRunSpec(runSpec({ schema_version: 'run-spec/v2' })).ok, false)
  assert.equal(validateRunSpec(null).ok, false)
})

test('spec: caller-supplied admission/verdict authority fields are rejected', () => {
  const admission = validateRunSpec(runSpec({
    scenario: { cases: [{ test_id: 'a', node_id: 'a', classification: 'required', probe: {}, admission: 'rejected' }] },
  }))
  assert.equal(admission.ok, false)
  assert.ok(admission.errors.some((e) => e.includes('untrusted-caller-field:admission')))

  const verdict = validateRunSpec(runSpec({
    scenario: { cases: [{ test_id: 'a', node_id: 'a', classification: 'required', probe: {}, verdict: 'pass' }] },
  }))
  assert.equal(verdict.ok, false)
  assert.ok(verdict.errors.some((e) => e.includes('untrusted-caller-field:verdict')))
})

test('spec: floating/version-unpinned references are rejected', () => {
  assert.equal(isPinnedVersion('1.0.0'), true)
  assert.equal(isPinnedVersion('latest'), false)
  assert.equal(isPinnedVersion('^1.0.0'), false)
  assert.equal(isPinnedVersion('1.x'), false)
  assert.equal(isPinnedVersion(''), false)

  const floating = validateRunSpec(runSpec({ profile_ref: { id: 'smoke', version: 'latest' } }))
  assert.equal(floating.ok, false)
  assert.ok(floating.errors.includes('floating_ref:profile_ref'))

  const unpinned = validateRunSpec(runSpec({ policy_ref: null }))
  assert.equal(unpinned.ok, false)
  assert.ok(unpinned.errors.includes('version_unpinned:policy'))
})

test('spec: tool paths must stay inside the declared workspace', () => {
  const cwd = process.cwd()
  const inside = join(cwd, 'tool.mjs')
  const outside = join(cwd, '..', 'escape.mjs')
  assert.equal(pathContainment(cwd, inside), 'ok')
  assert.equal(pathContainment(cwd, outside), 'escape')
  assert.equal(pathContainment(cwd, 'relative/tool.mjs'), 'unresolved')

  const toolCase = (artifactPath) => runSpec({
    scenario: {
      cases: [{
        test_id: 'a', node_id: 'a', classification: 'required',
        tool: { manifest: {}, input: {}, workspaceRoot: cwd, artifactPath },
      }],
    },
  })
  assert.equal(validateRunSpec(toolCase(inside)).ok, true)
  const escaped = validateRunSpec(toolCase(outside))
  assert.equal(escaped.ok, false)
  assert.ok(escaped.errors.some((e) => e.startsWith('path_escape:')))
  const relative = validateRunSpec(toolCase('relative/tool.mjs'))
  assert.equal(relative.ok, false)
  assert.ok(relative.errors.some((e) => e.startsWith('artifact_unresolved:')))
})

test('spec: invalid aggregate budget in the policy is rejected', () => {
  const result = validateRunSpec(runSpec({ policy: { budget: { schema_version: RUN_BUDGET_VERSION } } }))
  assert.equal(result.ok, false)
  assert.ok(result.errors.some((e) => e.startsWith('budget:')))
})

test('spec: valid gate-policy/v1 passes with the frozen precedence', () => {
  const result = validateGatePolicy(gatePolicy(), { caseTestIds: ['a', 'b'] })
  assert.equal(result.ok, true, JSON.stringify(result.errors))
  assert.equal(result.policy.aggregation.precedence[0], 'blocked')
})

test('spec: gate policy requires at least one required baseline and disjoint baselines', () => {
  const zero = validateGatePolicy(gatePolicy({ required_baseline: [] }))
  assert.equal(zero.ok, false)
  assert.ok(zero.errors.includes('empty-required-baseline'))

  const overlap = validateGatePolicy(gatePolicy({ required_baseline: ['a'], optional_baseline: ['a'] }))
  assert.ok(overlap.errors.includes('baseline-overlap:a'))
})

test('spec: aggregation precedence is fixed to blocked > reject > pass', () => {
  for (const precedence of [['pass', 'reject', 'blocked'], ['blocked', 'pass', 'reject']]) {
    const result = validateGatePolicy(gatePolicy({ aggregation: { precedence } }))
    assert.equal(result.ok, false)
    assert.ok(result.errors.includes('aggregation-precedence-invalid'))
  }
  // Wrong cardinality is already rejected by the declarative protocol schema.
  assert.equal(validateGatePolicy(gatePolicy({ aggregation: { precedence: ['blocked', 'reject'] } })).ok, false)
})

test('spec: applicability predicates and waivers must resolve to declared tests', () => {
  const predicate = validateGatePolicy(gatePolicy({
    not_applicable_predicates: [{ test_id: 'ghost', observed: 'absent' }],
  }))
  assert.ok(predicate.errors.some((e) => e.startsWith('not-applicable-predicate-unknown-test')))

  const unknownObserved = validateGatePolicy(gatePolicy({
    not_applicable_predicates: [{ test_id: 'a', observed: 'unknown' }],
  }))
  assert.ok(unknownObserved.errors.some((e) => e.includes('not-applicable-predicate-unknown-observed')))

  const waiver = validateGatePolicy(gatePolicy({ waiver_rules: [{ test_id: 'ghost' }] }))
  assert.ok(waiver.errors.some((e) => e.startsWith('waiver-rule-unknown-test')))
})

test('spec: candidate baseline must not omit a policy-declared required test', () => {
  const result = validateGatePolicy(gatePolicy({ required_baseline: ['a', 'missing'] }), { caseTestIds: ['a', 'b'] })
  assert.equal(result.ok, false)
  assert.ok(result.errors.includes('candidate-missing-required-baseline:missing'))
})

test('spec: protocol-invalid gate policy versions are rejected', () => {
  assert.equal(validateGatePolicy(gatePolicy({ schema_version: 'gate-policy/v2' })).ok, false)
  assert.equal(validateGatePolicy({}).ok, false)
  assert.equal(validateGatePolicy(null).ok, false)
})
