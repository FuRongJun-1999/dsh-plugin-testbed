/** Frozen-plan identity, non-removability and mutation-rejection tests. */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  compilePlanCandidate,
  freezePlan,
  planResolutionEntries,
  rejectPlanMutation,
  verifyFrozenPlan,
} from '../../../src/control/plan.js'
import { verifyCapabilitySnapshot } from '../../../src/control/capability.js'
import { RUN_BUDGET_VERSION, PLATFORM_BUDGET_CEILINGS } from '../../../src/control/budget.js'
import { canonicalJson } from '../../../src/protocol/digest.js'

const sha = (c) => 'sha256:' + c.repeat(64)
const context = {
  put_digest: sha('a'),
  environment_fingerprint: sha('b'),
  probe_version: 'capability-probe/test',
}

function mk(testId, overrides = {}) {
  return {
    test_id: testId,
    node_id: testId,
    classification: 'required',
    criteria: { assert: 'equals', expected: 1 },
    probe: { value: 1 },
    ...overrides,
  }
}

function gatePolicy(overrides = {}) {
  return {
    schema_version: 'gate-policy/v1',
    required_baseline: ['a'],
    optional_baseline: [],
    not_applicable_predicates: [],
    waiver_rules: [],
    aggregation: { precedence: ['blocked', 'reject', 'pass'] },
    ...overrides,
  }
}

test('plan: compile rejects caller-supplied authority fields', () => {
  for (const field of ['admission', 'verdict', 'gate_decision', 'required', 'expected', 'plan']) {
    const result = compilePlanCandidate([mk('a', { [field]: 'x' })])
    assert.equal(result.ok, false, field)
    assert.ok(result.errors.some((e) => e.startsWith(`untrusted-caller-field:${field}`)), field)
  }

  const runSpecShaped = compilePlanCandidate({
    schema_version: 'run-spec/v1',
    target: { kind: 'plugin', put_digest: sha('c') },
    scenario: { cases: [mk('a', { admission: 'rejected' })] },
  })
  assert.equal(runSpecShaped.ok, false)
  assert.ok(runSpecShaped.errors.some((e) => e.startsWith('untrusted-caller-field:admission')))

  const validRunSpec = compilePlanCandidate({
    schema_version: 'run-spec/v1',
    target: { kind: 'plugin', put_digest: sha('c') },
    scenario: { cases: [mk('a')] },
  })
  assert.equal(validRunSpec.ok, true)
})

test('plan: policy-declared required baseline cannot be omitted or downgraded', () => {
  const missing = compilePlanCandidate([mk('a')], {
    gatePolicy: gatePolicy({ required_baseline: ['a', 'ghost'] }),
  })
  assert.equal(missing.ok, false)
  assert.ok(missing.errors.includes('candidate-missing-required-baseline:ghost'))

  const optionalCase = compilePlanCandidate([mk('a', { classification: 'optional' })], {
    gatePolicy: gatePolicy(),
  })
  assert.equal(optionalCase.ok, false)
  assert.ok(optionalCase.errors.includes('required-baseline-classification-mismatch:a'))

  const undeclaredRequired = compilePlanCandidate([mk('a'), mk('b')], {
    gatePolicy: gatePolicy(),
  })
  assert.equal(undeclaredRequired.ok, false)
  assert.ok(undeclaredRequired.errors.includes('required-classification-not-in-policy:b'))
})

test('plan: freeze independently re-checks policy baseline coverage', () => {
  const compiled = compilePlanCandidate([mk('a')])
  assert.throws(
    () => freezePlan(compiled.candidate, { gatePolicy: gatePolicy({ required_baseline: ['ghost'] }) }),
    /gate policy invalid|required-baseline/,
  )
})

test('plan: caller admission is stripped from the frozen plan and cannot change its identity', () => {
  const candidate = {
    cases: [mk('a', { admission: 'rejected' })],
    testIds: ['a'],
    baselineTestIds: ['a'],
    requiredTestIds: ['a'],
    topoOrder: ['a'],
    testOrder: ['a'],
  }
  const frozen = freezePlan(candidate)
  assert.equal(Object.hasOwn(frozen.testCases[0], 'admission'), false)
  assert.ok(frozen.mutationDiagnostics.some((d) => d.reason === 'case-authority-field-stripped:admission'))
  assert.deepEqual(frozen.expected, ['a'])
  assert.deepEqual(frozen.required, ['a'])
})

test('plan: unknown/contradicted capability verification never shrinks required', () => {
  const cases = [mk('a'), mk('b', { not_applicable_when: { observed: 'absent', verification: 'corroborated' } })]
  const compiled = compilePlanCandidate(cases)
  const snapshot = {
    test_id: 'b', source: 'worker', claim: 'not-declared', observed: 'unknown',
    probe_version: context.probe_version, probe_time: '2026-01-01T00:00:00.000Z',
    environment_fingerprint: context.environment_fingerprint, put_digest: context.put_digest,
    limitations: [],
  }
  const verification = verifyCapabilitySnapshot(compiled.candidate, { b: snapshot }, {
    planContext: context,
    notApplicable: ['b'],
  })
  const frozen = freezePlan(compiled.candidate, { capabilityVerification: verification })
  assert.deepEqual(frozen.notApplicable, [])
  assert.deepEqual(frozen.expected, ['a', 'b'])
  assert.deepEqual(frozen.required, ['a', 'b'])
  assert.ok(frozen.notApplicableDiagnostics.some((d) => d.test_id === 'b'))
})

test('plan: only a corroborated verified predicate moves an item to not-applicable', () => {
  const cases = [mk('a'), mk('b', { not_applicable_when: { observed: 'absent', verification: 'corroborated' } })]
  const compiled = compilePlanCandidate(cases)
  const snapshot = {
    test_id: 'b', source: 'worker', claim: 'not-declared', observed: 'absent',
    probe_version: context.probe_version, probe_time: '2026-01-01T00:00:00.000Z',
    environment_fingerprint: context.environment_fingerprint, put_digest: context.put_digest,
    limitations: [],
  }
  const verification = verifyCapabilitySnapshot(compiled.candidate, { b: snapshot }, {
    planContext: context,
    notApplicable: ['b'],
  })
  const frozen = freezePlan(compiled.candidate, { capabilityVerification: verification })
  assert.deepEqual(frozen.notApplicable, ['b'])
  assert.deepEqual(frozen.expected, ['a'])
  assert.deepEqual(frozen.required, ['a'])
  assert.deepEqual(frozen.classification.not_applicable, ['b'])
  // The item remains in testCases (never silently deleted from the baseline).
  assert.deepEqual(frozen.testCases.map((testCase) => testCase.test_id), ['a', 'b'])
  assert.equal(frozen.notApplicableDetails[0].test_id, 'b')
  assert.match(frozen.notApplicableDetails[0].not_applicable.capability_snapshot_ref, /^cap-sha256:/)
})

test('plan: budget and environment matrix are bound into plan identity', () => {
  const compiled = compilePlanCandidate([mk('a')])
  const base = freezePlan(compiled.candidate)
  const budget = { schema_version: RUN_BUDGET_VERSION, ...PLATFORM_BUDGET_CEILINGS, max_total_attempts: 2 }
  const withBudget = freezePlan(compiled.candidate, { budget })
  const withEnv = freezePlan(compiled.candidate, {
    environmentMatrix: { node: 'v24', os: 'windows', isolation: 'L1' },
  })
  assert.notEqual(withBudget.plan_id, base.plan_id)
  assert.notEqual(withEnv.plan_id, base.plan_id)
  assert.notEqual(withBudget.plan_id, withEnv.plan_id)
})

test('plan: frozen plan is deep-frozen and verifies its own identity offline', () => {
  const compiled = compilePlanCandidate([mk('a')])
  const frozen = freezePlan(compiled.candidate)
  assert.equal(Object.isFrozen(frozen), true)
  assert.equal(Object.isFrozen(frozen.testCases), true)
  assert.equal(Object.isFrozen(frozen.expected), true)
  assert.equal(Object.isFrozen(frozen.capabilitySnapshotRefs), true)

  const verified = verifyFrozenPlan(frozen)
  assert.equal(verified.ok, true, JSON.stringify(verified.errors))
  assert.equal(verified.recomputed, frozen.plan_id)
})

test('plan: mutation of a clone is detected as plan identity mismatch', () => {
  const compiled = compilePlanCandidate([mk('a'), mk('b')])
  const frozen = freezePlan(compiled.candidate)
  const tampered = structuredClone(frozen)
  tampered.expected = ['a']
  const verified = verifyFrozenPlan(tampered)
  assert.equal(verified.ok, false)
  assert.ok(verified.errors.includes('plan-identity-mismatch'))
  // The original frozen plan is unchanged.
  assert.deepEqual(frozen.expected, ['a', 'b'])
})

test('plan: injected authority field into a frozen test case is detected', () => {
  const compiled = compilePlanCandidate([mk('a')])
  const frozen = freezePlan(compiled.candidate)
  const tampered = structuredClone(frozen)
  tampered.testCases[0].admission = 'rejected'
  const verified = verifyFrozenPlan(tampered)
  assert.equal(verified.ok, false)
  assert.ok(verified.errors.some((e) => e.includes('frozen-test-case-authority-field:admission')))
})

test('plan: post-freeze mutation requests are rejected and traced without touching the plan', () => {
  const compiled = compilePlanCandidate([mk('a')])
  const frozen = freezePlan(compiled.candidate)
  const before = structuredClone(frozen)

  const rejection = rejectPlanMutation(frozen, {
    operation: 'add', test_id: 'ghost', requestor: 'suggester',
  }, { now: '2026-01-01T00:00:00.000Z' })
  assert.equal(rejection.ok, false)
  assert.equal(rejection.rejection.type, 'plan_immutable_violation')
  assert.equal(rejection.rejection.plan_id, frozen.plan_id)
  assert.equal(rejection.rejection.operation, 'add')
  assert.equal(rejection.rejection.test_id, 'ghost')
  assert.equal(rejection.rejection.requestor, 'suggester')
  assert.equal(rejection.rejection.at, '2026-01-01T00:00:00.000Z')
  assert.equal(canonicalJson(frozen), canonicalJson(before))

  const verified = verifyFrozenPlan(frozen)
  assert.equal(verified.ok, true)
})

test('plan: graph candidates freeze with deterministic test order', () => {
  const graph = {
    nodes: [
      { type: 'ToolTask', node_id: 'n2', test_id: 't2', classification: 'optional', tool: {
        manifest: {
          schema_version: 'test-tool-manifest/v1', tool_id: 't', tool_version: '1.0.0',
          artifact_digest: sha('a'), role: 'probe', tags: [],
          runner: { adapter: 'local-worker-json', entrypoint: 'run' },
          input_schema: { type: 'object' }, observation_schema: { type: 'object' },
          requires: [], permissions: { filesystem: [], network: [], subprocess: [], devices: [], secrets: [] },
          limits: { timeout_ms: 1000, cpu_ms: 1000, memory_mb: 64, temp_bytes: 1024, output_bytes: 1024, attachment_bytes: 1024, processes: 1, concurrency: 1 },
          determinism: 'deterministic', retry: { safe: false, max_attempts: 1 },
        },
        input: {},
      } },
      { type: 'ToolTask', node_id: 'n1', test_id: 't1', classification: 'required', probe: undefined },
    ],
  }
  // Replace the second node with a valid ToolTask shape (probe is not a graph node field).
  graph.nodes[1] = {
    type: 'ToolTask', node_id: 'n1', test_id: 't1', classification: 'required',
    tool: {
      manifest: graph.nodes[0].tool.manifest,
      input: {},
    },
  }
  const compiled = compilePlanCandidate(graph)
  assert.equal(compiled.ok, true, JSON.stringify(compiled.errors))
  const frozen = freezePlan(compiled.candidate)
  assert.deepEqual(frozen.testOrder, ['t1', 't2'])
  assert.deepEqual(frozen.topoOrder, ['n1', 'n2'])
  assert.deepEqual(frozen.required, ['t1'])
  const verified = verifyFrozenPlan(frozen)
  assert.equal(verified.ok, true, JSON.stringify(verified.errors))
})

test('plan: arbitrary/user-supplied assertions are rejected statically', () => {
  for (const criteria of [{ assert: 'evil-code', source: 'x' }, { assert: 'eval' }, null, ['equals']]) {
    const result = compilePlanCandidate([mk('a', { criteria })])
    assert.equal(result.ok, false, JSON.stringify(criteria))
    assert.ok(result.errors.some((e) => e.startsWith('unsupported-assertion:')), JSON.stringify(result.errors))
  }
})

test('plan: design signatures compilePlanCandidate(runSpec, policy, scenario) / freezePlan(candidate, verification) work', () => {
  const runSpec = { schema_version: 'run-spec/v1', target: { kind: 'plugin', put_digest: sha('c') } }
  const compiled = compilePlanCandidate(runSpec, gatePolicy(), { cases: [mk('a')] })
  assert.equal(compiled.ok, true, JSON.stringify(compiled.errors))

  const verification = verifyCapabilitySnapshot(compiled.candidate, {}, { planContext: context })
  const frozen = freezePlan(compiled.candidate, verification)
  assert.deepEqual(frozen.expected, ['a'])
  assert.equal(verifyFrozenPlan(frozen).ok, true)
})

test('plan: planResolutionEntries keeps every candidate and carries N/A evidence', () => {
  const cases = [mk('a'), mk('b', { not_applicable_when: { observed: 'absent', verification: 'corroborated' } })]
  const compiled = compilePlanCandidate(cases)
  const snapshot = {
    test_id: 'b', source: 'worker', claim: 'not-declared', observed: 'absent',
    probe_version: context.probe_version, probe_time: '2026-01-01T00:00:00.000Z',
    environment_fingerprint: context.environment_fingerprint, put_digest: context.put_digest,
    limitations: [],
  }
  const verification = verifyCapabilitySnapshot(compiled.candidate, { b: snapshot }, {
    planContext: context, notApplicable: ['b'],
  })
  const frozen = freezePlan(compiled.candidate, { capabilityVerification: verification })
  const entries = planResolutionEntries(frozen)
  assert.deepEqual(entries.map((entry) => entry.test_id), ['a', 'b'])
  assert.equal(entries[1].not_applicable.predicate_version, 'capability-predicate/v1')
  assert.match(entries[1].not_applicable.capability_snapshot_ref, /^cap-sha256:/)
  assert.equal(entries[0].not_applicable, undefined)
})
