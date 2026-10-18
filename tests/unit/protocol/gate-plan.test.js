/**
 * 单元 · protocol gate-policy/v1 · plan-candidate/v1 · plan/v1（node:test）。
 *
 * 覆盖 implementation-design-protocol §6.2–6.4 与 architecture §6.1、§9.4：
 * 严格版本、字段闭集、枚举与摘要/内容寻址格式；这些只是类型声明，
 * 聚合与计划编译算法不在此模块。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  validateGatePolicyV1,
  validatePlanCandidateV1,
  validatePlanV1,
} from '../../../src/protocol/contracts.js'
import {
  GATE_POLICY_V1_SCHEMA,
  PLAN_CANDIDATE_V1_SCHEMA,
  PLAN_V1_SCHEMA,
  isGatePolicyVersion,
  isPlanCandidateVersion,
  isPlanVersion,
  schemaForVersion,
} from '../../../src/protocol/schemas.js'
import { validateValue } from '../../../src/protocol/jsonschema.js'

const DIGEST = (ch) => 'sha256:' + ch.repeat(64)
const PLAN_ID = 'plan-sha256:' + '6'.repeat(64)

function makePolicy(overrides = {}) {
  return {
    schema_version: 'gate-policy/v1',
    required_baseline: ['contract.login.schema'],
    optional_baseline: ['smoke.optional'],
    not_applicable_predicates: [{ test_id: 'contract.login.schema', observed: 'absent', verification: 'corroborated' }],
    waiver_rules: [{ test_id: 'smoke.optional', reason: 'not-applicable', scope: 'preapproved' }],
    aggregation: { precedence: ['blocked', 'reject', 'pass'] },
    ...overrides,
  }
}

function makeCandidate(overrides = {}) {
  return {
    schema_version: 'plan-candidate/v1',
    baseline_test_ids: ['contract.login.schema'],
    required_test_ids: ['contract.login.schema'],
    nodes: [{ node_id: 'n1', test_id: 'contract.login.schema' }],
    digest: DIGEST('b'),
    ...overrides,
  }
}

function makePlan(overrides = {}) {
  return {
    schema_version: 'plan/v1',
    plan_id: PLAN_ID,
    expected: ['contract.login.schema'],
    classification: {
      required: ['contract.login.schema'],
      optional: [],
      not_applicable: [],
    },
    attempt_limits: { max_attempts_per_case: 3, max_total_attempts: 768 },
    environment_matrix: { node: '24' },
    node_metadata: [{ test_id: 'contract.login.schema', tool_digest: DIGEST('1') }],
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// gate-policy/v1
// ---------------------------------------------------------------------------

test('gate-policy: 合法声明 → 通过', () => {
  const result = validateGatePolicyV1(makePolicy())
  assert.equal(result.ok, true, JSON.stringify(result.errors))
})

test('gate-policy: 未知主版本 → 拒绝且不降级', () => {
  for (const version of ['gate-policy/v2', 'gate-policy/v999', 'policy/v1']) {
    const result = validateGatePolicyV1(makePolicy({ schema_version: version }))
    assert.equal(result.ok, false, version)
    assert.ok(result.errors.includes(`unknown-version:${version}`))
  }
  assert.equal(isGatePolicyVersion('gate-policy/v1'), true)
  assert.equal(isGatePolicyVersion('gate-policy/v2'), false)
  assert.equal(schemaForVersion('gate-policy/v2'), null)
})

test('gate-policy: 缺必填/未知字段 → 拒绝', () => {
  for (const field of ['required_baseline', 'optional_baseline', 'not_applicable_predicates', 'waiver_rules', 'aggregation']) {
    const policy = makePolicy()
    delete policy[field]
    assert.equal(validateGatePolicyV1(policy).ok, false, field)
  }
  assert.equal(validateGatePolicyV1(makePolicy({ unexpected: 1 })).ok, false)
  assert.equal(validateGatePolicyV1(makePolicy({ signing_key: 'x' })).ok, false)
})

test('gate-policy: baseline 必须是唯一 test_id 数组', () => {
  assert.equal(validateGatePolicyV1(makePolicy({ required_baseline: 'x' })).ok, false)
  assert.equal(validateGatePolicyV1(makePolicy({ required_baseline: ['t1', 't1'] })).ok, false)
  assert.equal(validateGatePolicyV1(makePolicy({ required_baseline: [1] })).ok, false)
})

test('gate-policy: 谓词/豁免/聚合优先级枚举受检', () => {
  assert.equal(validateGatePolicyV1(makePolicy({
    not_applicable_predicates: [{ test_id: 't', observed: 'maybe' }],
  })).ok, false)
  assert.equal(validateGatePolicyV1(makePolicy({
    not_applicable_predicates: [{ test_id: 't', observed: 'absent', verification: 'contradicted' }],
  })).ok, false)
  assert.equal(validateGatePolicyV1(makePolicy({
    not_applicable_predicates: [{ test_id: 't', observed: 'absent', signature: 'x' }],
  })).ok, false)
  assert.equal(validateGatePolicyV1(makePolicy({
    waiver_rules: [{ reason: 'no-test-id' }],
  })).ok, false)
  assert.equal(validateGatePolicyV1(makePolicy({
    aggregation: { precedence: ['blocked', 'pass', 'blocked'] },
  })).ok, false)
  assert.equal(validateGatePolicyV1(makePolicy({
    aggregation: { precedence: ['blocked', 'reject'] },
  })).ok, false)
  assert.equal(validateGatePolicyV1(makePolicy({ aggregation: { precedence: ['blocked', 'reject', 'pass'], extra: 1 } })).ok, false)
})

test('gate-policy: schema 顶层 additionalProperties=false', () => {
  assert.equal(GATE_POLICY_V1_SCHEMA.additionalProperties, false)
  const checked = validateValue({ ...makePolicy(), injected: true }, GATE_POLICY_V1_SCHEMA)
  assert.equal(checked.ok, false)
  assert.ok(checked.errors.includes('additional-properties-not-allowed:injected'))
})

// ---------------------------------------------------------------------------
// plan-candidate/v1
// ---------------------------------------------------------------------------

test('plan-candidate: 合法声明 → 通过', () => {
  const result = validatePlanCandidateV1(makeCandidate())
  assert.equal(result.ok, true, JSON.stringify(result.errors))
})

test('plan-candidate: 未知主版本 → 拒绝且不降级', () => {
  for (const version of ['plan-candidate/v2', 'plan-candidate/v999', 'candidate/v1']) {
    const result = validatePlanCandidateV1(makeCandidate({ schema_version: version }))
    assert.equal(result.ok, false, version)
    assert.ok(result.errors.includes(`unknown-version:${version}`))
  }
  assert.equal(isPlanCandidateVersion('plan-candidate/v1'), true)
  assert.equal(isPlanCandidateVersion('plan-candidate/v2'), false)
  assert.equal(schemaForVersion('plan-candidate/v2'), null)
})

test('plan-candidate: 缺必填/未知字段/重复基线/坏摘要 → 拒绝', () => {
  for (const field of ['baseline_test_ids', 'required_test_ids', 'digest']) {
    const candidate = makeCandidate()
    delete candidate[field]
    assert.equal(validatePlanCandidateV1(candidate).ok, false, field)
  }
  assert.equal(validatePlanCandidateV1(makeCandidate({ unexpected: 1 })).ok, false)
  assert.equal(validatePlanCandidateV1(makeCandidate({ baseline_test_ids: ['t1', 't1'] })).ok, false)
  assert.equal(validatePlanCandidateV1(makeCandidate({ digest: 'sha256:not-hex' })).ok, false)
  assert.equal(validatePlanCandidateV1(makeCandidate({ signature: 'x' })).ok, false)
})

test('plan-candidate: schema 顶层 additionalProperties=false', () => {
  assert.equal(PLAN_CANDIDATE_V1_SCHEMA.additionalProperties, false)
  const checked = validateValue({ ...makeCandidate(), injected: true }, PLAN_CANDIDATE_V1_SCHEMA)
  assert.equal(checked.ok, false)
})

// ---------------------------------------------------------------------------
// plan/v1
// ---------------------------------------------------------------------------

test('plan: 合法冻结声明 → 通过', () => {
  const result = validatePlanV1(makePlan())
  assert.equal(result.ok, true, JSON.stringify(result.errors))
})

test('plan: 未知主版本 → 拒绝且不降级', () => {
  for (const version of ['plan/v2', 'plan/v999', 'frozen-plan/v1']) {
    const result = validatePlanV1(makePlan({ schema_version: version }))
    assert.equal(result.ok, false, version)
    assert.ok(result.errors.includes(`unknown-version:${version}`))
  }
  assert.equal(isPlanVersion('plan/v1'), true)
  assert.equal(isPlanVersion('plan/v2'), false)
  assert.equal(schemaForVersion('plan/v2'), null)
})

test('plan: plan_id 必须是 plan-sha256 内容寻址摘要', () => {
  assert.equal(validatePlanV1(makePlan({ plan_id: DIGEST('6') })).ok, false)
  assert.equal(validatePlanV1(makePlan({ plan_id: 'plan-sha256:abc' })).ok, false)
})

test('plan: classification 三组齐备、expected 唯一；非法 attempt 上限拒绝', () => {
  assert.equal(validatePlanV1(makePlan({ classification: { required: [], optional: [] } })).ok, false)
  assert.equal(validatePlanV1(makePlan({ expected: ['t1', 't1'] })).ok, false)
  assert.equal(validatePlanV1(makePlan({
    classification: { required: [], optional: [], not_applicable: [], injected: [] },
  })).ok, false)
  assert.equal(validatePlanV1(makePlan({ attempt_limits: { max_attempts_per_case: 4 } })).ok, false)
  assert.equal(validatePlanV1(makePlan({ attempt_limits: { max_attempts_per_case: 3, unexpected: 1 } })).ok, false)
  assert.equal(validatePlanV1(makePlan({ unexpected: 1 })).ok, false)
  assert.equal(validatePlanV1(makePlan({ expected: ['t1'], signature: 'x' })).ok, false)
})

test('plan: schema 顶层 additionalProperties=false', () => {
  assert.equal(PLAN_V1_SCHEMA.additionalProperties, false)
  const checked = validateValue({ ...makePlan(), injected: true }, PLAN_V1_SCHEMA)
  assert.equal(checked.ok, false)
  assert.ok(checked.errors.includes('additional-properties-not-allowed:injected'))
})
