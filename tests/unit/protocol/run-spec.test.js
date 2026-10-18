/**
 * 单元 · protocol/run-spec/v1 严格校验（node:test）。
 *
 * 覆盖 implementation-design-protocol §6.1 / §7 与 architecture §9.1、§12：
 * 版本固定、字段闭集、目标摘要格式、场景 case 必填/枚举、profile/policy 引用、
 * retry 有界；未知主版本不隐式降级。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import { validateRunSpecV1 } from '../../../src/protocol/contracts.js'
import { RUN_SPEC_V1_SCHEMA, isRunSpecVersion, schemaForVersion } from '../../../src/protocol/schemas.js'
import { validateValue } from '../../../src/protocol/jsonschema.js'

const DIGEST = (ch) => 'sha256:' + ch.repeat(64)

function makeCase(overrides = {}) {
  return {
    test_id: 'contract.echo',
    node_id: 'n1',
    classification: 'required',
    criteria: { assert: 'equals', path: 'status', expected: 'ok' },
    probe: { observations: [{ value: { status: 'ok' } }] },
    ...overrides,
  }
}

function makeRunSpec(overrides = {}) {
  return {
    schema_version: 'run-spec/v1',
    target: { kind: 'plugin', put_digest: DIGEST('a') },
    scenario: { cases: [makeCase()] },
    ...overrides,
  }
}

test('run-spec: 最小合法声明 → 通过', () => {
  const result = validateRunSpecV1(makeRunSpec())
  assert.equal(result.ok, true, JSON.stringify(result.errors))
})

test('run-spec: profile/scenario/policy 引用与 policy.budget 均可选地出现', () => {
  const spec = makeRunSpec({
    profile_ref: { id: 'smoke', version: '1.0.0' },
    scenario_ref: { id: 'scenario', version: '1.0.0', digest: DIGEST('b') },
    policy_ref: { id: 'gate-policy', version: '1.0.0' },
    policy: { budget: { schema_version: 'run-budget/v1' }, preapproved_waivers: [] },
  })
  const result = validateRunSpecV1(spec)
  assert.equal(result.ok, true, JSON.stringify(result.errors))
})

test('run-spec: 完整 case（needs/dimensions/retry/not_applicable_when/tool）→ 通过', () => {
  const spec = makeRunSpec({
    scenario: {
      cases: [makeCase({
        needs: ['n0'],
        dimensions: { test_level: 'component', test_type: ['functional'] },
        retry: { safe: true, max_attempts: 3 },
        not_applicable_when: { observed: 'absent', verification: 'corroborated' },
        tool: {
          manifest: { schema_version: 'test-tool-manifest/v1' },
          input: { fixture_ref: 'fixture://login/v1' },
          artifactPath: 'tools/api-contract',
          workspaceRoot: '.',
        },
      })],
    },
  })
  const result = validateRunSpecV1(spec)
  assert.equal(result.ok, true, JSON.stringify(result.errors))
})

test('run-spec: 未知主版本 run-spec/v2 → 拒绝且不降级', () => {
  for (const version of ['run-spec/v2', 'run-spec/v999', 'run-spec', 'other/v1']) {
    const result = validateRunSpecV1(makeRunSpec({ schema_version: version }))
    assert.equal(result.ok, false, version)
    assert.ok(result.errors.includes(`unknown-version:${version}`), version)
  }
  assert.equal(isRunSpecVersion('run-spec/v1'), true)
  assert.equal(isRunSpecVersion('run-spec/v2'), false)
  assert.equal(schemaForVersion('run-spec/v2'), null)
})

test('run-spec: schema_version/target/scenario 缺失 → 拒绝', () => {
  for (const field of ['schema_version', 'target', 'scenario']) {
    const spec = makeRunSpec()
    delete spec[field]
    assert.equal(validateRunSpecV1(spec).ok, false, field)
  }
})

test('run-spec: 未知顶层字段（含凭据形态）→ 拒绝', () => {
  for (const field of ['credentials', 'secret', 'signing_key', 'extra']) {
    const result = validateRunSpecV1(makeRunSpec({ [field]: 'x' }))
    assert.equal(result.ok, false, field)
    assert.ok(result.errors.includes(`schema:additional-properties-not-allowed:${field}`))
  }
})

test('run-spec: target 必须绑定具体摘要，拒绝浮动 tag/未知 kind', () => {
  assert.equal(validateRunSpecV1(makeRunSpec({ target: { kind: 'plugin' } })).ok, false)
  assert.equal(validateRunSpecV1(makeRunSpec({ target: { kind: 'plugin', put_digest: 'latest' } })).ok, false)
  assert.equal(validateRunSpecV1(makeRunSpec({ target: { kind: 'unknown', put_digest: DIGEST('a') } })).ok, false)
  assert.equal(validateRunSpecV1(makeRunSpec({ target: { kind: 'plugin', put_digest: DIGEST('a'), extra: 1 } })).ok, false)
})

test('run-spec: scenario.cases 必须非空数组', () => {
  assert.equal(validateRunSpecV1(makeRunSpec({ scenario: {} })).ok, false)
  assert.equal(validateRunSpecV1(makeRunSpec({ scenario: { cases: [] } })).ok, false)
  assert.equal(validateRunSpecV1(makeRunSpec({ scenario: { cases: 'nope' } })).ok, false)
})

test('run-spec: case 必填 test_id/node_id/classification，classification 为闭集', () => {
  for (const field of ['test_id', 'node_id', 'classification']) {
    const spec = makeRunSpec({ scenario: { cases: [makeCase({ [field]: undefined })] } })
    assert.equal(validateRunSpecV1(spec).ok, false, field)
  }
  for (const classification of ['required', 'optional']) {
    assert.equal(validateRunSpecV1(makeRunSpec({ scenario: { cases: [makeCase({ classification })] } })).ok, true, classification)
  }
  assert.equal(validateRunSpecV1(makeRunSpec({ scenario: { cases: [makeCase({ classification: 'not-applicable' })] } })).ok, false)
})

test('run-spec: case 未知字段与 needs 重复 → 拒绝', () => {
  const unknown = makeRunSpec({ scenario: { cases: [makeCase({ unexpected: 1 })] } })
  assert.equal(validateRunSpecV1(unknown).ok, false)
  const dupNeeds = makeRunSpec({ scenario: { cases: [makeCase({ needs: ['n0', 'n0'] })] } })
  assert.equal(validateRunSpecV1(dupNeeds).ok, false)
})

test('run-spec: retry 有界（safe 布尔、max_attempts ≤ 3），未知字段拒绝', () => {
  assert.equal(validateRunSpecV1(makeRunSpec({ scenario: { cases: [makeCase({ retry: { safe: false, max_attempts: 1 } })] } })).ok, true)
  assert.equal(validateRunSpecV1(makeRunSpec({ scenario: { cases: [makeCase({ retry: { safe: true, max_attempts: 4 } })] } })).ok, false)
  assert.equal(validateRunSpecV1(makeRunSpec({ scenario: { cases: [makeCase({ retry: { safe: 'yes', max_attempts: 1 } })] } })).ok, false)
  assert.equal(validateRunSpecV1(makeRunSpec({ scenario: { cases: [makeCase({ retry: {} })] } })).ok, false)
  assert.equal(validateRunSpecV1(makeRunSpec({ scenario: { cases: [makeCase({ retry: { safe: true, max_attempts: 1, backoff: 'x' } })] } })).ok, false)
})

test('run-spec: criteria 仅允许受控断言 DSL，未知 assert/字段拒绝', () => {
  const badAssert = makeRunSpec({ scenario: { cases: [makeCase({ criteria: { assert: 'eval-js' } })] } })
  assert.equal(validateRunSpecV1(badAssert).ok, false)
  const badField = makeRunSpec({ scenario: { cases: [makeCase({ criteria: { assert: 'equals', expected: 1, code: 'x' } })] } })
  assert.equal(validateRunSpecV1(badField).ok, false)
  const noAssert = makeRunSpec({ scenario: { cases: [makeCase({ criteria: { expected: 1 } })] } })
  assert.equal(validateRunSpecV1(noAssert).ok, false)
})

test('run-spec: profile_ref 可省略 digest，但字段闭集且 digest 格式受检', () => {
  assert.equal(validateRunSpecV1(makeRunSpec({ profile_ref: { id: 'smoke', version: '1.0.0' } })).ok, true)
  assert.equal(validateRunSpecV1(makeRunSpec({ profile_ref: { id: 'smoke', version: '1.0.0', digest: 'sha256:bad' } })).ok, false)
  assert.equal(validateRunSpecV1(makeRunSpec({ profile_ref: { id: 'smoke', version: '1.0.0', unknown: 1 } })).ok, false)
  assert.equal(validateRunSpecV1(makeRunSpec({ profile_ref: null })).ok, true)
})

test('run-spec: policy 未知字段拒绝；preapproved_waivers 必须为字符串数组', () => {
  assert.equal(validateRunSpecV1(makeRunSpec({ policy: { extra: 1 } })).ok, false)
  assert.equal(validateRunSpecV1(makeRunSpec({ policy: { preapproved_waivers: [1] } })).ok, false)
  assert.equal(validateRunSpecV1(makeRunSpec({ policy: { preapproved_waivers: ['t1', 't1'] } })).ok, false)
})

test('run-spec: not_applicable_when 只接受已登记的观测枚举', () => {
  assert.equal(validateRunSpecV1(makeRunSpec({ scenario: { cases: [makeCase({ not_applicable_when: { observed: 'unknown' } })] } })).ok, true)
  assert.equal(validateRunSpecV1(makeRunSpec({ scenario: { cases: [makeCase({ not_applicable_when: { observed: 'maybe' } })] } })).ok, false)
  assert.equal(validateRunSpecV1(makeRunSpec({ scenario: { cases: [makeCase({ not_applicable_when: { observed: 'absent', verification: 'contradicted' } })] } })).ok, false)
})

test('run-spec: schema 顶层 additionalProperties=false', () => {
  assert.equal(RUN_SPEC_V1_SCHEMA.additionalProperties, false)
  const checked = validateValue({ ...makeRunSpec(), injected: true }, RUN_SPEC_V1_SCHEMA)
  assert.equal(checked.ok, false)
  assert.ok(checked.errors.includes('additional-properties-not-allowed:injected'))
})
