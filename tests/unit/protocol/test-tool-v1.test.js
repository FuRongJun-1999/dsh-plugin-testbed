/**
 * 单元 · protocol/test-tool/v1 声明式 envelope（node:test）。
 *
 * 覆盖 architecture §8.4.2 / implementation-design-protocol §4.4：
 * 封闭字段、版本固定、correlation tuple 回显、响应不得携带
 * verdict/GateDecision/required/expected/Plan 修改；声明式 schema 与
 * transport.js 的可执行拒绝规则保持一致。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  TEST_TOOL_REQUEST_V1_SCHEMA,
  TEST_TOOL_RESPONSE_V1_SCHEMA,
  TEST_TOOL_V1_SCHEMAS,
  TEST_TOOL_CORRELATION_FIELDS,
} from '../../../src/protocol/schemas.js'
import {
  validateTestToolRequestV1,
  validateTestToolResponseV1,
} from '../../../src/protocol/contracts.js'
import {
  assertToolRequest,
  assertToolResponse,
  buildToolRequestFrame,
} from '../../../src/protocol/transport.js'
import { validateValue } from '../../../src/protocol/jsonschema.js'

const TOOL_REF = Object.freeze({
  tool_id: 'example.api-contract',
  version: '1.0.0',
  artifact_digest: 'sha256:' + '1'.repeat(64),
})
const TARGET_REF = Object.freeze({
  kind: 'api',
  owner_put_digest: 'sha256:' + '3'.repeat(64),
  origin: 'http://127.0.0.1:4001',
})
const CAPABILITY_REF = 'cap-sha256:' + '4'.repeat(64)
const PLAN_ID = 'plan-sha256:' + '6'.repeat(64)

function makeRequest(overrides = {}) {
  return buildToolRequestFrame({
    request_id: 'req-20261016-001',
    run_id: 'run-20261016-001',
    plan_id: PLAN_ID,
    test_id: 'contract.login.schema',
    attempt: 1,
    tool_ref: { ...TOOL_REF },
    target_ref: { ...TARGET_REF },
    input: { fixture_ref: 'fixture://login/v1' },
    deadline: '2026-10-16T04:30:00Z',
    capability_snapshot_ref: CAPABILITY_REF,
    ...overrides,
  })
}

function makeResponse(request, overrides = {}) {
  return {
    protocol_version: 'test-tool/v1',
    request_id: request.request_id,
    run_id: request.run_id,
    plan_id: request.plan_id,
    test_id: request.test_id,
    attempt: request.attempt,
    tool_ref: { ...request.tool_ref },
    execution_status: 'completed',
    observations: [{
      observation_id: 'obs-001',
      schema_ref: 'urn:example:tool:api-contract:observation:v1',
      value: { status_code: 200, body: { user_id: 'fixture-user-001' } },
      source: 'worker',
      limitations: ['controlled-fixture'],
    }],
    artifact_refs: [{ kind: 'log', digest: 'sha256:' + '5'.repeat(64), size_bytes: 412 }],
    diagnostics: [],
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// ToolRequest
// ---------------------------------------------------------------------------

test('test-tool/v1: 合法 ToolRequest 同时通过声明式 schema 与 transport 校验', () => {
  const request = makeRequest()
  const schemaCheck = validateValue(request, TEST_TOOL_REQUEST_V1_SCHEMA)
  assert.equal(schemaCheck.ok, true, JSON.stringify(schemaCheck.errors))
  assert.deepEqual(validateTestToolRequestV1(request), { ok: true, errors: [] })
  assert.deepEqual(assertToolRequest(request), { ok: true })
})

test('test-tool/v1: 未知主版本 → schema 与 transport 都拒绝（不降级）', () => {
  const request = { ...makeRequest(), protocol_version: 'test-tool/v2' }
  assert.equal(validateValue(request, TEST_TOOL_REQUEST_V1_SCHEMA).ok, false)
  const result = validateTestToolRequestV1(request)
  assert.equal(result.ok, false)
  assert.ok(result.errors.includes('unknown-version:test-tool/v2'))
  assert.equal(assertToolRequest(request).reason_code, 'unknown-version')
})

test('test-tool/v1: 未知字段/缺失字段/错误枚举 → 拒绝', () => {
  const request = makeRequest()
  assert.equal(validateTestToolRequestV1({ ...request, extra: 1 }).ok, false)
  assert.equal(assertToolRequest({ ...request, extra: 1 }).reason_code, 'unknown-field')

  for (const field of ['request_id', 'run_id', 'plan_id', 'test_id', 'attempt', 'tool_ref', 'target_ref', 'input', 'deadline', 'capability_snapshot_ref']) {
    const missing = makeRequest()
    delete missing[field]
    assert.equal(validateTestToolRequestV1(missing).ok, false, field)
    assert.equal(assertToolRequest(missing).ok, false, field)
  }

  assert.equal(validateTestToolRequestV1({ ...request, attempt: 0 }).ok, false)
  assert.equal(assertToolRequest({ ...request, attempt: 0 }).ok, false)
})

test('test-tool/v1: 摘要/能力引用/deadline 格式受检', () => {
  const badToolRef = makeRequest()
  badToolRef.tool_ref.artifact_digest = 'sha256:latest'
  assert.equal(validateTestToolRequestV1(badToolRef).ok, false)
  assert.equal(assertToolRequest(badToolRef).ok, false)

  const badCap = makeRequest()
  badCap.capability_snapshot_ref = 'cap-sha256:abc'
  assert.equal(validateTestToolRequestV1(badCap).ok, false)
  assert.equal(assertToolRequest(badCap).ok, false)

  const badDeadline = { ...makeRequest(), deadline: 'tomorrow' }
  assert.equal(validateTestToolRequestV1(badDeadline).ok, false)
  assert.equal(assertToolRequest(badDeadline).ok, false)

  assert.equal(validateTestToolRequestV1({ ...makeRequest(), kind: 'request' }).ok, false)
})

// ---------------------------------------------------------------------------
// ToolResponse
// ---------------------------------------------------------------------------

test('test-tool/v1: 合法 ToolResponse 同时通过声明式 schema 与 transport 校验', () => {
  const request = makeRequest()
  const response = makeResponse(request)
  const schemaCheck = validateValue(response, TEST_TOOL_RESPONSE_V1_SCHEMA)
  assert.equal(schemaCheck.ok, true, JSON.stringify(schemaCheck.errors))
  assert.deepEqual(validateTestToolResponseV1(response), { ok: true, errors: [] })
  assert.deepEqual(assertToolResponse(response, request), { ok: true })
})

test('test-tool/v1: 响应不得携带 verdict/GateDecision/required/expected/Plan 修改', () => {
  const request = makeRequest()
  const forbidden = {
    verdict: 'pass',
    gate_decision: 'pass',
    required: ['contract.login.schema'],
    expected: ['contract.login.schema'],
    plan: {},
    plan_resolution: [],
  }
  for (const [field, value] of Object.entries(forbidden)) {
    const response = makeResponse(request, { [field]: value })
    const result = validateTestToolResponseV1(response)
    assert.equal(result.ok, false, field)
    assert.ok(result.errors.includes(`tool-response-forbidden-field:${field}`), field)
    assert.equal(assertToolResponse(response, request).reason_code, 'unknown-field', field)
  }
})

test('test-tool/v1: execution_status 采用闭集（pass 不是执行终态）', () => {
  const request = makeRequest()
  for (const status of ['completed', 'skipped', 'error', 'timeout', 'cancelled']) {
    assert.equal(validateTestToolResponseV1(makeResponse(request, { execution_status: status })).ok, true, status)
  }
  const response = makeResponse(request, { execution_status: 'pass' })
  assert.equal(validateTestToolResponseV1(response).ok, false)
  assert.equal(assertToolResponse(response, request).reason_code, 'unknown-field')
})

test('test-tool/v1: observation source 只能是 worker；schema_ref/artifact 摘要受检', () => {
  const request = makeRequest()
  const controlSource = makeResponse(request)
  controlSource.observations[0].source = 'control-plane'
  assert.equal(validateTestToolResponseV1(controlSource).ok, false)
  assert.equal(assertToolResponse(controlSource, request).ok, false)

  const noSchemaRef = makeResponse(request)
  delete noSchemaRef.observations[0].schema_ref
  assert.equal(validateTestToolResponseV1(noSchemaRef).ok, false)
  assert.equal(assertToolResponse(noSchemaRef, request).ok, false)

  const badArtifact = makeResponse(request, {
    artifact_refs: [{ kind: 'log', digest: 'sha256:nope', size_bytes: -1 }],
  })
  assert.equal(validateTestToolResponseV1(badArtifact).ok, false)
  assert.equal(assertToolResponse(badArtifact, request).ok, false)
})

test('test-tool/v1: 响应未知字段/未知版本拒绝', () => {
  const request = makeRequest()
  assert.equal(validateTestToolResponseV1(makeResponse(request, { extra: 1 })).ok, false)
  const v2 = makeResponse(request, { protocol_version: 'test-tool/v2' })
  const result = validateTestToolResponseV1(v2)
  assert.equal(result.ok, false)
  assert.ok(result.errors.includes('unknown-version:test-tool/v2'))
})

test('test-tool/v1: 两个方向的 schema 注册与 correlation tuple 公开面稳定', () => {
  assert.deepEqual(Object.keys(TEST_TOOL_V1_SCHEMAS).sort(), ['request', 'response'])
  assert.deepEqual([...TEST_TOOL_CORRELATION_FIELDS], ['request_id', 'run_id', 'plan_id', 'test_id', 'attempt'])
  assert.equal(TEST_TOOL_REQUEST_V1_SCHEMA.additionalProperties, false)
  assert.equal(TEST_TOOL_RESPONSE_V1_SCHEMA.additionalProperties, false)
})
