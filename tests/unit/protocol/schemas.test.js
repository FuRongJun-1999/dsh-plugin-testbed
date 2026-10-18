/**
 * 单元 · protocol schema registry / version boundaries（node:test）。
 *
 * 覆盖 implementation-design-protocol §1、§7、§8.2 与 development-plan
 * 「版本边界」：每个工件独立演进、未知主版本拒绝、schema 固定 Draft 2020-12、
 * `$id` 命名空间稳定、注册表只解析精确版本。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  GATE_POLICY_VERSION,
  KNOWN_SCHEMA_VERSIONS,
  PLAN_CANDIDATE_VERSION,
  PLAN_VERSION,
  RECEIPT_SCHEMA_VERSION,
  RUN_SPEC_VERSION,
  TEST_TOOL_MANIFEST_VERSION,
  TEST_TOOL_PROTOCOL_VERSION,
} from '../../../src/protocol/enums.js'
import {
  GATE_POLICY_V1_SCHEMA,
  PLAN_CANDIDATE_V1_SCHEMA,
  PLAN_V1_SCHEMA,
  RECEIPT_V1_SCHEMA,
  RUN_SPEC_V1_SCHEMA,
  SCHEMA_BY_VERSION,
  TEST_TOOL_MANIFEST_V1_SCHEMA,
  TEST_TOOL_REQUEST_V1_SCHEMA,
  TEST_TOOL_RESPONSE_V1_SCHEMA,
  TEST_TOOL_V1_SCHEMAS,
  isGatePolicyVersion,
  isPlanCandidateVersion,
  isPlanVersion,
  isReceiptSchemaVersion,
  isRunSpecVersion,
  isTestToolManifestVersion,
  isTestToolProtocolVersion,
  schemaForVersion,
} from '../../../src/protocol/schemas.js'
import { JSON_SCHEMA_DRAFT_2020_12, validateSchemaMeta } from '../../../src/protocol/jsonschema.js'

const SINGLE_DOCUMENT_SCHEMAS = [
  [RECEIPT_SCHEMA_VERSION, RECEIPT_V1_SCHEMA, 'receipt_schema_version'],
  [RUN_SPEC_VERSION, RUN_SPEC_V1_SCHEMA, 'schema_version'],
  [GATE_POLICY_VERSION, GATE_POLICY_V1_SCHEMA, 'schema_version'],
  [PLAN_CANDIDATE_VERSION, PLAN_CANDIDATE_V1_SCHEMA, 'schema_version'],
  [PLAN_VERSION, PLAN_V1_SCHEMA, 'schema_version'],
  [TEST_TOOL_MANIFEST_VERSION, TEST_TOOL_MANIFEST_V1_SCHEMA, 'schema_version'],
]

test('schema registry: 六个单文档工件全部登记，版本列表与注册表一致', () => {
  assert.deepEqual(Object.keys(SCHEMA_BY_VERSION).sort(), [
    GATE_POLICY_VERSION,
    PLAN_CANDIDATE_VERSION,
    PLAN_VERSION,
    RECEIPT_SCHEMA_VERSION,
    RUN_SPEC_VERSION,
    TEST_TOOL_MANIFEST_VERSION,
  ])
  assert.deepEqual([...KNOWN_SCHEMA_VERSIONS].sort(), Object.keys(SCHEMA_BY_VERSION).sort())
  assert.deepEqual(Object.keys(TEST_TOOL_V1_SCHEMAS).sort(), ['request', 'response'])
})

test('schema registry: 每个 schema 是合法 Draft 2020-12 元结构且 $id 命名空间固定', () => {
  for (const [version, schema] of [
    ...SINGLE_DOCUMENT_SCHEMAS.map(([v, s]) => [v, s]),
    [TEST_TOOL_PROTOCOL_VERSION + '#request', TEST_TOOL_REQUEST_V1_SCHEMA],
    [TEST_TOOL_PROTOCOL_VERSION + '#response', TEST_TOOL_RESPONSE_V1_SCHEMA],
  ]) {
    assert.equal(schema.$schema, JSON_SCHEMA_DRAFT_2020_12, version)
    assert.ok(schema.$id.startsWith('urn:dsh:plugin-testbed:'), `${version}: ${schema.$id}`)
    const meta = validateSchemaMeta(schema)
    assert.equal(meta.ok, true, `${version}: ${JSON.stringify(meta.errors)}`)
    assert.equal(Object.isFrozen(schema), true, `${version} schema must be immutable`)
  }
})

test('schema registry: 每个 schema 的版本常量与其注册键一致', () => {
  for (const [version, schema, versionField] of SINGLE_DOCUMENT_SCHEMAS) {
    assert.equal(schema.properties[versionField].const, version, version)
  }
  assert.equal(TEST_TOOL_REQUEST_V1_SCHEMA.properties.protocol_version.const, TEST_TOOL_PROTOCOL_VERSION)
  assert.equal(TEST_TOOL_RESPONSE_V1_SCHEMA.properties.protocol_version.const, TEST_TOOL_PROTOCOL_VERSION)
})

test('schema registry: schemaForVersion 只解析精确版本，未知主版本返回 null', () => {
  for (const [version, schema] of SINGLE_DOCUMENT_SCHEMAS.map(([v, s]) => [v, s])) {
    assert.equal(schemaForVersion(version), schema, version)
  }
  for (const unknown of ['receipt/v2', 'run-spec/v2', 'gate-policy/v2', 'plan-candidate/v2', 'plan/v2', 'test-tool-manifest/v2', '', null, 1, 'receipt/v1 ']) {
    assert.equal(schemaForVersion(unknown), null, String(unknown))
  }
})

test('version guards: v1 精确匹配，v2/变体/垃圾值全部拒绝（不隐式降级）', () => {
  const table = [
    [isReceiptSchemaVersion, RECEIPT_SCHEMA_VERSION, ['receipt/v2', 'receipt/v1.0', 'receipt/v01', 'receipt', 'RECEIPT/V1']],
    [isRunSpecVersion, RUN_SPEC_VERSION, ['run-spec/v2', 'run-spec/v1.0', 'run-spec', 'runspec/v1']],
    [isGatePolicyVersion, GATE_POLICY_VERSION, ['gate-policy/v2', 'gate-policy/v1.0', 'gatepolicy/v1']],
    [isPlanCandidateVersion, PLAN_CANDIDATE_VERSION, ['plan-candidate/v2', 'plan-candidate/v1.0', 'plan-candidate']],
    [isPlanVersion, PLAN_VERSION, ['plan/v2', 'plan/v1.0', 'plan', 'plans/v1']],
    [isTestToolManifestVersion, TEST_TOOL_MANIFEST_VERSION, ['test-tool-manifest/v2', 'test-tool/v1', 'test-tool-manifest']],
    [isTestToolProtocolVersion, TEST_TOOL_PROTOCOL_VERSION, ['test-tool/v2', 'test-tool-manifest/v1', 'test-tool']],
  ]
  for (const [guard, known, unknowns] of table) {
    assert.equal(guard(known), true, known)
    for (const value of unknowns) assert.equal(guard(value), false, `${guard.name}(${value})`)
    for (const value of [null, undefined, 1, {}, []]) assert.equal(guard(value), false, `${guard.name}(${String(value)})`)
  }
})

test('schema registry: 除 manifest 可带命名空间扩展外，单文档 schema 顶层封闭', () => {
  for (const [, schema, versionField] of SINGLE_DOCUMENT_SCHEMAS) {
    if (schema === TEST_TOOL_MANIFEST_V1_SCHEMA) {
      // §8.4.1 allows namespaced extensions; the executable validator warns.
      assert.equal(schema.additionalProperties, true)
      continue
    }
    assert.equal(schema.additionalProperties, false, versionField)
  }
  assert.equal(TEST_TOOL_REQUEST_V1_SCHEMA.additionalProperties, false)
  assert.equal(TEST_TOOL_RESPONSE_V1_SCHEMA.additionalProperties, false)
})

test('receipt schema: 恒在字段 + 三种形态分支齐备', () => {
  const required = [...RECEIPT_V1_SCHEMA.required].sort()
  assert.deepEqual(required, [
    'artifacts', 'gate_decision', 'integrity', 'limitations', 'market_eligible',
    'observations', 'plan_candidate_ref', 'plan_id', 'plan_resolution', 'profile_ref',
    'provenance', 'receipt_schema_version', 'reconciliation', 'run_id', 'run_status',
    'scenario_ref', 'target_ref', 'test_cases', 'trust_scope',
  ])
  assert.equal(RECEIPT_V1_SCHEMA.properties.market_eligible.const, false)
  assert.equal(RECEIPT_V1_SCHEMA.properties.trust_scope.const, 'local-only')
  assert.equal(RECEIPT_V1_SCHEMA.properties.integrity.properties.signed.const, false)
  assert.equal(RECEIPT_V1_SCHEMA.oneOf.length, 3)
})
