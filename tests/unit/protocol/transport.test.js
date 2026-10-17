import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  CONTROL_PROTOCOL_VERSION,
  assertFrameShape,
  assertToolRequest,
  assertToolResponse,
  buildRequestFrame,
  buildToolRequestFrame,
} from '../../../src/protocol/transport.js'

const TOOL_REF = Object.freeze({
  tool_id: 'transport.fixture',
  version: '1.2.3',
  artifact_digest: `sha256:${'a'.repeat(64)}`,
})
const TARGET_REF = Object.freeze({
  kind: 'plugin',
  owner_put_digest: `sha256:${'b'.repeat(64)}`,
  origin: 'unit-test',
})
const CAPABILITY_REF = `cap-sha256:${'c'.repeat(64)}`

function makeRequest(overrides = {}) {
  return buildToolRequestFrame({
    request_id: 'req-transport',
    run_id: 'run-transport',
    plan_id: 'plan-transport',
    test_id: 'test-transport',
    attempt: 1,
    tool_ref: { ...TOOL_REF },
    target_ref: { ...TARGET_REF },
    input: { value: 1 },
    deadline: '2030-01-01T00:00:00.000Z',
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
      observation_id: 'obs-1',
      schema_ref: 'transport.fixture@1.2.3#observation_schema',
      value: { value: 1 },
      source: 'worker',
      limitations: [],
    }],
    artifact_refs: [],
    diagnostics: [],
    ...overrides,
  }
}

test('test-tool/v1 request is closed and requires valid correlation, pin and capability ref', () => {
  const request = makeRequest()
  assert.deepEqual(assertToolRequest(request), { ok: true })

  assert.equal(assertToolRequest({ ...request, unexpected: true }).reason_code, 'unknown-field')
  assert.equal(assertToolRequest({ ...request, protocol_version: CONTROL_PROTOCOL_VERSION }).reason_code, 'unknown-version')
  assert.equal(assertToolRequest({ ...request, request_id: '' }).reason_code, 'correlation-mismatch')
  assert.equal(assertToolRequest({ ...request, attempt: 0 }).reason_code, 'correlation-mismatch')
  assert.equal(assertToolRequest({ ...request, capability_snapshot_ref: 'cap-latest' }).reason_code, 'unknown-field')
})

test('ToolResponse must exactly match all five correlation fields and pinned tool_ref', () => {
  const request = makeRequest()
  assert.deepEqual(assertToolResponse(makeResponse(request), request), { ok: true })

  for (const field of ['request_id', 'run_id', 'plan_id', 'test_id', 'attempt']) {
    const response = makeResponse(request, { [field]: field === 'attempt' ? 2 : `other-${field}` })
    assert.equal(assertToolResponse(response, request).reason_code, 'correlation-mismatch', field)
  }
  for (const field of ['tool_id', 'version', 'artifact_digest']) {
    const other = field === 'artifact_digest' ? `sha256:${'d'.repeat(64)}` : `other-${field}`
    const response = makeResponse(request, { tool_ref: { ...request.tool_ref, [field]: other } })
    assert.equal(assertToolResponse(response, request).reason_code, 'correlation-mismatch', field)
  }
})

test('ToolResponse rejects malformed/extra fields and malformed observation collections', () => {
  const request = makeRequest()
  const valid = makeResponse(request)

  assert.equal(assertToolResponse({ ...valid, extra: 1 }, request).reason_code, 'unknown-field')
  assert.equal(assertToolResponse({ ...valid, execution_status: 'started' }, request).reason_code, 'unknown-field')
  assert.equal(assertToolResponse({ ...valid, observations: [{ ...valid.observations[0], source: 'caller' }] }, request).reason_code, 'unknown-field')
  assert.equal(assertToolResponse({ ...valid, observations: [valid.observations[0], valid.observations[0]] }, request).reason_code, 'duplicate')
  assert.equal(assertToolResponse({ ...valid, artifact_refs: [{ kind: 'log', digest: 'sha256:nope', size_bytes: 0 }] }, request).reason_code, 'unknown-field')
})

test('legacy control-protocol/v1 request and started frame remain accepted; extra fields remain rejected', () => {
  const request = buildRequestFrame({
    request_id: 'req-legacy', run_id: 'run-legacy', plan_id: 'plan-legacy',
    test_id: 'test-legacy', attempt: 1, input: { op: 'echo' }, deadline_ms: 1000,
  })
  assert.equal(request.protocol_version, CONTROL_PROTOCOL_VERSION)
  assert.deepEqual(assertFrameShape(request), { ok: true })
  assert.deepEqual(assertFrameShape({
    protocol_version: CONTROL_PROTOCOL_VERSION,
    kind: 'started',
    request_id: request.request_id,
    run_id: request.run_id,
    plan_id: request.plan_id,
    test_id: request.test_id,
    attempt: request.attempt,
    tool_ref: null,
  }), { ok: true })
  assert.equal(assertFrameShape({ ...request, extra: true }).reason_code, 'unknown-field')
})
