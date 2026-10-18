/** executeFrozenPlan + response adoption tests (control/execute.js). */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { compilePlanCandidate, freezePlan } from '../../../src/control/plan.js'
import { buildToolRequest, executeFrozenPlan } from '../../../src/control/execute.js'
import { reconcileAdoptedAttempts } from '../../../src/control/reconcile.js'
import { RUN_BUDGET_VERSION, PLATFORM_BUDGET_CEILINGS } from '../../../src/control/budget.js'

const sha = (c) => 'sha256:' + c.repeat(64)

function criteria(expected = 200) {
  return { assert: 'equals', path: 'status_code', expected }
}

function makeCase(testId, overrides = {}) {
  return {
    test_id: testId,
    node_id: testId,
    classification: 'required',
    criteria: criteria(),
    probe: { value: { status_code: 200 } },
    ...overrides,
  }
}

function frozenPlan(cases, options = {}) {
  const compiled = compilePlanCandidate(cases)
  assert.equal(compiled.ok, true, JSON.stringify(compiled.errors))
  return freezePlan(compiled.candidate, options)
}

function manifest(overrides = {}) {
  return {
    schema_version: 'test-tool-manifest/v1',
    tool_id: 'echo-tool',
    tool_version: '1.0.0',
    artifact_digest: sha('a'),
    role: 'probe',
    tags: ['unit'],
    runner: { adapter: 'local-worker-json', entrypoint: 'run' },
    input_schema: { type: 'object', properties: { value: { type: 'number' } }, required: ['value'] },
    observation_schema: {
      type: 'object',
      properties: { status_code: { type: 'integer' } },
      required: ['status_code'],
      additionalProperties: false,
    },
    requires: [],
    permissions: { filesystem: [], network: [], subprocess: [], devices: [], secrets: [] },
    limits: {
      timeout_ms: 1000, cpu_ms: 1000, memory_mb: 64, temp_bytes: 1024,
      output_bytes: 1024, attachment_bytes: 1024, processes: 1, concurrency: 1,
    },
    determinism: 'deterministic',
    retry: { safe: false, max_attempts: 1 },
    ...overrides,
  }
}

function toolCase(testId, overrides = {}) {
  return {
    test_id: testId,
    node_id: testId,
    classification: 'required',
    criteria: criteria(),
    tool: { manifest: manifest(), input: { value: 1 } },
    ...overrides,
  }
}

function outcomeFor(request, overrides = {}) {
  return {
    protocol_version: 'test-tool/v1',
    request_id: request.request_id,
    run_id: request.run_id,
    plan_id: request.plan_id,
    test_id: request.test_id,
    attempt: request.attempt,
    admission_status: 'accepted',
    execution_status: 'completed',
    observations: [{
      observation_id: 'obs-1',
      schema_ref: 'schema/observation/v1',
      value: { status_code: 200 },
      source: 'worker',
      limitations: [],
    }],
    ...overrides,
  }
}

function fakePort(handler) {
  const calls = []
  return {
    calls,
    async dispatchToolRequest(request, signal) {
      calls.push(request)
      return handler(request, calls.length, signal)
    },
  }
}

test('execute: dispatches frozen expected items in stable topo order', async () => {
  const frozen = frozenPlan([makeCase('b', { needs: ['a'] }), makeCase('a')])
  const port = fakePort((request) => outcomeFor(request))
  const result = await executeFrozenPlan(frozen, port)
  assert.deepEqual(port.calls.map((call) => call.test_id), ['a', 'b'])
  assert.equal(result.recordsByTestId.a.verdict, 'pass')
  assert.equal(result.recordsByTestId.b.verdict, 'pass')
  assert.equal(result.adoptedAttempts.length, 2)
})

test('execute: retries append attempts and never overwrite prior history', async () => {
  const frozen = frozenPlan([makeCase('a', { retry: { safe: true, max_attempts: 3 } })])
  const port = fakePort((request, count) => outcomeFor(request, count === 1
    ? { observations: [{ observation_id: 'obs-1', source: 'worker', value: { status_code: 500 }, limitations: [] }] }
    : {}))
  const result = await executeFrozenPlan(frozen, port)
  const record = result.recordsByTestId.a
  assert.equal(record.attempts.length, 2)
  assert.equal(record.attempts[0].verdict, 'fail')
  assert.equal(record.attempts[1].verdict, 'pass')
  assert.equal(record.verdict, 'pass')
})

test('execute: worker-supplied verdict/gate/required fields are rejected, not adopted', async () => {
  const frozen = frozenPlan([makeCase('a')])
  for (const field of ['verdict', 'gate_decision', 'required', 'expected', 'plan']) {
    const port = fakePort((request) => outcomeFor(request, { [field]: field === 'verdict' ? 'pass' : 'x' }))
    const result = await executeFrozenPlan(frozen, port)
    const record = result.recordsByTestId.a
    assert.equal(record.verdict, 'error', field)
    assert.ok(record.reason_codes.includes(`worker-authority-field:${field}`), JSON.stringify(record.reason_codes))
  }
})

test('execute: correlation mismatch becomes a controlled non-pass terminal', async () => {
  const frozen = frozenPlan([makeCase('a')])
  const port = fakePort((request) => outcomeFor(request, { request_id: 'req-other' }))
  const result = await executeFrozenPlan(frozen, port)
  assert.equal(result.recordsByTestId.a.verdict, 'error')
  assert.ok(result.recordsByTestId.a.reason_codes.includes('correlation-mismatch'))
})

test('execute: worker self-reported started_at is ignored without adapter evidence', async () => {
  const frozen = frozenPlan([makeCase('a')])
  const port = fakePort((request) => outcomeFor(request, { started_at: '2026-01-01T00:00:00.000Z' }))
  const result = await executeFrozenPlan(frozen, port)
  const attempt = result.recordsByTestId.a.attempts[0]
  assert.equal(attempt.invocation_status, 'unknown')
  assert.equal(attempt.invocation_evidence_verified, false)
  assert.equal(attempt.started_at, undefined)
})

test('execute: adapter-attested start evidence writes started; untrusted sources stay unknown', async () => {
  const frozen = frozenPlan([makeCase('a')])
  const verifiedPort = fakePort((request) => outcomeFor(request, {
    invocation_evidence_verified: true,
    invocation_evidence: {
      source: 'adapter-lifecycle',
      request_id: request.request_id,
      run_id: request.run_id,
      plan_id: request.plan_id,
      test_id: request.test_id,
      attempt: request.attempt,
      started_at: '2026-01-01T00:00:00.000Z',
    },
  }))
  const verified = await executeFrozenPlan(frozen, verifiedPort)
  assert.equal(verified.recordsByTestId.a.invocation_status, 'started')
  assert.equal(verified.recordsByTestId.a.invocation_evidence_verified, true)
  assert.equal(verified.recordsByTestId.a.attempts[0].started_at, '2026-01-01T00:00:00.000Z')

  const untrustedPort = fakePort((request) => outcomeFor(request, {
    invocation_evidence_verified: true,
    invocation_evidence: { source: 'worker', request_id: request.request_id },
  }))
  const untrusted = await executeFrozenPlan(frozen, untrustedPort)
  assert.equal(untrusted.recordsByTestId.a.invocation_status, 'unknown')
  assert.ok(untrusted.recordsByTestId.a.reason_codes.includes('invocation-evidence-source-untrusted'))
})

test('execute: cases with no observation producer are rejected before dispatch', async () => {
  const frozen = frozenPlan([makeCase('a', { probe: undefined })])
  const port = fakePort((request) => outcomeFor(request))
  const result = await executeFrozenPlan(frozen, port)
  assert.equal(port.calls.length, 0)
  const record = result.recordsByTestId.a
  assert.equal(record.admission_status, 'rejected')
  assert.equal(record.execution_status, 'skipped')
  assert.equal(record.verdict, 'skip')
  assert.equal(record.invocation_status, 'not-started')
  assert.ok(record.reason_codes.includes('no-observation-producer'))
})

test('execute: caller-supplied admission on a candidate is stripped and never authoritative', async () => {
  const cases = [makeCase('a', { admission: 'rejected' })]
  const candidate = {
    cases,
    testIds: ['a'],
    baselineTestIds: ['a'],
    requiredTestIds: ['a'],
    topoOrder: ['a'],
    testOrder: ['a'],
  }
  const frozen = freezePlan(candidate)
  assert.ok(frozen.mutationDiagnostics.some((d) => d.reason === 'case-authority-field-stripped:admission'))
  assert.equal(Object.hasOwn(frozen.testCases[0], 'admission'), false)
  const port = fakePort((request) => outcomeFor(request))
  const result = await executeFrozenPlan(frozen, port)
  assert.equal(port.calls.length, 1)
  assert.equal(result.recordsByTestId.a.admission_status, 'accepted')
  assert.equal(result.recordsByTestId.a.verdict, 'pass')
})

test('execute: aggregate budget exhaustion is a control admission rejection', async () => {
  const frozen = frozenPlan([makeCase('a'), makeCase('b')])
  const budget = { schema_version: RUN_BUDGET_VERSION, ...PLATFORM_BUDGET_CEILINGS, max_total_attempts: 1 }
  const port = fakePort((request) => outcomeFor(request))
  const result = await executeFrozenPlan(frozen, port, { budget })
  assert.equal(port.calls.length, 1)
  assert.equal(result.budget_exceeded, 'budget_exhausted')
  assert.equal(result.recordsByTestId.a.verdict, 'pass')
  assert.equal(result.recordsByTestId.b.admission_status, 'rejected')
  assert.ok(result.recordsByTestId.b.reason_codes.includes('budget_exhausted'))
})

test('execute: cancellation before dispatch stops without fabricated terminals', async () => {
  const frozen = frozenPlan([makeCase('a')])
  const controller = new AbortController()
  controller.abort()
  const port = fakePort((request) => outcomeFor(request))
  const result = await executeFrozenPlan(frozen, port, { signal: controller.signal })
  assert.equal(result.cancelled, true)
  assert.equal(port.calls.length, 0)
  assert.equal(Object.keys(result.recordsByTestId).length, 0)
})

test('execute: control-measured deadline overrun becomes timeout/error, not pass', async () => {
  const frozen = frozenPlan([makeCase('a')])
  let now = 0
  const port = fakePort((request) => {
    now += 100
    return outcomeFor(request)
  })
  const result = await executeFrozenPlan(frozen, port, { now: () => now, timeoutMs: 50 })
  const record = result.recordsByTestId.a
  assert.equal(record.execution_status, 'timeout')
  assert.equal(record.verdict, 'error')
  assert.ok(record.reason_codes.includes('deadline-exceeded'))
})

test('execute: adapter-local rejection is recorded as rejected/skipped/skip/not-started', async () => {
  const frozen = frozenPlan([makeCase('a')])
  const port = fakePort((request) => outcomeFor(request, {
    admission_status: 'rejected',
    reason_codes: ['adapter-refused'],
  }))
  const result = await executeFrozenPlan(frozen, port)
  const attempt = result.recordsByTestId.a.attempts[0]
  assert.equal(attempt.admission_status, 'rejected')
  assert.equal(attempt.execution_status, 'skipped')
  assert.equal(attempt.verdict, 'skip')
  assert.equal(attempt.invocation_status, 'not-started')
  assert.ok(attempt.reason_codes.includes('adapter-refused'))
})

test('execute: tool request carries correlation, pinned tool_ref, target and snapshot ref', () => {
  const frozen = frozenPlan([toolCase('tool.a')])
  const request = buildToolRequest(frozen, frozen.testCases[0], 2, {
    runId: 'run-1',
    toolBindings: { 'tool.a': { toolRef: { tool_id: 'echo-tool', version: '1.0.0', artifact_digest: sha('a') } } },
    targetRef: { kind: 'plugin', owner_put_digest: sha('c'), origin: 'trusted' },
    timeoutMs: 1000,
    now: () => 0,
  })
  assert.equal(request.request_id, 'req-run-1-tool.a-2')
  assert.equal(request.plan_id, frozen.plan_id)
  assert.equal(request.attempt, 2)
  assert.equal(request.tool_ref.artifact_digest, sha('a'))
  assert.equal(request.target_ref.owner_put_digest, sha('c'))
  assert.equal(request.deadline, '1970-01-01T00:00:01.000Z')
})

test('execute: tool observation schema and pinned binding are enforced', async () => {
  const frozen = frozenPlan([toolCase('tool.a')])
  const context = {
    toolBindings: { 'tool.a': { toolRef: { tool_id: 'echo-tool', version: '1.0.0', artifact_digest: sha('a') } } },
    targetRef: { kind: 'plugin', owner_put_digest: sha('c'), origin: 'trusted' },
  }
  const invalid = fakePort((request) => outcomeFor(request, {
    observations: [{ observation_id: 'obs-1', source: 'worker', value: { status_code: 'nope' }, limitations: [] }],
  }))
  const invalidResult = await executeFrozenPlan(frozen, invalid, context)
  assert.equal(invalidResult.recordsByTestId['tool.a'].verdict, 'error')
  assert.ok(invalidResult.recordsByTestId['tool.a'].reason_codes.includes('observation-schema-invalid'))

  const unpinned = fakePort((request) => outcomeFor(request))
  const unpinnedResult = await executeFrozenPlan(frozen, unpinned, { targetRef: context.targetRef })
  assert.equal(unpinned.calls.length, 0)
  assert.equal(unpinnedResult.recordsByTestId['tool.a'].admission_status, 'rejected')
  assert.ok(unpinnedResult.recordsByTestId['tool.a'].reason_codes.includes('tool-ref-unpinned'))

  const toolRefMismatch = fakePort((request) => outcomeFor(request, {
    tool_ref: { ...request.tool_ref, artifact_digest: sha('b') },
  }))
  const mismatchResult = await executeFrozenPlan(frozen, toolRefMismatch, context)
  assert.equal(mismatchResult.recordsByTestId['tool.a'].verdict, 'error')
  assert.ok(mismatchResult.recordsByTestId['tool.a'].reason_codes.includes('tool-ref-mismatch'))

  const badArtifact = fakePort((request) => outcomeFor(request, {
    artifact_refs: [{ kind: 'log', digest: 'not-a-digest', size_bytes: 10 }],
  }))
  const artifactResult = await executeFrozenPlan(frozen, badArtifact, context)
  assert.equal(artifactResult.recordsByTestId['tool.a'].verdict, 'error')
  assert.ok(artifactResult.recordsByTestId['tool.a'].reason_codes.includes('artifact-ref-invalid'))
})

test('execute: a throwing/invalid dispatch port yields a controlled error terminal', async () => {
  const frozen = frozenPlan([makeCase('a')])
  const throwing = { async dispatchToolRequest() { throw new Error('boom') } }
  const result = await executeFrozenPlan(frozen, throwing)
  const record = result.recordsByTestId.a
  assert.equal(record.execution_status, 'error')
  assert.equal(record.verdict, 'error')
  assert.ok(record.reason_codes.includes('dispatch-error'))

  const invalid = { async dispatchToolRequest() { return null } }
  const invalidResult = await executeFrozenPlan(frozen, invalid)
  assert.equal(invalidResult.recordsByTestId.a.verdict, 'error')
  assert.ok(invalidResult.recordsByTestId.a.reason_codes.includes('invalid-response'))
})

test('execute: unknown assertion code in a frozen case fails closed (never pass)', async () => {
  const candidate = {
    cases: [{
      test_id: 'a', node_id: 'a', classification: 'required',
      criteria: { assert: 'evil-code', source: 'user' },
      probe: { value: 1 },
    }],
    testIds: ['a'], baselineTestIds: ['a'], requiredTestIds: ['a'],
    topoOrder: ['a'], testOrder: ['a'],
  }
  const frozen = freezePlan(candidate)
  const port = fakePort((request) => outcomeFor(request, {
    observations: [{ observation_id: 'obs-1', source: 'worker', value: 1, limitations: [] }],
  }))
  const result = await executeFrozenPlan(frozen, port)
  assert.equal(result.recordsByTestId.a.verdict, 'fail')
  assert.ok(result.recordsByTestId.a.reason_codes.includes('unknown-assertion'))
})

test('execute: adopted attempts reconcile independently from the frozen plan', async () => {
  const frozen = frozenPlan([makeCase('a'), makeCase('b')])
  const port = fakePort((request) => outcomeFor(request))
  const result = await executeFrozenPlan(frozen, port)
  const reconciliation = reconcileAdoptedAttempts(frozen, result.adoptedAttempts)
  assert.deepEqual(reconciliation.expected, ['a', 'b'])
  assert.deepEqual(reconciliation.executed, ['a', 'b'])
  assert.deepEqual(reconciliation.missing, [])
  assert.deepEqual(reconciliation.missing_required, [])
})
