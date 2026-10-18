/** Static scenario-graph compiler tests (control/graph.js). */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  compileScenarioGraph,
  schemasCompatible,
  SUPPORTED_NODE_TYPES,
} from '../../../src/control/graph.js'
import { RUN_BUDGET_VERSION, PLATFORM_BUDGET_CEILINGS } from '../../../src/control/budget.js'

const sha = (c) => 'sha256:' + c.repeat(64)

function manifest(overrides = {}) {
  return {
    schema_version: 'test-tool-manifest/v1',
    tool_id: 'probe-tool',
    tool_version: '1.0.0',
    artifact_digest: sha('a'),
    role: 'probe',
    tags: ['unit'],
    runner: { adapter: 'local-worker-json', entrypoint: 'run' },
    input_schema: {
      type: 'object',
      properties: { x: { type: 'number' } },
      required: ['x'],
      additionalProperties: false,
    },
    observation_schema: {
      type: 'object',
      properties: { status_code: { type: 'integer' }, body: { type: 'string' } },
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

function toolNode(nodeId, overrides = {}) {
  return {
    type: 'ToolTask',
    node_id: nodeId,
    test_id: nodeId,
    classification: 'required',
    tool: { manifest: manifest(), input: { x: 1 } },
    ...overrides,
  }
}

function assertNode(nodeId, overrides = {}) {
  return {
    type: 'AssertTask',
    node_id: nodeId,
    test_id: nodeId,
    classification: 'required',
    criteria: { assert: 'equals', expected: 200 },
    inputs: { value: { from: 'probe', output: 'observation' } },
    ...overrides,
  }
}

function fixtureNode(nodeId = 'fixture', overrides = {}) {
  return {
    type: 'Fixture',
    node_id: nodeId,
    fixture_ref: { id: 'login', version: '1.0.0', digest: sha('b') },
    outputs: { token: { type: 'string' } },
    ...overrides,
  }
}

test('graph: supported node vocabulary is exactly ToolTask/AssertTask/Fixture/Target', () => {
  assert.deepEqual([...SUPPORTED_NODE_TYPES], ['ToolTask', 'AssertTask', 'Fixture', 'Target'])
})

test('graph: valid graph produces a deterministic topo order and non-removable baseline', () => {
  const scenario = {
    nodes: [
      assertNode('assert', { inputs: { value: { from: 'probe', output: 'observation' } } }),
      toolNode('probe'),
      fixtureNode(),
    ],
  }
  const result = compileScenarioGraph(scenario)
  assert.equal(result.ok, true, JSON.stringify(result.errors))
  assert.deepEqual(result.candidate.topoOrder, ['fixture', 'probe', 'assert'])
  assert.deepEqual(result.candidate.testIds, ['probe', 'assert'])
  assert.deepEqual(result.candidate.requiredTestIds, ['probe', 'assert'])
  assert.equal(result.candidate.dataEdges.length, 1)
})

test('graph: ready-layer tie-break uses lexicographic node_id', () => {
  const result = compileScenarioGraph({ nodes: [toolNode('n9'), toolNode('n2'), toolNode('n1')] })
  assert.equal(result.ok, true)
  assert.deepEqual(result.candidate.topoOrder, ['n1', 'n2', 'n9'])
})

test('graph: duplicate node/test IDs and unsupported node types reject', () => {
  const duplicateNode = compileScenarioGraph({ nodes: [toolNode('dup', { test_id: 'a' }), toolNode('dup', { test_id: 'b' })] })
  assert.ok(duplicateNode.errors.includes('duplicate_id:node:dup'))

  const duplicateTest = compileScenarioGraph({ nodes: [toolNode('n1', { test_id: 'same' }), toolNode('n2', { test_id: 'same' })] })
  assert.ok(duplicateTest.errors.includes('duplicate_id:test:same'))

  const unsupported = compileScenarioGraph({ nodes: [{ type: 'ShellTask', node_id: 'n1' }] })
  assert.ok(unsupported.errors.some((e) => e.startsWith('unsupported_node:ShellTask')))

  const unknownField = compileScenarioGraph({ nodes: [toolNode('n1', { shell: 'rm -rf /' })] })
  assert.ok(unknownField.errors.some((e) => e.includes('unsupported_node-field:n1:shell')))
})

test('graph: unresolved needs and cycles reject', () => {
  const unresolved = compileScenarioGraph({ nodes: [toolNode('n1', { needs: ['ghost'] })] })
  assert.ok(unresolved.errors.includes('reference_unresolved:n1->ghost'))

  const cycle = compileScenarioGraph({
    nodes: [toolNode('n1', { needs: ['n2'] }), toolNode('n2', { needs: ['n1'] })],
  })
  assert.ok(cycle.errors.includes('cycle'))
})

test('graph: needs is ordering only; data dependencies must be explicit and bound', () => {
  const unbound = compileScenarioGraph({
    nodes: [toolNode('probe'), assertNode('assert', { inputs: { value: { from: 'probe', output: 'missing_output' } } })],
  })
  assert.ok(unbound.errors.includes('unbound_input:assert:value'))

  const missingProducer = compileScenarioGraph({
    nodes: [assertNode('assert', { inputs: { value: { from: 'ghost', output: 'observation' } } })],
  })
  assert.ok(missingProducer.errors.includes('reference_unresolved:assert->ghost'))

  const noInputs = compileScenarioGraph({
    nodes: [toolNode('probe'), assertNode('assert', { inputs: {} })],
  })
  assert.ok(noInputs.errors.includes('unbound_input:assert:value'))
})

test('graph: needs alone does not satisfy an AssertTask input binding', () => {
  const scenario = {
    nodes: [
      toolNode('probe'),
      assertNode('assert', { needs: ['probe'], inputs: { value: { from: 'probe', output: 'observation' } } }),
    ],
  }
  const result = compileScenarioGraph(scenario)
  assert.equal(result.ok, true)
  assert.deepEqual(result.candidate.dataEdges, [{ from: 'probe', output: 'observation', to: 'assert', input: 'value' }])
})

test('graph: incompatible input/output schemas reject', () => {
  const incompatible = compileScenarioGraph({
    nodes: [
      toolNode('probe'),
      assertNode('assert', {
        inputs: { value: { from: 'probe', output: 'observation', schema: { type: 'string' } } },
      }),
    ],
  })
  assert.ok(incompatible.errors.includes('schema_incompatible:assert:value'))

  const compatible = compileScenarioGraph({
    nodes: [
      toolNode('probe'),
      assertNode('assert', {
        inputs: {
          value: {
            from: 'probe',
            output: 'observation',
            schema: {
              type: 'object',
              properties: { status_code: { type: 'integer' } },
              required: ['status_code'],
            },
          },
        },
      }),
    ],
  })
  assert.equal(compatible.ok, true, JSON.stringify(compatible.errors))
})

test('graph: schemasCompatible is conservative about contradictory declarations', () => {
  assert.equal(schemasCompatible(undefined, { type: 'string' }), true)
  assert.equal(schemasCompatible({ type: 'string' }, { type: 'number' }), false)
  assert.equal(schemasCompatible({ type: ['string', 'null'] }, { type: 'string' }), true)
  assert.equal(schemasCompatible({ type: 'string' }, { type: ['string', 'null'] }), false)
  assert.equal(schemasCompatible({ const: 'a' }, { const: 'b' }), false)
  assert.equal(schemasCompatible({ enum: ['a', 'b'] }, { enum: ['a'] }), true)
  assert.equal(
    schemasCompatible(
      { type: 'object', properties: { a: { type: 'string' } }, required: ['a'] },
      { type: 'object', properties: { a: { type: 'number' } }, required: ['a'] },
    ),
    false,
  )
})

test('graph: permission requests must be a subset of the policy grant', () => {
  const node = toolNode('probe', {
    tool: {
      manifest: manifest({ permissions: { filesystem: ['workspace:read'], network: [], subprocess: [], devices: [], secrets: [] } }),
      input: { x: 1 },
    },
  })
  const denied = compileScenarioGraph({ nodes: [node] }, {
    authorization: { granted_permissions: { filesystem: [], network: [], subprocess: [], devices: [], secrets: [] } },
  })
  assert.ok(denied.errors.includes('permission_denied:probe:filesystem:workspace:read'))

  const granted = compileScenarioGraph({ nodes: [node] }, {
    authorization: { granted_permissions: { filesystem: ['workspace:read'], network: [], subprocess: [], devices: [], secrets: [] } },
  })
  assert.equal(granted.ok, true, JSON.stringify(granted.errors))
})

test('graph: target ownership mismatch is rejected', () => {
  const node = toolNode('probe', {
    target_ref: { kind: 'plugin', owner_put_digest: sha('b'), origin: 'x' },
  })
  const result = compileScenarioGraph({ nodes: [node] }, {
    target: { kind: 'plugin', put_digest: sha('a'), origin: 'trusted' },
  })
  assert.ok(result.errors.includes('ownership_mismatch:probe'))
})

test('graph: cross-domain data references are rejected', () => {
  const result = compileScenarioGraph({
    nodes: [
      toolNode('probe', { domain: 'trusted' }),
      assertNode('assert', { domain: 'untrusted', inputs: { value: { from: 'probe', output: 'observation' } } }),
    ],
  })
  assert.ok(result.errors.includes('cross_domain_ref:probe->assert'))
})

test('graph: aggregate and per-node budgets are enforced', () => {
  const budget = { schema_version: RUN_BUDGET_VERSION, ...PLATFORM_BUDGET_CEILINGS }
  const node = toolNode('probe')
  assert.equal(compileScenarioGraph({ nodes: [node] }, { budget }).ok, true)

  const tooManyAttempts = compileScenarioGraph({
    nodes: [toolNode('p1', { retry: { safe: true, max_attempts: 3 } }), toolNode('p2', { retry: { safe: true, max_attempts: 3 } })],
  }, { budget: { ...budget, max_total_attempts: 2 } })
  assert.ok(tooManyAttempts.errors.includes('budget_exceeded:attempts'))

  const tooMuchTime = compileScenarioGraph({ nodes: [node] }, {
    budget: { ...budget, max_total_time_ms: 500 },
  })
  assert.ok(tooMuchTime.errors.includes('budget_exceeded:timeout_ms'))

  const invalidBudget = compileScenarioGraph({ nodes: [node] }, { budget: { schema_version: RUN_BUDGET_VERSION } })
  assert.ok(invalidBudget.errors.some((e) => e.startsWith('budget-invalid:')))
})

test('graph: invalid tool manifest and input schema reject', () => {
  const badManifest = compileScenarioGraph({ nodes: [toolNode('probe', { tool: { manifest: {}, input: {} } })] })
  assert.ok(badManifest.errors.some((e) => e.startsWith('tool-manifest-invalid:')))

  const badInput = compileScenarioGraph({ nodes: [toolNode('probe', { tool: { manifest: manifest(), input: {} } })] })
  assert.ok(badInput.errors.some((e) => e.startsWith('tool-input-schema-invalid:')))
})

test('graph: floating fixture dependencies and invalid target refs reject', () => {
  const floating = compileScenarioGraph({ nodes: [fixtureNode('fixture', {
    fixture_ref: { id: 'login', version: 'latest', digest: sha('b') },
  })] })
  assert.ok(floating.errors.includes('floating_ref:fixture'))

  const missingDigest = compileScenarioGraph({ nodes: [fixtureNode('fixture', {
    fixture_ref: { id: 'login', version: '1.0.0' },
  })] })
  assert.ok(missingDigest.errors.includes('artifact_unresolved:fixture'))

  const badTarget = compileScenarioGraph({ nodes: [{
    type: 'Target', node_id: 'target', target_ref: { kind: 'plugin', owner_put_digest: 'not-a-digest' },
  }] })
  assert.ok(badTarget.errors.includes('unauthorized_target:target'))
})

test('graph: candidate count is bounded without truncation', () => {
  const tooMany = compileScenarioGraph({ nodes: Array.from({ length: 257 }, (_, i) => toolNode(`n${i}`)) })
  assert.equal(tooMany.ok, false)
  assert.ok(tooMany.errors.includes('case-count-exceeds-limit:256'))

  const empty = compileScenarioGraph({ nodes: [] })
  assert.deepEqual(empty.errors, ['scenario-nodes-empty'])
})
