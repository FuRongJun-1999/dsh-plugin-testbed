/**
 * Worker tool runner tests — argv launch (no shell), minimal environment,
 * bounded/redacted observations, request boundaries and cancellation.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, writeFileSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  MAX_ARTIFACT_BYTES,
  MAX_OBSERVATION_BYTES,
  pinManifestArtifact,
  runToolRequest,
} from '../../../src/worker/runner.js'
import { buildToolRequestFrame } from '../../../src/protocol/transport.js'
import { REDACTED } from '../../../src/worker/observe.js'

const DIGEST64 = 'ab'.repeat(32)
const CAP_REF = `cap-sha256:${'cd'.repeat(32)}`
const FIXTURES = fileURLToPath(new URL('../../fixtures/', import.meta.url))
const TOOL_ECHO = join(FIXTURES, 'tool-echo-value.mjs')
const TOOL_ENV = join(FIXTURES, 'tool-read-env.mjs')
const TOOL_CWD = join(FIXTURES, 'tool-cwd.mjs')
const TOOL_SLOW = join(FIXTURES, 'tool-slow.mjs')
const TOOL_HUGE = join(FIXTURES, 'tool-huge-output.mjs')
const TOOL_SECRET = join(FIXTURES, 'tool-secret-output.mjs')

function tmpDir(t) {
  const dir = mkdtempSync(join(tmpdir(), 'testbed-runner-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function digestOf(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`
}

function writeArtifact(dir, source, name = 'tool.mjs') {
  const bytes = Buffer.from(source, 'utf8')
  const artifactPath = join(dir, name)
  writeFileSync(artifactPath, bytes)
  return { artifactPath, artifactDigest: digestOf(bytes), bytes }
}

function manifestFor(artifactDigest, overrides = {}) {
  return {
    schema_version: 'test-tool-manifest/v1',
    tool_id: 'worker.fixture.tool',
    tool_version: '1.0.0',
    artifact_digest: artifactDigest,
    role: 'probe',
    runner: { adapter: 'local-worker-json', entrypoint: 'run' },
    input_schema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object',
      properties: { value: {} },
      required: [],
      additionalProperties: true,
    },
    observation_schema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object',
      additionalProperties: true,
    },
    requires: ['target:plugin'],
    permissions: { filesystem: ['workspace:read'], network: [], subprocess: [], devices: [], secrets: [] },
    limits: {
      timeout_ms: 5000, cpu_ms: 1000, memory_mb: 128, temp_bytes: 1048576,
      output_bytes: 1024 * 1024, attachment_bytes: 1024, processes: 1, concurrency: 1,
    },
    determinism: 'deterministic',
    retry: { safe: false, max_attempts: 1 },
    ...overrides,
  }
}

function makeSetup(dir, artifact, input = {}) {
  const manifest = manifestFor(artifact.artifactDigest)
  const toolRef = { tool_id: manifest.tool_id, version: manifest.tool_version, artifact_digest: artifact.artifactDigest }
  const binding = { manifest, artifactPath: artifact.artifactPath, workspaceRoot: dir, toolRef }
  return { manifest, toolRef, binding }
}

function makeRequest(toolRef, input, overrides = {}) {
  return buildToolRequestFrame({
    request_id: overrides.request_id ?? 'req-runner',
    run_id: 'run-runner',
    plan_id: 'plan-runner',
    test_id: 't.runner',
    attempt: 1,
    tool_ref: overrides.tool_ref ?? toolRef,
    target_ref: { kind: 'plugin', owner_put_digest: `sha256:${'ef'.repeat(32)}`, origin: 'runner-test' },
    input,
    deadline: overrides.deadline ?? new Date(Date.now() + 10_000).toISOString(),
    capability_snapshot_ref: overrides.capability_snapshot_ref ?? CAP_REF,
  })
}

async function run(t, setup, input, overrides = {}) {
  const request = makeRequest(setup.toolRef, input, overrides)
  let started = 0
  const response = await runToolRequest({
    request,
    binding: setup.binding,
    expectedCapabilitySnapshotRef: overrides.expectedCapabilitySnapshotRef ?? CAP_REF,
    onStarted: () => { started += 1 },
  })
  return { request, response, started: () => started }
}

test('normal artifact output becomes a worker observation; started fires once', async (t) => {
  const dir = tmpDir(t)
  const artifact = writeArtifact(dir, 'export async function run(input) { return { echoed: input.value } }\n')
  const setup = makeSetup(dir, artifact)
  const { response, started } = await run(t, setup, { value: 'hello' })
  assert.equal(response.execution_status, 'completed')
  assert.equal(started(), 1)
  assert.equal(response.observations.length, 1)
  assert.equal(response.observations[0].source, 'worker')
  assert.deepEqual(response.observations[0].value, { echoed: 'hello' })
  assert.deepEqual(response.diagnostics, [])
})

test('shell metacharacters in input stay argv/JSON data (shell:false, no side effects)', async (t) => {
  const dir = tmpDir(t)
  const artifact = writeArtifact(dir, readFileSync(TOOL_ECHO))
  const setup = makeSetup(dir, artifact)
  const payload = '$(touch pwned); `whoami` | cat > pwned.txt && echo "quoted"'
  const { response } = await run(t, setup, { value: payload })
  assert.equal(response.execution_status, 'completed')
  assert.deepEqual(response.observations[0].value, { echoed: payload })
  assert.deepEqual(readdirSync(dir).sort(), ['tool.mjs'], 'no shell side effects in the workspace')
})

test('tool child receives a minimal environment with no ambient credentials', async (t) => {
  const dir = tmpDir(t)
  const artifact = writeArtifact(dir, readFileSync(TOOL_ENV))
  const setup = makeSetup(dir, artifact)
  process.env.DSH_TESTBED_FAKE_SECRET = 'leaked-secret-value'
  process.env.OPENAI_API_KEY = 'sk-' + 'f'.repeat(40)
  t.after(() => {
    delete process.env.DSH_TESTBED_FAKE_SECRET
    delete process.env.OPENAI_API_KEY
  })
  const { response } = await run(t, setup, {})
  assert.equal(response.execution_status, 'completed')
  assert.deepEqual(response.observations[0].value, {
    fake_secret: null,
    openai_key: null,
    node_no_warnings: '1',
  })
  assert.equal(JSON.stringify(response).includes('leaked-secret-value'), false)
})

test('tool child runs in the pinned workspace root, not the control cwd', async (t) => {
  const dir = tmpDir(t)
  const artifact = writeArtifact(dir, readFileSync(TOOL_CWD))
  const setup = makeSetup(dir, artifact)
  const { response } = await run(t, setup, {})
  assert.equal(response.execution_status, 'completed')
  assert.equal(resolve(response.observations[0].value.cwd).toLowerCase(), resolve(dir).toLowerCase())
})

test('secret-looking observation values are redacted inside the worker', async (t) => {
  const dir = tmpDir(t)
  const artifact = writeArtifact(dir, readFileSync(TOOL_SECRET))
  const setup = makeSetup(dir, artifact)
  const { response } = await run(t, setup, {})
  const serialized = JSON.stringify(response)
  assert.equal(serialized.includes('sk-' + 'a'.repeat(40)), false)
  assert.equal(serialized.includes('Bearer ' + 'b'.repeat(30)), false)
  assert.ok(serialized.includes(REDACTED))
  assert.ok(response.observations[0].limitations.includes('value-redacted'))
  assert.ok(response.diagnostics.includes('observation-value-redacted'))
})

test('oversized observation values are summarized instead of sent raw', async (t) => {
  const dir = tmpDir(t)
  const artifact = writeArtifact(dir, 'export async function run() { return { huge: "x".repeat(' + (MAX_OBSERVATION_BYTES + 1024) + ') } }\n')
  const setup = makeSetup(dir, artifact)
  const { response } = await run(t, setup, {})
  assert.equal(response.execution_status, 'completed')
  assert.ok(response.observations[0].limitations.includes('value-summarized'))
  assert.match(response.observations[0].value.digest, /^sha256:[0-9a-f]{64}$/)
  assert.ok(Buffer.byteLength(JSON.stringify(response), 'utf8') < 64 * 1024)
})

test('observation schema violations are surfaced, not silently accepted', async (t) => {
  const dir = tmpDir(t)
  const artifact = writeArtifact(dir, 'export async function run() { return { status_code: "not-an-integer" } }\n')
  const manifest = manifestFor(artifact.artifactDigest, {
    observation_schema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object',
      properties: { status_code: { type: 'integer' } },
      required: ['status_code'],
      additionalProperties: false,
    },
  })
  const toolRef = { tool_id: manifest.tool_id, version: manifest.tool_version, artifact_digest: artifact.artifactDigest }
  const setup = { manifest, toolRef, binding: { manifest, artifactPath: artifact.artifactPath, workspaceRoot: dir, toolRef } }
  const { response } = await run(t, setup, {})
  assert.equal(response.execution_status, 'completed')
  assert.ok(response.observations[0].limitations.includes('observation-schema-invalid'))
  assert.ok(response.diagnostics.includes('observation-schema-invalid'))
})

test('deadline kills the tool child and records timeout', async (t) => {
  const dir = tmpDir(t)
  const artifact = writeArtifact(dir, readFileSync(TOOL_SLOW))
  const manifest = manifestFor(artifact.artifactDigest, {
    limits: { ...manifestFor(artifact.artifactDigest).limits, timeout_ms: 400 },
  })
  const toolRef = { tool_id: manifest.tool_id, version: manifest.tool_version, artifact_digest: artifact.artifactDigest }
  const setup = { manifest, toolRef, binding: { manifest, artifactPath: artifact.artifactPath, workspaceRoot: dir, toolRef } }
  const { response } = await run(t, setup, {})
  assert.equal(response.execution_status, 'timeout')
  assert.ok(response.diagnostics.includes('deadline'))
})

test('excessive stdout is bounded and rejected', async (t) => {
  const dir = tmpDir(t)
  const artifact = writeArtifact(dir, readFileSync(TOOL_HUGE))
  const manifest = manifestFor(artifact.artifactDigest, {
    limits: { ...manifestFor(artifact.artifactDigest).limits, output_bytes: 8192 },
  })
  const toolRef = { tool_id: manifest.tool_id, version: manifest.tool_version, artifact_digest: artifact.artifactDigest }
  const setup = { manifest, toolRef, binding: { manifest, artifactPath: artifact.artifactPath, workspaceRoot: dir, toolRef } }
  const { response } = await run(t, setup, {})
  assert.equal(response.execution_status, 'error')
  assert.ok(response.diagnostics.includes('tool-output-oversize'))
})

test('request boundary failures produce error responses and never start', async (t) => {
  const dir = tmpDir(t)
  const artifact = writeArtifact(dir, 'export async function run(input) { return { value: input.value } }\n')
  const manifest = manifestFor(artifact.artifactDigest, {
    input_schema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object', properties: { value: { type: 'number' } }, required: ['value'], additionalProperties: false,
    },
  })
  const strictRef = { tool_id: manifest.tool_id, version: manifest.tool_version, artifact_digest: artifact.artifactDigest }
  const strictSetup = { manifest, toolRef: strictRef, binding: { manifest, artifactPath: artifact.artifactPath, workspaceRoot: dir, toolRef: strictRef } }
  const { response, started } = await run(t, strictSetup, { value: 'string' })
  assert.equal(response.execution_status, 'error')
  assert.deepEqual(response.diagnostics, ['tool-input-schema-invalid'])
  assert.equal(started(), 0, 'preflight failure must not emit a started notification')

  const nonSerializable = await runToolRequest({
    request: { ...makeRequest(strictRef, { value: 1 }), input: { value: 1n } },
    binding: strictSetup.binding,
    expectedCapabilitySnapshotRef: CAP_REF,
    onStarted: () => { throw new Error('must not start') },
  })
  assert.deepEqual(nonSerializable, { ok: false, reason: 'oversize' })
})

test('binding and digest mismatches are rejected without starting the tool', async (t) => {
  const dir = tmpDir(t)
  const artifact = writeArtifact(dir, 'export async function run() { return {} }\n')
  const setup = makeSetup(dir, artifact)
  const wrongRef = { ...setup.toolRef, artifact_digest: `sha256:${'99'.repeat(32)}` }
  const request = makeRequest(wrongRef, {})
  const response = await runToolRequest({
    request,
    binding: setup.binding,
    expectedCapabilitySnapshotRef: CAP_REF,
    onStarted: () => { throw new Error('must not start') },
  })
  assert.equal(response.execution_status, 'error')
  assert.deepEqual(response.diagnostics, ['tool-binding-mismatch'])

  const capMismatch = await runToolRequest({
    request: makeRequest(setup.toolRef, {}),
    binding: setup.binding,
    expectedCapabilitySnapshotRef: `cap-sha256:${'11'.repeat(32)}`,
    onStarted: () => { throw new Error('must not start') },
  })
  assert.equal(capMismatch.execution_status, 'error')
  assert.deepEqual(capMismatch.diagnostics, ['capability-snapshot-mismatch'])
})

test('pinManifestArtifact rejects escapes, non-node imports, oversize and digest mismatches', async (t) => {
  const dir = tmpDir(t)
  const inside = writeArtifact(dir, 'export async function run() { return {} }\n')
  const escaped = await pinManifestArtifact({
    manifest: manifestFor(inside.artifactDigest),
    artifactPath: '..\\outside.mjs',
    workspaceRoot: dir,
  })
  assert.equal(escaped.ok, false)
  assert.deepEqual(escaped.errors, ['tool-artifact-path-invalid'])

  const remoteArtifact = writeArtifact(dir, "import fs from 'fs'\nexport async function run() { return {} }\n", 'remote.mjs')
  const remotePinned = await pinManifestArtifact({
    manifest: manifestFor(remoteArtifact.artifactDigest),
    artifactPath: remoteArtifact.artifactPath,
    workspaceRoot: dir,
  })
  assert.equal(remotePinned.ok, false)
  assert.deepEqual(remotePinned.errors, ['tool-import-unsupported'])

  const oversize = writeArtifact(dir, 'x'.repeat(MAX_ARTIFACT_BYTES + 1), 'oversize.mjs')
  const oversizePinned = await pinManifestArtifact({
    manifest: manifestFor(oversize.artifactDigest),
    artifactPath: oversize.artifactPath,
    workspaceRoot: dir,
  })
  assert.equal(oversizePinned.ok, false)
  assert.deepEqual(oversizePinned.errors, ['tool-artifact-oversize'])

  const mismatch = await pinManifestArtifact({
    manifest: manifestFor(`sha256:${'77'.repeat(32)}`),
    artifactPath: inside.artifactPath,
    workspaceRoot: dir,
  })
  assert.equal(mismatch.ok, false)
})

test('manifest runner/entrypoint must be the fixed adapter; missing artifact is explicit', async (t) => {
  const dir = tmpDir(t)
  const artifact = writeArtifact(dir, 'export async function run() { return {} }\n')
  const badAdapter = manifestFor(artifact.artifactDigest, { runner: { adapter: 'shell', entrypoint: 'run' } })
  const adapterResult = await pinManifestArtifact({
    manifest: badAdapter,
    artifactPath: artifact.artifactPath,
    workspaceRoot: dir,
  })
  assert.equal(adapterResult.ok, false)
  assert.deepEqual(adapterResult.errors, ['runner-adapter-unsupported'])

  const badEntry = manifestFor(artifact.artifactDigest, { runner: { adapter: 'local-worker-json', entrypoint: 'sh -c' } })
  const entryResult = await pinManifestArtifact({
    manifest: badEntry,
    artifactPath: artifact.artifactPath,
    workspaceRoot: dir,
  })
  assert.equal(entryResult.ok, false)
  assert.deepEqual(entryResult.errors, ['runner-entrypoint-shell-metachar'])

  const missing = await pinManifestArtifact({
    manifest: manifestFor(artifact.artifactDigest),
    artifactPath: join(dir, 'missing.mjs'),
    workspaceRoot: dir,
  })
  assert.equal(missing.ok, false)
  assert.deepEqual(missing.errors, ['tool-artifact-not-found'])
})
