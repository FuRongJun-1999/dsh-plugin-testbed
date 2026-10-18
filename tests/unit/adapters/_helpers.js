/**
 * Adapter 单元测试共用 helper（不作为 node:test 文件执行）。
 *
 * 只创建临时工具工件/worker 脚本并构造 adapter；不做断言，不改变生产语义。
 */
import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

import { buildToolRequestFrame } from '../../../src/protocol/transport.js'
import { makeSubprocessAdapter } from '../../../src/adapters/subprocess.js'

export const HOST_ENTRY = fileURLToPath(new URL('../../../src/worker/host.js', import.meta.url))
export const LEGACY_FIXTURE = fileURLToPath(new URL('../../fixtures/worker-fixture.js', import.meta.url))
export const WRONG_CORR_FIXTURE = fileURLToPath(new URL('../../fixtures/worker-wrong-corr.mjs', import.meta.url))
export const FAKE_TIMESTAMP_FIXTURE = fileURLToPath(new URL('../../fixtures/worker-fake-timestamp.mjs', import.meta.url))

export const CAPABILITY_REF = `cap-sha256:${'b'.repeat(64)}`
export const OWNER_DIGEST = `sha256:${'c'.repeat(64)}`
export const TOOL_SOURCE = 'export async function run(input) { return { status_code: input.status_code } }\n'

export const NO_VERDICT_KEYS = Object.freeze(['verdict', 'gate_decision', 'required', 'expected', 'plan'])

let sequence = 0
export function unique(prefix = 'adapter') {
  sequence += 1
  return `${prefix}-${Date.now().toString(36)}-${sequence}`
}

export function makeTempDir(prefix = 'testbed-adapter-') {
  return mkdtempSync(join(tmpdir(), prefix))
}

/** 注册 after 清理，保证即使断言失败也不泄漏临时目录。 */
export function cleanupDirs(t, dirs) {
  t.after(() => {
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true })
  })
}

export function sha256(data) {
  return `sha256:${createHash('sha256').update(data).digest('hex')}`
}

export function writeToolArtifact(dir, { name = 'tool.mjs', source = TOOL_SOURCE } = {}) {
  const bytes = Buffer.from(source, 'utf8')
  const artifactPath = join(dir, name)
  writeFileSync(artifactPath, bytes)
  return { artifactPath, workspaceRoot: dir, artifactDigest: sha256(bytes) }
}

/** 写一个自包含临时 worker 脚本；用于传输/环境/参数等负向与探针场景。 */
export function writeWorkerScript(dir, source, name = 'worker.mjs') {
  const path = join(dir, name)
  writeFileSync(path, source, 'utf8')
  return path
}

export function makeManifest(overrides = {}) {
  return {
    schema_version: 'test-tool-manifest/v1',
    tool_id: 'example.strict-probe',
    tool_version: '1.0.0',
    artifact_digest: `sha256:${'1'.repeat(64)}`,
    role: 'probe',
    tags: ['unit'],
    runner: { adapter: 'local-worker-json', entrypoint: 'run' },
    input_schema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object', properties: { status_code: { type: 'integer' } },
      required: ['status_code'], additionalProperties: false,
    },
    observation_schema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object', properties: { status_code: { type: 'integer' } },
      required: ['status_code'], additionalProperties: false,
    },
    requires: ['target:plugin'],
    permissions: { filesystem: ['workspace:read'], network: [], subprocess: [], devices: [], secrets: [] },
    limits: {
      timeout_ms: 10000, cpu_ms: 5000, memory_mb: 128, processes: 1,
      temp_bytes: 1048576, output_bytes: 1048576, attachment_bytes: 1048576, concurrency: 1,
    },
    determinism: 'deterministic',
    retry: { safe: false, max_attempts: 1 },
    ...overrides,
  }
}

export function toolRefFor(manifest) {
  return { tool_id: manifest.tool_id, version: manifest.tool_version, artifact_digest: manifest.artifact_digest }
}

export function makeToolRequest({
  testId = 't.strict', runId = 'run-strict', planId = 'plan-strict', attempt = 1,
  input = { status_code: 204 }, toolRef, capabilityRef = CAPABILITY_REF,
  deadline = new Date(Date.now() + 8000).toISOString(), requestId = `req-${testId}-${attempt}-${unique('r')}`,
} = {}) {
  return buildToolRequestFrame({
    request_id: requestId,
    run_id: runId,
    plan_id: planId,
    test_id: testId,
    attempt,
    tool_ref: toolRef,
    target_ref: { kind: 'plugin', owner_put_digest: OWNER_DIGEST, origin: 'unit-test' },
    input,
    deadline,
    capability_snapshot_ref: capabilityRef,
  })
}

/**
 * 构造带一个 pinned tool binding 的 adapter（tool 模式）。
 * @param {{source?:string, testId?:string, manifestOverrides?:object, adapterOptions?:object,
 *   capabilitySnapshotRefs?:Record<string,string>}} [options]
 */
export function makePinnedToolCase(options = {}) {
  const workspaceRoot = makeTempDir('testbed-tool-')
  const artifact = writeToolArtifact(workspaceRoot, { source: options.source ?? TOOL_SOURCE })
  const manifest = makeManifest({ artifact_digest: artifact.artifactDigest, ...(options.manifestOverrides ?? {}) })
  const toolRef = toolRefFor(manifest)
  const testId = options.testId ?? 't.strict'
  const adapter = makeSubprocessAdapter({
    workerEntry: HOST_ENTRY,
    runId: unique('tool-run'),
    toolBindings: {
      [testId]: { manifest, artifactPath: artifact.artifactPath, workspaceRoot, toolRef },
    },
    capabilitySnapshotRefs: { [testId]: CAPABILITY_REF },
    ...(options.adapterOptions ?? {}),
  })
  return {
    adapter,
    workspaceRoot,
    artifact,
    manifest,
    toolRef,
    testId,
    request: (overrides = {}) => makeToolRequest({ testId, toolRef, ...overrides }),
  }
}

/** 断言 attempt 终态不携带任何 verdict/gate/required/expected/plan 类字段。 */
export function assertNoVerdictKeys(outcome) {
  for (const key of NO_VERDICT_KEYS) {
    if (key in outcome) throw new Error(`attempt terminal must not carry ${key}`)
  }
  const evidence = outcome.invocation_evidence
  if (evidence) {
    for (const key of NO_VERDICT_KEYS) {
      if (key in evidence) throw new Error(`invocation evidence must not carry ${key}`)
    }
  }
}

export { pathToFileURL }
