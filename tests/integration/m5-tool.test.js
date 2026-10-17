/**
 * M5 集成 · 受控工具组合（test-tool-manifest/v1 + JSON Schema Draft 2020-12），node:test，纯 ESM。
 *
 * 走 `runSelfCheck(spec, { executionMode:'subprocess' })`，case 带 manifest/input 与真实 artifact 路径，
 * 由 manifest runner 执行一次性字节快照，验证 CONTRACT-m5 §4 四条：
 *   ① 合法 tool（manifest 过 validateToolManifest，input 过 input_schema，observation 过
 *      observation_schema）→ observation verdict=pass，但无可信独立启动来源时 invocation=unknown，gate blocked、exit 2。
 *   ② 非法 manifest（缺 artifact_digest）→ pre-plan blocked（plan_id=null、reconciliation=null、
 *      reason_codes 含 tool-manifest-invalid）、exit 2。
 *   ③ 输入不合 input_schema → pre-plan blocked（reason 含 tool-input-schema-invalid）。
 *   ④ 观测不合 observation_schema → 该项 verdict=error、required→gate blocked、
 *      attempt.reason_codes 含 observation-schema-invalid。
 *
 * 依赖：src/protocol/{jsonschema,tool-manifest}.js、kernel 的 artifact pinning/strict dispatch 与 receipt
 * evidence fields，以及 adapter 的 worker/child notification handling（无独立可信启动源时为 unknown/false）。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { runSelfCheck } from '../../src/index.js'
import { makeRunSpec } from '../fixtures/run-specs.js'

const DIGEST64 = 'ab'.repeat(32) // 64 hex chars for negative-path fixtures only

/** 合法 tool manifest（CONTRACT-m5 §2 全字段）。 */
function makeToolManifest(overrides = {}) {
  return {
    schema_version: 'test-tool-manifest/v1',
    tool_id: 'example.echo-probe',
    tool_version: '1.0.0',
    artifact_digest: 'sha256:' + DIGEST64,
    role: 'probe',
    runner: { adapter: 'local-worker-json', entrypoint: 'run' },
    input_schema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object',
      properties: { value: { type: 'number' } },
      required: ['value'],
      additionalProperties: false,
    },
    observation_schema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object',
      properties: { status_code: { type: 'integer' } },
      required: ['status_code'],
      additionalProperties: false,
    },
    requires: ['target:plugin'],
    permissions: { filesystem: ['workspace:read'], network: [], subprocess: [], devices: [], secrets: [] },
    limits: {
      timeout_ms: 30000, cpu_ms: 15000, memory_mb: 256, temp_bytes: 8388608,
      output_bytes: 1048576, attachment_bytes: 1048576, processes: 1, concurrency: 1,
    },
    determinism: 'deterministic',
    retry: { safe: false, max_attempts: 1 },
    ...overrides,
  }
}

/** 构造一个带 tool（manifest + input）的 required 用例。 */
function makeToolCase(id, { manifest, input, probe, criteria, artifactPath, workspaceRoot }) {
  const tool = { manifest, input }
  if (artifactPath !== undefined) tool.artifactPath = artifactPath
  if (workspaceRoot !== undefined) tool.workspaceRoot = workspaceRoot
  const testCase = {
    test_id: id,
    node_id: id,
    classification: 'required',
    criteria,
    tool,
  }
  if (probe !== undefined) testCase.probe = probe
  return testCase
}

/** Write the exact bytes executed by the manifest runner and return its digest/pinning fields. */
function writeToolArtifact(dir, { name = 'tool.mjs', source = 'export async function run(input) { return { status_code: input.value } }' } = {}) {
  const artifactBytes = Buffer.from(source, 'utf8')
  const artifactPath = join(dir, name)
  writeFileSync(artifactPath, artifactBytes)
  const artifactDigest = `sha256:${createHash('sha256').update(artifactBytes).digest('hex')}`
  return { artifactPath, workspaceRoot: dir, artifactDigest }
}

function tmpDir() {
  return mkdtempSync(join(tmpdir(), 'testbed-m5-'))
}
function cleanup(t, dir) {
  t.after(() => rmSync(dir, { recursive: true, force: true }))
}
function readReceipt(result) {
  return JSON.parse(readFileSync(result.receiptPath, 'utf8'))
}

// ---------------------------------------------------------------------------
// §4① 合法 tool executes but is not independently verified as started → blocked
// ---------------------------------------------------------------------------

test('§4① 合法 tool executes; without trusted invocation evidence it is blocked/unknown', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const artifact = writeToolArtifact(dir)
  const spec = makeRunSpec([
    makeToolCase('t.legal', {
      ...artifact,
      manifest: makeToolManifest({ artifact_digest: artifact.artifactDigest }),
      input: { value: 200 }, // The artifact returns { status_code: 200 }; no built-in probe fallback.
      criteria: { assert: 'equals', path: 'status_code', expected: 200 },
    }),
  ])

  const out = await runSelfCheck(spec, { executionMode: 'subprocess', receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  assert.notEqual(receipt.plan_id, null, '合法 tool 应走 frozen Plan 形态')
  const tc = receipt.test_cases.find((c) => c.test_id === 't.legal')
  assert.equal(tc.execution_status, 'completed', 'the manifest artifact returns a valid observation')
  assert.equal(tc.verdict, 'pass', 'valid tool result remains a passing test verdict')
  assert.equal(tc.invocation_status, 'unknown', 'worker/child notifications are not trusted invocation evidence')
  assert.equal(tc.invocation_evidence_verified, false, 'worker/child notifications must not verify invocation')
  assert.equal(tc.attempts[0].execution_status, 'completed')
  assert.equal(tc.attempts[0].invocation_status, 'unknown')
  assert.equal(tc.attempts[0].invocation_evidence_verified, false)
})

// ---------------------------------------------------------------------------
// §4② 非法 manifest（缺 artifact_digest）→ pre-plan blocked
// ---------------------------------------------------------------------------

test('§4② 非法 manifest（缺 artifact_digest）→ pre-plan blocked、reason 含 tool-manifest-invalid', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const bad = makeToolManifest()
  delete bad.artifact_digest
  const spec = makeRunSpec([
    makeToolCase('t.badmanifest', {
      manifest: bad,
      input: { value: 42 },
      probe: { op: 'echo', value: { status_code: 200 } },
      criteria: { assert: 'equals', path: 'status_code', expected: 200 },
    }),
  ])

  const out = await runSelfCheck(spec, { executionMode: 'subprocess', receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)
  assert.equal(out.reconciliation, null)

  const receipt = readReceipt(out)
  assert.equal(receipt.plan_id, null, 'Plan 前阻断 → plan_id=null')
  assert.equal(receipt.reconciliation, null, 'Plan 前阻断 → reconciliation=null')
  assert.deepEqual(receipt.test_cases, [])
  assert.ok(
    Array.isArray(receipt.reason_codes) && receipt.reason_codes.some((r) => String(r).includes('tool-manifest-invalid')),
    `reason_codes 应含 tool-manifest-invalid，got: ${JSON.stringify(receipt.reason_codes)}`,
  )
})

// ---------------------------------------------------------------------------
// §4③ 输入不合 input_schema → pre-plan blocked
// ---------------------------------------------------------------------------

test('§4③ 输入不合 input_schema → pre-plan blocked、reason 含 tool-input-schema-invalid', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const artifact = writeToolArtifact(dir)
  const spec = makeRunSpec([
    makeToolCase('t.badinput', {
      ...artifact,
      manifest: makeToolManifest({ artifact_digest: artifact.artifactDigest }),
      input: { value: 'not-a-number' }, // 违反 input_schema（value 应为 number）
      criteria: { assert: 'equals', path: 'status_code', expected: 200 },
    }),
  ])

  const out = await runSelfCheck(spec, { executionMode: 'subprocess', receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  assert.equal(receipt.plan_id, null)
  assert.equal(receipt.reconciliation, null)
  assert.ok(
    Array.isArray(receipt.reason_codes) && receipt.reason_codes.some((r) => String(r).includes('tool-input-schema-invalid')),
    `reason_codes 应含 tool-input-schema-invalid，got: ${JSON.stringify(receipt.reason_codes)}`,
  )
})

// ---------------------------------------------------------------------------
// §4④ 观测不合 observation_schema → verdict=error、required→blocked、
//     attempt.reason_codes 含 observation-schema-invalid
// ---------------------------------------------------------------------------

test('§4④ 观测不合 observation_schema → verdict=error、gate blocked、attempt 含 observation-schema-invalid', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const artifact = writeToolArtifact(dir, {
    source: "export async function run() { return { status_code: 'not-an-integer' } }",
  })
  const spec = makeRunSpec([
    makeToolCase('t.badobs', {
      ...artifact,
      manifest: makeToolManifest({ artifact_digest: artifact.artifactDigest }),
      input: { value: 42 },
      criteria: { assert: 'equals', path: 'status_code', expected: 200 },
    }),
  ])

  const out = await runSelfCheck(spec, { executionMode: 'subprocess', receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  const tc = receipt.test_cases.find((c) => c.test_id === 't.badobs')
  assert.equal(tc.verdict, 'error', '观测 schema 校验失败 → 强制 error（fail-closed）')
  // architecture §11.2.1 canonical receipt 把 reason_codes 放 test_case 级（attempts[] 只带
  // verdict/observation_refs）；kernel 当前把 observation-schema-invalid 写入 test_case.reason_codes。
  // 兼容两种落点：case 级 reason_codes 或 attempts[0].reason_codes 任一命中即可。
  const caseCodes = Array.isArray(tc.reason_codes) ? tc.reason_codes : []
  const attemptCodes = Array.isArray(tc.attempts?.[0]?.reason_codes) ? tc.attempts[0].reason_codes : []
  assert.ok(
    caseCodes.includes('observation-schema-invalid') || attemptCodes.includes('observation-schema-invalid'),
    `reason_codes 应含 observation-schema-invalid，got case=${JSON.stringify(caseCodes)} attempt=${JSON.stringify(attemptCodes)}`,
  )
})