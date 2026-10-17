/**
 * src/adapters/subprocess.js 的单元测试（node:test，真实 spawn L1 子进程）。
 *
 * workerEntry：若 worker-owner 已落 src/worker/host.js 则用真实入口，否则用本目录的
 * tests/fixtures/worker-fixture.js（其协议行为与 CONTRACT-m2 §2 一致）跑通；
 * host.js 落地后自动切换，无需改本测试。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { access } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { buildToolRequestFrame } from '../../../src/protocol/transport.js'

import {
  ISOLATION_LEVEL,
  UNENFORCED_RESOURCES,
  ENFORCED_LIMITS,
  makeSubprocessAdapter,
} from '../../../src/adapters/subprocess.js'

const realHost = new URL('../../../src/worker/host.js', import.meta.url)
const fixtureHost = new URL('../../fixtures/worker-fixture.js', import.meta.url)
const workerEntry = fileURLToPath(existsSync(realHost) ? realHost : fixtureHost)

const exists = (p) => access(p).then(() => true, () => false)
const NO_VERDICT_KEYS = ['verdict', 'gate_decision', 'required', 'expected', 'plan', 'plan_id']

/** 断言 attemptTerminal 不含任何 verdict/gate/required/expected/plan 类字段。 */
function assertNoVerdictKeys(outcome) {
  for (const k of NO_VERDICT_KEYS) assert.ok(!(k in outcome), `attemptTerminal 不应携带字段 ${k}`)
}

test('导出：ISOLATION_LEVEL / UNENFORCED_RESOURCES / ENFORCED_LIMITS 与契约闭集一致', () => {
  assert.equal(ISOLATION_LEVEL, 'L1-subprocess')
  assert.deepEqual([...UNENFORCED_RESOURCES], ['filesystem', 'network', 'subprocess', 'devices', 'cpu_ms', 'memory_mb'])
  assert.deepEqual([...ENFORCED_LIMITS], ['max_frame_bytes', 'max_output_bytes', 'timeout_ms', 'processes'])
})

test('echo：真实 spawn，worker started 通知不构成可信证据；observation + launchRecord + 无 verdict 字段', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry, runId: `echo-${Date.now()}` })
  try {
    const { pid } = adapter.start()
    assert.ok(typeof pid === 'number' && pid > 0, 'start() 应返回正整数 pid')

    const rec = adapter.launchRecord
    assert.equal(rec.isolation, 'L1-subprocess')
    assert.equal(rec.pid, pid)
    assert.equal(typeof rec.temp_dir, 'string')
    assert.ok(rec.temp_dir.includes('dsh-testbed-'), 'temp_dir 应按 owner(run_id) 命名')
    assert.deepEqual([...rec.enforceable], ENFORCED_LIMITS)
    assert.deepEqual([...rec.unenforced], UNENFORCED_RESOURCES)
    assert.equal(typeof rec.max_frame_bytes, 'number')
    assert.equal(typeof rec.max_output_bytes, 'number')
    assert.equal(typeof rec.timeout_ms, 'number')
    assert.ok(await exists(rec.temp_dir), 'start() 后临时目录应已创建')

    const outcome = await adapter.execute({
      request_id: 'req-echo-1',
      run_id: 'run-echo',
      plan_id: 'plan-echo',
      test_id: 't-echo',
      attempt: 1,
      input: { op: 'echo', value: { status_code: 200 } },
    })

    assert.equal(outcome.admission_status, 'accepted')
    assert.equal(outcome.execution_status, 'completed')
    assert.equal(outcome.invocation_status, 'unknown')
    assert.equal(outcome.invocation_evidence_verified, false)
    assert.deepEqual(outcome.observations, [
      { observation_id: 'obs-1', value: { status_code: 200 }, source: 'worker', limitations: ['l1-subprocess'] },
    ])
    assert.deepEqual(outcome.reason_codes, [])
    assertNoVerdictKeys(outcome)
  } finally {
    await adapter.reap()
  }
})

test('error op：execution_status=error，worker started notification stays unverified/unknown', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry, runId: `err-${Date.now()}` })
  try {
    adapter.start()
    const outcome = await adapter.execute({
      request_id: 'req-err-1',
      run_id: 'run-err',
      plan_id: 'plan-err',
      test_id: 't-err',
      attempt: 1,
      input: { op: 'error' },
    })
    assert.equal(outcome.admission_status, 'accepted')
    assert.equal(outcome.execution_status, 'error')
    assert.equal(outcome.invocation_status, 'unknown') // worker started frame is not trusted evidence
    assert.equal(outcome.invocation_evidence_verified, false)
    assert.deepEqual(outcome.observations, [])
    assert.deepEqual(outcome.reason_codes, ['worker-error'])
    assertNoVerdictKeys(outcome)
  } finally {
    await adapter.reap()
  }
})

test('timeout：input.delay_ms 大 + 短 timeoutMs → deadline 终态，reap 后 pid 不存活', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry, runId: `timeout-${Date.now()}`, timeoutMs: 300 })
  const { pid } = adapter.start()
  try {
    const outcome = await adapter.execute({
      request_id: 'req-to-1',
      run_id: 'run-to',
      plan_id: 'plan-to',
      test_id: 't-to',
      attempt: 1,
      input: { op: 'sleep', delay_ms: 5000 },
    })
    assert.equal(outcome.admission_status, 'accepted')
    assert.equal(outcome.execution_status, 'timeout')
    assert.equal(outcome.invocation_status, 'unknown') // deadline 路径按契约固定 unknown
    assert.deepEqual(outcome.observations, [])
    assert.deepEqual(outcome.reason_codes, ['deadline'])
    assertNoVerdictKeys(outcome)
  } finally {
    const r = await adapter.reap()
    assert.equal(r.pid_alive, false, '超时后 reap 应核验 pid 不存活')
    assert.equal(r.temp_removed, true, '超时后回收应删除临时目录')
  }
})

test('bounded output：超出 maxOutputBytes 后拒绝响应并回收子进程', async () => {
  const root = mkdtempSync(join(tmpdir(), 'subprocess-oversize-'))
  const noisyWorker = join(root, 'noisy-worker.mjs')
  writeFileSync(noisyWorker, 'process.stdout.write("x".repeat(10000))\nsetInterval(() => {}, 1000)\n', 'utf8')
  const adapter = makeSubprocessAdapter({ workerEntry: noisyWorker, runId: `oversize-${Date.now()}`, maxOutputBytes: 128 })
  try {
    adapter.start()
    const outcome = await adapter.execute({
      request_id: 'req-oversize', run_id: 'run-oversize', plan_id: 'plan-oversize',
      test_id: 't-oversize', attempt: 1, input: { op: 'echo' },
    })
    assert.equal(outcome.execution_status, 'error')
    assert.deepEqual(outcome.reason_codes, ['oversize'])
    assert.equal(outcome.invocation_evidence_verified, false)
    assert.equal(outcome.invocation_status, 'unknown')
  } finally {
    await adapter.reap()
    rmSync(root, { recursive: true, force: true })
  }
})

test('reap()：pid 不存活 + 临时目录已删 + 幂等（不以退出码替代回收验收）', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry, runId: `reap-${Date.now()}` })
  const { pid } = adapter.start()
  const tempDir = adapter.launchRecord.temp_dir
  assert.ok(await exists(tempDir), 'start() 后临时目录应存在')

  const r1 = await adapter.reap()
  assert.equal(r1.pid_alive, false, `reap 后 pid=${pid} 应不存活`)
  assert.equal(r1.temp_removed, true, 'reap 后临时目录应已删除')

  // 幂等：二次 reap 结果一致，无副作用。
  const r2 = await adapter.reap()
  assert.equal(r2.pid_alive, false)
  assert.equal(r2.temp_removed, true)
})

test('duplicate：同一 request_id 二次派发 → duplicate 拒绝（进程内串行）', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry, runId: `dup-${Date.now()}` })
  try {
    adapter.start()
    const req = {
      request_id: 'req-dup-1',
      run_id: 'run-dup',
      plan_id: 'plan-dup',
      test_id: 't-dup',
      attempt: 1,
      input: { op: 'echo', value: 1 },
    }
    await adapter.execute(req) // 首次正常完成
    const outcome = await adapter.execute(req) // 同一 request_id 再次派发
    assert.equal(outcome.admission_status, 'accepted')
    assert.equal(outcome.execution_status, 'error')
    assert.deepEqual(outcome.reason_codes, ['duplicate'])
    assert.deepEqual(outcome.observations, [])
    assertNoVerdictKeys(outcome)
  } finally {
    await adapter.reap()
  }
})

const TOOL_SOURCE = 'export async function run(input) { return { status_code: input.status_code } }\n'
const TOOL_DIGEST = `sha256:${createHash('sha256').update(TOOL_SOURCE).digest('hex')}`
const CAPABILITY_REF = `cap-sha256:${'b'.repeat(64)}`
const OWNER_DIGEST = `sha256:${'c'.repeat(64)}`

function makePinnedToolCase(testId = 't.strict') {
  const workspaceRoot = mkdtempSync(join(tmpdir(), 'subprocess-tool-'))
  const artifactPath = join(workspaceRoot, 'tool.mjs')
  writeFileSync(artifactPath, TOOL_SOURCE, 'utf8')
  const manifest = {
    schema_version: 'test-tool-manifest/v1',
    tool_id: 'example.strict-probe',
    tool_version: '1.0.0',
    artifact_digest: TOOL_DIGEST,
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
  }
  const toolRef = { tool_id: manifest.tool_id, version: manifest.tool_version, artifact_digest: TOOL_DIGEST }
  const targetRef = { kind: 'plugin', owner_put_digest: OWNER_DIGEST, origin: 'unit-test' }
  const request = buildToolRequestFrame({
    request_id: `req-${testId}`, run_id: 'run-strict', plan_id: 'plan-strict',
    test_id: testId, attempt: 1, tool_ref: toolRef, target_ref: targetRef,
    input: { status_code: 204 }, deadline: new Date(Date.now() + 8000).toISOString(),
    capability_snapshot_ref: CAPABILITY_REF,
  })
  const adapter = makeSubprocessAdapter({
    workerEntry, runId: `strict-${testId}-${Date.now()}`,
    toolBindings: { [testId]: { manifest, artifactPath, workspaceRoot, toolRef } },
    capabilitySnapshotRefs: { [testId]: CAPABILITY_REF },
  })
  return { adapter, request, workspaceRoot }
}

test('test-tool/v1：严格绑定响应相关字段；worker started 仅为通知，证据仍 unknown', async (t) => {
  const pinned = makePinnedToolCase()
  t.after(() => rmSync(pinned.workspaceRoot, { recursive: true, force: true }))
  try {
    pinned.adapter.start()
    const outcome = await pinned.adapter.execute(pinned.request)
    assert.equal(outcome.admission_status, 'accepted')
    assert.equal(outcome.execution_status, 'completed', JSON.stringify(outcome))
    assert.equal(outcome.invocation_status, 'unknown')
    assert.equal(outcome.invocation_evidence_verified, false)
    assert.deepEqual(outcome.observations, [{
      observation_id: 'obs-1',
      schema_ref: 'example.strict-probe@1.0.0#observation_schema',
      value: { status_code: 204 },
      source: 'worker',
      limitations: [],
    }])
    assert.deepEqual(outcome.diagnostics, [])
  } finally {
    await pinned.adapter.reap()
  }
})

test('test-tool/v1：worker preflight 拒绝无效 input，响应仍不证明 invocation started', async (t) => {
  const pinned = makePinnedToolCase('t.preflight')
  t.after(() => rmSync(pinned.workspaceRoot, { recursive: true, force: true }))
  try {
    pinned.adapter.start()
    const outcome = await pinned.adapter.execute({ ...pinned.request, input: { status_code: '204' } })
    assert.equal(outcome.admission_status, 'accepted')
    assert.equal(outcome.execution_status, 'error')
    assert.equal(outcome.invocation_status, 'unknown')
    assert.equal(outcome.invocation_evidence_verified, false)
    assert.deepEqual(outcome.observations, [])
    assert.deepEqual(outcome.diagnostics, ['tool-input-schema-invalid'])
  } finally {
    await pinned.adapter.reap()
  }
})

test('test-tool/v1：tool_ref 或 capability snapshot 不匹配时 adapter 拒绝派发', async (t) => {
  const pinned = makePinnedToolCase('t.pin-mismatch')
  t.after(() => rmSync(pinned.workspaceRoot, { recursive: true, force: true }))
  try {
    pinned.adapter.start()
    const badToolRef = await pinned.adapter.execute({
      ...pinned.request,
      request_id: 'req-wrong-tool-ref',
      tool_ref: { ...pinned.request.tool_ref, artifact_digest: `sha256:${'d'.repeat(64)}` },
    })
    assert.equal(badToolRef.execution_status, 'error')
    assert.equal(badToolRef.invocation_status, 'not-started')
    assert.deepEqual(badToolRef.reason_codes, ['correlation-mismatch'])
    assert.equal(badToolRef.invocation_evidence_verified, false)

    const badCapability = await pinned.adapter.execute({
      ...pinned.request,
      request_id: 'req-wrong-capability',
      capability_snapshot_ref: `cap-sha256:${'e'.repeat(64)}`,
    })
    assert.equal(badCapability.execution_status, 'error')
    assert.equal(badCapability.invocation_status, 'not-started')
    assert.deepEqual(badCapability.reason_codes, ['correlation-mismatch'])
    assert.equal(badCapability.invocation_evidence_verified, false)
  } finally {
    await pinned.adapter.reap()
  }
})

test('mixed host：strict tool request 后仍接受 legacy control-protocol/v1 request', async (t) => {
  const pinned = makePinnedToolCase('t.mixed')
  t.after(() => rmSync(pinned.workspaceRoot, { recursive: true, force: true }))
  try {
    pinned.adapter.start()
    const strict = await pinned.adapter.execute(pinned.request)
    assert.equal(strict.execution_status, 'completed')
    assert.equal(strict.invocation_status, 'unknown')
    assert.equal(strict.invocation_evidence_verified, false)

    const legacy = await pinned.adapter.execute({
      request_id: 'req-legacy-after-tool', run_id: 'run-legacy', plan_id: 'plan-legacy',
      test_id: 't-legacy', attempt: 1, input: { op: 'echo', value: { status_code: 200 } },
    })
    assert.equal(legacy.execution_status, 'completed')
    assert.equal(legacy.invocation_status, 'unknown')
    assert.equal(legacy.invocation_evidence_verified, false)
    assert.deepEqual(legacy.observations[0].value, { status_code: 200 })
  } finally {
    await pinned.adapter.reap()
  }
})