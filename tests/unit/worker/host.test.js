/**
 * worker/host.js 单元测试（node:test）。
 * 直接 spawn host 子进程，经 stdin 发 NDJSON request 帧，校验：
 * started 先行、response 后到、correlation 回显一致、echo value 透传、
 * error reason_codes=['worker-error']、stdout 逐行可 JSON.parse（无杂音）。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { buildRequestFrame, buildToolRequestFrame, assertToolResponse, CONTROL_PROTOCOL_VERSION } from '../../../src/protocol/transport.js'
import { TEST_TOOL_PROTOCOL_VERSION } from '../../../src/protocol/enums.js'

// host 是子进程入口：由其自身所在模块目录的相对路径解析出绝对路径。
const HOST_ENTRY = fileURLToPath(new URL('../../../src/worker/host.js', import.meta.url))

// 真实 Cordis built entry（CONTRACT-m3 §0/§3 锚定的 Windows 绝对 file URL）。
const CORDIS_ENTRY = 'file:///D:/deepseek-harness/vendor/cordis/lib/index.js'
// 合规 fixture PUT（worker-owner 自有，避免与 tests-owner 的 put-compliant.js 撞名）。
const PUT_ENTRY = new URL('../../fixtures/put-host-compliant.mjs', import.meta.url).href

const CORRELATION_FIELDS = ['request_id', 'run_id', 'plan_id', 'test_id', 'attempt']

/**
 * 启动 host 子进程，逐帧写入 stdin，收集到进程退出。
 * @param {unknown[]} requestFrames 已构造好的 request 帧对象（会 JSON 序列化写入）。
 * @returns {Promise<{ stdout:string, stderr:string, code:number|null }>}
 */
function runHost(requestFrames, args = []) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [HOST_ENTRY, ...args], { stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    child.stdout.setEncoding('utf8')
    child.stdout.on('data', (chunk) => { stdout += chunk })
    child.stderr.setEncoding('utf8')
    child.stderr.on('data', (chunk) => { stderr += chunk })
    child.on('error', reject)
    child.on('close', (code) => resolve({ stdout, stderr, code }))

    for (const frame of requestFrames) child.stdin.write(JSON.stringify(frame) + '\n')
    child.stdin.end()
  })
}

/** 把 stdout 按行切分并逐行 JSON.parse（任何一行解析失败即抛错 → 体现“无杂音”）。 */
function parseStdout(stdout) {
  return stdout
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line) => JSON.parse(line))
}

/** 断言某帧的 correlation tuple 与请求帧逐字段一致。 */
function assertCorrelation(frame, request) {
  assert.equal(frame.protocol_version, CONTROL_PROTOCOL_VERSION, 'protocol_version echoed')
  for (const key of CORRELATION_FIELDS) {
    assert.equal(frame[key], request[key], `${key} echoed consistently`)
  }
}

test('echo + error：started 先行、correlation 回显、value 透传、error reason、stdout 无杂音', async () => {
  const echoValue = { status_code: 200, body: 'ok' }
  const echoReq = buildRequestFrame({
    request_id: 'req-echo',
    run_id: 'run-1',
    plan_id: 'plan-1',
    test_id: 't-echo',
    attempt: 1,
    input: { op: 'echo', value: echoValue },
    deadline_ms: Date.now() + 5000,
  })
  const errorReq = buildRequestFrame({
    request_id: 'req-error',
    run_id: 'run-1',
    plan_id: 'plan-1',
    test_id: 't-error',
    attempt: 1,
    input: { op: 'error' },
    deadline_ms: Date.now() + 5000,
  })

  const { stdout, code } = await runHost([echoReq, errorReq])
  const frames = parseStdout(stdout) // 任一行非 JSON 会在 parseStdout 抛错 → 测试失败。

  // 顺序：started(echo) → response(echo) → started(error) → response(error)。
  assert.equal(frames.length, 4, 'expected started+response × 2')
  assert.equal(frames[0].kind, 'started')
  assert.equal(frames[0].request_id, 'req-echo')
  assertCorrelation(frames[0], echoReq)
  assert.equal(frames[1].kind, 'response')
  assert.equal(frames[1].request_id, 'req-echo')
  assertCorrelation(frames[1], echoReq)
  assert.equal(frames[2].kind, 'started')
  assert.equal(frames[2].request_id, 'req-error')
  assertCorrelation(frames[2], errorReq)
  assert.equal(frames[3].kind, 'response')
  assert.equal(frames[3].request_id, 'req-error')
  assertCorrelation(frames[3], errorReq)

  // echo response：completed + 单条 observation，value 原样透传。
  const echoResp = frames[1]
  assert.equal(echoResp.execution_status, 'completed')
  assert.deepEqual(echoResp.reason_codes, [])
  assert.equal(echoResp.observations.length, 1)
  const obs = echoResp.observations[0]
  assert.equal(obs.observation_id, 'obs-1')
  assert.equal(obs.source, 'worker')
  assert.deepEqual(obs.limitations, ['l1-subprocess'])
  assert.deepEqual(obs.value, echoValue, 'observation value passed through verbatim')

  // error response：error + 空 observations + reason_codes=['worker-error']。
  const errResp = frames[3]
  assert.equal(errResp.execution_status, 'error')
  assert.deepEqual(errResp.observations, [])
  assert.deepEqual(errResp.reason_codes, ['worker-error'])

  // 正常退出码 0；本用例无 stderr（happy path 不清空也不断言，仅供诊断）。
  assert.equal(code, 0)
})

test('缺省 op 视为 echo（未指定 op 的 request 也能回 completed echo）', async () => {
  const req = buildRequestFrame({
    request_id: 'req-default',
    run_id: 'run-2',
    plan_id: 'plan-2',
    test_id: 't-default',
    attempt: 1,
    input: { value: 'hello' }, // 无 op → 缺省 echo
    deadline_ms: Date.now() + 5000,
  })
  const { stdout } = await runHost([req])
  const frames = parseStdout(stdout)
  assert.equal(frames.length, 2)
  assert.equal(frames[0].kind, 'started')
  assert.equal(frames[1].kind, 'response')
  assert.equal(frames[1].execution_status, 'completed')
  assert.deepEqual(frames[1].observations[0].value, 'hello')
})

test('非法帧（未知版本）→ error response(reason=unknown-version) 后继续读下一帧', async () => {
  const badFrame = {
    protocol_version: 'bogus/v1',
    kind: 'request',
    request_id: 'req-bad',
    run_id: 'run-3',
    plan_id: 'plan-3',
    test_id: 't-bad',
    attempt: 1,
    input: { op: 'echo', value: 1 },
  }
  const goodReq = buildRequestFrame({
    request_id: 'req-good',
    run_id: 'run-3',
    plan_id: 'plan-3',
    test_id: 't-good',
    attempt: 1,
    input: { op: 'echo', value: 2 },
    deadline_ms: Date.now() + 5000,
  })

  const { stdout } = await runHost([badFrame, goodReq])
  const frames = parseStdout(stdout)

  // 非法帧只回一条 error response（无 started）；随后合法帧正常 started+response。
  assert.equal(frames.length, 3)
  assert.equal(frames[0].kind, 'response')
  assert.equal(frames[0].request_id, 'req-bad')
  assert.equal(frames[0].execution_status, 'error')
  assert.deepEqual(frames[0].reason_codes, ['unknown-version'])
  assert.deepEqual(frames[0].observations, [])

  assert.equal(frames[1].kind, 'started')
  assert.equal(frames[1].request_id, 'req-good')
  assert.equal(frames[2].kind, 'response')
  assert.equal(frames[2].request_id, 'req-good')
  assert.equal(frames[2].execution_status, 'completed')
  assert.deepEqual(frames[2].observations[0].value, 2)
})

test('load-put：真实 Cordis 装载合规 fixture PUT → ACTIVE→DISPOSED、effects_count≥1、error=null', async () => {
  const req = buildRequestFrame({
    request_id: 'req-load-put',
    run_id: 'run-m3',
    plan_id: 'plan-m3',
    test_id: 't-load-put',
    attempt: 1,
    input: { op: 'load-put', cordis_entry: CORDIS_ENTRY, put_entry: PUT_ENTRY, put_config: {} },
    deadline_ms: Date.now() + 5000,
  })

  const { stdout, code } = await runHost([req])
  const frames = parseStdout(stdout)

  assert.equal(frames.length, 2)
  assert.equal(frames[0].kind, 'started')
  assertCorrelation(frames[0], req)
  assert.equal(frames[1].kind, 'response')
  assertCorrelation(frames[1], req)

  const resp = frames[1]
  assert.equal(resp.execution_status, 'completed')
  assert.deepEqual(resp.reason_codes, [])
  assert.equal(resp.observations.length, 1)
  const obs = resp.observations[0]
  assert.equal(obs.observation_id, 'obs-1')
  assert.equal(obs.source, 'worker')
  assert.deepEqual(obs.limitations, ['l1-subprocess', 'real-cordis'])

  const value = obs.value
  assert.equal(value.state_after_load, 'ACTIVE')
  assert.ok(value.effects_count >= 1, `effects_count >= 1 (got ${value.effects_count})`)
  assert.equal(value.state_after_dispose, 'DISPOSED')
  assert.equal(value.error, null)
  assert.equal(value.put_state, 'put-host-compliant: loaded')
  assert.equal(code, 0)
})

test('load-put：import 失败 → error response(reason=worker-error)', async () => {
  const req = buildRequestFrame({
    request_id: 'req-load-put-bad',
    run_id: 'run-m3',
    plan_id: 'plan-m3',
    test_id: 't-load-put-bad',
    attempt: 1,
    input: { op: 'load-put', cordis_entry: CORDIS_ENTRY, put_entry: 'file:///D:/nonexistent/definitely-missing-put.mjs', put_config: {} },
    deadline_ms: Date.now() + 5000,
  })

  const { stdout } = await runHost([req])
  const frames = parseStdout(stdout)

  assert.equal(frames.length, 2)
  assert.equal(frames[0].kind, 'started')
  assert.equal(frames[1].kind, 'response')
  assert.equal(frames[1].execution_status, 'error')
  assert.deepEqual(frames[1].observations, [])
  assert.deepEqual(frames[1].reason_codes, ['worker-error'])
})

test('mixed protocols preserve envelopes; binding, digest and missing-artifact preflight failures emit no started', async () => {
  const root = mkdtempSync(join(tmpdir(), 'testbed-host-context-'))
  try {
    const artifactBytes = Buffer.from('export async function run(input) { return { status_code: input.value } }\n')
    const actualDigest = `sha256:${createHash('sha256').update(artifactBytes).digest('hex')}`
    const wrongDigest = `sha256:${'ab'.repeat(32)}`
    const toolRef = { tool_id: 'host.fixture', version: '1.0.0', artifact_digest: actualDigest }
    const badToolRef = { ...toolRef, artifact_digest: wrongDigest }
    const manifest = {
      schema_version: 'test-tool-manifest/v1', tool_id: toolRef.tool_id, tool_version: toolRef.version,
      artifact_digest: actualDigest, role: 'probe',
      runner: { adapter: 'local-worker-json', entrypoint: 'run' },
      input_schema: {
        $schema: 'https://json-schema.org/draft/2020-12/schema', type: 'object',
        properties: { value: { type: 'number' } }, required: ['value'], additionalProperties: false,
      },
      observation_schema: {
        $schema: 'https://json-schema.org/draft/2020-12/schema', type: 'object',
        properties: { status_code: { type: 'integer' } }, required: ['status_code'], additionalProperties: false,
      },
      requires: ['target:plugin'],
      permissions: { filesystem: ['workspace:read'], network: [], subprocess: [], devices: [], secrets: [] },
      limits: {
        timeout_ms: 5000, cpu_ms: 1000, memory_mb: 64, temp_bytes: 1024,
        output_bytes: 4096, attachment_bytes: 1024, processes: 1, concurrency: 1,
      },
      determinism: 'deterministic', retry: { safe: false, max_attempts: 1 },
    }
    const goodArtifact = join(root, 'good.mjs')
    const badArtifact = join(root, 'digest-mismatch.mjs')
    const contextPath = join(root, 'worker-context.json')
    writeFileSync(goodArtifact, artifactBytes)
    writeFileSync(badArtifact, 'export async function run(input) { return { status_code: input.value + 1 } }\n')
    const capRef = `cap-sha256:${'cd'.repeat(32)}`
    writeFileSync(contextPath, JSON.stringify({
      schema_version: 'worker-context/v1',
      bindings: {
        't-host-good': { manifest, artifactPath: goodArtifact, workspaceRoot: root, toolRef },
        't-host-bad-digest': {
          manifest: { ...manifest, artifact_digest: wrongDigest },
          artifactPath: badArtifact,
          workspaceRoot: root,
          toolRef: badToolRef,
        },
        't-host-missing-artifact': {
          manifest,
          artifactPath: join(root, 'missing-artifact.mjs'),
          workspaceRoot: root,
          toolRef,
        },
      },
      capability_snapshot_refs: {
        't-host-good': capRef,
        't-host-bad-digest': capRef,
        't-host-missing-artifact': capRef,
      },
    }))
    const makeToolRequest = (testId, requestId, ref) => buildToolRequestFrame({
      request_id: requestId, run_id: 'run-host-mixed', plan_id: 'plan-host-mixed', test_id: testId, attempt: 1,
      tool_ref: ref,
      target_ref: { kind: 'plugin', owner_put_digest: `sha256:${'ef'.repeat(32)}`, origin: 'host-test' },
      input: { value: 200 }, deadline: new Date(Date.now() + 10000).toISOString(), capability_snapshot_ref: capRef,
    })
    const legacy = buildRequestFrame({
      request_id: 'req-legacy-mixed', run_id: 'run-host-mixed', plan_id: 'plan-host-mixed',
      test_id: 't-legacy-mixed', attempt: 1, input: { op: 'echo', value: 'legacy' }, deadline_ms: Date.now() + 10000,
    })
    const validToolReq = makeToolRequest('t-host-good', 'req-tool-good', toolRef)
    const badDigestReq = makeToolRequest('t-host-bad-digest', 'req-tool-bad-digest', badToolRef)
    const missingArtifactReq = makeToolRequest('t-host-missing-artifact', 'req-tool-missing-artifact', toolRef)
    const missingBindingReq = makeToolRequest('t-host-no-binding', 'req-tool-no-binding', toolRef)
    const { stdout, code } = await runHost(
      [legacy, validToolReq, badDigestReq, missingArtifactReq, missingBindingReq],
      ['--worker-context', contextPath],
    )
    const frames = parseStdout(stdout)

    assert.equal(code, 0)
    assert.deepEqual(frames.map((frame) => [frame.request_id, frame.kind ?? 'tool-response']), [
      ['req-legacy-mixed', 'started'],
      ['req-legacy-mixed', 'response'],
      ['req-tool-good', 'started'],
      ['req-tool-good', 'tool-response'],
      ['req-tool-bad-digest', 'tool-response'],
      ['req-tool-missing-artifact', 'tool-response'],
      ['req-tool-no-binding', 'tool-response'],
    ])
    assertCorrelation(frames[0], legacy)
    assert.equal(frames[0].tool_ref, null)
    assertCorrelation(frames[1], legacy)
    assert.equal(frames[2].protocol_version, CONTROL_PROTOCOL_VERSION)
    assert.equal(frames[2].kind, 'started')
    for (const key of CORRELATION_FIELDS) assert.equal(frames[2][key], validToolReq[key], `${key} echoed for test-tool started`)
    assert.deepEqual(frames[2].tool_ref, validToolReq.tool_ref)
    assert.equal(frames[3].protocol_version, TEST_TOOL_PROTOCOL_VERSION)
    assert.deepEqual(assertToolResponse(frames[3], validToolReq), { ok: true })
    assert.equal(frames[3].execution_status, 'completed', JSON.stringify(frames[3]))
    assert.deepEqual(frames[3].observations[0].value, { status_code: 200 })
    assert.deepEqual(assertToolResponse(frames[4], badDigestReq), { ok: true })
    assert.equal(frames[4].execution_status, 'error')
    assert.deepEqual(frames[4].observations, [])
    assert.ok(frames[4].diagnostics.length > 0)
    for (const [index, request] of [
      [4, badDigestReq],
      [5, missingArtifactReq],
      [6, missingBindingReq],
    ]) {
      assert.deepEqual(assertToolResponse(frames[index], request), { ok: true })
      assert.equal(frames[index].execution_status, 'error')
      assert.deepEqual(frames[index].observations, [])
      assert.equal(frames.some((frame) => frame.request_id === request.request_id && frame.kind === 'started'), false,
        `${request.request_id} preflight failure must not create invocation evidence`)
    }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})