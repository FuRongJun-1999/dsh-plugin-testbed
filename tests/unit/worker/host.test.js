/**
 * worker/host.js 单元测试（node:test）。
 *
 * 直接 spawn host 子进程，经 stdin 发 NDJSON request 帧，校验：
 * started 先行且无权威时间戳、response 后到、correlation 回显一致、echo value 透传、
 * error reason_codes、stdout 逐行可 JSON.parse（无杂音）、load-put 生命周期、
 * 两阶段能力探测、环境清理与脱敏。
 *
 * 真实 Cordis 在锁定运行环境不可用时由 host 显式报告
 * `cordis-runtime-unavailable`/`unknown`；这些用例用 worker 自有 TEST DOUBLE
 * （`fake-cordis-stub.mjs`，runtime_kind=test-fixture）确定性覆盖生命周期代码路径，
 * 绝不把它标成 `real-cordis`。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { buildRequestFrame, buildToolRequestFrame, assertToolResponse, CONTROL_PROTOCOL_VERSION } from '../../../src/protocol/transport.js'
import { TEST_TOOL_PROTOCOL_VERSION } from '../../../src/protocol/enums.js'
import { RUNTIME_ANCHOR_VERSION } from '../../../src/worker/runtime.js'
import { findForbiddenAuthorityKeys } from '../../../src/worker/observe.js'

const HOST_ENTRY = fileURLToPath(new URL('../../../src/worker/host.js', import.meta.url))

// worker 自有 TEST DOUBLE（非 Cordis；runtime_kind=test-fixture）。
const STUB_RUNTIME_URL = new URL('../../fixtures/fake-cordis-stub.mjs', import.meta.url).href
const PUT_COMPLIANT = new URL('../../fixtures/put-host-compliant.mjs', import.meta.url).href
const PUT_FAILING = new URL('../../fixtures/put-failing.js', import.meta.url).href
const PUT_SECRET_ERROR = new URL('../../fixtures/put-secret-error.mjs', import.meta.url).href
const PUT_HUGE_STATE = new URL('../../fixtures/put-huge-state.mjs', import.meta.url).href
const PUT_DECLARED = new URL('../../fixtures/put-declared.mjs', import.meta.url).href
const PROBE_TIME = '2026-01-01T00:00:00.000Z'
const MISSING_RUNTIME_URL = pathToFileURL(join(tmpdir(), 'testbed-definitely-missing-cordis.mjs')).href
const MISSING_PUT_URL = pathToFileURL(join(tmpdir(), 'testbed-definitely-missing-put.mjs')).href

const CORRELATION_FIELDS = ['request_id', 'run_id', 'plan_id', 'test_id', 'attempt']

function testRuntime(kind = 'test-fixture') {
  return {
    schema_version: RUNTIME_ANCHOR_VERSION,
    cordis_entry: STUB_RUNTIME_URL,
    cordis_version: '0.0.0-fixture',
    runtime_kind: kind,
  }
}

/**
 * 启动 host 子进程，逐帧写入 stdin，收集到进程退出。
 */
function runHost(requestFrames, { args = [], env = null } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [HOST_ENTRY, ...args], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: env ?? process.env,
    })
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

function loadPutRequest(input, ids = {}) {
  return buildRequestFrame({
    request_id: ids.request_id ?? 'req-load-put',
    run_id: ids.run_id ?? 'run-m3',
    plan_id: ids.plan_id ?? 'plan-m3',
    test_id: ids.test_id ?? 't-load-put',
    attempt: 1,
    input: { op: 'load-put', ...input },
    deadline_ms: Date.now() + 5000,
  })
}

function probeRequest(probe, ids = {}) {
  return buildRequestFrame({
    request_id: ids.request_id ?? 'req-probe',
    run_id: ids.run_id ?? 'run-probe',
    plan_id: ids.plan_id ?? 'plan-probe',
    test_id: ids.test_id ?? 't-probe',
    attempt: 1,
    input: { op: 'probe-capabilities', probe },
    deadline_ms: Date.now() + 5000,
  })
}

test('echo + error：started 先行、无权威时间戳、correlation 回显、value 透传、stdout 无杂音', async () => {
  const echoValue = { status_code: 200, body: 'ok' }
  const echoReq = buildRequestFrame({
    request_id: 'req-echo', run_id: 'run-1', plan_id: 'plan-1', test_id: 't-echo', attempt: 1,
    input: { op: 'echo', value: echoValue }, deadline_ms: Date.now() + 5000,
  })
  const errorReq = buildRequestFrame({
    request_id: 'req-error', run_id: 'run-1', plan_id: 'plan-1', test_id: 't-error', attempt: 1,
    input: { op: 'error' }, deadline_ms: Date.now() + 5000,
  })

  const { stdout, code } = await runHost([echoReq, errorReq])
  const frames = parseStdout(stdout)
  assert.equal(frames.length, 4, 'expected started+response × 2')
  assert.equal(frames[0].kind, 'started')
  assertCorrelation(frames[0], echoReq)
  assert.equal(frames[1].kind, 'response')
  assert.equal(frames[1].execution_status, 'completed')
  assert.deepEqual(frames[1].reason_codes, [])
  assert.equal(frames[1].observations[0].source, 'worker')
  assert.deepEqual(frames[1].observations[0].value, echoValue, 'observation value passed through verbatim')

  // started only echoes correlation; it must not carry authority/time fields.
  assert.deepEqual(Object.keys(frames[0]).sort(), [
    'attempt', 'kind', 'plan_id', 'protocol_version', 'request_id', 'run_id', 'test_id', 'tool_ref',
  ])
  assert.equal(JSON.stringify(frames[0]).includes('started_at'), false)
  assert.equal(JSON.stringify(frames[0]).includes('invocation_status'), false)

  assert.equal(frames[2].kind, 'started')
  assert.equal(frames[3].kind, 'response')
  assert.equal(frames[3].execution_status, 'error')
  assert.deepEqual(frames[3].observations, [])
  assert.deepEqual(frames[3].reason_codes, ['worker-error'])
  assert.equal(code, 0)
})

test('缺省 op 视为 echo；非法帧只回 error response 后继续读', async () => {
  const defaultReq = buildRequestFrame({
    request_id: 'req-default', run_id: 'run-2', plan_id: 'plan-2', test_id: 't-default', attempt: 1,
    input: { value: 'hello' }, deadline_ms: Date.now() + 5000,
  })
  const badFrame = {
    protocol_version: 'bogus/v1', kind: 'request', request_id: 'req-bad', run_id: 'run-2',
    plan_id: 'plan-2', test_id: 't-bad', attempt: 1, input: { op: 'echo', value: 1 },
  }
  const { stdout } = await runHost([badFrame, defaultReq])
  const frames = parseStdout(stdout)
  assert.equal(frames.length, 3)
  assert.equal(frames[0].kind, 'response')
  assert.equal(frames[0].request_id, 'req-bad')
  assert.deepEqual(frames[0].reason_codes, ['unknown-version'])
  assert.equal(frames[1].kind, 'started')
  assert.equal(frames[1].request_id, 'req-default')
  assert.equal(frames[2].execution_status, 'completed')
  assert.deepEqual(frames[2].observations[0].value, 'hello')
})

test('load-put：注入的测试运行时装载合规 fixture PUT → ACTIVE→DISPOSED、effects_count≥2、error=null', async () => {
  const req = loadPutRequest({
    cordis_entry: STUB_RUNTIME_URL,
    cordis_version: '0.0.0-fixture',
    dsh_commit: '86a402200d95fecef4529d969836f1fe13c6cb0d',
    runtime_kind: 'test-fixture',
    put_entry: PUT_COMPLIANT,
    put_config: {},
  })
  const { stdout, code } = await runHost([req])
  const frames = parseStdout(stdout)
  assert.equal(frames.length, 2)
  assert.equal(frames[0].kind, 'started')
  assertCorrelation(frames[0], req)
  assertCorrelation(frames[1], req)

  const resp = frames[1]
  assert.equal(resp.execution_status, 'completed')
  assert.deepEqual(resp.reason_codes, [])
  const obs = resp.observations[0]
  assert.equal(obs.source, 'worker')
  assert.ok(obs.limitations.includes('l1-subprocess'))
  assert.ok(obs.limitations.includes('injected-runtime'))
  assert.equal(obs.limitations.includes('real-cordis'), false, 'a test double must never be labelled real Cordis')

  const value = obs.value
  assert.equal(value.state_after_plugin, 'PENDING')
  assert.equal(value.state_after_load, 'ACTIVE')
  assert.ok(value.effects_count >= 2, `effects_count >= 2 (got ${value.effects_count})`)
  assert.equal(value.state_after_dispose, 'DISPOSED')
  assert.equal(value.error, null)
  assert.equal(value.load_phase, null)
  assert.equal(value.put_state, 'put-host-compliant: loaded')
  assert.ok(Array.isArray(value.transitions))
  assert.equal(value.runtime.status, 'available')
  assert.equal(value.runtime.runtime_kind, 'test-fixture')
  assert.equal(value.runtime.cordis_version, '0.0.0-fixture')
  assert.equal(value.runtime.cordis_version_verified, false)
  assert.equal(value.runtime.dsh_commit, '86a402200d95fecef4529d969836f1fe13c6cb0d')
  assert.ok(obs.limitations.includes('dsh-commit-injected-unverified'),
    'a built runtime cannot verify the injected commit')
  assert.equal(code, 0)
})

test('load-put：failing PUT 仍 completed（FAILED/apply 错误是待断言观测值）', async () => {
  const req = loadPutRequest({
    cordis_entry: STUB_RUNTIME_URL,
    runtime_kind: 'test-fixture',
    put_entry: PUT_FAILING,
    put_config: {},
  })
  const { stdout } = await runHost([req])
  const frames = parseStdout(stdout)
  assert.equal(frames[1].execution_status, 'completed')
  const value = frames[1].observations[0].value
  assert.equal(value.state_after_load, 'FAILED')
  assert.equal(value.load_phase, 'host-apply')
  assert.match(value.error, /intentional/)
  assert.equal(value.state_after_dispose, 'DISPOSED')
})

test('load-put：语法错误/非 plugin PUT → error（不伪造 completed 观测）', async () => {
  const syntaxReq = loadPutRequest({
    cordis_entry: STUB_RUNTIME_URL,
    runtime_kind: 'test-fixture',
    put_entry: new URL('../../fixtures/put-syntax-error.mjs', import.meta.url).href,
    put_config: {},
  })
  const nonPluginReq = loadPutRequest({
    cordis_entry: STUB_RUNTIME_URL,
    runtime_kind: 'test-fixture',
    put_entry: new URL('../../fixtures/put-not-plugin.mjs', import.meta.url).href,
    put_config: {},
  })
  const { stdout } = await runHost([syntaxReq, nonPluginReq])
  const frames = parseStdout(stdout)
  for (const frame of [frames[1], frames[3]]) {
    assert.equal(frame.kind, 'response')
    assert.equal(frame.execution_status, 'error')
    assert.deepEqual(frame.observations, [])
    assert.deepEqual(frame.reason_codes, ['worker-error'])
  }
})

test('load-put：错误信息与超大 PUT 状态在 worker 内先脱敏/限长', async () => {
  const secretReq = loadPutRequest({
    cordis_entry: STUB_RUNTIME_URL,
    runtime_kind: 'test-fixture',
    put_entry: PUT_SECRET_ERROR,
    put_config: {},
  })
  const hugeReq = loadPutRequest({
    cordis_entry: STUB_RUNTIME_URL,
    runtime_kind: 'test-fixture',
    put_entry: PUT_HUGE_STATE,
    put_config: {},
  })
  const { stdout } = await runHost([secretReq, hugeReq])
  const frames = parseStdout(stdout)

  // Secret-ish failure text is redacted before it reaches stdout.
  assert.equal(stdout.includes('sk-test000000000000000000000000'), false)
  assert.equal(stdout.includes('token=abcdefghijklmnop'), false)
  const secretValue = frames[1].observations[0].value
  assert.match(secretValue.error, /intentional/)
  assert.ok(secretValue.error.includes('[redacted]'))

  // Oversized PUT state is summarized to a digest, not written raw.
  const hugeObs = frames[3].observations[0]
  assert.ok(hugeObs.limitations.includes('value-summarized'))
  const serialized = JSON.stringify(frames[3])
  assert.ok(Buffer.byteLength(serialized, 'utf8') < 64 * 1024, 'oversized PUT state must stay bounded')
  assert.equal(serialized.includes('x'.repeat(1024)), false)
})

test('load-put：Cordis 入口不可解析时显式 cordis-runtime-unavailable，不伪造结果', async () => {
  const missingCordis = loadPutRequest({
    cordis_entry: MISSING_RUNTIME_URL,
    runtime_kind: 'locked-runtime',
    put_entry: PUT_COMPLIANT,
    put_config: {},
  })
  const { stdout } = await runHost([missingCordis])
  const frames = parseStdout(stdout)
  assert.equal(frames[0].kind, 'started')
  assert.equal(frames[1].execution_status, 'error')
  assert.deepEqual(frames[1].reason_codes, ['cordis-runtime-unavailable'])
  assert.deepEqual(frames[1].observations, [])

  // No injection at all and no resolvable installed runtime in this workspace.
  const noRuntime = loadPutRequest({ put_entry: PUT_COMPLIANT, put_config: {} })
  const noRuntimeRun = await runHost([noRuntime], { env: { SystemRoot: 'C:\\Windows', TEMP: 'C:\\Temp' } })
  const noRuntimeFrames = parseStdout(noRuntimeRun.stdout)
  assert.equal(noRuntimeFrames[1].execution_status, 'error')
  assert.deepEqual(noRuntimeFrames[1].reason_codes, ['cordis-runtime-unavailable'])
})

test('load-put：PUT 入口缺失/非法 → put-entry-invalid', async () => {
  const missingPut = loadPutRequest({
    cordis_entry: STUB_RUNTIME_URL,
    runtime_kind: 'test-fixture',
    put_entry: MISSING_PUT_URL,
    put_config: {},
  })
  const relativePut = loadPutRequest({
    cordis_entry: STUB_RUNTIME_URL,
    runtime_kind: 'test-fixture',
    put_entry: 'relative-put.mjs',
    put_config: {},
  })
  const { stdout } = await runHost([missingPut, relativePut])
  const frames = parseStdout(stdout)
  for (const frame of [frames[1], frames[3]]) {
    assert.equal(frame.execution_status, 'error')
    assert.deepEqual(frame.reason_codes, ['put-entry-invalid'])
  }
})

test('--runtime-anchor CLI 注入锁定运行时描述符；--worker-context 仍可并列使用', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'testbed-host-anchor-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const req = loadPutRequest({ put_entry: PUT_COMPLIANT, put_config: {} })
  const anchorJson = JSON.stringify(testRuntime())
  const { stdout } = await runHost([req], { args: ['--runtime-anchor', anchorJson] })
  const frames = parseStdout(stdout)
  assert.equal(frames[1].execution_status, 'completed')
  assert.equal(frames[1].observations[0].value.state_after_load, 'ACTIVE')

  const rejected = await runHost([req], { args: ['--runtime-anchor', '{}', '--unexpected', 'x'] })
  assert.notEqual(rejected.code, 0, 'unknown arguments fail closed')
})

test('probe-capabilities：两阶段快照含 claim/observed 与绑定指纹，无 verification/verdict', async () => {
  const req = probeRequest({
    probe_time: PROBE_TIME,
    runtime_anchor: testRuntime(),
    cases: [
      { test_id: 'case.echo', probe: { op: 'echo' } },
      { test_id: 'case.load', probe: { op: 'load-put' } },
      { test_id: 'case.tool', tool: { manifest: { requires: ['target:plugin'] } } },
    ],
    put: { entry: PUT_DECLARED },
  })
  const { stdout } = await runHost([req])
  const frames = parseStdout(stdout)
  assert.equal(frames.length, 2)
  assert.equal(frames[0].kind, 'started')
  assertCorrelation(frames[0], req)
  assert.equal(frames[1].execution_status, 'completed')
  assert.deepEqual(frames[1].reason_codes, [])

  const snapshot = frames[1].observations[0].value
  assert.equal(snapshot.snapshot_version, 'capability-snapshot/v1')
  assert.equal(snapshot.source, 'worker')
  assert.equal(snapshot.phase, 'put')
  assert.equal(snapshot.probe_time, PROBE_TIME)
  assert.match(snapshot.environment_fingerprint, /^sha256:[0-9a-f]{64}$/)
  assert.match(snapshot.worker_fingerprint, /^sha256:[0-9a-f]{64}$/)
  assert.equal(snapshot.cases.length, 3)
  assert.equal(snapshot.runtime.status, 'available')
  assert.equal(snapshot.runtime.runtime_kind, 'test-fixture')
  assert.equal(snapshot.phases.put.state_after_load, 'ACTIVE')
  assert.equal(snapshot.phases.put.state_after_dispose, 'DISPOSED')
  assert.ok(snapshot.declarations.capabilities.includes('service:example'))

  const serialized = JSON.stringify(snapshot)
  assert.equal(serialized.includes('"verification"'), false, 'worker must not derive verification')
  assert.equal(serialized.includes('"verdict"'), false)
  assert.equal(serialized.includes('"not_applicable"'), false)
  assert.deepEqual(findForbiddenAuthorityKeys(snapshot), [])
})

test('probe-capabilities：运行时不可用时显式 unavailable + unknown/absent 观测', async () => {
  const req = probeRequest({
    probe_time: PROBE_TIME,
    runtime_anchor: {
      schema_version: RUNTIME_ANCHOR_VERSION,
      cordis_entry: MISSING_RUNTIME_URL,
      runtime_kind: 'locked-runtime',
    },
    cases: [{ test_id: 'case.load', probe: { op: 'load-put' } }],
  })
  const { stdout } = await runHost([req])
  const frames = parseStdout(stdout)
  assert.equal(frames[1].execution_status, 'completed')
  assert.deepEqual(frames[1].reason_codes, ['cordis-runtime-unavailable'])
  const snapshot = frames[1].observations[0].value
  assert.equal(snapshot.runtime.status, 'unavailable')
  assert.equal(snapshot.runtime.reason, 'runtime-entry-missing')
  const cordis = snapshot.phases.env.records.find((record) => record.capability_key === 'host:cordis-runtime')
  assert.equal(cordis.observed, 'absent')
  assert.equal(snapshot.cases[0].observed, 'absent')
  assert.equal(JSON.stringify(snapshot).includes('"verification"'), false)
})

test('probe-capabilities：非法探测请求 → capability-probe-invalid', async () => {
  const bad = buildRequestFrame({
    request_id: 'req-bad-probe', run_id: 'run-probe', plan_id: 'plan-probe',
    test_id: 't-bad-probe', attempt: 1,
    input: { op: 'probe-capabilities', probe: { cases: 'not-an-array' } },
    deadline_ms: Date.now() + 5000,
  })
  const { stdout } = await runHost([bad])
  const frames = parseStdout(stdout)
  assert.equal(frames[1].execution_status, 'error')
  assert.deepEqual(frames[1].reason_codes, ['capability-probe-invalid'])
})

test('env-audit：worker 启动即清理 ambient env，只回传键名/计数', async () => {
  const req = buildRequestFrame({
    request_id: 'req-env-audit', run_id: 'run-env', plan_id: 'plan-env',
    test_id: 't-env-audit', attempt: 1,
    input: { op: 'env-audit' }, deadline_ms: Date.now() + 5000,
  })
  const secret = 'sk-env-audit-secret-value'
  const { stdout } = await runHost([req], {
    env: { ...process.env, OPENAI_API_KEY: secret, DSH_TESTBED_FAKE_SECRET: 'also-secret', MY_CUSTOM_VAR: 'x' },
  })
  const frames = parseStdout(stdout)
  const audit = frames[1].observations[0].value
  assert.equal(audit.schema_version, 'worker-env-audit/v1')
  assert.equal(audit.isolation, 'L1-subprocess')
  assert.ok(audit.credential_name_count >= 2, `credential env names should be removed (got ${audit.credential_name_count})`)
  assert.equal(audit.ambient_credentials_observed, true)
  assert.ok(audit.removed_env_name_count >= 2)
  assert.ok(Array.isArray(audit.kept_env_names))
  assert.equal(audit.ambient_secret_present, undefined)
  assert.equal(stdout.includes(secret), false)
  assert.equal(stdout.includes('also-secret'), false)
})

test('mixed protocols preserve envelopes; binding, digest and missing-artifact preflight failures emit no started', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'testbed-host-context-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
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
    { args: ['--worker-context', contextPath] },
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
})
