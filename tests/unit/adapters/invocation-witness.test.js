/**
 * 独立 invocation start 见证语义（node:test，真实 spawn）。
 *
 * 核心不变量（architecture §9.5 / §16.1）：
 * - 只有 adapter 自己发起的 OS 进程创建事实可写 `invocation_status=started`；
 * - worker `started` 帧、`ToolResponse`、`RunSpec`、caller 字段、worker 时间戳都不是证据；
 * - 无法核验 → `unknown`；派发前有证据被阻止 → `not-started`；
 * - 见证记录不可变、按固定 request/test/attempt 关联，且不含任何 verdict/gate 字段。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { makeSubprocessAdapter } from '../../../src/adapters/subprocess.js'
import {
  INVOCATION_START_KIND,
  INVOCATION_WITNESS_LIMITATIONS,
  INVOCATION_WITNESS_MECHANISM,
  INVOCATION_WITNESS_SOURCE,
} from '../../../src/adapters/invocation-witness.js'
import {
  LEGACY_FIXTURE,
  assertNoVerdictKeys,
  cleanupDirs,
  makePinnedToolCase,
  makeTempDir,
  unique,
  writeWorkerScript,
} from './_helpers.js'

test('test-tool 成功 attempt：见证按固定 correlation 关联、时间来自 adapter 时钟、深冻结', async (t) => {
  const pinned = makePinnedToolCase({ testId: 't.witness' })
  t.after(async () => {
    await pinned.adapter.reap()
    cleanupDirs(t, [pinned.workspaceRoot])
  })
  pinned.adapter.start()

  const request = pinned.request({ attempt: 3, requestId: 'req-witness-3' })
  const before = Date.now()
  const outcome = await pinned.adapter.execute(request)
  const after = Date.now()

  assert.equal(outcome.execution_status, 'completed')
  assert.equal(outcome.invocation_status, 'started')
  assert.equal(outcome.invocation_evidence_verified, true)
  const event = outcome.invocation_evidence
  assert.ok(event)
  assert.equal(event.kind, INVOCATION_START_KIND)
  assert.equal(event.verified, true)
  assert.deepEqual(event.correlation, {
    request_id: 'req-witness-3',
    run_id: request.run_id,
    plan_id: request.plan_id,
    test_id: 't.witness',
    attempt: 3,
    tool_ref: pinned.toolRef,
  })
  const startedAt = Date.parse(event.started_at)
  assert.ok(Number.isFinite(startedAt), `started_at 必须是 RFC3339: ${event.started_at}`)
  assert.ok(startedAt >= before - 2000 && startedAt <= after + 2000, 'started_at 必须落在 adapter 观测窗口内')

  assert.equal(event.isolation, 'L1-subprocess')
  assert.equal(outcome.started_at, event.started_at, 'attempt 终态只携带已核验的 started_at')
  assert.equal(event.observed.mechanism, INVOCATION_WITNESS_MECHANISM)
  assert.equal(event.observed.source, INVOCATION_WITNESS_SOURCE)
  assert.equal(event.observed.worker_self_report_used, false)
  assert.ok(Number.isSafeInteger(event.observed.child_pid) && event.observed.child_pid > 0)
  assert.equal(event.observed.launcher_pid, process.pid)
  assert.equal(typeof event.observed.pid_alive_at_witness, 'boolean')
  assert.deepEqual(event.limitations, [...INVOCATION_WITNESS_LIMITATIONS])

  // 不可变：调用方无法回填/改写见证。
  assert.ok(Object.isFrozen(event))
  assert.ok(Object.isFrozen(event.correlation))
  assert.ok(Object.isFrozen(event.observed))
  assert.ok(Object.isFrozen(event.limitations))
  assert.throws(() => { event.verified = false }, TypeError)
  assert.throws(() => { event.correlation.test_id = 'tampered' }, TypeError)

  assertNoVerdictKeys(outcome)
})

test('reportInvocationStart：只返回本 adapter、本 run、本 test/attempt 的已核验事件', async (t) => {
  const pinned = makePinnedToolCase({ testId: 't.report' })
  t.after(async () => {
    await pinned.adapter.reap()
    cleanupDirs(t, [pinned.workspaceRoot])
  })
  pinned.adapter.start()

  assert.equal(pinned.adapter.reportInvocationStart(undefined, 't.report', 1), null, '执行前无见证')
  const outcome = await pinned.adapter.execute(pinned.request({ attempt: 2, requestId: 'req-report-2' }))
  assert.equal(outcome.invocation_status, 'started')

  const event = pinned.adapter.reportInvocationStart({ run_id: pinned.adapter.runId }, 't.report', 2)
  assert.ok(event)
  assert.equal(event.kind, INVOCATION_START_KIND)
  assert.deepEqual(event, outcome.invocation_evidence)
  assert.ok(Object.isFrozen(event))

  assert.equal(pinned.adapter.reportInvocationStart(undefined, 't.report', 2), event, 'workerRef 省略时按本 adapter run')
  assert.equal(pinned.adapter.reportInvocationStart({ run_id: 'run-other' }, 't.report', 2), null)
  assert.equal(pinned.adapter.reportInvocationStart('run-other', 't.report', 2), null)
  assert.equal(pinned.adapter.reportInvocationStart({}, 't.report', 2), null)
  assert.equal(pinned.adapter.reportInvocationStart(undefined, 't.other', 2), null)
  assert.equal(pinned.adapter.reportInvocationStart(undefined, 't.report', 1), null)
  assert.equal(pinned.adapter.reportInvocationStart(undefined, 't.report', '2'), null)
  assert.equal(pinned.adapter.reportInvocationStart(undefined, '', 2), null)
})

test('多次 attempt：每个 request/test/attempt 见证彼此独立，不串用', async (t) => {
  const pinned = makePinnedToolCase({ testId: 't.multi' })
  t.after(async () => {
    await pinned.adapter.reap()
    cleanupDirs(t, [pinned.workspaceRoot])
  })
  pinned.adapter.start()

  const first = await pinned.adapter.execute(pinned.request({ attempt: 1, requestId: 'req-multi-1' }))
  const second = await pinned.adapter.execute(pinned.request({ attempt: 2, requestId: 'req-multi-2' }))
  assert.equal(first.invocation_status, 'started')
  assert.equal(second.invocation_status, 'started')

  const e1 = pinned.adapter.reportInvocationStart(undefined, 't.multi', 1)
  const e2 = pinned.adapter.reportInvocationStart(undefined, 't.multi', 2)
  assert.equal(e1.correlation.request_id, 'req-multi-1')
  assert.equal(e2.correlation.request_id, 'req-multi-2')
  assert.equal(e1.correlation.attempt, 1)
  assert.equal(e2.correlation.attempt, 2)
  assert.notEqual(e1.observed.child_pid, e2.observed.child_pid)

  // 另一测试 id 不会复用该见证。
  const other = await pinned.adapter.execute(pinned.request({
    testId: 't.other', requestId: 'req-other-1',
  }))
  // 未 pin 的 test_id → adapter 在派发前拒绝，不产生见证。
  assert.equal(other.invocation_status, 'not-started')
  assert.equal(other.invocation_evidence, null)
  assert.equal(pinned.adapter.reportInvocationStart(undefined, 't.other', 1), null)
})

test('adapter 侧拒绝调用方伪造的 started_at / invocation_status / start_boundary 请求字段', async (t) => {
  const pinned = makePinnedToolCase({ testId: 't.forged-caller' })
  t.after(async () => {
    await pinned.adapter.reap()
    cleanupDirs(t, [pinned.workspaceRoot])
  })
  pinned.adapter.start()

  const forged = {
    ...pinned.request({ requestId: 'req-forged-caller' }),
    started_at: '2026-10-17T00:00:00.000Z',
    invocation_status: 'started',
    start_boundary: { started: true, pid: 1 },
    verdict: 'pass',
    required: true,
  }
  const outcome = await pinned.adapter.execute(forged)
  assert.equal(outcome.execution_status, 'error')
  assert.deepEqual(outcome.reason_codes, ['unknown-field'])
  assert.equal(outcome.invocation_status, 'not-started', '闭集外 caller 字段必须 fail-closed，不得派发')
  assert.equal(outcome.invocation_evidence_verified, false)
  assert.equal(outcome.invocation_evidence, null)
  assert.equal(pinned.adapter.reportInvocationStart(undefined, 't.forged-caller', 1), null)
})

test('legacy worker started 帧：即使 correlation 正确也不产生见证', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry: LEGACY_FIXTURE, runId: unique('legacy-start') })
  try {
    adapter.start()
    const request = {
      request_id: 'req-legacy-start', run_id: 'run-legacy-start', plan_id: 'plan-legacy-start',
      test_id: 't-legacy-start', attempt: 1, input: { op: 'echo', value: 1 },
    }
    const outcome = await adapter.execute(request)
    assert.equal(outcome.execution_status, 'completed')
    assert.equal(outcome.invocation_status, 'unknown')
    assert.equal(outcome.invocation_evidence, null)
    assert.equal(adapter.reportInvocationStart(undefined, request.test_id, request.attempt), null)
  } finally {
    await adapter.reap()
  }
})

test('worker 伪造 verdict / started_at / invocation_status：严格帧拒绝且不产生见证', async (t) => {
  const root = makeTempDir('testbed-forge-')
  cleanupDirs(t, [root])
  const forgedWorker = writeWorkerScript(root, `
import { createInterface } from 'node:readline'
const rl = createInterface({ input: process.stdin })
rl.on('line', (line) => {
  const f = JSON.parse(line)
  const corr = { request_id: f.request_id, run_id: f.run_id, plan_id: f.plan_id, test_id: f.test_id, attempt: f.attempt }
  process.stdout.write(JSON.stringify({
    protocol_version: 'control-protocol/v1', kind: 'started', ...corr,
  }) + '\\n')
  process.stdout.write(JSON.stringify({
    protocol_version: 'control-protocol/v1', kind: 'response', ...corr,
    execution_status: 'completed',
    verdict: 'pass',
    required: true,
    invocation_status: 'started',
    started_at: '2026-10-17T00:00:00.000Z',
    observations: [{ observation_id: 'obs-1', value: { status_code: 200 }, source: 'worker', limitations: [] }],
    reason_codes: [],
  }) + '\\n')
})
`, 'forged-worker.mjs')
  const adapter = makeSubprocessAdapter({ workerEntry: forgedWorker, runId: unique('forged') })
  try {
    adapter.start()
    const outcome = await adapter.execute({
      request_id: 'req-forged-worker', run_id: 'run-forged', plan_id: 'plan-forged',
      test_id: 't-forged', attempt: 1, input: { op: 'echo' },
    })
    assert.equal(outcome.execution_status, 'error')
    assert.deepEqual(outcome.reason_codes, ['unknown-field'])
    assert.equal(outcome.invocation_status, 'unknown')
    assert.equal(outcome.invocation_evidence, null)
    assert.equal(adapter.reportInvocationStart(undefined, 't-forged', 1), null)
  } finally {
    await adapter.reap()
  }
})

test('execution error 的 tool attempt 仍有 OS 启动见证（启动事实与结果分开）', async (t) => {
  const pinned = makePinnedToolCase({
    testId: 't.throws',
    source: 'export async function run() { throw new Error("boom") }\n',
  })
  t.after(async () => {
    await pinned.adapter.reap()
    cleanupDirs(t, [pinned.workspaceRoot])
  })
  pinned.adapter.start()
  const outcome = await pinned.adapter.execute(pinned.request({ input: { status_code: 204 } }))
  assert.equal(outcome.execution_status, 'error')
  assert.equal(outcome.invocation_status, 'started')
  assert.equal(outcome.invocation_evidence_verified, true)
  assert.ok(outcome.invocation_evidence)
  assert.deepEqual(outcome.reason_codes, [])
  assert.equal(outcome.invocation_evidence.correlation.test_id, 't.throws')
})

test('deadline timeout 的 tool attempt：见证来自 OS spawn，不依赖 worker 响应', async (t) => {
  const pinned = makePinnedToolCase({
    testId: 't.slow',
    source: 'export async function run(input) { await new Promise((r) => setTimeout(r, 2000)); return { status_code: input.status_code } }\n',
    adapterOptions: { timeoutMs: 300 },
  })
  t.after(async () => {
    await pinned.adapter.reap()
    cleanupDirs(t, [pinned.workspaceRoot])
  })
  pinned.adapter.start()
  const outcome = await pinned.adapter.execute(pinned.request())
  assert.equal(outcome.execution_status, 'timeout')
  assert.deepEqual(outcome.reason_codes, ['deadline'])
  assert.equal(outcome.invocation_status, 'started')
  assert.equal(outcome.invocation_evidence_verified, true)
  const event = pinned.adapter.reportInvocationStart(undefined, 't.slow', 1)
  assert.ok(event, '超时终态不得抹掉已观测到的启动事实')
})
