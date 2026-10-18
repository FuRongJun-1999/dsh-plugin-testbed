/**
 * src/adapters/subprocess.js 传输/生命周期单元测试（node:test，真实 spawn L1 子进程）。
 *
 * 覆盖：
 * - legacy control-protocol/v1 的内建 smoke 传输（echo/error/sleep）与拒绝语义；
 * - worker started 帧 / 伪造时间戳 / 错配 / 未知帧**永不**产生独立启动见证；
 * - test-tool/v1 的独立启动见证语义（adapter 自己 spawn 的 OS 进程事实）；
 * - preflight admission、串行 in-flight、超时/超限/回收幂等。
 *
 * 隔离定位：L1 普通同权限子进程 = 故障隔离，不是安全边界。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  ADAPTER_REF,
  ENFORCED_LIMITS,
  ISOLATION_LEVEL,
  UNENFORCED_RESOURCES,
  makeSubprocessAdapter,
} from '../../../src/adapters/subprocess.js'
import {
  INVOCATION_START_KIND,
  INVOCATION_WITNESS_LIMITATIONS,
  INVOCATION_WITNESS_MECHANISM,
  INVOCATION_WITNESS_SCOPE,
  INVOCATION_WITNESS_SOURCE,
} from '../../../src/adapters/invocation-witness.js'
import {
  FAKE_TIMESTAMP_FIXTURE,
  LEGACY_FIXTURE,
  WRONG_CORR_FIXTURE,
  assertNoVerdictKeys,
  cleanupDirs,
  makePinnedToolCase,
  makeTempDir,
  unique,
  writeWorkerScript,
} from './_helpers.js'

const exists = async (path) => {
  const { access } = await import('node:fs/promises')
  return access(path).then(() => true, () => false)
}

test('导出：adapter 身份、L1 声明与见证闭集', () => {
  assert.equal(ADAPTER_REF, 'local-worker-json@1.0.0')
  assert.equal(ISOLATION_LEVEL, 'L1-subprocess')
  assert.deepEqual([...UNENFORCED_RESOURCES], ['filesystem', 'network', 'subprocess', 'devices', 'cpu_ms', 'memory_mb'])
  assert.deepEqual([...ENFORCED_LIMITS], [
    'max_frame_bytes', 'max_output_bytes', 'attachment_bytes', 'timeout_ms', 'concurrency', 'max_context_bytes',
  ])
  assert.equal(INVOCATION_START_KIND, 'invocation-start/v1')
  assert.equal(INVOCATION_WITNESS_MECHANISM, 'os-child-spawn')
  assert.equal(INVOCATION_WITNESS_SOURCE, 'control-plane-launcher')
  assert.equal(INVOCATION_WITNESS_SCOPE, 'test-tool-attempts')
  assert.ok(INVOCATION_WITNESS_LIMITATIONS.includes('l1-fault-isolation-is-not-a-security-boundary'))
})

test('echo（legacy）：真实 spawn、observation 归一化、launchRecord 与无 verdict 字段', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry: LEGACY_FIXTURE, runId: unique('echo') })
  try {
    const { pid } = adapter.start()
    assert.ok(Number.isSafeInteger(pid) && pid > 0, 'start() 应返回常驻 worker pid')

    const rec = adapter.launchRecord
    assert.equal(rec.adapter_ref, ADAPTER_REF)
    assert.equal(rec.owner, adapter.runId)
    assert.equal(rec.isolation, 'L1-subprocess')
    assert.equal(rec.pid, pid)
    assert.equal(rec.state, 'ready')
    assert.match(rec.temp_dir, /dsh-testbed-/)
    assert.deepEqual([...rec.enforceable], ENFORCED_LIMITS)
    assert.deepEqual([...rec.unenforced], UNENFORCED_RESOURCES)
    assert.equal(rec.market_conclusion, 'none')
    assert.equal(rec.trust_scope, 'local-only')
    assert.equal(rec.invocation_witness.worker_self_report_used, false)
    assert.ok(await exists(rec.temp_dir))

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
    // legacy control-protocol 没有 adapter 侧 OS 启动事实 → 永远 unknown。
    assert.equal(outcome.invocation_status, 'unknown')
    assert.equal(outcome.invocation_evidence_verified, false)
    assert.equal(outcome.invocation_evidence, null)
    assert.equal(outcome.started_at, null, '未知启动证据不得携带 started_at')
    assert.deepEqual(outcome.observations, [
      { observation_id: 'obs-1', value: { status_code: 200 }, source: 'worker', limitations: ['l1-subprocess'] },
    ])
    assert.deepEqual(outcome.reason_codes, [])
    assertNoVerdictKeys(outcome)
    assert.equal(adapter.state, 'ready')
  } finally {
    await adapter.reap()
  }
})

test('error op：execution_status=error，worker started 通知不产生启动见证', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry: LEGACY_FIXTURE, runId: unique('err') })
  try {
    adapter.start()
    const outcome = await adapter.execute({
      request_id: 'req-err-1', run_id: 'run-err', plan_id: 'plan-err',
      test_id: 't-err', attempt: 1, input: { op: 'error' },
    })
    assert.equal(outcome.admission_status, 'accepted')
    assert.equal(outcome.execution_status, 'error')
    assert.equal(outcome.invocation_status, 'unknown')
    assert.equal(outcome.invocation_evidence_verified, false)
    assert.equal(outcome.invocation_evidence, null)
    assert.deepEqual(outcome.reason_codes, ['worker-error'])
    assertNoVerdictKeys(outcome)
  } finally {
    await adapter.reap()
  }
})

test('timeout：短 timeout + 长 delay → deadline 终态；reap 实测 pid 不存活且临时目录已删', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry: LEGACY_FIXTURE, runId: unique('timeout'), timeoutMs: 300 })
  try {
    adapter.start()
    const outcome = await adapter.execute({
      request_id: 'req-to-1', run_id: 'run-to', plan_id: 'plan-to',
      test_id: 't-to', attempt: 1, input: { op: 'sleep', delay_ms: 5000 },
    })
    assert.equal(outcome.execution_status, 'timeout')
    assert.equal(outcome.invocation_status, 'unknown')
    assert.deepEqual(outcome.reason_codes, ['deadline'])
    assertNoVerdictKeys(outcome)
  } finally {
    const r = await adapter.reap()
    assert.equal(r.pid_alive, false, '超时后 reap 应核验进程树无存活')
    assert.equal(r.temp_removed, true, '超时后回收应删除临时目录')
  }
})

test('bounded output：超出 maxOutputBytes 后拒绝并回收子进程', async (t) => {
  const root = makeTempDir('testbed-oversize-')
  cleanupDirs(t, [root])
  const noisyWorker = writeWorkerScript(root, 'process.stdout.write("x".repeat(10000))\nsetInterval(() => {}, 1000)\n', 'noisy-worker.mjs')
  const adapter = makeSubprocessAdapter({ workerEntry: noisyWorker, runId: unique('oversize'), maxOutputBytes: 128 })
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
  }
})

test('reap()：幂等、实测 pid 不存活 + 临时目录已删（不以 exit code 替代验收）', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry: LEGACY_FIXTURE, runId: unique('reap') })
  const { pid } = adapter.start()
  const tempDir = adapter.launchRecord.temp_dir
  assert.ok(await exists(tempDir))

  const r1 = await adapter.reap()
  assert.equal(r1.pid_alive, false, `reap 后 pid=${pid} 应不存活`)
  assert.equal(r1.temp_removed, true)

  const r2 = await adapter.reap()
  assert.equal(r2.pid_alive, false)
  assert.equal(r2.temp_removed, true)
  assert.equal(adapter.state, 'reaped')
})

test('duplicate：同一 request_id 二次派发 → duplicate', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry: LEGACY_FIXTURE, runId: unique('dup') })
  try {
    adapter.start()
    const req = {
      request_id: 'req-dup-1', run_id: 'run-dup', plan_id: 'plan-dup',
      test_id: 't-dup', attempt: 1, input: { op: 'echo', value: 1 },
    }
    const first = await adapter.execute(req)
    assert.equal(first.execution_status, 'completed')
    const second = await adapter.execute(req)
    assert.equal(second.execution_status, 'error')
    assert.deepEqual(second.reason_codes, ['duplicate'])
    assert.deepEqual(second.observations, [])
    assert.equal(second.invocation_evidence, null)
    assertNoVerdictKeys(second)
  } finally {
    await adapter.reap()
  }
})

test('unknown-version：未知协议版本在 adapter 侧拒绝，不派发', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry: LEGACY_FIXTURE, runId: unique('version') })
  try {
    adapter.start()
    const outcome = await adapter.execute({
      protocol_version: 'control-protocol/v9', request_id: 'req-v9', run_id: 'run-v9',
      plan_id: 'plan-v9', test_id: 't-v9', attempt: 1, input: { op: 'echo' },
    })
    assert.equal(outcome.execution_status, 'error')
    assert.deepEqual(outcome.reason_codes, ['unknown-version'])
    assert.equal(outcome.invocation_status, 'not-started')
    assert.equal(outcome.invocation_evidence, null)
  } finally {
    await adapter.reap()
  }
})

test('out-of-order：串行 in-flight 时第二个 execute 被拒绝且不影响第一个', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry: LEGACY_FIXTURE, runId: unique('ooo') })
  try {
    adapter.start()
    const first = adapter.execute({
      request_id: 'req-ooo-1', run_id: 'run-ooo', plan_id: 'plan-ooo',
      test_id: 't-1', attempt: 1, input: { op: 'sleep', delay_ms: 150 },
    })
    const second = await adapter.execute({
      request_id: 'req-ooo-2', run_id: 'run-ooo', plan_id: 'plan-ooo',
      test_id: 't-2', attempt: 1, input: { op: 'echo', value: 2 },
    })
    assert.equal(second.execution_status, 'error')
    assert.deepEqual(second.reason_codes, ['out-of-order'])
    const firstOutcome = await first
    assert.equal(firstOutcome.execution_status, 'completed')
  } finally {
    await adapter.reap()
  }
})

test('correlation-mismatch：worker response 回显错配 → 拒绝且无启动见证', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry: WRONG_CORR_FIXTURE, runId: unique('corr') })
  try {
    adapter.start()
    const outcome = await adapter.execute({
      request_id: 'req-corr-1', run_id: 'run-corr', plan_id: 'plan-corr',
      test_id: 't-corr', attempt: 1, input: { op: 'echo', value: { status: 'ok' } },
    })
    assert.equal(outcome.execution_status, 'error')
    assert.deepEqual(outcome.reason_codes, ['correlation-mismatch'])
    assert.equal(outcome.invocation_status, 'unknown')
    assert.equal(outcome.invocation_evidence_verified, false)
  } finally {
    await adapter.reap()
  }
})

test('worker 自报 started_at：严格帧校验拒绝，invocation 保持 unknown', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry: FAKE_TIMESTAMP_FIXTURE, runId: unique('fake-ts') })
  try {
    adapter.start()
    const outcome = await adapter.execute({
      request_id: 'req-fake-1', run_id: 'run-fake', plan_id: 'plan-fake',
      test_id: 't-fake', attempt: 1, input: { op: 'echo', value: { status_code: 200 } },
    })
    assert.equal(outcome.execution_status, 'error')
    assert.deepEqual(outcome.reason_codes, ['unknown-field'])
    assert.equal(outcome.invocation_status, 'unknown')
    assert.equal(outcome.invocation_evidence, null)
  } finally {
    await adapter.reap()
  }
})

test('worker started 帧 + 无 response：不产生启动见证，deadline 记 timeout', async (t) => {
  const root = makeTempDir('testbed-started-only-')
  cleanupDirs(t, [root])
  const startedOnly = writeWorkerScript(root, `
import { createInterface } from 'node:readline'
const rl = createInterface({ input: process.stdin })
rl.on('line', (line) => {
  const f = JSON.parse(line)
  process.stdout.write(JSON.stringify({
    protocol_version: 'control-protocol/v1', kind: 'started',
    request_id: f.request_id, run_id: f.run_id, plan_id: f.plan_id, test_id: f.test_id, attempt: f.attempt,
  }) + '\\n')
})
`, 'started-only.mjs')
  const adapter = makeSubprocessAdapter({ workerEntry: startedOnly, runId: unique('started-only'), timeoutMs: 350 })
  try {
    adapter.start()
    const outcome = await adapter.execute({
      request_id: 'req-started-1', run_id: 'run-started', plan_id: 'plan-started',
      test_id: 't-started', attempt: 1, input: { op: 'echo' },
    })
    assert.equal(outcome.execution_status, 'timeout')
    assert.equal(outcome.invocation_status, 'unknown', 'worker started 帧永远不是独立启动证据')
    assert.equal(outcome.invocation_evidence_verified, false)
    assert.equal(outcome.invocation_evidence, null)
    assert.deepEqual(outcome.reason_codes, ['deadline'])
  } finally {
    await adapter.reap()
  }
})

test('非 JSON 杂音：adapter 拒绝 unknown-field，不采信任何后续内容', async (t) => {
  const root = makeTempDir('testbed-noise-')
  cleanupDirs(t, [root])
  const noisy = writeWorkerScript(root, 'process.stdout.write("this is not json\\n")\n', 'noise.mjs')
  const adapter = makeSubprocessAdapter({ workerEntry: noisy, runId: unique('noise') })
  try {
    adapter.start()
    const outcome = await adapter.execute({
      request_id: 'req-noise-1', run_id: 'run-noise', plan_id: 'plan-noise',
      test_id: 't-noise', attempt: 1, input: { op: 'echo' },
    })
    assert.equal(outcome.execution_status, 'error')
    assert.deepEqual(outcome.reason_codes, ['unknown-field'])
    assert.equal(outcome.invocation_evidence, null)
  } finally {
    await adapter.reap()
  }
})

test('test-tool/v1：严格 ToolResponse + adapter 侧独立启动见证', async (t) => {
  const pinned = makePinnedToolCase()
  t.after(async () => {
    await pinned.adapter.reap()
    cleanupDirs(t, [pinned.workspaceRoot])
  })
  pinned.adapter.start()

  const outcome = await pinned.adapter.execute(pinned.request())
  assert.equal(outcome.admission_status, 'accepted')
  assert.equal(outcome.execution_status, 'completed', JSON.stringify(outcome))
  assert.equal(outcome.invocation_status, 'started')
  assert.equal(outcome.invocation_evidence_verified, true)
  assert.ok(outcome.invocation_evidence, '必须有 adapter 侧 OS 启动见证')
  assert.equal(outcome.invocation_evidence.kind, INVOCATION_START_KIND)
  assert.equal(outcome.invocation_evidence.correlation.test_id, pinned.testId)
  assert.deepEqual(outcome.observations, [{
    observation_id: 'obs-1',
    schema_ref: 'example.strict-probe@1.0.0#observation_schema',
    value: { status_code: 204 },
    source: 'worker',
    limitations: [],
  }])
  assert.deepEqual(outcome.diagnostics, [])
  assertNoVerdictKeys(outcome)
})

test('test-tool/v1：preflight 无效 input → spawn 前拒绝（not-started、无见证）', async (t) => {
  const pinned = makePinnedToolCase({ testId: 't.preflight' })
  t.after(async () => {
    await pinned.adapter.reap()
    cleanupDirs(t, [pinned.workspaceRoot])
  })
  pinned.adapter.start()
  const outcome = await pinned.adapter.execute(pinned.request({ input: { status_code: '204' } }))
  assert.equal(outcome.admission_status, 'accepted')
  assert.equal(outcome.execution_status, 'error')
  assert.equal(outcome.invocation_status, 'not-started', '派发前被 adapter admission 阻止 → 有证据的 not-started')
  assert.equal(outcome.invocation_evidence_verified, false)
  assert.equal(outcome.invocation_evidence, null)
  assert.deepEqual(outcome.diagnostics, ['tool-input-schema-invalid'])
  assert.equal(pinned.adapter.reportInvocationStart(undefined, 't.preflight', 1), null)
})

test('test-tool/v1：tool_ref / capability snapshot 不匹配时 adapter 拒绝且无见证', async (t) => {
  const pinned = makePinnedToolCase({ testId: 't.pin-mismatch' })
  t.after(async () => {
    await pinned.adapter.reap()
    cleanupDirs(t, [pinned.workspaceRoot])
  })
  pinned.adapter.start()

  const badToolRef = await pinned.adapter.execute(pinned.request({
    requestId: 'req-wrong-tool-ref',
    toolRef: { ...pinned.toolRef, artifact_digest: `sha256:${'d'.repeat(64)}` },
  }))
  assert.equal(badToolRef.execution_status, 'error')
  assert.equal(badToolRef.invocation_status, 'not-started')
  assert.deepEqual(badToolRef.reason_codes, ['correlation-mismatch'])
  assert.equal(badToolRef.invocation_evidence, null)

  const badCapability = await pinned.adapter.execute(pinned.request({
    requestId: 'req-wrong-capability',
    capabilityRef: `cap-sha256:${'e'.repeat(64)}`,
  }))
  assert.equal(badCapability.execution_status, 'error')
  assert.equal(badCapability.invocation_status, 'not-started')
  assert.deepEqual(badCapability.reason_codes, ['correlation-mismatch'])
  assert.equal(badCapability.invocation_evidence, null)
})

test('mixed：strict tool attempt 之后仍接受 legacy control-protocol/v1 request', async (t) => {
  const pinned = makePinnedToolCase({ testId: 't.mixed' })
  t.after(async () => {
    await pinned.adapter.reap()
    cleanupDirs(t, [pinned.workspaceRoot])
  })
  pinned.adapter.start()

  const strict = await pinned.adapter.execute(pinned.request())
  assert.equal(strict.execution_status, 'completed')
  assert.equal(strict.invocation_status, 'started')

  const legacy = await pinned.adapter.execute({
    request_id: 'req-legacy-after-tool', run_id: 'run-legacy', plan_id: 'plan-legacy',
    test_id: 't-legacy', attempt: 1, input: { op: 'echo', value: { status_code: 200 } },
  })
  assert.equal(legacy.execution_status, 'completed')
  assert.equal(legacy.invocation_status, 'unknown')
  assert.equal(legacy.invocation_evidence_verified, false)
  assert.deepEqual(legacy.observations[0].value, { status_code: 200 })
})

test('没有 workerEntry：构造即 fail-closed', () => {
  assert.throws(() => makeSubprocessAdapter({}), /workerEntry/)
  assert.throws(() => makeSubprocessAdapter({ workerEntry: 'relative/worker.js' }), /absolute path/)
})

test('start() 前 execute：不派发，no-response/not-started', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry: LEGACY_FIXTURE, runId: unique('not-started') })
  const outcome = await adapter.execute({
    request_id: 'req-ns', run_id: 'run-ns', plan_id: 'plan-ns',
    test_id: 't-ns', attempt: 1, input: { op: 'echo' },
  })
  assert.equal(outcome.execution_status, 'error')
  assert.deepEqual(outcome.reason_codes, ['no-response'])
  assert.equal(outcome.invocation_status, 'not-started')
  assert.equal(outcome.invocation_evidence, null)
})
