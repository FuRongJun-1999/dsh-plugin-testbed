/**
 * Adapter 生命周期 / owner / 取消 / 回收 / 跨平台路径 / 凭据边界（node:test，真实 spawn）。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { access } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

import {
  RUNTIME_ANCHOR_ARG,
  buildWorkerEnvironment,
  isPidAlive,
  makeSubprocessAdapter,
} from '../../../src/adapters/subprocess.js'
import {
  CAPABILITY_REF,
  HOST_ENTRY,
  LEGACY_FIXTURE,
  cleanupDirs,
  makeManifest,
  makePinnedToolCase,
  makeTempDir,
  makeToolRequest,
  sha256,
  toolRefFor,
  unique,
  writeToolArtifact,
  writeWorkerScript,
} from './_helpers.js'

const exists = (path) => access(path).then(() => true, () => false)

/**
 * OS process identity (`pid` alone is not identity on Windows: PIDs are recycled
 * quickly under concurrent test load — measured 4 reuses / 120 sequential child
 * spawns on this host). The lifecycle test must prove the *original* runner
 * grandchild is gone, not that no unrelated process ever holds the recycled PID.
 * Returns null for a terminated process object that has no live process entry.
 */
function processStartTime(pid) {
  if (process.platform === 'win32') {
    const script = `$p = Get-Process -Id ${pid} -ErrorAction SilentlyContinue; if ($p) { $p.StartTime.ToUniversalTime().ToString('o') }`
    const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
      encoding: 'utf8', windowsHide: true, timeout: 15000,
    })
    const value = (result.stdout ?? '').trim()
    return value.length > 0 ? value : null
  }
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8')
    return `proc-start:${stat.slice(stat.lastIndexOf(')') + 2).split(' ')[19] ?? ''}`
  } catch {
    return null
  }
}

/** True only when the *same process instance* (pid + start identity) is alive. */
function isSameProcessAlive(pid, startTime) {
  if (!isPidAlive(pid)) return false
  if (startTime === null || startTime === undefined) return true // no identity => stay conservative
  const current = processStartTime(pid)
  if (current === null) return false // terminated object / no live process entry
  return current === startTime
}

/** 一个把 argv/env 作为 observation 回传的 legacy worker（control-protocol/v1）。 */
function writeProbeWorker(dir, name = 'probe-worker.mjs') {
  return writeWorkerScript(dir, `
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
    observations: [{
      observation_id: 'obs-1',
      value: {
        argv: process.argv.slice(2),
        env_keys: Object.keys(process.env).sort(),
        node_no_warnings: process.env.NODE_NO_WARNINGS ?? null,
        canary: process.env.DSH_TESTBED_SECRET_CANARY ?? null,
      },
      source: 'worker',
      limitations: [],
    }],
    reason_codes: [],
  }) + '\\n')
})
`, name)
}

function legacyRequest(overrides = {}) {
  return {
    request_id: unique('req'), run_id: 'run-life', plan_id: 'plan-life',
    test_id: 't-life', attempt: 1, input: { op: 'echo', value: 1 },
    ...overrides,
  }
}

test('reap() 在 start() 前幂等；reaped 后 start() 拒绝', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry: LEGACY_FIXTURE, runId: unique('reap-before') })
  const first = await adapter.reap()
  assert.deepEqual(first, { pid_alive: false, temp_removed: true })
  const second = await adapter.reap()
  assert.deepEqual(second, { pid_alive: false, temp_removed: true })
  assert.equal(adapter.state, 'reaped')
  assert.throws(() => adapter.start(), /already reaped/)

  const outcome = await adapter.execute(legacyRequest())
  assert.equal(outcome.execution_status, 'error')
  assert.deepEqual(outcome.reason_codes, ['no-response'])
  assert.equal(outcome.invocation_status, 'not-started')
})

test('start() 幂等：重复调用返回同一常驻 worker，owner 临时目录不重建', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry: LEGACY_FIXTURE, runId: unique('start-twice') })
  try {
    const first = adapter.start()
    const firstTemp = adapter.launchRecord.temp_dir
    const second = adapter.start()
    assert.equal(second.pid, first.pid)
    assert.equal(adapter.launchRecord.temp_dir, firstTemp)
    assert.ok(await exists(firstTemp))
  } finally {
    await adapter.reap()
  }
})

test('cancel()：空闲取消幂等，之后 execute 记 cancelled 且不派发', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry: LEGACY_FIXTURE, runId: unique('cancel-idle') })
  try {
    adapter.start()
    adapter.cancel()
    adapter.cancel()
    assert.equal(adapter.state, 'stopping')
    const outcome = await adapter.execute(legacyRequest())
    assert.equal(outcome.execution_status, 'error')
    assert.deepEqual(outcome.reason_codes, ['cancelled'])
    assert.equal(outcome.invocation_status, 'not-started')
  } finally {
    await adapter.reap()
  }
})

test('cancel()：执行中取消 → terminal cancelled，reap 后无存活进程、临时目录已删', async () => {
  const adapter = makeSubprocessAdapter({ workerEntry: LEGACY_FIXTURE, runId: unique('cancel-running'), timeoutMs: 10000 })
  try {
    adapter.start()
    const pending = adapter.execute(legacyRequest({ input: { op: 'sleep', delay_ms: 5000 } }))
    setTimeout(() => adapter.cancel(), 120)
    const outcome = await pending
    assert.equal(outcome.execution_status, 'cancelled')
    assert.deepEqual(outcome.reason_codes, ['cancelled'])
    assert.equal(outcome.invocation_status, 'unknown')
  } finally {
    const report = await adapter.reap()
    assert.equal(report.pid_alive, false)
    assert.equal(report.temp_removed, true)
  }
})

test('cancel()：工具 attempt 已取得 OS 见证后取消 → cancelled 且保留启动事实', async (t) => {
  const pinned = makePinnedToolCase({
    testId: 't.cancel-tool',
    source: 'export async function run(input) { await new Promise((r) => setTimeout(r, 3000)); return { status_code: input.status_code } }\n',
    adapterOptions: { timeoutMs: 10000 },
  })
  t.after(async () => {
    await pinned.adapter.reap()
    cleanupDirs(t, [pinned.workspaceRoot])
  })
  pinned.adapter.start()

  const pending = pinned.adapter.execute(pinned.request({ requestId: 'req-cancel-tool' }))
  const waitUntilWitness = Date.now() + 5000
  while (pinned.adapter.reportInvocationStart(undefined, 't.cancel-tool', 1) === null) {
    if (Date.now() > waitUntilWitness) throw new Error('等待 tool attempt 启动见证超时')
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
  pinned.adapter.cancel()
  const outcome = await pending
  assert.equal(outcome.execution_status, 'cancelled')
  assert.deepEqual(outcome.reason_codes, ['cancelled'])
  assert.equal(outcome.invocation_status, 'started', '启动事实不受取消影响')
  assert.equal(outcome.invocation_evidence_verified, true)
  assert.ok(outcome.started_at)
})

/**
 * t7 回归：阻塞工具的 runner 孙进程 cwd 固定为 workspaceRoot；Windows 上若
 * adapter 在孙进程仍存活/句柄未释放时 resolve，测试 after-hook 的 rmSync 会偶发 EPERM。
 * 这里用工具自己写入的 pid 直接断言「execute resolve 时孙进程已死」，并重复多轮。
 */
test('cancel()/reap()：等 runner 孙进程真正终止后才 resolve，workspace 可立即删除', async (t) => {
  const workspaceRoot = makeTempDir('testbed-tree-cancel-')
  cleanupDirs(t, [workspaceRoot])
  const source = [
    "import { writeFileSync } from 'node:fs'",
    'export async function run(input) {',
    '  writeFileSync(input.marker_path, String(process.pid))',
    '  await new Promise((resolve) => setTimeout(resolve, 60000))',
    '  return { status_code: 200 }',
    '}',
  ].join('\n')
  const artifact = writeToolArtifact(workspaceRoot, { source })
  const manifest = makeManifest({
    artifact_digest: artifact.artifactDigest,
    input_schema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object',
      properties: { marker_path: { type: 'string' } },
      required: ['marker_path'],
      additionalProperties: false,
    },
  })
  const toolRef = toolRefFor(manifest)
  const testId = 't.cancel-tree'
  const toolPids = []

  for (let iteration = 1; iteration <= 3; iteration += 1) {
    const markerPath = join(workspaceRoot, `tool-${iteration}.marker`)
    const adapter = makeSubprocessAdapter({
      workerEntry: HOST_ENTRY,
      runId: unique(`cancel-tree-${iteration}`),
      timeoutMs: 10000,
      toolBindings: {
        [testId]: { manifest, artifactPath: artifact.artifactPath, workspaceRoot, toolRef },
      },
      capabilitySnapshotRefs: { [testId]: CAPABILITY_REF },
    })
    try {
      adapter.start()
      const pending = adapter.execute(makeToolRequest({
        testId,
        toolRef,
        input: { marker_path: markerPath },
        requestId: `req-cancel-tree-${iteration}`,
      }))
      const waitUntil = Date.now() + 15000
      while (!existsSync(markerPath)) {
        if (Date.now() > waitUntil) throw new Error(`等待工具 marker 超时: ${markerPath}`)
        await new Promise((resolve) => setTimeout(resolve, 20))
      }
      const toolPid = Number(readFileSync(markerPath, 'utf8'))
      assert.ok(Number.isSafeInteger(toolPid) && toolPid > 0, '工具必须回传自身 pid')
      assert.equal(isPidAlive(toolPid), true, '取消前工具孙进程应存活')
      const toolStartIdentity = processStartTime(toolPid)
      toolPids.push({ pid: toolPid, startTime: toolStartIdentity })

      adapter.cancel()
      const outcome = await pending
      assert.equal(outcome.execution_status, 'cancelled')
      assert.equal(outcome.invocation_status, 'started')
      assert.equal(
        isPidAlive(toolPid),
        false,
        'execute resolve 时 runner 孙进程必须已终止（否则 Windows workspace 回收会 EPERM）',
      )

      const report = await adapter.reap()
      assert.equal(report.pid_alive, false, 'cleanup 报告必须覆盖实际进程树')
      assert.equal(report.temp_removed, true)
    } finally {
      await adapter.reap()
    }
  }

  // The late cross-iteration check must not use a bare recycled PID: under the
  // concurrent full-suite runner Windows recycles PIDs for unrelated processes
  // within milliseconds. Prove the *original process instances* are gone (pid +
  // OS start identity), which is the actual security/resource invariant. The
  // immediate `isPidAlive` assertions above are intentionally kept unchanged.
  const identityDeadline = Date.now() + 3000
  let survivors = toolPids.filter(({ pid, startTime }) => isSameProcessAlive(pid, startTime))
  while (survivors.length > 0 && Date.now() < identityDeadline) {
    await new Promise((resolve) => setTimeout(resolve, 50))
    survivors = toolPids.filter(({ pid, startTime }) => isSameProcessAlive(pid, startTime))
  }
  assert.deepEqual(
    survivors,
    [],
    `runner 孙进程的原始进程实例必须全部终止（按 pid+start identity，排除并发 PID 复用）: ${JSON.stringify(survivors)}`,
  )
  // 立即删除 owner workspace：修复前该步骤会在 Windows 上偶发 EPERM。
  assert.doesNotThrow(() => rmSync(workspaceRoot, { recursive: true, force: true }))
})

test('reap()：attempt 仍 in-flight（未 cancel）时也等待完整进程树终止', async (t) => {
  const workspaceRoot = makeTempDir('testbed-tree-reap-')
  cleanupDirs(t, [workspaceRoot])
  const source = [
    "import { writeFileSync } from 'node:fs'",
    'export async function run(input) {',
    '  writeFileSync(input.marker_path, String(process.pid))',
    '  await new Promise((resolve) => setTimeout(resolve, 60000))',
    '  return { status_code: 200 }',
    '}',
  ].join('\n')
  const artifact = writeToolArtifact(workspaceRoot, { source })
  const manifest = makeManifest({
    artifact_digest: artifact.artifactDigest,
    input_schema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object',
      properties: { marker_path: { type: 'string' } },
      required: ['marker_path'],
      additionalProperties: false,
    },
  })
  const toolRef = toolRefFor(manifest)
  const markerPath = join(workspaceRoot, 'reap-tool.marker')
  const adapter = makeSubprocessAdapter({
    workerEntry: HOST_ENTRY,
    runId: unique('reap-inflight'),
    timeoutMs: 10000,
    toolBindings: { 't.reap-tree': { manifest, artifactPath: artifact.artifactPath, workspaceRoot, toolRef } },
    capabilitySnapshotRefs: { 't.reap-tree': CAPABILITY_REF },
  })
  t.after(async () => {
    await adapter.reap()
    cleanupDirs(t, [workspaceRoot])
  })
  adapter.start()
  const pending = adapter.execute(makeToolRequest({
    testId: 't.reap-tree', toolRef, input: { marker_path: markerPath }, requestId: 'req-reap-tree',
  }))
  const waitUntil = Date.now() + 15000
  while (!existsSync(markerPath)) {
    if (Date.now() > waitUntil) throw new Error('等待工具 marker 超时')
    await new Promise((resolve) => setTimeout(resolve, 20))
  }
  const toolPid = Number(readFileSync(markerPath, 'utf8'))

  const report = await adapter.reap()
  await pending
  assert.equal(report.pid_alive, false, 'reap 报告必须等待实际树终止')
  assert.equal(isPidAlive(toolPid), false, 'reap resolve 后孙进程必须已终止')
  assert.doesNotThrow(() => rmSync(workspaceRoot, { recursive: true, force: true }))
})

test('worker 环境：显式非密钥白名单，不透传 ambient credentials / PATH', async (t) => {
  const root = makeTempDir('testbed-env-')
  cleanupDirs(t, [root])
  const worker = writeProbeWorker(root)
  process.env.DSH_TESTBED_SECRET_CANARY = 'super-secret-canary'
  const adapter = makeSubprocessAdapter({ workerEntry: worker, runId: unique('env') })
  t.after(() => { delete process.env.DSH_TESTBED_SECRET_CANARY })
  try {
    adapter.start()
    const outcome = await adapter.execute(legacyRequest())
    assert.equal(outcome.execution_status, 'completed', JSON.stringify(outcome))
    const value = outcome.observations[0].value
    assert.equal(value.canary, null, 'worker 不得继承 ambient credential')
    assert.ok(!value.env_keys.includes('DSH_TESTBED_SECRET_CANARY'))
    if (process.platform !== 'win32') {
      // Windows 的 OS/Node 会补入少量非密钥用户变量（如 PATH/USERPROFILE）；
      // POSIX 下环境应与显式白名单一致。
      assert.ok(!value.env_keys.includes('PATH'), '最小环境不继承 PATH')
    }
    assert.equal(value.node_no_warnings, '1')
    if (process.platform === 'win32') {
      assert.ok(value.env_keys.includes('SystemRoot'), 'Windows 需要 SystemRoot 才能启动 Node')
    }
    // 纯函数语义：whitelist 之外一律剔除。
    const built = buildWorkerEnvironment({ SystemRoot: 'C:\\Windows', SECRET_TOKEN: 'x', PATH: '/usr/bin' })
    assert.equal(built.NODE_NO_WARNINGS, '1')
    assert.ok(!('SECRET_TOKEN' in built))
    assert.ok(!('PATH' in built))
  } finally {
    await adapter.reap()
  }
})

test('runtime anchor：只作为可信 constructor 配置透传为固定 argv，并出现在 launchRecord', async (t) => {
  const root = makeTempDir('testbed-anchor-')
  cleanupDirs(t, [root])
  const worker = writeProbeWorker(root, 'anchor-worker.mjs')
  const anchor = JSON.stringify({ schema_version: 'testbed-runtime-anchor/v1', cordis_entry: 'file:///locked/cordis.js' })
  const adapter = makeSubprocessAdapter({ workerEntry: worker, runId: unique('anchor'), runtimeAnchor: anchor })
  try {
    adapter.start()
    assert.equal(adapter.launchRecord.runtime_anchor_configured, true)
    const outcome = await adapter.execute(legacyRequest())
    const argv = outcome.observations[0].value.argv
    const index = argv.indexOf(RUNTIME_ANCHOR_ARG)
    assert.ok(index >= 0, `argv 应包含 ${RUNTIME_ANCHOR_ARG}: ${JSON.stringify(argv)}`)
    assert.equal(argv[index + 1], anchor)
  } finally {
    await adapter.reap()
  }
  assert.throws(
    () => makeSubprocessAdapter({ workerEntry: worker, runtimeAnchor: 42 }),
    /runtimeAnchor/,
  )
  assert.throws(
    () => makeSubprocessAdapter({ workerEntry: worker, runtimeAnchor: 'bad\0anchor' }),
    /runtimeAnchor/,
  )
})

test('workerEntry：支持 file: URL；不存在时 start() fail-closed', async () => {
  const adapter = makeSubprocessAdapter({
    workerEntry: pathToFileURL(LEGACY_FIXTURE).href,
    runId: unique('file-url'),
  })
  try {
    adapter.start()
    const outcome = await adapter.execute(legacyRequest())
    assert.equal(outcome.execution_status, 'completed')
  } finally {
    await adapter.reap()
  }

  const missing = makeSubprocessAdapter({
    workerEntry: join(tmpdir(), `missing-worker-${unique('x')}.mjs`),
    runId: unique('missing'),
  })
  assert.throws(() => missing.start(), /does not exist/)
  assert.equal(missing.state, 'failed')
  await missing.reap()
})

test('跨平台路径：workspaceRoot 外的 artifact 在构造期拒绝', () => {
  const root = makeTempDir('testbed-path-root-')
  const outside = makeTempDir('testbed-path-outside-')
  try {
    const artifact = writeToolArtifact(outside)
    const manifest = makeManifest({ artifact_digest: artifact.artifactDigest })
    assert.throws(() => makeSubprocessAdapter({
      workerEntry: HOST_ENTRY,
      runId: unique('outside'),
      toolBindings: {
        't.outside': {
          manifest,
          artifactPath: artifact.artifactPath,
          workspaceRoot: root,
          toolRef: toolRefFor(manifest),
        },
      },
      capabilitySnapshotRefs: { 't.outside': CAPABILITY_REF },
    }), /below workspaceRoot/)
  } finally {
    rmSync(root, { recursive: true, force: true })
    rmSync(outside, { recursive: true, force: true })
  }
})

test('跨平台路径：symlink/junction 逃逸在 start() 的 realpath 核验处拒绝', async (t) => {
  const root = makeTempDir('testbed-link-root-')
  const outside = makeTempDir('testbed-link-outside-')
  cleanupDirs(t, [root, outside])
  const artifact = writeToolArtifact(outside)
  const link = join(root, 'escape')
  try {
    symlinkSync(outside, link, process.platform === 'win32' ? 'junction' : 'dir')
  } catch (err) {
    t.skip(`无法创建目录链接（环境限制）：${err.code ?? err.message}`)
    return
  }
  const manifest = makeManifest({ artifact_digest: artifact.artifactDigest })
  const adapter = makeSubprocessAdapter({
    workerEntry: HOST_ENTRY,
    runId: unique('link'),
    toolBindings: {
      't.link': {
        manifest,
        artifactPath: join(link, 'tool.mjs'),
        workspaceRoot: root,
        toolRef: toolRefFor(manifest),
      },
    },
    capabilitySnapshotRefs: { 't.link': CAPABILITY_REF },
  })
  await assert.rejects(async () => adapter.start(), /below workspaceRoot|not resolvable/)
})

test('跨平台路径：含空格的工作区/工具路径可正常执行并产生见证', async (t) => {
  const workspaceRoot = mkdtempSync(join(tmpdir(), 'testbed space '))
  cleanupDirs(t, [workspaceRoot])
  mkdirSync(join(workspaceRoot, 'sub dir'), { recursive: true })
  const source = 'export async function run(input) { return { status_code: input.status_code } }\n'
  const artifactBytes = Buffer.from(source, 'utf8')
  const artifactPath = join(workspaceRoot, 'sub dir', 'tool with space.mjs')
  writeFileSync(artifactPath, artifactBytes)
  const digest = sha256(artifactBytes)
  const manifest = makeManifest({ artifact_digest: digest })
  const adapter = makeSubprocessAdapter({
    workerEntry: HOST_ENTRY,
    runId: unique('spaces'),
    toolBindings: {
      't.spaces': { manifest, artifactPath, workspaceRoot, toolRef: toolRefFor(manifest) },
    },
    capabilitySnapshotRefs: { 't.spaces': CAPABILITY_REF },
  })
  try {
    adapter.start()
    const request = makeToolRequest({
      testId: 't.spaces',
      toolRef: toolRefFor(manifest),
      input: { status_code: 201 },
      requestId: 'req-spaces-1',
    })
    const outcome = await adapter.execute(request)
    assert.equal(outcome.execution_status, 'completed', JSON.stringify(outcome))
    assert.equal(outcome.invocation_status, 'started')
    assert.deepEqual(outcome.observations[0].value, { status_code: 201 })
  } finally {
    await adapter.reap()
  }
})

test('owner 隔离：两个 adapter 的临时目录互不复用，回收互不影响', async () => {
  const first = makeSubprocessAdapter({ workerEntry: LEGACY_FIXTURE, runId: unique('owner-a') })
  const second = makeSubprocessAdapter({ workerEntry: LEGACY_FIXTURE, runId: unique('owner-b') })
  try {
    first.start()
    second.start()
    const firstTemp = first.launchRecord.temp_dir
    const secondTemp = second.launchRecord.temp_dir
    assert.notEqual(firstTemp, secondTemp)
    assert.match(firstTemp, new RegExp(first.runId.replace(/[^A-Za-z0-9_.-]/g, '_')))

    const firstReap = await first.reap()
    assert.equal(firstReap.temp_removed, true)
    assert.equal(await exists(firstTemp), false)
    assert.equal(await exists(secondTemp), true, '回收 A 不得影响 B 的 owner 临时目录')

    const secondReap = await second.reap()
    assert.equal(secondReap.temp_removed, true)
  } finally {
    await first.reap()
    await second.reap()
  }
})

test('maxContextBytes 过小：start() fail-closed 且清理临时目录', async (t) => {
  const pinned = makePinnedToolCaseWithLimits()
  t.after(() => cleanupDirs(t, [pinned.workspaceRoot]))
  assert.throws(() => pinned.adapter.start(), /maxContextBytes/)
  assert.equal(pinned.adapter.state, 'failed')
  assert.equal(pinned.adapter.launchRecord.temp_dir, null)
  const report = await pinned.adapter.reap()
  assert.equal(report.temp_removed, true)
})

function makePinnedToolCaseWithLimits() {
  const workspaceRoot = makeTempDir('testbed-context-')
  const artifact = writeToolArtifact(workspaceRoot)
  const manifest = makeManifest({ artifact_digest: artifact.artifactDigest })
  const toolRef = toolRefFor(manifest)
  const adapter = makeSubprocessAdapter({
    workerEntry: HOST_ENTRY,
    runId: unique('context'),
    maxContextBytes: 8,
    toolBindings: { 't.context': { manifest, artifactPath: artifact.artifactPath, workspaceRoot, toolRef } },
    capabilitySnapshotRefs: { 't.context': CAPABILITY_REF },
  })
  return { adapter, workspaceRoot }
}
