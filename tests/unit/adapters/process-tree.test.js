/**
 * 进程树终止/等待原语的单元测试（node:test，真实 spawn）。
 *
 * 回归点（t7）：Windows 上 `taskkill /T` 是异步子进程；adapter 的
 * cancel/done/reap 必须在**完整进程树（含 runner 孙进程）实测消失后**才 resolve，
 * 且 `pid_alive` 报告要覆盖实际观察到的树，不能用 exit code / 立即返回替代。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  isPidAlive,
  terminateProcessTree,
  waitForPidsGone,
} from '../../../src/adapters/subprocess.js'

const RUNNER_CHILD_ARG = '--local-worker-json-child'
const RUNNER_ENTRY = fileURLToPath(new URL('../../../src/worker/runner.js', import.meta.url))

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function workerDir(prefix = 'testbed-tree-') {
  return mkdtempSync(join(tmpdir(), prefix))
}

function writeScript(dir, source) {
  const path = join(dir, 'tree-worker.mjs')
  writeFileSync(path, source, 'utf8')
  return path
}

/** Read the first stdout line (a pid) from a spawned helper, bounded by timeout. */
function readPidLine(child, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    let buffer = ''
    const timer = setTimeout(() => reject(new Error('pid line timeout')), timeoutMs)
    child.stdout.setEncoding('utf8')
    child.stdout.on('data', (chunk) => {
      buffer += chunk
      const idx = buffer.indexOf('\n')
      if (idx >= 0) {
        clearTimeout(timer)
        resolve(Number(buffer.slice(0, idx)))
      }
    })
    child.once('error', (err) => { clearTimeout(timer); reject(err) })
  })
}

test('terminateProcessTree：等待根进程与已知孙进程全部消失后才 resolve', async () => {
  const dir = workerDir()
  const script = writeScript(dir, `
import { spawn } from 'node:child_process'
const grandchild = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' })
process.stdout.write(String(grandchild.pid) + '\\n')
setInterval(() => {}, 1000)
`)
  const root = spawn(process.execPath, [script], { stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true })
  try {
    const grandchildPid = await readPidLine(root)
    assert.ok(Number.isSafeInteger(grandchildPid) && grandchildPid > 0)
    await sleep(50)
    assert.equal(isPidAlive(root.pid), true)
    assert.equal(isPidAlive(grandchildPid), true)

    const report = await terminateProcessTree(root.pid, {
      knownChildPids: [grandchildPid],
      timeoutMs: 8000,
    })
    assert.equal(report.ok, true, `tree should be gone, remaining=${JSON.stringify(report.remaining)}`)
    assert.equal(isPidAlive(root.pid), false, '根进程必须已终止')
    assert.equal(isPidAlive(grandchildPid), false, 'runner 孙进程必须已终止')
  } finally {
    await terminateProcessTree(root.pid, { timeoutMs: 5000 })
    rmSync(dir, { recursive: true, force: true })
  }
})

test('terminateProcessTree：根进程已退出时仍直接补杀已知孙进程（孤儿清理路径）', async () => {
  const survivor = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore', windowsHide: true })
  const deadRoot = spawn(process.execPath, ['-e', 'process.exit(0)'], { stdio: 'ignore', windowsHide: true })
  try {
    await new Promise((resolve) => deadRoot.once('close', resolve))
    await sleep(100)
    assert.equal(isPidAlive(deadRoot.pid), false, '根进程应已退出')
    assert.equal(isPidAlive(survivor.pid), true, '已知孙进程此时应仍存活')

    const report = await terminateProcessTree(deadRoot.pid, {
      knownChildPids: [survivor.pid],
      timeoutMs: 8000,
    })
    assert.equal(report.ok, true, `known grandchild should be reaped, remaining=${JSON.stringify(report.remaining)}`)
    assert.equal(isPidAlive(survivor.pid), false, '根进程不存在时已知孙进程必须被直接补杀')
  } finally {
    await terminateProcessTree(survivor.pid, { timeoutMs: 5000 })
  }
})

test('waitForPidsGone：超时如实返回 remaining（fail-closed，不虚报清理成功）', async () => {
  const survivor = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore', windowsHide: true })
  try {
    await sleep(100)
    const report = await waitForPidsGone([survivor.pid], { timeoutMs: 120 })
    assert.equal(report.ok, false)
    assert.deepEqual(report.remaining, [survivor.pid])
  } finally {
    await terminateProcessTree(survivor.pid, { timeoutMs: 5000 })
  }
})

test('terminateProcessTree：已退出/非法 pid 立即返回 ok（幂等）', async () => {
  const dead = spawn(process.execPath, ['-e', 'process.exit(0)'], { stdio: 'ignore', windowsHide: true })
  await new Promise((resolve) => dead.once('close', resolve))
  const first = await terminateProcessTree(dead.pid, { timeoutMs: 1000 })
  assert.deepEqual(first, { ok: true, remaining: [] })
  const second = await terminateProcessTree(dead.pid, { timeoutMs: 1000 })
  assert.deepEqual(second, { ok: true, remaining: [] })
  assert.deepEqual(await terminateProcessTree(null), { ok: true, remaining: [] })
})

test('waitForPidsGone：确认成功要求稳定缺失窗口（settleMs），不是单次采样', async () => {
  const child = spawn(process.execPath, ['-e', 'setTimeout(() => process.exit(0), 120)'], {
    stdio: 'ignore',
    windowsHide: true,
  })
  try {
    const startedAt = Date.now()
    const report = await waitForPidsGone([child.pid], { timeoutMs: 8000, settleMs: 200 })
    const elapsed = Date.now() - startedAt
    assert.equal(report.ok, true)
    assert.deepEqual(report.remaining, [])
    assert.ok(elapsed >= 200, `stable-absence window must elapse before success, got ${elapsed}ms`)
    assert.equal(isPidAlive(child.pid), false)
  } finally {
    await terminateProcessTree(child.pid, { timeoutMs: 3000 })
  }
})

test('runner 孙进程 parent-death 守卫：父进程被杀/退出后孙进程必须自行终止（不依赖 taskkill 枚举）', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'testbed-orphan-guard-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  // Tool artifact stays alive for a minute: only the parent-death guard can end
  // the child after the parent process disappears.
  const artifact = Buffer.from('export async function run() { await new Promise((r) => setTimeout(r, 60000)); return {} }\n')
  const envelope = JSON.stringify({
    input: {},
    artifact_b64: artifact.toString('base64'),
    artifact_digest: 'sha256:' + createHash('sha256').update(artifact).digest('hex'),
  })
  // Parent mimics worker/host: spawn the fixed runner child, write one protocol
  // line, keep stdin open, then exit without any cleanup (simulated crash).
  const parentScript = join(dir, 'parent.mjs')
  writeFileSync(parentScript, `
import { spawn } from 'node:child_process'
const child = spawn(process.execPath, [process.argv[2], ${JSON.stringify(RUNNER_CHILD_ARG)}], {
  stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true,
})
child.once('spawn', () => {
  process.stdout.write(String(child.pid) + '\\n')
  child.stdin.write(process.argv[3] + '\\n')
  setTimeout(() => process.exit(0), 1200)
})
`, 'utf8')

  const parent = spawn(process.execPath, [parentScript, RUNNER_ENTRY, envelope], {
    stdio: ['ignore', 'pipe', 'inherit'], windowsHide: true,
  })
  let output = ''
  parent.stdout.setEncoding('utf8')
  parent.stdout.on('data', (chunk) => { output += chunk })
  let childPid = null
  t.after(async () => {
    if (childPid !== null) await terminateProcessTree(childPid, { timeoutMs: 3000 })
  })
  const pidDeadline = Date.now() + 15000
  while (!output.includes('\n')) {
    if (Date.now() > pidDeadline) throw new Error('等待 runner child pid 超时')
    await sleep(20)
  }
  childPid = Number(output.trim().split(/\r?\n/)[0])
  assert.ok(Number.isSafeInteger(childPid) && childPid > 0)
  await sleep(700)
  assert.equal(isPidAlive(childPid), true, '父进程存活期间 runner 孙进程应仍在执行工具')

  await new Promise((resolve) => parent.once('close', resolve))
  const startedAt = Date.now()
  const report = await waitForPidsGone([childPid], { timeoutMs: 8000, settleMs: 100 })
  assert.equal(report.ok, true, `parent-death guard failed, remaining=${JSON.stringify(report.remaining)}`)
  assert.equal(isPidAlive(childPid), false)
  assert.ok(Date.now() - startedAt < 8000)
})

