/**
 * M6 缺口收口 · 真实 missing_required 注入（node:test，纯 ESM）。
 *
 * 通过**冻结后取消**制造真实缺口：阻塞中的工具 attempt 被控制面取消，其后的
 * expected 项从未派发、也没有任何可核验终态，只能由控制面独立对账为 `missing`
 * （不得伪造逐项 verdict，也不得从 worker stdout 补结果）。
 *
 * 取消时机由工具子进程写出的 marker 文件确定：marker 出现即证明该 attempt 已被
 * 派发且工具逻辑已开始，随后 abort 是真实的运行中取消，不依赖 sleep 竞速。
 *
 *   ① required 缺失 → gate=blocked、exit 2；missing/missing_required 含该项。
 *   ② optional 缺失 → missing 含该项但 missing_required 空；required 无独立
 *      invocation 证据仍 gate=blocked（no-required-started-pass）。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { runSelfCheck } from '../../src/index.js'
import { makeRunSpec } from '../fixtures/run-specs.js'

const DIGEST64 = 'ab'.repeat(32)

function tmpDir() {
  return mkdtempSync(join(tmpdir(), 'testbed-miss-'))
}
/**
 * 产品侧取消/回收已经等待完整进程树（含 runner 孙进程）终止；Windows 上
 * TerminateProcess 返回后目录句柄仍可能由内核/安全软件短暂持有，因此 after-hook
 * 允许有限次 EPERM/EBUSY 重试。重试耗尽仍抛最后一个错误 —— 不吞错、不放宽断言。
 */
const RETRYABLE_CLEANUP_CODES = new Set(['EPERM', 'EBUSY', 'ENOTEMPTY'])
function cleanupWithRetry(dir, { attempts = 8, delayMs = 100 } = {}) {
  return (async () => {
    let lastError = null
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        rmSync(dir, { recursive: true, force: true })
        return
      } catch (err) {
        lastError = err
        if (!RETRYABLE_CLEANUP_CODES.has(err?.code) || attempt === attempts) break
        await new Promise((resolve) => setTimeout(resolve, delayMs))
      }
    }
    throw lastError
  })()
}
function cleanup(t, dir) {
  t.after(async () => { await cleanupWithRetry(dir) })
}
function readReceipt(result) {
  assert.ok(result.receiptPath, `receipt 必须落盘：${result.writeError ?? 'unknown error'}`)
  return JSON.parse(readFileSync(result.receiptPath, 'utf8'))
}

function echoCase(id, classification, needs) {
  const c = {
    test_id: id,
    node_id: id,
    classification,
    criteria: { assert: 'equals', expected: 200 },
    probe: { op: 'echo', value: 200 },
  }
  if (needs !== undefined) c.needs = needs
  return c
}

/** A tool that writes a marker and then blocks: its start is observable, its end is not. */
function blockingToolCase(dir, id, classification, needs) {
  const source = [
    "import { writeFileSync } from 'node:fs'",
    'export async function run(input) {',
    "  writeFileSync(input.marker_path, 'started')",
    '  await new Promise((resolve) => setTimeout(resolve, 60000))',
    '  return { status_code: 200 }',
    '}',
  ].join('\n')
  const artifactPath = join(dir, `${id}.mjs`)
  const markerPath = join(dir, `${id}.marker`)
  writeFileSync(artifactPath, source)
  const artifactDigest = 'sha256:' + createHash('sha256').update(Buffer.from(source)).digest('hex')
  const manifest = {
    schema_version: 'test-tool-manifest/v1',
    tool_id: `fixture.blocking.${id}`,
    tool_version: '1.0.0',
    artifact_digest: artifactDigest,
    role: 'probe',
    runner: { adapter: 'local-worker-json', entrypoint: 'run' },
    input_schema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object',
      properties: { marker_path: { type: 'string' } },
      required: ['marker_path'],
      additionalProperties: false,
    },
    observation_schema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object',
      properties: { status_code: { type: 'integer' } },
      required: ['status_code'],
      additionalProperties: false,
    },
    requires: [],
    permissions: { filesystem: ['workspace:readwrite'], network: [], subprocess: [], devices: [], secrets: [] },
    limits: {
      timeout_ms: 30000, cpu_ms: 15000, memory_mb: 256, temp_bytes: 8388608,
      output_bytes: 1048576, attachment_bytes: 1048576, processes: 1, concurrency: 1,
    },
    determinism: 'deterministic',
    retry: { safe: false, max_attempts: 1 },
  }
  const c = {
    test_id: id,
    node_id: id,
    classification,
    criteria: { assert: 'equals', path: 'status_code', expected: 200 },
    tool: { manifest, input: { marker_path: markerPath }, artifactPath, workspaceRoot: dir },
  }
  if (needs !== undefined) c.needs = needs
  return { caseSpec: c, markerPath }
}

async function waitForMarker(markerPath, timeoutMs = 20000) {
  const start = Date.now()
  while (!existsSync(markerPath)) {
    if (Date.now() - start > timeoutMs) throw new Error(`marker not written: ${markerPath}`)
    await new Promise((resolve) => setTimeout(resolve, 25))
  }
}

/** Start the run, wait until the dispatched tool attempt is provably running, then cancel. */
async function cancelWhileToolRunning(spec, dir, markerPath) {
  const ac = new AbortController()
  const pending = runSelfCheck(spec, {
    executionMode: 'subprocess',
    signal: ac.signal,
    receiptOutDir: dir,
  })
  try {
    await waitForMarker(markerPath)
    ac.abort()
    return await pending
  } finally {
    if (!ac.signal.aborted) ac.abort()
    await pending.catch(() => {})
  }
}

// ---------------------------------------------------------------------------
// ① required 缺失 → blocked
// ---------------------------------------------------------------------------

test('m6-miss ① 冻结后取消导致 required 从未派发 → missing/missing_required，gate=blocked', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const blocking = blockingToolCase(dir, 'req.blocking', 'required')
  const spec = makeRunSpec([
    blocking.caseSpec,
    echoCase('req.later', 'required', ['req.blocking']),
  ], { target: { kind: 'plugin', put_digest: 'sha256:' + DIGEST64 } })

  const out = await cancelWhileToolRunning(spec, dir, blocking.markerPath)
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  assert.equal(receipt.run_status, 'cancelled')
  assert.ok(receipt.reconciliation.expected.includes('req.later'), 'expected 应含 req.later')
  assert.ok(!receipt.reconciliation.executed.includes('req.later'), 'executed 不应含 req.later')
  assert.ok(receipt.reconciliation.missing.includes('req.later'), `missing 应含 req.later，got: ${JSON.stringify(receipt.reconciliation.missing)}`)
  assert.ok(receipt.reconciliation.missing_required.includes('req.later'), `missing_required 应含 req.later，got: ${JSON.stringify(receipt.reconciliation.missing_required)}`)
  // 无逐项 verdict（不伪造终态）
  assert.ok(!receipt.test_cases.some((c) => c.test_id === 'req.later'), 'req.later 不应出现在 test_cases（无逐项 verdict）')
  // 已派发但被取消的阻塞工具保留控制面可关联终态；启动事实仍由 OS spawn 见证
  const blockingCase = receipt.test_cases.find((c) => c.test_id === 'req.blocking')
  assert.equal(blockingCase.execution_status, 'cancelled')
  assert.equal(blockingCase.verdict, 'error')
  assert.equal(blockingCase.invocation_status, 'started')
  assert.equal(blockingCase.invocation_evidence_verified, true)
})

// ---------------------------------------------------------------------------
// ② optional 缺失 → missing_required 为空；unverified required invocation 仍 blocked
// ---------------------------------------------------------------------------

test('m6-miss ② optional 从未派发保持非 required；required 无独立启动证据仍 blocked', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const blocking = blockingToolCase(dir, 'opt.blocking', 'optional', ['req.a'])
  const spec = makeRunSpec([
    echoCase('req.a', 'required'),
    blocking.caseSpec,
    echoCase('opt.after', 'optional', ['opt.blocking']),
  ], { target: { kind: 'plugin', put_digest: 'sha256:' + DIGEST64 } })

  const out = await cancelWhileToolRunning(spec, dir, blocking.markerPath)
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  assert.equal(out.gateReason, 'no-required-started-pass')
  const req = receipt.test_cases.find((c) => c.test_id === 'req.a')
  assert.equal(req.verdict, 'pass')
  assert.equal(req.invocation_status, 'unknown')
  assert.equal(req.invocation_evidence_verified, false)
  assert.ok(receipt.reconciliation.missing.includes('opt.after'), `missing 应含 opt.after，got: ${JSON.stringify(receipt.reconciliation.missing)}`)
  assert.deepEqual(receipt.reconciliation.missing_required, [], 'optional 缺口不产生 missing_required')
  assert.ok(!receipt.test_cases.some((c) => c.test_id === 'opt.after'), 'opt.after 不应出现在 test_cases')
})
