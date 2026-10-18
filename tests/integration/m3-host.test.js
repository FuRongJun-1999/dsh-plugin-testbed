/**
 * M3 集成 · 真实宿主纵向闭环（node:test，真实 spawn 子进程走 subprocess adapter）。
 *
 * 通过公共门面 `runSelfCheck(spec, { executionMode:'subprocess' })`，用 worker 子进程内
 * 两阶段能力探测 + PUT 加载（`probe.op='load-put'`），覆盖：
 *   1. 契约/加载卸载（put-compliant → ACTIVE → DISPOSED，effects_count>=1）
 *   2. 失败 fail-closed（put-failing → FAILED + error 含 intentional）
 *   3. 两阶段探测 → 冻结 Plan → 同一固定探测时钟下 `plan_id` 确定性
 *   4. 真实 Cordis 不可用 → 显式 blocked/unknown，绝不伪造 present/pass
 *
 * 运行时锚定：本机没有可复现的锁定 Cordis 安装，因此生命周期用例显式注入
 * `tests/fixtures/fake-cordis-stub.mjs`（runtime_kind=test-fixture，测试替身，非 Cordis）。
 * 不再硬编码任何主机 checkout 路径；provenance 必须反映被注入的锚点与真实未知项。
 * PUT 摘要由测试对测试实际字节计算，内核在加载前独立 pin 并比对 RunSpec target。
 * receiptOutDir 用 os.tmpdir 随机子目录，测试后清理，不污染源码树。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { runSelfCheck } from '../../src/index.js'
import { makeRuntimeAnchor } from '../../src/worker/runtime.js'
import { validateReceiptV1 } from '../../src/protocol/contracts.js'
import { makeRunSpec, makeCase } from '../fixtures/run-specs.js'

// TEST DOUBLE（非 Cordis；runtime_kind=test-fixture）。
const STUB_RUNTIME_URL = new URL('../fixtures/fake-cordis-stub.mjs', import.meta.url).href
const PUT_COMPLIANT_URL = new URL('../fixtures/put-compliant.js', import.meta.url).href
const PUT_FAILING_URL = new URL('../fixtures/put-failing.js', import.meta.url).href
const MISSING_RUNTIME_URL = new URL('../fixtures/definitely-missing-runtime.mjs', import.meta.url).href
const PROBE_TIME = '2026-01-01T00:00:00.000Z'

function putDigestOf(url) {
  return 'sha256:' + createHash('sha256').update(readFileSync(fileURLToPath(url))).digest('hex')
}

function fixtureRuntime() {
  return makeRuntimeAnchor({
    cordis_entry: STUB_RUNTIME_URL,
    cordis_version: '0.0.0-fixture',
    runtime_kind: 'test-fixture',
  })
}

function tmpDir() {
  return mkdtempSync(join(tmpdir(), 'testbed-m3-'))
}

function readReceipt(result) {
  assert.ok(result.receiptPath, `receipt 必须落盘：${result.writeError ?? 'unknown error'}`)
  return JSON.parse(readFileSync(result.receiptPath, 'utf8'))
}

function cleanup(t, dir) {
  t.after(() => rmSync(dir, { recursive: true, force: true }))
}

/** 构造一个 `load-put` required 用例。 */
function loadPutCase(id, putEntry, criteria) {
  return makeCase({
    test_id: id,
    node_id: id,
    classification: 'required',
    criteria,
    probe: { op: 'load-put', put_entry: putEntry, put_config: {} },
  })
}

function runLoadPutSpecs(cases, putUrl, dir, extra = {}) {
  const spec = makeRunSpec(cases, {
    target: { kind: 'plugin', put_digest: putDigestOf(putUrl) },
  })
  return runSelfCheck(spec, {
    executionMode: 'subprocess',
    runtimeAnchor: fixtureRuntime(),
    probeTime: PROBE_TIME,
    receiptOutDir: dir,
    ...extra,
  })
}

// ---------------------------------------------------------------------------
// §4.1 契约/加载卸载：put-compliant 走两阶段真实宿主生命周期
// ---------------------------------------------------------------------------

test('M3: put-compliant lifecycle is observable; legacy load-put stays unknown and gate blocked', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const out = await runLoadPutSpecs([
    loadPutCase('m3.compliant.load', PUT_COMPLIANT_URL, {
      assert: 'equals', path: 'state_after_load', expected: 'ACTIVE',
    }),
    loadPutCase('m3.compliant.dispose', PUT_COMPLIANT_URL, {
      assert: 'equals', path: 'state_after_dispose', expected: 'DISPOSED',
    }),
  ], PUT_COMPLIANT_URL, dir)

  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  assert.equal(validateReceiptV1(receipt).ok, true, JSON.stringify(validateReceiptV1(receipt).errors))
  for (const id of ['m3.compliant.load', 'm3.compliant.dispose']) {
    const tc = receipt.test_cases.find((c) => c.test_id === id)
    assert.equal(tc.verdict, 'pass')
    assert.equal(tc.invocation_status, 'unknown', 'legacy load-put has no OS-spawn witness')
    assert.equal(tc.invocation_evidence_verified, false)
  }

  const obs = receipt.observations[0]
  assert.equal(obs.source, 'worker')
  assert.equal(obs.value.state_after_load, 'ACTIVE')
  assert.equal(obs.value.state_after_dispose, 'DISPOSED')
  assert.ok(obs.value.effects_count >= 1, 'apply 曾注册 effect，effects_count 应 >= 1')

  // provenance 绑定注入锚点（无真实 Cordis 时 cordis_version_verified=false，dsh_commit 保持 null）
  assert.equal(receipt.provenance.cordis_version, '0.0.0-fixture')
  assert.equal(receipt.provenance.dsh_commit, null)
  assert.equal(receipt.provenance.put_digest, putDigestOf(PUT_COMPLIANT_URL))
  assert.ok(receipt.limitations.includes('non-locked-runtime'))
  assert.ok(receipt.limitations.includes('cordis-version-unverified'))
})

// ---------------------------------------------------------------------------
// §4.2 失败 fail-closed：put-failing → FAILED + error 含 intentional
// ---------------------------------------------------------------------------

test('M3: put-failing fail-closed verdicts are preserved while gate blocks without invocation evidence', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const out = await runLoadPutSpecs([
    loadPutCase('m3.failing.load', PUT_FAILING_URL, {
      assert: 'equals', path: 'state_after_load', expected: 'FAILED',
    }),
    loadPutCase('m3.failing.error', PUT_FAILING_URL, {
      assert: 'contains', path: 'error', expected: 'intentional',
    }),
  ], PUT_FAILING_URL, dir)

  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  for (const id of ['m3.failing.load', 'm3.failing.error']) {
    const tc = receipt.test_cases.find((c) => c.test_id === id)
    assert.equal(tc.verdict, 'pass', `${id} 应正确检测到失败（fail-closed 仍为 pass）`)
  }
})

// ---------------------------------------------------------------------------
// §4.3 two-phase probe/freeze: same snapshot binds to a deterministic plan_id.
// ---------------------------------------------------------------------------

test('M3: identical frozen capability snapshots yield stable plan_id; invocation remains unknown', async (t) => {
  const dirA = tmpDir()
  const dirB = tmpDir()
  cleanup(t, dirA)
  cleanup(t, dirB)
  const cases = [
    loadPutCase('m3.det', PUT_COMPLIANT_URL, {
      assert: 'equals', path: 'state_after_load', expected: 'ACTIVE',
    }),
  ]

  const a = await runLoadPutSpecs(cases, PUT_COMPLIANT_URL, dirA)
  const b = await runLoadPutSpecs(cases, PUT_COMPLIANT_URL, dirB)

  const ra = readReceipt(a)
  const rb = readReceipt(b)
  // The probe snapshot (including the fixed probe_time) is bound into plan_id.
  assert.deepEqual(ra.plan_resolution, rb.plan_resolution)
  assert.equal(ra.plan_id, rb.plan_id, 'equal snapshot-bound frozen inputs yield equal plan IDs')
  assert.notEqual(ra.run_id, rb.run_id)

  const tc = rb.test_cases.find((c) => c.test_id === 'm3.det')
  assert.equal(tc.invocation_status, 'unknown', 'worker started 帧不构成独立 invocation 证据')
  assert.equal(tc.invocation_evidence_verified, false)
})

// ---------------------------------------------------------------------------
// §4.4 运行时不可用：显式 blocked/unknown，绝不伪造 pass。
// ---------------------------------------------------------------------------

test('M3: unavailable Cordis runtime is explicit (blocked/unknown), never fabricated present/pass', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const spec = makeRunSpec([
    loadPutCase('m3.unavailable', PUT_COMPLIANT_URL, {
      assert: 'equals', path: 'state_after_load', expected: 'ACTIVE',
    }),
  ], { target: { kind: 'plugin', put_digest: putDigestOf(PUT_COMPLIANT_URL) } })

  const out = await runSelfCheck(spec, {
    executionMode: 'subprocess',
    runtimeAnchor: makeRuntimeAnchor({
      cordis_entry: MISSING_RUNTIME_URL,
      runtime_kind: 'injected-runtime',
    }),
    probeTime: PROBE_TIME,
    receiptOutDir: dir,
  })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  assert.equal(validateReceiptV1(receipt).ok, true, JSON.stringify(validateReceiptV1(receipt).errors))
  assert.equal(receipt.provenance.cordis_version, null)
  assert.equal(receipt.provenance.dsh_commit, null)
  assert.ok(
    receipt.limitations.some((limitation) => String(limitation).startsWith('runtime-unavailable:')),
    `limitations 应显式记录 runtime-unavailable，got: ${JSON.stringify(receipt.limitations)}`,
  )
  const tc = receipt.test_cases.find((c) => c.test_id === 'm3.unavailable')
  assert.equal(tc.verdict, 'error', '运行时不可用时不得伪造 pass')
  assert.equal(tc.invocation_status, 'unknown')
  assert.ok(tc.reason_codes.includes('cordis-runtime-unavailable'), JSON.stringify(tc.reason_codes))
})
