/**
 * M3 集成 · 真实宿主纵向闭环（node:test，真实 spawn 子进程走 subprocess adapter）。
 *
 * 通过公共门面 `runSelfCheck(spec, { executionMode:'subprocess' })`，用 worker 子进程内
 * 真实 Cordis 装载 fixture PUT（`probe.op='load-put'`），覆盖 CONTRACT-m3 §4 三条：
 *   1. 契约/加载卸载（put-compliant → ACTIVE → DISPOSED，effects_count>=1）
 *   2. 失败 fail-closed（put-failing → FAILED + error 含 intentional）
 *   3. 两阶段探测→冻结→started + plan_id 确定性
 * 并核验 provenance 已含 cordis_version / dsh_commit（版本锚）。
 *
 * 路径层级（本文件位于 tests/integration/，fixtures 在 tests/fixtures/）：
 *   - src 门面：`../../src/index.js`（上溯两级到包根）
 *   - fixture PUT：`../fixtures/put-*.js`（上溯一级到 tests/ 再进 fixtures/）
 * receiptOutDir 用 os.tmpdir 随机子目录，测试后清理，不污染源码树。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { runSelfCheck } from '../../src/index.js'
import { makeRunSpec, makeCase } from '../fixtures/run-specs.js'

// put_entry 必须为绝对 file URL（worker 侧 `await import(put_entry)` 用）。
const PUT_COMPLIANT_URL = new URL('../fixtures/put-compliant.js', import.meta.url).href
const PUT_FAILING_URL = new URL('../fixtures/put-failing.js', import.meta.url).href

function tmpDir() {
  return mkdtempSync(join(tmpdir(), 'testbed-m3-'))
}

function readReceipt(result) {
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

// ---------------------------------------------------------------------------
// §4.1 契约/加载卸载：put-compliant 走真实 Cordis 生命周期
// ---------------------------------------------------------------------------

test('M3: put-compliant lifecycle remains observable while gate blocks without independent invocation evidence', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const spec = makeRunSpec([
    loadPutCase('m3.compliant.load', PUT_COMPLIANT_URL, {
      assert: 'equals', path: 'state_after_load', expected: 'ACTIVE',
    }),
  ])

  const out = await runSelfCheck(spec, { executionMode: 'subprocess', receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  const tc = receipt.test_cases.find((c) => c.test_id === 'm3.compliant.load')
  assert.equal(tc.verdict, 'pass')
  assert.equal(tc.invocation_status, 'unknown')
  assert.equal(tc.invocation_evidence_verified, false)

  const obs = receipt.observations[0]
  assert.equal(obs.source, 'worker')
  assert.equal(obs.value.state_after_load, 'ACTIVE')
  assert.equal(obs.value.state_after_dispose, 'DISPOSED')
  assert.ok(obs.value.effects_count >= 1, 'apply 曾注册 effect，effects_count 应 >= 1')

  // provenance 版本锚（CONTRACT-m3 §3）
  assert.equal(receipt.provenance.cordis_version, '4.0.5-alpha.2')
  assert.ok(receipt.provenance.dsh_commit.startsWith('86a402200d'))
})

// ---------------------------------------------------------------------------
// §4.2 失败 fail-closed：put-failing → FAILED + error 含 intentional
// ---------------------------------------------------------------------------

test('M3: put-failing fail-closed verdicts are preserved while gate blocks without invocation evidence', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const spec = makeRunSpec([
    loadPutCase('m3.failing.load', PUT_FAILING_URL, {
      assert: 'equals', path: 'state_after_load', expected: 'FAILED',
    }),
    loadPutCase('m3.failing.error', PUT_FAILING_URL, {
      assert: 'contains', path: 'error', expected: 'intentional',
    }),
  ])

  const out = await runSelfCheck(spec, { executionMode: 'subprocess', receiptOutDir: dir })
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
  t.mock.timers.enable({ apis: ['Date'], now: 1767225600000 })
  const spec = makeRunSpec([
    loadPutCase('m3.det', PUT_COMPLIANT_URL, {
      assert: 'equals', path: 'state_after_load', expected: 'ACTIVE',
    }),
  ])

  const a = await runSelfCheck(spec, { executionMode: 'subprocess', receiptOutDir: dirA })
  const b = await runSelfCheck(spec, { executionMode: 'subprocess', receiptOutDir: dirB })

  const ra = readReceipt(a)
  const rb = readReceipt(b)
  assert.deepEqual(ra.plan_resolution.capability_snapshot, rb.plan_resolution.capability_snapshot)
  assert.equal(ra.plan_id, rb.plan_id, 'equal snapshot-bound frozen inputs yield equal plan IDs')

  const tc = rb.test_cases.find((c) => c.test_id === 'm3.det')
  assert.equal(tc.invocation_status, 'unknown', 'worker started 帧不构成独立 invocation 证据')
  assert.equal(tc.invocation_evidence_verified, false)
})