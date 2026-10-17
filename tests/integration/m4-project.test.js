/**
 * M4 集成 · 只读投影（HTML / JUnit / TAP / CI 摘要），node:test，纯 ESM。
 *
 * 用真实 receipt（runSelfCheck 落盘后读回，或 buildReceipt 构造对账缺口）验证
 * CONTRACT-m4 §6 五条（覆盖 lead 四条 + §6④ 篡改不改 canonical）：
 *   ① 四格式产物含 source_receipt_digest（= receipt.integrity.record_digest）与 exporter_id
 *   ② 字节稳定：同一 receipt 两次 projectAll 四产物 body 严格相等
 *   ③ 枚举保真：inconclusive / missing 原值可见，且不被洗成 pass
 *   ④ 篡改导出件 / receipt 不改 canonical（project 对篡改 receipt 拒绝生成）
 *   ⑤ 投影不改变门禁；缺少独立 invocation evidence 时 local 与 market-required 均 blocked/exit 2
 *
 * 导入门面（CONTRACT-m4 §1/§2）：`src/reports/project/index.js` 导出
 * `PROJECT_FORMATS / project(receipt, format, exporterId) / projectAll(receipt, exporterId)`。
 * 若 reports/project 尚未落地，本文件会以 ERR_MODULE_NOT_FOUND 报错（如实反映阻塞）。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { runSelfCheck, verifyRecordDigest } from '../../src/index.js'
import { project, projectAll, PROJECT_FORMATS } from '../../src/reports/project/index.js'
import { buildReceipt, verifyReceipt } from '../../src/reports/shape.js'
import { makeRunSpec, makeCase, probeValue, criteriaEquals } from '../fixtures/run-specs.js'

const EXPORTER = 'testbed-m4-integration'
const FORMATS = ['junit', 'tap', 'html', 'ci-summary']

function tmpDir() {
  return mkdtempSync(join(tmpdir(), 'testbed-m4-'))
}
function cleanup(t, dir) {
  t.after(() => rmSync(dir, { recursive: true, force: true }))
}
function readReceipt(result) {
  return JSON.parse(readFileSync(result.receiptPath, 'utf8'))
}

/** Passing verdict receipt; the aggregate gate stays blocked until invocation evidence exists. */
const passSpec = () => makeRunSpec([
  makeCase({
    test_id: 'req.pass', node_id: 'req.pass', classification: 'required',
    criteria: criteriaEquals(200), probe: probeValue(200),
  }),
])

/** 含 inconclusive 的 receipt（required completed 但无 criteria）。 */
const incSpec = () => makeRunSpec([
  makeCase({
    test_id: 'req.inc', node_id: 'req.inc', classification: 'required',
    probe: probeValue(200), // 无 criteria → completed → inconclusive
  }),
])

/**
 * 构造含对账缺口（missing）的 frozen receipt。当前 in-process kernel 每个 case 必产
 * 终态、missing 结构性恒空，故此处直接 buildReceipt 构造 `reconciliation.missing=['req.missing']`
 * 以驱动投影的 missing 合成路径（结构性合法，verifyReceipt=ok）。
 */
function missingReceipt() {
  return buildReceipt({
    shape: 'frozen',
    runId: 'run-m4-missing',
    planResolution: {
      plan_id: 'plan-sha256:' + 'cd'.repeat(32),
      test_cases: [
        { test_id: 'req.pass', node_id: 'req.pass', classification: 'required', needs: [] },
        { test_id: 'req.missing', node_id: 'req.missing', classification: 'required', needs: [] },
      ],
    },
    reconciliation: {
      expected: ['req.pass', 'req.missing'],
      executed: ['req.pass'],
      missing: ['req.missing'],
      waived: [],
      missing_required: ['req.missing'],
    },
    testCases: [{
      test_id: 'req.pass', classification: 'required', verdict: 'pass',
      invocation_status: 'unknown', invocation_evidence_verified: false, execution_status: 'completed', admission_status: 'accepted',
      reason_codes: [], dimensions: {}, criteria_ref: 'criteria/req.pass',
      attempts: [{ attempt: 1, admission_status: 'accepted', execution_status: 'completed', invocation_status: 'unknown', invocation_evidence_verified: false, verdict: 'pass' }],
      observation_refs: [],
    }],
    observations: [],
    artifacts: [],
    gateDecision: 'blocked',
    gateReason: 'missing-required',
    runStatus: 'completed',
    limitations: ['local-only'],
  })
}

// ---------------------------------------------------------------------------
// §6① 四格式产物均含 source_receipt_digest 与 exporter_id
// ---------------------------------------------------------------------------

test('§6① 四格式产物含 source_receipt_digest（=record_digest）与 exporter_id', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const out = await runSelfCheck(passSpec(), { receiptOutDir: dir })
  const receipt = readReceipt(out)

  assert.deepEqual(PROJECT_FORMATS, FORMATS, 'PROJECT_FORMATS 应为四格式闭集')

  for (const fmt of FORMATS) {
    const p = project(receipt, fmt, EXPORTER)
    assert.equal(p.exporter_id, EXPORTER, `${fmt} 应含 exporter_id`)
    assert.equal(p.source_receipt_digest, receipt.integrity.record_digest, `${fmt} source_receipt_digest 应等于 record_digest`)
    assert.ok(typeof p.format_version === 'string' && p.format_version.length > 0, `${fmt} 应含非空 format_version`)
    assert.equal(typeof p.body, 'string', `${fmt} body 应为字符串`)
  }

  const all = projectAll(receipt, EXPORTER)
  for (const fmt of FORMATS) {
    assert.ok(all[fmt], `projectAll 应有 ${fmt}`)
    assert.equal(all[fmt].source_receipt_digest, receipt.integrity.record_digest, `projectAll.${fmt} source_receipt_digest`)
  }
})

// ---------------------------------------------------------------------------
// §6② 字节稳定：同一 receipt 两次 projectAll 四产物 body 严格相等
// ---------------------------------------------------------------------------

test('§6② 字节稳定：同一 receipt 两次 projectAll 四产物 body 严格相等', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const out = await runSelfCheck(passSpec(), { receiptOutDir: dir })
  const receipt = readReceipt(out)

  const a = projectAll(receipt, EXPORTER)
  const b = projectAll(receipt, EXPORTER)
  for (const fmt of FORMATS) {
    assert.notEqual(a[fmt].body, '', `${fmt} body 非空`)
    assert.strictEqual(a[fmt].body, b[fmt].body, `${fmt} 两次生成 body 应完全相等`)
  }
})

// ---------------------------------------------------------------------------
// §6③ 枚举保真：inconclusive / missing 原值可见，且不被洗成 pass
// ---------------------------------------------------------------------------

test('§6③ inconclusive 不被洗成 pass（原值可见 + skip/TODO 标记）', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const out = await runSelfCheck(incSpec(), { receiptOutDir: dir })
  const receipt = readReceipt(out)
  const tc = receipt.test_cases.find((c) => c.test_id === 'req.inc')
  assert.equal(tc.verdict, 'inconclusive', '前置：case 应为 inconclusive')

  const all = projectAll(receipt, EXPORTER)
  const junit = all.junit.body
  const tap = all.tap.body
  // 原值可见 + 非 pass 标记（CONTRACT-m4 §3）
  assert.ok(junit.includes('inconclusive'), 'junit 原值 inconclusive 可见')
  assert.ok(junit.includes('<skipped'), 'junit inconclusive 映射为 <skipped>（非 pass）')
  assert.ok(tap.includes('inconclusive'), 'tap 原值 inconclusive 可见')
  assert.ok(tap.includes('TODO'), 'tap 用 # TODO 标记（非 plain ok）')
})

test('§6③ missing 不被洗成 pass（原值可见 + error/not ok 标记）', () => {
  const receipt = missingReceipt()
  assert.equal(verifyReceipt(receipt).status, 'ok', '前置：构造的 missing receipt 结构性合法')
  assert.deepEqual(receipt.reconciliation.missing, ['req.missing'])

  const all = projectAll(receipt, EXPORTER)
  const junit = all.junit.body
  const tap = all.tap.body
  // 原值可见 + 非 pass 标记（CONTRACT-m4 §3）
  assert.ok(junit.includes('missing'), 'junit 原值 missing 可见')
  assert.ok(junit.includes('<error'), 'junit missing 合成 <error>（非 pass）')
  assert.ok(tap.includes('missing'), 'tap 原值 missing 可见')
  assert.ok(tap.includes('not ok'), 'tap missing 走 not ok（非 pass）')
})

// ---------------------------------------------------------------------------
// §6④ 篡改导出件 / receipt 不改 canonical
// ---------------------------------------------------------------------------

test('§6④ 篡改导出件不改 canonical；篡改 receipt 被 project 拒绝', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const out = await runSelfCheck(passSpec(), { receiptOutDir: dir })
  const receipt = readReceipt(out)
  const digestBefore = receipt.integrity.record_digest

  // 篡改导出的投影对象（新字符串），canonical receipt 不变。
  const all = projectAll(receipt, EXPORTER)
  all.junit.body = 'TAMPERED-JUNIT'
  all.tap.body = 'TAMPERED-TAP'
  assert.equal(receipt.integrity.record_digest, digestBefore, '导出件被改不影响 canonical record_digest')
  assert.equal(verifyRecordDigest(receipt).ok, true, 'canonical 摘要仍可复算一致')

  // 篡改 receipt（改 gate_decision 不改 digest）→ project 拒绝生成（verifyReceipt 非 ok）。
  const tampered = structuredClone(receipt)
  tampered.gate_decision = 'reject' // digest 随即失效
  assert.notEqual(verifyReceipt(tampered).status, 'ok')
  assert.throws(() => project(tampered, 'junit', EXPORTER), 'project 应拒绝篡改 receipt')
})

// ---------------------------------------------------------------------------
// §6⑤ 退出码/门禁不被投影改变
// ---------------------------------------------------------------------------

test('§6⑤ projection preserves blocked gate and exit 2 absent independent invocation evidence', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const local = await runSelfCheck(passSpec(), { profile: 'local-selfcheck/v1', receiptOutDir: dir })
  const mkt = await runSelfCheck(passSpec(), { profile: 'market-required/v1', receiptOutDir: dir })
  const receipt = readReceipt(local)

  // 投影前后 canonical 不变 + gate_decision 一致。
  assert.equal(receipt.gate_decision, 'blocked')
  assert.equal(local.gateDecision, 'blocked')
  assert.equal(local.exitCode, 2)
  assert.equal(mkt.gateDecision, 'blocked')
  assert.equal(mkt.exitCode, 2)

  const digestBefore = receipt.integrity.record_digest
  projectAll(receipt, EXPORTER)
  assert.equal(receipt.integrity.record_digest, digestBefore, '投影不改变 canonical')
  assert.equal(receipt.gate_decision, 'blocked', '投影不改变 gate_decision')

  // ci-summary reflects the required blocked gate.
  const ci = project(readReceipt(local), 'ci-summary', EXPORTER)
  assert.ok(ci.body.includes('blocked'), 'ci-summary includes gate_decision=blocked')
})