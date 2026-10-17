/**
 * M6 缺口收口 · 真实 missing_required 注入（node:test，纯 ESM）。
 *
 * 覆盖 §16.1 行3「执行与对账」的真实缺项注入（lead 已加 seam：case `no_terminal:true`
 * 表示「既无有效响应也无控制面终态」→ 不计入 executed、留在 reconciliation.missing，
 * required 则 missing_required 非空 → gate blocked）：
 *   ① required 缺失 → gate=blocked、exit 2；missing/missing_required 含该项，无逐项 verdict。
 *   ② optional 缺失 → missing 含该项但 missing_required 空；required 结果无独立 invocation 证据仍 gate=blocked。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { runSelfCheck } from '../../src/index.js'
import { makeRunSpec, probeValue, criteriaEquals } from '../fixtures/run-specs.js'

function tmpDir() {
  return mkdtempSync(join(tmpdir(), 'testbed-miss-'))
}
function cleanup(t, dir) {
  t.after(() => rmSync(dir, { recursive: true, force: true }))
}
function readReceipt(result) {
  return JSON.parse(readFileSync(result.receiptPath, 'utf8'))
}

/** required 通过用例（in-process probe echo + criteria equals）。 */
function passingRequired(id) {
  return { test_id: id, node_id: id, classification: 'required', criteria: criteriaEquals(200), probe: probeValue(200) }
}

// ---------------------------------------------------------------------------
// ① required 缺失（no_terminal）→ blocked
// ---------------------------------------------------------------------------

test('m6-miss ① required 缺失 → gate=blocked、exit 2，missing/missing_required 含该项', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const spec = makeRunSpec([
    passingRequired('req.a'),
    { test_id: 'req.b', node_id: 'req.b', classification: 'required', no_terminal: true },
  ])

  const out = await runSelfCheck(spec, { receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  assert.ok(receipt.reconciliation.expected.includes('req.b'), 'expected 应含 req.b')
  assert.ok(!receipt.reconciliation.executed.includes('req.b'), 'executed 不应含 req.b')
  assert.ok(receipt.reconciliation.missing.includes('req.b'), `missing 应含 req.b，got: ${JSON.stringify(receipt.reconciliation.missing)}`)
  assert.ok(receipt.reconciliation.missing_required.includes('req.b'), `missing_required 应含 req.b，got: ${JSON.stringify(receipt.reconciliation.missing_required)}`)
  // 无逐项 verdict（不伪造终态）
  assert.ok(!receipt.test_cases.some((c) => c.test_id === 'req.b'), 'req.b 不应出现在 test_cases（无逐项 verdict）')
})

// ---------------------------------------------------------------------------
// ② optional 缺失（no_terminal）→ missing_required 为空；unverified required invocation 仍使 gate blocked
// ---------------------------------------------------------------------------

test('m6-miss ② optional 缺失保持非 required；unverified required invocation blocks gate', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const spec = makeRunSpec([
    passingRequired('req.a'),
    { test_id: 'req.c', node_id: 'req.c', classification: 'optional', no_terminal: true },
  ])

  const out = await runSelfCheck(spec, { receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  assert.equal(receipt.gate_reason, 'no-required-started-pass')
  const req = receipt.test_cases.find((c) => c.test_id === 'req.a')
  assert.equal(req.verdict, 'pass')
  assert.equal(req.invocation_status, 'unknown')
  assert.equal(req.invocation_evidence_verified, false)
  assert.ok(receipt.reconciliation.missing.includes('req.c'), `missing 应含 req.c，got: ${JSON.stringify(receipt.reconciliation.missing)}`)
  assert.deepEqual(receipt.reconciliation.missing_required, [], 'optional 缺口不产生 missing_required')
  assert.ok(!receipt.test_cases.some((c) => c.test_id === 'req.c'), 'req.c 不应出现在 test_cases')
})