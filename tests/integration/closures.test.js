/**
 * 集成 · 完整本地纵向闭环 + 负向回归（node:test，纯 ESM JS）。
 *
 * 通过公共门面 `runSelfCheck`（src/index.js）走 RunSpec → 冻结 Plan → 执行 →
 * receipt → 退出码，并对落盘 receipt JSON 做形态/摘要断言（复用 reports/shape 的
 * `verifyReceipt`）。
 *
 * 覆盖映射（development.md「必测负向用例」行号 + development-plan.md 负向七类 + §16.1）：
 *  - #1  空计划 / 零 required → blocked（计划完整性 / 状态与门禁）
 *  - #3  required fail → reject；required error/skip/inconclusive → blocked
 *  - #4  required 无终态（inconclusive 制造）→ blocked
 *  - #7  伪造/unknown started（pass 但未 started）→ blocked（准入与启动证据）
 *  - #10 market-required 恒 exit 2（信任边界 / 入口与发布）
 *  - #9  未知 schema / 改正文不改摘要 → pre-plan blocked / digest-mismatch（权威记录与协议）
 *  - §16.1 计划顺序与冻结：同一 runSpec 两次 plan_id 相同（确定性）
 *
 * 不得修改任何 src/ 或他人文件；只写 tests/fixtures/ 与 tests/integration/。
 * receiptOutDir 用 os.tmpdir()+随机子目录，测试后清理，不污染源码树。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { runSelfCheck } from '../../src/index.js'
import { verifyReceipt } from '../../src/reports/shape.js'
import {
  makeRunSpec,
  makeCase,
  criteriaEquals,
  probeValue,
  passingRequired,
} from '../fixtures/run-specs.js'

function tmpDir() {
  return mkdtempSync(join(tmpdir(), 'testbed-closures-'))
}

function readReceipt(result) {
  return JSON.parse(readFileSync(result.receiptPath, 'utf8'))
}

function cleanup(t, dir) {
  t.after(() => rmSync(dir, { recursive: true, force: true }))
}

// ---------------------------------------------------------------------------
// #1 空计划 / 零 required → blocked，exit 2
// ---------------------------------------------------------------------------

test('closure: 空计划（cases=[]）→ pre-plan blocked，plan_id=null，exit 2', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const out = await runSelfCheck(makeRunSpec([]), { receiptOutDir: dir })
  assert.equal(out.exitCode, 2)
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.trustScope, 'local-only')
  assert.equal(out.marketEligible, false)
  assert.equal(out.reconciliation, null)

  const receipt = readReceipt(out)
  assert.equal(receipt.plan_id, null)
  assert.equal(receipt.reconciliation, null)
  assert.deepEqual(receipt.test_cases, [])
  assert.equal(receipt.run_status, 'blocked')
  assert.equal(receipt.gate_decision, 'blocked')
  assert.equal(receipt.blocked_stage, 'intake')
  // 无伪造 expected/missing/waived 字段
  assert.equal(receipt.expected, undefined)
  assert.equal(receipt.missing, undefined)
  assert.equal(receipt.waived, undefined)
})

test('closure: 零 required（仅 optional）→ 冻结前 policy-admission blocked，exit 2', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const optionalPassing = makeCase({
    test_id: 'opt.1',
    node_id: 'opt.1',
    classification: 'optional',
    criteria: criteriaEquals(200),
    probe: probeValue(200),
  })
  const out = await runSelfCheck(makeRunSpec([optionalPassing]), { receiptOutDir: dir })
  assert.equal(out.exitCode, 2)
  assert.equal(out.gateDecision, 'blocked')

  const receipt = readReceipt(out)
  // GatePolicy requires at least one required baseline item; a zero-required
  // candidate is rejected before Plan freeze (fail-closed, no fabricated plan).
  assert.equal(receipt.plan_id, null)
  assert.equal(receipt.reconciliation, null)
  assert.equal(receipt.blocked_stage, 'policy-admission')
  assert.ok(receipt.reason_codes.includes('empty-required-baseline'), JSON.stringify(receipt.reason_codes))
  assert.deepEqual(receipt.test_cases, [])
  assert.equal(receipt.expected, undefined)
})

// ---------------------------------------------------------------------------
// #3 required fail → reject，exit 1
// ---------------------------------------------------------------------------

test('closure: required fail → reject，exit 1', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const failingRequired = makeCase({
    test_id: 'req.fail',
    node_id: 'req.fail',
    classification: 'required',
    criteria: criteriaEquals(200),
    probe: probeValue(999),
  })
  const out = await runSelfCheck(makeRunSpec([failingRequired]), { receiptOutDir: dir })
  assert.equal(out.gateDecision, 'reject')
  assert.equal(out.exitCode, 1)

  const receipt = readReceipt(out)
  const tc = receipt.test_cases.find((c) => c.test_id === 'req.fail')
  assert.equal(tc.verdict, 'fail')
  assert.equal(receipt.gate_decision, 'reject')
})

// ---------------------------------------------------------------------------
// #3 required error（probe 缺席）→ blocked，exit 2（准入与启动证据）
// ---------------------------------------------------------------------------

test('closure: required 无 observation producer → 控制面独立准入拒绝（skip/rejected/not-started）→ blocked', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const noProbe = makeCase({ test_id: 'req.no-probe', node_id: 'req.no-probe', classification: 'required' })
  const out = await runSelfCheck(makeRunSpec([noProbe]), { receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  const tc = receipt.test_cases.find((c) => c.test_id === 'req.no-probe')
  assert.equal(tc.verdict, 'skip')
  assert.equal(tc.admission_status, 'rejected')
  assert.equal(tc.execution_status, 'skipped')
  assert.equal(tc.invocation_status, 'not-started')
  assert.equal(tc.invocation_evidence_verified, false)
  assert.ok(tc.reason_codes.includes('policy_rejected'), JSON.stringify(tc.reason_codes))
  assert.ok(tc.reason_codes.includes('no-observation-producer'), JSON.stringify(tc.reason_codes))
})

// ---------------------------------------------------------------------------
// #4 required 无终态（无 criteria 且 completed）→ inconclusive → blocked，exit 2
//    （注：当前进程内 adapter 对每个 case 必产终态，missing_required 结构性为空，
//      故按“required 未决/无判据 → blocked”负向路径覆盖）
// ---------------------------------------------------------------------------

test('closure: required 无判据（completed 无 criteria）→ inconclusive → blocked，exit 2', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const noCriteria = makeCase({
    test_id: 'req.inconclusive',
    node_id: 'req.inconclusive',
    classification: 'required',
    probe: probeValue(200), // completed，但无 criteria
  })
  const out = await runSelfCheck(makeRunSpec([noCriteria]), { receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  const tc = receipt.test_cases.find((c) => c.test_id === 'req.inconclusive')
  assert.equal(tc.verdict, 'inconclusive')
})

// ---------------------------------------------------------------------------
// #5 all required pass verdicts remain blocked absent independent invocation evidence.
// ---------------------------------------------------------------------------

test('closure: all required verdicts pass without independent invocation evidence → blocked, exit 2', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const out = await runSelfCheck(makeRunSpec([passingRequired('req.pass')]), { receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)
  assert.deepEqual(out.reconciliation.missing, [])
  assert.deepEqual(out.reconciliation.missing_required, [])

  const receipt = readReceipt(out)
  const tc = receipt.test_cases.find((c) => c.test_id === 'req.pass')
  assert.equal(tc.verdict, 'pass')
  assert.equal(tc.invocation_status, 'unknown')
  assert.equal(tc.invocation_evidence_verified, false)
})

// 若 required 全部 pass 但无一项 started → blocked（no-required-started-pass）
test('closure: required pass 但 invocation_status=unknown → blocked（无 started+pass），exit 2', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const passNotStarted = makeCase({
    test_id: 'req.no-start',
    node_id: 'req.no-start',
    classification: 'required',
    criteria: criteriaEquals(200),
    probe: probeValue(200, { invocation_status: 'unknown' }),
  })
  const out = await runSelfCheck(makeRunSpec([passNotStarted]), { receiptOutDir: dir })
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)

  const receipt = readReceipt(out)
  const tc = receipt.test_cases.find((c) => c.test_id === 'req.no-start')
  assert.equal(tc.verdict, 'pass') // verdict 仍 pass
  assert.equal(tc.invocation_status, 'unknown') // 但启动不可核验
  assert.equal(out.gateReason, 'no-required-started-pass')
})

// ---------------------------------------------------------------------------
// #10 market-required profile：即使 gate pass 也恒 exit 2，绝不 0/1
// ---------------------------------------------------------------------------

test('closure: market-required remains blocked without independent invocation evidence', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const out = await runSelfCheck(makeRunSpec([passingRequired('req.mkt')]), {
    profile: 'market-required/v1',
    receiptOutDir: dir,
  })
  assert.equal(out.profileId, 'market-required/v1')
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.exitCode, 2)
  assert.notEqual(out.exitCode, 0)
  assert.notEqual(out.exitCode, 1)
  assert.equal(out.marketEligible, false)
})

// ---------------------------------------------------------------------------
// #7 未知 schema_version → pre-plan blocked，plan_id=null，reconciliation=null，
//    无 expected 伪造字段
// ---------------------------------------------------------------------------

test('closure: 未知 run-spec schema_version → pre-plan blocked，无伪造 expected', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const badSpec = makeRunSpec([passingRequired('x')], { schema_version: 'run-spec/v9' })
  const out = await runSelfCheck(badSpec, { receiptOutDir: dir })
  assert.equal(out.exitCode, 2)
  assert.equal(out.gateDecision, 'blocked')
  assert.equal(out.reconciliation, null)

  const receipt = readReceipt(out)
  assert.equal(receipt.plan_id, null)
  assert.equal(receipt.reconciliation, null)
  assert.deepEqual(receipt.test_cases, [])
  assert.equal(receipt.gate_decision, 'blocked')
  assert.equal(receipt.blocked_stage, 'intake')
  assert.deepEqual(receipt.reason_codes, ['run-spec-version-unknown'])
  assert.equal(receipt.expected, undefined)
  assert.equal(receipt.missing, undefined)
  assert.equal(receipt.waived, undefined)

  // 仍是合法的 pre-plan receipt（verifyReceipt 通过）
  assert.equal(verifyReceipt(receipt).status, 'ok')
})

// ---------------------------------------------------------------------------
// #9 receipt tampering → verifyReceipt non-ok (shape or digest validation).
// ---------------------------------------------------------------------------

test('closure: 篡改落盘 receipt（改 gate_decision 不改 digest）→ verifyReceipt 非 ok', async (t) => {
  const dir = tmpDir()
  cleanup(t, dir)
  const out = await runSelfCheck(makeRunSpec([passingRequired('req.tamper')]), { receiptOutDir: dir })
  const receipt = readReceipt(out)
  assert.equal(receipt.gate_decision, 'blocked')

  const tampered = structuredClone(receipt)
  tampered.gate_decision = 'reject' // violates gate cross-field consistency; digest remains unchanged
  const res = verifyReceipt(tampered)
  assert.notEqual(res.status, 'ok')
})

// ---------------------------------------------------------------------------
// §16.1 plan identity is stable when repeated runs freeze the same capability snapshot.
// ---------------------------------------------------------------------------

test('closure: identical frozen inputs across runs produce the same plan_id', async (t) => {
  const dirA = tmpDir()
  const dirB = tmpDir()
  cleanup(t, dirA)
  cleanup(t, dirB)
  t.mock.timers.enable({ apis: ['Date'], now: 1767225600000 })
  const spec = makeRunSpec([
    passingRequired('req.det'),
    makeCase({
      test_id: 'opt.det',
      node_id: 'opt.det',
      classification: 'optional',
      criteria: criteriaEquals(7),
      probe: probeValue(7),
    }),
  ])
  const a = await runSelfCheck(spec, { receiptOutDir: dirA })
  const b = await runSelfCheck(spec, { receiptOutDir: dirB })

  const ra = readReceipt(a)
  const rb = readReceipt(b)
  assert.deepEqual(ra.plan_resolution, rb.plan_resolution)
  assert.equal(ra.plan_id, rb.plan_id)
  assert.notEqual(ra.run_id, rb.run_id) // Run IDs remain unique while frozen inputs are identical
})