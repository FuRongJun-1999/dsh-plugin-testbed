/**
 * 单元 · protocol/receipt/v1 严格校验（node:test）。
 *
 * 覆盖 architecture §11.2.1 / implementation-design-protocol §2 / §8.1：
 *  - 三种互斥形态（Plan 已冻结 / Plan 前阻断 / Plan 前取消）各自合法样本；
 *  - `plan_id=null ⇔ reconciliation=null` 与「不得伪造 expected/missing/waived、
 *    逐项终态」的 fail-closed 负向；
 *  - 未知字段/未知主版本/非法签名形态拒绝，`market_eligible=false` 与
 *    `integrity.signed=false` 固定；
 *  - 摘要复算只排除 `integrity.record_digest`（可选 verifyDigest）。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import { validateReceiptV1 } from '../../../src/protocol/contracts.js'
import { recordDigest } from '../../../src/protocol/digest.js'
import { RECEIPT_V1_SCHEMA } from '../../../src/protocol/schemas.js'
import { validateValue } from '../../../src/protocol/jsonschema.js'
import { CANONICAL_RECEIPT_EXAMPLE } from './fixtures/canonical-receipt.js'

const DIGEST = (ch) => 'sha256:' + ch.repeat(64)
const PLAN_ID = 'plan-sha256:' + '6'.repeat(64)

function makeFrozenReceipt() {
  return {
    receipt_schema_version: 'receipt/v1',
    run_id: 'run-20261016-001',
    plan_id: PLAN_ID,
    scenario_ref: { id: 'plugin-baseline', version: '1.0.0', digest: DIGEST('2') },
    profile_ref: { id: 'smoke', version: '1.0.0', digest: DIGEST('8') },
    target_ref: { kind: 'api', owner_put_digest: DIGEST('3'), origin: 'http://127.0.0.1:4001' },
    trust_scope: 'local-only',
    market_eligible: false,
    run_status: 'completed',
    gate_decision: 'pass',
    plan_candidate_ref: {
      digest: DIGEST('b'),
      baseline_test_ids: ['contract.login.schema'],
      required_test_ids: ['contract.login.schema'],
    },
    provenance: {
      put_digest: DIGEST('3'),
      dsh_commit: '0123456789abcdef0123456789abcdef01234567',
      cordis_version: '1.0.0',
      adapter_ref: 'local-worker-json@1.0.0',
      tool_refs: [{ tool_id: 'example.api-contract', version: '1.0.0', artifact_digest: DIGEST('1') }],
      assertion_refs: ['assert/login-contract@1.0.0'],
      policy_ref: { id: 'gate-policy', version: '1.0.0', digest: DIGEST('a') },
      environment_fingerprint: DIGEST('4'),
    },
    limitations: ['local-only', 'l1-local-only', 'no-external-trust-anchor'],
    integrity: { record_digest: DIGEST('9'), signed: false },
    plan_resolution: [{ test_id: 'contract.login.schema', classification: 'required' }],
    reconciliation: {
      expected: ['contract.login.schema'],
      executed: ['contract.login.schema'],
      missing: [],
      waived: [],
      missing_required: [],
    },
    test_cases: [{
      test_id: 'contract.login.schema',
      dimensions: {
        test_level: 'component-integration',
        test_type: ['functional'],
        test_technique: ['contract'],
        trigger: 'manual',
        suite_profile: 'smoke',
        target_kind: 'api',
        execution_mode: 'mock',
        repeatability: 'environment-bound',
        evidence_kind: ['assertion', 'artifact'],
      },
      attempts: [{
        attempt: 1,
        admission_status: 'accepted',
        execution_status: 'completed',
        invocation_status: 'started',
        started_at: '2026-10-16T04:29:01Z',
        ended_at: '2026-10-16T04:29:03Z',
        verdict: 'pass',
        observation_refs: ['obs-001'],
      }],
      verdict: 'pass',
      criteria_ref: 'assert/login-contract@1.0.0',
      reason_codes: [],
    }],
    observations: [{
      observation_id: 'obs-001',
      schema_ref: 'urn:example:tool:api-contract:observation:v1',
      value: { status_code: 200, body: { user_id: 'fixture-user-001' } },
      source: 'worker',
      limitations: ['controlled-fixture'],
    }],
    artifacts: [{ kind: 'log', digest: DIGEST('5'), size_bytes: 412 }],
  }
}

function makeFrozenWithValidDigest() {
  const receipt = makeFrozenReceipt()
  receipt.integrity.record_digest = recordDigest(receipt)
  return receipt
}

function makePrePlanBlocked() {
  return {
    ...makeFrozenWithValidDigest(),
    plan_id: null,
    plan_resolution: null,
    reconciliation: null,
    test_cases: [],
    observations: [],
    artifacts: [],
    run_status: 'blocked',
    gate_decision: 'blocked',
    plan_candidate_ref: null,
    blocked_stage: 'static-validation',
    reason_codes: ['tool-manifest-invalid'],
  }
}

function makePrePlanCancelled() {
  const receipt = makePrePlanBlocked()
  delete receipt.blocked_stage
  return {
    ...receipt,
    run_status: 'cancelled',
    cancelled_stage: 'capability-probe',
    reason_codes: ['user-cancelled'],
  }
}

/** Recompute the digest of a mutated receipt so only the mutation is tested. */
function resign(receipt) {
  const body = structuredClone(receipt)
  body.integrity = { ...(body.integrity ?? {}), signed: false }
  body.integrity.record_digest = recordDigest(body)
  return body
}

// ---------------------------------------------------------------------------
// 合法三种形态
// ---------------------------------------------------------------------------

test('receipt: 完整 Plan 已冻结形态 → 通过且 form=frozen', () => {
  const result = validateReceiptV1(makeFrozenWithValidDigest(), { verifyDigest: true })
  assert.deepEqual(result.errors, [])
  assert.equal(result.ok, true)
  assert.equal(result.form, 'frozen')
})

test('receipt: Plan 前阻断形态（plan_id/reconciliation/plan_resolution 均 null）→ 通过', () => {
  const result = validateReceiptV1(resign(makePrePlanBlocked()))
  assert.equal(result.ok, true, JSON.stringify(result.errors))
  assert.equal(result.form, 'pre-plan-blocked')
})

test('receipt: Plan 前取消形态 → 通过且 form=pre-plan-cancelled', () => {
  const result = validateReceiptV1(resign(makePrePlanCancelled()))
  assert.equal(result.ok, true, JSON.stringify(result.errors))
  assert.equal(result.form, 'pre-plan-cancelled')
})

test('receipt: 冻结后取消/阻断仍属冻结形态（plan_id 非 null 且有 reconciliation）', () => {
  for (const overrides of [
    { run_status: 'cancelled', gate_decision: 'blocked' },
    { run_status: 'completed', gate_decision: 'blocked' },
    { run_status: 'completed', gate_decision: 'reject' },
  ]) {
    const receipt = resign({ ...makeFrozenWithValidDigest(), ...overrides })
    const result = validateReceiptV1(receipt)
    assert.equal(result.ok, true, `${JSON.stringify(overrides)}: ${JSON.stringify(result.errors)}`)
    assert.equal(result.form, 'frozen')
  }
})

test('receipt: Plan 前形态允许 plan_candidate_ref 为 null 或已形成的引用', () => {
  const nullRef = validateReceiptV1(resign(makePrePlanBlocked()))
  assert.equal(nullRef.ok, true, JSON.stringify(nullRef.errors))
  const withRef = { ...makePrePlanBlocked(), plan_candidate_ref: makeFrozenReceipt().plan_candidate_ref }
  const result = validateReceiptV1(resign(withRef))
  assert.equal(result.ok, true, JSON.stringify(result.errors))
})

// ---------------------------------------------------------------------------
// 互斥形态 fail-closed
// ---------------------------------------------------------------------------

test('receipt: plan_id=null 但 reconciliation!=null → 拒绝', () => {
  const receipt = resign(makeFrozenWithValidDigest())
  receipt.plan_id = null
  receipt.plan_resolution = null
  receipt.run_status = 'blocked'
  receipt.gate_decision = 'blocked'
  receipt.blocked_stage = 'intake'
  receipt.reason_codes = ['x']
  const result = validateReceiptV1(resign(receipt))
  assert.equal(result.ok, false)
  assert.ok(result.errors.includes('pre-plan-must-have-null-reconciliation'))
})

test('receipt: plan_id 非 null 但 reconciliation=null → 拒绝', () => {
  const receipt = { ...makeFrozenWithValidDigest(), reconciliation: null }
  const result = validateReceiptV1(resign(receipt))
  assert.equal(result.ok, false)
  assert.ok(result.errors.includes('frozen-must-have-reconciliation'))
})

test('receipt: Plan 前伪造 plan_resolution/逐项 test_cases/observations/artifacts → 拒绝', () => {
  const base = makePrePlanBlocked()
  for (const [field, value] of Object.entries({
    plan_resolution: [{ test_id: 't', classification: 'required' }],
    test_cases: makeFrozenReceipt().test_cases,
    observations: makeFrozenReceipt().observations,
    artifacts: makeFrozenReceipt().artifacts,
  })) {
    const receipt = resign({ ...base, [field]: value })
    const result = validateReceiptV1(receipt)
    assert.equal(result.ok, false, `${field} must be rejected`)
  }
})

test('receipt: Plan 前形态禁止 expected/missing/waived/required/verdict 顶层字段 → 拒绝', () => {
  for (const field of ['expected', 'missing', 'waived', 'required', 'verdict']) {
    const receipt = resign({ ...makePrePlanBlocked(), [field]: [] })
    const result = validateReceiptV1(receipt)
    assert.equal(result.ok, false, `${field} must be rejected`)
    assert.ok(result.errors.some((e) => e.includes(`additional-properties-not-allowed:${field}`)))
  }
})

test('receipt: 阻断形态带 cancelled_stage / 取消形态带 blocked_stage → 拒绝', () => {
  const blocked = validateReceiptV1(resign({ ...makePrePlanBlocked(), cancelled_stage: 'x' }))
  assert.equal(blocked.ok, false)
  assert.ok(blocked.errors.includes('blocked-form-forbidden-field:cancelled_stage'))

  const cancelled = validateReceiptV1(resign({ ...makePrePlanCancelled(), blocked_stage: 'x' }))
  assert.equal(cancelled.ok, false)
  assert.ok(cancelled.errors.includes('cancelled-form-forbidden-field:blocked_stage'))
})

test('receipt: Plan 前 gate_decision 必须 blocked 且必须有 reason_codes', () => {
  const passGate = validateReceiptV1(resign({ ...makePrePlanBlocked(), gate_decision: 'pass' }))
  assert.equal(passGate.ok, false)
  assert.ok(passGate.errors.includes('pre-plan-gate-decision-must-be-blocked'))

  const noReason = validateReceiptV1(resign({ ...makePrePlanBlocked(), reason_codes: [] }))
  assert.equal(noReason.ok, false)
  assert.ok(noReason.errors.includes('pre-plan-requires-reason-codes'))
})

test('receipt: plan_id=null + run_status=completed（既非阻断也非取消）→ 拒绝', () => {
  const receipt = resign({
    ...makePrePlanBlocked(),
    run_status: 'completed',
    gate_decision: 'blocked',
    blocked_stage: 'x',
    reason_codes: ['x'],
  })
  const result = validateReceiptV1(receipt)
  assert.equal(result.ok, false)
  assert.ok(result.errors.includes('receipt-form-indeterminate'))
})

test('receipt: 冻结形态不得携带 C 组 blocked_stage/cancelled_stage/reason_codes → 拒绝', () => {
  for (const field of ['blocked_stage', 'cancelled_stage', 'reason_codes']) {
    const result = validateReceiptV1(resign({ ...makeFrozenWithValidDigest(), [field]: 'x' }))
    assert.equal(result.ok, false, `${field} must be rejected`)
  }
})

// ---------------------------------------------------------------------------
// market_eligible / trust_scope / integrity.signed 固定
// ---------------------------------------------------------------------------

test('receipt: market_eligible=true → 拒绝（无置真路径）', () => {
  const result = validateReceiptV1(resign({ ...makeFrozenWithValidDigest(), market_eligible: true }))
  assert.equal(result.ok, false)
  assert.ok(result.errors.includes('market-eligible-must-be-false'))
})

test('receipt: market_eligible 缺失 → 拒绝', () => {
  const receipt = makeFrozenWithValidDigest()
  delete receipt.market_eligible
  const result = validateReceiptV1(resign(receipt))
  assert.equal(result.ok, false)
  assert.ok(result.errors.some((e) => e === 'schema:required-missing:market_eligible'))
})

test('receipt: trust_scope 非 local-only → 拒绝', () => {
  const result = validateReceiptV1(resign({ ...makeFrozenWithValidDigest(), trust_scope: 'market' }))
  assert.equal(result.ok, false)
  assert.ok(result.errors.includes('trust-scope-must-be-local-only'))
})

test('receipt: integrity.signed=true → 拒绝；signed 缺失 → 拒绝', () => {
  const signedTrue = makeFrozenWithValidDigest()
  signedTrue.integrity.signed = true
  const result = validateReceiptV1(signedTrue)
  assert.equal(result.ok, false)
  assert.ok(result.errors.includes('integrity-signed-must-be-false'))

  const noSigned = makeFrozenWithValidDigest()
  delete noSigned.integrity.signed
  assert.equal(validateReceiptV1(noSigned).ok, false)
})

// ---------------------------------------------------------------------------
// 非法签名形态（schema 未声明）
// ---------------------------------------------------------------------------

test('receipt: 未声明的签名字段/信任锚字段一律拒绝', () => {
  const variants = [
    { signature: { algorithm: 'ed25519' } },
    { signatures: [] },
    { key_id: 'k1' },
    { signing_key_id: 'k1' },
    { archive_anchor: { t: 1 } },
    { trust_anchor: 'x' },
    { jws: 'x' },
    { integrity: { record_digest: DIGEST('9'), signed: false, signature: 'x' } },
  ]
  for (const variant of variants) {
    const result = validateReceiptV1(resign({ ...makeFrozenWithValidDigest(), ...variant }))
    assert.equal(result.ok, false, JSON.stringify(variant))
    assert.ok(
      result.errors.some((e) => e.startsWith('forbidden-signature-form:') || e.includes('additional-properties-not-allowed')),
      JSON.stringify(result.errors),
    )
  }
})

test('receipt: 嵌套 provenance/case 中的 signed 形态同样拒绝', () => {
  const receipt = makeFrozenWithValidDigest()
  receipt.provenance.signed = true
  receipt.test_cases[0].attempts[0].signed = false
  const result = validateReceiptV1(resign(receipt))
  assert.equal(result.ok, false)
  assert.ok(result.errors.includes('forbidden-signature-form:provenance.signed'))
  assert.ok(result.errors.includes('forbidden-signature-form:test_cases[0].attempts[0].signed'))
})

// ---------------------------------------------------------------------------
// 未知字段 / 未知主版本 / 缺必填
// ---------------------------------------------------------------------------

test('receipt: 未知顶层字段 → 拒绝（additionalProperties:false）', () => {
  const result = validateReceiptV1(resign({ ...makeFrozenWithValidDigest(), extra: 1 }))
  assert.equal(result.ok, false)
  assert.ok(result.errors.includes('schema:additional-properties-not-allowed:extra'))
})

test('receipt: 嵌套未知字段（scenario_ref/integrity）→ 拒绝', () => {
  const receipt = makeFrozenWithValidDigest()
  receipt.provenance = { ...receipt.provenance, signature_ref: 'x' }
  receipt.integrity = { ...receipt.integrity, protected: 'x' }
  const result = validateReceiptV1(resign(receipt))
  assert.equal(result.ok, false)
})

test('receipt: 未知主版本 receipt/v2、receipt/v999、垃圾值 → 拒绝且不降级', () => {
  for (const version of ['receipt/v2', 'receipt/v999', 'receipt', 'other/v1']) {
    const result = validateReceiptV1(resign({ ...makeFrozenWithValidDigest(), receipt_schema_version: version }))
    assert.equal(result.ok, false, version)
    assert.ok(result.errors.includes(`unknown-version:${version}`), version)
  }
})

test('receipt: 恒在字段缺失 → 拒绝', () => {
  const required = RECEIPT_V1_SCHEMA.required
  for (const field of required) {
    const receipt = makeFrozenWithValidDigest()
    delete receipt[field]
    const result = validateReceiptV1(receipt)
    assert.equal(result.ok, false, `${field} must be required`)
  }
})

test('receipt: plan_id 采用 plan-sha256 内容寻址格式，普通 sha256 摘要拒绝', () => {
  const result = validateReceiptV1(resign({ ...makeFrozenWithValidDigest(), plan_id: DIGEST('6') }))
  assert.equal(result.ok, false)
  assert.ok(result.errors.some((e) => e.startsWith('schema:pattern:')))
})

// ---------------------------------------------------------------------------
// 枚举词汇分离（execution_status ≠ verdict；verdict ≠ gate_decision）
// ---------------------------------------------------------------------------

test('receipt: execution_status 注入 pass、verdict 注入 reject、run_status 注入 pass → 拒绝', () => {
  const badExecution = makeFrozenWithValidDigest()
  badExecution.test_cases[0].attempts[0].execution_status = 'pass'
  assert.ok(validateReceiptV1(resign(badExecution)).errors.some((e) => e.startsWith('schema:enum:')))

  const badVerdict = makeFrozenWithValidDigest()
  badVerdict.test_cases[0].attempts[0].verdict = 'reject'
  assert.ok(validateReceiptV1(resign(badVerdict)).errors.some((e) => e.startsWith('schema:enum:')))

  const badRun = makeFrozenWithValidDigest()
  badRun.run_status = 'pass'
  assert.ok(validateReceiptV1(resign(badRun)).errors.some((e) => e.startsWith('schema:enum:')))

  const badGate = makeFrozenWithValidDigest()
  badGate.gate_decision = 'ok'
  assert.ok(validateReceiptV1(resign(badGate)).errors.some((e) => e.startsWith('schema:enum:')))
})

// ---------------------------------------------------------------------------
// 摘要与排除纪律
// ---------------------------------------------------------------------------

test('receipt: verifyDigest 通过合法摘要、拒绝正文篡改', () => {
  const receipt = makeFrozenWithValidDigest()
  assert.equal(validateReceiptV1(receipt, { verifyDigest: true }).ok, true)

  receipt.run_id = 'run-tampered'
  const result = validateReceiptV1(receipt, { verifyDigest: true })
  assert.equal(result.ok, false)
  assert.ok(result.errors.includes('record-digest-mismatch'))
})

test('receipt: 默认只做结构/形态校验，不擅自重算摘要', () => {
  const receipt = makeFrozenWithValidDigest()
  receipt.integrity.record_digest = DIGEST('9') // syntactically valid but stale
  assert.equal(validateReceiptV1(receipt).ok, true)
  assert.equal(validateReceiptV1(receipt, { verifyDigest: true }).ok, false)
})

test('receipt: schema 本身静态编码三种形态（oneOf 3 分支）', () => {
  assert.equal(RECEIPT_V1_SCHEMA.oneOf.length, 3)
  assert.equal(RECEIPT_V1_SCHEMA.additionalProperties, false)

  const frozen = makeFrozenWithValidDigest()
  assert.equal(validateValue(frozen, RECEIPT_V1_SCHEMA).ok, true)

  const forged = {
    ...frozen,
    plan_id: null,
    reconciliation: { expected: [], executed: [], missing: [], waived: [] },
  }
  const checked = validateValue(forged, RECEIPT_V1_SCHEMA)
  assert.equal(checked.ok, false)
  assert.ok(checked.errors.some((e) => e.startsWith('oneOf:')))
})

// ---------------------------------------------------------------------------
// 与 architecture §11.2.1 canonical 示例一一对应
// ---------------------------------------------------------------------------

test('receipt: architecture §11.2.1 canonical 示例逐字段通过严格 schema', () => {
  const result = validateReceiptV1(CANONICAL_RECEIPT_EXAMPLE)
  assert.deepEqual(result.errors, [])
  assert.equal(result.ok, true)
  assert.equal(result.form, 'frozen')
  assert.equal(validateValue(CANONICAL_RECEIPT_EXAMPLE, RECEIPT_V1_SCHEMA).ok, true)
})

test('receipt: canonical 示例中的摘要/时间仅为格式示意，不冒充完整性证据', () => {
  // The document explicitly says all digests/commits/timestamps in examples are
  // placeholders. Structural validation passes; digest recomputation does not.
  const result = validateReceiptV1(CANONICAL_RECEIPT_EXAMPLE, { verifyDigest: true })
  assert.equal(result.ok, false)
  assert.ok(result.errors.includes('record-digest-mismatch'))
})
