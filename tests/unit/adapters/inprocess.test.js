/**
 * src/adapters/inprocess.js 的单元测试（node:test）。
 * 覆盖：有 probe 正常回传 / 无 probe → rejected+error+not-started /
 * observation 归一化 / caller probe 的 started 声明不作为独立启动证据。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ISOLATION_LEVEL, makeInProcessPort } from '../../../src/adapters/inprocess.js'

test('ISOLATION_LEVEL 诚实标注为 L0-in-process（进程内，非隔离）', () => {
  assert.equal(ISOLATION_LEVEL, 'L0-in-process')
})

test('有 probe：逐字段组装 attempt 终态，admission=accepted，observation 归一化', () => {
  const port = makeInProcessPort()
  const out = port.execute({
    test_id: 't1',
    probe: {
      execution_status: 'completed',
      invocation_status: 'started',
      observations: [{ observation_id: 'obs-001', value: { status_code: 200 } }],
      reason_codes: [],
    },
  })
  assert.deepEqual(out, {
    admission_status: 'accepted',
    execution_status: 'completed',
    invocation_status: 'unknown',
    invocation_evidence_verified: false,
    observations: [
      { observation_id: 'obs-001', value: { status_code: 200 }, source: 'worker', limitations: [] },
    ],
    reason_codes: [],
  })
})

test('无 probe → rejected + error + not-started + no-probe，无 observation', () => {
  const port = makeInProcessPort()
  const out = port.execute({ test_id: 't2' })
  assert.deepEqual(out, {
    admission_status: 'rejected',
    execution_status: 'error',
    invocation_status: 'not-started',
    observations: [],
    reason_codes: ['no-probe'],
  })
})

test('observation 归一化：source=worker、limitations 缺省 []、observation_id 缺省补 obs-<序号>', () => {
  const port = makeInProcessPort()
  const out = port.execute({
    test_id: 't3',
    probe: {
      execution_status: 'completed',
      observations: [
        { value: { a: 1 } },
        { observation_id: 'keep-me', value: { b: 2 }, schema_ref: 'urn:s', limitations: ['x'] },
      ],
    },
  })
  assert.equal(out.observations.length, 2)
  assert.deepEqual(out.observations[0], {
    observation_id: 'obs-1',
    value: { a: 1 },
    source: 'worker',
    limitations: [],
  })
  assert.deepEqual(out.observations[1], {
    observation_id: 'keep-me',
    schema_ref: 'urn:s',
    value: { b: 2 },
    source: 'worker',
    limitations: ['x'],
  })
})

test('默认值：probe 缺 execution_status/invocation_status → completed/unknown，且无可信启动证据', () => {
  const port = makeInProcessPort()
  const out = port.execute({ test_id: 't4', probe: { observations: [] } })
  assert.equal(out.execution_status, 'completed')
  assert.equal(out.invocation_status, 'unknown')
  assert.equal(out.invocation_evidence_verified, false)
  assert.equal(out.admission_status, 'accepted')
  assert.deepEqual(out.observations, [])
  assert.deepEqual(out.reason_codes, [])
})

test('caller 伪造 invocation_status=started 不能升级为可信 started', () => {
  const port = makeInProcessPort()
  const out = port.execute({
    test_id: 'spoofed-start',
    probe: { execution_status: 'completed', invocation_status: 'started', invocation_evidence_verified: true },
  })
  assert.equal(out.invocation_status, 'unknown')
  assert.equal(out.invocation_evidence_verified, false)
})

test('reason_codes 按输入保留', () => {
  const port = makeInProcessPort()
  const out = port.execute({ test_id: 't5', probe: { reason_codes: ['a', 'b'] } })
  assert.deepEqual(out.reason_codes, ['a', 'b'])
})

test('硬约束：返回对象上绝不携带 verdict/gate_decision/required/expected/plan 键', () => {
  const port = makeInProcessPort()
  const forbidden = ['verdict', 'gate_decision', 'required', 'expected', 'plan', 'plan_id']
  const cases = [
    { test_id: 'no-probe' },
    {
      test_id: 'with-probe',
      probe: { observations: [{ value: 1 }, { observation_id: 'x', value: 2, schema_ref: 's' }], reason_codes: [] },
    },
    {
      test_id: 'with-extra-fields',
      probe: { execution_status: 'cancelled', invocation_status: 'unknown', observations: [], reason_codes: ['r'] },
    },
  ]
  for (const caseSpec of cases) {
    const out = port.execute(caseSpec)
    for (const key of forbidden) {
      assert.ok(!(key in out), `caseSpec=${caseSpec.test_id} 不应携带字段 ${key}`)
    }
  }
})