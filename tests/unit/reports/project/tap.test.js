import { test } from 'node:test'
import assert from 'node:assert/strict'
import { project } from '../../../../src/reports/project/index.js'
import { makeReceipt } from './_fixtures.js'

test('tap: pass/fail/skip/error/inconclusive/missing map to ok/not-ok with markers', () => {
  const { body } = project(makeReceipt(), 'tap', 'exporter-tap')
  assert.match(body, /ok \d+ - t\.case-pass\b/)
  assert.match(body, /not ok \d+ - t\.case-fail\b/)
  assert.match(body, /ok \d+ - t\.case-skip # SKIP policy_rejected/)
  assert.match(body, /not ok \d+ - t\.case-error # error/)
  assert.match(body, /ok \d+ - t\.case-inconclusive # TODO inconclusive/)
  assert.match(body, /not ok \d+ - t\.case-missing # missing/)
  assert.match(body, /# reason: equals-mismatch/)
})

test('tap: blocked gate → Bail out!', () => {
  const { body } = project(makeReceipt({ gateDecision: 'blocked', gateReason: 'missing-required' }), 'tap', 'e')
  assert.match(body, /Bail out! missing-required/)
  assert.doesNotMatch(body, /^ok .*#.*$/)
})

test('tap: plan line counts only real points', () => {
  const { body } = project(makeReceipt(), 'tap', 'e')
  assert.match(body, /^1\.\.6$/m)
})

test('tap: deterministic byte-stable output', () => {
  const receipt = makeReceipt()
  assert.equal(project(receipt, 'tap', 'e').body, project(receipt, 'tap', 'e').body)
})