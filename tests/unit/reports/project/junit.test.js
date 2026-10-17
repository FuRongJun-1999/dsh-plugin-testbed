import { test } from 'node:test'
import assert from 'node:assert/strict'
import { project } from '../../../../src/reports/project/index.js'
import { makeReceipt } from './_fixtures.js'

test('junit: per-verdict elements — pass/fail/skip/error/inconclusive/missing', () => {
  const { body } = project(makeReceipt(), 'junit', 'exporter-junit')
  assert.match(body, /<testcase[^>]*name="t\.case-pass"/)
  assert.match(body, /<failure[^>]*message="criteria:assert\/contract@1\.0\.0 \| equals-mismatch"/)
  assert.match(body, /<skipped message="policy_rejected"/)
  assert.match(body, /<error[^>]*message="boom"/)
  // inconclusive → <skipped> + property
  assert.match(body, /name="t\.case-inconclusive"[^>]*>.*<skipped/)
  assert.match(body, /plugin-testbed\.verdict" value="inconclusive"/)
  // missing → synthesized error + property, not washed to pass
  assert.match(body, /name="t\.case-missing"/)
  assert.match(body, /plugin-testbed\.verdict" value="missing"/)
  assert.match(body, /reconciliation gap/)
})

test('junit: original verdict value always visible on every testcase', () => {
  const { body } = project(makeReceipt(), 'junit', 'e')
  assert.ok(body.includes('plugin-testbed.verdict" value="pass"'))
  assert.ok(body.includes('plugin-testbed.verdict" value="fail"'))
  assert.ok(body.includes('plugin-testbed.verdict" value="skip"'))
  assert.ok(body.includes('plugin-testbed.verdict" value="error"'))
  assert.ok(body.includes('plugin-testbed.verdict" value="inconclusive"'))
  assert.ok(body.includes('plugin-testbed.verdict" value="missing"'))
})

test('junit: blocked gate emits suite-level failure summary (not success)', () => {
  const { body } = project(makeReceipt({ gateDecision: 'blocked', gateReason: 'missing-required' }), 'junit', 'e')
  assert.match(body, /plugin-testbed\.gate_decision" value="blocked"/)
  assert.match(body, /<failure type="gate-blocked" message="missing-required"/)
})

test('junit: deterministic byte-stable output', () => {
  const receipt = makeReceipt()
  assert.equal(project(receipt, 'junit', 'e').body, project(receipt, 'junit', 'e').body)
})