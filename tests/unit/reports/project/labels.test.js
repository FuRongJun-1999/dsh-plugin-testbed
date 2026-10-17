import { test } from 'node:test'
import assert from 'node:assert/strict'
import { JUNIT_MAP, TAP_MAP, junitFor, tapFor } from '../../../../src/reports/project/labels.js'

test('labels: junit map covers every required verdict & preserves original value', () => {
  assert.equal(JUNIT_MAP.pass.kind, 'pass')
  assert.equal(JUNIT_MAP.fail.kind, 'failure')
  assert.equal(JUNIT_MAP.skip.kind, 'skipped')
  assert.equal(JUNIT_MAP.error.kind, 'error')
  assert.equal(JUNIT_MAP.inconclusive.kind, 'skipped')
  assert.equal(JUNIT_MAP.inconclusive.properties['plugin-testbed.verdict'], 'inconclusive')
  assert.equal(JUNIT_MAP.missing.kind, 'error')
  assert.equal(JUNIT_MAP.missing.synth, true)
  assert.equal(JUNIT_MAP.missing.properties['plugin-testbed.verdict'], 'missing')
  assert.equal(JUNIT_MAP.not_run.kind, 'property-only')
  assert.equal(JUNIT_MAP.flaky.kind, 'property-only')
})

test('labels: tap map — inconclusive/missing never `ok` without marker', () => {
  assert.deepEqual(TAP_MAP.pass, { ok: true })
  assert.deepEqual(TAP_MAP.fail, { ok: false })
  assert.equal(TAP_MAP.skip.ok, true)
  assert.equal(TAP_MAP.skip.directive, 'SKIP')
  assert.equal(TAP_MAP.error.ok, false)
  assert.equal(TAP_MAP.error.directive, 'error')
  assert.equal(TAP_MAP.inconclusive.ok, true)
  assert.equal(TAP_MAP.inconclusive.directive, 'TODO inconclusive')
  assert.equal(TAP_MAP.missing.ok, false)
  assert.equal(TAP_MAP.missing.directive, 'missing')
  assert.equal(TAP_MAP.not_run.ok, null)
  assert.equal(TAP_MAP.flaky.ok, null)
})

test('labels: unknown verdict fails closed (never pass)', () => {
  assert.equal(junitFor('evil').kind, 'error')
  assert.equal(junitFor('evil').properties['plugin-testbed.verdict'], 'evil')
  assert.equal(tapFor('evil').ok, false)
})