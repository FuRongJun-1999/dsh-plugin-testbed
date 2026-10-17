/**
 * The single mapping point from receipt verdict → external-format labels.
 * Original enum values are always preserved (never laundered into `pass`).
 * Unknown verdicts fail-closed (JUnit → error-kind, TAP → `not ok`), never `pass`.
 * @module @deepseek-ai/dsh-plugin-testbed/reports/project/labels
 */

/**
 * Verdict → JUnit-style rendering kind.
 *   pass:          <testcase> only (properties carry retention info)
 *   fail:          <failure>
 *   skip:          <skipped> (includes `policy_rejected`)
 *   error:         <error>
 *   inconclusive:  <skipped> + property `plugin-testbed.verdict=inconclusive`
 *   missing:       synthesized <testcase> + <error> + property `verdict=missing`
 *   not_run:       property only (no testcase synthesized)
 *   flaky:         property only (diagnostic; never a terminal verdict)
 */
export const JUNIT_MAP = Object.freeze({
  pass: { kind: 'pass' },
  fail: { kind: 'failure' },
  skip: { kind: 'skipped' },
  error: { kind: 'error' },
  inconclusive: {
    kind: 'skipped',
    properties: { 'plugin-testbed.verdict': 'inconclusive' },
  },
  missing: {
    kind: 'error',
    synth: true,
    properties: { 'plugin-testbed.verdict': 'missing' },
  },
  not_run: { kind: 'property-only', properties: { 'plugin-testbed.verdict': 'not_run' } },
  flaky: { kind: 'property-only', properties: { 'plugin-testbed.flaky': 'true' } },
})

/**
 * Verdict → TAP mapping.
 *   pass: ok / fail: not ok / skip: ok # SKIP / error: not ok # error
 *   inconclusive: ok # TODO inconclusive / missing: not ok # missing
 *   not_run / flaky: comment line (never a numbered test point)
 */
export const TAP_MAP = Object.freeze({
  pass: { ok: true },
  fail: { ok: false },
  skip: { ok: true, directive: 'SKIP' },
  error: { ok: false, directive: 'error' },
  inconclusive: { ok: true, directive: 'TODO inconclusive' },
  missing: { ok: false, directive: 'missing' },
  not_run: { ok: null, comment: 'not_run' },
  flaky: { ok: null, comment: 'flaky' },
})

/** @param {string} verdict */
export function junitFor(verdict) {
  return (
    JUNIT_MAP[verdict] ??
    { kind: 'error', properties: { 'plugin-testbed.verdict': String(verdict ?? 'unknown') } }
  )
}

/** @param {string} verdict */
export function tapFor(verdict) {
  return TAP_MAP[verdict] ?? { ok: false, directive: 'unknown' }
}