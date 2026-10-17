/**
 * JUnit-style XML projection (read-only). Deterministic string building; original
 * verdict is always retained via a `plugin-testbed.verdict` property on every
 * testcase, so `inconclusive`/`missing` are never laundered into `pass`.
 * @module @deepseek-ai/dsh-plugin-testbed/reports/project/junit
 */
import { junitFor } from './labels.js'

const SUITE = 'dsh-plugin-testbed'
const XML_DECL = '<?xml version="1.0" encoding="UTF-8"?>\n'

/**
 * Render a projection model as JUnit-style XML.
 * @param {{meta:object, reconcliation:object|null, entries:Array}} model
 * @param {string} exporterId
 * @returns {string}
 */
export function renderJUnit(model, exporterId) {
  const entries = model.entries
  const meta = model.meta

  let failures = 0
  let errors = 0
  let skipped = 0
  for (const e of entries) {
    const kind = junitFor(e.verdict).kind
    if (kind === 'failure') failures++
    else if (kind === 'error') errors++
    else if (kind === 'skipped') skipped++
  }
  const tests = entries.length

  const props = [
    ['plugin-testbed.run_id', meta.run_id],
    ['plugin-testbed.gate_decision', meta.gate_decision],
    ['plugin-testbed.gate_reason', meta.gate_reason],
    ['plugin-testbed.trust_scope', meta.trust_scope],
    ['plugin-testbed.market_eligible', meta.market_eligible == null ? null : String(meta.market_eligible)],
    ['plugin-testbed.exporter_id', exporterId],
    ['plugin-testbed.source_receipt_digest', meta.source_receipt_digest],
  ]
  if (meta.gate_decision === 'blocked') {
    props.push(['plugin-testbed.gate_blocked_reason', meta.gate_reason ?? 'blocked'])
  }

  const lines = []
  lines.push(XML_DECL)
  lines.push(
    `<testsuites name="${esc(SUITE)}" tests="${tests}" failures="${failures}" errors="${errors}" skipped="${skipped}">`,
  )
  lines.push(
    `  <testsuite name="${esc(SUITE)}" tests="${tests}" failures="${failures}" errors="${errors}" skipped="${skipped}">`,
  )

  // top-level properties (gate_decision always visible; blocked adds summary)
  lines.push('    <properties>')
  for (const [name, value] of props) {
    if (value == null) continue
    lines.push(`      <property name="${esc(name)}" value="${esc(String(value))}"/>`)
  }
  lines.push('    </properties>')

  // suite-level failure summary when the gate is blocked (never success)
  if (meta.gate_decision === 'blocked') {
    lines.push(`    <failure type="gate-blocked" message="${esc(meta.gate_reason ?? 'blocked')}"/>`)
  }

  for (const e of entries) {
    lines.push('    ' + renderTestCase(e))
  }

  lines.push('  </testsuite>')
  lines.push('</testsuites>')
  return lines.join('\n') + '\n'
}

function renderTestCase(e) {
  const mapping = junitFor(e.verdict)
  const name = e.isMissing ? e.test_id : e.test_id
  const cls = e.classification ?? 'unknown'

  const props = [
    ['plugin-testbed.verdict', e.verdict],
    ['plugin-testbed.invocation_status', e.invocation_status],
    ['plugin-testbed.attempts', e.attempts.length],
    ['plugin-testbed.classification', cls],
    ['plugin-testbed.admission_status', e.admission_status],
    ['plugin-testbed.execution_status', e.execution_status],
    ['plugin-testbed.criteria_ref', e.criteria_ref],
  ]
  // mapping-specific properties (inconclusive / missing / not_run / flaky labels)
  if (mapping.properties) {
    for (const [k, v] of Object.entries(mapping.properties)) props.push([k, v])
  }

  let children = ''
  const reason = reasonText(e)
  if (mapping.kind === 'failure') {
    children = `<failure type="assertion-failure" message="${esc(reason || 'failed')}"/>`
  } else if (mapping.kind === 'skipped') {
    children = `<skipped message="${esc(reason || e.verdict)}"/>`
  } else if (mapping.kind === 'error') {
    children = `<error type="test-error" message="${esc(reason || (e.isMissing ? 'reconciliation gap (not an execution result)' : 'error'))}"/>`
  }
  // property-only kinds (not_run/flaky): no terminal verdict element → no child

  const propXml = props
    .filter(([, v]) => v != null && v !== '')
    .map(([k, v]) => `<property name="${esc(k)}" value="${esc(String(v))}"/>`)
    .join('')

  const openTag = `<testcase classname="${esc(SUITE)}" name="${esc(name)}"`
  if (propXml || children) {
    return openTag + '>' + (propXml ? `<properties>${propXml}</properties>` : '') + children + '</testcase>'
  }
  return openTag + '/>'
}

function reasonText(e) {
  const parts = []
  if (e.criteria_ref) parts.push(`criteria:${e.criteria_ref}`)
  if (Array.isArray(e.reason_codes) && e.reason_codes.length) parts.push(e.reason_codes.join(';'))
  return parts.filter(Boolean).join(' | ')
}

function esc(s) {
  return String(s ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;')
}