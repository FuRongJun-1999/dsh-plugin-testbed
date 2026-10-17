/**
 * TAP projection (read-only). `missing` → `not ok … # missing`; `inconclusive`
 * → `ok … # TODO inconclusive`; `policy_rejected` skip keeps its reason. A
 * `blocked` gate emits `Bail out!` (never success).
 * @module @deepseek-ai/dsh-plugin-testbed/reports/project/tap
 */
import { tapFor } from './labels.js'

/**
 * Render a projection model as TAP text.
 * @param {{meta:object, entries:Array}} model
 * @param {string} exporterId
 * @returns {string}
 */
export function renderTAP(model, exporterId) {
  const entries = model.entries
  const meta = model.meta

  // numbered points: every verdict with a definite ok/not-ok
  const points = entries.filter((e) => tapFor(e.verdict).ok !== null)
  const plan = points.length

  const lines = []
  lines.push('TAP version 13')
  lines.push(`# exporter_id: ${exporterId}`)
  lines.push(`# source_receipt_digest: ${meta.source_receipt_digest ?? ''}`)
  lines.push(`1..${plan}`)

  let n = 0
  for (const e of entries) {
    const m = tapFor(e.verdict)
    if (m.ok === null) {
      // not_run / flaky → comment line, never a test point
      lines.push(`# ${e.test_id} ${m.comment}`)
      continue
    }
    n++
    const label = `${m.ok ? 'ok' : 'not ok'} ${n} - ${e.test_id}`
    if (m.directive) {
      lines.push(`${label} # ${m.directive}${directiveExtra(e)}`)
    } else {
      lines.push(label)
    }
    if (m.ok === false && e.reason_codes && e.reason_codes.length) {
      lines.push(`  # reason: ${e.reason_codes.join('; ')}`)
    }
  }

  if (meta.gate_decision === 'blocked') {
    lines.push(`Bail out! ${meta.gate_reason ?? 'blocked'}`)
  }
  return lines.join('\n') + '\n'
}

function directiveExtra(e) {
  if (e.verdict === 'skip' && e.reason_codes && e.reason_codes.length) {
    return ` ${e.reason_codes.join('; ')}`
  }
  return ''
}