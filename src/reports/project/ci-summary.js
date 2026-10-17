/**
 * CI summary projection (read-only). Includes source_receipt_digest, exporter_id,
 * local-profile exit code, gate_decision, trust markers and reconciliation counts.
 * Never derives `market_eligible=true` from a local pass.
 * @module @deepseek-ai/dsh-plugin-testbed/reports/project/ci-summary
 */

/**
 * Render a projection model as a CI summary text block.
 * @param {{meta:object, reconciliation:object|null}} model
 * @param {string} exporterId
 * @returns {string}
 */
export function renderCiSummary(model, exporterId) {
  const m = model.meta
  const rec = model.reconciliation
  const lines = []
  lines.push(`source_receipt_digest: ${m.source_receipt_digest ?? ''}`)
  lines.push(`exporter_id: ${exporterId}`)
  lines.push(`exit_code(local): ${localExitCode(m.gate_decision)}`)
  lines.push(`gate_decision: ${m.gate_decision ?? ''}`)
  lines.push(`trust_scope: ${m.trust_scope ?? ''}`)
  lines.push(`market_eligible: ${m.market_eligible === true ? 'true' : 'false'}`)
  lines.push(`run_status: ${m.run_status ?? ''}`)
  lines.push(
    `reconciliation: expected=${rec ? rec.expected.length : 0} executed=${rec ? rec.executed.length : 0} missing=${rec ? rec.missing.length : 0} waived=${rec ? rec.waived.length : 0}`,
  )
  return lines.join('\n') + '\n'
}

/** Local profile exit code; never market-derived. */
function localExitCode(gateDecision) {
  if (gateDecision === 'pass') return 0
  if (gateDecision === 'reject') return 1
  return 2
}