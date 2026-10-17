/**
 * Human-readable HTML projection (read-only). Fixed section order per
 * architecture §11.2.2: run summary → target/env/isolation → Plan reconciliation
 * → per-test results+attempts → findings/metrics → evidence & limitations →
 * reproduction → GateDecision & next steps.
 * @module @deepseek-ai/dsh-plugin-testbed/reports/project/html
 */
import { stableJson } from './model.js'

/**
 * Render a projection model as an HTML string.
 * @param {{meta:object, reconciliation:object|null, entries:Array}} model
 * @param {string} exporterId
 * @returns {string}
 */
export function renderHTML(model, exporterId) {
  const m = model.meta
  const rec = model.reconciliation
  const entries = model.entries

  const secs = []

  // 1. run summary + trust scope
  secs.push(
    section(
      'Run summary & trust scope',
      kv([
        ['run_id', m.run_id],
        ['run_status', m.run_status],
        ['trust_scope', m.trust_scope],
        ['market_eligible', m.market_eligible],
        ['gate_decision', m.gate_decision],
        ['gate_reason', m.gate_reason],
        ['exporter_id', exporterId],
      ]),
    ),
  )

  // 2. target / environment / isolation
  secs.push(
    section(
      'Target, environment & isolation',
      kv([
        ['target_ref', m.target_ref ? stableJson(m.target_ref) : null],
        ['provenance', m.provenance ? stableJson(m.provenance) : null],
        ['limitations', Array.isArray(m.limitations) ? m.limitations.join('; ') : null],
      ]),
    ),
  )

  // 3. Plan reconciliation
  secs.push(
    section(
      'Plan reconciliation',
      kv([
        ['plan_id', m.plan_id],
        ['expected', rec ? rec.expected.length : null],
        ['executed', rec ? rec.executed.length : null],
        ['missing', rec ? rec.missing.length : null],
        ['waived', rec ? rec.waived.length : null],
      ]),
    ),
  )

  // 4. per-test results + attempts
  const rows = entries
    .map((e) => {
      const attempts = e.attempts
        .map((a) => `#${a.attempt} ${a.verdict ?? '-'}(inv:${a.invocation_status ?? '-'})`)
        .join(' ')
      return `<tr><td>${esc(e.test_id)}</td><td>${esc(e.verdict)}</td><td>${esc(e.invocation_status ?? '')}</td><td>${esc(attempts)}</td><td>${esc((e.reason_codes ?? []).join('; '))}</td></tr>`
    })
    .join('')
  secs.push(
    section(
      'Test cases',
      `<table><thead><tr><th>test_id</th><th>verdict</th><th>invocation</th><th>attempts</th><th>reason_codes</th></tr></thead><tbody>${rows}</tbody></table>`,
    ),
  )

  // 5. findings / metrics
  secs.push(
    section(
      'Findings & metrics',
      kv([
        ['observations', m.observation_count],
        ['artifacts', m.artifact_count],
      ]),
    ),
  )

  // 6. evidence & limitations
  secs.push(
    section(
      'Evidence & limitations',
      kv([
        ['source_receipt_digest', m.source_receipt_digest],
        ['integrity.signed', m.integrity_signed],
        ['limitations', Array.isArray(m.limitations) ? m.limitations.join('; ') : null],
      ]),
    ),
  )

  // 7. reproduction
  secs.push(
    section(
      'Reproduction',
      kv([
        ['run_id', m.run_id],
        ['plan_id', m.plan_id],
        ['profile_ref', m.profile_ref ? stableJson(m.profile_ref) : null],
        ['scenario_ref', m.scenario_ref ? stableJson(m.scenario_ref) : null],
        ['provenance', m.provenance ? stableJson(m.provenance) : null],
      ]),
    ),
  )

  // 8. GateDecision & next steps
  const next = m.market_eligible === false ? 'local-only (not market eligible)' : 'market eligible'
  secs.push(section('GateDecision & next steps', kv([['gate_decision', m.gate_decision], ['gate_reason', m.gate_reason], ['next', next]])))

  return `<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8"><title>DSH plugin-testbed report</title></head><body><h1>DSH plugin-testbed report</h1>${secs.join('')}</body></html>\n`
}

function section(title, inner) {
  return `<section><h2>${esc(title)}</h2>${inner}</section>`
}

function kv(rows) {
  return `<dl>${rows
    .filter(([, v]) => v !== null && v !== undefined)
    .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(String(v))}</dd>`)
    .join('')}</dl>`
}

function esc(s) {
  return String(s ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
}