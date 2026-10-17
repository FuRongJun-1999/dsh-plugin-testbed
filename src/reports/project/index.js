/**
 * Projection facade: `project` / `projectAll` / `PROJECT_FORMATS`.
 * Read-only: verifies the receipt first, then renders a pure string body.
 * Never mutates the receipt; never changes verdict/gate_decision.
 * @module @deepseek-ai/dsh-plugin-testbed/reports/project
 */
import { verifyReceipt } from '../shape.js'
import { buildModel } from './model.js'
import { renderJUnit } from './junit.js'
import { renderTAP } from './tap.js'
import { renderHTML } from './html.js'
import { renderCiSummary } from './ci-summary.js'

export const PROJECT_FORMATS = Object.freeze(['junit', 'tap', 'html', 'ci-summary'])

const FORMAT_VERSIONS = Object.freeze({
  junit: 'junit/v1',
  tap: 'tap/v1',
  html: 'html/v1',
  'ci-summary': 'ci-summary/v1',
})

const RENDERERS = {
  junit: renderJUnit,
  tap: renderTAP,
  html: renderHTML,
  'ci-summary': renderCiSummary,
}

/**
 * Project one receipt into one format.
 *
 * @param {object} receipt verified receipt/v1
 * @param {string} format one of {@link PROJECT_FORMATS}
 * @param {string} exporterId
 * @returns {{exporter_id:string, format_version:string, source_receipt_digest:string|null, body:string}}
 * @throws {Error} if the receipt is invalid or the format is unknown
 */
export function project(receipt, format, exporterId) {
  const v = verifyReceipt(receipt)
  if (v.status !== 'ok') {
    throw new Error(`project: invalid receipt (${v.status}: ${v.detail})`)
  }
  if (!PROJECT_FORMATS.includes(format)) {
    throw new Error(`project: unknown format ${String(format)}`)
  }
  const model = buildModel(receipt)
  const body = RENDERERS[format](model, exporterId ?? '')
  return {
    exporter_id: exporterId ?? '',
    format_version: FORMAT_VERSIONS[format],
    source_receipt_digest: model.meta.source_receipt_digest,
    body,
  }
}

/**
 * Project a receipt into all four formats at once (single verify).
 *
 * @param {object} receipt verified receipt/v1
 * @param {string} exporterId
 * @returns {{junit:object, tap:object, html:object, 'ci-summary':object}}
 */
export function projectAll(receipt, exporterId) {
  const v = verifyReceipt(receipt)
  if (v.status !== 'ok') {
    throw new Error(`projectAll: invalid receipt (${v.status}: ${v.detail})`)
  }
  const model = buildModel(receipt)
  const out = {}
  for (const format of PROJECT_FORMATS) {
    out[format] = {
      exporter_id: exporterId ?? '',
      format_version: FORMAT_VERSIONS[format],
      source_receipt_digest: model.meta.source_receipt_digest,
      body: RENDERERS[format](model, exporterId ?? ''),
    }
  }
  return out
}