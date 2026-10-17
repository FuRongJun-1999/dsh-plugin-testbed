/**
 * Schema contracts (declarative). Validation of the receipt shape is enforced
 * by `reports/shape.js`; unknown major versions are rejected, no implicit
 * downgrade (architecture §11.2.1, development-plan §协议/receipt 契约).
 * @module @deepseek-ai/dsh-plugin-testbed/protocol/schemas
 */
import {
  RECEIPT_SCHEMA_VERSION,
  RUN_SPEC_VERSION,
  TEST_TOOL_MANIFEST_VERSION,
  TEST_TOOL_PROTOCOL_VERSION,
} from './enums.js'

/** @param {string} v */
export function isReceiptSchemaVersion(v) {
  return v === RECEIPT_SCHEMA_VERSION
}
/** @param {string} v */
export function isRunSpecVersion(v) {
  return v === RUN_SPEC_VERSION
}
/** @param {string} v */
export function isTestToolManifestVersion(v) {
  return v === TEST_TOOL_MANIFEST_VERSION
}
/** @param {string} v */
export function isTestToolProtocolVersion(v) {
  return v === TEST_TOOL_PROTOCOL_VERSION
}

/**
 * Minimal `receipt/v1` JSON Schema (Draft 2020-12). Structural invariants
 * (three mutually-exclusive forms) are additionally enforced by shape guards.
 */
export const RECEIPT_V1_SCHEMA = Object.freeze({
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'urn:dsh:plugin-testbed:receipt:v1',
  type: 'object',
  required: [
    'receipt_schema_version', 'run_id', 'trust_scope', 'market_eligible',
    'run_status', 'integrity',
  ],
  properties: {
    receipt_schema_version: { const: 'receipt/v1' },
    run_id: { type: 'string' },
    trust_scope: { const: 'local-only' },
    market_eligible: { const: false },
    run_status: { enum: ['queued', 'running', 'completed', 'cancelled', 'blocked'] },
    integrity: {
      type: 'object',
      required: ['record_digest', 'signed'],
      properties: { record_digest: { type: 'string' }, signed: { const: false } },
    },
  },
})