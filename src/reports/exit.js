/**
 * Versioned exit-code profile (development "持久化 receipt 与 CI 接口";
 * plugin-reports §5.3 matrix). Pure function of (receipt|write-failure, profileId).
 * @module @deepseek-ai/dsh-plugin-testbed/reports/exit
 */
import { isReceiptSchemaVersion } from '../protocol/schemas.js'
import { verifyRecordDigest } from '../protocol/digest.js'

/**
 * Resolve a process exit code.
 *
 * @param {{kind:'write-failure'} | {kind:'receipt', receipt:object}} input
 * @param {string} profileId `local-selfcheck/v1` | `market-required/v1`
 * @returns {number} 0 | 1 | 2 | 3
 */
export function resolveExitCode(input, profileId) {
  if (!input || typeof input !== 'object') return 3
  if (input.kind === 'write-failure') return 3
  if (input.kind !== 'receipt') return 3

  const receipt = input.receipt
  if (receiptInvalid(receipt)) return 3

  if (profileId === 'market-required/v1') return 2 // local receipt never market-eligible
  if (profileId === 'local-selfcheck/v1') {
    const gd = receipt.gate_decision
    if (gd === 'pass') return 0
    if (gd === 'reject') return 1
    return 2 // blocked (or any other) — never success
  }
  return 3 // unknown profile
}

/** Invalid ⇒ process-level `3`. Schema version / digest / trust markers / shape. */
function receiptInvalid(receipt) {
  if (!receipt || typeof receipt !== 'object') return true
  if (!isReceiptSchemaVersion(receipt.receipt_schema_version)) return true
  if (receipt.trust_scope !== 'local-only') return true
  if (receipt.market_eligible !== false) return true
  if (receipt.integrity?.signed !== false) return true
  if (!verifyRecordDigest(receipt).ok) return true
  // shape invariants (mirrors shape.verifyReceipt)
  if (receipt.plan_id == null) {
    if (receipt.reconciliation != null) return true
    if (receipt.gate_decision !== 'blocked') return true
  } else {
    if (receipt.reconciliation == null) return true
    if (receipt.gate_decision !== 'pass' && receipt.gate_decision !== 'reject' && receipt.gate_decision !== 'blocked') {
      return true
    }
  }
  return false
}