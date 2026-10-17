/**
 * Canonical closed enums — the single vocabulary per architecture.md §9.5.
 * Do not invent synonymous values anywhere else in the codebase.
 * @module @deepseek-ai/dsh-plugin-testbed/protocol/enums
 */

export const RUN_STATUS = Object.freeze(['queued', 'running', 'completed', 'cancelled', 'blocked'])
export const ADMISSION_STATUS = Object.freeze(['accepted', 'rejected'])
export const EXECUTION_STATUS = Object.freeze(['completed', 'skipped', 'error', 'timeout', 'cancelled'])
export const INVOCATION_STATUS = Object.freeze(['not-started', 'started', 'unknown'])
export const VERDICT = Object.freeze(['pass', 'fail', 'skip', 'error', 'inconclusive'])
export const GATE_DECISION = Object.freeze(['pass', 'reject', 'blocked'])

// Auxiliary vocabularies (architecture §8.3 / §8.4.1).
export const CAPABILITY_CLAIM = Object.freeze(['declared', 'not-declared'])
export const CAPABILITY_OBSERVED = Object.freeze(['present', 'absent', 'unknown'])
export const CAPABILITY_VERIFICATION = Object.freeze(['corroborated', 'contradicted', 'not-run'])
export const TOOL_ADMISSION_STAGE = Object.freeze(['draft', 'validated', 'pinned'])
export const TOOL_ATTEMPT_STAGE = Object.freeze(['prepared', 'running', 'completed', 'skipped', 'error', 'timeout', 'cancelled'])

// Version boundaries (architecture §11.2.1 / §8.4.1).
export const RECEIPT_SCHEMA_VERSION = 'receipt/v1'
export const TEST_TOOL_MANIFEST_VERSION = 'test-tool-manifest/v1'
export const TEST_TOOL_PROTOCOL_VERSION = 'test-tool/v1'
export const RUN_SPEC_VERSION = 'run-spec/v1'

export const TRUST_SCOPE = Object.freeze(['local-only'])

export const EXIT_CODE_PROFILES = Object.freeze(['local-selfcheck/v1', 'market-required/v1'])

/** @param {string} v */
export function inSet(set, v) {
  return Array.isArray(set) && set.includes(v)
}