/**
 * 公共门面：对外只暴露 runSelfCheck（DSH 工具入口、CI、开发者脚本共享同一实现）。
 * @module @deepseek-ai/dsh-plugin-testbed
 */
export { runSelfCheck } from './kernel.js'
export { canonicalJson, sha256Hex, recordDigest, verifyRecordDigest, FIXED_VECTOR_INPUT, FIXED_VECTOR_DIGEST } from './protocol/digest.js'
export { project, projectAll, PROJECT_FORMATS } from './reports/project/index.js'

// Market-stage entry (t8). Independent from the local selfcheck profile: it
// never upgrades a local pass to market eligible and stays blocked when real
// isolation/signing/archive providers are missing.
export {
  runMarketGate,
  computeEligibility,
  assessReceipt,
  validateMarketPolicy,
  verifyRuntimeEvidence,
  assessIsolation,
  assessProviders,
  buildEvidencePackage,
  verifyEvidencePackage,
  MARKET_CONDITION_IDS,
  MARKET_REASON_CODES,
} from './market/index.js'

// Scheduler entry (t11). Default is disabled; enabling requires an explicit
// frozen policy + operator authorization and a durable store. The entry only
// reports status and closes the store; it never starts a timer/cron loop and
// never affects market eligibility.
export { describeSchedulerEntry } from './scheduler/index.js'
