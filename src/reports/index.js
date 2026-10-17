/**
 * Reports facade: re-exports projection entry points (read-only projections
 * only; receipt persistence + integrity are in shape/receipt/exit).
 * @module @deepseek-ai/dsh-plugin-testbed/reports
 */
export { project, projectAll, PROJECT_FORMATS } from './project/index.js'
export { buildReceipt, verifyReceipt } from './shape.js'
export { persistReceipt } from './receipt.js'
export { resolveExitCode } from './exit.js'