/**
 * Shared fail-closed size limits for the trusted control kernel (architecture
 * §9.4, development-plan「有界图编译」). Kept in one module so `plan.js`,
 * `graph.js` and `budget.js` can share the exact same ceilings without a module
 * cycle.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/control/limits
 */
import { MAX_RETRY_ATTEMPTS } from '../protocol/tool-manifest.js'

/** Maximum number of candidate plan cases / scenario nodes in one run. */
export const MAX_PLAN_CASES = 256

/** Maximum attempts per test case (including the first attempt). */
export const MAX_CASE_ATTEMPTS = MAX_RETRY_ATTEMPTS

/** Maximum aggregate declared attempts of a whole candidate plan. */
export const MAX_PLAN_TOTAL_ATTEMPTS = MAX_PLAN_CASES * MAX_CASE_ATTEMPTS
