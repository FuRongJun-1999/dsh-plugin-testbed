/**
 * Public control-kernel surface (`src/control/`).
 *
 * Wiring order (implementation-design-control §1.2):
 *   compilePlanCandidate → verifyCapabilitySnapshot + freezePlan →
 *   executeFrozenPlan → reconcile / reconcileAdoptedAttempts →
 *   aggregateGateDecision
 *
 * All functions except `executeFrozenPlan` are pure and offline-recomputable.
 * The kernel composes them; control never imports adapters/worker/reports.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/control
 */
export {
  compilePlanCandidate,
  freezePlan,
  verifyFrozenPlan,
  rejectPlanMutation,
  planResolutionEntries,
  predicateVersionFor,
  MAX_PLAN_CASES,
  MAX_CASE_ATTEMPTS,
  MAX_PLAN_TOTAL_ATTEMPTS,
} from './plan.js'
export {
  compileScenarioGraph,
  validateScenario,
  schemasCompatible,
  SUPPORTED_NODE_TYPES,
  SUPPORTED_ASSERTIONS,
} from './graph.js'
export { validateRunSpec, validateGatePolicy, isPinnedVersion, pathContainment } from './spec.js'
export {
  verifyCapabilitySnapshot,
  verifySnapshotBindings,
  deriveVerification,
  normalizeCapabilitySnapshots,
  capabilitySnapshotRef,
  CAPABILITY_PREDICATE_VERSION,
} from './capability.js'
export { decideAdmission, ADMISSION_REASONS } from './admission.js'
export { executeFrozenPlan, buildToolRequest, adoptInvocationEvidence, CONTROL_EVIDENCE_SOURCES } from './execute.js'
export { reconcile, reconcileAdoptedAttempts } from './reconcile.js'
export { aggregateGateDecision } from './gate.js'
export { applyAssertion } from './assert.js'
export {
  normalizeAttempt,
  normalizeAdmissionStatus,
  summarizeCaseState,
  hasVerifiedStartedPass,
  findAuthorityFields,
  AUTHORITY_FIELDS,
} from './state.js'
export {
  RUN_BUDGET_VERSION,
  DEFAULT_RUN_BUDGET,
  PLATFORM_BUDGET_CEILINGS,
  BUDGET_ENFORCED_AT_L1,
  BUDGET_UNENFORCED_AT_L1,
  validateRunBudget,
  resolveRunBudget,
  planDeclaredAttempts,
  assertPlanAttemptsWithinBudget,
  createBudgetLedger,
} from './budget.js'
