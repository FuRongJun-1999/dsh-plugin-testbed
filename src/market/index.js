/**
 * Public market-gate surface (t8).
 *
 * Consumers import this entry (re-exported by `src/index.js` and the CLI) rather
 * than deep module paths. The gate is independent from the local selfcheck
 * profile: importing it never enables market publishing, and `runMarketGate`
 * remains fail-closed without real providers.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/market
 */
export { validateMarketPolicy, policyDigest, policyRef, } from './policy.js';
export { MARKET_CONDITION_IDS, MARKET_REASON_CODES, } from '../protocol/market-schemas.js';
export { validateApprovalLedger, } from './approvals.js';
export { CORDIS_PACKAGE, CONTRACT_CATALOG_FILE, CONTRACT_RESULTS_FILE, CONTRACT_SUITE_FILE, CONTRACT_SUITE_ID, DSH_PACKAGE, EXPECTED_DSH_VERSION, EXPECTED_NODE_VERSION, RUNTIME_MARKET_REASONS, runtimeAnchorDigest, verifyRuntimeEvidence, } from './runtime.js';
export { assessIsolation, normalizeAttestationInput, } from './isolation.js';
export { conditionIds, computeEligibility, marketManifestDigest, assessReceipt, } from './eligibility.js';
export { assessProviders, } from './providers.js';
export { buildEvidencePackage, describeArtifact, safeRelativePath, verifyEvidencePackage, writeEvidencePackage, } from './evidence-package.js';
export { runMarketGate, schedulerEvidenceFrom } from './gate.js';
