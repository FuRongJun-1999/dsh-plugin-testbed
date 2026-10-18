/**
 * Market-gate integration types (t8).
 *
 * The market gate is an independent control-plane entry. It never rewrites
 * `receipt/v1`; every market conclusion lives in a sidecar
 * (`market-eligibility/v1`, `market-attestation/v1`,
 * `market-attestation-verification/v1`, `market-evidence-package/v1`) and is
 * only produced from verified evidence inputs.
 *
 * All types are strict and closed; no `any` escape is allowed by the migration
 * gate. JSON documents are modelled as `UnknownRecord` and narrowed explicitly
 * at the trust boundary.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/market/types
 */
export {};
