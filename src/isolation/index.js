/**
 * Public isolation module surface for the market-stage integration.
 *
 * Consumers should import from this entry point rather than deep file paths.
 * The module deliberately has no adapter/worker dependency: it describes,
 * verifies and admits isolation facts; `src/adapters/isolation-port.js` is the
 * thin control-plane port, and the existing L1 adapter is never imported here.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/isolation
 */
export * from './contracts.js';
export * from './attestation.js';
export * from './runner-attestation.js';
export * from './host-capabilities.js';
export * from './providers.js';
export * from './suite-evidence.js';
export * from './a2.js';
export * from './a3.js';
export * from './admission.js';
