/**
 * Market evidence subsystem — public surface.
 *
 * Provides the provider-neutral contracts required by
 * `NEXT-PHASE-REQUIREMENTS.md` §5.4/§5.5 and §6.4–§6.6:
 *  - signing provider interface + request/response + signature verification;
 *  - `market-attestation/v1` construction and independent verification;
 *  - append-only archive chain, anchors, chain verification and trusted time;
 *  - the fixed entry N → eligibility → sign → entry N+1 → verify sequence.
 *
 * This environment has no KMS/HSM/OS keystore, no independent WORM archive and
 * no TSA, so the real provider factories return `blocked`, and the development
 * providers are permanently marked `development-only` (`E1`). Nothing here can
 * by itself produce a market-eligible result; eligibility remains owned by the
 * (not yet implemented) market gate.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/evidence
 */
export { ARCHIVE_ANCHOR_VERSION, ARCHIVE_ANCHOR_V1_SCHEMA, ARCHIVE_CHAIN_VERIFICATION_VERSION, ARCHIVE_CHAIN_VERIFICATION_V1_SCHEMA, ARCHIVE_DEVELOPMENT_MODES, ARCHIVE_ENTRY_VERSION, ARCHIVE_ENTRY_V1_SCHEMA, ARCHIVE_MARKET_MODES, ARCHIVE_MODES, ARCHIVE_PROVIDER_KINDS, ARCHIVE_TRUST_ANCHOR_TYPES, EVIDENCE_CLASSES, EVIDENCE_REASON_CODES, MARKET_ARCHIVE_V1_SCHEMA, MARKET_ARCHIVE_VERSION, MARKET_ATTESTATION_V1_SCHEMA, MARKET_ATTESTATION_VERIFICATION_V1_SCHEMA, MARKET_ATTESTATION_VERIFICATION_VERSION, MARKET_ATTESTATION_VERSION, MARKET_SCHEMA_BY_VERSION, MARKET_SCHEMA_VERSIONS, PROVIDER_TRUST_CLASSES, SIGNING_ALGORITHMS, SIGNING_DOMAINS, SIGNING_DOMAIN_MARKET_ARCHIVE, SIGNING_DOMAIN_MARKET_ATTESTATION, SIGNING_KEY_STATES, SIGNING_PAYLOAD_KINDS, SIGNING_PROVIDER_KINDS, SIGNING_PROVIDER_V1_SCHEMA, SIGNING_PROVIDER_VERSION, SIGNING_REQUEST_V1_SCHEMA, SIGNING_REQUEST_VERSION, SIGNING_RESPONSE_V1_SCHEMA, SIGNING_RESPONSE_VERSION, TRUSTED_TIME_SOURCES, VERIFICATION_CHECK_STATUSES, VERIFICATION_RESULTS, isArchiveAnchorVersion, isArchiveChainVerificationVersion, isArchiveEntryVersion, isMarketArchiveVersion, isMarketAttestationVerificationVersion, isMarketAttestationVersion, isSigningProviderVersion, isSigningRequestVersion, isSigningResponseVersion, marketSchemaForVersion, validateMarketDocument, } from '../protocol/market-schemas.js';
export { ENTRY_DIGEST_EXCLUDED_FIELDS, archiveEntryDigest, archiveEntryDigestBody, attestationSigningBytes, attestationSigningDigest, attestationVerificationDigest, base64urlDecode, base64urlEncode, canonicalBytes, canonicalDigest, digestBytes, marketAttestationDigest, pushSchemaErrors, validateArchiveAnchor, validateArchiveEntry, validateAttestationVerification, validateMarketAttestation, validateSigningProvider, validateSigningRequest, validateSigningResponse, } from './canonical.js';
export { EvidenceError, buildSigningRequest, checkKeyValidity, deriveKeyId, encodePublicKey, evaluateSigningRequest, importPinnedPublicKey, signMarketAttestation, signingPayloadDigest, signingProviderTrustIssues, unique, validateVerificationRecord, verifyAttestationSignature, verifySigningResponseBinding, } from './signing.js';
export { SIGNING_PROVIDER_METHODS, assertSigningProvider, createBlockedSigningProvider, createDevelopmentSigningProvider, createHsmSigningProvider, createKmsSigningProvider, createOsKeystoreSigningProvider, validateSigningProviderDocument, } from './signing-provider.js';
export { archiveProviderTrustIssues, archiveAnchorDigest, buildArchiveAnchor, buildAttestationEntryDraft, buildSubjectEntryDraft, verifyArchiveChain, verifyEntryDigest, } from './archive.js';
export { ARCHIVE_PROVIDER_METHODS, assertTrustedTimeProvider, createBlockedArchiveProvider, createBlockedTrustedTimeProvider, createDevelopmentArchiveProvider, createDevelopmentTrustedTimeProvider, validateArchiveProviderDocument, } from './archive-provider.js';
export { buildMarketAttestation, classifyMarketEvidence, validateAttestationDraft, verificationDigest, verifyAndClassify, verifyMarketAttestation, verifySavedVerificationRecord, } from './attestation.js';
export { EVIDENCE_SEQUENCE_STAGES, evidenceManifestDigest, readArchiveEntries, runMarketEvidenceSequence, } from './sequence.js';
