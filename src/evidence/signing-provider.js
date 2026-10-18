import { generateKeyPairSync, sign as cryptoSign, } from 'node:crypto';
import { EVIDENCE_REASON_CODES, SIGNING_ALGORITHMS, SIGNING_DOMAIN_MARKET_ATTESTATION, SIGNING_PROVIDER_V1_SCHEMA, SIGNING_PROVIDER_VERSION, validateMarketDocument, } from '../protocol/market-schemas.js';
import { attestationSigningBytes, base64urlEncode, validateSigningProvider, } from './canonical.js';
import { deriveKeyId, encodePublicKey, evaluateSigningRequest, } from './signing.js';
/** Required provider interface (`signing-provider/v1`). */
export const SIGNING_PROVIDER_METHODS = Object.freeze([
    'describe', 'sign', 'rotateKey', 'revokeKey', 'audit',
]);
function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
/**
 * Assert that an injected object implements the provider surface.
 */
export function assertSigningProvider(provider, options = {}) {
    const errors = [];
    if (!isPlainObject(provider) && typeof provider !== 'object') {
        errors.push('provider-not-object');
    }
    else {
        for (const method of SIGNING_PROVIDER_METHODS) {
            const candidate = provider[method];
            if (typeof candidate !== 'function')
                errors.push(`provider-method-missing:${method}`);
        }
    }
    const result = { ok: errors.length === 0, errors };
    if (!result.ok && options.throw === true) {
        throw new TypeError(`invalid signing provider: ${errors.join(', ')}`);
    }
    return result;
}
/**
 * Create the in-memory development signer. NOT market evidence.
 */
export function createDevelopmentSigningProvider(options = {}) {
    const providerId = options.providerId ?? 'development-signer';
    const providerVersion = options.providerVersion ?? '0.0.1-development';
    const trustDomain = options.trustDomain ?? 'dsh-market-development/v1';
    const algorithms = options.algorithms ?? ['ed25519'];
    const allowedDomains = options.allowedDomains ?? [SIGNING_DOMAIN_MARKET_ATTESTATION];
    const authorizedRequesters = options.authorizedRequesters ?? [];
    const now = options.now ?? (() => new Date());
    const expiresAt = options.expiresAt ?? null;
    const maxRequestAgeMs = options.maxRequestAgeMs;
    const auditEntries = [];
    const keyStore = new Map();
    function generateKey(alg) {
        if (!SIGNING_ALGORITHMS.includes(alg)) {
            throw new TypeError(`unsupported development signing algorithm: ${alg}`);
        }
        const pair = alg === 'ed25519'
            ? generateKeyPairSync('ed25519')
            : generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
        const publicView = encodePublicKey(pair.publicKey);
        const keyId = deriveKeyId(alg, pair.publicKey.export({ format: 'der', type: 'spki' }));
        const doc = {
            key_id: keyId,
            alg,
            public_key: publicView.public_key,
            public_key_digest: publicView.public_key_digest,
            state: 'active',
            created_at: toIso(now()),
            expires_at: expiresAt,
            rotated_at: null,
            revoked_at: null,
            revocation_reason: null,
            attestation_ref: null,
        };
        keyStore.set(keyId, { key_id: keyId, alg, privateKey: pair.privateKey, doc });
        return keyId;
    }
    for (const alg of algorithms)
        generateKey(alg);
    function describe() {
        return {
            schema_version: SIGNING_PROVIDER_VERSION,
            provider_id: providerId,
            provider_version: providerVersion,
            provider_kind: 'development-local',
            trust_domain: trustDomain,
            algorithms: [...algorithms],
            keys: [...keyStore.values()].map((entry) => structuredClone(entry.doc)),
            guarantees: {
                private_key_export: 'never',
                signing_op: 'local-development',
                audit: 'in-memory-development',
                blind_sign: 'forbidden',
            },
            trust_class: 'development-only',
            availability: 'available',
            limitations: [
                'development-only-signer',
                'no-kms-hsm-os-keystore',
                'private-key-in-memory-only',
                'not-market-evidence',
            ],
            attestation: null,
        };
    }
    const provider = {
        describe,
        /**
         * Sign exactly one canonical payload after re-validating the request.
         * The payload object (not just its digest) is mandatory: no blind signing.
         */
        sign(request, payload) {
            const providerDoc = describe();
            const evaluation = evaluateSigningRequest({
                request,
                payload,
                providerDoc,
                now: toIso(now()),
                authorizedRequesters,
                allowedDomains,
                maxRequestAgeMs,
            });
            if (!evaluation.ok) {
                return {
                    status: 'rejected',
                    reason_codes: evaluation.reason_codes,
                    errors: evaluation.errors,
                };
            }
            const entry = keyStore.get(request.key_id);
            if (entry === undefined) {
                return {
                    status: 'rejected',
                    reason_codes: [EVIDENCE_REASON_CODES.SIGNING_KEY_UNKNOWN],
                    errors: ['key-store-miss'],
                };
            }
            const bytes = attestationSigningBytes(payload);
            const signature = request.alg === 'ed25519'
                ? cryptoSign(null, bytes, entry.privateKey)
                : cryptoSign('sha256', bytes, { key: entry.privateKey, dsaEncoding: 'ieee-p1363' });
            const response = {
                schema_version: 'signing-response/v1',
                request_id: request.request_id,
                key_id: request.key_id,
                alg: request.alg,
                signature: base64urlEncode(signature),
                signed_payload_digest: request.payload_digest,
                signed_at: request.requested_at,
                provider_audit_ref: request.audit_ref,
            };
            auditEntries.push({
                event: 'sign',
                request_id: request.request_id,
                key_id: request.key_id,
                alg: request.alg,
                payload_kind: request.payload_kind,
                payload_digest: request.payload_digest,
                domain_separation: request.domain_separation,
                provider_audit_ref: request.audit_ref,
                signed_at: request.requested_at,
                requester: structuredClone(request.requester),
            });
            return { status: 'signed', response };
        },
        /**
         * Rotate an active key: retain the old public key (`rotated`) and create a
         * fresh active key (SIG-04). Old signatures remain verifiable when policy
         * allows rotated keys signed before `rotated_at`.
         */
        rotateKey(input) {
            const current = keyStore.get(input.keyId);
            if (current === undefined) {
                return { status: 'rejected', reason_codes: [EVIDENCE_REASON_CODES.SIGNING_KEY_UNKNOWN] };
            }
            if (current.doc.state !== 'active') {
                return { status: 'rejected', reason_codes: [EVIDENCE_REASON_CODES.SIGNING_KEY_INACTIVE] };
            }
            current.doc.state = 'rotated';
            current.doc.rotated_at = toIso(now());
            const alg = input.alg ?? current.alg;
            const newKeyId = generateKey(alg);
            auditEntries.push({
                event: 'rotate',
                old_key_id: input.keyId,
                new_key_id: newKeyId,
                rotated_at: current.doc.rotated_at,
            });
            return { status: 'rotated', old_key_id: input.keyId, new_key_id: newKeyId };
        },
        /**
         * Revoke a key. Revocation is sticky and historical signatures fail
         * verification (SIG-04/SIG-06).
         */
        revokeKey(input) {
            const current = keyStore.get(input.keyId);
            if (current === undefined) {
                return { status: 'rejected', reason_codes: [EVIDENCE_REASON_CODES.SIGNING_KEY_UNKNOWN] };
            }
            current.doc.state = 'revoked';
            current.doc.revoked_at = toIso(now());
            current.doc.revocation_reason = input.reason ?? 'revoked';
            auditEntries.push({
                event: 'revoke',
                key_id: input.keyId,
                revoked_at: current.doc.revoked_at,
                reason: current.doc.revocation_reason,
            });
            return { status: 'revoked', key_id: input.keyId };
        },
        /** Provider audit trail (development in-memory; never contains key material). */
        audit() {
            return {
                status: 'ok',
                trust_class: 'development-only',
                entries: structuredClone(auditEntries),
            };
        },
        /** Test helper: active key ids (public metadata). */
        activeKeyIds() {
            return [...keyStore.values()]
                .filter((entry) => entry.doc.state === 'active')
                .map((entry) => entry.key_id);
        },
    };
    return provider;
}
/**
 * A provider interface that is deliberately unavailable. This models the real
 * KMS/HSM/OS-keystore boundary in an environment without one: the operation
 * returns `blocked`, never a signature.
 */
export function createBlockedSigningProvider(options = {}) {
    const providerKind = options.providerKind ?? 'unavailable';
    const providerId = options.providerId ?? `blocked-${providerKind}`;
    const providerVersion = options.providerVersion ?? 'unavailable';
    const reasonCode = options.reasonCode ?? EVIDENCE_REASON_CODES.SIGNING_PROVIDER_MISSING;
    const detail = options.detail ?? 'no KMS/HSM/OS-keystore provider is configured in this environment';
    const blocked = () => ({
        status: 'blocked',
        reason_codes: [reasonCode],
        detail,
    });
    return {
        describe() {
            return {
                schema_version: SIGNING_PROVIDER_VERSION,
                provider_id: providerId,
                provider_version: providerVersion,
                provider_kind: providerKind,
                trust_domain: 'unconfigured',
                algorithms: [...SIGNING_ALGORITHMS],
                keys: [],
                guarantees: {
                    private_key_export: 'never',
                    signing_op: 'remote',
                    audit: 'append-only',
                    blind_sign: 'forbidden',
                },
                trust_class: 'unavailable',
                availability: 'blocked',
                limitations: [
                    'provider-not-configured',
                    'no-kms-hsm-os-keystore',
                    'market-entry-blocked',
                ],
                attestation: null,
            };
        },
        sign() {
            return blocked();
        },
        rotateKey() {
            return blocked();
        },
        revokeKey() {
            return blocked();
        },
        audit() {
            return { status: 'blocked', reason_codes: [reasonCode], detail };
        },
    };
}
/** Remote KMS provider interface (blocked until a real KMS is provisioned). */
export function createKmsSigningProvider(options = {}) {
    return createBlockedSigningProvider({ ...options, providerKind: 'kms' });
}
/** Remote HSM provider interface (blocked until a real HSM is provisioned). */
export function createHsmSigningProvider(options = {}) {
    return createBlockedSigningProvider({ ...options, providerKind: 'hsm' });
}
/** OS keystore provider interface (blocked until CNG/TPM custody is verified). */
export function createOsKeystoreSigningProvider(options = {}) {
    return createBlockedSigningProvider({
        ...options,
        providerKind: 'os-keystore',
        reasonCode: options.reasonCode ?? EVIDENCE_REASON_CODES.SIGNING_KEY_CUSTODY_UNVERIFIED,
    });
}
/**
 * Validate a provider document against the registered schema and the market
 * trust predicates. Convenience wrapper used by tests/integration.
 */
export function validateSigningProviderDocument(providerDoc) {
    const schema = validateMarketDocument(providerDoc, SIGNING_PROVIDER_V1_SCHEMA);
    const shaped = validateSigningProvider(providerDoc);
    return { ok: schema.ok && shaped.ok, schema };
}
// ---------------------------------------------------------------------------
function toIso(date) {
    return date.toISOString();
}
