/**
 * Remote L3 `runner-attestation/v1` validation + control-plane verification.
 *
 * L3 may only be claimed by a rootless container, micro-VM or dedicated remote
 * runner (L3-01). A remote runner must present an externally **signed**
 * attestation bound to the runner identity/operator, pinned image digest,
 * runtime version, network policy, credential scope, validity window and nonce.
 * The control plane verifies signature, allowlists, freshness, nonce and
 * revocation; a missing verifier, pinned key or revocation source is a
 * fail-closed verification failure, never a pass.
 *
 * This module holds no private key and performs no signing. Signature
 * verification is delegated to a caller-supplied callback using pinned public
 * key material.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/isolation/runner-attestation
 */
import { ATTESTATION_SIGNATURE_ALGORITHMS, ISOLATION_REASON, L3_RUNTIME_ENGINES, deepFreeze, isNonEmptyString, isNonce, isPlainRecord, isRfc3339Utc, isRunnerAttestationId, isSha256Digest, runnerAttestationDigest, } from './contracts.js';
export const RUNNER_ATTESTATION_VERIFICATION_VERSION = 'runner-attestation-verification/v1';
export const DEFAULT_MAX_RUNNER_ATTESTATION_AGE_MS = 10 * 60 * 1000;
export const MAX_RUNNER_ATTESTATION_LIFETIME_MS = 24 * 60 * 60 * 1000;
const MAX_FUTURE_SKEW_MS = 60 * 1000;
const RUNNER_FIELDS = Object.freeze([
    'schema_version', 'attestation_id', 'runner_id', 'operator', 'runner_version',
    'isolation_level', 'image', 'runtime', 'host', 'network', 'credential_scope',
    'issued_at', 'expires_at', 'nonce', 'revocation_ref', 'signature',
]);
const OPERATOR_FIELDS = Object.freeze(['org', 'principal']);
const IMAGE_FIELDS = Object.freeze(['name', 'digest', 'platform']);
const RUNTIME_FIELDS = Object.freeze(['engine', 'version', 'kernel', 'hypervisor']);
const HOST_FIELDS = Object.freeze(['os', 'patch_level']);
const NETWORK_FIELDS = Object.freeze(['default', 'allowlist', 'policy_digest']);
const SIGNATURE_FIELDS = Object.freeze(['alg', 'key_id', 'value']);
const PLATFORM_RE = /^[a-z0-9]+\/[a-z0-9]+$/;
const REF_RE = /^[A-Za-z0-9][A-Za-z0-9._:/#+-]{0,255}$/;
function push(errors, path, detail) {
    errors.push({ path, detail });
}
function checkAllowedFields(record, allowed, path, errors) {
    if (!isPlainRecord(record)) {
        push(errors, path, 'expected-object');
        return false;
    }
    for (const key of Object.keys(record)) {
        if (!allowed.includes(key))
            push(errors, `${path}.${key}`, 'unknown-field');
    }
    return true;
}
/**
 * @param {unknown} value
 */
export function validateRunnerAttestation(value) {
    const errors = [];
    if (!checkAllowedFields(value, RUNNER_FIELDS, '$', errors))
        return { ok: false, errors };
    const doc = value;
    if (doc.schema_version !== 'runner-attestation/v1')
        push(errors, '$.schema_version', 'unknown-schema-version');
    if (!isRunnerAttestationId(doc.attestation_id))
        push(errors, '$.attestation_id', 'runner-attestation-id-invalid');
    if (!isNonEmptyString(doc.runner_id) || doc.runner_id.length > 128)
        push(errors, '$.runner_id', 'runner-id-invalid');
    if (!isNonEmptyString(doc.runner_version) || doc.runner_version.length > 64)
        push(errors, '$.runner_version', 'runner-version-invalid');
    if (doc.isolation_level !== 'L3')
        push(errors, '$.isolation_level', 'l3-required');
    if (checkAllowedFields(doc.operator, OPERATOR_FIELDS, '$.operator', errors)) {
        const operator = doc.operator;
        if (!isNonEmptyString(operator.org) || operator.org.length > 128)
            push(errors, '$.operator.org', 'operator-org-invalid');
        if (!isNonEmptyString(operator.principal) || operator.principal.length > 256)
            push(errors, '$.operator.principal', 'operator-principal-invalid');
    }
    if (checkAllowedFields(doc.image, IMAGE_FIELDS, '$.image', errors)) {
        const image = doc.image;
        if (!isNonEmptyString(image.name) || image.name.length > 256)
            push(errors, '$.image.name', 'image-name-invalid');
        if (!isSha256Digest(image.digest))
            push(errors, '$.image.digest', 'image-digest-required');
        if (typeof image.platform !== 'string' || !PLATFORM_RE.test(image.platform))
            push(errors, '$.image.platform', 'image-platform-invalid');
    }
    if (checkAllowedFields(doc.runtime, RUNTIME_FIELDS, '$.runtime', errors)) {
        const runtime = doc.runtime;
        if (typeof runtime.engine !== 'string' || !L3_RUNTIME_ENGINES.includes(runtime.engine)) {
            push(errors, '$.runtime.engine', 'l3-runtime-engine-invalid');
        }
        if (!isNonEmptyString(runtime.version) || runtime.version.length > 128)
            push(errors, '$.runtime.version', 'runtime-version-invalid');
        if (!isNonEmptyString(runtime.kernel) || runtime.kernel.length > 128)
            push(errors, '$.runtime.kernel', 'runtime-kernel-invalid');
        if (runtime.hypervisor !== null && (!isNonEmptyString(runtime.hypervisor) || runtime.hypervisor.length > 128)) {
            push(errors, '$.runtime.hypervisor', 'runtime-hypervisor-invalid');
        }
    }
    if (checkAllowedFields(doc.host, HOST_FIELDS, '$.host', errors)) {
        const host = doc.host;
        if (!isNonEmptyString(host.os) || host.os.length > 128)
            push(errors, '$.host.os', 'host-os-invalid');
        if (!isNonEmptyString(host.patch_level) || host.patch_level.length > 128)
            push(errors, '$.host.patch_level', 'host-patch-level-invalid');
    }
    if (checkAllowedFields(doc.network, NETWORK_FIELDS, '$.network', errors)) {
        const network = doc.network;
        if (network.default !== 'deny')
            push(errors, '$.network.default', 'network-deny-required');
        if (!Array.isArray(network.allowlist) || network.allowlist.length > 128 ||
            network.allowlist.some((item) => typeof item !== 'string' || item.length === 0 || item.length > 256)) {
            push(errors, '$.network.allowlist', 'network-allowlist-invalid');
        }
        if (!isSha256Digest(network.policy_digest))
            push(errors, '$.network.policy_digest', 'network-policy-digest-required');
    }
    if (doc.credential_scope !== 'none')
        push(errors, '$.credential_scope', 'credential-scope-must-be-none');
    if (!isRfc3339Utc(doc.issued_at))
        push(errors, '$.issued_at', 'rfc3339-utc-required');
    if (!isRfc3339Utc(doc.expires_at))
        push(errors, '$.expires_at', 'rfc3339-utc-required');
    if (isRfc3339Utc(doc.issued_at) && isRfc3339Utc(doc.expires_at)) {
        const issued = Date.parse(doc.issued_at);
        const expires = Date.parse(doc.expires_at);
        if (!(expires > issued))
            push(errors, '$.expires_at', 'expires-before-issued');
        if (expires - issued > MAX_RUNNER_ATTESTATION_LIFETIME_MS)
            push(errors, '$.expires_at', 'lifetime-too-long');
    }
    if (!isNonce(doc.nonce))
        push(errors, '$.nonce', 'nonce-invalid');
    if (typeof doc.revocation_ref !== 'string' || !REF_RE.test(doc.revocation_ref)) {
        push(errors, '$.revocation_ref', 'revocation-ref-invalid');
    }
    if (checkAllowedFields(doc.signature, SIGNATURE_FIELDS, '$.signature', errors)) {
        const signature = doc.signature;
        if (typeof signature.alg !== 'string' || !ATTESTATION_SIGNATURE_ALGORITHMS.includes(signature.alg)) {
            push(errors, '$.signature.alg', 'algorithm-not-allowed');
        }
        if (!isNonEmptyString(signature.key_id) || signature.key_id.length > 128)
            push(errors, '$.signature.key_id', 'key-id-invalid');
        if (typeof signature.value !== 'string' || signature.value.length === 0 || signature.value.length > 4096) {
            push(errors, '$.signature.value', 'signature-value-invalid');
        }
    }
    return { ok: errors.length === 0, errors };
}
/**
 * Build a frozen signed `runner-attestation/v1` payload. The caller (external
 * runner/operator) signs it remotely; this module never signs. `signature` must
 * be supplied by the external signer; placeholders are rejected by verification.
 *
 * @param {unknown} input
 * @returns {Readonly<RunnerAttestation>}
 */
export function buildRunnerAttestation(input) {
    if (!isPlainRecord(input))
        throw new TypeError('buildRunnerAttestation: input must be a plain object');
    const opt = (value) => (isPlainRecord(value) ? value : null);
    const operator = opt(input.operator);
    const image = opt(input.image);
    const runtime = opt(input.runtime);
    const host = opt(input.host);
    const network = opt(input.network);
    const signature = opt(input.signature);
    const attestation = {
        schema_version: 'runner-attestation/v1',
        attestation_id: input.attestation_id,
        runner_id: input.runner_id,
        operator: { org: operator?.org, principal: operator?.principal },
        runner_version: input.runner_version,
        isolation_level: 'L3',
        image: { name: image?.name, digest: image?.digest, platform: image?.platform },
        runtime: {
            engine: runtime?.engine,
            version: runtime?.version,
            kernel: runtime?.kernel,
            hypervisor: runtime?.hypervisor ?? null,
        },
        host: { os: host?.os, patch_level: host?.patch_level },
        network: {
            default: network?.default,
            allowlist: Array.isArray(network?.allowlist) ? [...network.allowlist] : network?.allowlist,
            policy_digest: network?.policy_digest,
        },
        credential_scope: input.credential_scope,
        issued_at: input.issued_at,
        expires_at: input.expires_at,
        nonce: input.nonce,
        revocation_ref: input.revocation_ref,
        signature: {
            alg: signature?.alg,
            key_id: signature?.key_id,
            value: signature?.value,
        },
    };
    const { ok, errors } = validateRunnerAttestation(attestation);
    if (!ok) {
        const first = errors[0];
        throw new TypeError(`buildRunnerAttestation: invalid at ${first.path}: ${first.detail}`);
    }
    return deepFreeze(attestation);
}
/**
 * @param {unknown} attestation
 * @param {RunnerAttestationExpected} expected
 * @param {RunnerAttestationVerifyOptions} options
 */
export function verifyRunnerAttestation(attestation, expected = {}, options = {}) {
    const nowMs = resolveNowMs(options.now);
    const checks = [];
    const reasonCodes = new Set();
    let nonceConsumed = false;
    const check = (id, condition, reason = null, detail) => {
        checks.push(detail === undefined ? { id, status: condition ? 'pass' : 'fail' } : { id, status: condition ? 'pass' : 'fail', detail });
        if (!condition && reason)
            reasonCodes.add(reason);
        return condition;
    };
    const finish = (result, digest = null) => deepFreeze({
        schema_version: RUNNER_ATTESTATION_VERIFICATION_VERSION,
        runner_attestation_digest: digest,
        verified_by: typeof options.verified_by === 'string' && options.verified_by.length > 0
            ? options.verified_by
            : 'control-plane:runner-attestation-verifier',
        verified_at: new Date(nowMs).toISOString(),
        result,
        checks,
        reason_codes: [...reasonCodes],
        nonce_consumed: nonceConsumed,
    });
    const validation = validateRunnerAttestation(attestation);
    if (!validation.ok) {
        const first = validation.errors[0];
        check('contract', false, ISOLATION_REASON.runnerAttestationInvalid, `${first.path}:${first.detail}`);
        return finish('invalid');
    }
    const doc = attestation;
    let digest = null;
    try {
        digest = runnerAttestationDigest(doc);
    }
    catch {
        check('digest', false, ISOLATION_REASON.runnerAttestationInvalid, 'digest-uncomputable');
        return finish('invalid');
    }
    check('digest', true);
    // Signature is mandatory for a remote L3 runner; no self-signed/unsigned path.
    if (typeof options.verifySignature !== 'function') {
        check('signature-metadata', false, ISOLATION_REASON.unverified, 'signature-verifier-missing');
    }
    else {
        let pinnedOk = true;
        if (isPlainRecord(options.pinnedKeys)) {
            const pinned = options.pinnedKeys[doc.signature.key_id];
            pinnedOk = isPlainRecord(pinned) &&
                (pinned.alg === undefined || pinned.alg === doc.signature.alg) &&
                typeof pinned.public_key === 'string' && pinned.public_key.length > 0;
        }
        check('signature-metadata', pinnedOk, ISOLATION_REASON.unverified, 'pinned-key-unknown');
        let verified = false;
        try {
            const outcome = options.verifySignature({
                alg: doc.signature.alg,
                key_id: doc.signature.key_id,
                signature: doc.signature.value,
                payload_digest: digest,
                payload: doc,
            });
            verified = outcome === true || (isPlainRecord(outcome) && outcome.valid === true);
        }
        catch {
            verified = false;
        }
        check('signature-verify', verified, ISOLATION_REASON.unverified, 'runner-signature-verification-failed');
    }
    // Allowlists: runner / image / operator.
    const allow = isPlainRecord(expected.allowlist) ? expected.allowlist : {};
    const runnerAllowed = Array.isArray(allow.runner_ids) && allow.runner_ids.includes(doc.runner_id);
    check('allowlist.runner', runnerAllowed, ISOLATION_REASON.runnerNotAllowed, `runner:${doc.runner_id}`);
    let imageAllowed = Array.isArray(allow.image_digests) && allow.image_digests.includes(doc.image.digest);
    if (expected.required_image_digest !== undefined) {
        imageAllowed = imageAllowed && expected.required_image_digest === doc.image.digest;
    }
    check('allowlist.image', imageAllowed, ISOLATION_REASON.runnerNotAllowed, `image:${doc.image.digest}`);
    const operatorAllowed = Array.isArray(allow.operators) && allow.operators.some((entry) => isPlainRecord(entry) && entry.org === doc.operator.org && entry.principal === doc.operator.principal);
    check('allowlist.operator', operatorAllowed, ISOLATION_REASON.runnerNotAllowed, 'operator-not-allowlisted');
    // L3 invariants.
    check('l3.engine', L3_RUNTIME_ENGINES.includes(doc.runtime.engine), ISOLATION_REASON.runnerAttestationInvalid, 'l3-engine-invalid');
    check('l3.network', doc.network.default === 'deny' && doc.network.allowlist.length === 0, ISOLATION_REASON.runnerAttestationInvalid, 'network-must-default-deny-with-no-allowlist');
    check('l3.credentials', doc.credential_scope === 'none', ISOLATION_REASON.runnerAttestationInvalid, 'credential-scope-must-be-none');
    // Revocation must be checkable; absence of a revocation source is a failure.
    if (typeof options.isRevoked !== 'function') {
        check('revocation', false, ISOLATION_REASON.runnerNotAllowed, 'revocation-check-missing');
    }
    else {
        let revoked = true;
        try {
            revoked = options.isRevoked({
                runner_id: doc.runner_id,
                attestation_id: doc.attestation_id,
                revocation_ref: doc.revocation_ref,
                image_digest: doc.image.digest,
            }) === true;
        }
        catch {
            revoked = true;
        }
        check('revocation', !revoked, ISOLATION_REASON.runnerNotAllowed, 'runner-revoked');
    }
    // Freshness + nonce.
    const maxAgeMs = typeof expected.max_age_ms === 'number' && Number.isFinite(expected.max_age_ms)
        ? expected.max_age_ms
        : DEFAULT_MAX_RUNNER_ATTESTATION_AGE_MS;
    const issuedMs = Date.parse(doc.issued_at);
    const expiresMs = Date.parse(doc.expires_at);
    const fresh = Number.isFinite(issuedMs) && Number.isFinite(expiresMs) &&
        issuedMs <= nowMs + MAX_FUTURE_SKEW_MS &&
        nowMs - issuedMs <= maxAgeMs &&
        nowMs <= expiresMs;
    check('freshness', fresh, expiresMs < nowMs ? ISOLATION_REASON.runnerAttestationExpired : ISOLATION_REASON.runnerAttestationInvalid, `age_ms:${Number.isFinite(issuedMs) ? nowMs - issuedMs : 'unparsable'}`);
    if (!isNonce(doc.nonce)) {
        check('nonce.shape', false, ISOLATION_REASON.runnerAttestationInvalid, 'nonce-invalid');
    }
    else if (!options.nonceRegistry || typeof options.nonceRegistry.consume !== 'function') {
        check('nonce.consume', false, ISOLATION_REASON.unverified, 'nonce-registry-required');
    }
    else {
        let outcome;
        try {
            outcome = options.nonceRegistry.consume(doc.nonce, { nowMs, expiresAtMs: expiresMs });
        }
        catch {
            outcome = { ok: false, reason: 'invalid' };
        }
        if (outcome.ok === true) {
            nonceConsumed = true;
            check('nonce.consume', true);
        }
        else if (outcome.reason === 'replay') {
            check('nonce.consume', false, ISOLATION_REASON.runnerAttestationReplay, 'nonce-replayed');
        }
        else {
            check('nonce.consume', false, ISOLATION_REASON.runnerAttestationInvalid, 'nonce-registry-rejected');
        }
    }
    const valid = checks.every((entry) => entry.status === 'pass') && reasonCodes.size === 0;
    return finish(valid ? 'valid' : 'invalid', digest);
}
function resolveNowMs(value) {
    if (value instanceof Date)
        return value.getTime();
    if (typeof value === 'number' && Number.isFinite(value))
        return value;
    if (typeof value === 'string') {
        const parsed = Date.parse(value);
        if (Number.isFinite(parsed))
            return parsed;
    }
    return Date.now();
}
