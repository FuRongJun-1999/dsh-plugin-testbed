/**
 * `market-archive/v1` provider implementations and the trusted-time interface.
 *
 * The only working archive in this repository is the development provider
 * (`local-file` / `git`). It is *explicitly* not an independent append-only
 * archive: files can be deleted or rewritten by any process that can write the
 * directory, and git history can be rewritten (`git reset`, force-push). Its
 * capability document therefore declares `development-only`, non-immutable
 * immutability flags and `host-clock-development-only` time, and the market
 * verifier always rejects it (`E1`, never market).
 *
 * Real WORM/object-lock/tlog/independent-archive providers do not exist in this
 * environment (§4.7, §5.5.3). `createBlockedArchiveProvider` is their declared
 * interface: every operation returns `blocked` with `archive-provider-missing`
 * (or `trusted-time-unavailable`) and never fabricates an anchor.
 *
 * Provider MAC keys for the development archive are generated in memory per
 * provider instance and are never exported or written to disk.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/evidence/archive-provider
 */
import { createHmac, randomBytes, timingSafeEqual, } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync, } from 'node:fs';
import { join } from 'node:path';
import { ARCHIVE_DEVELOPMENT_MODES, ARCHIVE_ENTRY_VERSION, ARCHIVE_MARKET_MODES, EVIDENCE_REASON_CODES, MARKET_ARCHIVE_VERSION, TRUSTED_TIME_SOURCES, validateMarketDocument, MARKET_ARCHIVE_V1_SCHEMA, } from '../protocol/market-schemas.js';
import { archiveEntryDigest, base64urlEncode, canonicalBytes, validateArchiveEntry, } from './canonical.js';
import { buildArchiveAnchor, verifyArchiveChain, } from './archive.js';
import { unique } from './signing.js';
/** Required archive provider interface (ARC operations in §6.6). */
export const ARCHIVE_PROVIDER_METHODS = Object.freeze([
    'describe', 'append', 'get', 'head', 'verifyChain', 'audit',
]);
const ENTRY_FILE_PATTERN = /^entry-(\d{12})-([0-9a-f]{64})\.json$/;
function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function pad(value, width) {
    return String(value).padStart(width, '0');
}
function boundedSleepMs(value, max) {
    return Math.max(1, Math.min(value, max));
}
/**
 * Validate a trusted-time provider object.
 */
export function assertTrustedTimeProvider(provider) {
    const errors = [];
    if (!isPlainObject(provider))
        errors.push('trusted-time-provider-not-object');
    else {
        if (typeof provider.describe !== 'function')
            errors.push('trusted-time-provider-method-missing:describe');
        if (typeof provider.now !== 'function')
            errors.push('trusted-time-provider-method-missing:now');
    }
    return { ok: errors.length === 0, errors };
}
/**
 * Development trusted-time source. Every reading is explicitly untrusted and
 * carries `host-clock-development-only`; market verification rejects it.
 *
 * `times` forces an exact sequence (useful for monotonic-clock tests); once
 * exhausted, the clock advances by `stepMs` per reading.
 */
export function createDevelopmentTrustedTimeProvider(options = {}) {
    const providerId = options.providerId ?? 'development-trusted-time';
    const stepMs = options.stepMs ?? 1000;
    const forced = [...(options.times ?? [])];
    const startMs = Date.parse(options.start ?? '2026-01-01T00:00:00.000Z');
    let cursor = 0;
    function nextTime() {
        if (cursor < forced.length) {
            const value = forced[cursor] ?? new Date(startMs).toISOString();
            cursor += 1;
            return value;
        }
        const offset = cursor - forced.length;
        cursor += 1;
        return new Date(startMs + offset * stepMs).toISOString();
    }
    return {
        describe() {
            return {
                provider_id: providerId,
                provider_kind: 'development-clock',
                availability: 'available',
                trust_class: 'development-only',
                source: 'host-clock-development-only',
                trusted: false,
                limitations: ['development-clock', 'not-trusted-time', 'not-market-evidence'],
            };
        },
        now() {
            return {
                status: 'ok',
                time: nextTime(),
                source: 'host-clock-development-only',
                trusted: false,
                trust_class: 'development-only',
                reference: providerId,
            };
        },
    };
}
/**
 * Trusted-time interface without a configured TSA/provider clock. Returns
 * `blocked`; callers must not fall back to the host clock for market evidence.
 */
export function createBlockedTrustedTimeProvider(options = {}) {
    const reasonCode = options.reasonCode ?? EVIDENCE_REASON_CODES.TRUSTED_TIME_UNAVAILABLE;
    const detail = options.detail ?? 'no trusted time provider or TSA is configured in this environment';
    return {
        describe() {
            return {
                provider_id: 'blocked-trusted-time',
                provider_kind: 'tsa',
                availability: 'blocked',
                trust_class: 'unavailable',
                source: 'tsa',
                trusted: false,
                limitations: ['trusted-time-provider-missing', 'tsa-unavailable', 'market-entry-blocked'],
            };
        },
        now() {
            return { status: 'blocked', reason_codes: [reasonCode], detail };
        },
    };
}
/**
 * Create the development archive provider (`local-file` or `git`).
 *
 * Chain writes are serialised in-process and use exclusive file creation
 * (`wx`), so concurrent appends receive distinct contiguous sequences and never
 * overwrite an existing entry. Cross-process collisions fail closed.
 */
export function createDevelopmentArchiveProvider(options) {
    if (!isPlainObject(options) || typeof options.dir !== 'string' || options.dir.length === 0) {
        throw new TypeError('createDevelopmentArchiveProvider requires a non-empty dir');
    }
    const dir = options.dir;
    const mode = options.mode ?? 'local-file';
    if (!ARCHIVE_DEVELOPMENT_MODES.includes(mode)) {
        throw new TypeError(`development archive mode must be one of ${ARCHIVE_DEVELOPMENT_MODES.join(', ')}`);
    }
    const repoDir = options.repoDir ?? null;
    if (mode === 'git' && (typeof repoDir !== 'string' || repoDir.length === 0)) {
        throw new TypeError('git development archive requires repoDir');
    }
    const archiveId = options.archiveId ?? 'development-archive';
    const providerId = options.providerId ?? `development-archive-${mode}`;
    const providerVersion = options.providerVersion ?? '0.0.1-development';
    const trustedTime = options.trustedTime ?? createDevelopmentTrustedTimeProvider();
    const timeCheck = assertTrustedTimeProvider(trustedTime);
    if (!timeCheck.ok)
        throw new TypeError(`invalid trusted-time provider: ${timeCheck.errors.join(', ')}`);
    const gitBin = options.gitBin ?? 'git';
    const hmacKey = randomBytes(32);
    mkdirSync(dir, { recursive: true });
    if (mode === 'git' && typeof repoDir === 'string') {
        mkdirSync(repoDir, { recursive: true });
        if (!existsSync(join(repoDir, '.git')))
            git(['init', '-q'], repoDir);
    }
    let queue = Promise.resolve();
    function enqueue(task) {
        const run = queue.then(() => task());
        queue = run.then(() => undefined, () => undefined);
        return run;
    }
    function git(args, cwd) {
        return execFileSync(gitBin, args, {
            cwd,
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'pipe'],
            windowsHide: true,
        });
    }
    function gitHead() {
        if (typeof repoDir !== 'string')
            return null;
        try {
            return git(['rev-parse', 'HEAD'], repoDir).trim();
        }
        catch {
            return null;
        }
    }
    function gitCommit(message) {
        if (typeof repoDir !== 'string')
            throw new Error('git repo directory missing');
        git(['add', '-A'], repoDir);
        git([
            '-c', 'user.name=dsh-plugin-testbed',
            '-c', 'user.email=plugin-testbed@localhost',
            '-c', 'commit.gpgsign=false',
            'commit', '-q', '-m', message,
        ], repoDir);
    }
    /**
     * Read all entry files in sequence order. Corrupt/unreadable entries are
     * returned as errors instead of being skipped (deletion/tamper must fail
     * closed, ARC-01/ARC-08).
     */
    function scanEntries() {
        const entries = [];
        const errors = [];
        let names;
        try {
            names = readdirSync(dir);
        }
        catch (error) {
            const code = isPlainObject(error) && typeof error.code === 'string' ? error.code : String(error);
            errors.push(`archive-unreadable:${code}`);
            return { entries, errors };
        }
        const matching = names.filter((name) => ENTRY_FILE_PATTERN.test(name)).sort();
        for (const name of matching) {
            const path = join(dir, name);
            try {
                const parsed = JSON.parse(readFileSync(path, 'utf8'));
                const match = ENTRY_FILE_PATTERN.exec(name);
                const expectedDigest = match === null ? null : match[2];
                if (!isPlainObject(parsed)) {
                    errors.push(`entry-not-object:${name}`);
                    continue;
                }
                if (expectedDigest !== null && parsed.entry_digest !== `sha256:${expectedDigest}`) {
                    errors.push(`entry-file-digest-mismatch:${name}`);
                    continue;
                }
                entries.push(parsed);
            }
            catch {
                errors.push(`entry-unreadable:${name}`);
            }
        }
        entries.sort((a, b) => a.sequence - b.sequence);
        return { entries, errors };
    }
    function currentHead() {
        const { entries, errors } = scanEntries();
        if (errors.length > 0) {
            return { status: 'blocked', reason_codes: [EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED], errors };
        }
        if (entries.length === 0) {
            return { status: 'ok', sequence: 0, entry_digest: null, archived_at: null, provider_audit_ref: null };
        }
        const head = entries[entries.length - 1];
        return {
            status: 'ok',
            sequence: head.sequence,
            entry_digest: head.entry_digest,
            archived_at: head.archived_at,
            provider_audit_ref: head.provider_audit_ref,
            time_source: structuredClone(head.time_source),
        };
    }
    function describe() {
        const head = currentHead();
        const timeDoc = trustedTime.describe();
        const doc = {
            schema_version: MARKET_ARCHIVE_VERSION,
            provider_id: providerId,
            provider_version: providerVersion,
            provider_kind: 'development-local',
            mode,
            immutability: {
                append_only: false,
                delete_forbidden: false,
                retention_days: 0,
                legal_hold: false,
            },
            trust_anchor: {
                type: 'none-development-only',
                key_id: null,
                verification_ref: null,
            },
            trusted_time: {
                source: 'host-clock-development-only',
                verified: false,
                reference: typeof timeDoc.provider_id === 'string' ? timeDoc.provider_id : null,
            },
            sequence_head: head.status === 'ok' ? (head.sequence ?? 0) : 0,
            trust_class: 'development-only',
            availability: 'available',
            limitations: unique([
                'development-only-archive',
                `${mode}-storage-rewritable`,
                mode === 'git' ? 'git-history-rewritable' : 'plain-files-rewritable',
                'no-worm-object-lock-tlog',
                'not-market-evidence',
                ...(head.status === 'ok' ? [] : ['archive-head-unreadable']),
            ]),
        };
        const shaped = validateMarketDocument(doc, MARKET_ARCHIVE_V1_SCHEMA);
        if (!shaped.ok) {
            throw new TypeError(`development archive capability document invalid: ${shaped.errors.join(', ')}`);
        }
        return doc;
    }
    function signEntry(entry) {
        const body = structuredClone(entry);
        delete body.provider_signature;
        const mac = createHmac('sha256', hmacKey).update(canonicalBytes(body)).digest();
        return {
            alg: 'hmac-sha256-development-only',
            key_id: 'development-archive-hmac',
            value: base64urlEncode(mac),
        };
    }
    function verifyProviderSignature(entry) {
        if (!isPlainObject(entry) || !isPlainObject(entry.provider_signature))
            return false;
        if (entry.provider_signature.alg !== 'hmac-sha256-development-only')
            return false;
        const body = structuredClone(entry);
        delete body.provider_signature;
        const expected = createHmac('sha256', hmacKey).update(canonicalBytes(body)).digest();
        const value = entry.provider_signature.value;
        if (typeof value !== 'string')
            return false;
        let actual;
        try {
            actual = Buffer.from(value, 'base64url');
        }
        catch {
            return false;
        }
        return actual.length === expected.length && timingSafeEqual(actual, expected);
    }
    /**
     * Append one entry. The provider owns sequence, previous digest, trusted
     * time, entry digest, audit ref and provider signature.
     */
    async function append(draft) {
        return enqueue(async () => {
            if (!isPlainObject(draft)) {
                return reject([EVIDENCE_REASON_CODES.ARCHIVE_REQUEST_INVALID], 'entry-draft-not-object');
            }
            for (const providerOwned of [
                'sequence', 'previous_entry_digest', 'entry_digest', 'archived_at',
                'time_source', 'provider_audit_ref', 'provider_signature',
                'schema_version', 'archive_id',
            ]) {
                if (providerOwned in draft) {
                    return reject([EVIDENCE_REASON_CODES.ARCHIVE_REQUEST_INVALID], `provider-owned-field-in-draft:${providerOwned}`);
                }
            }
            for (const required of [
                'receipt_digest', 'isolation_attestation_digest', 'policy_digest',
                'approval_digests', 'attestation_digest', 'eligibility_digest',
            ]) {
                if (!(required in draft)) {
                    return reject([EVIDENCE_REASON_CODES.ARCHIVE_REQUEST_INVALID], `draft-missing:${required}`);
                }
            }
            if (!/^sha256:[0-9a-f]{64}$/.test(draft.receipt_digest)) {
                return reject([EVIDENCE_REASON_CODES.ARCHIVE_REQUEST_INVALID], 'receipt-digest-invalid');
            }
            if (!Array.isArray(draft.approval_digests) || draft.approval_digests.some((value) => typeof value !== 'string')) {
                return reject([EVIDENCE_REASON_CODES.ARCHIVE_REQUEST_INVALID], 'approval-digests-invalid');
            }
            const { entries, errors } = scanEntries();
            if (errors.length > 0) {
                return {
                    status: 'blocked',
                    reason_codes: [EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED],
                    detail: errors.join('; '),
                };
            }
            // Never append onto a chain that no longer verifies: a tampered or
            // rewritten prefix must block new evidence instead of being extended.
            if (entries.length > 0) {
                const existing = verifyArchiveChain(entries, {
                    archiveId,
                    providerId,
                    verifyProviderSignature,
                });
                if (!existing.ok) {
                    return {
                        status: 'blocked',
                        reason_codes: unique([
                            ...existing.verification.reason_codes,
                            EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED,
                        ]),
                        detail: `existing-chain-invalid:${existing.verification.reason_codes.join(',')}`,
                    };
                }
            }
            const head = entries.length === 0 ? null : entries[entries.length - 1];
            const expected = isPlainObject(draft.expected)
                ? draft.expected
                : null;
            const headSequence = head === null ? 0 : head.sequence;
            const headDigest = head === null ? null : head.entry_digest;
            if (expected !== null) {
                if (expected.sequence <= headSequence) {
                    return reject([EVIDENCE_REASON_CODES.ARCHIVE_REPLAY_DETECTED], 'expected-sequence-already-consumed');
                }
                if (expected.sequence > headSequence + 1) {
                    return reject([EVIDENCE_REASON_CODES.ARCHIVE_SEQUENCE_GAP], 'expected-sequence-skips-gap');
                }
                if (expected.previous_entry_digest !== headDigest) {
                    return reject([EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISMATCH], 'expected-previous-digest-mismatch');
                }
            }
            const sequence = headSequence + 1;
            const hasAttestation = typeof draft.attestation_digest === 'string';
            const hasEligibility = typeof draft.eligibility_digest === 'string';
            if (hasAttestation !== hasEligibility) {
                return reject([EVIDENCE_REASON_CODES.ARCHIVE_REQUEST_INVALID], 'attestation-and-eligibility-digest-must-pair');
            }
            if (hasAttestation) {
                if (head === null || head.attestation_digest !== null || head.receipt_digest !== draft.receipt_digest) {
                    return reject([EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISMATCH], 'attestation-entry-needs-matching-subject-entry');
                }
            }
            const time = trustedTime.now();
            if (time.status !== 'ok' || typeof time.time !== 'string') {
                return {
                    status: 'blocked',
                    reason_codes: [EVIDENCE_REASON_CODES.TRUSTED_TIME_UNAVAILABLE],
                    detail: 'trusted-time-provider-blocked',
                };
            }
            if (head !== null && Date.parse(time.time) < Date.parse(head.archived_at)) {
                return reject([EVIDENCE_REASON_CODES.ARCHIVE_TIME_REVERSED], 'trusted-time-went-backwards');
            }
            const entry = {
                schema_version: ARCHIVE_ENTRY_VERSION,
                archive_id: archiveId,
                sequence,
                previous_entry_digest: headDigest,
                receipt_digest: draft.receipt_digest,
                isolation_attestation_digest: draft.isolation_attestation_digest,
                policy_digest: draft.policy_digest,
                approval_digests: [...draft.approval_digests],
                attestation_digest: draft.attestation_digest,
                eligibility_digest: draft.eligibility_digest,
                entry_digest: '',
                archived_at: time.time,
                time_source: {
                    source: typeof time.source === 'string' && TRUSTED_TIME_SOURCES.includes(time.source)
                        ? time.source
                        : 'host-clock-development-only',
                    trusted: time.trusted === true,
                    reference: typeof time.reference === 'string' ? time.reference : null,
                },
                provider_signature: null,
                provider_audit_ref: '',
            };
            entry.entry_digest = archiveEntryDigest(entry);
            entry.provider_audit_ref = `dev-archive:${archiveId}:${sequence}:${entry.entry_digest}`;
            entry.provider_signature = signEntry(entry);
            const shaped = validateArchiveEntry(entry);
            if (!shaped.ok) {
                return reject([EVIDENCE_REASON_CODES.EVIDENCE_UNVERIFIABLE], shaped.errors.map((error) => `schema:${error}`).join('; '));
            }
            const fileName = `entry-${pad(sequence, 12)}-${entry.entry_digest.slice('sha256:'.length)}.json`;
            const filePath = join(dir, fileName);
            let written = false;
            for (let attempt = 0; attempt < 8 && !written; attempt += 1) {
                try {
                    writeFileSync(filePath, `${JSON.stringify(entry, null, 2)}\n`, { flag: 'wx', encoding: 'utf8' });
                    written = true;
                }
                catch (error) {
                    const code = isPlainObject(error) && typeof error.code === 'string' ? error.code : '';
                    if (code === 'EEXIST') {
                        // Another writer consumed this sequence. Fail closed rather than
                        // creating a second entry with the same sequence number.
                        return reject([EVIDENCE_REASON_CODES.ARCHIVE_REPLAY_DETECTED], 'sequence-race-detected');
                    }
                    if (attempt < 7 && (code === 'EPERM' || code === 'EBUSY')) {
                        await new Promise((resolve) => setTimeout(resolve, boundedSleepMs(2 + attempt * 2, 20)));
                        continue;
                    }
                    return {
                        status: 'blocked',
                        reason_codes: [EVIDENCE_REASON_CODES.ARCHIVE_APPEND_FAILED],
                        detail: `write-failed:${code || String(error)}`,
                    };
                }
            }
            if (!written) {
                return {
                    status: 'blocked',
                    reason_codes: [EVIDENCE_REASON_CODES.ARCHIVE_APPEND_FAILED],
                    detail: 'exclusive-write-retry-exhausted',
                };
            }
            if (mode === 'git') {
                try {
                    gitCommit(`archive entry ${sequence} ${entry.entry_digest}`);
                }
                catch (error) {
                    const code = isPlainObject(error) && typeof error.code === 'string' ? error.code : String(error);
                    return {
                        status: 'blocked',
                        reason_codes: [EVIDENCE_REASON_CODES.ARCHIVE_APPEND_FAILED],
                        detail: `git-commit-failed:${code}`,
                    };
                }
            }
            return {
                status: 'appended',
                entry,
                anchor: buildArchiveAnchor(entry, describe()),
            };
        });
    }
    function get(sequence) {
        const { entries, errors } = scanEntries();
        if (errors.length > 0) {
            return { status: 'blocked', reason_codes: [EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED], errors };
        }
        const entry = entries.find((candidate) => candidate.sequence === sequence);
        if (entry === undefined)
            return { status: 'not-found' };
        return { status: 'ok', entry };
    }
    function head() {
        return currentHead();
    }
    async function verifyChain(chainOptions = {}) {
        const { entries, errors } = scanEntries();
        const { verification } = verifyArchiveChain(entries, {
            archiveId,
            providerId,
            expectedHead: chainOptions.expectedHead ?? null,
            requireAttestationPair: chainOptions.requireAttestationPair === true,
            verifyProviderSignature,
            verificationId: chainOptions.verificationId,
            verifiedAt: chainOptions.verifiedAt,
            limitations: [
                'development-only-archive',
                `${mode}-storage-rewritable`,
                'host-clock-development-only',
                'not-market-evidence',
                ...(errors.length > 0 ? errors : []),
            ],
        });
        if (errors.length > 0 && !verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED)) {
            verification.reason_codes.push(EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED);
            verification.result = 'invalid';
        }
        return {
            status: verification.result,
            verification,
            entries,
        };
    }
    function audit() {
        const { entries, errors } = scanEntries();
        if (errors.length > 0) {
            return { status: 'blocked', reason_codes: [EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED], errors };
        }
        return {
            status: 'ok',
            provider_audit_ref: entries.length === 0 ? null : entries[entries.length - 1].provider_audit_ref,
            git_head: mode === 'git' ? gitHead() : null,
            entries: entries.map((entry) => ({
                sequence: entry.sequence,
                entry_digest: entry.entry_digest,
                provider_audit_ref: entry.provider_audit_ref,
            })),
        };
    }
    const provider = {
        describe,
        append,
        get,
        head,
        verifyChain,
        audit,
        /** Test/diagnostic helper; not part of the provider protocol. */
        verifyEntrySignature(entry) {
            return verifyProviderSignature(entry);
        },
        /** Directory holding the append-only (development) entry files. */
        storageDir: dir,
    };
    return provider;
}
/**
 * Declared interface for a real object-lock/WORM/tlog provider that does not
 * exist in this environment. All mutating and reading operations return
 * `blocked`; no anchor is ever fabricated.
 */
export function createBlockedArchiveProvider(options = {}) {
    const providerKind = options.providerKind ?? 'object-store';
    const mode = options.mode ?? (ARCHIVE_MARKET_MODES[0] ?? 'object-lock');
    const providerId = options.providerId ?? `blocked-archive-${providerKind}`;
    const providerVersion = options.providerVersion ?? 'unavailable';
    const reasonCode = options.reasonCode ?? EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_MISSING;
    const detail = options.detail ?? 'no WORM/object-lock/tlog/independent archive provider is configured in this environment';
    const blocked = () => ({ status: 'blocked', reason_codes: [reasonCode], detail });
    function describe() {
        const doc = {
            schema_version: MARKET_ARCHIVE_VERSION,
            provider_id: providerId,
            provider_version: providerVersion,
            provider_kind: providerKind,
            mode,
            immutability: {
                append_only: true,
                delete_forbidden: true,
                retention_days: 3650,
                legal_hold: true,
            },
            trust_anchor: {
                type: 'none-development-only',
                key_id: null,
                verification_ref: null,
            },
            trusted_time: {
                source: 'host-clock-development-only',
                verified: false,
                reference: null,
            },
            sequence_head: 0,
            trust_class: 'unavailable',
            availability: 'blocked',
            limitations: [
                'provider-not-configured',
                'no-worm-object-lock-tlog',
                'trusted-time-unavailable',
                'market-entry-blocked',
            ],
        };
        const shaped = validateMarketDocument(doc, MARKET_ARCHIVE_V1_SCHEMA);
        if (!shaped.ok) {
            throw new TypeError(`blocked archive capability document invalid: ${shaped.errors.join(', ')}`);
        }
        return doc;
    }
    return {
        describe,
        append() {
            return Promise.resolve(blocked());
        },
        get() {
            return { status: 'blocked', reason_codes: [reasonCode] };
        },
        head() {
            return { status: 'blocked', reason_codes: [reasonCode], detail };
        },
        async verifyChain() {
            const verification = {
                schema_version: 'archive-chain-verification/v1',
                verification_id: 'chain-verify:blocked',
                archive_id: 'unconfigured',
                provider_id: providerId,
                sequence_head: 0,
                head_entry_digest: null,
                expected_head: null,
                result: 'blocked',
                checks: [{
                        id: 'provider-availability',
                        status: 'blocked',
                        reason_code: reasonCode,
                        evidence_ref: null,
                    }],
                reason_codes: [reasonCode],
                verified_at: new Date().toISOString(),
                limitations: ['provider-not-configured'],
            };
            return {
                status: 'blocked',
                verification: verification,
                entries: [],
            };
        },
        audit() {
            return blocked();
        },
        storageDir: null,
    };
}
/**
 * Validate a `market-archive/v1` document against the registered schema.
 */
export function validateArchiveProviderDocument(providerDoc) {
    return validateMarketDocument(providerDoc, MARKET_ARCHIVE_V1_SCHEMA);
}
// ---------------------------------------------------------------------------
function reject(reasonCodes, detail) {
    return { status: 'rejected', reason_codes: unique(reasonCodes), detail };
}
