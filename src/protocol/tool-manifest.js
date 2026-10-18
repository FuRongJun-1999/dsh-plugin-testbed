/**
 * `test-tool-manifest/v1` static validation + tool pinning (CONTRACT-m5 §2,
 * architecture §8.4.1).
 *
 * A manifest is an input *declaration*, not a permission proof (§8.4.1); the
 * launcher records the actually-enforceable subset (incl. `unenforced`)
 * separately and lives in adapters/worker — not here. This module only does
 * static, fail-closed checks: no shell strings, no floating-tag digests, no
 * filesystem path escape (`..`/drive-letter/`file://`/absolute), bounded JSON
 * Schema, and the §8.4.1 manifest field table.
 *
 * Admission stages follow architecture §8.4.1: `draft` (hard error) →
 * `validated` (static checks pass) → `pinned` (bound to a specific digest).
 *
 * Migration phase `protocol/types`: the public boundary accepts `unknown`,
 * returns explicit validation/pin result unions, and uses `inSet` for every
 * closed vocabulary check. Internal error codes and ordering are unchanged.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/protocol/tool-manifest
 */
import { DETERMINISM_VALUES, TEST_TOOL_MANIFEST_VERSION, TOOL_PERMISSION_KEYS, TOOL_ROLE, inSet, } from './enums.js';
import { validateSchemaMeta } from './jsonschema.js';
const RUNNER_FIELDS = Object.freeze(['adapter', 'entrypoint']);
const SHAPE_FIELDS = Object.freeze(['command', 'args', 'shell']);
// Known top-level manifest fields (§8.4.1). Anything outside this set is a
// warning, not a hard error (CONTRACT-m5 §2).
const KNOWN_TOP_LEVEL = new Set([
    'schema_version', 'tool_id', 'tool_version', 'artifact_digest', 'role', 'tags',
    'runner', 'input_schema', 'observation_schema', 'requires', 'permissions',
    'limits', 'determinism', 'retry', 'evidence', 'compatibility',
]);
// Static ceiling for manifest requests. Runner-enforced bounds follow its
// MAX_TIMEOUT_MS / MAX_OUTPUT_BYTES; fields without L1 enforcement use the
// existing adapter grant examples. A declaration ceiling is not an OS limit.
export const MAX_MANIFEST_LIMITS = Object.freeze({
    timeout_ms: 5 * 60 * 1000,
    cpu_ms: 15_000,
    memory_mb: 256,
    temp_bytes: 8 * 1024 * 1024,
    output_bytes: 1024 * 1024,
    attachment_bytes: 1024 * 1024,
    processes: 1,
    concurrency: 1,
});
export const MAX_RETRY_ATTEMPTS = 3;
const LIMIT_FIELDS = Object.keys(MAX_MANIFEST_LIMITS);
// Shell metacharacters + whitespace, banned inside runner.adapter/entrypoint.
const SHELL_META = /[\s;&|><$`'"\\]/;
// Semantic version required by §8.4.1 (`tool_version`); no floating tags.
// Exported so the declarative manifest schema uses the exact same rule.
export const TOOL_VERSION_PATTERN = '^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-[0-9A-Za-z.-]+)?(?:\\+[0-9A-Za-z.-]+)?$';
const SEMVER = new RegExp(TOOL_VERSION_PATTERN);
function isPlainObject(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
}
function nonEmptyString(v) {
    return typeof v === 'string' && v.length > 0;
}
/**
 * Assert a content digest is a fixed `sha256:<64 hex>`. Floating tags
 * (`latest`, `main`, semver ranges) are rejected — §8.4.1「不可用浮动 tag」.
 */
export function assertArtifactDigest(dg) {
    const errors = [];
    if (typeof dg !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(dg)) {
        errors.push(`artifact-digest-invalid:${String(dg)}`);
    }
    return { ok: errors.length === 0, errors };
}
function validateRunner(runner, errors) {
    if (!isPlainObject(runner)) {
        errors.push('runner-invalid');
        return;
    }
    for (const forbidden of SHAPE_FIELDS) {
        if (forbidden in runner)
            errors.push(`runner-${forbidden}-forbidden`);
    }
    for (const key of Object.keys(runner)) {
        if (!RUNNER_FIELDS.includes(key))
            errors.push(`runner-unknown-field:${key}`);
    }
    for (const field of RUNNER_FIELDS) {
        const v = runner[field];
        if (!nonEmptyString(v))
            errors.push(`runner-${field}-invalid`);
        else if (SHELL_META.test(v))
            errors.push(`runner-${field}-shell-metachar`);
    }
}
/**
 * A filesystem entry is an escape if it is not a capability token
 * (`workspace:read`) and is a drive reference / absolute path / UNC / `file://`
 * / contains a `..` segment.
 *
 * @returns true when the entry must be rejected
 */
function isFilesystemEntryEscape(entry) {
    if (typeof entry !== 'string' || entry.length === 0)
        return true;
    // capability token: <namespace>:<cap> (namespace ≥ 2 chars so single-letter
    // drive forms like `C:` never match this branch)
    if (/^[a-zA-Z][a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+$/.test(entry))
        return false;
    if (/^[a-zA-Z]:/.test(entry))
        return true; // Windows drive (absolute or drive-relative)
    if (/^(?:\/|\\\\|\/\/|file:)/i.test(entry))
        return true; // POSIX abs / UNC / file://
    return entry.split(/[\\/]+/).includes('..');
}
function validatePermissions(permissions, errors) {
    if (!isPlainObject(permissions)) {
        errors.push('permissions-invalid');
        return;
    }
    for (const key of Object.keys(permissions)) {
        if (!inSet(TOOL_PERMISSION_KEYS, key)) {
            errors.push(`permissions-unknown-key:${key}`);
            continue;
        }
        const val = permissions[key];
        if (!Array.isArray(val)) {
            errors.push(`permissions-${key}-not-array`);
            continue;
        }
        if (!val.every((x) => typeof x === 'string')) {
            errors.push(`permissions-${key}-not-strings`);
            continue;
        }
        if (key === 'filesystem') {
            for (const entry of val) {
                if (isFilesystemEntryEscape(entry))
                    errors.push(`permissions-filesystem-escape:${String(entry)}`);
            }
        }
    }
}
function validateLimits(limits, errors) {
    if (!isPlainObject(limits)) {
        errors.push('limits-invalid');
        return;
    }
    for (const field of LIMIT_FIELDS) {
        const v = limits[field];
        if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 1) {
            errors.push(`limits-${field}-invalid`);
        }
        else if (v > MAX_MANIFEST_LIMITS[field]) {
            errors.push(`limits-${field}-exceeds-limit`);
        }
    }
}
function validateRetry(retry, errors) {
    if (!isPlainObject(retry)) {
        errors.push('retry-invalid');
        return;
    }
    if (typeof retry.safe !== 'boolean')
        errors.push('retry-safe-invalid');
    const maxAttempts = retry.max_attempts;
    if (typeof maxAttempts !== 'number' || !Number.isSafeInteger(maxAttempts) || maxAttempts < 1) {
        errors.push('retry-max-attempts-invalid');
    }
    else if (maxAttempts > MAX_RETRY_ATTEMPTS) {
        errors.push('retry-max-attempts-exceeds-limit');
    }
}
/**
 * Validate a `test-tool-manifest/v1` manifest against §8.4.1 (CONTRACT-m5 §2).
 * Unknown top-level fields are warnings, not hard errors.
 */
export function validateToolManifest(manifest) {
    if (!isPlainObject(manifest)) {
        return { ok: false, errors: ['manifest-not-object'], warnings: [], admission_stage: 'draft' };
    }
    const errors = [];
    const warnings = [];
    for (const key of Object.keys(manifest)) {
        if (!KNOWN_TOP_LEVEL.has(key))
            warnings.push(`unknown-top-level-field:${key}`);
    }
    if (manifest.schema_version !== TEST_TOOL_MANIFEST_VERSION)
        errors.push('schema-version-invalid');
    if (!nonEmptyString(manifest.tool_id))
        errors.push('tool-id-invalid');
    if (!nonEmptyString(manifest.tool_version) || !SEMVER.test(manifest.tool_version)) {
        errors.push('tool-version-invalid');
    }
    const dg = assertArtifactDigest(manifest.artifact_digest);
    errors.push(...dg.errors);
    if (!inSet(TOOL_ROLE, manifest.role))
        errors.push('role-invalid');
    // §8.4.1 lists `tags` as required, but the frozen M5 contract's required set
    // omits it so existing local tools stay loadable: absence is surfaced as a
    // warning, malformed tags are still a hard error. `schemas.js` mirrors the
    // same rule for the declarative v1 document.
    if (manifest.tags === undefined)
        warnings.push('missing-required-field:tags');
    else if (!Array.isArray(manifest.tags) || !manifest.tags.every(nonEmptyString))
        errors.push('tags-invalid');
    validateRunner(manifest.runner, errors);
    for (const field of ['input_schema', 'observation_schema']) {
        const meta = validateSchemaMeta(manifest[field]);
        for (const e of meta.errors)
            errors.push(`${field}-${e}`);
    }
    if (!Array.isArray(manifest.requires) || !manifest.requires.every((x) => typeof x === 'string')) {
        errors.push('requires-invalid');
    }
    validatePermissions(manifest.permissions, errors);
    validateLimits(manifest.limits, errors);
    if (!inSet(DETERMINISM_VALUES, manifest.determinism))
        errors.push('determinism-invalid');
    validateRetry(manifest.retry, errors);
    // Optional-but-recommended declaration blocks (§8.4.1). They must be objects
    // when present; they grant nothing and carry no credential fields.
    for (const field of ['evidence', 'compatibility']) {
        if (manifest[field] !== undefined && !isPlainObject(manifest[field])) {
            errors.push(`${field}-invalid`);
        }
    }
    return { ok: errors.length === 0, errors, warnings, admission_stage: errors.length === 0 ? 'validated' : 'draft' };
}
/**
 * Pin a validated manifest to a specific artifact digest (architecture §8.4.1
 * `pinned`:「已解析到具体版本、摘要、adapter 和环境能力快照」).
 *
 * The resolved `artifactDigest` must be a fixed `sha256:<hex>` and must equal
 * the manifest-declared `artifact_digest`; otherwise pinning fails (draft).
 * `env` is an optional environment/capability snapshot recorded as-is
 * (its validation is `adapters-owner`'s responsibility, not the manifest's).
 */
export function pinTool(manifest, artifactDigest, env) {
    const check = validateToolManifest(manifest);
    if (!check.ok)
        return { ok: false, errors: check.errors, admission_stage: 'draft' };
    const dg = assertArtifactDigest(artifactDigest);
    if (!dg.ok)
        return { ok: false, errors: dg.errors, admission_stage: 'draft' };
    const manifestRecord = manifest;
    if (artifactDigest !== manifestRecord.artifact_digest) {
        return { ok: false, errors: ['pin-digest-mismatch'], admission_stage: 'draft' };
    }
    const runner = manifestRecord.runner;
    return {
        ok: true,
        errors: [],
        admission_stage: 'pinned',
        tool_ref: {
            tool_id: manifestRecord.tool_id,
            version: manifestRecord.tool_version,
            artifact_digest: artifactDigest,
        },
        adapter: runner.adapter,
        entrypoint: runner.entrypoint,
        env: env ?? null,
    };
}
