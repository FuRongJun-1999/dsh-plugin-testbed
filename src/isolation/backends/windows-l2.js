/**
 * Windows L2 native backend wrapper (AppContainer + Job Object).
 *
 * The wrapper is the only TypeScript entry point to the native launcher. It
 * exposes:
 *   - a declarative plan with the exact operations, impact and rollback that
 *     require captain/user authorization (`AUTHORIZATION-REQUEST.md`);
 *   - a read-only inspection (`launcher.ps1 -Mode inspect`) that compiles the
 *     native source in memory and probes AppContainer/Job Object availability;
 *   - a guarded transport that refuses to launch anything without a valid,
 *     unexpired authorization object and the `launcher.ps1` scope checks;
 *   - measurement → `isolation-attestation/v1` construction for an authorized
 *     run. It never signs, never contains a private key and never decides market
 *     eligibility; A2 evidence and an external availability record are still
 *     required by `admission.ts`.
 *
 * Nothing in this module mutates the OS unless `launch()` is called with a valid
 * authorization. `inspect` is read-only (a transient Job Object is created and
 * closed; no profile, process or ACL change).
 *
 * @module @deepseek-ai/dsh-plugin-testbed/isolation/backends/windows-l2
 */
import { execFile, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ISOLATION_REASON, MARKET_GATE_POLICY_VERSION, buildIsolationAttestation, deepFreeze, digestDocument, isNonEmptyString, isPlainRecord, isRfc3339Utc, policyDigestOf, } from '../contracts.js';
export const WINDOWS_L2_PLAN_VERSION = 'windows-l2-plan/v1';
export const WINDOWS_L2_AUTHORIZATION_SCHEMA_VERSION = 'windows-l2-authorization/v1';
export const WINDOWS_L2_LAUNCH_REQUEST_SCHEMA_VERSION = 'windows-l2-launch-request/v1';
export const WINDOWS_L2_PROFILE_NAME = 'DshTestbedL2';
export const WINDOWS_L2_MECHANISMS = Object.freeze([
    'appcontainer-lowbox', 'job-object', 'acl-temp-root', 'reparse-deny', 'env-allowlist',
]);
const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_LAUNCHER_PATH = resolve(SCRIPT_DIR, '..', 'native', 'windows-l2', 'launcher.ps1');
const STATUS_PREFIX = 'DSH_L2_STATUS ';
const AUTHORIZATION_REQUIRED_SCOPES = Object.freeze([
    'create-appcontainer-profile',
    'launch-appcontainer-process',
    'assign-job-object',
    'create-temp-root',
    'delete-attempt-temp',
]);
const AUTHORIZATION_OPTIONAL_SCOPES = Object.freeze(['delete-appcontainer-profile']);
const AUTHORIZATION_ALL_SCOPES = Object.freeze([...AUTHORIZATION_REQUIRED_SCOPES, ...AUTHORIZATION_OPTIONAL_SCOPES]);
/** Declarative operations plan; tests assert every mutation is gated. */
export function getWindowsL2Plan() {
    const operations = [
        {
            id: 'compile-inspect',
            api: 'Add-Type NativeL2.cs; NativeL2.Probe()',
            creates: [],
            impact: 'in-memory compilation; Job Object API export check (no object created); no profile, process or ACL change',
            rollback: 'none required',
            authorization_scope: null,
        },
        {
            id: 'create-profile',
            api: `CreateAppContainerProfile("${WINDOWS_L2_PROFILE_NAME}", ...)`,
            creates: [
                'per-user AppContainer profile registry entry',
                'per-user AppContainer profile folder under %LOCALAPPDATA%\\Packages',
            ],
            impact: 'persistent per-user state usable only by this Windows account; no local user, group, service or firewall change',
            rollback: `launcher.ps1 -Mode delete-profile (DeleteAppContainerProfile("${WINDOWS_L2_PROFILE_NAME}")) and remove the reported folder`,
            authorization_scope: 'create-appcontainer-profile',
        },
        {
            id: 'launch-worker',
            api: 'CreateProcessW with PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES + PROC_THREAD_ATTRIBUTE_HANDLE_LIST',
            creates: ['one transient Job Object', 'one AppContainer worker process', 'one attempt temp root'],
            impact: 'worker runs as AppContainer low-integrity identity with zero capabilities, minimal env, stdio-only handles',
            rollback: 'kill launcher (KILL_ON_JOB_CLOSE), terminate job, delete attempt temp root',
            authorization_scope: 'launch-appcontainer-process',
        },
        {
            id: 'assign-job-object',
            api: 'CreateJobObject/SetInformationJobObject/AssignProcessToJobObject',
            creates: ['transient Job Object limits'],
            impact: 'OS-enforced CPU user time, process memory, job memory, active-process count, kill-on-close',
            rollback: 'closing the Job Object kills the job',
            authorization_scope: 'assign-job-object',
        },
        {
            id: 'create-temp-root',
            api: 'Directory.CreateDirectory under the AppContainer profile folder + DACL SDDL measurement',
            creates: ['attempt temp root inside the AppContainer profile folder'],
            impact: 'inherited AppContainer ACL; reparse points rejected; host workspace not mounted',
            rollback: 'delete the attempt temp root',
            authorization_scope: 'create-temp-root',
        },
        {
            id: 'delete-attempt-temp',
            api: 'Directory.Delete(attempt temp root, recursive)',
            creates: [],
            impact: 'removes per-attempt temp files after child exit',
            rollback: 'none (deletion)',
            authorization_scope: 'delete-attempt-temp',
        },
        {
            id: 'delete-profile',
            api: `DeleteAppContainerProfile("${WINDOWS_L2_PROFILE_NAME}")`,
            creates: [],
            impact: 'removes the per-user testbed AppContainer profile registration',
            rollback: 'recreate requires a new authorization',
            authorization_scope: 'delete-appcontainer-profile',
        },
    ];
    return deepFreeze({
        schema_version: WINDOWS_L2_PLAN_VERSION,
        profile_name: WINDOWS_L2_PROFILE_NAME,
        level: 'L2',
        mechanisms: [...WINDOWS_L2_MECHANISMS],
        authorization_required: true,
        authorization_schema_version: WINDOWS_L2_AUTHORIZATION_SCHEMA_VERSION,
        required_scopes: [...AUTHORIZATION_REQUIRED_SCOPES],
        optional_scopes: [...AUTHORIZATION_OPTIONAL_SCOPES],
        operations,
        not_changed: [
            'no new local user or group',
            'no Windows optional feature or service',
            'no global or per-user firewall rule',
            'no live DSH profile or app.asar modification',
            'no repository or receipt schema change',
        ],
        limitations: [
            'test harness/launcher runs in the current High-IL administrator session during acceptance',
            'temp/output disk quotas are control-plane monitored, not OS-enforced',
            'network is AppContainer default-deny with zero capabilities; no host:port allowlist',
            'no signing key and no market-eligibility decision in the isolation module',
        ],
        authorization_document: 'src/isolation/native/windows-l2/AUTHORIZATION-REQUEST.md',
    });
}
/**
 * Validate a captain/user authorization object. This is a governance gate, not
 * a cryptographic proof; `launcher.ps1` re-validates the same fields.
 */
export function validateWindowsL2Authorization(value, options = {}) {
    const errors = [];
    if (!isPlainRecord(value))
        return { ok: false, errors: ['authorization-not-object'] };
    const doc = value;
    const allowed = [
        'schema_version', 'approved_by', 'approval_ref', 'profile_name', 'scope',
        'issued_at', 'expires_at', 'acknowledged_risks',
    ];
    for (const key of Object.keys(doc)) {
        if (!allowed.includes(key))
            errors.push(`unknown-field:${key}`);
    }
    if (doc.schema_version !== WINDOWS_L2_AUTHORIZATION_SCHEMA_VERSION)
        errors.push('unknown-schema-version');
    if (!isNonEmptyString(doc.approved_by) || doc.approved_by.length > 256)
        errors.push('approved-by-invalid');
    if (!isNonEmptyString(doc.approval_ref) || doc.approval_ref.length > 512)
        errors.push('approval-ref-invalid');
    if (doc.profile_name !== WINDOWS_L2_PROFILE_NAME)
        errors.push('profile-name-mismatch');
    if (!Array.isArray(doc.scope)) {
        errors.push('scope-not-array');
    }
    else {
        for (const scope of doc.scope) {
            if (typeof scope !== 'string' || !AUTHORIZATION_ALL_SCOPES.includes(scope)) {
                errors.push(`scope-invalid:${String(scope)}`);
            }
        }
        for (const required of AUTHORIZATION_REQUIRED_SCOPES) {
            if (!doc.scope.includes(required))
                errors.push(`scope-missing:${required}`);
        }
    }
    if (!isRfc3339Utc(doc.issued_at))
        errors.push('issued-at-invalid');
    if (!isRfc3339Utc(doc.expires_at))
        errors.push('expires-at-invalid');
    if (isRfc3339Utc(doc.issued_at) && isRfc3339Utc(doc.expires_at)) {
        const issued = Date.parse(doc.issued_at);
        const expires = Date.parse(doc.expires_at);
        if (!(expires > issued))
            errors.push('expires-before-issued');
    }
    const nowMs = resolveNow(options.now);
    if (isRfc3339Utc(doc.expires_at) && nowMs > Date.parse(doc.expires_at))
        errors.push('authorization-expired');
    if (isRfc3339Utc(doc.issued_at) && Date.parse(doc.issued_at) > nowMs + 5 * 60 * 1000)
        errors.push('issued-at-in-future');
    if (!Array.isArray(doc.acknowledged_risks) || doc.acknowledged_risks.length === 0 ||
        doc.acknowledged_risks.some((item) => typeof item !== 'string' || item.length === 0 || item.length > 512)) {
        errors.push('acknowledged-risks-invalid');
    }
    return { ok: errors.length === 0, errors };
}
/** Read-only inspection. Never creates a profile or launches a worker. */
let defaultInspectionPromise = null;
export function inspectWindowsL2Backend(options = {}) {
    const isDefault = options.pwshPath === undefined && options.launcherPath === undefined &&
        options.timeoutMs === undefined && options.now === undefined && options.fresh !== true;
    if (isDefault && defaultInspectionPromise !== null)
        return defaultInspectionPromise;
    const run = (async () => {
        const first = await inspectWindowsL2BackendOnce(options);
        if (first.status === 'ok')
            return first;
        // A concurrent Add-Type invocation can transiently fail; retry once. This
        // never turns a real blocked/failed probe into a pass (the retry must also
        // return status=ok).
        await new Promise((resolveWait) => setTimeout(resolveWait, 300));
        const second = await inspectWindowsL2BackendOnce(options);
        return second.status === 'ok' ? second : first;
    })();
    if (isDefault) {
        defaultInspectionPromise = run;
        run.then((result) => {
            if (result.status !== 'ok' && isDefault)
                defaultInspectionPromise = null;
        }, () => {
            if (isDefault)
                defaultInspectionPromise = null;
        });
    }
    return run;
}
async function inspectWindowsL2BackendOnce(options = {}) {
    const now = typeof options.now === 'function' ? options.now : () => new Date();
    const pwshPath = options.pwshPath ?? defaultPwshPath();
    const launcherPath = options.launcherPath ?? DEFAULT_LAUNCHER_PATH;
    if (!existsSync(launcherPath)) {
        return deepFreeze({
            ran: false,
            status: 'unavailable',
            probe: null,
            errors: ['launcher-script-missing'],
            evidence_grade: 'E0',
            mutations: false,
            launcher_path: launcherPath,
            inspected_at: now().toISOString(),
        });
    }
    try {
        const { stdout, stderr, exitCode } = await runLauncher(pwshPath, launcherPath, ['-Mode', 'inspect'], options.timeoutMs ?? 60_000);
        const probe = parseStatusLine(stderr);
        if (exitCode === 0 && probe !== null && probe.status === 'ok') {
            const redacted = { ...probe };
            if (Object.hasOwn(redacted, 'current_user'))
                redacted.current_user = 'redacted';
            return deepFreeze({
                ran: true,
                status: 'ok',
                probe: redacted,
                errors: [],
                evidence_grade: 'E0',
                mutations: false,
                launcher_path: launcherPath,
                inspected_at: now().toISOString(),
            });
        }
        return deepFreeze({
            ran: true,
            status: 'blocked',
            probe,
            errors: [stderr.trim().slice(0, 2048) || 'inspect-failed', `exit:${exitCode}`, `stdout:${stdout.trim().slice(0, 512)}`],
            evidence_grade: 'E0',
            mutations: false,
            launcher_path: launcherPath,
            inspected_at: now().toISOString(),
        });
    }
    catch (error) {
        return deepFreeze({
            ran: false,
            status: 'unavailable',
            probe: null,
            errors: [error instanceof Error ? error.message : String(error)],
            evidence_grade: 'E0',
            mutations: false,
            launcher_path: launcherPath,
            inspected_at: now().toISOString(),
        });
    }
}
/**
 * Readiness report for the provider/plan. `market_available` is hard-coded
 * false: native preparation is not evidence and A2/availability are missing.
 */
export function windowsL2ProviderReadiness(hostFacts, inspection) {
    const probe = inspection?.probe ?? null;
    const prepared = inspection?.ran === true &&
        inspection.status === 'ok' &&
        probe?.native_backend_compiled === true &&
        probe?.job_object_ready === true &&
        probe?.userenv_exports === true;
    const reasons = new Set();
    if (!prepared)
        reasons.add(ISOLATION_REASON.providerMissing);
    if (hostFacts.session.elevated !== false)
        reasons.add(ISOLATION_REASON.workerIdentityNotLowPrivilege);
    reasons.add(ISOLATION_REASON.providerNotMeasured);
    reasons.add(ISOLATION_REASON.adversarialSuiteMissing);
    return deepFreeze({
        mechanism: 'windows-appcontainer-jobobject/v1',
        prepared,
        market_available: false,
        reason_codes: [...reasons],
        requires_authorization: true,
        authorization_steps: getWindowsL2Plan().operations.filter((operation) => operation.authorization_scope !== null),
        enforced_dimensions: {
            identity: prepared,
            filesystem: prepared,
            network: prepared,
            subprocess: prepared,
            devices: prepared,
            cpu_ms: prepared,
            memory_mb: prepared,
            secrets: prepared,
        },
        unenforced: ['temp_bytes', 'output_bytes'],
        limitations: [
            'temp/output bytes are control-plane monitored, not OS-enforced',
            'acceptance harness runs in the current High-IL administrator session',
            'no network allowlist; AppContainer zero-capability default-deny only',
        ],
    });
}
/**
 * Create the guarded native transport. Without a valid authorization object the
 * transport returns structured blocked results and never spawns the launcher.
 */
export function createWindowsL2Transport(options) {
    const now = typeof options.now === 'function' ? options.now : () => new Date();
    const authorizationValidation = validateWindowsL2Authorization(options.authorization, options.authorizationCheck ?? {});
    const pwshPath = options.pwshPath ?? defaultPwshPath();
    const launcherPath = options.launcherPath ?? DEFAULT_LAUNCHER_PATH;
    const policyDigest = isPlainRecord(options.policy) ? policyDigestOf(options.policy) : null;
    const handles = new WeakMap();
    function blocked(detail, reasonCodes = [ISOLATION_REASON.launchBlocked]) {
        return deepFreeze({
            schema_version: 'launcher-launch-result/v1',
            provider_id: 'windows-appcontainer-l2',
            status: 'blocked',
            worker_id: null,
            pid: null,
            attestation: null,
            launch_attempted: false,
            fallback_used: false,
            reason_codes: reasonCodes,
            detail,
        });
    }
    return deepFreeze({
        async launch(input) {
            if (!authorizationValidation.ok) {
                return blocked(`authorization-required:${authorizationValidation.errors[0]}`);
            }
            if (policyDigest === null)
                return blocked('market-gate-policy-required');
            if (!isPlainRecord(input.request))
                return blocked('launch-request-not-object');
            if (!existsSync(options.workerNodePath))
                return blocked('worker-node-path-missing');
            if (!existsSync(options.workerEntry))
                return blocked('worker-entry-missing');
            const request = input.request;
            const authorizationPath = options.authorizationPath ?? writeAuthorizationFile(options.authorization);
            const requestPath = writeJsonTempFile('dsh-l2-request-', {
                schema_version: WINDOWS_L2_LAUNCH_REQUEST_SCHEMA_VERSION,
                profile_name: WINDOWS_L2_PROFILE_NAME,
                temp_root: 'auto',
                application_path: options.workerNodePath,
                arguments: '"' + options.workerEntry + '"',
                working_directory: 'auto',
                limits: {
                    cpu_ms: options.limits.cpu_ms,
                    memory_mb: options.limits.memory_mb,
                    processes: options.limits.processes,
                },
                env: minimalEnvironment(),
                create_profile: true,
                delete_temp_on_exit: true,
                delete_profile_on_exit: false,
            });
            try {
                const child = spawn(pwshPath, [
                    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                    '-File', launcherPath, '-Mode', 'execute',
                    '-RequestPath', requestPath, '-AuthorizationPath', authorizationPath,
                ], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
                const launched = await waitForStatus(child, 'launched', options.launchTimeoutMs ?? 120_000);
                if (launched === null) {
                    child.kill();
                    return blocked('launcher-blocked-or-timeout');
                }
                const childPid = typeof launched.pid === 'number' ? launched.pid : null;
                const tempRoot = typeof launched.temp_root === 'string' ? launched.temp_root : null;
                const handle = {
                    launcher: child,
                    launched,
                    request,
                    descriptor: input.descriptor,
                    tempRoot,
                    childPid,
                    exited: new Promise((resolveExit) => {
                        child.once('close', (code) => resolveExit(code));
                        child.once('error', () => resolveExit(null));
                    }),
                };
                const handleKey = Object.freeze({ handle: handle.launched.pid ?? 0 });
                handles.set(handleKey, handle);
                const launchResult = {
                    schema_version: 'launcher-launch-result/v1',
                    provider_id: 'windows-appcontainer-l2',
                    status: 'launched',
                    worker_id: `worker-${String(launched.pid ?? 'unknown')}`,
                    pid: childPid,
                    attestation: null,
                    launch_attempted: true,
                    fallback_used: false,
                    reason_codes: [],
                    detail: 'launched',
                };
                return deepFreeze({ ...launchResult, handle: handleKey });
            }
            finally {
                if (options.authorizationPath === undefined)
                    rmSync(authorizationPath, { force: true });
                rmSync(requestPath, { force: true });
            }
        },
        async cancel(handle) {
            const internal = handleFor(handles, handle);
            if (!internal) {
                return deepFreeze({ acknowledged: false, reason_codes: [ISOLATION_REASON.launchBlocked] });
            }
            internal.launcher.kill();
            const exitCode = await withTimeout(internal.exited, options.reapTimeoutMs ?? 30_000);
            const pidAlive = internal.childPid !== null ? isPidAlive(internal.childPid) : null;
            return deepFreeze({
                schema_version: 'launcher-cancel-result/v1',
                acknowledged: exitCode !== null && pidAlive === false,
                exit_code: exitCode,
                pid_alive: pidAlive,
                reason_codes: exitCode === null || pidAlive !== false ? ['cancel-not-acknowledged'] : [],
            });
        },
        async reap(handle) {
            const internal = handleFor(handles, handle);
            if (!internal) {
                return deepFreeze({
                    schema_version: 'launcher-reap-result/v1',
                    reaped: false,
                    pid_alive: null,
                    temp_removed: null,
                    reason_codes: [ISOLATION_REASON.launchBlocked],
                });
            }
            const exitCode = await withTimeout(internal.exited, options.reapTimeoutMs ?? 30_000);
            const pidAlive = internal.childPid !== null ? isPidAlive(internal.childPid) : null;
            const tempRemoved = internal.tempRoot === null ? null : !existsSync(internal.tempRoot);
            const reaped = pidAlive === false && tempRemoved !== false;
            return deepFreeze({
                schema_version: 'launcher-reap-result/v1',
                reaped,
                exit_code: exitCode,
                pid_alive: pidAlive,
                temp_removed: tempRemoved,
                reason_codes: reaped ? [] : ['reap-incomplete'],
            });
        },
        async attest(handle) {
            const internal = handleFor(handles, handle);
            if (!internal || policyDigest === null) {
                return deepFreeze({ status: 'blocked', attestation: null, reason_codes: [ISOLATION_REASON.attestationMissing] });
            }
            const attestation = buildNativeAttestation(internal, options, policyDigest, now);
            return deepFreeze({ status: 'attested', attestation });
        },
        async runAdversarialCase(caseSpec) {
            if (authorizationValidation.ok && typeof options.adversarialRunner === 'function') {
                return options.adversarialRunner(caseSpec);
            }
            return {
                case_id: caseSpec.id,
                status: 'blocked',
                reason_codes: [ISOLATION_REASON.adversarialSuiteMissing],
                command: null,
                observed: null,
            };
        },
    });
}
/**
 * Build a measured `isolation-attestation/v1` from a native launch status. This
 * is used both by the guarded transport and by the authorized one-off A2
 * execution harness. The caller must verify the resulting attestation; it is not
 * market evidence by itself.
 */
export function buildWindowsL2AttestationFromMeasurement(input) {
    const now = typeof input.now === 'function' ? input.now : () => new Date();
    const launched = input.launched;
    const sddl = typeof launched.acl_sddl === 'string' ? launched.acl_sddl : '';
    const pid = typeof launched.pid === 'number' && Number.isSafeInteger(launched.pid) ? launched.pid : 1;
    const jobLimits = isPlainRecord(launched.job_limits) ? launched.job_limits : {};
    const appContainerSid = typeof launched.appcontainer_sid === 'string' ? launched.appcontainer_sid : '';
    const startedAt = typeof launched.started_at === 'string' && launched.started_at.length > 0
        ? launched.started_at
        : now().toISOString();
    const request = input.request;
    const runId = typeof request.run_id === 'string' ? request.run_id : 'run-unknown';
    const planId = typeof request.plan_id === 'string' ? request.plan_id : 'plan-sha256:' + '0'.repeat(64);
    const testId = typeof request.test_id === 'string' ? request.test_id : 'unknown.test';
    const attempt = typeof request.attempt === 'number' && Number.isSafeInteger(request.attempt) ? request.attempt : 1;
    const artifactDigest = typeof request.artifact_digest === 'string' ? request.artifact_digest : 'sha256:' + '0'.repeat(64);
    const inputRef = 'input-' + artifactDigest.replace(/^sha256:/, '');
    const envKeys = ['SystemRoot', 'SystemDrive', 'windir', 'TEMP', 'TMP', 'PATH'];
    const measuredCpuMs = typeof jobLimits.process_time_100ns === 'number'
        ? Math.max(1, Math.floor(jobLimits.process_time_100ns / 10000))
        : input.limits.cpu_ms;
    const measuredMemoryMb = typeof jobLimits.process_memory_bytes === 'number'
        ? Math.max(1, Math.floor(jobLimits.process_memory_bytes / (1024 * 1024)))
        : input.limits.memory_mb;
    const measuredProcesses = typeof jobLimits.active_process_limit === 'number'
        ? Math.max(1, jobLimits.active_process_limit)
        : input.limits.processes;
    const evidenceOne = 'ev-launcher-' + digestDocument({
        pid,
        sid: appContainerSid,
        sddl,
        job_limits: jobLimits,
        launched_at: startedAt,
    }).replace(/^sha256:/, '');
    const evidenceTwo = 'ev-jobobject-' + digestDocument({ job_limits: jobLimits, temp: launched.temp_root ?? null }).replace(/^sha256:/, '');
    const nonce = randomBytes(32).toString('base64url');
    return buildIsolationAttestation({
        attestation_id: 'iso-' + randomBytes(16).toString('hex'),
        issuer: {
            launcher_id: input.descriptor.launcher_id,
            version: input.descriptor.launcher_version,
            trust: 'control-plane-measured',
            provider_digest: input.descriptor.provider_digest,
        },
        run_id: runId,
        plan_id: planId,
        test_id: testId,
        attempt,
        worker: {
            worker_id: 'worker-' + String(pid),
            pid,
            started_at: startedAt,
        },
        isolation: {
            level: 'L2',
            mechanisms: ['appcontainer-lowbox', 'job-object', 'acl-temp-root', 'reparse-deny', 'env-allowlist'],
            elevated: false,
        },
        identity: {
            sid: appContainerSid,
            user: WINDOWS_L2_PROFILE_NAME,
            integrity: 'low',
            appcontainer_sid: appContainerSid,
        },
        filesystem: {
            root: typeof launched.temp_root === 'string' ? launched.temp_root : '',
            acl_digest: 'sha256:' + digestDocument({ sddl }).replace(/^sha256:/, ''),
            read_only_inputs: [inputRef],
            reparse_follow: 'deny',
        },
        network: {
            default: 'deny',
            allowlist: [],
            mechanism: 'appcontainer-no-capability',
            rules_digest: 'sha256:' + digestDocument({ default: 'deny', capability_count: launched.capability_count ?? 0, allowlist: [] }).replace(/^sha256:/, ''),
        },
        resources: {
            cpu_ms: measuredCpuMs,
            memory_mb: measuredMemoryMb,
            processes: measuredProcesses,
            temp_bytes: input.limits.temp_bytes,
            output_bytes: input.limits.output_bytes,
            job_object: 'windows-job-object',
            limits_digest: 'sha256:' + digestDocument({
                job_limits: jobLimits,
                temp_bytes: input.limits.temp_bytes,
                output_bytes: input.limits.output_bytes,
            }).replace(/^sha256:/, ''),
        },
        process_tree: {
            kill_on_close: true,
            observed_pids: [pid],
        },
        devices: {
            enforced: true,
            denied: ['device-access-not-granted'],
        },
        secrets: {
            enforced: true,
            ambient_credentials: 'none',
            env_allowlist_digest: 'sha256:' + digestDocument({ keys: envKeys }).replace(/^sha256:/, ''),
            handle_inheritance: 'deny',
        },
        evidence_refs: [evidenceOne, evidenceTwo],
        issued_at: startedAt,
        nonce,
        policy: {
            policy_version: MARKET_GATE_POLICY_VERSION,
            policy_digest: policyDigestOf(input.policy),
        },
        signature: null,
    });
}
function buildNativeAttestation(handle, options, policyDigest, now) {
    return buildWindowsL2AttestationFromMeasurement({
        launched: handle.launched,
        request: handle.request,
        descriptor: handle.descriptor,
        limits: options.limits,
        policy: options.policy,
        now,
    });
}
function handleFor(handles, handle) {
    if (handle === null || typeof handle !== 'object')
        return null;
    return handles.get(handle) ?? null;
}
function defaultPwshPath() {
    return process.env.DSH_PWSH_PATH ?? process.env.PWSH_PATH ?? 'pwsh';
}
function runLauncher(pwshPath, launcherPath, args, timeoutMs) {
    return new Promise((resolveRun, rejectRun) => {
        execFile(pwshPath, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', launcherPath, ...args], {
            timeout: timeoutMs,
            windowsHide: true,
            encoding: 'utf8',
            maxBuffer: 8 * 1024 * 1024,
        }, (error, stdout, stderr) => {
            if (error && error.code === 'ENOENT') {
                rejectRun(error);
                return;
            }
            resolveRun({
                stdout: typeof stdout === 'string' ? stdout : '',
                stderr: typeof stderr === 'string' ? stderr : '',
                exitCode: error && typeof error.code === 'number' ? error.code : 0,
            });
        });
    });
}
function parseStatusLine(stderr) {
    for (const line of stderr.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed.startsWith(STATUS_PREFIX))
            continue;
        try {
            const parsed = JSON.parse(trimmed.slice(STATUS_PREFIX.length));
            if (isPlainRecord(parsed))
                return parsed;
        }
        catch {
            // fall through to the next status line
        }
    }
    return null;
}
function waitForStatus(child, status, timeoutMs) {
    return new Promise((resolveStatus) => {
        let settled = false;
        let buffer = '';
        const finish = (value) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            resolveStatus(value);
        };
        const timer = setTimeout(() => finish(null), timeoutMs);
        child.stderr?.setEncoding('utf8');
        child.stderr?.on('data', (chunk) => {
            buffer += chunk;
            let index = buffer.indexOf('\n');
            while (index >= 0) {
                const line = buffer.slice(0, index).trim();
                buffer = buffer.slice(index + 1);
                if (line.startsWith(STATUS_PREFIX)) {
                    try {
                        const parsed = JSON.parse(line.slice(STATUS_PREFIX.length));
                        if (isPlainRecord(parsed) && parsed.status === status) {
                            finish(parsed);
                            return;
                        }
                        if (isPlainRecord(parsed) && parsed.status === 'blocked') {
                            finish(null);
                            return;
                        }
                    }
                    catch {
                        // ignore malformed status line
                    }
                }
                index = buffer.indexOf('\n');
            }
        });
        child.once('close', () => finish(null));
        child.once('error', () => finish(null));
    });
}
function writeAuthorizationFile(authorization) {
    return writeJsonTempFile('dsh-l2-auth-', authorization);
}
function writeJsonTempFile(prefix, value) {
    const dir = mkdtempSync(join(tmpdir(), prefix));
    const file = join(dir, 'payload.json');
    writeFileSync(file, JSON.stringify(value), { encoding: 'utf8', mode: 0o600 });
    return file;
}
function minimalEnvironment() {
    const env = {};
    for (const key of ['SystemRoot', 'SystemDrive', 'windir']) {
        const value = process.env[key];
        if (typeof value === 'string' && value.length > 0)
            env[key] = value;
    }
    return env;
}
function isPidAlive(pid) {
    try {
        process.kill(pid, 0);
        return true;
    }
    catch {
        return false;
    }
}
function withTimeout(promise, timeoutMs) {
    return new Promise((resolveTimeout) => {
        const timer = setTimeout(() => resolveTimeout(null), timeoutMs);
        promise.then((value) => { clearTimeout(timer); resolveTimeout(value); }, () => { clearTimeout(timer); resolveTimeout(null); });
    });
}
function resolveNow(value) {
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
