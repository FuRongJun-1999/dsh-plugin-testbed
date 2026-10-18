/**
 * Capability-driven L2/L3 isolation provider catalog.
 *
 * ## Fail-closed provider rule
 * A provider is **available** only when all of the following hold:
 *   1. the platform prerequisites are present (checked read-only);
 *   2. the worker would run under a verified non-elevated dedicated identity;
 *   3. the launcher has produced an externally measured provider availability
 *      record (`isolation-availability/v1`, grades E2/E3) bound to this host;
 *   4. an A2 (L2) / A3 (L3) adversarial suite has been executed and passed.
 *
 * None of these hold on the current Windows host, so every built-in candidate is
 * unavailable and `launch()` returns a structured `blocked` result **without
 * starting a process**. There is no code path from these providers to the L1
 * subprocess adapter: L1 can never be substituted for L2/L3 (L2-12, L3-08).
 *
 * Candidate mechanisms are still described (Windows restricted token /
 * AppContainer + Job Object, rootless container, micro-VM, remote runner) so a
 * future approved environment can implement the external transport and be
 * measured. The interface here is intentionally provider-neutral.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/isolation/providers
 */
import { ISOLATION_DIMENSIONS, ISOLATION_REASON, MARKET_EVIDENCE_GRADES, MARKET_ISOLATION_LEVELS, WORKER_LAUNCHER_SCHEMA_VERSION, buildLauncherDescriptor, deepFreeze, findSecretMaterial, isEvidenceRef, isMarketIsolationLevel, isNonce, isPlainRecord, isPositiveSafeInteger, isRfc3339Utc, isRunId, isPlanId, isTestId, isolationLevelRank, } from './contracts.js';
import { collectHostFacts, hostFingerprint } from './host-capabilities.js';
/** Stable provider ids (used by evidence and market policy). */
export const PROVIDER_IDS = Object.freeze({
    windowsRestrictedTokenL2: 'windows-restricted-token-l2',
    windowsAppContainerL2: 'windows-appcontainer-l2',
    posixUserNamespaceL2: 'posix-user-namespace-l2',
    rootlessContainerL3: 'rootless-container-l3',
    microVmL3: 'micro-vm-l3',
    remoteRunnerL3: 'remote-runner-l3',
});
export const ISOLATION_AVAILABILITY_SCHEMA_VERSION = 'isolation-availability/v1';
export const LAUNCHER_LAUNCH_REQUEST_SCHEMA_VERSION = 'launcher-launch-request/v1';
export const LAUNCHER_LAUNCH_RESULT_SCHEMA_VERSION = 'launcher-launch-result/v1';
export const LAUNCHER_REAP_RESULT_SCHEMA_VERSION = 'launcher-reap-result/v1';
export const PROVIDER_SELECTION_SCHEMA_VERSION = 'provider-selection/v1';
export const PROVIDER_LAUNCHER_VERSION = '0.1.0-isolation-candidate';
const COMMON_LIMITATIONS = Object.freeze([
    'candidate-not-installed',
    'no-external-measurement',
    'a2-a3-not-executed',
    'market-use-blocked',
]);
const SPECS = Object.freeze([
    {
        provider_id: PROVIDER_IDS.windowsRestrictedTokenL2,
        level: 'L2',
        platform: 'win32',
        mechanisms: ['dedicated-user', 'restricted-token', 'job-object', 'firewall-per-user', 'acl-temp-root', 'reparse-deny', 'env-allowlist'],
        capability_mechanisms: {
            filesystem: 'acl-temp-root+reparse-deny',
            network: 'firewall-per-user',
            subprocess: 'restricted-token+job-object',
            devices: 'token-device-restriction',
            cpu_ms: 'job-object',
            memory_mb: 'job-object',
            secrets: 'env-allowlist+no-handle-inheritance',
        },
        limitations: [...COMMON_LIMITATIONS, 'requires-dedicated-low-privilege-identity', 'requires-SeAssignPrimaryTokenPrivilege'],
    },
    {
        provider_id: PROVIDER_IDS.windowsAppContainerL2,
        level: 'L2',
        platform: 'win32',
        mechanisms: ['appcontainer-lowbox', 'job-object', 'firewall-per-user', 'acl-temp-root', 'reparse-deny', 'env-allowlist'],
        capability_mechanisms: {
            filesystem: 'appcontainer-capability+acl-temp-root',
            network: 'appcontainer-no-network',
            subprocess: 'appcontainer-lowbox+job-object',
            devices: 'appcontainer-device-restriction',
            cpu_ms: 'job-object',
            memory_mb: 'job-object',
            secrets: 'env-allowlist+no-handle-inheritance',
        },
        limitations: [...COMMON_LIMITATIONS, 'requires-appcontainer-profile', 'requires-lowbox-token'],
    },
    {
        provider_id: PROVIDER_IDS.posixUserNamespaceL2,
        level: 'L2',
        platform: 'linux',
        mechanisms: ['user-namespace', 'cgroup-v2', 'network-namespace', 'env-allowlist'],
        capability_mechanisms: {
            filesystem: 'mount-namespace',
            network: 'network-namespace',
            subprocess: 'user-namespace+cgroup-v2',
            devices: 'device-cgroup',
            cpu_ms: 'cgroup-v2',
            memory_mb: 'cgroup-v2',
            secrets: 'env-allowlist+no-secret-mount',
        },
        limitations: [...COMMON_LIMITATIONS, 'requires-user-namespace', 'requires-cgroup-v2-delegation'],
    },
    {
        provider_id: PROVIDER_IDS.rootlessContainerL3,
        level: 'L3',
        platform: 'linux',
        mechanisms: ['rootless-container', 'pinned-image-digest', 'readonly-rootfs', 'no-new-privs', 'seccomp', 'network-namespace', 'credential-isolation'],
        capability_mechanisms: {
            filesystem: 'readonly-rootfs',
            network: 'network-namespace',
            subprocess: 'seccomp+no-new-privs',
            devices: 'minimal-device-set',
            cpu_ms: 'cgroup-v2',
            memory_mb: 'cgroup-v2',
            secrets: 'no-host-secret-mount',
        },
        limitations: [...COMMON_LIMITATIONS, 'requires-rootless-container-runtime', 'requires-pinned-image-digest'],
    },
    {
        provider_id: PROVIDER_IDS.microVmL3,
        level: 'L3',
        platform: 'linux',
        mechanisms: ['micro-vm', 'pinned-image-digest', 'readonly-rootfs', 'network-namespace', 'credential-isolation'],
        capability_mechanisms: {
            filesystem: 'readonly-rootfs',
            network: 'vm-network-deny',
            subprocess: 'vm-boundary',
            devices: 'vm-minimal-devices',
            cpu_ms: 'vm-vcpu-quota',
            memory_mb: 'vm-memory-quota',
            secrets: 'no-host-secret-mount',
        },
        limitations: [...COMMON_LIMITATIONS, 'requires-hypervisor', 'requires-pinned-vm-image'],
    },
    {
        provider_id: PROVIDER_IDS.remoteRunnerL3,
        level: 'L3',
        platform: 'any',
        mechanisms: ['remote-runner', 'signed-runner-attestation', 'pinned-image-digest', 'network-namespace', 'credential-isolation'],
        capability_mechanisms: {
            filesystem: 'runner-declared-fs',
            network: 'runner-network-policy',
            subprocess: 'runner-process-isolation',
            devices: 'runner-device-policy',
            cpu_ms: 'runner-quota',
            memory_mb: 'runner-quota',
            secrets: 'credential-scope-none',
        },
        limitations: [...COMMON_LIMITATIONS, 'requires-registered-runner', 'requires-pinned-operator-key'],
    },
]);
function buildPrerequisites(spec, hostFacts, options) {
    const platformOk = spec.platform === 'any' || spec.platform === hostFacts.platform;
    const prerequisites = [
        { id: 'platform', status: platformOk ? 'available' : 'unavailable', detail: `${spec.platform} vs ${hostFacts.platform}` },
    ];
    const add = (id, status, detail) => {
        prerequisites.push({ id, status, detail });
    };
    const sessionLowPrivilege = hostFacts.session.elevated === false &&
        ['low', 'medium', 'medium-plus'].includes(hostFacts.session.integrity);
    add('session-not-elevated', sessionLowPrivilege ? 'available' : 'unavailable', `elevated:${String(hostFacts.session.elevated)},integrity:${hostFacts.session.integrity}`);
    add('dedicated-low-privilege-identity', hostFacts.dedicated_worker_identity.status === 'available' ? 'available' : 'unavailable', hostFacts.dedicated_worker_identity.detail);
    if (spec.provider_id === PROVIDER_IDS.windowsRestrictedTokenL2) {
        add('restricted-token-privileges', hostFacts.privileges.status === 'probed' &&
            hostFacts.privileges.enabled.includes('SeAssignPrimaryTokenPrivilege') &&
            hostFacts.privileges.enabled.includes('SeIncreaseQuotaPrivilege') ? 'available' : 'unavailable', `enabled:${hostFacts.privileges.enabled.join(',') || 'none'}`);
    }
    else if (spec.provider_id === PROVIDER_IDS.windowsAppContainerL2) {
        const profileReady = options.nativeBackend?.profile_exists === true;
        add('appcontainer-profile', profileReady ? 'available' : 'unavailable', profileReady ? 'profile-exists' : 'no AppContainer/LowBox profile provisioned');
        const nativeCompiled = options.nativeBackend?.native_backend_compiled === true &&
            options.nativeBackend?.userenv_exports === true;
        add('native-backend', nativeCompiled ? 'available' : 'unavailable', nativeCompiled ? 'native-backend-compiled' : 'native-backend-not-prepared');
    }
    else if (spec.provider_id === PROVIDER_IDS.posixUserNamespaceL2) {
        add('user-namespace', hostFacts.isolation_primitives.user_namespace === 'present-unverified' ? 'unverified' : 'unavailable', String(hostFacts.isolation_primitives.user_namespace));
        add('cgroup-v2', hostFacts.isolation_primitives.cgroup_v2 === 'present-unverified' ? 'unverified' : 'unavailable', String(hostFacts.isolation_primitives.cgroup_v2));
    }
    else if (spec.provider_id === PROVIDER_IDS.rootlessContainerL3) {
        add('rootless-container-runtime', hostFacts.isolation_primitives.rootless_container === 'runtime-binary-present-unverified' ? 'unverified' : 'unavailable', String(hostFacts.isolation_primitives.rootless_container));
        add('pinned-image-digest', 'unavailable', 'no pinned image digest supplied');
    }
    else if (spec.provider_id === PROVIDER_IDS.microVmL3) {
        add('hypervisor', hostFacts.isolation_primitives.micro_vm === 'tooling-present-unverified' ? 'unverified' : 'unavailable', String(hostFacts.isolation_primitives.micro_vm));
        add('pinned-vm-image', 'unavailable', 'no pinned VM image supplied');
    }
    else if (spec.provider_id === PROVIDER_IDS.remoteRunnerL3) {
        add('registered-runner', hostFacts.isolation_primitives.remote_runner === 'available' ? 'available' : 'unavailable', String(hostFacts.isolation_primitives.remote_runner));
        add('pinned-operator-key', 'unavailable', 'no pinned operator public key supplied');
    }
    if (spec.provider_id === PROVIDER_IDS.windowsRestrictedTokenL2 || spec.provider_id === PROVIDER_IDS.windowsAppContainerL2) {
        const jobReady = options.nativeBackend?.job_object_ready === true
            ? 'available'
            : (hostFacts.isolation_primitives.windows_job_object === 'os-supported-unmeasured' ? 'unverified' : 'unavailable');
        add('job-object', jobReady, jobReady === 'available' ? 'job-object-ready' : String(hostFacts.isolation_primitives.windows_job_object));
    }
    add('external-availability-record', options.availabilityRecord ? 'unverified' : 'unavailable', options.availabilityRecord ? 'record-not-yet-validated' : 'no externally measured availability record');
    add('a2-or-a3-suite', options.a2Suite ? 'unverified' : 'unavailable', options.a2Suite ? 'suite-evidence-not-yet-validated' : 'adversarial suite not executed');
    return prerequisites;
}
function reasonsFromPrerequisites(prerequisites) {
    const reasons = new Set();
    if (prerequisites.find((item) => item.id === 'platform')?.status === 'unavailable') {
        reasons.add(ISOLATION_REASON.providerPlatformMismatch);
    }
    if (prerequisites.find((item) => item.id === 'session-not-elevated')?.status === 'unavailable' ||
        prerequisites.find((item) => item.id === 'dedicated-low-privilege-identity')?.status === 'unavailable') {
        reasons.add(ISOLATION_REASON.workerIdentityNotLowPrivilege);
    }
    if (prerequisites.find((item) => item.id === 'external-availability-record')?.status !== 'available') {
        reasons.add(ISOLATION_REASON.providerNotMeasured);
    }
    if (prerequisites.find((item) => item.id === 'a2-or-a3-suite')?.status !== 'available') {
        reasons.add(ISOLATION_REASON.adversarialSuiteMissing);
    }
    reasons.add(ISOLATION_REASON.providerMissing);
    return [...reasons];
}
/**
 * Validate an externally supplied provider availability record. Only a record
 * graded E2/E3, produced by an external environment for the exact provider
 * digest and host fingerprint, can make a provider available.
 *
 * @param {unknown} record
 * @param {{providerDigest:string, launcherVersion:string, hostFingerprint:string}} binding
 * @returns {{ok:boolean, errors:string[]}}
 */
export function validateAvailabilityRecord(record, binding) {
    const errors = [];
    if (!isPlainRecord(record))
        return { ok: false, errors: ['availability-record-invalid'] };
    const doc = record;
    const allowed = [
        'schema_version', 'provider_digest', 'launcher_version', 'grade', 'provenance',
        'host_fingerprint', 'measured_by', 'measured_at', 'evidence_refs', 'a2_suite', 'a3_suite',
    ];
    for (const key of Object.keys(doc)) {
        if (!allowed.includes(key))
            errors.push(`unknown-field:${key}`);
    }
    if (doc.schema_version !== ISOLATION_AVAILABILITY_SCHEMA_VERSION)
        errors.push('unknown-schema-version');
    if (doc.provider_digest !== binding.providerDigest)
        errors.push('provider-digest-mismatch');
    if (doc.launcher_version !== binding.launcherVersion)
        errors.push('launcher-version-mismatch');
    if (typeof doc.grade !== 'string' || !MARKET_EVIDENCE_GRADES.includes(doc.grade))
        errors.push('evidence-grade-not-market');
    if (doc.provenance !== 'external-environment')
        errors.push('provenance-not-external');
    if (doc.host_fingerprint !== binding.hostFingerprint)
        errors.push('host-fingerprint-mismatch');
    if (typeof doc.measured_by !== 'string' || doc.measured_by.length === 0 || doc.measured_by.length > 256) {
        errors.push('measured-by-invalid');
    }
    if (!isRfc3339Utc(doc.measured_at))
        errors.push('measured-at-invalid');
    if (!Array.isArray(doc.evidence_refs) || doc.evidence_refs.length === 0 || !doc.evidence_refs.every(isEvidenceRef)) {
        errors.push('evidence-refs-invalid');
    }
    const suiteRecord = doc.a2_suite ?? doc.a3_suite;
    if (!isPlainRecord(suiteRecord) || suiteRecord.result !== 'pass') {
        errors.push('adversarial-suite-record-missing-or-not-pass');
    }
    if (findSecretMaterial(record).length > 0)
        errors.push('secret-material-forbidden');
    return { ok: errors.length === 0, errors };
}
function createCandidateProvider(spec, options) {
    const hostFacts = options.hostFacts;
    const now = typeof options.now === 'function' ? options.now : () => new Date();
    const launcherVersion = PROVIDER_LAUNCHER_VERSION;
    const fingerprint = hostFingerprint(hostFacts);
    const descriptor = buildLauncherDescriptor({
        launcher_id: spec.provider_id,
        launcher_version: launcherVersion,
        isolation: {
            level: spec.level,
            mechanisms: spec.mechanisms,
            platform: hostFacts.platform === 'win32' ? 'win32' : (hostFacts.platform === 'darwin' ? 'darwin' : 'linux'),
            arch: hostFacts.arch,
            os_build: String(hostFacts.os_release),
        },
        capabilities: Object.fromEntries(ISOLATION_DIMENSIONS.map((dimension) => [dimension, {
                enforced: false,
                mechanism: spec.capability_mechanisms[dimension],
                ...(dimension === 'network' ? { default: 'deny' } : {}),
                ...(dimension === 'secrets' ? { ambient_credentials: 'unknown' } : {}),
            }])),
        limitations: spec.limitations,
        attestation: {
            method: 'control-plane-measured',
            schema_version: 'isolation-attestation/v1',
        },
        declared_at: now().toISOString(),
    });
    const prerequisites = buildPrerequisites(spec, hostFacts, options);
    let availabilityRecord = null;
    let availabilityProblems = [];
    if (options.availabilityRecord !== undefined) {
        if (options.externalEnvironment !== true) {
            availabilityProblems = ['external-environment-not-declared'];
        }
        else {
            const validation = validateAvailabilityRecord(options.availabilityRecord, {
                providerDigest: descriptor.provider_digest,
                launcherVersion,
                hostFingerprint: fingerprint,
            });
            availabilityRecord = validation.ok ? options.availabilityRecord : null;
            availabilityProblems = validation.errors;
        }
    }
    else if (options.externalEnvironment === true) {
        availabilityProblems = ['availability-record-missing'];
    }
    // A validated external record is the measurement that satisfies the
    // record/suite/job-object prerequisites. Host/session/profile prerequisites
    // remain independently checked above and are never waived by the record.
    if (availabilityRecord !== null) {
        for (const prerequisite of prerequisites) {
            if (prerequisite.id === 'external-availability-record' ||
                prerequisite.id === 'a2-or-a3-suite' ||
                prerequisite.id === 'job-object') {
                prerequisite.status = 'available';
                prerequisite.detail = 'external-availability-record';
            }
        }
    }
    const baseReasons = reasonsFromPrerequisites(prerequisites);
    const externalReady = availabilityRecord !== null &&
        typeof options.transport === 'object' && options.transport !== null &&
        typeof options.transport.launch === 'function';
    const available = prerequisites.every((item) => item.status === 'available') && externalReady;
    const reasonCodes = new Set(baseReasons);
    if (!externalReady)
        reasonCodes.add(ISOLATION_REASON.providerMissing);
    const measuredBy = availabilityRecord && typeof availabilityRecord.measured_by === 'string'
        ? availabilityRecord.measured_by
        : null;
    const grade = availabilityRecord && typeof availabilityRecord.grade === 'string' ? availabilityRecord.grade : 'E0';
    const evidenceRefs = availabilityRecord && Array.isArray(availabilityRecord.evidence_refs)
        ? availabilityRecord.evidence_refs.filter((value) => typeof value === 'string')
        : [];
    const availability = {
        provider_id: spec.provider_id,
        level: spec.level,
        available,
        provenance: availabilityRecord ? 'external-environment' : 'candidate',
        evidence: {
            grade,
            measured_by: measuredBy,
            evidence_refs: evidenceRefs,
        },
        prerequisites: prerequisites.map((item) => ({ ...item })),
        problems: [...new Set(availabilityProblems)],
        reason_codes: [...reasonCodes],
        host_fingerprint: fingerprint,
        a2_suite_present: Boolean(options.a2Suite),
        checked_at: now().toISOString(),
    };
    async function launch(request) {
        const requestValidation = validateLauncherLaunchRequest(request);
        if (!requestValidation.ok) {
            return blockedLaunchResult(spec.provider_id, [ISOLATION_REASON.launchBlocked, ISOLATION_REASON.attestationInvalid], `launch-request-invalid:${requestValidation.errors[0]}`);
        }
        if (!available || !options.transport) {
            return blockedLaunchResult(spec.provider_id, availability.reason_codes, 'provider-unavailable:no-managed-process-was-started');
        }
        // Only an explicitly supplied external transport can reach this point.
        return options.transport.launch({ request, descriptor });
    }
    return deepFreeze({
        provider_id: spec.provider_id,
        level: spec.level,
        schema_version: WORKER_LAUNCHER_SCHEMA_VERSION,
        provenance: availabilityRecord ? 'external-environment' : 'candidate',
        holds_signing_key: false,
        descriptor,
        availability,
        probe() {
            return availability;
        },
        describe() {
            return descriptor;
        },
        launch,
        async cancel(handle) {
            if (!available || !options.transport) {
                return deepFreeze({
                    schema_version: 'launcher-cancel-result/v1',
                    provider_id: spec.provider_id,
                    status: 'blocked',
                    acknowledged: false,
                    reason_codes: [ISOLATION_REASON.providerMissing, ISOLATION_REASON.launchBlocked],
                });
            }
            return options.transport.cancel(handle);
        },
        async reap(handle) {
            if (!available || !options.transport) {
                return deepFreeze({
                    schema_version: LAUNCHER_REAP_RESULT_SCHEMA_VERSION,
                    provider_id: spec.provider_id,
                    status: 'blocked',
                    reaped: false,
                    pid_alive: null,
                    temp_removed: null,
                    reason_codes: [ISOLATION_REASON.providerMissing, ISOLATION_REASON.launchBlocked],
                });
            }
            return options.transport.reap(handle);
        },
        async attest(handle) {
            if (!available || !options.transport) {
                return deepFreeze({
                    schema_version: 'launcher-attest-result/v1',
                    provider_id: spec.provider_id,
                    status: 'blocked',
                    attestation: null,
                    reason_codes: [ISOLATION_REASON.providerMissing, ISOLATION_REASON.attestationMissing],
                });
            }
            return options.transport.attest(handle);
        },
        async runAdversarialCase(caseSpec) {
            if (!available || !options.transport) {
                return {
                    case_id: caseSpec.id,
                    status: 'blocked',
                    reason_codes: [...availability.reason_codes],
                    observed: null,
                    command: null,
                };
            }
            return options.transport.runAdversarialCase(caseSpec);
        },
    });
}
function blockedLaunchResult(providerId, reasonCodes, detail) {
    return deepFreeze({
        schema_version: LAUNCHER_LAUNCH_RESULT_SCHEMA_VERSION,
        provider_id: providerId,
        status: 'blocked',
        worker_id: null,
        pid: null,
        attestation: null,
        launch_attempted: false,
        fallback_used: false,
        reason_codes: [...new Set(reasonCodes)],
        detail,
    });
}
/**
 * Validate a `launcher-launch-request/v1`. No secret values are permitted.
 * @param {unknown} request
 * @returns {{ok:boolean, errors:string[]}}
 */
export function validateLauncherLaunchRequest(request) {
    const errors = [];
    if (!isPlainRecord(request))
        return { ok: false, errors: ['request-not-object'] };
    const doc = request;
    const allowed = [
        'schema_version', 'run_id', 'plan_id', 'test_id', 'attempt', 'artifact_digest',
        'input_dir', 'output_dir', 'budget', 'deadline', 'network_allowlist', 'required_level',
        'cancel_token', 'nonce',
    ];
    for (const key of Object.keys(doc)) {
        if (!allowed.includes(key))
            errors.push(`unknown-field:${key}`);
    }
    if (doc.schema_version !== LAUNCHER_LAUNCH_REQUEST_SCHEMA_VERSION)
        errors.push('unknown-schema-version');
    if (!isRunId(doc.run_id))
        errors.push('run-id-invalid');
    if (!isPlanId(doc.plan_id))
        errors.push('plan-id-invalid');
    if (!isTestId(doc.test_id))
        errors.push('test-id-invalid');
    if (!isPositiveSafeInteger(doc.attempt))
        errors.push('attempt-invalid');
    if (typeof doc.artifact_digest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(doc.artifact_digest))
        errors.push('artifact-digest-invalid');
    if (typeof doc.input_dir !== 'string' || doc.input_dir.length === 0 || doc.input_dir.length > 1024)
        errors.push('input-dir-invalid');
    if (typeof doc.output_dir !== 'string' || doc.output_dir.length === 0 || doc.output_dir.length > 1024)
        errors.push('output-dir-invalid');
    if (!isPlainRecord(doc.budget)) {
        errors.push('budget-invalid');
    }
    else {
        const budget = doc.budget;
        for (const key of ['cpu_ms', 'memory_mb', 'processes', 'temp_bytes', 'output_bytes']) {
            if (!isPositiveSafeInteger(budget[key]))
                errors.push(`budget-${key}-invalid`);
        }
        for (const key of Object.keys(budget)) {
            if (!['cpu_ms', 'memory_mb', 'processes', 'temp_bytes', 'output_bytes'].includes(key))
                errors.push(`budget-unknown:${key}`);
        }
    }
    if (!isRfc3339Utc(doc.deadline))
        errors.push('deadline-invalid');
    if (!Array.isArray(doc.network_allowlist) || doc.network_allowlist.length > 128 ||
        doc.network_allowlist.some((item) => typeof item !== 'string' || item.length === 0 || item.length > 256)) {
        errors.push('network-allowlist-invalid');
    }
    if (typeof doc.required_level !== 'string' || !MARKET_ISOLATION_LEVELS.includes(doc.required_level))
        errors.push('required-level-not-market-grade');
    if (!isNonce(doc.cancel_token))
        errors.push('cancel-token-invalid');
    if (!isNonce(doc.nonce))
        errors.push('nonce-invalid');
    if (findSecretMaterial(request).length > 0)
        errors.push('secret-material-forbidden');
    return { ok: errors.length === 0, errors };
}
/**
 * Build the provider catalog for the observed host. The catalog is descriptive
 * and fail-closed: every candidate's `availability.available` is false unless an
 * explicit external environment record + transport were supplied.
 *
 * @param {{hostFacts?:HostFacts, external?:object, now?:()=>Date}} [options]
 * @returns {ReadonlyArray<IsolationProvider>}
 */
export function createProviderCatalog(options = {}) {
    const hostFacts = options.hostFacts ?? collectHostFacts();
    const external = isPlainRecord(options.external) ? options.external : {};
    const nativeBackend = options.nativeBackend ?? (isPlainRecord(external.nativeBackend) ? external.nativeBackend : null);
    const providers = SPECS.map((spec) => createCandidateProvider(spec, {
        hostFacts,
        availabilityRecord: external.availabilityRecord,
        a2Suite: external.a2Suite,
        transport: isPlainRecord(external.transport) ? external.transport : undefined,
        externalEnvironment: external.enabled === true,
        nativeBackend,
        now: options.now,
    }));
    return Object.freeze(providers);
}
/**
 * Capability-driven provider selection. L2 requirements accept an available L2
 * or L3 provider; L3 requirements accept only L3. L0/L1 and downgrades are
 * rejected explicitly (`isolation-level-downgrade-forbidden`).
 *
 * @param {{requiredLevel:'L2'|'L3', hostFacts?:HostFacts, catalog?:readonly IsolationProvider[], now?:()=>Date}} input
 * @returns {Readonly<ProviderSelection>}
 */
export function selectIsolationProvider(input) {
    const requiredLevel = input?.requiredLevel ?? 'L2';
    const now = typeof input?.now === 'function' ? input.now : () => new Date();
    const catalog = input?.catalog ?? createProviderCatalog({ hostFacts: input?.hostFacts, now });
    const candidates = catalog.map((provider) => ({
        provider_id: provider.provider_id,
        level: provider.level,
        available: provider.availability.available,
        reason_codes: [...provider.availability.reason_codes],
    }));
    if (!isMarketIsolationLevel(requiredLevel)) {
        return deepFreeze({
            schema_version: PROVIDER_SELECTION_SCHEMA_VERSION,
            status: 'blocked',
            required_level: String(requiredLevel),
            selected_provider: null,
            candidates,
            reason_codes: [ISOLATION_REASON.levelInsufficient, ISOLATION_REASON.downgradeForbidden],
            downgrade_forbidden: true,
            no_fallback: true,
            checked_at: now().toISOString(),
        });
    }
    const ranked = catalog.filter((provider) => isolationLevelRank(provider.level) >= isolationLevelRank(requiredLevel));
    const available = ranked.find((provider) => provider.availability.available) ?? null;
    const anyAtLevel = catalog.some((provider) => provider.level === requiredLevel);
    const reasonCodes = new Set();
    if (!anyAtLevel)
        reasonCodes.add(ISOLATION_REASON.levelInsufficient);
    if (!available) {
        reasonCodes.add(ISOLATION_REASON.providerMissing);
        for (const provider of ranked) {
            for (const reason of provider.availability.reason_codes) {
                if (reason !== ISOLATION_REASON.providerMissing)
                    reasonCodes.add(reason);
            }
        }
    }
    return deepFreeze({
        schema_version: PROVIDER_SELECTION_SCHEMA_VERSION,
        status: available ? 'available' : 'blocked',
        required_level: requiredLevel,
        selected_provider: available ? available.provider_id : null,
        candidates,
        reason_codes: available ? [] : [...reasonCodes],
        downgrade_forbidden: true,
        no_fallback: true,
        checked_at: now().toISOString(),
    });
}
/**
 * Test/extension hook: create a provider from an externally measured record.
 * This never fabricates availability; a missing/invalid record or a test double
 * yields an unavailable, explicitly non-market provider.
 *
 * @param {object} [input]
 * @returns {Readonly<IsolationProvider>}
 */
export function createExternalIsolationProvider(input = {}) {
    const providerId = input.provider_id;
    const spec = SPECS.find((candidate) => candidate.provider_id === providerId);
    if (!spec)
        throw new TypeError(`createExternalIsolationProvider: unknown provider_id ${String(providerId)}`);
    const hostFacts = input.hostFacts ?? collectHostFacts();
    const options = {
        hostFacts,
        availabilityRecord: input.test_double === true ? undefined : input.availabilityRecord,
        a2Suite: input.a2Suite,
        transport: input.transport,
        externalEnvironment: input.test_double !== true && input.externalEnvironment === true,
        nativeBackend: input.nativeBackend ?? null,
        now: input.now,
    };
    const provider = createCandidateProvider(spec, options);
    if (input.test_double === true) {
        return deepFreeze({
            ...provider,
            provenance: 'test-double',
            availability: {
                ...provider.availability,
                available: false,
                provenance: 'test-double',
                evidence: { ...provider.availability.evidence, grade: 'E0' },
                reason_codes: [...new Set([...provider.availability.reason_codes, ISOLATION_REASON.fixtureNotMarketEvidence])],
            },
        });
    }
    return provider;
}
/** All static candidate specs (frozen) for evidence/tests. */
export function candidateProviderSpecs() {
    return deepFreeze(SPECS.map((spec) => ({
        provider_id: spec.provider_id,
        level: spec.level,
        platform: spec.platform,
        mechanisms: [...spec.mechanisms],
        limitations: [...spec.limitations],
    })));
}
