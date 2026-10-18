/**
 * Isolation evidence intake for the market gate (MKT-C01/MKT-C02, L2/L3).
 *
 * The gate never re-implements isolation measurement: it feeds recorded facts
 * into the t4 admission evaluator (`evaluateIsolationAdmission`) and copies the
 * resulting blocked/admitted verdict. A worker self-report, a missing provider,
 * a partial A2 suite, an expired attestation or the High-IL harness session all
 * stay blocked; no fallback to L1 is attempted.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/market/isolation
 */
import { evaluateIsolationAdmission } from '../isolation/admission.js';
import { createNonceRegistry } from '../isolation/attestation.js';
import { asRecord, canonicalDigest, isArray, isNonEmptyString } from './util.js';
/**
 * Accept either a raw `isolation-attestation/v1` object or the t4
 * `windows-l2-execution-evidence/v1` container (`{attestation:{attestation:…}}`).
 * The container is only a transport; the inner attestation is still verified.
 */
export function normalizeAttestationInput(value) {
    const record = asRecord(value);
    if (!record)
        return { attestation: null, executionEvidence: null };
    if (record.schema_version === 'isolation-attestation/v1') {
        return { attestation: record, executionEvidence: null };
    }
    const wrapper = asRecord(record.attestation);
    const inner = asRecord(wrapper?.attestation);
    if (inner && inner.schema_version === 'isolation-attestation/v1') {
        return { attestation: inner, executionEvidence: record };
    }
    return { attestation: null, executionEvidence: null };
}
function blocked(reasonCodes, detail, extra = {}) {
    return {
        status: 'blocked',
        reasonCodes: [...new Set(reasonCodes)],
        requiredLevel: null,
        achievedLevel: null,
        attestationDigest: null,
        verificationDigest: null,
        attestation: null,
        admission: null,
        evidenceRefs: [],
        limitations: [],
        ...extra,
    };
}
/**
 * Evaluate the isolation input. The returned record is the market gate's
 * `C01/C02` source; `status=admitted` only means the isolation *input* passed.
 */
export function assessIsolation(options) {
    const normalized = normalizeAttestationInput(options.attestation);
    const limitations = [];
    const evidence = normalized.executionEvidence;
    if (evidence) {
        limitations.push('t4-execution-evidence-container-unwrapped');
        const a2Summary = asRecord(evidence.a2);
        if (a2Summary && a2Summary.evaluation_result === 'blocked') {
            limitations.push('t4-recorded-a2-evaluation-blocked');
        }
        if (isArray(evidence.residual_risks)) {
            for (const risk of evidence.residual_risks) {
                if (isNonEmptyString(risk))
                    limitations.push(`t4-residual-risk:${risk.slice(0, 160)}`);
            }
        }
    }
    const attestation = normalized.attestation;
    if (attestation === null) {
        return blocked(['isolation-attestation-missing'], 'no isolation-attestation/v1 supplied', {
            requiredLevel: options.policy.requiredIsolation,
            limitations,
        });
    }
    const attestationDigest = canonicalDigest(attestation);
    const provider = asRecord(options.provider);
    const hostFacts = asRecord(options.hostFacts);
    if (provider === null) {
        return blocked(['isolation-provider-missing'], 'no measured isolation provider supplied', {
            requiredLevel: options.policy.requiredIsolation,
            attestationDigest,
            attestation,
            limitations: [...limitations, 'no-external-provider-availability-record'],
        });
    }
    if (hostFacts === null) {
        return blocked(['worker-identity-not-low-privilege'], 'no measured host facts supplied', {
            requiredLevel: options.policy.requiredIsolation,
            attestationDigest,
            attestation,
            limitations,
        });
    }
    const a2Evidence = options.a2Evidence;
    if (a2Evidence === undefined || a2Evidence === null) {
        limitations.push('no-a2-suite-evidence-supplied');
    }
    const input = {
        required_level: options.policy.requiredIsolation,
        provider: provider,
        host_facts: hostFacts,
        policy: options.policy.raw,
        attestation,
        a2_evidence: a2Evidence,
        attestation_expected: {
            run_id: options.runId ?? undefined,
            plan_id: options.planId ?? undefined,
            // test_id/attempt are echoed from the recorded measurement; the external
            // bindings (run, plan, launcher, provider, policy) come from the receipt
            // and frozen policy.
            test_id: typeof attestation.test_id === 'string' ? attestation.test_id : undefined,
            attempt: typeof attestation.attempt === 'number' ? attestation.attempt : undefined,
            required_level: options.policy.requiredIsolation,
            policy_version: 'market-gate-policy/v1',
            policy_digest: options.policy.digest,
            max_age_ms: options.policy.maxAttestationAgeMs,
            denied_roots: options.policy.deniedRoots,
            network_allowlist: options.policy.networkAllowlist,
            limits: options.policy.isolationLimits,
        },
        nonce_registry: createNonceRegistry({ now: () => options.nowMs }),
        now: new Date(options.nowMs),
        verified_by: 'market-gate/1.0.0',
    };
    const admission = evaluateIsolationAdmission(input);
    const reasonCodes = isArray(admission.reason_codes)
        ? admission.reason_codes.filter(isNonEmptyString)
        : [];
    const verification = asRecord(admission.verification);
    const evidenceRefs = isArray(admission.evidence_refs)
        ? admission.evidence_refs.filter(isNonEmptyString)
        : [];
    const achievedLevel = typeof admission.achieved_level === 'string' ? admission.achieved_level : null;
    const status = admission.result === 'admitted' ? 'admitted' : 'blocked';
    return {
        status,
        reasonCodes: [...reasonCodes],
        requiredLevel: options.policy.requiredIsolation,
        achievedLevel,
        attestationDigest,
        verificationDigest: verification ? canonicalDigest(verification) : null,
        attestation,
        admission,
        evidenceRefs: [...evidenceRefs, `attestation:${attestationDigest}`],
        limitations,
    };
}
