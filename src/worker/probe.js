/**
 * Worker-side capability probe snapshot.
 *
 * This MVP does not load a PUT manifest or measure PUT capabilities. Therefore
 * it reports unknown observations, and never accepts declarations from caller
 * fields as artifact claims. Verification is derived by the control face and is
 * deliberately absent from worker records.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/worker/probe
 */
export const CAPABILITY_PROBE_VERSION = 'capability-probe/v1'
const SHA256 = /^sha256:[0-9a-f]{64}$/

function validDigest(value) {
  return typeof value === 'string' && SHA256.test(value) ? value : null
}

/**
 * Produce worker records keyed by test_id. Context is supplied by the control
 * plane; absent/invalid bindings are explicit nulls, never inferred from cases.
 *
 * @param {Array<{test_id:string}>} cases
 * @param {{put_digest?:string, probe_version?:string, environment_fingerprint?:string}} [context]
 * @returns {Record<string, {source:'worker', claim:'not-declared', observed:'unknown',
 *   probe_version:string, probe_time:string, environment_fingerprint:string|null,
 *   worker_fingerprint:null, put_digest:string|null, evidence_ref:null, limitations:string[]}>}
 */
export function probeCapabilities(cases, context = {}) {
  const result = {}
  if (!Array.isArray(cases)) return result

  const probeVersion = typeof context?.probe_version === 'string' && context.probe_version.length > 0
    ? context.probe_version
    : CAPABILITY_PROBE_VERSION
  const environmentFingerprint = validDigest(context?.environment_fingerprint)
  const putDigest = validDigest(context?.put_digest)
  const probeTime = new Date().toISOString()

  for (const caseSpec of cases) {
    const testId = caseSpec && typeof caseSpec.test_id === 'string' ? caseSpec.test_id : ''
    if (testId === '') continue // Validity/uniqueness is owned by compilePlanCandidate.

    const limitations = ['put-manifest-not-loaded-by-mvp', 'capability-not-measured-by-mvp-probe']
    if (environmentFingerprint === null) limitations.push('environment-fingerprint-unavailable')
    if (putDigest === null) limitations.push('put-digest-unavailable')

    Object.defineProperty(result, testId, { value: {
      test_id: testId,
      source: 'worker',
      claim: 'not-declared',
      observed: 'unknown',
      probe_version: probeVersion,
      probe_time: probeTime,
      environment_fingerprint: environmentFingerprint,
      worker_fingerprint: null,
      put_digest: putDigest,
      evidence_ref: null,
      limitations,
    }, enumerable: true, configurable: true, writable: true })
  }
  return result
}
