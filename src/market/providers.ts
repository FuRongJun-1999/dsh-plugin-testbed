/**
 * Signing/archive provider assessment for the market gate (MKT-C05/MKT-C06).
 *
 * The gate never creates or trusts a signer/archive by itself: it consumes the
 * provider declarations from `src/evidence`, verifies their trust class against
 * the frozen policy allowlists, and refuses development-only or unavailable
 * providers. In this environment the default factories are blocked, so C05/C06
 * stay failed and no market evidence is ever signed or archived.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/market/providers
 */

import {
  archiveProviderTrustIssues,
  createBlockedArchiveProvider,
  createBlockedSigningProvider,
  signingProviderTrustIssues,
} from '../evidence/index.js'
import type {
  ArchiveProviderLike,
  SigningProviderLike,
} from '../evidence/types.js'
import type { MarketPolicyView, ProviderAssessment, UnknownRecord } from './types.js'
import { asRecord, isArray, isNonEmptyString } from './util.js'

export interface ProviderAssessmentOptions {
  policy: MarketPolicyView
  signingProvider?: unknown
  archiveProvider?: unknown
}

function reasonList(result: unknown): string[] {
  const record = asRecord(result)
  const codes = record !== null && isArray(record.reason_codes) ? record.reason_codes : []
  return codes.filter(isNonEmptyString)
}

function errorList(result: unknown): string[] {
  const record = asRecord(result)
  const values = record !== null && isArray(record.errors) ? record.errors : []
  return values.filter(isNonEmptyString)
}

/**
 * Assess the injected/default signing + archive providers against the policy.
 * The functions are called for their declarations only; no signing/charging
 * happens here.
 */
export async function assessProviders(options: ProviderAssessmentOptions): Promise<ProviderAssessment> {
  const signingProvider = (options.signingProvider ?? createBlockedSigningProvider()) as SigningProviderLike
  const archiveProvider = (options.archiveProvider ?? createBlockedArchiveProvider()) as ArchiveProviderLike
  const limitations: string[] = []

  let signingDoc: UnknownRecord | null = null
  let archiveDoc: UnknownRecord | null = null
  try {
    const described = await signingProvider.describe()
    signingDoc = asRecord(described)
  } catch {
    limitations.push('signing-provider-describe-failed')
  }
  try {
    const described = await archiveProvider.describe()
    archiveDoc = asRecord(described)
  } catch {
    limitations.push('archive-provider-describe-failed')
  }

  const signingIssues = signingDoc === null
    ? { ok: false, reason_codes: ['signing-provider-missing'], errors: ['no-signing-provider'] }
    : signingProviderTrustIssues(signingDoc)
  const archiveIssues = archiveDoc === null
    ? { ok: false, reason_codes: ['archive-provider-missing'], errors: ['no-archive-provider'] }
    : archiveProviderTrustIssues(archiveDoc)

  const signingReasons = new Set<string>(reasonList(signingIssues))
  const archiveReasons = new Set<string>(reasonList(archiveIssues))

  let signingKeyId: string | null = null
  let signingAlg: string | null = null
  if (signingDoc !== null) {
    const keys = isArray(signingDoc.keys) ? signingDoc.keys : []
    const allowed = options.policy.allowedSigners.filter((signer) => signer.state === 'active')
    for (const rawKey of keys) {
      const key = asRecord(rawKey)
      if (key === null || !isNonEmptyString(key.key_id) || !isNonEmptyString(key.alg)) continue
      if (key.state !== 'active') continue
      const policySigner = allowed.find((signer) => signer.key_id === key.key_id && signer.alg === key.alg)
      if (policySigner === undefined) continue
      signingKeyId = key.key_id
      signingAlg = key.alg
      break
    }
    if (signingKeyId === null) {
      signingReasons.add('signing-key-unknown')
      signingReasons.add('signing-provider-untrusted')
    }
  }
  if (signingDoc !== null && signingDoc.availability !== 'available') {
    signingReasons.add('signing-provider-missing')
  }

  const archiveMode = asRecord(archiveDoc)?.mode
  const archiveProviderId = asRecord(archiveDoc)?.provider_id
  if (archiveDoc !== null) {
    if (typeof archiveMode !== 'string' ||
        !options.policy.allowedArchives.some((archive) =>
          archive.provider_id === archiveProviderId && archive.mode === archiveMode)) {
      archiveReasons.add('archive-mode-not-immutable')
      archiveReasons.add('archive-provider-untrusted')
    }
    const trustedTime = asRecord(archiveDoc.trusted_time)
    if (trustedTime === null || trustedTime.verified !== true) {
      archiveReasons.add('trusted-time-unavailable')
    }
    if (archiveDoc.availability !== 'available') archiveReasons.add('archive-provider-missing')
  }

  const signingTrusted = signingDoc !== null && signingDoc.trust_class === 'market-independent' &&
    signingDoc.availability === 'available' && signingKeyId !== null &&
    reasonList(signingIssues).length === 0
  const archiveTrusted = archiveDoc !== null && archiveDoc.trust_class === 'market-independent' &&
    archiveDoc.availability === 'available' && archiveReasons.size === 0

  return {
    signingProviderDoc: signingDoc,
    archiveProviderDoc: archiveDoc,
    signingTrusted,
    archiveTrusted,
    signingKeyId,
    signingAlg,
    signingReasonCodes: [...signingReasons],
    archiveReasonCodes: [...archiveReasons],
    signingLimitations: [
      ...limitations.filter((item) => item.startsWith('signing-provider')),
      ...errorList(signingIssues),
    ],
    archiveLimitations: [
      ...limitations.filter((item) => item.startsWith('archive-provider')),
      ...errorList(archiveIssues),
    ],
  }
}
