/**
 * 单元 · market-attestation/v1 构建与独立市场验证（node:test）。
 *
 * 覆盖 SIG-05..SIG-09 与 §6.5：attestation 绑定 receipt/eligibility/isolation/
 * runtime/anchor；签名输入只覆盖 anchor_N 而 entry N+1 只进入验证记录；开发
 * signer/archive 即使密码学签名有效也必须是 `invalid` + E1，不能发布；blocked
 * provider、篡改、缺失 entry、digest 错配全部 fail-closed。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  EVIDENCE_REASON_CODES,
  MARKET_ATTESTATION_V1_SCHEMA,
  validateMarketDocument,
} from '../../../src/protocol/market-schemas.js'
import { recordDigest } from '../../../src/protocol/digest.js'
import {
  createBlockedArchiveProvider,
  createBlockedSigningProvider,
  createDevelopmentArchiveProvider,
  createDevelopmentSigningProvider,
} from '../../../src/evidence/index.js'
import {
  buildMarketAttestation,
  classifyMarketEvidence,
  validateAttestationDraft,
  verifyAndClassify,
  verifyMarketAttestation,
  verifySavedVerificationRecord,
} from '../../../src/evidence/attestation.js'
import {
  canonicalDigest,
  marketAttestationDigest,
  validateAttestationVerification,
} from '../../../src/evidence/canonical.js'
import { evidenceManifestDigest } from '../../../src/evidence/sequence.js'
import { signMarketAttestation, validateVerificationRecord } from '../../../src/evidence/signing.js'
import {
  CONTROL_PLANE,
  DIGEST,
  FIXED_TIME,
  ISOLATION_REF,
  POLICY_REF,
  RUNTIME_REF,
  makeEligibility,
  makeValidReceipt,
} from './_fixtures.js'

const AUTHORIZED = Object.freeze([{
  control_plane_id: 'control-plane-development',
  authorization_ref: 'auth-ref-1',
}])

async function buildFixture(root) {
  const archive = createDevelopmentArchiveProvider({
    dir: join(root, 'archive'),
    archiveId: 'run-evidence-001',
  })
  const signer = createDevelopmentSigningProvider({
    authorizedRequesters: [...AUTHORIZED],
    now: () => new Date(FIXED_TIME),
  })
  const receipt = makeValidReceipt()
  const receiptDigest = recordDigest(receipt)
  const subject = await archive.append({
    receipt_digest: receiptDigest,
    isolation_attestation_digest: ISOLATION_REF.attestation_digest,
    policy_digest: POLICY_REF.digest,
    approval_digests: [DIGEST('c')],
    attestation_digest: null,
    eligibility_digest: null,
  })
  assert.equal(subject.status, 'appended')
  const manifestDigest = evidenceManifestDigest({
    receiptDigest,
    isolationAttestationDigest: ISOLATION_REF.attestation_digest,
    isolationVerificationDigest: ISOLATION_REF.verification_digest,
    policyDigest: POLICY_REF.digest,
    approvalDigests: [DIGEST('c')],
    archiveAnchorDigest: canonicalDigest(subject.anchor),
  })
  const eligibility = makeEligibility({ manifestDigest })
  const eligibilityDigest = canonicalDigest(eligibility)
  const keyId = signer.activeKeyIds()[0]
  const draft = buildMarketAttestation({
    attestationId: 'attestation-fixture-001',
    receipt,
    receiptDigest,
    eligibility,
    eligibilityDigest,
    expectedManifestDigest: manifestDigest,
    controlPlane: CONTROL_PLANE,
    isolation: ISOLATION_REF,
    runtime: RUNTIME_REF,
    subjectAnchor: subject.anchor,
    signing: {
      provider_id: signer.describe().provider_id,
      key_id: keyId,
      alg: 'ed25519',
      signed_at: FIXED_TIME,
      provider_audit_ref: 'audit:attestation-1',
    },
    limitations: ['controlled-fixture'],
  })
  const signed = await signMarketAttestation({
    attestation: draft,
    signingProvider: signer,
    requester: AUTHORIZED[0],
    requestId: 'request-attestation-1',
  })
  assert.equal(signed.status, 'signed', JSON.stringify(signed))
  const attestation = signed.attestation
  const attestationEntry = await archive.append({
    receipt_digest: receiptDigest,
    isolation_attestation_digest: null,
    policy_digest: null,
    approval_digests: [],
    attestation_digest: marketAttestationDigest(attestation),
    eligibility_digest: eligibilityDigest,
  })
  assert.equal(attestationEntry.status, 'appended')
  const entries = [archive.get(1).entry, archive.get(2).entry]
  return {
    archive,
    signer,
    receipt,
    receiptDigest,
    subject,
    subjectAnchor: subject.anchor,
    eligibility,
    eligibilityDigest,
    draft,
    signed,
    attestation,
    entries,
    attestationEntry,
    pinnedSigner: signer.describe(),
    pinnedArchive: archive.describe(),
  }
}

function verifyInput(fixture, overrides = {}) {
  return {
    attestation: fixture.attestation,
    pinnedSigningProvider: fixture.pinnedSigner,
    pinnedArchiveProvider: fixture.pinnedArchive,
    archiveEntries: fixture.entries,
    expectedReceiptDigest: fixture.receiptDigest,
    expectedEligibilityDigest: fixture.eligibilityDigest,
    expectedSubjectAnchor: fixture.subjectAnchor,
    verificationId: 'verify:attestation-fixture-001',
    verifiedBy: 'independent-verifier',
    verifiedAt: '2026-01-01T00:00:10.000Z',
    ...overrides,
  }
}

async function withTempDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-evidence-attestation-'))
  try {
    return await fn(dir)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

test('attestation: 构建绑定 receipt/eligibility/isolation/runtime/anchor_N', async () => {
  await withTempDir(async (root) => {
    const fixture = await buildFixture(root)
    const attestation = fixture.attestation
    assert.equal(validateMarketDocument(attestation, MARKET_ATTESTATION_V1_SCHEMA).ok, true)
    assert.equal(attestation.schema_version, 'market-attestation/v1')
    assert.equal(attestation.subject.receipt_schema_version, 'receipt/v1')
    assert.equal(attestation.subject.record_digest, fixture.receiptDigest)
    assert.equal(attestation.eligibility.schema_version, 'market-eligibility/v1')
    assert.equal(attestation.eligibility.decision_digest, fixture.eligibilityDigest)
    assert.equal(attestation.archive.sequence, fixture.subjectAnchor.sequence)
    assert.equal(attestation.archive.entry_digest, fixture.subjectAnchor.entry_digest)
    assert.equal(attestation.archive.anchor_id, fixture.subjectAnchor.anchor_id)
    assert.equal(attestation.signing.signature, fixture.signed.response.signature)
    assert.equal(attestation.runtime.cordis_version, '4.0.5')
    assert.equal(fixture.attestationEntry.entry.attestation_digest, marketAttestationDigest(attestation))
  })
})

test('attestation: 构建拒绝非法 receipt / non-eligible / digest 错配 / anchor 错配', () => {
  const receipt = makeValidReceipt()
  const receiptDigest = recordDigest(receipt)
  const eligibility = makeEligibility({ manifestDigest: DIGEST('b') })
  const anchor = {
    schema_version: 'archive-anchor/v1',
    anchor_id: `x:1:${DIGEST('1')}`,
    provider_id: 'development-archive-local-file',
    archive_id: 'run-evidence-001',
    sequence: 1,
    entry_digest: DIGEST('1'),
    previous_entry_digest: null,
    receipt_digest: receiptDigest,
    archived_at: FIXED_TIME,
    trust_anchor: { type: 'none-development-only', key_id: null, verification_ref: null },
    trusted_time: { source: 'host-clock-development-only', verified: false, reference: null },
    provider_audit_ref: 'dev-audit:1',
  }
  const base = {
    attestationId: 'attestation-fixture-002',
    receipt,
    receiptDigest,
    eligibility,
    controlPlane: CONTROL_PLANE,
    isolation: ISOLATION_REF,
    runtime: RUNTIME_REF,
    subjectAnchor: anchor,
    signing: {
      provider_id: 'development-signer',
      key_id: 'key-ed25519-fixture',
      alg: 'ed25519',
      signed_at: FIXED_TIME,
      provider_audit_ref: 'audit:x',
    },
  }
  assert.equal(buildMarketAttestation(base).subject.record_digest, receiptDigest)

  assert.throws(() => buildMarketAttestation({ ...base, receipt: { ...receipt, integrity: { ...receipt.integrity, record_digest: DIGEST('0') } } }))
  assert.throws(() => buildMarketAttestation({ ...base, eligibility: { ...eligibility, decision: 'non-eligible' } }))
  assert.throws(() => buildMarketAttestation({ ...base, eligibilityDigest: DIGEST('0') }))
  assert.throws(() => buildMarketAttestation({ ...base, expectedManifestDigest: DIGEST('0') }))
  assert.throws(() => buildMarketAttestation({ ...base, subjectAnchor: { ...anchor, receipt_digest: DIGEST('0') } }))
  assert.throws(() => buildMarketAttestation({
    ...base,
    subjectAnchor: { ...anchor, schema_version: 'archive-anchor/v2' },
  }))
  const validDraft = buildMarketAttestation(base)
  const signedDraft = validateAttestationDraft({
    ...validDraft,
    signing: { ...validDraft.signing, signature: 'c2ln' },
  })
  assert.equal(signedDraft.ok, false)
})

test('attestation: 开发 provider 即使在密码学上验证通过也必须是 invalid + E1（不得发布）', async () => {
  await withTempDir(async (root) => {
    const fixture = await buildFixture(root)
    const result = verifyMarketAttestation(verifyInput(fixture))
    const verification = result.verification
    assert.equal(verification.signature_verified, true)
    assert.equal(verification.archive_chain_verified, true)
    assert.equal(verification.result, 'invalid')
    assert.equal(result.evidence_class, 'E1')
    assert.equal(result.market_eligible, false)
    assert.ok(verification.reason_codes.includes(EVIDENCE_REASON_CODES.DEVELOPMENT_ONLY_NOT_MARKET))
    assert.ok(verification.reason_codes.includes(EVIDENCE_REASON_CODES.TRUSTED_TIME_UNAVAILABLE))
    assert.ok(verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_UNTRUSTED))
    assert.equal(verification.checks.find((entry) => entry.id === 'entry-trusted-time').status, 'fail')
    assert.equal(verification.attestation_digest, marketAttestationDigest(fixture.attestation))
    assert.equal(verification.attestation_archive_entry_digest, fixture.attestationEntry.entry.entry_digest)
    assert.equal(verification.checks.every((entry) => entry.status === 'pass' || entry.reason_code !== null), true)
    assert.equal(validateAttestationVerification(verification).ok, true, JSON.stringify(validateAttestationVerification(verification).errors))
    assert.equal(validateVerificationRecord(verification).ok, true)

    const combined = verifyAndClassify(verifyInput(fixture))
    assert.equal(combined.market_eligible, false)
  })
})

test('attestation: 签名后篡改任一被签字段 → 签名验证失败', async () => {
  await withTempDir(async (root) => {
    const fixture = await buildFixture(root)
    for (const mutate of [
      (copy) => { copy.isolation.level = 'L3' },
      (copy) => { copy.archive.entry_digest = DIGEST('0') },
      (copy) => { copy.subject.record_digest = DIGEST('0') },
      (copy) => { copy.signing.provider_audit_ref = 'audit:other' },
    ]) {
      const tampered = structuredClone(fixture.attestation)
      mutate(tampered)
      const result = verifyMarketAttestation(verifyInput(fixture, { attestation: tampered }))
      assert.equal(result.verification.result, 'invalid')
      assert.equal(result.verification.signature_verified, false)
      assert.ok(result.verification.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNATURE_VERIFICATION_FAILED))
    }
  })
})

test('attestation: 错误 pinned key / 缺失 entry N+1 / 链篡改 / digest 错配全部 invalid', async () => {
  await withTempDir(async (root) => {
    const fixture = await buildFixture(root)

    const otherSigner = createDevelopmentSigningProvider({
      authorizedRequesters: [...AUTHORIZED],
      now: () => new Date(FIXED_TIME),
    })
    const wrongKey = verifyMarketAttestation(verifyInput(fixture, {
      pinnedSigningProvider: otherSigner.describe(),
    }))
    assert.equal(wrongKey.verification.result, 'invalid')
    assert.ok(wrongKey.verification.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_KEY_UNKNOWN))

    const missingEntry = verifyMarketAttestation(verifyInput(fixture, {
      archiveEntries: [fixture.entries[0]],
    }))
    assert.equal(missingEntry.verification.archive_chain_verified, false)
    assert.equal(missingEntry.verification.result, 'invalid')
    assert.ok(missingEntry.verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISSING))

    const tamperedEntries = structuredClone(fixture.entries)
    tamperedEntries[0].receipt_digest = DIGEST('0')
    const tamperedChain = verifyMarketAttestation(verifyInput(fixture, {
      archiveEntries: tamperedEntries,
    }))
    assert.equal(tamperedChain.verification.result, 'invalid')
    assert.ok(tamperedChain.verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED))

    const wrongReceipt = verifyMarketAttestation(verifyInput(fixture, {
      expectedReceiptDigest: DIGEST('0'),
    }))
    assert.equal(wrongReceipt.verification.result, 'invalid')

    const wrongEligibility = verifyMarketAttestation(verifyInput(fixture, {
      expectedEligibilityDigest: DIGEST('0'),
    }))
    assert.equal(wrongEligibility.verification.result, 'invalid')

    const wrongAnchor = verifyMarketAttestation(verifyInput(fixture, {
      expectedSubjectAnchor: { ...fixture.subjectAnchor, entry_digest: DIGEST('0') },
    }))
    assert.equal(wrongAnchor.verification.result, 'invalid')
  })
})

test('attestation: blocked KMS/归档 provider 只能得到 invalid + blocked 证据等级', async () => {
  await withTempDir(async (root) => {
    const fixture = await buildFixture(root)
    const blocked = verifyMarketAttestation(verifyInput(fixture, {
      pinnedSigningProvider: createBlockedSigningProvider().describe(),
      pinnedArchiveProvider: createBlockedArchiveProvider().describe(),
    }))
    assert.equal(blocked.verification.result, 'invalid')
    assert.equal(blocked.evidence_class, 'blocked')
    assert.equal(blocked.market_eligible, false)
    assert.ok(blocked.verification.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_PROVIDER_MISSING))
    assert.ok(blocked.verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_MISSING))
  })
})

test('attestation: evidence 分级 — 开发= E1，unavailable=blocked，且永不 market_eligible', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-classify-'))
  try {
    const dev = classifyMarketEvidence({
      signingProvider: createDevelopmentSigningProvider().describe(),
      archiveProvider: createDevelopmentArchiveProvider({
        dir: join(root, 'archive'),
        archiveId: 'classify',
      }).describe(),
      verificationValid: true,
    })
    assert.equal(dev.evidence_class, 'E1')
    assert.equal(dev.market_eligible, false)
    assert.ok(dev.reason_codes.includes(EVIDENCE_REASON_CODES.DEVELOPMENT_ONLY_NOT_MARKET))

    const blocked = classifyMarketEvidence({
      signingProvider: createBlockedSigningProvider().describe(),
      archiveProvider: createBlockedArchiveProvider().describe(),
      verificationValid: true,
    })
    assert.equal(blocked.evidence_class, 'blocked')
    assert.equal(blocked.market_eligible, false)

    // Missing providers cannot be classified as trusted either.
    const missing = classifyMarketEvidence({ verificationValid: true })
    assert.equal(missing.market_eligible, false)
    assert.notEqual(missing.evidence_class, 'E3')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('attestation: 独立验证可强制校验归档 provider 签名/MAC', async () => {
  await withTempDir(async (root) => {
    const fixture = await buildFixture(root)
    const withProviderSignature = verifyMarketAttestation(verifyInput(fixture, {
      verifyArchiveProviderSignature: fixture.archive.verifyEntrySignature,
    }))
    assert.equal(withProviderSignature.verification.archive_chain_verified, true)
    assert.equal(withProviderSignature.verification.result, 'invalid', 'dev archive still never market')

    const forgedProviderSignature = verifyMarketAttestation(verifyInput(fixture, {
      verifyArchiveProviderSignature: () => false,
    }))
    assert.equal(forgedProviderSignature.verification.archive_chain_verified, false)
    assert.ok(forgedProviderSignature.verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED))
  })
})

test('attestation: 已保存 verification 记录需与 attestation digest 绑定', async () => {
  await withTempDir(async (root) => {
    const fixture = await buildFixture(root)
    const verification = verifyMarketAttestation(verifyInput(fixture)).verification
    assert.equal(verifySavedVerificationRecord(verification, fixture.attestation).ok, true)

    const tampered = structuredClone(verification)
    tampered.result = 'valid'
    assert.equal(verifySavedVerificationRecord(tampered, fixture.attestation).ok, false)

    const digestMismatch = structuredClone(verification)
    digestMismatch.attestation_digest = DIGEST('0')
    assert.equal(verifySavedVerificationRecord(digestMismatch, fixture.attestation).ok, false)
  })
})

test('attestation: verification 记录不允许 valid 但含失败 check 或 reason code', async () => {
  await withTempDir(async (root) => {
    const fixture = await buildFixture(root)
    const verification = verifyMarketAttestation(verifyInput(fixture)).verification
    const inconsistent = {
      ...structuredClone(verification),
      result: 'valid',
      signature_verified: true,
      archive_chain_verified: true,
      reason_codes: ['development-only-not-market-evidence'],
      checks: [{ id: 'x', status: 'fail', reason_code: 'x', evidence_ref: null }],
    }
    assert.equal(validateVerificationRecord(inconsistent).ok, false)
  })
})
