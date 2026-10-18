/**
 * 单元 · SIG-08 固定顺序与 fail-closed 序列（node:test）。
 *
 * 验证严格顺序：receipt 严格校验 → entry N（receipt/isolation/policy/approvals）
 * → eligibility（拿到 anchor_N）→ attestation 构建 → 签名 → entry N+1 →
 * 独立验证。非 eligible 绝不签名；签名/归档失败绝不产生 entry N+1；开发
 * provider 的完整链路最终只能是 non-eligible/blocked，不能 publish。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  EVIDENCE_REASON_CODES,
} from '../../../src/protocol/market-schemas.js'
import { recordDigest } from '../../../src/protocol/digest.js'
import {
  EVIDENCE_SEQUENCE_STAGES,
  runMarketEvidenceSequence,
} from '../../../src/evidence/sequence.js'
import {
  createBlockedArchiveProvider,
  createBlockedSigningProvider,
  createBlockedTrustedTimeProvider,
  createDevelopmentArchiveProvider,
  createDevelopmentSigningProvider,
} from '../../../src/evidence/index.js'
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

async function withTempDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-evidence-sequence-'))
  try {
    return await fn(dir)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

function makeProviders(root, archiveOverrides = {}) {
  const archive = createDevelopmentArchiveProvider({
    dir: join(root, 'archive'),
    archiveId: 'run-evidence-001',
    ...archiveOverrides,
  })
  const signer = createDevelopmentSigningProvider({
    authorizedRequesters: [...AUTHORIZED],
    now: () => new Date(FIXED_TIME),
  })
  return { archive, signer }
}

function baseOptions({ archive, signer, events = [] }) {
  const receipt = makeValidReceipt()
  const keyId = typeof signer.activeKeyIds === 'function' ? signer.activeKeyIds()[0] : 'key-blocked'
  return {
    receipt,
    isolation: ISOLATION_REF,
    policy: POLICY_REF,
    approvalDigests: [DIGEST('c')],
    controlPlane: CONTROL_PLANE,
    runtime: RUNTIME_REF,
    archiveProvider: archive,
    signingProvider: signer,
    computeEligibility: async (input) => {
      events.push({
        event: 'eligibility',
        anchorSequence: input.subjectAnchor.sequence,
        anchorDigest: input.subjectAnchor.entry_digest,
        subjectEntrySequence: input.subjectEntry.sequence,
      })
      return makeEligibility({ manifestDigest: input.evidenceManifestDigest })
    },
    requester: AUTHORIZED[0],
    attestationId: 'attestation-sequence-001',
    requestId: 'request-sequence-001',
    signing: {
      key_id: keyId,
      alg: 'ed25519',
      signed_at: FIXED_TIME,
      provider_audit_ref: 'audit:sequence-1',
    },
    verifier: { id: 'qa-independent', verifiedAt: '2026-01-01T00:00:10.000Z' },
  }
}

test('sequence: 开发 provider 全链路按固定顺序执行，但结果 non-eligible 且不可发布', async () => {
  await withTempDir(async (root) => {
    const { archive, signer } = makeProviders(root)
    const events = []
    const options = baseOptions({ archive, signer, events })
    const receiptBefore = JSON.stringify(options.receipt)
    const result = await runMarketEvidenceSequence(options)

    assert.deepEqual(result.steps, [...EVIDENCE_SEQUENCE_STAGES])
    assert.equal(result.status, 'non-eligible')
    assert.equal(result.market_eligible, false)
    assert.equal(result.publish, false)
    assert.equal(result.evidence_class, 'E1')
    assert.equal(result.failure_stage, 'verification')
    assert.ok(result.reason_codes.includes(EVIDENCE_REASON_CODES.DEVELOPMENT_ONLY_NOT_MARKET))
    assert.ok(result.reason_codes.includes(EVIDENCE_REASON_CODES.TRUSTED_TIME_UNAVAILABLE))

    // eligibility was computed only after entry N existed (anchor_N input).
    assert.equal(events.length, 1)
    assert.equal(events[0].anchorSequence, 1)
    assert.equal(events[0].anchorDigest, result.subject_anchor.entry_digest)
    assert.equal(events[0].subjectEntrySequence, 1)

    // attestation binds anchor_N; entry N+1 chains to it.
    assert.equal(result.attestation.archive.sequence, 1)
    assert.equal(result.attestation.archive.entry_digest, result.subject_anchor.entry_digest)
    assert.equal(result.attestation_anchor.sequence, 2)
    assert.equal(result.attestation_anchor.previous_entry_digest, result.subject_anchor.entry_digest)
    assert.equal(result.attestation_digest, result.verification.attestation_digest)
    assert.equal(result.verification.attestation_archive_entry_digest, result.attestation_anchor.entry_digest)
    assert.equal(archive.head().sequence, 2)
    assert.equal(archive.get(2).entry.attestation_digest, result.attestation_digest)
    assert.equal(archive.get(2).entry.eligibility_digest, result.eligibility_digest)

    // receipt/v1 was never rewritten.
    assert.equal(JSON.stringify(options.receipt), receiptBefore)
    assert.equal(recordDigest(options.receipt), result.receipt_digest)

    const chain = await archive.verifyChain({ requireAttestationPair: true })
    assert.equal(chain.status, 'valid')
    const audit = signer.audit()
    assert.equal(audit.entries.length, 1)
    assert.equal(audit.entries[0].provider_audit_ref, 'audit:sequence-1')
  })
})

test('sequence: eligibility non-eligible 时绝不签名、绝不产生 entry N+1', async () => {
  await withTempDir(async (root) => {
    const { archive, signer } = makeProviders(root)
    const options = baseOptions({ archive, signer })
    options.computeEligibility = async (input) => makeEligibility({
      manifestDigest: input.evidenceManifestDigest,
      decision: 'non-eligible',
      reasonCodes: ['isolation-provider-missing'],
    })
    const result = await runMarketEvidenceSequence(options)

    assert.equal(result.status, 'non-eligible')
    assert.equal(result.failure_stage, 'eligibility')
    assert.deepEqual(result.steps, ['receipt-validation', 'archive-subject', 'eligibility'])
    assert.equal(result.attestation, undefined)
    assert.equal(archive.head().sequence, 1)
    assert.equal(signer.audit().entries.length, 0)
    assert.ok(result.reason_codes.includes('isolation-provider-missing'))
  })
})

test('sequence: 签名 provider blocked 时停在 sign，entry N+1 不存在', async () => {
  await withTempDir(async (root) => {
    const { archive } = makeProviders(root)
    const blockedSigner = createBlockedSigningProvider()
    const options = baseOptions({ archive, signer: blockedSigner })
    options.signing = {
      key_id: 'key-unknown',
      alg: 'ed25519',
      signed_at: FIXED_TIME,
      provider_audit_ref: 'audit:blocked',
    }
    const result = await runMarketEvidenceSequence(options)

    assert.equal(result.status, 'blocked')
    assert.equal(result.failure_stage, 'sign')
    assert.equal(result.publish, false)
    assert.deepEqual(result.steps, [
      'receipt-validation', 'archive-subject', 'eligibility', 'attestation-build',
    ])
    assert.equal(result.attestation_entry_absent, true)
    assert.ok(result.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_PROVIDER_MISSING))
    assert.equal(archive.head().sequence, 1, 'no entry N+1 after signing failure')
  })
})

test('sequence: 归档 provider blocked 时停在 archive-subject，未进入 eligibility/sign', async () => {
  let eligibilityCalls = 0
  const options = {
    receipt: makeValidReceipt(),
    isolation: ISOLATION_REF,
    policy: POLICY_REF,
    controlPlane: CONTROL_PLANE,
    runtime: RUNTIME_REF,
    archiveProvider: createBlockedArchiveProvider(),
    signingProvider: createDevelopmentSigningProvider({
      authorizedRequesters: [...AUTHORIZED],
      now: () => new Date(FIXED_TIME),
    }),
    computeEligibility: async () => {
      eligibilityCalls += 1
      return makeEligibility({ manifestDigest: DIGEST('b') })
    },
    requester: AUTHORIZED[0],
    attestationId: 'attestation-blocked-archive',
    requestId: 'request-blocked-archive',
    signing: {
      key_id: 'key-unknown',
      alg: 'ed25519',
      signed_at: FIXED_TIME,
      provider_audit_ref: 'audit:blocked-archive',
    },
    verifier: { id: 'qa-independent' },
  }
  const result = await runMarketEvidenceSequence(options)
  assert.equal(result.status, 'blocked')
  assert.equal(result.failure_stage, 'archive-subject')
  assert.deepEqual(result.steps, ['receipt-validation'])
  assert.equal(eligibilityCalls, 0)
  assert.ok(result.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_MISSING))
})

test('sequence: entry N+1 append 失败时不发布，已签名 attestation 不被当作最终证据', async () => {
  await withTempDir(async (root) => {
    const { archive, signer } = makeProviders(root)
    let attestationAppendAttempts = 0
    const failingArchive = {
      ...archive,
      append: async (draft) => {
        if (draft.attestation_digest !== null) {
          attestationAppendAttempts += 1
          return {
            status: 'blocked',
            reason_codes: [EVIDENCE_REASON_CODES.ARCHIVE_APPEND_FAILED],
            detail: 'archive-unavailable-after-subject',
          }
        }
        return archive.append(draft)
      },
    }
    const result = await runMarketEvidenceSequence(baseOptions({ archive: failingArchive, signer }))
    assert.equal(result.status, 'blocked')
    assert.equal(result.failure_stage, 'archive-attestation')
    assert.equal(result.publish, false)
    assert.equal(attestationAppendAttempts, 1)
    assert.ok(result.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_APPEND_FAILED))
    assert.ok(result.attestation !== undefined)
    assert.equal(archive.head().sequence, 1)
  })
})

test('sequence: eligibility 未绑定 subject manifest 时 fail-closed', async () => {
  await withTempDir(async (root) => {
    const { archive, signer } = makeProviders(root)
    const options = baseOptions({ archive, signer })
    options.computeEligibility = async () => makeEligibility({ manifestDigest: DIGEST('0') })
    const result = await runMarketEvidenceSequence(options)
    assert.equal(result.status, 'blocked')
    assert.equal(result.failure_stage, 'eligibility')
    assert.ok(result.reason_codes.includes(EVIDENCE_REASON_CODES.MARKET_EVIDENCE_INCOMPLETE))
    assert.equal(signer.audit().entries.length, 0)
    assert.equal(archive.head().sequence, 1)
  })
})

test('sequence: receipt/v1 非法时在 receipt-validation 停止，不写归档', async () => {
  await withTempDir(async (root) => {
    const { archive, signer } = makeProviders(root)
    const options = baseOptions({ archive, signer })
    options.receipt = {
      ...options.receipt,
      integrity: { ...options.receipt.integrity, record_digest: DIGEST('0') },
    }
    const result = await runMarketEvidenceSequence(options)
    assert.equal(result.status, 'blocked')
    assert.equal(result.failure_stage, 'receipt-validation')
    assert.deepEqual(result.steps, [])
    assert.ok(result.reason_codes.includes(EVIDENCE_REASON_CODES.MARKET_EVIDENCE_INCOMPLETE))
    assert.equal(archive.head().sequence, 0)
    assert.equal(signer.audit().entries.length, 0)
  })
})

test('sequence: 可信时间不可用时在 archive-subject 停止', async () => {
  await withTempDir(async (root) => {
    const archive = createDevelopmentArchiveProvider({
      dir: join(root, 'archive'),
      archiveId: 'run-evidence-001',
      trustedTime: createBlockedTrustedTimeProvider(),
    })
    const signer = createDevelopmentSigningProvider({
      authorizedRequesters: [...AUTHORIZED],
      now: () => new Date(FIXED_TIME),
    })
    const result = await runMarketEvidenceSequence(baseOptions({ archive, signer }))
    assert.equal(result.status, 'blocked')
    assert.equal(result.failure_stage, 'archive-subject')
    assert.ok(result.reason_codes.includes(EVIDENCE_REASON_CODES.TRUSTED_TIME_UNAVAILABLE))
    assert.equal(archive.head().sequence, 0)
  })
})

test('sequence: 隔离等级不足时验证失败（non-eligible），不改变已归档证据', async () => {
  await withTempDir(async (root) => {
    const { archive, signer } = makeProviders(root)
    const options = baseOptions({ archive, signer })
    options.expectedMinimumIsolation = 'L2'
    const result = await runMarketEvidenceSequence(options)
    assert.equal(result.market_eligible, false)
    assert.equal(result.publish, false)
    assert.ok(result.verification.reason_codes.includes('isolation-level-insufficient'))
    assert.equal(archive.head().sequence, 2)
  })
})
