/**
 * 安全 · 独立归档攻击面：篡改/删除/重放/回滚/伪造 provider 签名。
 *
 * 本地文件与 git 归档被明确标为 E1 development-only，不能作为市场锚；即使其
 * 哈希链/临时 MAC 校验通过，市场验证也必须 fail-closed。任何对已归档字节的
 * 修改、删除、重排或旧 anchor 重放都必须被检测或阻塞。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { EVIDENCE_REASON_CODES } from '../../src/protocol/market-schemas.js'
import {
  archiveProviderTrustIssues,
  verifyArchiveChain,
} from '../../src/evidence/archive.js'
import {
  createBlockedArchiveProvider,
  createDevelopmentArchiveProvider,
} from '../../src/evidence/archive-provider.js'
import { createDevelopmentSigningProvider } from '../../src/evidence/signing-provider.js'
import { archiveEntryDigest } from '../../src/evidence/canonical.js'
import { runMarketEvidenceSequence } from '../../src/evidence/sequence.js'
import {
  CONTROL_PLANE,
  DIGEST,
  FIXED_TIME,
  ISOLATION_REF,
  POLICY_REF,
  RUNTIME_REF,
  makeEligibility,
  makeValidReceipt,
} from '../unit/evidence/_fixtures.js'

const AUTHORIZED = Object.freeze([{
  control_plane_id: 'control-plane-development',
  authorization_ref: 'auth-ref-1',
}])

async function withTempDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-evidence-security-'))
  try {
    return await fn(dir)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

async function runDevSequence(root) {
  const archive = createDevelopmentArchiveProvider({
    dir: join(root, 'archive'),
    archiveId: 'run-evidence-001',
  })
  const signer = createDevelopmentSigningProvider({
    authorizedRequesters: [...AUTHORIZED],
    now: () => new Date(FIXED_TIME),
  })
  const receipt = makeValidReceipt()
  const result = await runMarketEvidenceSequence({
    receipt,
    isolation: ISOLATION_REF,
    policy: POLICY_REF,
    approvalDigests: [DIGEST('c')],
    controlPlane: CONTROL_PLANE,
    runtime: RUNTIME_REF,
    archiveProvider: archive,
    signingProvider: signer,
    computeEligibility: async (input) => makeEligibility({ manifestDigest: input.evidenceManifestDigest }),
    requester: AUTHORIZED[0],
    attestationId: 'attestation-security-001',
    requestId: 'request-security-001',
    signing: {
      key_id: signer.activeKeyIds()[0],
      alg: 'ed25519',
      signed_at: FIXED_TIME,
      provider_audit_ref: 'audit:security-1',
    },
    verifier: { id: 'qa-independent', verifiedAt: '2026-01-01T00:00:10.000Z' },
  })
  return { archive, signer, result, dir: join(root, 'archive') }
}

function listEntryPaths(dir) {
  return readdirSync(dir)
    .filter((name) => name.endsWith('.json'))
    .sort()
    .map((name) => join(dir, name))
}

function emptyDraft(overrides = {}) {
  return {
    receipt_digest: DIGEST('9'),
    isolation_attestation_digest: null,
    policy_digest: null,
    approval_digests: [],
    attestation_digest: null,
    eligibility_digest: null,
    ...overrides,
  }
}

test('archive security: 开发归档全链路不得市场通过，且 provider 信任结论为 E1', async () => {
  await withTempDir(async (root) => {
    const { archive, result } = await runDevSequence(root)
    assert.equal(result.market_eligible, false)
    assert.equal(result.publish, false)
    assert.equal(result.status, 'non-eligible')
    assert.equal(result.evidence_class, 'E1')
    assert.ok(result.reason_codes.includes(EVIDENCE_REASON_CODES.DEVELOPMENT_ONLY_NOT_MARKET))
    const trust = archiveProviderTrustIssues(archive.describe())
    assert.equal(trust.ok, false)
    assert.ok(trust.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_MODE_NOT_IMMUTABLE))
    assert.ok(trust.reason_codes.includes(EVIDENCE_REASON_CODES.TRUSTED_TIME_UNAVAILABLE))
  })
})

test('archive security: 正文篡改、删除、重排、重复均被检测；pin 住 head 才能发现删除', async () => {
  await withTempDir(async (root) => {
    const { archive, result, dir } = await runDevSequence(root)
    const files = listEntryPaths(dir)
    assert.equal(files.length, 2)
    const original = JSON.parse(readFileSync(files[0], 'utf8'))

    const tampered = structuredClone(original)
    tampered.receipt_digest = DIGEST('0')
    writeFileSync(files[0], JSON.stringify(tampered, null, 2))
    const tamperChain = await archive.verifyChain({})
    assert.equal(tamperChain.status, 'invalid')
    assert.ok(tamperChain.verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED))
    const blockedAppend = await archive.append(emptyDraft())
    assert.equal(blockedAppend.status, 'blocked')

    // Restore, then delete entry N+1: only a pinned head can prove truncation.
    writeFileSync(files[0], JSON.stringify(original, null, 2))
    unlinkSync(files[1])
    const expectedHead = {
      sequence: result.attestation_anchor.sequence,
      entry_digest: result.attestation_anchor.entry_digest,
    }
    const rollback = await archive.verifyChain({ expectedHead })
    assert.equal(rollback.status, 'invalid')
    assert.ok(rollback.verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_ROLLBACK_DETECTED))
    assert.ok(rollback.verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_TRUNCATION_DETECTED))

    const entries = [archive.get(1).entry, archive.get(1).entry]
    const replayed = verifyArchiveChain(entries, {})
    assert.equal(replayed.ok, false)
    assert.ok(replayed.verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_REPLAY_DETECTED))
  })
})

test('archive security: 重放旧 expected sequence 被拒绝，旧 anchor 不能覆盖新链', async () => {
  await withTempDir(async (root) => {
    const { archive } = await runDevSequence(root)
    const replay = await archive.append(emptyDraft({
      expected: { sequence: 1, previous_entry_digest: null },
    }))
    assert.equal(replay.status, 'rejected')
    assert.ok(replay.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_REPLAY_DETECTED))
    assert.equal(archive.head().sequence, 2, 'replay must not extend or rewrite the chain')
  })
})

test('archive security: 重算 entry_digest 的篡改仍被 provider 签名检测', async () => {
  await withTempDir(async (root) => {
    const { archive, dir } = await runDevSequence(root)
    const files = listEntryPaths(dir)
    const entry = JSON.parse(readFileSync(files[0], 'utf8'))
    entry.policy_digest = DIGEST('0')
    entry.entry_digest = archiveEntryDigest(entry)
    writeFileSync(files[0], JSON.stringify(entry, null, 2))
    const result = await archive.verifyChain({})
    assert.equal(result.status, 'invalid')
    assert.ok(result.verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED))
  })
})

test('archive security: 损坏/无法解析的 entry 文件 fail-closed（不接受静默跳过）', async () => {
  await withTempDir(async (root) => {
    const { archive, dir } = await runDevSequence(root)
    const files = listEntryPaths(dir)
    writeFileSync(files[0], '{ not-json')
    const chain = await archive.verifyChain({})
    assert.equal(chain.status, 'invalid')
    assert.ok(chain.verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED))
    const append = await archive.append(emptyDraft())
    assert.equal(append.status, 'blocked')
  })
})

test('archive security: 未配置对象锁/tlog/TSA 时不得产生 anchor 或 valid 链', async () => {
  const provider = createBlockedArchiveProvider({ mode: 'object-lock' })
  assert.equal(provider.describe().availability, 'blocked')
  const chain = await provider.verifyChain()
  assert.equal(chain.status, 'blocked')
  assert.equal(chain.verification.result, 'blocked')
  assert.equal(chain.entries.length, 0)
  const append = await provider.append({})
  assert.equal(append.status, 'blocked')
  assert.equal(append.anchor, undefined)
})
