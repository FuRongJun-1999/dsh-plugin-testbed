/**
 * 单元 · append-only 归档链、anchor、可信时间与 provider 信任（node:test）。
 *
 * 覆盖 ARC-01/02/04/07/08：单调 sequence、previous_digest 哈希链、anchor、
 * 幂等/冲突失败、并发 append、重放/篡改/删除/回滚检测、可信时间接口；
 * local-file/git provider 明确 development-only（E1），blocked provider 只返回
 * blocked。所有数据均为开发/测试数据，不是市场证据。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  ARCHIVE_ANCHOR_V1_SCHEMA,
  ARCHIVE_ENTRY_V1_SCHEMA,
  ARCHIVE_CHAIN_VERIFICATION_V1_SCHEMA,
  EVIDENCE_REASON_CODES,
  validateMarketDocument,
} from '../../../src/protocol/market-schemas.js'
import {
  createBlockedArchiveProvider,
  createBlockedTrustedTimeProvider,
  createDevelopmentArchiveProvider,
  createDevelopmentTrustedTimeProvider,
} from '../../../src/evidence/archive-provider.js'
import {
  archiveAnchorDigest,
  archiveProviderTrustIssues,
  verifyArchiveChain,
  verifyEntryDigest,
} from '../../../src/evidence/archive.js'
import { validateArchiveEntry } from '../../../src/evidence/canonical.js'
import { DIGEST, FIXED_TIME } from './_fixtures.js'

function makeSubjectDraft(overrides = {}) {
  return {
    receipt_digest: DIGEST('9'),
    isolation_attestation_digest: DIGEST('e'),
    policy_digest: DIGEST('a'),
    approval_digests: [DIGEST('c')],
    attestation_digest: null,
    eligibility_digest: null,
    ...overrides,
  }
}

function makeAttestationDraft(overrides = {}) {
  return {
    receipt_digest: DIGEST('9'),
    isolation_attestation_digest: null,
    policy_digest: null,
    approval_digests: [],
    attestation_digest: DIGEST('2'),
    eligibility_digest: DIGEST('3'),
    ...overrides,
  }
}

async function withTempDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-evidence-archive-'))
  try {
    return await fn(dir)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

function makeArchive(root, overrides = {}) {
  return createDevelopmentArchiveProvider({
    dir: join(root, 'archive'),
    archiveId: 'run-evidence-001',
    ...overrides,
  })
}

function entryFiles(dir) {
  return readdirSync(dir).filter((name) => name.endsWith('.json')).sort()
}

test('archive: subject entry N 与 attestation entry N+1 形成可验证链，anchor 绑定', async () => {
  await withTempDir(async (root) => {
    const archive = makeArchive(root)
    const subject = await archive.append(makeSubjectDraft())
    assert.equal(subject.status, 'appended')
    assert.equal(subject.entry.sequence, 1)
    assert.equal(subject.entry.previous_entry_digest, null)
    assert.equal(subject.entry.attestation_digest, null)
    assert.equal(subject.entry.eligibility_digest, null)
    assert.equal(validateArchiveEntry(subject.entry).ok, true)
    assert.equal(verifyEntryDigest(subject.entry).ok, true)
    assert.equal(validateMarketDocument(subject.anchor, ARCHIVE_ANCHOR_V1_SCHEMA).ok, true)
    assert.notEqual(archiveAnchorDigest(subject.anchor), archiveAnchorDigest({ ...subject.anchor, sequence: 2 }))

    const attestation = await archive.append(makeAttestationDraft())
    assert.equal(attestation.status, 'appended')
    assert.equal(attestation.entry.sequence, 2)
    assert.equal(attestation.entry.previous_entry_digest, subject.entry.entry_digest)
    assert.equal(attestation.entry.attestation_digest, DIGEST('2'))
    assert.equal(attestation.entry.eligibility_digest, DIGEST('3'))

    const head = archive.head()
    assert.equal(head.status, 'ok')
    assert.equal(head.sequence, 2)
    assert.equal(head.entry_digest, attestation.entry.entry_digest)

    const chain = await archive.verifyChain({ requireAttestationPair: true })
    assert.equal(chain.status, 'valid', JSON.stringify(chain.verification.reason_codes))
    assert.equal(validateMarketDocument(chain.verification, ARCHIVE_CHAIN_VERIFICATION_V1_SCHEMA).ok, true)
    assert.equal(chain.verification.checks.every((entry) => entry.status === 'pass'), true)

    const got = archive.get(1)
    assert.equal(got.status, 'ok')
    assert.equal(got.entry.entry_digest, subject.entry.entry_digest)
    assert.equal(archive.get(99).status, 'not-found')
    assert.equal(archive.describe().sequence_head, 2)
  })
})

test('archive: 并发 append 获得唯一、连续 sequence 且链完整', async () => {
  await withTempDir(async (root) => {
    const archive = makeArchive(root)
    const results = await Promise.all(
      Array.from({ length: 6 }, (_, index) => archive.append(makeSubjectDraft({
        receipt_digest: DIGEST(String(index % 10)),
      }))),
    )
    assert.equal(results.every((result) => result.status === 'appended'), true)
    const sequences = results.map((result) => result.entry.sequence).sort((a, b) => a - b)
    assert.deepEqual(sequences, [1, 2, 3, 4, 5, 6])
    assert.equal(new Set(results.map((result) => result.entry.entry_digest)).size, 6)
    const chain = await archive.verifyChain({})
    assert.equal(chain.status, 'valid', JSON.stringify(chain.verification.reason_codes))
    assert.equal(entryFiles(join(root, 'archive')).length, 6)
  })
})

test('archive: 重放旧 expected sequence / gap / previous-digest 错配均拒绝', async () => {
  await withTempDir(async (root) => {
    const archive = makeArchive(root)
    const first = await archive.append(makeSubjectDraft())
    assert.equal(first.status, 'appended')

    const stale = await archive.append(makeSubjectDraft({
      expected: { sequence: 1, previous_entry_digest: null },
    }))
    assert.equal(stale.status, 'rejected')
    assert.ok(stale.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_REPLAY_DETECTED))

    const gap = await archive.append(makeSubjectDraft({
      expected: { sequence: 3, previous_entry_digest: first.entry.entry_digest },
    }))
    assert.equal(gap.status, 'rejected')
    assert.ok(gap.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_SEQUENCE_GAP))

    const mismatch = await archive.append(makeSubjectDraft({
      expected: { sequence: 2, previous_entry_digest: DIGEST('0') },
    }))
    assert.equal(mismatch.status, 'rejected')
    assert.ok(mismatch.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISMATCH))
  })
})

test('archive: 正文篡改被 entry_digest / chain 检测，provider 拒绝继续 append', async () => {
  await withTempDir(async (root) => {
    const archive = makeArchive(root)
    await archive.append(makeSubjectDraft())
    await archive.append(makeAttestationDraft())
    const dir = join(root, 'archive')
    const files = entryFiles(dir)
    const firstPath = join(dir, files[0])
    const entry = JSON.parse(readFileSync(firstPath, 'utf8'))
    entry.receipt_digest = DIGEST('0')
    writeFileSync(firstPath, JSON.stringify(entry, null, 2))

    const chain = await archive.verifyChain({})
    assert.equal(chain.status, 'invalid')
    assert.ok(chain.verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED))

    const blocked = await archive.append(makeSubjectDraft())
    assert.equal(blocked.status, 'blocked')
    assert.ok(blocked.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED))
  })
})

test('archive: 删除 entry 需由已记录 head 检测（截断/回滚），否则链本身缺少新鲜度证明', async () => {
  await withTempDir(async (root) => {
    const archive = makeArchive(root)
    await archive.append(makeSubjectDraft())
    const second = await archive.append(makeAttestationDraft())
    const expectedHead = {
      sequence: second.anchor.sequence,
      entry_digest: second.anchor.entry_digest,
    }
    const dir = join(root, 'archive')
    const files = entryFiles(dir)
    unlinkSync(join(dir, files[files.length - 1]))

    const withoutPinnedHead = await archive.verifyChain({})
    assert.equal(withoutPinnedHead.status, 'valid')

    const withPinnedHead = await archive.verifyChain({ expectedHead })
    assert.equal(withPinnedHead.status, 'invalid')
    assert.ok(withPinnedHead.verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_ROLLBACK_DETECTED))
    assert.ok(withPinnedHead.verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_TRUNCATION_DETECTED))
  })
})

test('archive: provider signature 被篡改时即使 entry_digest 自洽也检测失败', async () => {
  await withTempDir(async (root) => {
    const archive = makeArchive(root)
    await archive.append(makeSubjectDraft())
    const dir = join(root, 'archive')
    const files = entryFiles(dir)
    const path = join(dir, files[0])
    const entry = JSON.parse(readFileSync(path, 'utf8'))
    const raw = Buffer.from(entry.provider_signature.value, 'base64url')
    raw[0] ^= 0xff
    entry.provider_signature.value = raw.toString('base64url')
    writeFileSync(path, JSON.stringify(entry, null, 2))

    assert.equal(verifyEntryDigest(entry).ok, true, 'entry digest excludes provider signature')
    assert.equal(archive.verifyEntrySignature(entry), false)
    const chain = await archive.verifyChain({})
    assert.equal(chain.status, 'invalid')
    assert.ok(chain.verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_TAMPER_DETECTED))
  })
})

test('archive: 重排/重复 sequence 被检测为重放/序列缺口', async () => {
  await withTempDir(async (root) => {
    const archive = makeArchive(root)
    const first = await archive.append(makeSubjectDraft())
    const second = await archive.append(makeSubjectDraft({ receipt_digest: DIGEST('8') }))
    const entries = [archive.get(1).entry, archive.get(2).entry]
    assert.equal(verifyArchiveChain(entries, {}).ok, true)

    const duplicated = [first.entry, first.entry]
    const duplicateChain = verifyArchiveChain(duplicated, {})
    assert.equal(duplicateChain.ok, false)
    assert.ok(duplicateChain.verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_REPLAY_DETECTED))

    const reordered = [second.entry, first.entry]
    const reorderedChain = verifyArchiveChain(reordered, {})
    assert.equal(reorderedChain.ok, false)
    assert.ok(reorderedChain.verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_SEQUENCE_GAP))
  })
})

test('archive: 可信时间接口 — 开发时钟不可信，回拨拒绝，TSA 缺失时 blocked', async () => {
  await withTempDir(async (root) => {
    const time = createDevelopmentTrustedTimeProvider({
      times: ['2026-01-01T00:00:02.000Z', '2026-01-01T00:00:01.000Z'],
    })
    const archive = createDevelopmentArchiveProvider({
      dir: join(root, 'archive'),
      archiveId: 'run-evidence-001',
      trustedTime: time,
    })
    const first = await archive.append(makeSubjectDraft())
    assert.equal(first.status, 'appended')
    assert.equal(first.entry.time_source.source, 'host-clock-development-only')
    assert.equal(first.entry.time_source.trusted, false)

    const rewound = await archive.append(makeSubjectDraft())
    assert.equal(rewound.status, 'rejected')
    assert.ok(rewound.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_TIME_REVERSED))

    const noTsa = createDevelopmentArchiveProvider({
      dir: join(root, 'archive-blocked-time'),
      archiveId: 'run-evidence-002',
      trustedTime: createBlockedTrustedTimeProvider(),
    })
    const blocked = await noTsa.append(makeSubjectDraft())
    assert.equal(blocked.status, 'blocked')
    assert.ok(blocked.reason_codes.includes(EVIDENCE_REASON_CODES.TRUSTED_TIME_UNAVAILABLE))
  })
})

test('archive: blocked WORM/object-lock provider 只返回 blocked，且 schema/信任结论 fail-closed', async () => {
  const provider = createBlockedArchiveProvider()
  const doc = provider.describe()
  assert.equal(doc.availability, 'blocked')
  assert.equal(doc.trust_class, 'unavailable')
  assert.ok(doc.limitations.includes('no-worm-object-lock-tlog'))
  const trust = archiveProviderTrustIssues(doc)
  assert.equal(trust.ok, false)
  assert.ok(trust.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_MISSING))

  const append = await provider.append(makeSubjectDraft())
  assert.equal(append.status, 'blocked')
  assert.ok(append.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_PROVIDER_MISSING))
  assert.equal(provider.get(1).status, 'blocked')
  assert.equal(provider.head().status, 'blocked')
  assert.equal(provider.audit().status, 'blocked')
  const chain = await provider.verifyChain()
  assert.equal(chain.status, 'blocked')
  assert.equal(chain.verification.result, 'blocked')
  assert.equal(validateMarketDocument(chain.verification, ARCHIVE_CHAIN_VERIFICATION_V1_SCHEMA).ok, true)
})

test('archive: 开发 provider（local-file / git）必须明确 E1 development-only，不得市场可用', async () => {
  await withTempDir(async (root) => {
    for (const mode of ['local-file', 'git']) {
      const repoDir = join(root, `repo-${mode}`)
      const archive = createDevelopmentArchiveProvider({
        dir: join(root, `entries-${mode}`),
        mode,
        repoDir: mode === 'git' ? repoDir : undefined,
        archiveId: `run-${mode}`,
      })
      const doc = archive.describe()
      assert.equal(doc.trust_class, 'development-only', mode)
      assert.equal(doc.mode, mode)
      assert.equal(doc.immutability.append_only, false)
      assert.equal(doc.immutability.delete_forbidden, false)
      assert.equal(doc.trust_anchor.type, 'none-development-only')
      assert.equal(doc.trusted_time.verified, false)
      assert.ok(doc.limitations.includes('not-market-evidence'))
      const trust = archiveProviderTrustIssues(doc)
      assert.equal(trust.ok, false)
      assert.ok(trust.reason_codes.includes(EVIDENCE_REASON_CODES.DEVELOPMENT_ONLY_NOT_MARKET))
      assert.ok(trust.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_MODE_NOT_IMMUTABLE))
    }
  })
})

test('archive: git 历史可改写，reset 后 pin 住的 head 检测到回滚', async () => {
  await withTempDir(async (root) => {
    const repoDir = join(root, 'repo')
    const dir = join(repoDir, 'archive')
    const archive = createDevelopmentArchiveProvider({
      dir,
      mode: 'git',
      repoDir,
      archiveId: 'run-git',
    })
    await archive.append(makeSubjectDraft())
    const second = await archive.append(makeAttestationDraft())
    const expectedHead = { sequence: second.anchor.sequence, entry_digest: second.anchor.entry_digest }
    const auditBefore = archive.audit()
    assert.equal(typeof auditBefore.git_head, 'string')
    assert.equal(auditBefore.git_head.length, 40)

    execFileSync('git', ['reset', '--hard', 'HEAD~1'], { cwd: repoDir, stdio: 'ignore' })

    const reopened = createDevelopmentArchiveProvider({
      dir,
      mode: 'git',
      repoDir,
      archiveId: 'run-git',
    })
    assert.equal(reopened.head().sequence, 1)
    const chain = await reopened.verifyChain({ expectedHead })
    assert.equal(chain.status, 'invalid')
    assert.ok(chain.verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_ROLLBACK_DETECTED))
    assert.ok(reopened.describe().limitations.includes('git-history-rewritable'))
  })
})

test('archive: entry/chain 校验对删除/截断/未知 schema 版本 fail-closed', async () => {
  await withTempDir(async (root) => {
    const archive = makeArchive(root)
    await archive.append(makeSubjectDraft())
    const entry = archive.get(1).entry
    assert.equal(validateMarketDocument(entry, ARCHIVE_ENTRY_V1_SCHEMA).ok, true)

    const badVersion = { ...entry, schema_version: 'archive-entry/v2' }
    assert.equal(validateMarketDocument(badVersion, ARCHIVE_ENTRY_V1_SCHEMA).ok, false)

    const chain = verifyArchiveChain([], { expectedHead: { sequence: 2, entry_digest: DIGEST('2') } })
    assert.equal(chain.ok, false)
    assert.ok(chain.verification.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_ROLLBACK_DETECTED))
  })
})
