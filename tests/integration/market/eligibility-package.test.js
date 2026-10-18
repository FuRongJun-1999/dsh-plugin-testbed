/**
 * Eligibility engine + evidence package contract tests (t8 / MKT-02/03/07/09).
 *
 * The eligibility engine is exercised with synthetic *contract* inputs so the
 * AND/fail-closed matrix is testable. This is not a market pass: the real
 * `runMarketGate` path has no measured isolation provider, no KMS signer and no
 * independent archive, and stays non-eligible (see runtime-gate.test.js).
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { assessReceipt, computeEligibility, marketManifestDigest } from '../../../src/market/eligibility.js'
import { validateMarketPolicy } from '../../../src/market/policy.js'
import {
  buildEvidencePackage,
  safeRelativePath,
  verifyEvidencePackage,
} from '../../../src/market/evidence-package.js'
import { validateMarketEligibility } from '../../../src/protocol/market-schemas.js'
import {
  deepMerge,
  makePassReceipt,
  makeRejectReceipt,
  tempDir,
  validPolicy,
} from './_fixtures.js'

const NOW = Date.parse('2026-10-19T05:00:00Z')
const DIGEST_A = 'sha256:' + 'a'.repeat(64)
const DIGEST_B = 'sha256:' + 'b'.repeat(64)

function syntheticInput(receipt, overrides = {}) {
  const policy = validPolicy()
  const policyView = validateMarketPolicy(policy, NOW).policy
  const base = {
    policy: policyView,
    receipt: assessReceipt(receipt),
    runtime: {
      status: 'available',
      reasonCodes: [],
      detail: null,
      anchor: {},
      anchorDigest: DIGEST_A,
      cordisVersion: '4.0.5',
      dshVersion: '0.2.1-rc.2',
      contractSuiteDigest: DIGEST_B,
      catalogDigest: DIGEST_A,
      lockfileDigest: DIGEST_A,
      entryDigest: DIGEST_A,
      environmentDigest: DIGEST_A,
      contractPassed: true,
      evidenceRefs: ['contract-results'],
    },
    isolation: {
      status: 'admitted',
      reasonCodes: [],
      requiredLevel: 'L2',
      achievedLevel: 'L2',
      attestationDigest: DIGEST_A,
      verificationDigest: DIGEST_B,
      attestation: { schema_version: 'isolation-attestation/v1' },
      admission: { checks: [{ id: 'provider.present', status: 'pass' }], evidence_refs: ['ev-isolation'] },
      evidenceRefs: ['ev-isolation'],
      limitations: [],
    },
    providers: {
      signingProviderDoc: null,
      archiveProviderDoc: null,
      signingTrusted: true,
      archiveTrusted: true,
      signingKeyId: 'kms-market-key-1',
      signingAlg: 'ed25519',
      signingReasonCodes: [],
      archiveReasonCodes: [],
      signingLimitations: [],
      archiveLimitations: [],
    },
    approvals: {
      ok: true,
      errors: [],
      reasonCodes: [],
      approvals: [
        {
          principal: 'security-reviewer-1',
          role: 'security',
          atMs: NOW - 3_600_000,
          targetDigest: receipt.target_ref.owner_put_digest,
          decision: 'approve',
          signatureRef: 'sig:security',
        },
        {
          principal: 'release-manager-1',
          role: 'release',
          atMs: NOW - 3_600_000,
          targetDigest: receipt.target_ref.owner_put_digest,
          decision: 'approve',
          signatureRef: 'sig:release',
        },
      ],
      waivers: [],
      approvedRoles: ['security', 'release'],
      approvalDigests: [DIGEST_A, DIGEST_B],
      waiverDigests: [],
      limitations: [],
    },
    scheduler: { present: false, ok: true, reasonCodes: [], evidenceRefs: [], limitations: [] },
    trustedTime: { verified: true, source: 'tsa', reasonCodes: [] },
    nowMs: NOW,
    subjectAnchor: {},
    subjectAnchorDigest: DIGEST_A,
  }
  return deepMerge(base, overrides)
}

test('eligibility: all required conditions pass → eligible (contract engine only)', async (t) => {
  const { receipt } = await makePassReceipt(t)
  const computation = computeEligibility(syntheticInput(receipt))
  assert.equal(computation.decision, 'eligible')
  assert.deepEqual(computation.reasonCodes, [])
  assert.equal(computation.conditions.length, 10)
  for (const condition of computation.conditions) {
    assert.equal(condition.status, 'pass', `${condition.id}: ${condition.reason_code}`)
  }
  assert.equal(computation.eligibility.decision, 'eligible')
  assert.match(computation.eligibility.decision_id, /^market-eligibility:/)
  assert.match(computation.digest, /^sha256:[0-9a-f]{64}$/)
  const shaped = validateMarketEligibility(computation.eligibility)
  assert.equal(shaped.ok, true, shaped.errors.join(','))
  assert.equal(
    computation.eligibility.evidence_manifest_digest,
    marketManifestDigest({
      receiptDigest: computation.eligibility.receipt_digest,
      isolationAttestationDigest: DIGEST_A,
      isolationVerificationDigest: DIGEST_B,
      policyDigest: computation.eligibility.policy.digest,
      runtimeAnchorDigest: DIGEST_A,
      contractSuiteDigest: DIGEST_B,
      approvalDigests: [DIGEST_A, DIGEST_B],
      waiverDigests: [],
      archiveAnchorDigest: DIGEST_A,
    }),
  )
})

test('eligibility: each failing/unknown condition yields non-eligible with a stable blocker', async (t) => {
  const { receipt } = await makePassReceipt(t)
  const flip = {
    'MKT-C01': { isolation: { status: 'blocked', achievedLevel: null, reasonCodes: ['isolation-provider-missing'] } },
    'MKT-C02': { isolation: { admission: { checks: [], evidence_refs: [] } } },
    'MKT-C03': { runtime: { status: 'blocked', contractPassed: false, reasonCodes: ['runtime-anchor-missing'] } },
    'MKT-C04': { receipt: { ok: false, reasonCodes: ['market-receipt-invalid'] } },
    'MKT-C05': { providers: { signingTrusted: false, signingReasonCodes: ['signing-provider-missing'] } },
    'MKT-C06': { providers: { archiveTrusted: false, archiveReasonCodes: ['archive-provider-missing'] } },
    'MKT-C07': { approvals: { ok: false } },
    'MKT-C08': { approvals: { ok: false, reasonCodes: ['market-approval-missing'] } },
    'MKT-C09': { approvals: { ok: true, approvals: [{ principal: 'x', role: 'security', atMs: NOW, targetDigest: 'sha256:' + '0'.repeat(64), decision: 'approve', signatureRef: 'sig:x' }] } },
    'MKT-C10': { trustedTime: { verified: false, source: 'host-clock-development-only', reasonCodes: ['trusted-time-unavailable'] } },
  }
  for (const [conditionId, override] of Object.entries(flip)) {
    const computation = computeEligibility(syntheticInput(receipt, override))
    assert.equal(computation.decision, 'non-eligible', `${conditionId} must not be eligible`)
    const blocker = computation.blockers.find((entry) => entry.condition_id === conditionId)
    assert.ok(blocker, `${conditionId} missing blocker (${JSON.stringify(computation.blockers)})`)
    assert.ok(typeof blocker.reason_code === 'string' && blocker.reason_code.length > 0)
  }
})

test('eligibility: only C03/C04 pass while C01/C02/C05..C10 fail → non-eligible', async (t) => {
  const { receipt } = await makePassReceipt(t)
  const computation = computeEligibility(syntheticInput(receipt, {
    isolation: {
      status: 'blocked',
      achievedLevel: null,
      reasonCodes: ['isolation-provider-missing'],
      admission: { checks: [], evidence_refs: [] },
    },
    providers: {
      signingTrusted: false,
      archiveTrusted: false,
      signingReasonCodes: ['signing-provider-missing'],
      archiveReasonCodes: ['archive-provider-missing'],
    },
    approvals: {
      ok: false,
      reasonCodes: ['market-approval-missing'],
      approvals: [],
      approvalDigests: [],
    },
    trustedTime: { verified: false, source: 'host-clock-development-only', reasonCodes: ['trusted-time-unavailable'] },
  }))
  const passed = computation.conditions.filter((condition) => condition.status === 'pass').map((condition) => condition.id)
  assert.deepEqual(passed, ['MKT-C03', 'MKT-C04'])
  assert.equal(computation.decision, 'non-eligible')
  assert.equal(computation.eligibility.decision, 'non-eligible')
  const blockerIds = new Set(computation.blockers.map((blocker) => blocker.condition_id))
  for (const conditionId of ['MKT-C01', 'MKT-C02', 'MKT-C05', 'MKT-C06', 'MKT-C07', 'MKT-C08', 'MKT-C09', 'MKT-C10']) {
    assert.ok(blockerIds.has(conditionId), `missing blocker for ${conditionId}`)
  }
})

test('eligibility: a caller-forced policy subset cannot shrink the fixed condition set', async (t) => {
  const { receipt } = await makePassReceipt(t)
  const tampered = syntheticInput(receipt, {
    isolation: { status: 'blocked', achievedLevel: null, reasonCodes: ['isolation-provider-missing'] },
  })
  // Simulate a caller bypassing policy validation by editing the derived view.
  tampered.policy.requiredConditions = ['MKT-C03', 'MKT-C04']
  const computation = computeEligibility(tampered)
  assert.equal(computation.decision, 'non-eligible')
  assert.equal(computation.conditions.length, 10)
  assert.ok(computation.blockers.some((blocker) => blocker.condition_id === 'MKT-C01'))
  assert.equal(computation.eligibility.conditions.length, 10)
})

test('eligibility: a valid waiver is carried in the manifest but never flips a status', async (t) => {
  const { receipt } = await makePassReceipt(t)
  const base = computeEligibility(syntheticInput(receipt))
  const waived = computeEligibility(syntheticInput(receipt, {
    approvals: {
      waiverDigests: [DIGEST_A],
      waivers: [{ conditionId: 'MKT-C04' }],
    },
  }))
  assert.deepEqual(
    waived.conditions.map((entry) => entry.status),
    base.conditions.map((entry) => entry.status),
  )
  assert.equal(waived.decision, 'eligible')
  assert.notEqual(
    waived.eligibility.evidence_manifest_digest,
    base.eligibility.evidence_manifest_digest,
  )
})

test('receipt assessment: real pass receipt passes, real reject receipt fails C04', async (t) => {
  const pass = await makePassReceipt(t)
  const passAssessment = assessReceipt(pass.receipt)
  assert.equal(passAssessment.ok, true, passAssessment.errors.join(','))
  assert.equal(passAssessment.form, 'frozen')
  assert.match(passAssessment.digest, /^sha256:[0-9a-f]{64}$/)

  const reject = await makeRejectReceipt(t)
  const rejectAssessment = assessReceipt(reject.receipt)
  assert.equal(rejectAssessment.ok, false)
  assert.ok(rejectAssessment.reasonCodes.includes('market-receipt-invalid'))
})

test('evidence package: digest/partial/tamper/path/extra-file rules are fail-closed', async (t) => {
  const dir = tempDir(t, 'market-package-')
  mkdirSync(join(dir, 'market'), { recursive: true })
  writeFileSync(join(dir, 'market', 'eligibility.json'), '{"a":1}\n', 'utf8')
  writeFileSync(join(dir, 'receipt.json'), '{"b":2}\n', 'utf8')
  const { describeArtifact } = await import('../../../src/market/evidence-package.js')
  const one = await describeArtifact(dir, 'market/eligibility.json', 'market-eligibility/v1')
  const two = await describeArtifact(dir, 'receipt.json', 'receipt/v1')
  assert.equal(one.ok, true)
  assert.equal(two.ok, true)
  const built = buildEvidencePackage({
    packageId: 'package:test',
    runId: 'run-test',
    receiptDigest: DIGEST_A,
    artifacts: [one.artifact, two.artifact],
    createdAt: new Date(NOW).toISOString(),
  })
  assert.match(built.digest, /^sha256:[0-9a-f]{64}$/)
  assert.equal((await verifyEvidencePackage(built.manifest, { root: dir })).ok, true)

  writeFileSync(join(dir, 'receipt.json'), '{"b":3}\n', 'utf8')
  const tampered = await verifyEvidencePackage(built.manifest, { root: dir })
  assert.equal(tampered.ok, false)
  assert.ok(tampered.reasonCodes.includes('market-evidence-digest-mismatch'))

  writeFileSync(join(dir, 'receipt.json'), '{"b":2}\n', 'utf8')
  writeFileSync(join(dir, 'extra.txt'), 'extra\n', 'utf8')
  const extra = await verifyEvidencePackage(built.manifest, { root: dir, rejectUnregistered: true })
  assert.equal(extra.ok, false)
  assert.ok(extra.reasonCodes.includes('market-evidence-unregistered'))

  assert.throws(() => buildEvidencePackage({
    packageId: 'package:bad',
    runId: 'run-test',
    receiptDigest: DIGEST_A,
    artifacts: [{ path: '../escape.json', kind: 'x', digest: DIGEST_A, size_bytes: 1 }],
    createdAt: new Date(NOW).toISOString(),
  }), /unsafe evidence path/)
  assert.equal(safeRelativePath('../escape.json'), null)
  assert.equal(safeRelativePath('C:/app.asar/x'), null)
  assert.equal(safeRelativePath('market/eligibility.json'), 'market/eligibility.json')
})
