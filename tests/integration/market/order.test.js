/**
 * Fixed evidence-order tests (t8 acceptance #2, SIG-08):
 *
 *   receipt validation → archive subject entry N → eligibility →
 *   attestation/sign → entry N+1 → independent verification
 *
 * The provider-contract run below uses explicit development-only providers via
 * the API-only `allowDevelopmentProviders` switch. That is not market evidence:
 * eligibility is non-eligible before signing, so no attestation and no entry
 * N+1 may exist. The CLI never enables this switch.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync } from 'node:fs'

import { createDevelopmentArchiveProvider, createDevelopmentSigningProvider } from '../../../src/evidence/index.js'
import { runMarketGate } from '../../../src/market/gate.js'
import {
  REAL_ANCHOR,
  REAL_CONTRACT_EVIDENCE,
  approvalsFor,
  makePassReceipt,
  positiveIsolation,
  tempDir,
  validPolicy,
} from './_fixtures.js'

function countEntryFiles(dir) {
  return readdirSync(dir).filter((name) => /^entry-\d{12}-[0-9a-f]{64}\.json$/.test(name)).length
}

test('order: dev providers reach eligibility only; non-eligible stops before sign/entry N+1', async (t) => {
  const { receipt, path } = await makePassReceipt(t)
  const policy = validPolicy()
  const nowIso = new Date().toISOString()
  const isolation = positiveIsolation(receipt, policy, nowIso)
  const archiveDir = tempDir(t, 'market-dev-archive-')
  const result = await runMarketGate({
    receipt: path,
    policy,
    runtimeAnchor: REAL_ANCHOR,
    contractEvidenceDir: REAL_CONTRACT_EVIDENCE,
    isolationAttestation: isolation.attestation,
    a2Evidence: isolation.a2Evidence,
    isolationProvider: isolation.provider,
    hostFacts: isolation.hostFacts,
    approvals: approvalsFor(receipt, policy, nowIso),
    signingProvider: createDevelopmentSigningProvider(),
    archiveProvider: createDevelopmentArchiveProvider({ dir: archiveDir }),
    allowDevelopmentProviders: true,
    controlPlane: { id: 'market-gate-test', version: '1.0.0' },
  })

  assert.equal(result.exit_code, 2)
  assert.equal(result.publish, false)
  assert.equal(result.market_eligible, false)
  assert.equal(result.failure_stage, 'eligibility')
  assert.ok(result.eligibility !== null, 'eligibility sidecar must be produced after entry N')
  assert.equal(result.eligibility.decision, 'non-eligible')
  assert.equal(result.eligibility.schema_version, 'market-eligibility/v1')
  assert.ok(result.reason_codes.includes('development-only-not-market-evidence'))
  assert.equal(result.attestation, null, 'a non-eligible decision must never be signed')
  assert.equal(result.verification, null)
  assert.equal(countEntryFiles(archiveDir), 1, 'only subject entry N exists; no entry N+1')
  const conditions = new Map(result.conditions.map((condition) => [condition.id, condition.status]))
  assert.equal(conditions.get('MKT-C01'), 'pass', 'positive isolation contract input is admitted')
  assert.equal(conditions.get('MKT-C04'), 'pass')
  assert.equal(conditions.get('MKT-C05'), 'fail', 'development signer is not market independent')
  assert.equal(conditions.get('MKT-C06'), 'fail', 'development archive is not market independent')
})

test('order: missing archive provider blocks at archive-subject before eligibility', async (t) => {
  const { receipt, path } = await makePassReceipt(t)
  const policy = validPolicy()
  const nowIso = new Date().toISOString()
  const isolation = positiveIsolation(receipt, policy, nowIso)
  const { createBlockedArchiveProvider } = await import('../../../src/evidence/index.js')
  const result = await runMarketGate({
    receipt: path,
    policy,
    runtimeAnchor: REAL_ANCHOR,
    contractEvidenceDir: REAL_CONTRACT_EVIDENCE,
    isolationAttestation: isolation.attestation,
    a2Evidence: isolation.a2Evidence,
    isolationProvider: isolation.provider,
    hostFacts: isolation.hostFacts,
    approvals: approvalsFor(receipt, policy, nowIso),
    signingProvider: createDevelopmentSigningProvider(),
    archiveProvider: createBlockedArchiveProvider(),
    allowDevelopmentProviders: true,
  })

  assert.equal(result.exit_code, 2)
  assert.equal(result.failure_stage, 'archive-subject')
  assert.equal(result.eligibility, null, 'eligibility must not be produced without entry N')
  assert.equal(result.attestation, null)
  assert.equal(result.publish, false)
  assert.ok(
    result.reason_codes.includes('archive-provider-missing') || result.reason_codes.includes('archive-append-failed'),
    result.reason_codes.join(','),
  )
})
