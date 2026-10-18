/**
 * Real runtime evidence + market gate + CLI exit-code tests (t8 / MKT-01/08).
 *
 * The gate is run against the actual t7 anchor/contract evidence and the t4
 * Windows L2 execution evidence. In this environment it must remain
 * non-eligible/blocked with exit 2 — never 0 — and receipt/v1 must stay
 * byte-identical.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { cpSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { verifyRuntimeEvidence } from '../../../src/market/runtime.js'
import { runMarketGate } from '../../../src/market/gate.js'
import { validateMarketPolicy } from '../../../src/market/policy.js'
import { recordDigest } from '../../../src/protocol/digest.js'
import { verifyEvidencePackage } from '../../../src/market/evidence-package.js'
import {
  REAL_ANCHOR,
  REAL_ANCHOR_BASE,
  REAL_CONTRACT_EVIDENCE,
  ROOT,
  T4_EXECUTION_EVIDENCE,
  makePassReceipt,
  tempDir,
  validPolicy,
} from './_fixtures.js'

const NOW = Date.now()

function policyView() {
  return validateMarketPolicy(validPolicy(), NOW).policy
}

test('runtime evidence: real t7 anchor + contract results verify and bind every digest', async () => {
  const evidence = await verifyRuntimeEvidence({
    anchor: REAL_ANCHOR,
    contractEvidenceDir: REAL_CONTRACT_EVIDENCE,
    policy: policyView(),
    nowMs: NOW,
  })
  assert.equal(evidence.status, 'available', evidence.detail ?? '')
  assert.equal(evidence.contractPassed, true)
  assert.equal(evidence.cordisVersion, '4.0.5')
  assert.equal(evidence.dshVersion, '0.2.1-rc.2')
  assert.match(evidence.anchorDigest, /^sha256:[0-9a-f]{64}$/)
  assert.match(evidence.contractSuiteDigest, /^sha256:[0-9a-f]{64}$/)
  const anchor = JSON.parse(readFileSync(REAL_ANCHOR, 'utf8'))
  const results = JSON.parse(readFileSync(join(REAL_CONTRACT_EVIDENCE, 'cordis-contract-results.v1.json'), 'utf8'))
  assert.equal(evidence.anchorDigest, results.runtime_anchor_digest)
  assert.match(String(anchor.entry), /cordis[\\/]lib[\\/]index\.js$/)
})

test('runtime evidence: app.asar, fixture, version/digest/environment drift are blocked', async () => {
  const anchor = JSON.parse(readFileSync(REAL_ANCHOR, 'utf8'))
  const policy = policyView()

  const asar = structuredClone(anchor)
  asar.entry = 'file:///D:/DeepSeek%20Harness/resources/app.asar/node_modules/@deepseek-ai/cordis/lib/index.js'
  const asarResult = await verifyRuntimeEvidence({ anchor: asar, runtimeBaseDir: REAL_ANCHOR_BASE, contractEvidenceDir: REAL_CONTRACT_EVIDENCE, policy, nowMs: NOW })
  assert.equal(asarResult.status, 'blocked')
  assert.ok(asarResult.reasonCodes.includes('runtime-anchor-app-asar-rejected'))

  const fixture = structuredClone(anchor)
  fixture.runtime_kind = 'test-fixture'
  const fixtureResult = await verifyRuntimeEvidence({ anchor: fixture, runtimeBaseDir: REAL_ANCHOR_BASE, contractEvidenceDir: REAL_CONTRACT_EVIDENCE, policy, nowMs: NOW })
  assert.ok(fixtureResult.reasonCodes.includes('runtime-anchor-fixture-rejected'))

  const version = structuredClone(anchor)
  version.package_version = '4.0.6'
  const versionResult = await verifyRuntimeEvidence({ anchor: version, runtimeBaseDir: REAL_ANCHOR_BASE, contractEvidenceDir: REAL_CONTRACT_EVIDENCE, policy, nowMs: NOW })
  assert.equal(versionResult.status, 'blocked')
  assert.ok(versionResult.reasonCodes.includes('runtime-version-mismatch'))

  const digest = structuredClone(anchor)
  digest.entry_digest = 'sha256:' + '0'.repeat(64)
  const digestResult = await verifyRuntimeEvidence({ anchor: digest, runtimeBaseDir: REAL_ANCHOR_BASE, contractEvidenceDir: REAL_CONTRACT_EVIDENCE, policy, nowMs: NOW })
  assert.ok(digestResult.reasonCodes.includes('runtime-entry-digest-mismatch'))

  const nodeVersion = structuredClone(anchor)
  nodeVersion.node_version = 'v22.0.0'
  const envResult = await verifyRuntimeEvidence({ anchor: nodeVersion, runtimeBaseDir: REAL_ANCHOR_BASE, contractEvidenceDir: REAL_CONTRACT_EVIDENCE, policy, nowMs: NOW })
  assert.ok(envResult.reasonCodes.includes('runtime-environment-mismatch'))
})

test('runtime evidence: tampered contract suite/results and stale copies are blocked', async (t) => {
  const dir = tempDir(t, 'market-contract-tamper-')
  cpSync(REAL_CONTRACT_EVIDENCE, dir, { recursive: true })
  const policy = policyView()

  const suitePath = join(dir, 'cordis-contract-suite.v1.json')
  const suite = JSON.parse(readFileSync(suitePath, 'utf8'))
  suite.suite_version = '9.9.9'
  writeFileSync(suitePath, JSON.stringify(suite), 'utf8')
  const suiteResult = await verifyRuntimeEvidence({ anchor: REAL_ANCHOR, contractEvidenceDir: dir, policy, nowMs: NOW })
  assert.ok(suiteResult.reasonCodes.includes('runtime-contract-suite-failed'), suiteResult.reasonCodes.join(','))

  cpSync(REAL_CONTRACT_EVIDENCE, dir, { recursive: true })
  const resultsPath = join(dir, 'cordis-contract-results.v1.json')
  const results = JSON.parse(readFileSync(resultsPath, 'utf8'))
  results.environment.node_version = 'v22.0.0'
  writeFileSync(resultsPath, JSON.stringify(results), 'utf8')
  const envResult = await verifyRuntimeEvidence({ anchor: REAL_ANCHOR, contractEvidenceDir: dir, policy, nowMs: NOW })
  assert.ok(envResult.reasonCodes.includes('runtime-environment-mismatch'), envResult.reasonCodes.join(','))

  const stalePolicy = validateMarketPolicy(validPolicy({ evidence_max_age_hours: 1 }), NOW + 48 * 3_600_000).policy
  const stale = await verifyRuntimeEvidence({
    anchor: REAL_ANCHOR,
    contractEvidenceDir: REAL_CONTRACT_EVIDENCE,
    policy: stalePolicy,
    nowMs: NOW + 48 * 3_600_000,
  })
  assert.equal(stale.status, 'blocked')
  assert.ok(stale.reasonCodes.includes('market-evidence-stale'), stale.reasonCodes.join(','))
})

test('market gate real environment: real runtime passes C03, everything else blocks, exit 2, no publish', async (t) => {
  const { receipt, path } = await makePassReceipt(t)
  const before = readFileSync(path, 'utf8')
  const result = await runMarketGate({
    receipt: path,
    policy: validPolicy(),
    runtimeAnchor: REAL_ANCHOR,
    contractEvidenceDir: REAL_CONTRACT_EVIDENCE,
    isolationAttestation: T4_EXECUTION_EVIDENCE,
  })
  assert.equal(result.exit_code, 2)
  assert.equal(result.status, 'non-eligible')
  assert.equal(result.market_eligible, false)
  assert.equal(result.publish, false)
  assert.equal(result.runtime.status, 'available')
  assert.equal(result.conditions.find((condition) => condition.id === 'MKT-C03').status, 'pass')
  assert.equal(result.conditions.find((condition) => condition.id === 'MKT-C04').status, 'pass')
  assert.equal(result.conditions.find((condition) => condition.id === 'MKT-C01').status, 'fail')
  assert.ok(result.reason_codes.includes('signing-provider-missing'))
  assert.ok(result.reason_codes.includes('archive-provider-missing'))
  assert.ok(result.reason_codes.includes('market-approval-missing'))
  assert.equal(result.eligibility, null)
  assert.equal(result.attestation, null)
  assert.equal(result.receipt_unchanged, true)
  assert.equal(readFileSync(path, 'utf8'), before, 'receipt/v1 must not change')
  assert.equal(recordDigest(receipt), result.receipt_digest)
})

test('market gate: missing/invalid policy is exit 2; invalid receipt is exit 3', async (t) => {
  const { path, receipt } = await makePassReceipt(t)
  const noPolicy = await runMarketGate({ receipt: path })
  assert.equal(noPolicy.exit_code, 2)
  assert.ok(noPolicy.reason_codes.includes('market-policy-missing'))

  const invalidPolicy = await runMarketGate({ receipt: path, policy: validPolicy({ fail_closed: false }) })
  assert.equal(invalidPolicy.exit_code, 2)
  assert.ok(invalidPolicy.reason_codes.includes('market-policy-invalid'))

  const partialConditions = await runMarketGate({
    receipt: path,
    policy: validPolicy({ required_conditions: ['MKT-C03', 'MKT-C04'] }),
  })
  assert.equal(partialConditions.exit_code, 2)
  assert.ok(partialConditions.reason_codes.includes('market-policy-invalid'))
  assert.equal(partialConditions.conditions.length, 0, 'invalid policy must not produce eligibility conditions')

  const invalidReceipt = await runMarketGate({
    receipt: { receipt_schema_version: 'receipt/v1' },
    policy: validPolicy(),
  })
  assert.equal(invalidReceipt.exit_code, 3)
  assert.ok(invalidReceipt.reason_codes.includes('market-receipt-invalid'))

  const forged = structuredClone(receipt)
  forged.market_eligible = true
  const forgedResult = await runMarketGate({ receipt: forged, policy: validPolicy() })
  assert.equal(forgedResult.exit_code, 3)
})

test('market gate: evidence package sidecar is written and independently verifiable', async (t) => {
  const { path } = await makePassReceipt(t)
  const out = tempDir(t, 'market-evidence-out-')
  const result = await runMarketGate({
    receipt: path,
    policy: validPolicy(),
    runtimeAnchor: REAL_ANCHOR,
    contractEvidenceDir: REAL_CONTRACT_EVIDENCE,
    isolationAttestation: T4_EXECUTION_EVIDENCE,
    evidenceOutDir: out,
  })
  assert.equal(result.exit_code, 2)
  assert.ok(result.evidence_package !== null, result.limitations.join(';'))
  const verified = await verifyEvidencePackage(result.evidence_package, { root: out, rejectUnregistered: true })
  assert.equal(verified.ok, true, verified.errors.join(','))
  assert.ok(verified.artifactPaths.includes('market-gate-result.json'))
})

test('CLI: market verb stays fail-closed (2/3) and legacy market-required profile stays 2', async (t) => {
  const { path } = await makePassReceipt(t)
  const policyPath = join(tempDir(t, 'market-policy-'), 'policy.json')
  writeFileSync(policyPath, JSON.stringify(validPolicy(), null, 2), 'utf8')
  const cli = join(ROOT, 'bin', 'selfcheck.js')

  const missingArgs = spawnSync(process.execPath, [cli, 'market'], { cwd: ROOT, encoding: 'utf8' })
  assert.equal(missingArgs.status, 3)

  const badReceipt = spawnSync(process.execPath, [cli, 'market', '--receipt', 'does-not-exist.json', '--policy', policyPath], { cwd: ROOT, encoding: 'utf8' })
  assert.equal(badReceipt.status, 3)

  const market = spawnSync(process.execPath, [
    cli, 'market',
    '--receipt', path,
    '--policy', policyPath,
    '--runtime-anchor', REAL_ANCHOR,
    '--contract-evidence-dir', REAL_CONTRACT_EVIDENCE,
    '--isolation-attestation', T4_EXECUTION_EVIDENCE,
  ], { cwd: ROOT, encoding: 'utf8', timeout: 120_000 })
  assert.equal(market.status, 2, market.stderr)
  const parsed = JSON.parse(market.stdout)
  assert.equal(parsed.status, 'non-eligible')
  assert.equal(parsed.publish, false)
  assert.equal(parsed.exit_code, 2)
  assert.equal(parsed.conditions.find((condition) => condition.id === 'MKT-C03').status, 'pass')

  const legacyOut = tempDir(t, 'market-legacy-')
  const legacy = spawnSync(process.execPath, [
    cli, 'selfcheck',
    '--spec', join(ROOT, 'tests', 'fixtures', 'cli-smoke.json'),
    '--profile', 'market-required/v1',
    '--receipt-out', legacyOut,
  ], { cwd: ROOT, encoding: 'utf8', timeout: 120_000 })
  assert.equal(legacy.status, 2)
  const legacyResult = JSON.parse(legacy.stdout)
  assert.equal(legacyResult.marketEligible, false)
  assert.equal(legacyResult.trustScope, 'local-only')
})
