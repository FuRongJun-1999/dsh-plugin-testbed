/**
 * Market policy + approval/waiver contract tests (t8 / MKT-02/MKT-05/MKT-06).
 *
 * These are contract tests for the frozen policy and the approval ledger. They
 * never claim market eligibility: the real environment still fails every
 * provider condition, and a valid waiver never changes a required status.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { validateMarketPolicy, policyDigest } from '../../../src/market/policy.js'
import { validateApprovalLedger } from '../../../src/market/approvals.js'
import { MARKET_CONDITION_IDS } from '../../../src/protocol/market-schemas.js'
import {
  approvalsFor,
  makePassReceipt,
  recordDigest,
  validPolicy,
  waiverFor,
} from './_fixtures.js'

const NOW = Date.now()

test('market policy: a frozen, fail-closed policy validates and has a stable digest', () => {
  const policy = validPolicy()
  const result = validateMarketPolicy(policy, NOW)
  assert.equal(result.ok, true, result.errors.join(','))
  assert.equal(result.policy.requiredIsolation, 'L2')
  assert.equal(result.policy.maxAttestationAgeMs, 3_000_000)
  assert.deepEqual(result.policy.approvalRoles, ['security', 'release'])
  assert.equal(result.policy.requiredConditions.length, 10)
  assert.match(result.digest, /^sha256:[0-9a-f]{64}$/)
  assert.equal(policyDigest(policy), result.digest)
  assert.equal(policyDigest(structuredClone(policy)), result.digest)
})

test('market policy: unknown version/field and every relaxation are rejected', () => {
  const cases = [
    ['unknown-version', validPolicy({ schema_version: 'market-gate-policy/v2' })],
    ['unknown-field', { ...validPolicy(), unexpected: true }],
    ['fail-closed-false', validPolicy({ fail_closed: false })],
    ['separation-false', validPolicy({ separation_of_duties: false })],
    ['waiver-hard-condition-missing', validPolicy({ waiver_rules: { forbidden_for: ['MKT-C01'] } })],
    ['no-active-signer', validPolicy({ allowed_signers: [{ key_id: 'k', alg: 'ed25519', state: 'revoked' }] })],
    ['required-suite-missing', validPolicy({ required_suites: ['A2'] })],
    ['isolation-inconsistent', validPolicy({ isolation: { required_level: 'L3' } })],
    ['evidence-age-invalid', validPolicy({ evidence_max_age_hours: 0 })],
    ['empty-runtimes', validPolicy({ allowed_runtimes: [] })],
  ]
  for (const [label, policy] of cases) {
    const result = validateMarketPolicy(policy, NOW)
    assert.equal(result.ok, false, `${label} should be rejected`)
    assert.ok(result.reasonCodes.includes('market-policy-invalid'), `${label} reason codes: ${result.reasonCodes}`)
  }
})

test('market policy: required_conditions is fixed to all 10; partial/omitted are policy-invalid', () => {
  assert.deepEqual(validPolicy().required_conditions, [...MARKET_CONDITION_IDS])

  const partial = validPolicy({ required_conditions: ['MKT-C03', 'MKT-C04'] })
  const partialResult = validateMarketPolicy(partial, NOW)
  assert.equal(partialResult.ok, false)
  assert.ok(partialResult.reasonCodes.includes('market-policy-invalid'))
  assert.ok(
    partialResult.errors.some((error) => /minItems|required-conditions-must-be-all/.test(error)),
    partialResult.errors.join(','),
  )

  const omitted = validPolicy()
  delete omitted.required_conditions
  const omittedResult = validateMarketPolicy(omitted, NOW)
  assert.equal(omittedResult.ok, false)
  assert.ok(omittedResult.reasonCodes.includes('market-policy-invalid'))
  assert.ok(
    omittedResult.errors.some((error) => /required-missing:required_conditions/.test(error)),
    omittedResult.errors.join(','),
  )

  const nine = validPolicy({ required_conditions: MARKET_CONDITION_IDS.slice(0, 9) })
  assert.equal(validateMarketPolicy(nine, NOW).ok, false)

  const duplicate = validPolicy({
    required_conditions: [...MARKET_CONDITION_IDS.slice(0, 9), MARKET_CONDITION_IDS[0]],
  })
  assert.equal(validateMarketPolicy(duplicate, NOW).ok, false)

  const unknown = validPolicy({
    required_conditions: [...MARKET_CONDITION_IDS.slice(0, 9), 'MKT-C99'],
  })
  assert.equal(validateMarketPolicy(unknown, NOW).ok, false)
})

test('market policy: effective window is wall-clock checked (not-yet-effective / expired)', () => {
  const notYet = validateMarketPolicy(validPolicy({ effective_from: '2026-12-01T00:00:00Z' }), NOW)
  assert.equal(notYet.ok, false)
  assert.ok(notYet.reasonCodes.includes('market-policy-not-effective'))
  const expired = validateMarketPolicy(validPolicy({ effective_until: '2026-10-01T00:00:00Z' }), NOW)
  assert.equal(expired.ok, false)
  assert.ok(expired.reasonCodes.includes('market-policy-expired'))
})

test('approvals: two distinct roles/principals satisfy the ledger; receipt digest is bound', async (t) => {
  const { receipt } = await makePassReceipt(t)
  const policy = validPolicy()
  const policyView = validateMarketPolicy(policy, NOW).policy
  const ledger = validateApprovalLedger(approvalsFor(receipt, policy, new Date(NOW).toISOString()), [], {
    policy: policyView,
    receiptDigest: recordDigest(receipt),
    runId: receipt.run_id,
    targetDigest: receipt.target_ref.owner_put_digest,
    requiredIsolation: 'L2',
    earliestStartedAtMs: Date.parse(receipt.test_cases[0].attempts[0].started_at),
    nowMs: NOW,
    forbiddenPrincipals: ['kms-signer', 'worm-archive-1'],
  })
  assert.equal(ledger.ok, true, ledger.errors.join(','))
  assert.deepEqual(ledger.approvedRoles.sort(), ['release', 'security'])
  assert.equal(ledger.approvalDigests.length, 2)
})

test('approvals: missing, self, duplicate, wrong-role, expired, unsigned and out-of-scope are rejected', async (t) => {
  const { receipt } = await makePassReceipt(t)
  const policy = validPolicy()
  const policyView = validateMarketPolicy(policy, NOW).policy
  const base = approvalsFor(receipt, policy, new Date(NOW).toISOString())
  const context = {
    policy: policyView,
    receiptDigest: recordDigest(receipt),
    runId: receipt.run_id,
    targetDigest: receipt.target_ref.owner_put_digest,
    requiredIsolation: 'L2',
    earliestStartedAtMs: Date.parse(receipt.test_cases[0].attempts[0].started_at),
    nowMs: NOW,
    forbiddenPrincipals: ['kms-signer'],
  }
  const run = (approvals, waivers = []) => validateApprovalLedger(approvals, waivers, context)

  const missing = run(undefined)
  assert.equal(missing.ok, false)
  assert.ok(missing.reasonCodes.includes('market-approval-missing'))

  const selfApproved = structuredClone(base)
  selfApproved[0].principal = 'kms-signer'
  assert.ok(run(selfApproved).reasonCodes.includes('market-approval-self'))

  const duplicatePrincipal = structuredClone(base)
  duplicatePrincipal[1].principal = duplicatePrincipal[0].principal
  assert.ok(run(duplicatePrincipal).reasonCodes.includes('market-approval-self'))

  const oneRole = [base[0]]
  assert.ok(run(oneRole).reasonCodes.includes('market-approval-role'))

  const expired = structuredClone(base)
  expired[0].expires_at = '2026-10-18T00:00:00Z'
  assert.ok(run(expired).reasonCodes.includes('market-approval-expired'))

  const unsigned = structuredClone(base)
  unsigned[0].signature_ref = null
  assert.ok(run(unsigned).reasonCodes.includes('market-approval-missing'))

  const wrongTarget = structuredClone(base)
  wrongTarget[0].scope.target_digest = 'sha256:' + '0'.repeat(64)
  assert.ok(run(wrongTarget).reasonCodes.includes('market-approval-out-of-scope'))

  const postExecution = structuredClone(base)
  postExecution[0].at = new Date(NOW + 3_600_000).toISOString()
  assert.ok(run(postExecution).reasonCodes.includes('market-approval-expired'))

  const earliest = Date.parse(receipt.test_cases[0].attempts[0].started_at ?? '')
  if (Number.isFinite(earliest)) {
    const afterStart = structuredClone(base)
    afterStart[0].at = new Date(earliest + 60_000).toISOString()
    assert.ok(run(afterStart).reasonCodes.includes('market-approval-expired'))
  }
})

test('waivers: scoped/valid is recorded but never changes a status; forbidden/expired/self are rejected', async (t) => {
  const { receipt } = await makePassReceipt(t)
  const policy = validPolicy()
  const policyView = validateMarketPolicy(policy, NOW).policy
  const context = {
    policy: policyView,
    receiptDigest: recordDigest(receipt),
    runId: receipt.run_id,
    targetDigest: receipt.target_ref.owner_put_digest,
    requiredIsolation: 'L2',
    earliestStartedAtMs: Date.parse(receipt.test_cases[0].attempts[0].started_at),
    nowMs: NOW,
    forbiddenPrincipals: [],
  }
  const approvals = approvalsFor(receipt, policy, new Date(NOW).toISOString())
  const valid = validateApprovalLedger(approvals, [waiverFor(receipt, policy, new Date(NOW).toISOString())], context)
  assert.equal(valid.ok, true, valid.errors.join(','))
  assert.equal(valid.waivers.length, 1)
  assert.equal(valid.waiverDigests.length, 1)
  assert.ok(valid.limitations.includes('valid-waivers-recorded-never-change-required-status'))

  const forbidden = waiverFor(receipt, policy, new Date(NOW).toISOString(), { condition_id: 'MKT-C01' })
  assert.ok(validateApprovalLedger(approvals, [forbidden], context).reasonCodes.includes('market-waiver-forbidden'))

  const expired = waiverFor(receipt, policy, new Date(NOW).toISOString(), { expires_at: '2026-10-18T00:00:00Z' })
  assert.ok(validateApprovalLedger(approvals, [expired], context).reasonCodes.includes('market-waiver-expired'))

  const selfApproved = waiverFor(receipt, policy, new Date(NOW).toISOString(), { approved_by: 'requester-1' })
  assert.ok(validateApprovalLedger(approvals, [selfApproved], context).reasonCodes.includes('market-waiver-invalid'))
})
