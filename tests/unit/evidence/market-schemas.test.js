/**
 * 单元 · market evidence schemas + canonical signing input（node:test）。
 *
 * 覆盖 NEXT-PHASE-REQUIREMENTS §6.4–§6.6、SIG-01/SIG-05/SIG-09：
 *  - 所有市场证据 schema 均为 Draft 2020-12 元结构、版本冻结、闭合字段；
 *  - 未知主版本拒绝（不隐式降级）；
 *  - 签名输入只排除 `signing.signature`（及保留字段 `attestation_archive`），
 *    其余字段（含 anchor_N 与 provider_audit_ref）全部被签名覆盖；
 *  - `receipt/v1` 继续拒绝 signature / signed=true / market_eligible 等形态。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  ARCHIVE_DEVELOPMENT_MODES,
  ARCHIVE_MARKET_MODES,
  EVIDENCE_REASON_CODES,
  MARKET_SCHEMA_BY_VERSION,
  MARKET_SCHEMA_VERSIONS,
  PROVIDER_TRUST_CLASSES,
  SIGNING_ALGORITHMS,
  SIGNING_KEY_STATES,
  isArchiveAnchorVersion,
  isArchiveChainVerificationVersion,
  isArchiveEntryVersion,
  isMarketArchiveVersion,
  isMarketAttestationVerificationVersion,
  isMarketAttestationVersion,
  isSigningProviderVersion,
  isSigningRequestVersion,
  isSigningResponseVersion,
  marketSchemaForVersion,
} from '../../../src/protocol/market-schemas.js'
import { JSON_SCHEMA_DRAFT_2020_12, validateSchemaMeta } from '../../../src/protocol/jsonschema.js'
import { validateReceiptV1 } from '../../../src/protocol/contracts.js'
import {
  attestationSigningBytes,
  attestationSigningDigest,
  base64urlDecode,
  base64urlEncode,
  marketAttestationDigest,
} from '../../../src/evidence/canonical.js'
import { DIGEST, FIXED_TIME, makeValidReceipt } from './_fixtures.js'

function sampleAttestation() {
  return {
    schema_version: 'market-attestation/v1',
    attestation_id: 'attestation-fixture-001',
    subject: {
      receipt_schema_version: 'receipt/v1',
      run_id: 'run-evidence-001',
      plan_id: 'plan-sha256:' + '6'.repeat(64),
      record_digest: DIGEST('9'),
    },
    eligibility: {
      schema_version: 'market-eligibility/v1',
      decision_digest: DIGEST('b'),
    },
    control_plane: {
      id: 'control-plane-development',
      version: '0.0.1-development',
      policy_ref: { id: 'market-gate-policy', version: '1.0.0', digest: DIGEST('a') },
    },
    isolation: {
      level: 'L1',
      attestation_digest: DIGEST('e'),
      verification_digest: DIGEST('f'),
    },
    runtime: {
      cordis_version: '4.0.5',
      dsh_version: '0.2.1-rc.2',
      anchor_digest: DIGEST('7'),
      contract_suite_digest: DIGEST('d'),
    },
    signing: {
      provider_id: 'development-signer',
      key_id: 'key-ed25519-fixture',
      alg: 'ed25519',
      signature: 'c2lnbmF0dXJl',
      signed_at: FIXED_TIME,
      provider_audit_ref: 'dev-audit:request-1',
    },
    archive: {
      provider_id: 'development-archive-local-file',
      anchor_id: `run-evidence-001:1:${DIGEST('1')}`,
      sequence: 1,
      entry_digest: DIGEST('1'),
      archived_at: FIXED_TIME,
    },
    limitations: ['controlled-fixture'],
  }
}

test('market schemas: 九个版本全部登记，lookup 只解析精确版本', () => {
  assert.deepEqual(Object.keys(MARKET_SCHEMA_BY_VERSION).sort(), [...MARKET_SCHEMA_VERSIONS].sort())
  assert.equal(MARKET_SCHEMA_VERSIONS.length, 9)
  for (const version of MARKET_SCHEMA_VERSIONS) {
    assert.equal(marketSchemaForVersion(version), MARKET_SCHEMA_BY_VERSION[version], version)
  }
  for (const unknown of ['signing-provider/v2', 'market-attestation/v1.0', 'archive-entry/v1 ', '', null, 42, 'receipt/v1']) {
    assert.equal(marketSchemaForVersion(unknown), null, String(unknown))
  }
})

test('market schemas: 每个 schema 是闭合的 Draft 2020-12 元结构且已冻结', () => {
  for (const version of MARKET_SCHEMA_VERSIONS) {
    const schema = MARKET_SCHEMA_BY_VERSION[version]
    assert.equal(schema.$schema, JSON_SCHEMA_DRAFT_2020_12, version)
    assert.ok(schema.$id.startsWith('urn:dsh:plugin-testbed:'), `${version}: ${schema.$id}`)
    assert.equal(schema.additionalProperties, false, `${version} must close its surface`)
    assert.equal(Object.isFrozen(schema), true, `${version} must be immutable`)
    const meta = validateSchemaMeta(schema)
    assert.equal(meta.ok, true, `${version}: ${JSON.stringify(meta.errors)}`)
  }
})

test('market schemas: 版本守卫拒绝 v2/变体，不隐式降级', () => {
  const table = [
    [isSigningProviderVersion, 'signing-provider/v1', ['signing-provider/v2', 'signing-provider']],
    [isSigningRequestVersion, 'signing-request/v1', ['signing-request/v2']],
    [isSigningResponseVersion, 'signing-response/v1', ['signing-response/v2']],
    [isMarketAttestationVersion, 'market-attestation/v1', ['market-attestation/v2']],
    [isMarketAttestationVerificationVersion, 'market-attestation-verification/v1', ['market-attestation-verification/v2']],
    [isMarketArchiveVersion, 'market-archive/v1', ['market-archive/v2']],
    [isArchiveEntryVersion, 'archive-entry/v1', ['archive-entry/v2']],
    [isArchiveAnchorVersion, 'archive-anchor/v1', ['archive-anchor/v2']],
    [isArchiveChainVerificationVersion, 'archive-chain-verification/v1', ['archive-chain-verification/v2']],
  ]
  for (const [guard, known, unknown] of table) {
    assert.equal(guard(known), true, known)
    for (const value of unknown) assert.equal(guard(value), false, value)
  }
})

test('market vocabularies: 算法 allowlist、密钥状态、信任类别与归档模式固定', () => {
  assert.deepEqual([...SIGNING_ALGORITHMS], ['ed25519', 'ecdsa-p256-sha256'])
  assert.deepEqual([...SIGNING_KEY_STATES], ['active', 'rotated', 'revoked'])
  assert.ok(PROVIDER_TRUST_CLASSES.includes('development-only'))
  assert.ok(PROVIDER_TRUST_CLASSES.includes('unavailable'))
  assert.ok(ARCHIVE_MARKET_MODES.includes('object-lock'))
  assert.ok(!ARCHIVE_MARKET_MODES.includes('local-file'))
  assert.deepEqual([...ARCHIVE_DEVELOPMENT_MODES], ['local-file', 'git'])
  assert.equal(EVIDENCE_REASON_CODES.DEVELOPMENT_ONLY_NOT_MARKET, 'development-only-not-market-evidence')
})

test('canonical signing input: 只排除 signature 与保留字段，anchor/audit-ref 均被覆盖', () => {
  const base = sampleAttestation()
  const baseDigest = attestationSigningDigest(base)

  const signatureChanged = structuredClone(base)
  signatureChanged.signing.signature = 'b3RoZXItc2ln'
  assert.equal(attestationSigningDigest(signatureChanged), baseDigest, 'signature must not be signed')

  const reserved = structuredClone(base)
  reserved.attestation_archive = { schema_version: 'x', digest: DIGEST('3') }
  assert.equal(attestationSigningDigest(reserved), baseDigest, 'reserved attestation_archive must be excluded')

  for (const mutate of [
    (copy) => { copy.archive.entry_digest = DIGEST('2') },
    (copy) => { copy.signing.provider_audit_ref = 'dev-audit:other' },
    (copy) => { copy.signing.signed_at = '2026-01-01T00:00:09.000Z' },
    (copy) => { copy.subject.record_digest = DIGEST('0') },
    (copy) => { copy.isolation.level = 'L2' },
  ]) {
    const changed = structuredClone(base)
    mutate(changed)
    assert.notEqual(attestationSigningDigest(changed), baseDigest)
  }

  assert.deepEqual(attestationSigningBytes(base).toString('utf8'), attestationSigningBytes(signatureChanged).toString('utf8'))
  assert.notEqual(marketAttestationDigest(signatureChanged), marketAttestationDigest(base))
})

test('canonical base64url: 无 padding、拒绝非法/带 padding 输入', () => {
  const bytes = Buffer.from('canonical-bytes')
  const encoded = base64urlEncode(bytes)
  assert.match(encoded, /^[A-Za-z0-9_-]+$/)
  assert.deepEqual(base64urlDecode(encoded), bytes)
  for (const bad of ['', 'abc=', 'a+b/', '==', null, 1, true]) {
    assert.equal(base64urlDecode(bad), null, String(bad))
  }
})

test('receipt/v1: 继续拒绝 signature / signed=true / market_eligible=true 等市场形态', () => {
  const valid = makeValidReceipt()
  assert.equal(validateReceiptV1(valid, { verifyDigest: true }).ok, true)

  const cases = [
    ['signature', (copy) => { copy.signature = 'not-allowed' }],
    ['signed-true', (copy) => { copy.integrity.signed = true }],
    ['top-level-signing', (copy) => { copy.signing = { provider_id: 'p', key_id: 'k' } }],
    ['archive-anchor', (copy) => { copy.archive = { anchor_id: 'a' } }],
    ['market-eligible', (copy) => { copy.market_eligible = true }],
    ['unknown-field', (copy) => { copy.market_attestation = { attestation_id: 'a' } }],
  ]
  for (const [label, mutate] of cases) {
    const receipt = structuredClone(valid)
    mutate(receipt)
    const result = validateReceiptV1(receipt)
    assert.equal(result.ok, false, `${label} must be rejected`)
  }
})
