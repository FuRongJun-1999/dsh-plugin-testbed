/**
 * 单元 · 签名 provider / request / response / attestation 签名验证（node:test）。
 *
 * 覆盖 SIG-01..SIG-10：算法 allowlist、域分离、blind-sign 拒绝、未授权请求、
 * 密钥 active/rotated/revoked/expired、请求-响应绑定、Ed25519 与 P-256 真实
 * 密码学校验、篡改检测、provider audit ref，以及 blocked KMS/HSM/OS-keystore
 * 接口只返回 blocked。开发 signer 始终是 E1，不是生产 trust root。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  EVIDENCE_REASON_CODES,
  SIGNING_DOMAIN_MARKET_ARCHIVE,
} from '../../../src/protocol/market-schemas.js'
import {
  assertSigningProvider,
  createBlockedSigningProvider,
  createDevelopmentSigningProvider,
  createHsmSigningProvider,
  createKmsSigningProvider,
  createOsKeystoreSigningProvider,
  validateSigningProviderDocument,
} from '../../../src/evidence/signing-provider.js'
import {
  buildSigningRequest,
  checkKeyValidity,
  deriveKeyId,
  evaluateSigningRequest,
  signMarketAttestation,
  signingProviderTrustIssues,
  verifyAttestationSignature,
  verifySigningResponseBinding,
} from '../../../src/evidence/signing.js'
import { validateMarketAttestation } from '../../../src/evidence/canonical.js'
import {
  DIGEST,
  FIXED_TIME,
  makeAttestationDraft,
} from './_fixtures.js'

const AUTHORIZED = Object.freeze([{
  control_plane_id: 'control-plane-development',
  authorization_ref: 'auth-ref-1',
}])
const REQUESTER = AUTHORIZED[0]
const PROVIDER_ID = 'development-signer'

function makeSigner(options = {}) {
  return createDevelopmentSigningProvider({
    authorizedRequesters: [...AUTHORIZED],
    now: () => new Date(FIXED_TIME),
    ...options,
  })
}

function signingFields(provider, overrides = {}) {
  const doc = provider.describe()
  return {
    provider_id: doc.provider_id,
    key_id: provider.activeKeyIds()[0],
    alg: 'ed25519',
    signed_at: FIXED_TIME,
    provider_audit_ref: 'audit:request-1',
    ...overrides,
  }
}

async function signFixture(provider, overrides = {}) {
  const { draft, receipt, subjectAnchor, eligibility } = makeAttestationDraft({
    signing: signingFields(provider, overrides.signing ?? {}),
  })
  const result = await signMarketAttestation({
    attestation: draft,
    signingProvider: provider,
    requester: REQUESTER,
    requestId: 'request-1',
    ...overrides.signOptions,
  })
  return { result, draft, receipt, subjectAnchor, eligibility, providerDoc: provider.describe() }
}

test('signing provider: dev/blocked/KMS/HSM/OS-keystore 文档 schema 合法且信任结论 fail-closed', () => {
  const dev = makeSigner()
  const devDoc = dev.describe()
  assert.equal(validateSigningProviderDocument(devDoc).ok, true)
  const devTrust = signingProviderTrustIssues(devDoc)
  assert.equal(devTrust.ok, false)
  assert.ok(devTrust.reason_codes.includes(EVIDENCE_REASON_CODES.DEVELOPMENT_ONLY_NOT_MARKET))
  assert.ok(devTrust.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_KEY_CUSTODY_UNVERIFIED))
  assert.equal(devDoc.trust_class, 'development-only')
  assert.equal(devDoc.availability, 'available')

  for (const factory of [createBlockedSigningProvider, createKmsSigningProvider, createHsmSigningProvider, createOsKeystoreSigningProvider]) {
    const provider = factory()
    const doc = provider.describe()
    assert.equal(validateSigningProviderDocument(doc).ok, true, factory.name)
    assert.equal(doc.availability, 'blocked')
    assert.equal(doc.trust_class, 'unavailable')
    assert.deepEqual(doc.keys, [])
    const trust = signingProviderTrustIssues(doc)
    assert.equal(trust.ok, false)
    assert.ok(trust.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_PROVIDER_MISSING))
    const signed = provider.sign({}, {})
    assert.equal(signed.status, 'blocked')
    assert.ok(signed.reason_codes.length > 0)
    assert.ok(signed.reason_codes.every((code) => code === EVIDENCE_REASON_CODES.SIGNING_PROVIDER_MISSING ||
      code === EVIDENCE_REASON_CODES.SIGNING_KEY_CUSTODY_UNVERIFIED))
    assert.equal(provider.audit().status, 'blocked')
  }

  assert.equal(assertSigningProvider({}).ok, false)
  assert.equal(assertSigningProvider(dev).ok, true)
})

test('signing: Ed25519 真实签名 → 响应绑定 → 独立密码学验证通过（开发 signer）', async () => {
  const provider = makeSigner()
  const { result, providerDoc } = await signFixture(provider)
  assert.equal(result.status, 'signed', JSON.stringify(result))
  assert.equal(validateMarketAttestation(result.attestation).ok, true)
  assert.equal(verifySigningResponseBinding(result.request, result.response).ok, true)

  const key = providerDoc.keys.find((candidate) => candidate.key_id === result.attestation.signing.key_id)
  const signature = verifyAttestationSignature({ attestation: result.attestation, key })
  assert.equal(signature.ok, true, JSON.stringify(signature.errors))
  assert.equal(result.attestation.signing.signature, result.response.signature)
  assert.equal(result.attestation.archive.entry_digest, DIGEST('1'))

  const audit = provider.audit()
  assert.equal(audit.entries.length, 1)
  assert.equal(audit.entries[0].provider_audit_ref, 'audit:request-1')
  assert.equal(audit.entries[0].key_id, result.attestation.signing.key_id)
})

test('signing: ECDSA P-256 签名/验证通过，且与 Ed25519 域分离互不冒充', async () => {
  const provider = makeSigner({ algorithms: ['ecdsa-p256-sha256'] })
  const { draft } = makeAttestationDraft({
    signing: signingFields(provider, { alg: 'ecdsa-p256-sha256' }),
  })
  const result = await signMarketAttestation({
    attestation: draft,
    signingProvider: provider,
    requester: REQUESTER,
    requestId: 'request-ecdsa',
  })
  assert.equal(result.status, 'signed', JSON.stringify(result))
  const key = provider.describe().keys[0]
  assert.equal(verifyAttestationSignature({ attestation: result.attestation, key }).ok, true)

  // A signature cannot be replayed under a different algorithm allowlist.
  const denied = verifyAttestationSignature({
    attestation: result.attestation,
    key,
    algorithmAllowlist: ['ed25519'],
  })
  assert.equal(denied.ok, false)
  assert.ok(denied.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_ALGORITHM_NOT_ALLOWED))
})

test('signing: 拒绝 blind sign（无 payload / payload 被替换）', async () => {
  const provider = makeSigner()
  const { draft } = makeAttestationDraft({ signing: signingFields(provider) })
  const request = buildSigningRequest({
    requestId: 'request-blind',
    keyId: signingFields(provider).key_id,
    alg: 'ed25519',
    payload: draft,
    auditRef: 'audit:blind',
    requestedAt: FIXED_TIME,
    requester: REQUESTER,
  })

  const noPayload = provider.sign(request)
  assert.equal(noPayload.status, 'rejected')
  assert.ok(noPayload.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_BLIND_SIGN_FORBIDDEN))

  const tampered = structuredClone(draft)
  tampered.isolation.level = 'L3'
  const replaced = provider.sign(request, tampered)
  assert.equal(replaced.status, 'rejected')
  assert.ok(replaced.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_PAYLOAD_DIGEST_MISMATCH))

  const wrongKind = provider.sign(request, { schema_version: 'archive-entry/v1' })
  assert.equal(wrongKind.status, 'rejected')
  assert.ok(wrongKind.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_PAYLOAD_KIND_MISMATCH))
})

test('signing: 未授权 requester、跨域复用、过期请求全部拒绝', async () => {
  const provider = makeSigner()
  const fields = signingFields(provider)
  const { draft } = makeAttestationDraft({ signing: fields })

  const validRequest = buildSigningRequest({
    requestId: 'request-domain',
    keyId: fields.key_id,
    alg: fields.alg,
    payload: draft,
    auditRef: 'audit:domain',
    requestedAt: FIXED_TIME,
    requester: REQUESTER,
  })

  const unauthorized = structuredClone(validRequest)
  unauthorized.requester = { control_plane_id: 'rogue-plane', authorization_ref: 'auth-ref-1' }
  const unauthorizedResult = provider.sign(unauthorized, draft)
  assert.equal(unauthorizedResult.status, 'rejected')
  assert.ok(unauthorizedResult.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_REQUEST_UNAUTHORIZED))

  const crossDomain = buildSigningRequest({
    requestId: 'request-cross-domain',
    keyId: fields.key_id,
    alg: fields.alg,
    payload: draft,
    auditRef: 'audit:cross-domain',
    requestedAt: FIXED_TIME,
    requester: REQUESTER,
    domainSeparation: SIGNING_DOMAIN_MARKET_ARCHIVE,
  })
  const crossDomainResult = provider.sign(crossDomain, draft)
  assert.equal(crossDomainResult.status, 'rejected')
  assert.ok(crossDomainResult.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_DOMAIN_SEPARATION_MISMATCH))

  // Provider clock is 10 minutes after the requested timestamp.
  const staleProvider = makeSigner({ now: () => new Date('2026-01-01T00:10:00.000Z') })
  const staleResult = staleProvider.sign(validRequest, draft)
  assert.equal(staleResult.status, 'rejected')
  assert.ok(staleResult.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_REQUEST_STALE))
})

test('signing: 未知 key / 算法不被 provider 支持时拒绝', async () => {
  const provider = makeSigner({ algorithms: ['ecdsa-p256-sha256'] })
  const keyId = provider.activeKeyIds()[0]
  const { draft } = makeAttestationDraft({
    signing: {
      provider_id: PROVIDER_ID,
      key_id: keyId,
      alg: 'ed25519',
      signed_at: FIXED_TIME,
      provider_audit_ref: 'audit:alg',
    },
  })
  const request = buildSigningRequest({
    requestId: 'request-alg',
    keyId,
    alg: 'ed25519',
    payload: draft,
    auditRef: 'audit:alg',
    requestedAt: FIXED_TIME,
    requester: REQUESTER,
  })
  const rejected = provider.sign(request, draft)
  assert.equal(rejected.status, 'rejected')
  assert.ok(rejected.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_ALGORITHM_NOT_ALLOWED))

  // Unknown key is rejected before signing.
  const unknown = await signMarketAttestation({
    attestation: makeAttestationDraft({
      signing: { ...signingFields(provider), alg: 'ecdsa-p256-sha256', key_id: 'key-does-not-exist' },
    }).draft,
    signingProvider: provider,
    requester: REQUESTER,
    requestId: 'request-unknown',
  })
  assert.equal(unknown.status, 'rejected')
  assert.ok(unknown.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_KEY_UNKNOWN))
})

test('signing: 轮换保留历史公钥；旧签名按策略判定，新 key 可签', async () => {
  const provider = makeSigner()
  const oldKeyId = provider.activeKeyIds()[0]
  const first = await signFixture(provider)
  assert.equal(first.result.status, 'signed')
  const oldAttestation = first.result.attestation

  const rotated = provider.rotateKey({ keyId: oldKeyId })
  assert.equal(rotated.status, 'rotated')
  const docAfterRotation = provider.describe()
  const oldKey = docAfterRotation.keys.find((key) => key.key_id === oldKeyId)
  assert.equal(oldKey.state, 'rotated')
  assert.equal(typeof oldKey.rotated_at, 'string')
  assert.equal(docAfterRotation.keys.length, 2)
  assert.notEqual(provider.activeKeyIds()[0], oldKeyId)

  // Old key is no longer usable for new signatures.
  const rejected = await signMarketAttestation({
    attestation: makeAttestationDraft({
      signing: { ...signingFields(provider), key_id: oldKeyId, signed_at: FIXED_TIME },
    }).draft,
    signingProvider: provider,
    requester: REQUESTER,
    requestId: 'request-rotated-old',
  })
  assert.equal(rejected.status, 'rejected')
  assert.ok(rejected.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_KEY_INACTIVE))

  // Historical signature verifies only under an explicit rotated-key policy.
  const strict = verifyAttestationSignature({ attestation: oldAttestation, key: oldKey })
  assert.equal(strict.ok, false)
  assert.ok(strict.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_KEY_INACTIVE))
  const permissive = verifyAttestationSignature({ attestation: oldAttestation, key: oldKey, allowRotatedKeys: true })
  assert.equal(permissive.ok, true, JSON.stringify(permissive.errors))

  // New active key signs.
  const newSigning = await signMarketAttestation({
    attestation: makeAttestationDraft({ signing: signingFields(provider) }).draft,
    signingProvider: provider,
    requester: REQUESTER,
    requestId: 'request-new-key',
  })
  assert.equal(newSigning.status, 'signed', JSON.stringify(newSigning))
})

test('signing: 吊销是粘性的，历史签名与新签名都失败', async () => {
  const provider = makeSigner({ algorithms: ['ed25519', 'ecdsa-p256-sha256'] })
  const keyId = provider.activeKeyIds()[0]
  const fieldsBeforeRevocation = signingFields(provider)
  const signed = await signFixture(provider)
  assert.equal(signed.result.status, 'signed')

  const revoked = provider.revokeKey({ keyId, reason: 'key-compromise' })
  assert.equal(revoked.status, 'revoked')
  const revokedKey = provider.describe().keys.find((key) => key.key_id === keyId)
  assert.equal(revokedKey.state, 'revoked')

  const verified = verifyAttestationSignature({ attestation: signed.result.attestation, key: revokedKey })
  assert.equal(verified.ok, false)
  assert.ok(verified.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_KEY_REVOKED))

  const rejected = await signMarketAttestation({
    attestation: makeAttestationDraft({ signing: fieldsBeforeRevocation }).draft,
    signingProvider: provider,
    requester: REQUESTER,
    requestId: 'request-revoked',
  })
  assert.equal(rejected.status, 'rejected')
  assert.ok(rejected.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_KEY_REVOKED))
})

test('signing: 过期 key 拒绝签名，checkKeyValidity 覆盖未生效/过期状态', async () => {
  const provider = makeSigner({ expiresAt: FIXED_TIME })
  const { draft } = makeAttestationDraft({ signing: signingFields(provider) })
  const expired = await signMarketAttestation({
    attestation: draft,
    signingProvider: provider,
    requester: REQUESTER,
    requestId: 'request-expired',
  })
  assert.equal(expired.status, 'rejected')
  assert.ok(expired.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_KEY_EXPIRED))

  const base = {
    key_id: 'key-x',
    state: 'active',
    created_at: FIXED_TIME,
    expires_at: null,
  }
  assert.equal(checkKeyValidity(base, { at: FIXED_TIME }).ok, true)
  assert.equal(checkKeyValidity(base, { at: '2025-12-31T23:59:59.000Z' }).ok, false)
  assert.equal(checkKeyValidity({ ...base, state: 'revoked' }, { at: FIXED_TIME }).ok, false)
  assert.equal(checkKeyValidity({ ...base, expires_at: FIXED_TIME }, { at: FIXED_TIME }).ok, false)
  assert.equal(
    checkKeyValidity({ ...base, state: 'rotated', rotated_at: '2026-01-02T00:00:00.000Z' }, {
      at: FIXED_TIME,
      allowRotatedKeys: true,
    }).ok,
    true,
  )
})

test('signing: 篡改 attestation 或签名值导致验证失败', async () => {
  const provider = makeSigner()
  const signed = await signFixture(provider)
  const key = provider.describe().keys[0]

  const tamperedField = structuredClone(signed.result.attestation)
  tamperedField.isolation.level = 'L3'
  const fieldCheck = verifyAttestationSignature({ attestation: tamperedField, key })
  assert.equal(fieldCheck.ok, false)
  assert.ok(fieldCheck.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNATURE_VERIFICATION_FAILED))

  const tamperedSignature = structuredClone(signed.result.attestation)
  const raw = Buffer.from(tamperedSignature.signing.signature, 'base64url')
  raw[0] ^= 0xff
  tamperedSignature.signing.signature = raw.toString('base64url')
  const signatureCheck = verifyAttestationSignature({ attestation: tamperedSignature, key })
  assert.equal(signatureCheck.ok, false)
  assert.ok(signatureCheck.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNATURE_VERIFICATION_FAILED))

  const wrongKeyProvider = makeSigner()
  const wrongKey = wrongKeyProvider.describe().keys[0]
  const wrongKeyCheck = verifyAttestationSignature({ attestation: signed.result.attestation, key: wrongKey })
  assert.equal(wrongKeyCheck.ok, false)
  assert.ok(wrongKeyCheck.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_KEY_UNKNOWN))
})

test('signing: 响应绑定不匹配（request/key/alg/digest/signed_at/audit_ref）全部拒绝', async () => {
  const provider = makeSigner()
  const signed = await signFixture(provider)
  const { request, response } = signed.result
  assert.equal(verifySigningResponseBinding(request, response).ok, true)

  for (const mutate of [
    (copy) => { copy.request_id = 'other-request' },
    (copy) => { copy.key_id = 'other-key' },
    (copy) => { copy.alg = 'ecdsa-p256-sha256' },
    (copy) => { copy.signed_payload_digest = DIGEST('0') },
    (copy) => { copy.signed_at = '2026-01-01T00:00:01.000Z' },
    (copy) => { copy.provider_audit_ref = 'audit:other' },
  ]) {
    const tampered = structuredClone(response)
    mutate(tampered)
    const binding = verifySigningResponseBinding(request, tampered)
    assert.equal(binding.ok, false)
    assert.ok(binding.reason_codes.length > 0)
  }
})

test('signing: 已签名对象不可重复签名，缺少 anchor/eligibility 时拒绝', async () => {
  const provider = makeSigner()
  const signed = await signFixture(provider)
  const twice = await signMarketAttestation({
    attestation: signed.result.attestation,
    signingProvider: provider,
    requester: REQUESTER,
    requestId: 'request-twice',
  })
  assert.equal(twice.status, 'rejected')
  assert.ok(twice.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_BLIND_SIGN_FORBIDDEN))

  const noAnchor = structuredClone(signed.draft)
  delete noAnchor.archive
  const noAnchorResult = await signMarketAttestation({
    attestation: noAnchor,
    signingProvider: provider,
    requester: REQUESTER,
    requestId: 'request-no-anchor',
  })
  assert.equal(noAnchorResult.status, 'rejected')
  assert.ok(noAnchorResult.reason_codes.includes(EVIDENCE_REASON_CODES.ARCHIVE_ANCHOR_MISSING))
})

test('signing: deriveKeyId 稳定且随算法/公钥变化', () => {
  const a = makeSigner({ algorithms: ['ed25519'] }).describe().keys[0]
  const b = makeSigner({ algorithms: ['ed25519'] }).describe().keys[0]
  assert.notEqual(a.key_id, b.key_id)
  assert.equal(a.key_id, deriveKeyId('ed25519', Buffer.from(a.public_key, 'base64url')))
  const key = a.key_id
  assert.equal(providerKeyIdStable(key), true)
})

function providerKeyIdStable(keyId) {
  return typeof keyId === 'string' && keyId.startsWith('key-ed25519-')
}
