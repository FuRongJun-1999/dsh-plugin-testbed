/**
 * 安全 · 签名/归档证据不得泄漏私钥、凭据或产生伪造 trust root。
 *
 * 覆盖 SIG-02/SIG-07、ARC-09 与 MKT-07：
 *  - src/ 运行时代码不含硬编码私钥/令牌/密钥导出；
 *  - 开发 signer 的 describe/audit/签名响应/attestation 均不含私钥材料；
 *  - provider 不读取 ambient credentials（process.env 等）；
 *  - receipt/v1 继续拒绝任何签名形态；
 *  - KMS/HSM/OS-keystore 与 WORM provider 在未配置时只能 blocked。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { validateReceiptV1 } from '../../src/protocol/contracts.js'
import { EVIDENCE_REASON_CODES } from '../../src/protocol/market-schemas.js'
import {
  buildSigningRequest,
  signMarketAttestation,
} from '../../src/evidence/signing.js'
import {
  createBlockedSigningProvider,
  createDevelopmentSigningProvider,
  createHsmSigningProvider,
  createKmsSigningProvider,
  createOsKeystoreSigningProvider,
} from '../../src/evidence/signing-provider.js'
import {
  createBlockedArchiveProvider,
} from '../../src/evidence/archive-provider.js'
import {
  CONTROL_PLANE,
  DIGEST,
  FIXED_TIME,
  ISOLATION_REF,
  RUNTIME_REF,
  makeAttestationDraft,
  makeEligibility,
  makeValidReceipt,
} from '../unit/evidence/_fixtures.js'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const EVIDENCE_DIR = join(ROOT, 'src', 'evidence')
const MARKET_SCHEMAS = join(ROOT, 'src', 'protocol', 'market-schemas.js')
const MARKET_SCHEMAS_SOURCE = join(ROOT, 'src', 'protocol', 'market-schemas.ts')

function walk(dir, acc = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    const stat = statSync(path)
    if (stat.isDirectory()) walk(path, acc)
    else if (/\.(js|ts)$/.test(name)) acc.push(path)
  }
  return acc
}

const RUNTIME_FILES = [...walk(EVIDENCE_DIR), MARKET_SCHEMAS, MARKET_SCHEMAS_SOURCE]

const SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\b(api[_-]?key|secret|password|access[_-]?token|client[_-]?secret)['"]?\s*[:=]\s*['"][^'"]{12,}['"]/i,
  /\bsk-[A-Za-z0-9]{20,}\b/,
  /\bghp_[A-Za-z0-9]{20,}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
]

function collectForbiddenKeyNames(value, path = '', hits = []) {
  if (value === null || typeof value !== 'object') return hits
  if (Array.isArray(value)) {
    value.forEach((item, index) => collectForbiddenKeyNames(item, `${path}[${index}]`, hits))
    return hits
  }
  const forbidden = ['private_key', 'privateKey', 'seed', 'key_material', 'private_key_der']
  for (const [key, child] of Object.entries(value)) {
    if (forbidden.includes(key)) hits.push(`${path}.${key}`)
    collectForbiddenKeyNames(child, path === '' ? key : `${path}.${key}`, hits)
  }
  return hits
}

test('secret isolation: src/evidence 与 market-schemas 不含硬编码秘密或私钥导出', () => {
  const hits = []
  for (const file of RUNTIME_FILES) {
    const text = readFileSync(file, 'utf8')
    for (const [index, line] of text.split('\n').entries()) {
      for (const pattern of SECRET_PATTERNS) {
        if (pattern.test(line)) hits.push(`${file}:${index + 1}: ${pattern.source}`)
      }
    }
  }
  assert.deepEqual(hits, [], `发现疑似硬编码秘密：\n${hits.join('\n')}`)

  const providerSource = readFileSync(join(EVIDENCE_DIR, 'signing-provider.ts'), 'utf8')
  assert.equal(providerSource.includes('pkcs8'), false, 'never export a private key as pkcs8')
  assert.equal(providerSource.includes('process.env'), false, 'signing provider must not read ambient credentials')
  const archiveSource = readFileSync(join(EVIDENCE_DIR, 'archive-provider.ts'), 'utf8')
  assert.equal(archiveSource.includes('process.env'), false, 'archive provider must not read ambient credentials')
})

test('secret isolation: 开发 signer 的公开文档/审计/签名结果不含私钥或密钥材料', async () => {
  const signer = createDevelopmentSigningProvider({
    authorizedRequesters: [{ control_plane_id: 'control-plane-development', authorization_ref: 'auth-ref-1' }],
    now: () => new Date(FIXED_TIME),
  })
  const keyId = signer.activeKeyIds()[0]
  const { draft } = makeAttestationDraft({
    signing: {
      provider_id: signer.describe().provider_id,
      key_id: keyId,
      alg: 'ed25519',
      signed_at: FIXED_TIME,
      provider_audit_ref: 'audit:secret-test',
    },
  })
  const signed = await signMarketAttestation({
    attestation: draft,
    signingProvider: signer,
    requester: { control_plane_id: 'control-plane-development', authorization_ref: 'auth-ref-1' },
    requestId: 'request-secret-test',
  })
  assert.equal(signed.status, 'signed')

  const serialized = [
    signer.describe(),
    signer.audit(),
    signed.response,
    signed.attestation,
  ].map((value) => JSON.stringify(value)).join('\n')
  assert.equal(serialized.includes('BEGIN PRIVATE KEY'), false)
  assert.equal(serialized.includes('"private_key"'), false)
  assert.equal(serialized.includes('"privateKey"'), false)
  assert.equal(serialized.includes('"seed"'), false)
  assert.deepEqual(collectForbiddenKeyNames(signer.describe()), [])
  assert.deepEqual(collectForbiddenKeyNames(signer.audit()), [])
  assert.deepEqual(collectForbiddenKeyNames(signed.attestation), [])

  // The signature response is a closed envelope: no private key field exists.
  assert.deepEqual(Object.keys(signed.response).sort(), [
    'alg', 'key_id', 'provider_audit_ref', 'request_id', 'schema_version',
    'signature', 'signed_at', 'signed_payload_digest',
  ])
  // Provider object exposes only the public protocol + active key ids.
  assert.deepEqual(Object.keys(signer).sort(), [
    'activeKeyIds', 'audit', 'describe', 'revokeKey', 'rotateKey', 'sign',
  ])
})

test('secret isolation: signer 不 blind sign，且签名请求只携带 digest 不携带 payload 内容', () => {
  const signer = createDevelopmentSigningProvider({
    authorizedRequesters: [{ control_plane_id: 'control-plane-development', authorization_ref: 'auth-ref-1' }],
    now: () => new Date(FIXED_TIME),
  })
  const keyId = signer.activeKeyIds()[0]
  const { draft } = makeAttestationDraft({
    signing: {
      provider_id: signer.describe().provider_id,
      key_id: keyId,
      alg: 'ed25519',
      signed_at: FIXED_TIME,
      provider_audit_ref: 'audit:request-shape',
    },
  })
  const request = buildSigningRequest({
    requestId: 'request-shape',
    keyId,
    alg: 'ed25519',
    payload: draft,
    auditRef: 'audit:request-shape',
    requestedAt: FIXED_TIME,
    requester: { control_plane_id: 'control-plane-development', authorization_ref: 'auth-ref-1' },
  })
  assert.equal(request.payload_digest.startsWith('sha256:'), true)
  assert.equal('payload' in request, false)
  assert.equal('private_key' in request, false)

  const blind = signer.sign(request)
  assert.equal(blind.status, 'rejected')
  assert.ok(blind.reason_codes.includes(EVIDENCE_REASON_CODES.SIGNING_BLIND_SIGN_FORBIDDEN))
})

test('fail-closed: 未配置 KMS/HSM/OS-keystore/WORM 时 provider 只能 blocked，绝不伪造签名/anchor', async () => {
  for (const factory of [createKmsSigningProvider, createHsmSigningProvider, createOsKeystoreSigningProvider]) {
    const provider = factory()
    const doc = provider.describe()
    assert.equal(doc.availability, 'blocked', factory.name)
    assert.deepEqual(doc.keys, [])
    const result = provider.sign({}, {})
    assert.equal(result.status, 'blocked')
    assert.equal(result.signature, undefined)
    assert.equal(result.response, undefined)
  }
  const blockedSigner = createBlockedSigningProvider()
  assert.equal(blockedSigner.sign({}, {}).status, 'blocked')

  const archive = createBlockedArchiveProvider()
  assert.equal(archive.describe().availability, 'blocked')
  const append = await archive.append({
    receipt_digest: DIGEST('9'),
    isolation_attestation_digest: null,
    policy_digest: null,
    approval_digests: [],
    attestation_digest: null,
    eligibility_digest: null,
  })
  assert.equal(append.status, 'blocked')
  assert.equal(append.anchor, undefined)
  assert.equal(append.entry, undefined)
})

test('receipt/v1: 市场字段只存在于独立 sidecar，receipt 拒绝签名/归档/eligible 形态', () => {
  const receipt = makeValidReceipt()
  assert.equal(validateReceiptV1(receipt, { verifyDigest: true }).ok, true)
  for (const mutate of [
    (copy) => { copy.signature = 'c2ln' },
    (copy) => { copy.signed = true },
    (copy) => { copy.integrity.signed = true },
    (copy) => { copy.market_eligible = true },
    (copy) => { copy.archive = { provider_id: 'x' } },
    (copy) => { copy.market_attestation = { attestation_id: 'x' } },
  ]) {
    const mutated = structuredClone(receipt)
    mutate(mutated)
    assert.equal(validateReceiptV1(mutated).ok, false)
  }
  // The fixture's attestation is a separate object and cannot be folded back in.
  const eligibility = makeEligibility({ manifestDigest: DIGEST('b') })
  assert.equal(eligibility.schema_version, 'market-eligibility/v1')
  assert.equal('signature' in receipt, false)
  assert.equal('integrity' in eligibility, false)
})
