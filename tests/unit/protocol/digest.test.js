import test from 'node:test'
import assert from 'node:assert/strict'
import {
  canonicalJson,
  recordDigest,
  verifyRecordDigest,
  FIXED_VECTOR_INPUT,
  FIXED_VECTOR_DIGEST,
} from '../../../src/protocol/digest.js'

test('fixed vector: canonicalized text matches RFC 8785', () => {
  const body = structuredClone(FIXED_VECTOR_INPUT)
  delete body.integrity.record_digest
  assert.equal(
    canonicalJson(body),
    '{"integrity":{"signed":false},"receipt_schema_version":"receipt/v1"}',
  )
})

test('fixed vector: digest equals c3b6ee…cc2fb', () => {
  assert.equal(
    FIXED_VECTOR_DIGEST,
    'sha256:c3b6ee97857bfdb5a83d46fc51aec09e9fb82e6da82a2e21d6101329d88cc2fb',
  )
  assert.equal(recordDigest(FIXED_VECTOR_INPUT), FIXED_VECTOR_DIGEST)
})

test('recordDigest excludes integrity.record_digest (field-exclusion invariant)', () => {
  const a = recordDigest({ ...FIXED_VECTOR_INPUT })
  const b = recordDigest({
    ...FIXED_VECTOR_INPUT,
    integrity: { record_digest: 'ANY-OTHER-VALUE', signed: false },
  })
  assert.equal(a, b)
})

test('recordDigest keeps integrity.signed in the hashed input', () => {
  const a = recordDigest({ ...FIXED_VECTOR_INPUT })
  const b = recordDigest({
    ...FIXED_VECTOR_INPUT,
    integrity: { record_digest: 'ignored', signed: true },
  })
  assert.notEqual(a, b)
})

test('verifyRecordDigest detects body tamper without digest update', () => {
  const receipt = { receipt_schema_version: 'receipt/v1', run_id: 'run-1', integrity: { signed: false } }
  receipt.integrity.record_digest = recordDigest(receipt)
  assert.equal(verifyRecordDigest(receipt).ok, true)
  receipt.run_id = 'run-2' // tamper body, keep stale digest
  const mismatch = verifyRecordDigest(receipt)
  assert.equal(mismatch.ok, false)
  assert.equal(mismatch.expected !== mismatch.actual, true)
})

test('unknown receipt schema version must not silently downgrade', async () => {
  const { isReceiptSchemaVersion } = await import('../../../src/protocol/schemas.js')
  assert.equal(isReceiptSchemaVersion('receipt/v1'), true)
  assert.equal(isReceiptSchemaVersion('receipt/v2'), false)
  assert.equal(isReceiptSchemaVersion('other'), false)
})