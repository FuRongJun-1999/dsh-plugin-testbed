import { test } from 'node:test'
import assert from 'node:assert/strict'
import { applyAssertion } from '../../../src/control/assert.js'

test('equals: deep-equal (key-order insensitive) pass', () => {
  const r = applyAssertion({ user_id: 'u1', age: 3 }, { assert: 'equals', expected: { age: 3, user_id: 'u1' } })
  assert.equal(r.verdict, 'pass')
  assert.deepEqual(r.reason_codes, [])
})

test('equals: mismatch → fail', () => {
  const r = applyAssertion({ a: 1 }, { assert: 'equals', expected: { a: 2 } })
  assert.equal(r.verdict, 'fail')
  assert.deepEqual(r.reason_codes, ['equals-mismatch'])
})

test('equals: dot-path value extraction', () => {
  const r = applyAssertion({ status_code: 200, body: { x: 1 } }, { assert: 'equals', path: 'status_code', expected: 200 })
  assert.equal(r.verdict, 'pass')
  const r2 = applyAssertion({ body: { user_id: 'u' } }, { assert: 'equals', path: 'body.user_id', expected: 'u' })
  assert.equal(r2.verdict, 'pass')
})

test('contains: array subset pass / miss fail', () => {
  assert.equal(applyAssertion([1, 2, 3], { assert: 'contains', expected: [2, 3] }).verdict, 'pass')
  assert.equal(applyAssertion([1, 2], { assert: 'contains', expected: [9] }).verdict, 'fail')
})

test('contains: string substring', () => {
  assert.equal(applyAssertion('hello world', { assert: 'contains', expected: 'lo wo' }).verdict, 'pass')
  assert.equal(applyAssertion('abc', { assert: 'contains', expected: 'z' }).verdict, 'fail')
})

test('contains: object subset', () => {
  const r = applyAssertion({ a: 1, b: 2, c: 3 }, { assert: 'contains', expected: { a: 1, c: 3 } })
  assert.equal(r.verdict, 'pass')
})

test('schema-valid: object type/properties/required/additionalProperties', () => {
  const schema = {
    type: 'object',
    required: ['status_code'],
    properties: { status_code: { type: 'integer' }, body: { type: 'object' } },
    additionalProperties: false,
  }
  assert.equal(applyAssertion({ status_code: 200 }, { assert: 'schema-valid', schema }).verdict, 'pass')
  assert.equal(applyAssertion({ wrong: 1 }, { assert: 'schema-valid', schema }).verdict, 'fail')
  assert.equal(applyAssertion({ status_code: '200' }, { assert: 'schema-valid', schema }).verdict, 'fail')
})

test('schema-valid: const / enum / items', () => {
  assert.equal(applyAssertion('x', { assert: 'schema-valid', schema: { const: 'x' } }).verdict, 'pass')
  assert.equal(applyAssertion('y', { assert: 'schema-valid', schema: { const: 'x' } }).verdict, 'fail')
  assert.equal(applyAssertion('b', { assert: 'schema-valid', schema: { enum: ['a', 'b'] } }).verdict, 'pass')
  assert.equal(applyAssertion([1, 2], { assert: 'schema-valid', schema: { type: 'array', items: { type: 'integer' } } }).verdict, 'pass')
  assert.equal(applyAssertion([1, 'x'], { assert: 'schema-valid', schema: { type: 'array', items: { type: 'integer' } } }).verdict, 'fail')
})

test('numeric-range: [min,max] / {min,max} / exact expected', () => {
  assert.equal(applyAssertion(5, { assert: 'numeric-range', expected: [1, 10] }).verdict, 'pass')
  assert.equal(applyAssertion(11, { assert: 'numeric-range', expected: [1, 10] }).verdict, 'fail')
  assert.equal(applyAssertion(3, { assert: 'numeric-range', expected: { min: 2, max: 4 } }).verdict, 'pass')
  assert.equal(applyAssertion(3, { assert: 'numeric-range', expected: 3 }).verdict, 'pass')
  assert.equal(applyAssertion(4, { assert: 'numeric-range', expected: 3 }).verdict, 'fail')
  assert.equal(applyAssertion('x', { assert: 'numeric-range', expected: [0, 1] }).verdict, 'fail')
})

test('finding-count: exact / max bound / path to findings', () => {
  const obs = { findings: [{ sev: 'high' }, { sev: 'low' }] }
  assert.equal(applyAssertion(obs, { assert: 'finding-count', expected: 2 }).verdict, 'pass')
  assert.equal(applyAssertion(obs, { assert: 'finding-count', expected: 1 }).verdict, 'fail')
  assert.equal(applyAssertion(obs, { assert: 'finding-count', expected: { min: 0, max: 2 } }).verdict, 'pass')
  const r = applyAssertion({ meta: { findings: [1, 2, 3] } }, { assert: 'finding-count', path: 'meta.findings', expected: 3 })
  assert.equal(r.verdict, 'pass')
})

test('unknown assertion / missing criteria → fail-closed', () => {
  assert.equal(applyAssertion(1, { assert: 'evil-code' }).verdict, 'fail')
  assert.equal(applyAssertion(1, null).verdict, 'fail')
  assert.deepEqual(applyAssertion(1, null).reason_codes, ['missing-or-invalid-criteria'])
})