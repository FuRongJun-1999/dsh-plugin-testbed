/** Worker observation assembly tests: redaction, bounds, authority-field guard. */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  REDACTED,
  assertNoAuthorityFields,
  boundObservationValue,
  findForbiddenAuthorityKeys,
  redactText,
  redactValue,
  sanitizeError,
  truncateUtf8,
} from '../../../src/worker/observe.js'

test('redactText removes common credential shapes', () => {
  const cases = [
    ['key sk-abcdefghijklmnopqrstuvwx', 'sk-abcdefghijklmnopqrstuvwx'],
    ['github ghp_abcdefghijklmnopqrstuvwxyz0123456789', 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'],
    ['aws AKIAABCDEFGHIJKLMNOP', 'AKIAABCDEFGHIJKLMNOP'],
    ['Authorization: Bearer abcdefghijklmnopqrstuvwxyz', 'abcdefghijklmnopqrstuvwxyz'],
    ['password=hunter2hunter2', 'hunter2hunter2'],
    ['url https://user:supersecret@example.com/path', 'supersecret'],
    ['jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U', 'eyJhbGciOiJIUzI1NiJ9'],
  ]
  for (const [input, secret] of cases) {
    const redacted = redactText(input)
    assert.equal(redacted.includes(secret), false, `${secret} must be redacted from ${input}`)
    assert.ok(redacted.includes(REDACTED), `redaction marker expected for ${input}`)
  }
  assert.equal(redactText('ordinary observation text'), 'ordinary observation text')
})

test('redactValue recursively redacts and bounds values', () => {
  const input = {
    api_key: 'sk-abcdefghijklmnopqrstuvwx',
    nested: { list: ['token=abcdefgh', 'plain', 42] },
    long: 'y'.repeat(100),
    big_array: Array.from({ length: 10 }, (_, index) => index),
  }
  const result = redactValue(input, { maxArray: 4, maxStringBytes: 20, maxDepth: 4 })
  assert.equal(result.redacted, true)
  assert.equal(result.truncated, true)
  assert.equal(result.value.api_key, REDACTED)
  assert.equal(JSON.stringify(result.value).includes('sk-abcdefghijklmnopqrstuvwx'), false)
  assert.equal(JSON.stringify(result.value).includes('token=abcdefgh'), false)
  assert.ok(result.value.long.endsWith('…[truncated]'))
  assert.deepEqual(result.value.big_array.slice(0, 4), [0, 1, 2, 3])
  assert.equal(result.value.big_array[4], '[truncated:6]')
})

test('redactValue handles cycles and unsupported values without throwing', () => {
  const cyclic = { name: 'x' }
  cyclic.self = cyclic
  const result = redactValue(cyclic)
  assert.equal(result.value.self, '[circular]')
  const unsupported = redactValue({ fn: () => {}, big: 1n })
  assert.equal(unsupported.value.fn, '[unsupported]')
  assert.equal(unsupported.value.big, '[unsupported]')
})

test('boundObservationValue summarizes oversize values to a digest', () => {
  const bounded = boundObservationValue({ huge: 'x'.repeat(2048) }, { maxBytes: 256 })
  assert.ok(bounded.limitations.includes('value-summarized'))
  assert.match(bounded.value.digest, /^sha256:[0-9a-f]{64}$/)
  assert.equal(bounded.value.truncated, true)

  const small = boundObservationValue({ ok: true })
  assert.equal(JSON.stringify(small.value), JSON.stringify({ ok: true }))
  assert.deepEqual(small.limitations, [])
})

test('sanitizeError redacts messages/stacks and bounds them', () => {
  const error = new Error('failure with sk-abcdefghijklmnopqrstuvwx and token=abcdefghijkl')
  error.stack = 'Error: sk-abcdefghijklmnopqrstuvwx\n' + 'at x\n'.repeat(2000)
  const sanitized = sanitizeError(error, { phase: 'host-apply' })
  assert.equal(sanitized.phase, 'host-apply')
  assert.equal(sanitized.message.includes('sk-abcdefghijklmnopqrstuvwx'), false)
  assert.equal(sanitized.stack.includes('sk-abcdefghijklmnopqrstuvwx'), false)
  assert.ok(Buffer.byteLength(sanitized.stack, 'utf8') <= 4096)
})

test('truncateUtf8 never splits a surrogate pair and appends a marker', () => {
  const text = '😀'.repeat(100)
  const cut = truncateUtf8(text, 100)
  assert.equal(cut.truncated, true)
  assert.ok(cut.text.endsWith('…[truncated]'))
  assert.equal(cut.text.includes('\uFFFD'), false)
})

test('authority fields are detected and rejected at the worker boundary', () => {
  const forged = {
    test_id: 't1',
    source: 'worker',
    claim: 'declared',
    observed: 'present',
    verification: 'corroborated',
    cases: [{ test_id: 't2', verdict: 'pass', nested: { gate_decision: 'pass' } }],
  }
  const found = findForbiddenAuthorityKeys(forged)
  assert.deepEqual(found.sort(), ['cases[0].nested.gate_decision', 'cases[0].verdict', 'verification'])
  assert.throws(() => assertNoAuthorityFields(forged), /verification/)

  const clean = {
    test_id: 't1',
    source: 'worker',
    claim: 'not-declared',
    observed: 'unknown',
    limitations: ['probe-snapshot-not-supplied'],
  }
  assert.deepEqual(findForbiddenAuthorityKeys(clean), [])
  assert.doesNotThrow(() => assertNoAuthorityFields(clean))
  // Shallow mode only inspects the top level.
  assert.deepEqual(findForbiddenAuthorityKeys({ cases: [{ verdict: 'pass' }] }, { deep: false }), [])
})
