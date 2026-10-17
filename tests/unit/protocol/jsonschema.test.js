/**
 * 单元 · protocol/jsonschema（node:test）。
 * 覆盖 CONTRACT-m5 §1/§4：remote `$ref`(http/file/绝对路径) 拒绝、size/depth 超限、
 * 本地 `#/` 指针可用、validateValue 各关键词正反、未知关键词忽略。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  MAX_SCHEMA_BYTES,
  MAX_SCHEMA_DEPTH,
  JSON_SCHEMA_DRAFT_2020_12,
  validateSchemaMeta,
  validateValue,
} from '../../../src/protocol/jsonschema.js'

// ---------------------------------------------------------------------------
// validateSchemaMeta：结构校验
// ---------------------------------------------------------------------------

test('meta: 非对象 schema → 拒绝', () => {
  for (const bad of [null, 'x', 42, [], true]) {
    const r = validateSchemaMeta(bad)
    assert.equal(r.ok, false)
    assert.ok(r.errors.includes('schema-not-object'))
  }
})

test('meta: 合法 schema（可选 $schema 正确）→ 通过', () => {
  assert.equal(validateSchemaMeta({ type: 'string' }).ok, true)
  assert.equal(validateSchemaMeta({ $schema: JSON_SCHEMA_DRAFT_2020_12, type: 'object' }).ok, true)
})

test('meta: 错误 $schema → 拒绝', () => {
  const r = validateSchemaMeta({ $schema: 'http://json-schema.org/draft-07/schema#', type: 'string' })
  assert.equal(r.ok, false)
  assert.ok(r.errors.some((e) => e.startsWith('schema-$schema-unsupported')))
})

test('meta: remote $ref http:// 拒绝', () => {
  const r = validateSchemaMeta({ type: 'object', properties: { a: { $ref: 'http://evil/schema.json' } } })
  assert.equal(r.ok, false)
  assert.ok(r.errors.some((e) => e.startsWith('remote-$ref:http://')))
})

test('meta: remote $ref file:// 拒绝', () => {
  const r = validateSchemaMeta({ $defs: { x: { type: 'string' } }, $ref: 'file:///etc/schema.json' })
  assert.equal(r.ok, false)
  assert.ok(r.errors.some((e) => e.startsWith('remote-$ref:file://')))
})

test('meta: 绝对路径 $ref 拒绝', () => {
  const r = validateSchemaMeta({ $ref: '/abs/schema.json' })
  assert.equal(r.ok, false)
  assert.ok(r.errors.some((e) => e.startsWith('remote-$ref:')))
})

test('meta: 本地 `#/` 指针允许（含 $defs 内联）', () => {
  const s = { $defs: { name: { type: 'string' } }, type: 'object', properties: { n: { $ref: '#/$defs/name' } } }
  const r = validateSchemaMeta(s)
  assert.equal(r.ok, true, JSON.stringify(r.errors))
})

test('meta: 序列化字节超限 → schema-too-large', () => {
  const s = { type: 'object', description: 'x'.repeat(MAX_SCHEMA_BYTES + 10) }
  const r = validateSchemaMeta(s)
  assert.equal(r.ok, false)
  assert.ok(r.errors.includes('schema-too-large'))
})

test('meta: 深度超限 → schema-too-deep', () => {
  let s = { type: 'string' }
  for (let i = 0; i < MAX_SCHEMA_DEPTH + 2; i++) s = { nested: s }
  const r = validateSchemaMeta(s)
  assert.equal(r.ok, false)
  assert.ok(r.errors.includes('schema-too-deep'))
})

test('meta: 深度等于上限 → 允许', () => {
  let s = { type: 'string' }
  // MAX_SCHEMA_DEPTH 层对象（根算 1 层）
  for (let i = 0; i < MAX_SCHEMA_DEPTH - 1; i++) s = { nested: s }
  const r = validateSchemaMeta(s)
  assert.equal(r.ok, true, JSON.stringify(r.errors))
})

// ---------------------------------------------------------------------------
// validateValue：type
// ---------------------------------------------------------------------------

test('value: type=string 正反', () => {
  assert.equal(validateValue('x', { type: 'string' }).ok, true)
  assert.equal(validateValue(1, { type: 'string' }).ok, false)
})

test('value: type=object/array 区分且 null 不属于 object', () => {
  assert.equal(validateValue({}, { type: 'object' }).ok, true)
  assert.equal(validateValue([], { type: 'object' }).ok, false)
  assert.equal(validateValue(null, { type: 'object' }).ok, false)
  assert.equal(validateValue([], { type: 'array' }).ok, true)
  assert.equal(validateValue({}, { type: 'array' }).ok, false)
})

test('value: type=integer/number 区分', () => {
  assert.equal(validateValue(3, { type: 'integer' }).ok, true)
  assert.equal(validateValue(3.5, { type: 'integer' }).ok, false)
  assert.equal(validateValue(3.5, { type: 'number' }).ok, true)
})

test('value: type=boolean/null', () => {
  assert.equal(validateValue(true, { type: 'boolean' }).ok, true)
  assert.equal(validateValue('true', { type: 'boolean' }).ok, false)
  assert.equal(validateValue(null, { type: 'null' }).ok, true)
  assert.equal(validateValue(0, { type: 'null' }).ok, false)
})

test('value: type 数组形式（union）', () => {
  assert.equal(validateValue(1, { type: ['string', 'number'] }).ok, true)
  assert.equal(validateValue('a', { type: ['string', 'number'] }).ok, true)
  assert.equal(validateValue(false, { type: ['string', 'number'] }).ok, false)
})

// ---------------------------------------------------------------------------
// validateValue：required / properties / additionalProperties
// ---------------------------------------------------------------------------

test('value: required 缺失 → 报错，满足 → 不报错', () => {
  const s = { type: 'object', required: ['a'] }
  assert.equal(validateValue({ a: 1 }, s).ok, true)
  assert.equal(validateValue({}, s).ok, false)
  assert.ok(validateValue({}, s).errors.includes('required-missing:a'))
})

test('value: properties 嵌套校验 + additionalProperties=false 拒未知', () => {
  const s = {
    type: 'object',
    properties: { name: { type: 'string' } },
    required: ['name'],
    additionalProperties: false,
  }
  assert.equal(validateValue({ name: 'ok' }, s).ok, true)
  const bad = validateValue({ name: 'ok', extra: 1 }, s)
  assert.equal(bad.ok, false)
  assert.ok(bad.errors.includes('additional-properties-not-allowed:extra'))
  const badType = validateValue({ name: 1 }, s)
  assert.equal(badType.ok, false)
})

test('value: additionalProperties 作为 schema 校验额外属性', () => {
  const s = { type: 'object', properties: { a: { type: 'number' } }, additionalProperties: { type: 'string' } }
  assert.equal(validateValue({ a: 1, b: 'x' }, s).ok, true)
  assert.equal(validateValue({ a: 1, b: 2 }, s).ok, false)
})

test('value: additionalProperties=true 允许任意额外属性', () => {
  const s = { type: 'object', properties: { a: { type: 'number' } }, additionalProperties: true }
  assert.equal(validateValue({ a: 1, anything: 'x' }, s).ok, true)
})

// ---------------------------------------------------------------------------
// validateValue：items / enum / const
// ---------------------------------------------------------------------------

test('value: items 单 schema 逐元素校验', () => {
  const s = { type: 'array', items: { type: 'integer' } }
  assert.equal(validateValue([1, 2, 3], s).ok, true)
  assert.equal(validateValue([1, 'x'], s).ok, false)
})

test('value: items=false 拒绝任何元素', () => {
  const s = { type: 'array', items: false }
  assert.equal(validateValue([], s).ok, true)
  assert.equal(validateValue([1], s).ok, false)
})

test('value: enum 正反', () => {
  const s = { enum: ['red', 'green', null] }
  assert.equal(validateValue('red', s).ok, true)
  assert.equal(validateValue(null, s).ok, true)
  assert.equal(validateValue('blue', s).ok, false)
})

test('value: const 正反（深度相等）', () => {
  const s = { const: { a: [1, 2] } }
  assert.equal(validateValue({ a: [1, 2] }, s).ok, true)
  assert.equal(validateValue({ a: [2, 1] }, s).ok, false)
})

// ---------------------------------------------------------------------------
// validateValue：minLength/maxLength/minimum/maximum
// ---------------------------------------------------------------------------

test('value: minLength/maxLength 正反', () => {
  const s = { type: 'string', minLength: 2, maxLength: 4 }
  assert.equal(validateValue('ab', s).ok, true)
  assert.equal(validateValue('abcd', s).ok, true)
  assert.equal(validateValue('a', s).ok, false)
  assert.equal(validateValue('abcde', s).ok, false)
})

test('value: minimum/maximum 正反（inclusive）', () => {
  const s = { type: 'number', minimum: 0, maximum: 10 }
  assert.equal(validateValue(0, s).ok, true)
  assert.equal(validateValue(10, s).ok, true)
  assert.equal(validateValue(-1, s).ok, false)
  assert.equal(validateValue(11, s).ok, false)
})

// ---------------------------------------------------------------------------
// validateValue：$ref 本地指针 + 未知关键词忽略
// ---------------------------------------------------------------------------

test('value: $ref 本地指针解析（$defs 内联）', () => {
  const s = {
    $defs: { positive: { type: 'integer', minimum: 1 } },
    type: 'object',
    properties: { n: { $ref: '#/$defs/positive' } },
  }
  assert.equal(validateValue({ n: 5 }, s).ok, true)
  assert.equal(validateValue({ n: 0 }, s).ok, false)
})

test('value: $ref 指向缺失指针 → unresolved-$ref', () => {
  const s = { $ref: '#/$defs/nope' }
  const r = validateValue(1, s)
  assert.equal(r.ok, false)
  assert.ok(r.errors.some((e) => e.startsWith('unresolved-$ref:')))
})

test('value: $ref 循环 → $ref-cycle', () => {
  const s = { $defs: { a: { $ref: '#/$defs/b' }, b: { $ref: '#/$defs/a' } }, $ref: '#/$defs/a' }
  const r = validateValue(1, s)
  assert.equal(r.ok, false)
  assert.ok(r.errors.some((e) => e.startsWith('$ref-cycle:')))
})

test('value: 未知关键词忽略（不报错）', () => {
  const s = { type: 'string', 'x-custom': 1, allOf: [{ type: 'string' }], pattern: '^a' }
  assert.equal(validateValue('a', s).ok, true)
  assert.equal(validateValue(1, s).ok, false) // type 仍生效
})

test('value: schema 为空对象 → 一切通过', () => {
  assert.equal(validateValue(undefined, {}).ok, true)
  assert.equal(validateValue(null, {}).ok, true)
  assert.equal(validateValue({ any: 'thing' }, {}).ok, true)
})