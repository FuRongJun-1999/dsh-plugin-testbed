/**
 * Minimal JSON Schema (Draft 2020-12) meta-validation + instance validation.
 *
 * Enforces the §8.4.1 / CONTRACT-m5 §1 constraints for tool `input_schema` and
 * `observation_schema`: no remote `$ref` (only `#`-local pointers / inline
 * `$defs`), bounded size and depth, and a fixed `$schema` dialect.
 *
 * `validateValue` implements the Draft 2020-12 subset the platform accepts.
 * Unknown keywords are ignored (not errors). This module is a pure validator —
 * it carries no credentials and no gate/verdict semantics (those are control).
 *
 * @module @deepseek-ai/dsh-plugin-testbed/protocol/jsonschema
 */
import { Buffer } from 'node:buffer'

export const JSON_SCHEMA_DRAFT_2020_12 = 'https://json-schema.org/draft/2020-12/schema'
export const MAX_SCHEMA_BYTES = 65536 // 64 KiB
export const MAX_SCHEMA_DEPTH = 32

/** @param {unknown} v */
function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

/** @param {unknown} v */
function fmt(v) {
  try {
    return JSON.stringify(v)
  } catch {
    return String(v)
  }
}

/**
 * Walk a schema tree once, computing max nesting depth and collecting any
 * `$ref` value that is not a `#`-local pointer (i.e. remote / absolute).
 * @param {unknown} node
 * @param {WeakSet<object>} visited
 * @returns {{ depth: number, remoteRefs: string[] }}
 */
function walkSchema(node, visited) {
  const empty = { depth: 0, remoteRefs: [] }
  if (node === null || typeof node !== 'object') return empty
  if (visited.has(node)) return empty // cycle guard (defensive)
  visited.add(node)

  let depth = 1
  const remoteRefs = []

  const entries = Array.isArray(node) ? node.map((v, i) => [i, v]) : Object.entries(node)
  for (const [key, value] of entries) {
    if (!Array.isArray(node) && key === '$ref') {
      // Only `#`-local pointers are allowed; anything else is remote/absolute.
      if (typeof value !== 'string' || !value.startsWith('#')) {
        remoteRefs.push(typeof value === 'string' ? value : String(value))
      }
      continue // the $ref value is a pointer string, not a subschema
    }
    const child = walkSchema(value, visited)
    remoteRefs.push(...child.remoteRefs)
    if (child.depth + 1 > depth) depth = child.depth + 1
  }
  return { depth, remoteRefs }
}

/**
 * Validate the *meta-structure* of a JSON Schema (not datavalidation): must be
 * an object, `$schema` (if present) fixed to Draft 2020-12, no remote `$ref`,
 * serialized size ≤ `MAX_SCHEMA_BYTES`, nesting depth ≤ `MAX_SCHEMA_DEPTH`.
 * @param {unknown} schema
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validateSchemaMeta(schema) {
  if (!isPlainObject(schema)) {
    return { ok: false, errors: ['schema-not-object'] }
  }
  const errors = []

  if (schema.$schema !== undefined && schema.$schema !== JSON_SCHEMA_DRAFT_2020_12) {
    errors.push(`schema-$schema-unsupported:${fmt(schema.$schema)}`)
  }

  let json
  try {
    json = JSON.stringify(schema)
  } catch {
    return { ok: false, errors: ['schema-not-serializable'] }
  }
  if (json === undefined) return { ok: false, errors: ['schema-not-serializable'] }
  if (Buffer.byteLength(json, 'utf8') > MAX_SCHEMA_BYTES) errors.push('schema-too-large')

  const { depth, remoteRefs } = walkSchema(schema, new WeakSet())
  if (depth > MAX_SCHEMA_DEPTH) errors.push('schema-too-deep')
  for (const ref of remoteRefs) errors.push(`remote-$ref:${ref}`)

  return { ok: errors.length === 0, errors }
}

/** @param {unknown} v @param {unknown} t */
function typeMatches(v, t) {
  switch (t) {
    case 'string': return typeof v === 'string'
    case 'number': return typeof v === 'number'
    case 'integer': return typeof v === 'number' && Number.isInteger(v)
    case 'boolean': return typeof v === 'boolean'
    case 'null': return v === null
    case 'object': return isPlainObject(v)
    case 'array': return Array.isArray(v)
    default: return false
  }
}

/** @param {unknown} a @param {unknown} b */
function deepEqual(a, b) {
  if (Object.is(a, b)) return true
  if (!isPlainObject(a) && !Array.isArray(a)) return false
  if (!isPlainObject(b) && !Array.isArray(b)) return false
  if (Array.isArray(a) !== Array.isArray(b)) return false
  if (Array.isArray(a)) {
    if (a.length !== b.length) return false
    for (let i = 0; i < a.length; i++) if (!deepEqual(a[i], b[i])) return false
    return true
  }
  const ka = Object.keys(a).sort()
  const kb = Object.keys(b).sort()
  if (ka.length !== kb.length) return false
  for (let i = 0; i < ka.length; i++) {
    if (ka[i] !== kb[i]) return false
    if (!deepEqual(a[ka[i]], b[ka[i]])) return false
  }
  return true
}

/**
 * Resolve a `#/...` JSON pointer against the root schema document.
 * @param {unknown} root
 * @param {string} pointer
 * @returns {unknown}
 */
function resolvePointer(root, pointer) {
  if (pointer === '#') return root
  if (!pointer.startsWith('#/')) return undefined
  let cur = root
  for (const raw of pointer.slice(2).split('/')) {
    const tok = raw.replace(/~1/g, '/').replace(/~0/g, '~')
    if (cur === null || typeof cur !== 'object') return undefined
    if (!(tok in cur)) return undefined
    cur = cur[tok]
  }
  return cur
}

/**
 * Validate one instance node against a (sub)schema in place, appending errors.
 * @param {unknown} value
 * @param {unknown} schema
 * @param {string[]} errors
 * @param {unknown} root
 * @param {string[]} refStack
 */
function validateInstance(value, schema, errors, root, refStack) {
  if (schema === true) return
  if (schema === false) { errors.push('value-not-allowed'); return }
  if (schema === null || typeof schema !== 'object' || Array.isArray(schema)) return

  // $ref — local `#/...` pointers only, resolved recursively against root.
  if ('$ref' in schema) {
    const ref = schema.$ref
    if (typeof ref !== 'string' || !ref.startsWith('#')) {
      errors.push(`invalid-$ref:${fmt(ref)}`)
      return
    }
    if (refStack.includes(ref)) {
      errors.push(`$ref-cycle:${ref}`)
      return
    }
    const target = resolvePointer(root, ref)
    if (target === undefined) {
      errors.push(`unresolved-$ref:${ref}`)
      return
    }
    validateInstance(value, target, errors, root, [...refStack, ref])
  }

  // type (single string or array of strings)
  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type]
    if (!types.some((t) => typeMatches(value, t))) {
      errors.push(`type:${fmt(schema.type)}`)
    }
  }

  // object-only keywords
  if (isPlainObject(value)) {
    if (Array.isArray(schema.required)) {
      for (const req of schema.required) {
        if (typeof req === 'string' && !(req in value)) errors.push(`required-missing:${req}`)
      }
    }
    if (isPlainObject(schema.properties)) {
      for (const name of Object.keys(schema.properties)) {
        if (name in value) validateInstance(value[name], schema.properties[name], errors, root, refStack)
      }
    }
    if (schema.additionalProperties !== undefined) {
      const known = isPlainObject(schema.properties) ? Object.keys(schema.properties) : []
      for (const name of Object.keys(value)) {
        if (known.includes(name)) continue
        const ap = schema.additionalProperties
        if (ap === false) errors.push(`additional-properties-not-allowed:${name}`)
        else if (ap !== true && isPlainObject(ap)) validateInstance(value[name], ap, errors, root, refStack)
      }
    }
  }

  // array-only keyword (single-schema `items`, per Draft 2020-12)
  if (Array.isArray(value) && schema.items !== undefined) {
    const items = schema.items
    if (items === false) {
      for (let i = 0; i < value.length; i++) errors.push(`items-not-allowed:${i}`)
    } else if (items !== true && isPlainObject(items)) {
      for (let i = 0; i < value.length; i++) validateInstance(value[i], items, errors, root, refStack)
    }
  }

  // enum / const
  if (Array.isArray(schema.enum) && !schema.enum.some((e) => deepEqual(value, e))) {
    errors.push(`enum:${fmt(schema.enum)}`)
  }
  if (schema.const !== undefined && !deepEqual(value, schema.const)) {
    errors.push(`const:${fmt(schema.const)}`)
  }

  // string length (Unicode code points, not UTF-16 units)
  if (typeof value === 'string') {
    const len = [...value].length
    if (typeof schema.minLength === 'number' && len < schema.minLength) errors.push(`minLength:${schema.minLength}`)
    if (typeof schema.maxLength === 'number' && len > schema.maxLength) errors.push(`maxLength:${schema.maxLength}`)
  }

  // numeric bounds
  if (typeof value === 'number') {
    if (typeof schema.minimum === 'number' && value < schema.minimum) errors.push(`minimum:${schema.minimum}`)
    if (typeof schema.maximum === 'number' && value > schema.maximum) errors.push(`maximum:${schema.maximum}`)
  }
}

/**
 * Validate an instance `value` against a schema (Draft 2020-12 subset).
 * Unknown keywords are ignored.
 * @param {unknown} value
 * @param {unknown} schema
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validateValue(value, schema) {
  const errors = []
  validateInstance(value, schema, errors, schema, [])
  return { ok: errors.length === 0, errors }
}