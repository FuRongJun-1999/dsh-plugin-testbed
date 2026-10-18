/**
 * Minimal JSON Schema (Draft 2020-12) meta-validation + instance validation.
 *
 * Enforces the §8.4.1 / CONTRACT-m5 §1 constraints for tool `input_schema` and
 * `observation_schema`: no remote `$ref` (only `#`-local pointers / inline
 * `$defs`), bounded size and depth, and a fixed `$schema` dialect.
 *
 * `validateValue` implements the Draft 2020-12 subset the platform accepts:
 * `type`, `required`, `properties`, `additionalProperties`, `items`, `enum`,
 * `const`, `minLength`/`maxLength`, `pattern`, `minimum`/`maximum`,
 * `minItems`/`maxItems`/`uniqueItems`, `allOf`/`anyOf`/`oneOf`/`not` and local
 * `$ref` pointers. Unknown keywords are ignored (not errors). This module is a
 * pure validator — it carries no credentials and no gate/verdict semantics.
 *
 * Migration phase `protocol/types`: inputs stay `unknown` (the validator is a
 * trust boundary) and are narrowed through explicit `isJsonObject` /
 * `UnknownRecord` guards; the validation algorithm and every rejection code are
 * byte-for-byte semantics-preserving with the JavaScript baseline.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/protocol/jsonschema
 */
import { Buffer } from 'node:buffer'
import type { UnknownRecord, ValidationResult } from './types.js'

export const JSON_SCHEMA_DRAFT_2020_12 = 'https://json-schema.org/draft/2020-12/schema'
export const MAX_SCHEMA_BYTES = 65536 // 64 KiB
export const MAX_SCHEMA_DEPTH = 32

/** Narrow an unknown value to a plain JSON object (arrays excluded). */
function isPlainObject(v: unknown): v is UnknownRecord {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

function fmt(v: unknown): string {
  try {
    return JSON.stringify(v) as string
  } catch {
    return String(v)
  }
}

interface SchemaWalk {
  depth: number
  remoteRefs: string[]
}

/**
 * Walk a schema tree once, computing max nesting depth and collecting any
 * `$ref` value that is not a `#`-local pointer (i.e. remote / absolute).
 */
function walkSchema(node: unknown, visited: WeakSet<object>): SchemaWalk {
  const empty: SchemaWalk = { depth: 0, remoteRefs: [] }
  if (node === null || typeof node !== 'object') return empty
  if (visited.has(node)) return empty // cycle guard (defensive)
  visited.add(node)

  let depth = 1
  const remoteRefs: string[] = []

  const entries: Array<[string | number, unknown]> = Array.isArray(node)
    ? node.map((v, i): [number, unknown] => [i, v])
    : Object.entries(node)
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
 */
export function validateSchemaMeta(schema: unknown): ValidationResult {
  if (!isPlainObject(schema)) {
    return { ok: false, errors: ['schema-not-object'] }
  }
  const errors: string[] = []

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

function typeMatches(v: unknown, t: unknown): boolean {
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

function deepEqual(a: unknown, b: unknown): boolean {
  if (Object.is(a, b)) return true
  if (!isPlainObject(a) && !Array.isArray(a)) return false
  if (!isPlainObject(b) && !Array.isArray(b)) return false
  if (Array.isArray(a) !== Array.isArray(b)) return false
  if (Array.isArray(a)) {
    const bArray = b as unknown[]
    if (a.length !== bArray.length) return false
    for (let i = 0; i < a.length; i++) if (!deepEqual(a[i], bArray[i])) return false
    return true
  }
  const aObject = a as UnknownRecord
  const bObject = b as UnknownRecord
  const ka = Object.keys(aObject).sort()
  const kb = Object.keys(bObject).sort()
  if (ka.length !== kb.length) return false
  for (let i = 0; i < ka.length; i++) {
    if (ka[i] !== kb[i]) return false
    if (!deepEqual(aObject[ka[i]], bObject[kb[i]])) return false
  }
  return true
}

/**
 * Resolve a `#/...` JSON pointer against the root schema document.
 */
function resolvePointer(root: unknown, pointer: string): unknown {
  if (pointer === '#') return root
  if (!pointer.startsWith('#/')) return undefined
  let cur: unknown = root
  for (const raw of pointer.slice(2).split('/')) {
    const tok = raw.replace(/~1/g, '/').replace(/~0/g, '~')
    if (cur === null || typeof cur !== 'object') return undefined
    if (!(tok in cur)) return undefined
    cur = (cur as UnknownRecord)[tok]
  }
  return cur
}

/**
 * Validate one instance node against a (sub)schema in place, appending errors.
 */
function validateInstance(
  value: unknown,
  schema: unknown,
  errors: string[],
  root: unknown,
  refStack: string[],
): void {
  validateInstanceNode(value, schema, errors, root, refStack)
}

/**
 * Boolean form of {@link validateInstanceNode}, used by combinators.
 */
function matchesSchema(value: unknown, schema: unknown, root: unknown, refStack: string[]): boolean {
  const branchErrors: string[] = []
  validateInstanceNode(value, schema, branchErrors, root, refStack)
  return branchErrors.length === 0
}

function validateInstanceNode(
  value: unknown,
  schema: unknown,
  errors: string[],
  root: unknown,
  refStack: string[],
): void {
  if (schema === true) return
  if (schema === false) { errors.push('value-not-allowed'); return }
  if (schema === null || typeof schema !== 'object' || Array.isArray(schema)) return
  const node = schema as UnknownRecord

  // $ref — local `#/...` pointers only, resolved recursively against root.
  if ('$ref' in node) {
    const ref = node.$ref
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
  if (node.type !== undefined) {
    const types = Array.isArray(node.type) ? node.type : [node.type]
    if (!types.some((t) => typeMatches(value, t))) {
      errors.push(`type:${fmt(node.type)}`)
    }
  }

  // combinators (Draft 2020-12). `oneOf` is used by the receipt/v1 schema to
  // statically force the three mutually-exclusive forms.
  if (Array.isArray(node.allOf)) {
    for (const sub of node.allOf) validateInstance(value, sub, errors, root, refStack)
  }
  if (Array.isArray(node.anyOf) && !node.anyOf.some((sub) => matchesSchema(value, sub, root, refStack))) {
    errors.push('anyOf')
  }
  if (Array.isArray(node.oneOf)) {
    const matched = node.oneOf.filter((sub) => matchesSchema(value, sub, root, refStack)).length
    if (matched !== 1) errors.push(`oneOf:matched-${matched}`)
  }
  if (node.not !== undefined && matchesSchema(value, node.not, root, refStack)) {
    errors.push('not')
  }

  // object-only keywords
  if (isPlainObject(value)) {
    if (Array.isArray(node.required)) {
      for (const req of node.required) {
        if (typeof req === 'string' && !(req in value)) errors.push(`required-missing:${req}`)
      }
    }
    if (isPlainObject(node.properties)) {
      for (const name of Object.keys(node.properties)) {
        if (name in value) validateInstance(value[name], node.properties[name], errors, root, refStack)
      }
    }
    if (node.additionalProperties !== undefined) {
      const known = isPlainObject(node.properties) ? Object.keys(node.properties) : []
      for (const name of Object.keys(value)) {
        if (known.includes(name)) continue
        const ap = node.additionalProperties
        if (ap === false) errors.push(`additional-properties-not-allowed:${name}`)
        else if (ap !== true && isPlainObject(ap)) validateInstance(value[name], ap, errors, root, refStack)
      }
    }
  }

  // array-only keywords (single-schema `items`, per Draft 2020-12)
  if (Array.isArray(value)) {
    if (node.items !== undefined) {
      const items = node.items
      if (items === false) {
        for (let i = 0; i < value.length; i++) errors.push(`items-not-allowed:${i}`)
      } else if (items !== true && isPlainObject(items)) {
        for (let i = 0; i < value.length; i++) validateInstance(value[i], items, errors, root, refStack)
      }
    }
    if (typeof node.minItems === 'number' && value.length < node.minItems) {
      errors.push(`minItems:${node.minItems}`)
    }
    if (typeof node.maxItems === 'number' && value.length > node.maxItems) {
      errors.push(`maxItems:${node.maxItems}`)
    }
    if (node.uniqueItems === true) {
      for (let i = 0; i < value.length; i++) {
        for (let j = i + 1; j < value.length; j++) {
          if (deepEqual(value[i], value[j])) {
            errors.push(`uniqueItems:${i},${j}`)
            i = value.length // stop after the first duplicate pair
            break
          }
        }
      }
    }
  }

  // enum / const
  if (Array.isArray(node.enum) && !node.enum.some((e) => deepEqual(value, e))) {
    errors.push(`enum:${fmt(node.enum)}`)
  }
  if (node.const !== undefined && !deepEqual(value, node.const)) {
    errors.push(`const:${fmt(node.const)}`)
  }

  // string length (Unicode code points, not UTF-16 units) + pattern
  if (typeof value === 'string') {
    const len = [...value].length
    if (typeof node.minLength === 'number' && len < node.minLength) errors.push(`minLength:${node.minLength}`)
    if (typeof node.maxLength === 'number' && len > node.maxLength) errors.push(`maxLength:${node.maxLength}`)
    if (typeof node.pattern === 'string') {
      let re: RegExp | undefined
      try {
        re = new RegExp(node.pattern)
      } catch {
        errors.push(`invalid-pattern:${node.pattern}`)
      }
      if (re && !re.test(value)) errors.push(`pattern:${node.pattern}`)
    }
  }

  // numeric bounds
  if (typeof value === 'number') {
    if (typeof node.minimum === 'number' && value < node.minimum) errors.push(`minimum:${node.minimum}`)
    if (typeof node.maximum === 'number' && value > node.maximum) errors.push(`maximum:${node.maximum}`)
  }
}

/**
 * Validate an instance `value` against a schema (Draft 2020-12 subset).
 * Unknown keywords are ignored.
 */
export function validateValue(value: unknown, schema: unknown): ValidationResult {
  const errors: string[] = []
  validateInstance(value, schema, errors, schema, [])
  return { ok: errors.length === 0, errors }
}
