/**
 * Controlled assertion DSL (architecture §8.2, §9.4): interpret a validated
 * observation against frozen criteria → verdict. No user-supplied arbitrary code
 * is ever executed; only the whitelisted `equals|contains|schema-valid|
 * numeric-range|finding-count` ops. Finding severity never maps directly to a
 * verdict here — that remains the GatePolicy's decision.
 *
 * Migration phase `pure control`: `unknown` observation/criteria boundary,
 * closed `'pass'|'fail'` verdict, no change to the whitelist or comparison
 * semantics (including malformed-criteria fail-closed behavior).
 *
 * @module @deepseek-ai/dsh-plugin-testbed/control/assert
 */
import type { UnknownRecord } from '../protocol/types.js'

/** Result of one controlled assertion (never a gate decision). */
export interface AssertionResult {
  verdict: 'pass' | 'fail'
  reason_codes: string[]
  criteria_ref: string | null
}

type RangeBounds = { min: unknown; max: unknown }

/**
 * Apply one whitelisted assertion to an observation.
 *
 * `observation` may be a single `value` or a whole object; `criteria.path`
 * selects a nested value via dot path (e.g. `status_code`).
 */
export function applyAssertion(observation: unknown, criteria: unknown): AssertionResult {
  if (!criteria || typeof criteria !== 'object' || Array.isArray(criteria) ||
      typeof (criteria as UnknownRecord).assert !== 'string') {
    return { verdict: 'fail', reason_codes: ['missing-or-invalid-criteria'], criteria_ref: null }
  }
  const spec = criteria as UnknownRecord

  const rawCriteriaRef = spec.ref ?? spec.criteria_ref ?? null
  const criteriaRef = rawCriteriaRef === null || rawCriteriaRef === undefined ? null : (rawCriteriaRef as string)
  const actual = pathValue(observation, spec.path)

  switch (spec.assert) {
    case 'equals':
      return verdictFor(deepEqual(actual, spec.expected), 'equals-mismatch', criteriaRef)
    case 'contains':
      return verdictFor(containsMatch(actual, spec.expected), 'contains-mismatch', criteriaRef)
    case 'schema-valid':
      return verdictFor(validateSchema(actual, spec.schema), 'schema-invalid', criteriaRef)
    case 'numeric-range':
      return verdictFor(numericRangeMatch(actual, spec), 'numeric-range-out-of-bounds', criteriaRef)
    case 'finding-count':
      return verdictFor(findingCountMatch(observation, spec), 'finding-count-mismatch', criteriaRef)
    default:
      return { verdict: 'fail', reason_codes: ['unknown-assertion'], criteria_ref: criteriaRef }
  }
}

function verdictFor(ok: boolean, reasonCode: string, ref: unknown): AssertionResult {
  return {
    verdict: ok ? 'pass' : 'fail',
    reason_codes: ok ? [] : [reasonCode],
    criteria_ref: ref === null || ref === undefined ? null : (ref as string),
  }
}

/** Dot-path value extraction; empty/absent path returns the whole object. */
function pathValue(obj: unknown, path: unknown): unknown {
  if (path == null || path === '') return obj
  const parts: Array<string | number> = Array.isArray(path) ? path as Array<string | number> : String(path).split('.')
  let cur: unknown = obj
  for (const p of parts) {
    if (cur == null) return undefined
    cur = (cur as UnknownRecord)[String(p)]
  }
  return cur
}

/** JSON deep-equality (key-order-insensitive; arrays order-sensitive). */
function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true
  if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) return false
  const aArr = Array.isArray(a)
  const bArr = Array.isArray(b)
  if (aArr !== bArr) return false
  if (aArr) {
    const aArray = a as unknown[]
    const bArray = b as unknown[]
    if (aArray.length !== bArray.length) return false
    for (let i = 0; i < aArray.length; i++) if (!deepEqual(aArray[i], bArray[i])) return false
    return true
  }
  const aObject = a as UnknownRecord
  const bObject = b as UnknownRecord
  const aKeys = Object.keys(aObject)
  const bKeys = Object.keys(bObject)
  if (aKeys.length !== bKeys.length) return false
  for (const k of aKeys) {
    if (!Object.prototype.hasOwnProperty.call(bObject, k)) return false
    if (!deepEqual(aObject[k], bObject[k])) return false
  }
  return true
}

function containsMatch(actual: unknown, expected: unknown): boolean {
  if (expected === undefined) return false
  if (Array.isArray(actual)) {
    const items = Array.isArray(expected) ? expected : [expected]
    return items.every((item) => actual.some((a) => deepEqual(a, item)))
  }
  if (typeof actual === 'string') {
    return actual.includes(String(expected))
  }
  if (actual !== null && typeof actual === 'object' && expected !== null && typeof expected === 'object') {
    const actualObject = actual as UnknownRecord
    const expectedObject = expected as UnknownRecord
    return Object.keys(expectedObject).every(
      (k) => Object.prototype.hasOwnProperty.call(actualObject, k) && deepEqual(actualObject[k], expectedObject[k]),
    )
  }
  return deepEqual(actual, expected)
}

function numericRangeMatch(value: unknown, criteria: UnknownRecord): boolean {
  if (typeof value !== 'number' || Number.isNaN(value)) return false
  const { min, max } = rangeBounds(criteria)
  if (min == null && max == null) return false
  if (min != null && value < (min as number)) return false
  if (max != null && value > (max as number)) return false
  return true
}

/** Shared bound decoding: `expected` as `[min,max]` | `{min,max}`, or `min`/`max`. */
function rangeBounds(criteria: UnknownRecord): RangeBounds {
  const expected = criteria.expected
  let min = criteria.min
  let max = criteria.max
  if (Array.isArray(expected) && expected.length === 2) {
    min = expected[0]
    max = expected[1]
  } else if (expected !== null && typeof expected === 'object' && !Array.isArray(expected)) {
    const expectedObject = expected as UnknownRecord
    if (expectedObject.min != null) min = expectedObject.min
    if (expectedObject.max != null) max = expectedObject.max
  } else if (typeof expected === 'number') {
    // a single number means an exact equality bound (min === max)
    min = expected
    max = expected
  }
  return { min, max }
}

function findingCountMatch(observation: unknown, criteria: UnknownRecord): boolean {
  let findings: unknown
  if (criteria.path != null) {
    findings = pathValue(observation, criteria.path)
  } else if (Array.isArray(observation)) {
    findings = observation
  } else if (observation !== null && typeof observation === 'object') {
    findings = (observation as UnknownRecord).findings ?? []
  } else {
    findings = []
  }
  const list = Array.isArray(findings) ? findings : []
  const count = list.length
  const { min, max } = rangeBounds(criteria)
  if (min == null && max == null) return false
  if (min != null && count < (min as number)) return false
  if (max != null && count > (max as number)) return false
  return true
}

/**
 * Minimal JSON Schema (Draft 2020-12 subset) validator — enough to validate the
 * platform's inline `observation_schema` (`type`/`required`/`properties`/
 * `additionalProperties`/`const`/`enum`/`items`/numeric bounds). No remote `$ref`.
 */
function validateSchema(value: unknown, schema: unknown): boolean {
  if (schema == null) return false
  if (Array.isArray(schema)) return schema.some((s) => validateSchema(value, s))

  const node = schema as UnknownRecord

  if (node.type) {
    const types = Array.isArray(node.type) ? node.type : [node.type]
    if (!types.some((t) => typeMatches(value, t))) return false
  }
  if ('const' in node && !deepEqual(value, node.const)) return false
  if (node.enum && Array.isArray(node.enum) && !node.enum.some((e) => deepEqual(value, e))) return false

  if (typeof value === 'number') {
    if (typeof node.minimum === 'number' && value < node.minimum) return false
    if (typeof node.maximum === 'number' && value > node.maximum) return false
  }

  if (Array.isArray(value)) {
    if (node.items != null && !value.every((item) => validateSchema(item, node.items))) return false
    if (node.minItems != null && value.length < (node.minItems as number)) return false
    if (node.maxItems != null && value.length > (node.maxItems as number)) return false
    return true
  }

  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const valueObject = value as UnknownRecord
    if (node.required) {
      for (const k of node.required as unknown[]) {
        if (!Object.prototype.hasOwnProperty.call(valueObject, k as string)) return false
      }
    }
    const properties = node.properties
    const known = new Set(properties ? Object.keys(properties as UnknownRecord) : [])
    for (const k of Object.keys(valueObject)) {
      if (properties && Object.prototype.hasOwnProperty.call(properties, k)) {
        if (!validateSchema(valueObject[k], (properties as UnknownRecord)[k])) return false
      } else if (node.additionalProperties === false) {
        return false
      } else if (node.additionalProperties && typeof node.additionalProperties === 'object') {
        if (!validateSchema(valueObject[k], node.additionalProperties)) return false
      }
    }
    void known
    return true
  }

  if (typeof value === 'string') {
    if (node.minLength != null && value.length < (node.minLength as number)) return false
    if (node.maxLength != null && value.length > (node.maxLength as number)) return false
  }

  return true
}

function typeMatches(value: unknown, t: unknown): boolean {
  switch (t) {
    case 'object':
      return value !== null && typeof value === 'object' && !Array.isArray(value)
    case 'array':
      return Array.isArray(value)
    case 'string':
      return typeof value === 'string'
    case 'number':
      return typeof value === 'number'
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value)
    case 'boolean':
      return typeof value === 'boolean'
    case 'null':
      return value === null
    default:
      return false
  }
}
