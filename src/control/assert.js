/**
 * Controlled assertion DSL (architecture §8.2, §9.4): interpret a validated
 * observation against frozen criteria → verdict. No user-supplied arbitrary code
 * is ever executed; only the whitelisted `equals|contains|schema-valid|
 * numeric-range|finding-count` ops. Finding severity never maps directly to a
 * verdict here — that remains the GatePolicy's decision.
 * @module @deepseek-ai/dsh-plugin-testbed/control/assert
 */

/**
 * Apply one whitelisted assertion to an observation.
 *
 * `observation` may be a single `value` or a whole object; `criteria.path`
 * selects a nested value via dot path (e.g. `status_code`).
 *
 * @param {unknown} observation observation value (or containing object)
 * @param {{assert:string, path?:string, expected?:unknown, schema?:object,
 *   min?:number, max?:number, ref?:string, criteria_ref?:string}} criteria
 * @returns {{verdict:'pass'|'fail', reason_codes:string[], criteria_ref:string|null}}
 */
export function applyAssertion(observation, criteria) {
  if (!criteria || typeof criteria !== 'object' || typeof criteria.assert !== 'string') {
    return { verdict: 'fail', reason_codes: ['missing-or-invalid-criteria'], criteria_ref: null }
  }

  const criteriaRef = criteria.ref ?? criteria.criteria_ref ?? null
  const actual = pathValue(observation, criteria.path)

  switch (criteria.assert) {
    case 'equals':
      return verdictFor(deepEqual(actual, criteria.expected), 'equals-mismatch', criteriaRef)
    case 'contains':
      return verdictFor(containsMatch(actual, criteria.expected), 'contains-mismatch', criteriaRef)
    case 'schema-valid':
      return verdictFor(validateSchema(actual, criteria.schema), 'schema-invalid', criteriaRef)
    case 'numeric-range':
      return verdictFor(numericRangeMatch(actual, criteria), 'numeric-range-out-of-bounds', criteriaRef)
    case 'finding-count':
      return verdictFor(findingCountMatch(observation, criteria), 'finding-count-mismatch', criteriaRef)
    default:
      return { verdict: 'fail', reason_codes: ['unknown-assertion'], criteria_ref: criteriaRef }
  }
}

function verdictFor(ok, reasonCode, ref) {
  return { verdict: ok ? 'pass' : 'fail', reason_codes: ok ? [] : [reasonCode], criteria_ref: ref }
}

/** Dot-path value extraction; empty/absent path returns the whole object. */
function pathValue(obj, path) {
  if (path == null || path === '') return obj
  const parts = Array.isArray(path) ? path : String(path).split('.')
  let cur = obj
  for (const p of parts) {
    if (cur == null) return undefined
    cur = cur[p]
  }
  return cur
}

/** JSON deep-equality (key-order-insensitive; arrays order-sensitive). */
function deepEqual(a, b) {
  if (a === b) return true
  if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) return false
  const aArr = Array.isArray(a)
  const bArr = Array.isArray(b)
  if (aArr !== bArr) return false
  if (aArr) {
    if (a.length !== b.length) return false
    for (let i = 0; i < a.length; i++) if (!deepEqual(a[i], b[i])) return false
    return true
  }
  const aKeys = Object.keys(a)
  const bKeys = Object.keys(b)
  if (aKeys.length !== bKeys.length) return false
  for (const k of aKeys) {
    if (!Object.prototype.hasOwnProperty.call(b, k)) return false
    if (!deepEqual(a[k], b[k])) return false
  }
  return true
}

function containsMatch(actual, expected) {
  if (expected === undefined) return false
  if (Array.isArray(actual)) {
    const items = Array.isArray(expected) ? expected : [expected]
    return items.every((item) => actual.some((a) => deepEqual(a, item)))
  }
  if (typeof actual === 'string') {
    return actual.includes(String(expected))
  }
  if (actual !== null && typeof actual === 'object' && expected !== null && typeof expected === 'object') {
    return Object.keys(expected).every(
      (k) => Object.prototype.hasOwnProperty.call(actual, k) && deepEqual(actual[k], expected[k]),
    )
  }
  return deepEqual(actual, expected)
}

function numericRangeMatch(value, criteria) {
  if (typeof value !== 'number' || Number.isNaN(value)) return false
  const { min, max } = rangeBounds(criteria)
  if (min == null && max == null) return false
  if (min != null && value < min) return false
  if (max != null && value > max) return false
  return true
}

/** Shared bound decoding: `expected` as `[min,max]` | `{min,max}`, or `min`/`max`. */
function rangeBounds(criteria) {
  const expected = criteria.expected
  let min = criteria.min
  let max = criteria.max
  if (Array.isArray(expected) && expected.length === 2) {
    min = expected[0]
    max = expected[1]
  } else if (expected !== null && typeof expected === 'object' && !Array.isArray(expected)) {
    if (expected.min != null) min = expected.min
    if (expected.max != null) max = expected.max
  } else if (typeof expected === 'number') {
    // a single number means an exact equality bound (min === max)
    min = expected
    max = expected
  }
  return { min, max }
}

function findingCountMatch(observation, criteria) {
  let findings
  if (criteria.path != null) {
    findings = pathValue(observation, criteria.path)
  } else if (Array.isArray(observation)) {
    findings = observation
  } else if (observation !== null && typeof observation === 'object') {
    findings = observation.findings ?? []
  } else {
    findings = []
  }
  if (!Array.isArray(findings)) findings = []
  const count = findings.length
  const { min, max } = rangeBounds(criteria)
  if (min == null && max == null) return false
  if (min != null && count < min) return false
  if (max != null && count > max) return false
  return true
}

/**
 * Minimal JSON Schema (Draft 2020-12 subset) validator — enough to validate the
 * platform's inline `observation_schema` (`type`/`required`/`properties`/
 * `additionalProperties`/`const`/`enum`/`items`/numeric bounds). No remote `$ref`.
 */
function validateSchema(value, schema) {
  if (schema == null) return false
  if (Array.isArray(schema)) return schema.some((s) => validateSchema(value, s))

  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type]
    if (!types.some((t) => typeMatches(value, t))) return false
  }
  if ('const' in schema && !deepEqual(value, schema.const)) return false
  if (schema.enum && Array.isArray(schema.enum) && !schema.enum.some((e) => deepEqual(value, e))) return false

  if (typeof value === 'number') {
    if (typeof schema.minimum === 'number' && value < schema.minimum) return false
    if (typeof schema.maximum === 'number' && value > schema.maximum) return false
  }

  if (Array.isArray(value)) {
    if (schema.items != null && !value.every((item) => validateSchema(item, schema.items))) return false
    if (schema.minItems != null && value.length < schema.minItems) return false
    if (schema.maxItems != null && value.length > schema.maxItems) return false
    return true
  }

  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    if (schema.required) {
      for (const k of schema.required) if (!Object.prototype.hasOwnProperty.call(value, k)) return false
    }
    const known = new Set(schema.properties ? Object.keys(schema.properties) : [])
    for (const k of Object.keys(value)) {
      if (schema.properties && Object.prototype.hasOwnProperty.call(schema.properties, k)) {
        if (!validateSchema(value[k], schema.properties[k])) return false
      } else if (schema.additionalProperties === false) {
        return false
      } else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
        if (!validateSchema(value[k], schema.additionalProperties)) return false
      }
    }
    return true
  }

  if (typeof value === 'string') {
    if (schema.minLength != null && value.length < schema.minLength) return false
    if (schema.maxLength != null && value.length > schema.maxLength) return false
  }

  return true
}

function typeMatches(value, t) {
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