/**
 * Control-plane ↔ worker protocol envelopes and bounded transport constraints.
 * `control-protocol/v1` is retained for built-in host operations; manifest tools
 * use the independent, closed `test-tool/v1` envelope.
 * @module @deepseek-ai/dsh-plugin-testbed/protocol/transport
 */
import { EXECUTION_STATUS, TEST_TOOL_PROTOCOL_VERSION } from './enums.js'

export const CONTROL_PROTOCOL_VERSION = 'control-protocol/v1'

/** Single serialized frame ceiling. */
export const MAX_FRAME_BYTES = 1048576 // 1 MiB
/** Default aggregate stdout/stderr ceiling per execution. */
export const DEFAULT_MAX_OUTPUT_BYTES = 1048576
/** Explicit collection limits; total serialized size is independently bounded. */
export const MAX_OBSERVATIONS = 1024
export const MAX_ARTIFACT_REFS = 256
export const MAX_DIAGNOSTICS = 256

const SHA256 = /^sha256:[0-9a-f]{64}$/
const CAPABILITY_REF = /^cap-sha256:[0-9a-f]{64}$/
const CORRELATION_FIELDS = Object.freeze(['request_id', 'run_id', 'plan_id', 'test_id', 'attempt'])
const TOOL_REF_FIELDS = Object.freeze(['tool_id', 'version', 'artifact_digest'])
const TARGET_REF_FIELDS = Object.freeze(['kind', 'owner_put_digest', 'origin'])
const TOOL_REQUEST_FIELDS = Object.freeze([
  'protocol_version', 'request_id', 'run_id', 'plan_id', 'test_id', 'attempt',
  'tool_ref', 'target_ref', 'input', 'deadline', 'capability_snapshot_ref',
])
const TOOL_RESPONSE_FIELDS = Object.freeze([
  'protocol_version', 'request_id', 'run_id', 'plan_id', 'test_id', 'attempt',
  'tool_ref', 'execution_status', 'observations', 'artifact_refs', 'diagnostics',
])
const CONTROL_REQUEST_FIELDS = Object.freeze([
  'protocol_version', 'kind', ...CORRELATION_FIELDS, 'tool_ref', 'input', 'deadline_ms',
])
const CONTROL_STARTED_FIELDS = Object.freeze([
  'protocol_version', 'kind', ...CORRELATION_FIELDS, 'tool_ref',
])
const CONTROL_RESPONSE_FIELDS = Object.freeze([
  'protocol_version', 'kind', ...CORRELATION_FIELDS, 'tool_ref', 'execution_status',
  'observations', 'reason_codes', 'artifact_refs', 'diagnostics',
])

/** Transport-level reject vocabulary. */
export const TRANSPORT_REASON_CODES = Object.freeze([
  'oversize', 'unknown-version', 'unknown-field', 'duplicate', 'out-of-order',
  'late', 'correlation-mismatch', 'orphan', 'deadline', 'no-response', 'worker-crash', 'cancelled',
])

/** @param {string} v */
export function isControlProtocolVersion(v) {
  return v === CONTROL_PROTOCOL_VERSION
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0
}

function hasOnlyKeys(value, allowed) {
  return Object.keys(value).every((key) => allowed.includes(key))
}

function jsonByteLength(value) {
  try {
    const json = JSON.stringify(value)
    return typeof json === 'string' ? Buffer.byteLength(json, 'utf8') : Infinity
  } catch {
    return Infinity
  }
}

function validToolRef(value) {
  return isPlainObject(value) && hasOnlyKeys(value, TOOL_REF_FIELDS) &&
    TOOL_REF_FIELDS.every((key) => isNonEmptyString(value[key])) && SHA256.test(value.artifact_digest)
}

function validTargetRef(value) {
  return isPlainObject(value) && hasOnlyKeys(value, TARGET_REF_FIELDS) &&
    TARGET_REF_FIELDS.every((key) => isNonEmptyString(value[key])) && SHA256.test(value.owner_put_digest)
}

function validCorrelation(frame) {
  return CORRELATION_FIELDS.every((key) => key === 'attempt'
    ? Number.isSafeInteger(frame[key]) && frame[key] > 0
    : isNonEmptyString(frame[key]))
}

function isRfc3339(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/.test(value)) return false
  return Number.isFinite(Date.parse(value))
}

function validArtifactRefs(value, maxCount = MAX_ARTIFACT_REFS) {
  if (!Array.isArray(value) || value.length > maxCount) return false
  return value.every((artifact) => isPlainObject(artifact) &&
    Object.keys(artifact).length === 3 && Object.keys(artifact).every((key) => ['kind', 'digest', 'size_bytes'].includes(key)) &&
    isNonEmptyString(artifact.kind) && SHA256.test(artifact.digest) &&
    Number.isSafeInteger(artifact.size_bytes) && artifact.size_bytes >= 0)
}

function validObservation(observation) {
  const keys = ['observation_id', 'schema_ref', 'value', 'source', 'limitations']
  return isPlainObject(observation) && Object.keys(observation).length === keys.length &&
    hasOnlyKeys(observation, keys) && isNonEmptyString(observation.observation_id) &&
    isNonEmptyString(observation.schema_ref) && observation.source === 'worker' &&
    Array.isArray(observation.limitations) && observation.limitations.every(isNonEmptyString) &&
    jsonByteLength(observation.value) !== Infinity
}

function validDiagnostics(value, maxCount = MAX_DIAGNOSTICS) {
  return Array.isArray(value) && value.length <= maxCount && value.every((item) =>
    typeof item === 'string' || isPlainObject(item) || Array.isArray(item) || item === null || typeof item === 'number' || typeof item === 'boolean')
}

function result(ok, reason_code) {
  return ok ? { ok: true } : { ok: false, reason_code }
}

/**
 * Build the exact `test-tool/v1` ToolRequest envelope. `input` remains only the
 * manifest-constrained payload; manifest/path binding is supplied out-of-band.
 * @param {{request_id:string,run_id:string,plan_id:string,test_id:string,attempt:number,
 * tool_ref:object,target_ref:object,input:unknown,deadline:string,capability_snapshot_ref:string}} params
 */
export function buildToolRequestFrame(params) {
  if (!isPlainObject(params) || !hasOnlyKeys(params, TOOL_REQUEST_FIELDS.filter((field) => field !== 'protocol_version'))) {
    throw new TypeError('buildToolRequestFrame: invalid request fields')
  }
  const frame = {
    protocol_version: TEST_TOOL_PROTOCOL_VERSION,
    request_id: params.request_id,
    run_id: params.run_id,
    plan_id: params.plan_id,
    test_id: params.test_id,
    attempt: params.attempt,
    tool_ref: params.tool_ref,
    target_ref: params.target_ref,
    input: params.input,
    deadline: params.deadline,
    capability_snapshot_ref: params.capability_snapshot_ref,
  }
  const checked = assertToolRequest(frame)
  if (!checked.ok) throw new TypeError(`buildToolRequestFrame: ${checked.reason_code}`)
  return frame
}

/** Validate a closed `test-tool/v1` ToolRequest envelope. */
export function assertToolRequest(frame, options = {}) {
  if (!isPlainObject(frame)) return result(false, 'unknown-field')
  if (frame.protocol_version !== TEST_TOOL_PROTOCOL_VERSION) return result(false, 'unknown-version')
  if (!hasOnlyKeys(frame, TOOL_REQUEST_FIELDS) || TOOL_REQUEST_FIELDS.some((key) => !(key in frame))) return result(false, 'unknown-field')
  if (!validCorrelation(frame) || !validToolRef(frame.tool_ref)) return result(false, 'correlation-mismatch')
  if (!validTargetRef(frame.target_ref) || !isRfc3339(frame.deadline) ||
      !CAPABILITY_REF.test(frame.capability_snapshot_ref ?? '')) return result(false, 'unknown-field')
  const maxBytes = options.maxBytes ?? MAX_FRAME_BYTES
  if (jsonByteLength(frame) > maxBytes) return result(false, 'oversize')
  return { ok: true }
}

/**
 * Validate a closed `test-tool/v1` ToolResponse and its exact request binding.
 * Observation values remain subject to the manifest observation schema.
 */
export function assertToolResponse(frame, request, options = {}) {
  if (!isPlainObject(frame)) return result(false, 'unknown-field')
  if (frame.protocol_version !== TEST_TOOL_PROTOCOL_VERSION) return result(false, 'unknown-version')
  if (!hasOnlyKeys(frame, TOOL_RESPONSE_FIELDS) || TOOL_RESPONSE_FIELDS.some((key) => !(key in frame))) return result(false, 'unknown-field')
  const reqShape = assertToolRequest(request, options)
  if (!reqShape.ok) return result(false, 'correlation-mismatch')
  if (!validCorrelation(frame) || !CORRELATION_FIELDS.every((key) => frame[key] === request[key]) ||
      !validToolRef(frame.tool_ref) || !TOOL_REF_FIELDS.every((key) => frame.tool_ref[key] === request.tool_ref[key])) {
    return result(false, 'correlation-mismatch')
  }
  if (!EXECUTION_STATUS.includes(frame.execution_status)) return result(false, 'unknown-field')
  const maxObservations = options.maxObservations ?? MAX_OBSERVATIONS
  const maxArtifacts = options.maxArtifactRefs ?? MAX_ARTIFACT_REFS
  const maxDiagnostics = options.maxDiagnostics ?? MAX_DIAGNOSTICS
  if (!Array.isArray(frame.observations) || frame.observations.length > maxObservations ||
      !frame.observations.every(validObservation)) return result(false, 'unknown-field')
  const ids = frame.observations.map((item) => item.observation_id)
  if (new Set(ids).size !== ids.length) return result(false, 'duplicate')
  if (!validArtifactRefs(frame.artifact_refs, maxArtifacts) || !validDiagnostics(frame.diagnostics, maxDiagnostics)) {
    return result(false, 'unknown-field')
  }
  if (jsonByteLength(frame) > (options.maxBytes ?? MAX_FRAME_BYTES)) return result(false, 'oversize')
  return { ok: true }
}

/**
 * Construct the backwards-compatible built-in host request frame.
 * @param {{request_id:string,run_id:string,plan_id:string,test_id:string,attempt:number,
 * tool_ref?:object|null,input:unknown,deadline_ms:number}} params
 */
export function buildRequestFrame({ request_id, run_id, plan_id, test_id, attempt, tool_ref = null, input, deadline_ms }) {
  return {
    protocol_version: CONTROL_PROTOCOL_VERSION,
    kind: 'request',
    request_id,
    run_id,
    plan_id,
    test_id,
    attempt,
    tool_ref,
    input,
    deadline_ms,
  }
}

/** Strict, version-aware validation for either protocol's transport frame. */
export function assertFrameShape(frame) {
  if (!isPlainObject(frame)) return result(false, 'unknown-field')
  if (frame.protocol_version === TEST_TOOL_PROTOCOL_VERSION) {
    if (frame.kind === undefined) return assertToolRequest(frame)
    return result(false, 'unknown-field')
  }
  if (frame.protocol_version !== CONTROL_PROTOCOL_VERSION) return result(false, 'unknown-version')
  const fieldsByKind = {
    request: CONTROL_REQUEST_FIELDS,
    started: CONTROL_STARTED_FIELDS,
    response: CONTROL_RESPONSE_FIELDS,
  }
  const allowed = fieldsByKind[frame.kind]
  if (!allowed) return result(false, 'unknown-field')
  if (!hasOnlyKeys(frame, allowed)) return result(false, 'unknown-field')
  if (!CORRELATION_FIELDS.every((key) => key in frame) || !validCorrelation(frame)) return result(false, 'correlation-mismatch')

  if (frame.tool_ref !== undefined && frame.tool_ref !== null && !validToolRef(frame.tool_ref)) {
    return result(false, 'unknown-field')
  }
  if (frame.kind === 'request') {
    if (!('input' in frame) || !Number.isFinite(frame.deadline_ms) || frame.deadline_ms <= 0 ||
        jsonByteLength(frame) > MAX_FRAME_BYTES) return result(false, 'unknown-field')
    return { ok: true }
  }
  if (frame.kind === 'started') return { ok: true }
  if (!EXECUTION_STATUS.includes(frame.execution_status) || !Array.isArray(frame.observations)) return result(false, 'unknown-field')
  if (frame.reason_codes !== undefined && (!Array.isArray(frame.reason_codes) || !frame.reason_codes.every(isNonEmptyString))) {
    return result(false, 'unknown-field')
  }
  if (frame.artifact_refs !== undefined && !validArtifactRefs(frame.artifact_refs)) return result(false, 'unknown-field')
  if (frame.diagnostics !== undefined && !validDiagnostics(frame.diagnostics)) return result(false, 'unknown-field')
  if (frame.observations.length > MAX_OBSERVATIONS || jsonByteLength(frame) > MAX_FRAME_BYTES) return result(false, 'oversize')
  return { ok: true }
}
