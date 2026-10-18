/**
 * Canonical protocol type model — migration phase `protocol/types`.
 *
 * This module is the single source of *types* for the versioned protocol
 * artifacts. It is type-only at runtime (elided from the emitted JavaScript),
 * so importing it can never change runtime behavior, and it carries no
 * credentials, verdicts or gate authority.
 *
 * The model deliberately separates:
 *   - JSON domain values (`JsonValue`) from loose `unknown` input at the trust
 *     boundary: every validator accepts `unknown` and narrows explicitly;
 *   - closed protocol vocabularies (`RunStatus`, `Verdict`, `GateDecision`, ...)
 *     re-exported from `enums.ts`, so an enum can never be widened in one place;
 *   - validation/check results (`ValidationResult`, `CheckResult`), keeping the
 *     fail-closed `{ ok: false, errors }` / `{ ok: false, reason_code }` shapes
 *     explicit instead of implicit `any`.
 *
 * Types only — no runtime exports, no `any`, no `@ts-ignore`.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/protocol/types
 */

// ---------------------------------------------------------------------------
// JSON domain
// ---------------------------------------------------------------------------

/** Any value a protocol artifact may legally serialize to JSON. */
export type JsonPrimitive = string | number | boolean | null

/** A legal JSON value (RFC 8259); `undefined` is not representable. */
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue }

/** A JSON object with arbitrary string keys. */
export type JsonObject = { [key: string]: JsonValue }

/** A JSON array. */
export type JsonArray = JsonValue[]

/** Loose record used only while narrowing `unknown` at a trust boundary. */
export type UnknownRecord = Record<string, unknown>

/**
 * Declarative JSON Schema document (Draft 2020-12 subset accepted by
 * `jsonschema.ts`). Kept as a JSON object: validation is data-driven, and the
 * schema registry may not smuggle executable values.
 */
export type JsonSchemaDocument = JsonObject

/** A digest string; the exact `sha256:<64 hex>` shape is enforced at runtime. */
export type Sha256Digest = `sha256:${string}`

// ---------------------------------------------------------------------------
// Closed vocabulary re-exports (single definition lives in `enums.ts`)
// ---------------------------------------------------------------------------

export type {
  RunStatus,
  AdmissionStatus,
  ExecutionStatus,
  InvocationStatus,
  Verdict,
  GateDecision,
  CapabilityClaim,
  CapabilityObserved,
  CapabilityVerification,
  ToolRole,
  ToolPermissionKey,
  DeterminismValue,
  ObservationSource,
  TestClassification,
} from './enums.js'

// ---------------------------------------------------------------------------
// Validation / check results
// ---------------------------------------------------------------------------

/** Accumulating fail-closed validation result (`{ok, errors}`). */
export interface ValidationResult {
  ok: boolean
  errors: string[]
}

/** Transport-level verdict: exactly one machine-readable reason code on failure. */
export type CheckResult = { ok: true } | { ok: false; reason_code: string }

/** The three mutually-exclusive `receipt/v1` forms (`null` = indeterminate). */
export type ReceiptForm = 'frozen' | 'pre-plan-blocked' | 'pre-plan-cancelled' | null

/** Result of recomputing a `record_digest` (`actual` may be absent/malformed). */
export interface DigestVerification {
  ok: boolean
  expected: string
  actual: unknown
}

/** Manifest admission stages (`draft` is a hard error by contract). */
export type ToolAdmissionStage = 'draft' | 'validated' | 'pinned'

// ---------------------------------------------------------------------------
// Protocol references and envelopes
// ---------------------------------------------------------------------------

/** A pinned tool reference; `artifact_digest` is a fixed content digest. */
export interface ToolRef {
  tool_id: string
  version: string
  artifact_digest: string
}

/** The frozen target reference of a run-spec/v1 execution. */
export interface TargetRef {
  kind: string
  owner_put_digest: string
  origin: string
}

/** Correlation tuple every transport response must echo unchanged (§8.4.2). */
export interface CorrelationFields {
  request_id: string
  run_id: string
  plan_id: string
  test_id: string
  attempt: number
}

/** An observation artifact reference (`kind`, `digest`, `size_bytes`). */
export interface ArtifactRef {
  kind: string
  digest: string
  size_bytes: number
}

/** One worker-produced observation (value is bounded JSON, never authority). */
export interface WorkerObservation {
  observation_id: string
  schema_ref: string
  value: JsonValue
  source: 'worker'
  limitations: string[]
}

/** Parameters accepted by `buildToolRequestFrame` (input stays opaque JSON). */
export interface ToolRequestParams {
  request_id: string
  run_id: string
  plan_id: string
  test_id: string
  attempt: number
  tool_ref: ToolRef
  target_ref: TargetRef
  input: JsonValue
  deadline: string
  capability_snapshot_ref: string
}

/** A built `test-tool/v1` ToolRequest envelope (closed field set). */
export interface ToolRequestEnvelope extends CorrelationFields {
  protocol_version: string
  tool_ref: ToolRef
  target_ref: TargetRef
  input: JsonValue
  deadline: string
  capability_snapshot_ref: string
}

/** A built `test-tool/v1` ToolResponse envelope (closed field set). */
export interface ToolResponseEnvelope extends CorrelationFields {
  protocol_version: string
  tool_ref: ToolRef
  execution_status: string
  observations: WorkerObservation[]
  artifact_refs: ArtifactRef[]
  diagnostics: JsonValue[]
}

/** A built `control-protocol/v1` request frame (backwards-compatible host form). */
export interface ControlRequestFrame extends CorrelationFields {
  protocol_version: string
  kind: 'request'
  tool_ref: ToolRef | null
  input: JsonValue
  deadline_ms: number
}

/** Options bounding a transport frame check. */
export interface FrameLimits {
  maxBytes?: number
  maxObservations?: number
  maxArtifactRefs?: number
  maxDiagnostics?: number
}

/** Parameters accepted by the built-in `control-protocol/v1` request builder. */
export interface ControlRequestParams {
  request_id: string
  run_id: string
  plan_id: string
  test_id: string
  attempt: number
  tool_ref?: ToolRef | null
  input: JsonValue
  deadline_ms: number
}

/** Receipt integrity block; MVP receipts are never signed. */
export interface ReceiptIntegrity {
  record_digest: string
  signed: false
}

/** A `run-budget/v1` policy once validated (all fields present, bounded). */
export interface RunBudget {
  schema_version: string
  max_total_attempts: number
  max_total_time_ms: number
  max_total_cpu_ms: number
  max_total_memory_mb: number
  max_total_output_bytes: number
}
