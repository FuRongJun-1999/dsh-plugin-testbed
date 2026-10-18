/**
 * Fixed manifest-driven `local-worker-json` runner.
 *
 * The launcher hashes one read-once artifact byte string and transports those
 * exact bytes to a fixed child entrypoint for data-URL execution. This is L1
 * fault isolation, not an OS security boundary; capabilities remain unenforced.
 */
import { createHash } from 'node:crypto'
import { createInterface } from 'node:readline'
import { readFile, realpath } from 'node:fs/promises'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { isAbsolute, relative, resolve, sep, win32 } from 'node:path'
import { validateValue } from '../protocol/jsonschema.js'
import { EXECUTION_STATUS, TEST_TOOL_PROTOCOL_VERSION } from '../protocol/enums.js'
import { assertToolRequest, assertToolResponse, MAX_FRAME_BYTES } from '../protocol/transport.js'
import { pinTool, validateToolManifest } from '../protocol/tool-manifest.js'
import { minimalChildEnvironment } from './environment.js'
import { boundObservationValue, redactText, truncateUtf8, MAX_OBSERVATION_BYTES } from './observe.js'

export const LOCAL_WORKER_JSON_ADAPTER = 'local-worker-json'
export const LOCAL_WORKER_JSON_ENTRYPOINT = 'run'
export const RUNNER_CHILD_ARG = '--local-worker-json-child'
/**
 * Cleanup coordination marker written by the **trusted runner** to the host's
 * stderr (never to the protocol stdout). The adapter consumes it only to track
 * the tool child pid for process-tree reaping — it is *not* invocation-start
 * evidence, not a protocol frame, and tool code cannot write it (tool code runs
 * in the grandchild, whose stderr is drained inside the host).
 */
export const RUNNER_CHILD_CLEANUP_MARKER = '[dsh-testbed-cleanup]'

/**
 * Parent-death channel: the runner host writes the single protocol line to the
 * child's stdin but **never ends the stream while the attempt is in flight**.
 * The child treats stdin `end`/`close` as "parent gone" and self-terminates. If
 * the host is killed (cancel/crash/`taskkill` of the process tree), the OS closes
 * the pipe and a re-parented tool grandchild cannot survive as an orphan — even
 * if `taskkill /T` missed it. No protocol data is read after the one line; this
 * is defense-in-depth for the L1 reaper, not an evidence channel.
 */

// Only the fixed worker host owns the adapter-facing stderr channel; direct
// in-process use (unit tests importing this module) must not emit markers.
const IS_WORKER_HOST_PROCESS = typeof process.argv[1] === 'string' &&
  /(?:^|[\\/])worker[\\/]host\.js$/.test(process.argv[1])

function emitChildCleanupMarker(event, pid) {
  if (!IS_WORKER_HOST_PROCESS) return
  if (!Number.isSafeInteger(pid) || pid < 1) return
  try {
    process.stderr.write(`${RUNNER_CHILD_CLEANUP_MARKER} ${event} pid=${pid}\n`)
  } catch {
    /* diagnostics-only channel: never fail the run because stderr is gone */
  }
}
export const MAX_OUTPUT_BYTES = 1024 * 1024
export const MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
export const MAX_TIMEOUT_MS = 5 * 60 * 1000
export const MAX_OBSERVATIONS = 64
export const MAX_DIAGNOSTIC_BYTES = 64 * 1024
// One observation value budget; re-exported from the assembly module so callers
// and tests see a single limit.
export { MAX_OBSERVATION_BYTES }

const SHA256_RE = /^sha256:[0-9a-f]{64}$/
const TOOL_REF_KEYS = ['tool_id', 'version', 'artifact_digest']
const REQUEST_FIELDS = [
  'protocol_version', 'request_id', 'run_id', 'plan_id', 'test_id', 'attempt',
  'tool_ref', 'target_ref', 'input', 'deadline', 'capability_snapshot_ref',
]

const json = (value) => {
  try { return JSON.stringify(value) ?? null } catch { return null }
}
const bytes = (value) => Buffer.byteLength(value, 'utf8')
const digest = (data) => `sha256:${createHash('sha256').update(data).digest('hex')}`
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)
const diagnostic = (code) => String(code).slice(0, 128)

function sameToolRef(left, right) {
  return isObject(left) && isObject(right) && TOOL_REF_KEYS.every((key) => left[key] === right[key]) &&
    Object.keys(left).length === TOOL_REF_KEYS.length && Object.keys(right).length === TOOL_REF_KEYS.length
}

/** Resolve a relative, slash-separated path strictly below workspaceRoot. */
export async function resolveArtifactPath(artifactPath, workspaceRoot = process.cwd()) {
  if (typeof artifactPath !== 'string' || artifactPath.length === 0 || artifactPath.includes('\0') ||
      artifactPath.startsWith('file:')) return { ok: false, reason: 'tool-artifact-path-invalid' }
  try {
    const root = await realpath(resolve(workspaceRoot))
    const isPinnedAbsolute = isAbsolute(artifactPath) || win32.isAbsolute(artifactPath)
    if (!isPinnedAbsolute && (artifactPath.includes('\\') || artifactPath.startsWith('/') || /^[a-zA-Z]:/i.test(artifactPath) ||
        artifactPath.split('/').some((part) => part === '' || part === '.' || part === '..'))) {
      return { ok: false, reason: 'tool-artifact-path-invalid' }
    }
    const candidate = isPinnedAbsolute ? resolve(artifactPath) : resolve(root, artifactPath)
    const lexical = relative(root, candidate)
    if (!lexical || lexical === '.' || lexical === '..' || lexical.startsWith(`..${sep}`) ||
        isAbsolute(lexical) || win32.isAbsolute(lexical)) return { ok: false, reason: 'tool-artifact-path-invalid' }
    const actual = await realpath(candidate)
    const rel = relative(root, actual)
    if (rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel) || win32.isAbsolute(rel)) {
      return { ok: false, reason: 'tool-artifact-path-invalid' }
    }
    return { ok: true, root, path: actual }
  } catch {
    return { ok: false, reason: 'tool-artifact-not-found' }
  }
}

function unsupportedModuleSpecifier(sourceBytes) {
  const source = sourceBytes.toString('utf8')
  if (source.includes('\u0000')) return 'tool-artifact-format-unsupported'
  if (/\bimport\s*\(\s*(?!['"])/.test(source)) return 'tool-import-unsupported'
  if (/\brequire\s*\(/.test(source)) return 'tool-import-unsupported'
  const specifiers = []
  const patterns = [
    /\bimport\s*\(\s*(['"])(.*?)\1\s*\)/gs,
    /\bimport\s+(?:[^;'"\n]*?\s+from\s*)?(['"])(.*?)\1/g,
    /\bexport\s+[^;]*?\s+from\s*(['"])(.*?)\1/gs,
  ]
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) specifiers.push(match[2])
  }
  return specifiers.some((specifier) => typeof specifier !== 'string' || !specifier.startsWith('node:'))
    ? 'tool-import-unsupported'
    : null
}

/** Read once, verify the declared digest, and return bytes for exact execution. */
export async function pinManifestArtifact({ manifest, artifactPath, workspaceRoot = process.cwd() } = {}) {
  const checked = validateToolManifest(manifest)
  if (!checked.ok) return { ok: false, errors: checked.errors, warnings: checked.warnings }
  if (manifest.runner?.adapter !== LOCAL_WORKER_JSON_ADAPTER) {
    return { ok: false, errors: ['runner-adapter-unsupported'], warnings: checked.warnings }
  }
  if (manifest.runner?.entrypoint !== LOCAL_WORKER_JSON_ENTRYPOINT) {
    return { ok: false, errors: ['runner-entrypoint-unsupported'], warnings: checked.warnings }
  }
  const resolved = await resolveArtifactPath(artifactPath, workspaceRoot)
  if (!resolved.ok) return { ok: false, errors: [resolved.reason], warnings: checked.warnings }

  let content
  try { content = await readFile(resolved.path) } catch {
    return { ok: false, errors: ['tool-artifact-read-failed'], warnings: checked.warnings }
  }
  if (content.byteLength > MAX_ARTIFACT_BYTES) {
    return { ok: false, errors: ['tool-artifact-oversize'], warnings: checked.warnings }
  }
  const unsupported = unsupportedModuleSpecifier(content)
  if (unsupported) return { ok: false, errors: [unsupported], warnings: checked.warnings }
  const artifactDigest = digest(content)
  const pinned = pinTool(manifest, artifactDigest)
  if (!pinned.ok) return { ...pinned, warnings: checked.warnings }

  return {
    ok: true,
    admission_stage: 'pinned',
    tool_ref: pinned.tool_ref,
    artifact_digest: artifactDigest,
    artifact_path: resolved.path,
    artifact_bytes: content,
    warnings: checked.warnings,
  }
}

function observationSchemaRef(manifest) {
  return typeof manifest.observation_schema?.$id === 'string' && manifest.observation_schema.$id.length > 0
    ? manifest.observation_schema.$id
    : `${manifest.tool_id}@${manifest.tool_version}#observation_schema`
}

function normalizeResult(raw, manifest, outputLimit) {
  let observations = []
  let refs = []
  let diagnostics = []
  if (isObject(raw) && ('observations' in raw || 'artifact_refs' in raw || 'diagnostics' in raw)) {
    observations = raw.observations ?? []
    refs = raw.artifact_refs ?? []
    diagnostics = raw.diagnostics ?? []
  } else if (Array.isArray(raw) && raw.every((v) => isObject(v) && 'value' in v)) {
    observations = raw
  } else {
    observations = [isObject(raw) && 'value' in raw ? raw : { value: raw }]
  }
  if (!Array.isArray(observations) || !Array.isArray(refs) || !Array.isArray(diagnostics)) {
    return { ok: false, reason: 'tool-output-invalid' }
  }
  if (observations.length > MAX_OBSERVATIONS) return { ok: false, reason: 'observation-limit-exceeded' }

  const ownDiagnostics = []
  const safeObservations = observations.map((item, index) => {
    const src = isObject(item) ? item : { value: item }
    const limitations = Array.isArray(src.limitations)
      ? src.limitations.filter((x) => typeof x === 'string').slice(0, 32)
        .map((x) => truncateUtf8(redactText(x), 128).text)
      : []
    // Redact inside the worker before anything is framed; summarize oversize.
    const bounded = boundObservationValue(src.value ?? null, { maxBytes: MAX_OBSERVATION_BYTES })
    limitations.push(...bounded.limitations)
    if (bounded.limitations.includes('value-summarized')) ownDiagnostics.push('observation-value-summarized')
    if (bounded.limitations.includes('value-redacted')) ownDiagnostics.push('observation-value-redacted')
    if (bounded.limitations.includes('value-truncated')) ownDiagnostics.push('observation-value-truncated')
    const schemaResult = validateValue(bounded.value, manifest.observation_schema)
    if (!schemaResult.ok) {
      limitations.push('observation-schema-invalid')
      ownDiagnostics.push('observation-schema-invalid')
    }
    return {
      observation_id: typeof src.observation_id === 'string' && src.observation_id.length > 0
        ? truncateUtf8(redactText(src.observation_id), 256).text
        : `obs-${index + 1}`,
      schema_ref: typeof src.schema_ref === 'string' && src.schema_ref.length > 0
        ? truncateUtf8(redactText(src.schema_ref), 512).text
        : observationSchemaRef(manifest),
      value: bounded.value,
      source: 'worker',
      limitations: [...new Set(limitations)],
    }
  })

  if (refs.length > 256) return { ok: false, reason: 'artifact-ref-limit-exceeded' }
  const safeRefs = []
  for (const ref of refs) {
    if (!isObject(ref) || typeof ref.kind !== 'string' || !ref.kind || !SHA256_RE.test(ref.digest) ||
        !Number.isSafeInteger(ref.size_bytes) || ref.size_bytes < 0) {
      ownDiagnostics.push('artifact-ref-invalid')
      continue
    }
    safeRefs.push({ kind: ref.kind.slice(0, 128), digest: ref.digest, size_bytes: ref.size_bytes })
  }
  if (diagnostics.length > 256) return { ok: false, reason: 'diagnostic-limit-exceeded' }
  // Do not forward tool-controlled diagnostic detail: it may contain ambient data.
  ownDiagnostics.push(...diagnostics.map(() => 'tool-diagnostic'))
  const result = { observations: safeObservations, artifact_refs: safeRefs, diagnostics: ownDiagnostics.slice(0, 256) }
  const text = json(result)
  if (text === null || bytes(text) > outputLimit) return { ok: false, reason: 'tool-output-oversize' }
  return { ok: true, ...result }
}

function childEnvironment() {
  // No ambient credentials: only allowlisted OS keys + NODE_NO_WARNINGS.
  return minimalChildEnvironment(process.env)
}

function terminate(child) {
  try { child.kill('SIGTERM') } catch { /* process already exited */ }
  const force = setTimeout(() => { try { child.kill('SIGKILL') } catch { /* already exited */ } }, 100)
  force.unref?.()
}

async function executeSnapshot({ artifactBytes, artifactDigest, input, timeoutMs, outputLimit, workspaceRoot, signal, onStarted }) {
  const childEntry = fileURLToPath(import.meta.url)
  let child
  try {
    child = spawn(process.execPath, [childEntry, RUNNER_CHILD_ARG], {
      // Fixed entry + argument array; never a shell string (architecture §8.4).
      shell: false,
      cwd: workspaceRoot ?? process.cwd(),
      env: childEnvironment(),
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    })
  } catch {
    return { ok: false, reason: 'tool-spawn-failed', execution_status: 'error' }
  }

  return await new Promise((resolveResult) => {
    let stdout = ''
    let failed = null
    let timer
    let settled = false
    const finish = (value) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      signal?.removeEventListener('abort', abort)
      // Release the parent side of the stdin parent-death channel once the
      // outcome is settled; the child has already exited (or is being terminated).
      try { child?.stdin?.destroy() } catch { /* already closed */ }
      resolveResult(value)
    }
    const stop = (reason, status = 'error') => {
      if (failed || settled) return
      failed = { ok: false, reason, execution_status: status }
      terminate(child)
    }
    const abort = () => stop('cancelled', 'cancelled')
    if (signal?.aborted) {
      abort()
    } else {
      signal?.addEventListener('abort', abort, { once: true })
      timer = setTimeout(() => stop('deadline', 'timeout'), timeoutMs)
    }
    child.stdout.setEncoding('utf8')
    child.stderr.resume() // drain; never surface untrusted diagnostics
    child.stdout.on('data', (chunk) => {
      if (failed || settled) return
      stdout += chunk
      if (bytes(stdout) > outputLimit) stop('tool-output-oversize')
    })
    child.on('error', () => finish(failed ?? { ok: false, reason: 'tool-spawn-failed', execution_status: 'error' }))
    child.on('close', (code) => {
      emitChildCleanupMarker('child_exit', child.pid)
      if (failed) return finish(failed)
      if (code !== 0) return finish({ ok: false, reason: 'tool-process-error', execution_status: 'error' })
      let payload
      try {
        const lines = stdout.split(/\r?\n/).filter((line) => line.trim() !== '')
        if (lines.length !== 1) throw new Error('one-line result required')
        payload = JSON.parse(lines[0])
      } catch {
        return finish({ ok: false, reason: 'tool-output-invalid', execution_status: 'error' })
      }
      if (!isObject(payload) || payload.ok !== true) return finish({ ok: false, reason: 'tool-process-error', execution_status: 'error' })
      finish({ ok: true, value: payload.result, execution_status: 'completed' })
    })

    const inputText = json({ input, artifact_b64: artifactBytes.toString('base64'), artifact_digest: artifactDigest })
    const inputLimit = MAX_ARTIFACT_BYTES * 2 + MAX_FRAME_BYTES
    if (inputText === null || bytes(inputText) > inputLimit) return stop('tool-input-oversize')
    child.once('spawn', () => {
      // Cleanup metadata only: lets the adapter track this grandchild pid for
      // process-tree reaping. It is *not* invocation-start evidence.
      emitChildCleanupMarker('child_spawn', child.pid)
      Promise.resolve().then(() => onStarted?.()).then(() => {
        // Keep stdin open while the attempt runs: EOF is the child's parent-death
        // signal. The stream is destroyed when the attempt settles.
        if (!settled) child.stdin.write(inputText + '\n')
      }).catch(() => stop('tool-start-notification-failed'))
    })
  })
}

function makeResponse(request, fields = {}) {
  return {
    protocol_version: TEST_TOOL_PROTOCOL_VERSION,
    request_id: request.request_id,
    run_id: request.run_id,
    plan_id: request.plan_id,
    test_id: request.test_id,
    attempt: request.attempt,
    tool_ref: request.tool_ref,
    execution_status: fields.execution_status ?? 'error',
    observations: fields.observations ?? [],
    artifact_refs: fields.artifact_refs ?? [],
    diagnostics: fields.diagnostics ?? [],
  }
}

/** Execute a validated test-tool/v1 request against independent pinned context. */
export async function runToolRequest({ request, binding, expectedCapabilitySnapshotRef, signal, onStarted } = {}) {
  const requestCheck = assertToolRequest(request)
  if (!requestCheck.ok) return { ok: false, reason: requestCheck.reason_code }
  if (!binding || !isObject(binding.manifest) || typeof binding.artifactPath !== 'string' ||
      typeof binding.workspaceRoot !== 'string' || !sameToolRef(binding.toolRef, request.tool_ref)) {
    return makeResponse(request, { diagnostics: ['tool-binding-mismatch'] })
  }
  if (request.capability_snapshot_ref !== expectedCapabilitySnapshotRef) {
    return makeResponse(request, { diagnostics: ['capability-snapshot-mismatch'] })
  }
  const manifestCheck = validateToolManifest(binding.manifest)
  if (!manifestCheck.ok) return makeResponse(request, { diagnostics: ['tool-manifest-invalid'] })
  // Request boundary: input must be bounded JSON before it reaches the runner.
  if (json(request.input) === null || Buffer.byteLength(json(request.input), 'utf8') > MAX_FRAME_BYTES) {
    return makeResponse(request, { diagnostics: ['tool-input-not-serializable'] })
  }
  if (typeof binding.workspaceRoot !== 'string' || !isAbsolute(binding.workspaceRoot)) {
    return makeResponse(request, { diagnostics: ['tool-workspace-invalid'] })
  }
  const inputCheck = validateValue(request.input, binding.manifest.input_schema)
  if (!inputCheck.ok) return makeResponse(request, { diagnostics: ['tool-input-schema-invalid'] })

  const requestDeadline = Date.parse(request.deadline)
  const declaredTimeout = Number(binding.manifest.limits?.timeout_ms) || 30_000
  const timeoutMs = Math.min(MAX_TIMEOUT_MS, declaredTimeout, Math.max(1, requestDeadline - Date.now()))
  const outputLimit = Math.min(MAX_OUTPUT_BYTES, Number(binding.manifest.limits?.output_bytes) || MAX_OUTPUT_BYTES)
  const pinned = await pinManifestArtifact({
    manifest: binding.manifest,
    artifactPath: binding.artifactPath,
    workspaceRoot: binding.workspaceRoot,
  })
  if (!pinned.ok) return makeResponse(request, { diagnostics: [pinned.errors?.[0] ?? 'tool-artifact-invalid'] })
  if (!sameToolRef(pinned.tool_ref, binding.toolRef) || !sameToolRef(pinned.tool_ref, request.tool_ref)) {
    return makeResponse(request, { diagnostics: ['tool-digest-mismatch'] })
  }

  const outcome = await executeSnapshot({
    artifactBytes: pinned.artifact_bytes,
    artifactDigest: pinned.artifact_digest,
    input: request.input,
    timeoutMs,
    outputLimit,
    workspaceRoot: binding.workspaceRoot,
    signal,
    onStarted,
  })
  if (!outcome.ok) {
    const status = EXECUTION_STATUS.includes(outcome.execution_status) ? outcome.execution_status : 'error'
    return makeResponse(request, { execution_status: status, diagnostics: [diagnostic(outcome.reason)] })
  }
  const normalized = normalizeResult(outcome.value, binding.manifest, outputLimit)
  if (!normalized.ok) return makeResponse(request, { diagnostics: [diagnostic(normalized.reason)] })
  const response = makeResponse(request, {
    execution_status: 'completed',
    observations: normalized.observations,
    artifact_refs: normalized.artifact_refs,
    diagnostics: normalized.diagnostics,
  })
  const responseCheck = assertToolResponse(response, request, { maxBytes: Math.min(MAX_FRAME_BYTES, outputLimit) })
  if (!responseCheck.ok) return makeResponse(request, { diagnostics: [diagnostic(responseCheck.reason_code)] })
  return response
}

async function runChild() {
  // Parent-death guard: the runner host keeps stdin open for the whole attempt
  // and is the only writer. EOF/close therefore means the host died (cancel,
  // crash, `taskkill` of the tree): the tool grandchild must not outlive it.
  let finished = false
  const onParentGone = () => {
    if (finished) return
    finished = true
    process.exit(0)
  }
  process.stdin.on('end', onParentGone)
  process.stdin.on('close', onParentGone)
  process.stdin.on('error', onParentGone)
  const finishChild = (payload, code) => {
    if (finished) return
    finished = true
    try { process.stdin.destroy() } catch { /* already closed */ }
    try {
      process.stdout.write(`${JSON.stringify(payload)}\n`, () => {
        process.exitCode = code
      })
    } catch {
      process.exitCode = 1
    }
  }

  const rl = createInterface({ input: process.stdin })
  let line = null
  try {
    line = await new Promise((resolve, reject) => {
      rl.once('line', resolve)
      rl.once('error', reject)
    })
    rl.close()
    // Keep observing EOF after the readline consumer is detached.
    process.stdin.resume()
    if (bytes(line) > MAX_ARTIFACT_BYTES * 2 + MAX_FRAME_BYTES) throw new Error('input oversize')
    if (process.argv.length !== 3 || process.argv[2] !== RUNNER_CHILD_ARG || line === null) throw new Error('invalid child invocation')
    const envelope = JSON.parse(line)
    if (!isObject(envelope) || typeof envelope.artifact_b64 !== 'string' || !isObject(envelope.input)) throw new Error('invalid child input')
    const artifactBytes = Buffer.from(envelope.artifact_b64, 'base64')
    if (artifactBytes.byteLength > MAX_ARTIFACT_BYTES || digest(artifactBytes) !== envelope.artifact_digest) {
      throw new Error('artifact digest mismatch')
    }
    // A data URL is built from the exact byte buffer that was hashed and
    // transported; no pathname is reopened after digest verification.
    const moduleUrl = `data:text/javascript;base64,${artifactBytes.toString('base64')}`
    const imported = await import(moduleUrl)
    const entry = imported.run ?? imported.default
    if (typeof entry !== 'function') throw new Error('artifact must export run(input)')
    const result = await entry(envelope.input)
    finishChild({ ok: true, result }, 0)
  } catch {
    finishChild({ ok: false }, 1)
  }
}

if (process.argv[2] === RUNNER_CHILD_ARG) await runChild()
