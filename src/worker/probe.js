/**
 * Worker-side two-phase capability probe (architecture §8.3; design §3).
 *
 * Phase 1 — environment preflight **before** PUT code is loaded:
 *   Node/OS, locked Cordis runtime availability, temp dir, credential state,
 *   and the L1 limitations (network/filesystem/limits are not enforced).
 * Phase 2 — load the PUT in this worker, read its declarations and *measure*
 *   what actually happens (plugin shape, apply result, effective registrations,
 *   dispose). Declarations and measurements stay separate.
 *
 * The worker emits `claim` (`declared`/`not-declared`) and `observed`
 * (`present`/`absent`/`unknown`) only. It never emits `verification`,
 * `verdict`, `required`, `expected`, `not-applicable` or an authoritative
 * start time — those are control-face derivations. `unknown` is never
 * downgraded to `absent`; a missing/invalid locked runtime therefore produces
 * explicit unknown/absent evidence, never a fabricated `present`.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/worker/probe
 */
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { isAbsolute, join, resolve, win32 } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { CAPABILITY_CLAIM, CAPABILITY_OBSERVED } from '../protocol/enums.js'
import { canonicalJson, sha256Hex } from '../protocol/digest.js'
import { isCredentialEnvName } from './environment.js'
import { isPlainRecord, redactText, redactValue, sanitizeError, truncateUtf8, assertNoAuthorityFields } from './observe.js'
import { MAX_RUNTIME_ENTRY_BYTES, resolveRuntimeAnchor } from './runtime.js'

export const CAPABILITY_PROBE_VERSION = 'capability-probe/v1'
export const CAPABILITY_SNAPSHOT_VERSION = 'capability-snapshot/v1'
export const PROBE_IMPLEMENTATION = 'worker-capability-probe/2'
export const MAX_PROBE_CASES = 256
export const MAX_DECLARED_CAPABILITIES = 64
export const MAX_PUT_TIMEOUT_MS = 30_000
export const PROBE_DEFAULT_PUT_TIMEOUT_MS = 5_000
const SHA256 = /^sha256:[0-9a-f]{64}$/
const WORKER_REF = 'worker/l1-subprocess@0.1.0'

/** Deterministic worker fingerprint (identity + host facts, no timestamp). */
export function workerFingerprint() {
  return 'sha256:' + sha256Hex(canonicalJson({
    worker_ref: WORKER_REF,
    probe_implementation: PROBE_IMPLEMENTATION,
    node_version: process.version,
    os_platform: process.platform,
    os_arch: process.arch,
    isolation: 'L1-subprocess',
  }))
}

function capabilityRecord(capabilityKey, claim, observed, { evidence = null, limitations = [], external = false } = {}) {
  if (!CAPABILITY_CLAIM.includes(claim)) throw new TypeError(`capability claim outside closed set: ${claim}`)
  if (!CAPABILITY_OBSERVED.includes(observed)) throw new TypeError(`capability observed outside closed set: ${observed}`)
  return {
    capability_key: truncateUtf8(String(capabilityKey), 160).text,
    claim,
    observed,
    evidence: evidence === null ? null : redactValue(evidence, { maxDepth: 4, maxStringBytes: 512 }).value,
    limitations: [...new Set(limitations.map((item) => truncateUtf8(redactText(String(item)), 160).text))].slice(0, 32),
    ...(external ? { external: true } : {}),
  }
}

function aggregateObserved(records) {
  if (!Array.isArray(records) || records.length === 0) return 'unknown'
  if (records.some((record) => record.observed === 'absent')) return 'absent'
  if (records.some((record) => record.observed === 'unknown')) return 'unknown'
  return records.every((record) => record.observed === 'present') ? 'present' : 'unknown'
}

function aggregateClaim(records) {
  return Array.isArray(records) && records.some((record) => record.claim === 'declared') ? 'declared' : 'not-declared'
}

/** Runtime absence is a measured fact only for a few failure reasons. */
function runtimeObserved(runtime) {
  if (runtime?.status === 'available') return 'present'
  const reason = runtime?.reason ?? ''
  if (['runtime-entry-missing', 'runtime-entry-invalid', 'runtime-version-mismatch', 'runtime-environment-mismatch'].includes(reason)) {
    return 'absent'
  }
  return 'unknown'
}

async function probeTempDir() {
  let dir = null
  try {
    dir = await mkdtemp(join(tmpdir(), 'dsh-testbed-probe-'))
    return { observed: 'present', evidence: { location: 'os.tmpdir', writable: true } }
  } catch (error) {
    return { observed: 'absent', evidence: sanitizeError(error, { phase: 'env' }), limitations: ['temp-dir-unavailable'] }
  } finally {
    if (dir) {
      try { await rm(dir, { recursive: true, force: true }) } catch { /* best effort */ }
    }
  }
}

async function probeCordisImport(runtime) {
  if (runtime.status !== 'available' || !runtime.anchor?.cordis_entry) {
    return capabilityRecord('host:cordis-import', 'declared', 'unknown', {
      evidence: { runtime_status: runtime.status, runtime_reason: runtime.reason },
      limitations: ['cordis-runtime-unavailable'],
    })
  }
  try {
    const mod = await import(runtime.anchor.cordis_entry)
    if (typeof mod?.Context !== 'function') {
      return capabilityRecord('host:cordis-import', 'declared', 'absent', {
        limitations: ['cordis-context-missing'],
      })
    }
    return capabilityRecord('host:cordis-import', 'declared', 'present', {
      evidence: { cordis_version: runtime.provenance?.cordis_version ?? null },
    })
  } catch (error) {
    return capabilityRecord('host:cordis-import', 'declared', 'absent', {
      evidence: sanitizeError(error, { phase: 'env' }),
      limitations: ['cordis-import-failed'],
    })
  }
}

async function probeEnvironmentPhase({ runtime, env, environmentAudit, probeTime }) {
  const records = []
  const limitations = []

  records.push(capabilityRecord(
    'host:cordis-runtime',
    runtime.anchor?.cordis_entry ? 'declared' : 'not-declared',
    runtimeObserved(runtime),
    {
      evidence: {
        status: runtime.status,
        reason: runtime.reason,
        source: runtime.provenance?.source ?? null,
        runtime_kind: runtime.provenance?.runtime_kind ?? null,
        cordis_version: runtime.provenance?.cordis_version ?? null,
        cordis_version_verified: runtime.provenance?.cordis_version_verified ?? false,
      },
      limitations: runtime.limitations ?? [],
    },
  ))
  limitations.push(...(runtime.limitations ?? []))

  const importRecord = await probeCordisImport(runtime)
  records.push(importRecord)
  limitations.push(...importRecord.limitations)

  // Known optional host services, detected without loading PUT code. The list is
  // deliberately not exhaustive → an empty result is `unknown`, not `absent`.
  if (importRecord.observed === 'present') {
    try {
      const { Context } = await import(runtime.anchor.cordis_entry)
      const root = new Context()
      const known = ['cordisInspect', 'dynamicCordisRunner', 'tools', 'logger', 'events']
      const available = known.filter((name) => root?.[name] !== undefined)
      try { await root?.dispose?.() } catch { /* best effort */ }
      records.push(capabilityRecord('host:host-services', 'not-declared',
        available.length > 0 ? 'present' : 'unknown', {
          evidence: { known_services: known, observed_services: available },
          limitations: ['host-service-catalog-not-exhaustive'],
        }))
      if (available.length === 0) limitations.push('host-service-catalog-not-exhaustive')
    } catch (error) {
      records.push(capabilityRecord('host:host-services', 'not-declared', 'unknown', {
        evidence: sanitizeError(error, { phase: 'env' }),
        limitations: ['host-service-catalog-probe-failed'],
      }))
    }
  }

  records.push(capabilityRecord('host:node-runtime', 'declared', 'present', {
    evidence: { node_version: process.version, os_platform: process.platform, os_arch: process.arch },
  }))

  const osPinned = Boolean(runtime.anchor?.platform || runtime.anchor?.arch)
  records.push(capabilityRecord('host:os', osPinned ? 'declared' : 'not-declared', 'present', {
    evidence: { os_platform: process.platform, os_arch: process.arch },
    limitations: osPinned ? [] : ['os-not-pinned-by-anchor'],
  }))

  // L1 cannot enforce these; the worker records unknown instead of pretending.
  for (const [key, limitation] of [
    ['host:network-enforcement', 'network-unenforced-by-l1'],
    ['host:filesystem-enforcement', 'filesystem-unenforced-by-l1'],
    ['host:device-enforcement', 'devices-unenforced-by-l1'],
    ['host:resource-limits', 'cpu-memory-limits-unenforced-by-l1'],
  ]) {
    records.push(capabilityRecord(key, 'not-declared', 'unknown', { limitations: [limitation] }))
    limitations.push(limitation)
  }

  const temp = await probeTempDir()
  records.push(capabilityRecord('host:temp-dir', 'declared', temp.observed, {
    evidence: temp.evidence,
    limitations: temp.limitations ?? [],
  }))
  limitations.push(...(temp.limitations ?? []))

  const credentialNames = Object.keys(env ?? {}).filter((name) => isCredentialEnvName(name))
  const removedCredentialNames = Number(environmentAudit?.credential_name_count ?? 0)
  if (credentialNames.length > 0) {
    records.push(capabilityRecord('host:ambient-credentials', 'not-declared', 'present', {
      evidence: { credential_name_count: credentialNames.length },
      limitations: ['ambient-credentials-visible-in-worker-environment'],
    }))
    limitations.push('ambient-credentials-visible-in-worker-environment')
  } else {
    records.push(capabilityRecord('host:ambient-credentials', 'not-declared', 'absent', {
      evidence: { credential_name_count: 0, scrubbed_credential_name_count: removedCredentialNames },
      limitations: removedCredentialNames > 0 ? ['ambient-credentials-removed-before-probe'] : [],
    }))
    if (removedCredentialNames > 0) limitations.push('ambient-credentials-removed-before-probe')
  }

  records.push(capabilityRecord('host:worker-entry', 'declared', 'present', {
    evidence: { worker_ref: WORKER_REF, isolation: 'L1-subprocess', probe_time: probeTime },
    limitations: ['l1-fault-isolation-not-a-security-boundary'],
  }))
  limitations.push('l1-fault-isolation-not-a-security-boundary')

  return { records, limitations: [...new Set(limitations)] }
}

function normalizePutEntry(entry) {
  if (typeof entry !== 'string' || entry.length === 0 || entry.includes('\0')) return null
  let path
  if (entry.startsWith('file:')) {
    try { path = fileURLToPath(entry) } catch { return null }
  } else if (isAbsolute(entry) || win32.isAbsolute(entry) || entry.startsWith('/')) {
    path = entry
  } else {
    return null
  }
  const resolvedPath = resolve(path)
  return { path: resolvedPath, url: pathToFileURL(resolvedPath).href }
}

function readDeclarations(mod) {
  const declarations = { requires: [], capabilities: [], invalid: false }
  const takeList = (value) => {
    if (value == null) return []
    if (!Array.isArray(value)) {
      declarations.invalid = true
      return []
    }
    const out = []
    for (const item of value) {
      if (typeof item !== 'string' || item.length === 0) {
        declarations.invalid = true
        continue
      }
      out.push(truncateUtf8(redactText(item), 160).text)
    }
    return [...new Set(out)].slice(0, MAX_DECLARED_CAPABILITIES)
  }
  declarations.requires = takeList(mod?.requires ?? mod?.manifest?.requires)
  const capabilityValue = mod?.capabilities ?? mod?.declared_capabilities ?? mod?.manifest?.capabilities
  if (isPlainRecord(capabilityValue) && !Array.isArray(capabilityValue)) {
    declarations.capabilities = takeList(Object.keys(capabilityValue))
  } else {
    declarations.capabilities = takeList(capabilityValue)
  }
  return declarations
}

function stateNameMapper() {
  // Fiber state is a const enum (no runtime name object) — CONTRACT-m3 §0.
  const names = ['PENDING', 'LOADING', 'ACTIVE', 'FAILED', 'DISPOSED', 'UNLOADING']
  return (value) => (Number.isInteger(value) && names[value]) || 'UNKNOWN'
}

async function withTimeout(promise, timeoutMs) {
  let timer = null
  try {
    return await Promise.race([
      Promise.resolve(promise).then(
        (value) => ({ ok: true, value, error: null }),
        (error) => ({ ok: true, value: null, error }),
      ),
      new Promise((resolvePromise) => {
        timer = setTimeout(() => resolvePromise({ ok: false, timeout: true }), timeoutMs)
      }),
    ])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

/** Dispose a fiber without letting a hung load block the probe/host forever. */
async function disposeWithTimeout(fiber, timeoutMs) {
  if (!fiber || typeof fiber.dispose !== 'function') return { ok: true }
  const disposed = await withTimeout(fiber.dispose(), Math.min(2000, Math.max(100, timeoutMs)))
  if (!disposed.ok) return { ok: false, reason: 'put-dispose-timeout' }
  if (disposed.error) return { ok: false, reason: 'put-dispose-failed' }
  return { ok: true }
}

async function probePutPhase({ runtime, put, signal, putTimeoutMs }) {
  const records = []
  const limitations = []
  const result = {
    attempted: false,
    loaded: false,
    put_entry: null,
    put_digest: null,
    declared: { requires: [], capabilities: [] },
    put_state: null,
    state_after_plugin: null,
    state_after_load: null,
    state_after_dispose: null,
    effects_count: null,
    load_phase: null,
    error: null,
    records,
    limitations,
  }
  if (!isPlainRecord(put) || typeof put.entry !== 'string' || put.entry.length === 0) {
    limitations.push('put-not-specified')
    return result
  }
  result.attempted = true
  const normalized = normalizePutEntry(put.entry)
  if (!normalized) {
    records.push(capabilityRecord('put:entry', 'declared', 'absent', { limitations: ['put-entry-invalid'] }))
    limitations.push('put-entry-invalid')
    return result
  }
  result.put_entry = normalized.url

  let bytes
  try {
    const info = await stat(normalized.path)
    if (!info.isFile() || info.size > MAX_RUNTIME_ENTRY_BYTES) throw new Error('put-entry-oversize-or-not-file')
    bytes = await readFile(normalized.path)
  } catch (error) {
    records.push(capabilityRecord('put:entry', 'declared', 'absent', {
      evidence: sanitizeError(error, { phase: 'host-load' }),
      limitations: ['put-entry-unreadable'],
    }))
    limitations.push('put-entry-unreadable')
    return result
  }
  const digest = 'sha256:' + createHash('sha256').update(bytes).digest('hex')
  result.put_digest = digest
  if (typeof put.digest === 'string' && SHA256.test(put.digest) && put.digest !== digest) {
    records.push(capabilityRecord('put:artifact-digest', 'declared', 'absent', {
      evidence: { expected_digest: put.digest, observed_digest: digest },
      limitations: ['put-digest-mismatch'],
    }))
    limitations.push('put-digest-mismatch')
    return result
  }
  records.push(capabilityRecord('put:artifact-digest', 'declared', 'present', {
    evidence: { digest, size_bytes: bytes.byteLength },
  }))

  if (runtime.status !== 'available') {
    records.push(capabilityRecord('put:load', 'declared', 'unknown', {
      evidence: { runtime_status: runtime.status, runtime_reason: runtime.reason },
      limitations: ['cordis-runtime-unavailable'],
    }))
    limitations.push('cordis-runtime-unavailable')
    return result
  }
  if (signal?.aborted) {
    records.push(capabilityRecord('put:load', 'declared', 'unknown', { limitations: ['probe-cancelled'] }))
    limitations.push('probe-cancelled')
    return result
  }

  let mod
  try {
    mod = await import(normalized.url)
  } catch (error) {
    result.load_phase = 'host-load'
    result.error = sanitizeError(error, { phase: 'host-load' })
    records.push(capabilityRecord('put:import', 'declared', 'absent', {
      evidence: result.error,
      limitations: ['put-import-failed'],
    }))
    limitations.push('put-import-failed')
    return result
  }
  const putPlugin = mod?.default ?? mod?.put ?? mod
  result.declared = readDeclarations(mod)
  if (result.declared.invalid) limitations.push('put-declarations-invalid')
  records.push(capabilityRecord('put:declarations', result.declared.requires.length + result.declared.capabilities.length > 0
    ? 'declared'
    : 'not-declared', 'present', {
    evidence: {
      requires: result.declared.requires,
      capabilities: result.declared.capabilities,
      invalid: result.declared.invalid === true,
    },
  }))

  const shapeOk = typeof putPlugin === 'function' ||
    (isPlainRecord(putPlugin) && (typeof putPlugin.apply === 'function' || typeof putPlugin.setup === 'function'))
  records.push(capabilityRecord('put:plugin-shape', 'declared', shapeOk ? 'present' : 'absent', {
    limitations: shapeOk ? [] : ['put-plugin-shape-invalid'],
  }))
  if (!shapeOk) {
    limitations.push('put-plugin-shape-invalid')
    return result
  }

  let Context
  try {
    ({ Context } = await import(runtime.anchor.cordis_entry))
  } catch (error) {
    result.load_phase = 'host-load'
    result.error = sanitizeError(error, { phase: 'host-load' })
    records.push(capabilityRecord('put:cordis-context', 'declared', 'absent', {
      evidence: result.error,
      limitations: ['cordis-context-import-failed'],
    }))
    limitations.push('cordis-context-import-failed')
    return result
  }
  if (typeof Context !== 'function') {
    records.push(capabilityRecord('put:cordis-context', 'declared', 'absent', {
      limitations: ['cordis-context-missing'],
    }))
    limitations.push('cordis-context-missing')
    return result
  }
  records.push(capabilityRecord('put:cordis-context', 'declared', 'present', {
    evidence: { cordis_version: runtime.provenance.cordis_version, verified: runtime.provenance.cordis_version_verified },
  }))

  const mapState = stateNameMapper()
  const transitions = []
  let root = null
  let fiber = null
  let listener = null
  try {
    root = new Context()
    if (typeof root.on === 'function') {
      listener = (target, oldState) => {
        if (transitions.length >= 32) return
        transitions.push({ from: mapState(oldState), to: mapState(target?.state) })
      }
      try { root.on('internal/status', listener) } catch { listener = null }
    }
    try {
      fiber = root.plugin(putPlugin, isPlainRecord(put.config) ? put.config : {})
    } catch (error) {
      result.load_phase = 'host-load'
      result.error = sanitizeError(error, { phase: 'host-load' })
      records.push(capabilityRecord('put:plugin-api', 'declared', 'absent', {
        evidence: result.error,
        limitations: ['put-plugin-api-rejected'],
      }))
      limitations.push('put-plugin-api-rejected')
      return result
    }
    result.state_after_plugin = mapState(fiber?.state)
    records.push(capabilityRecord('put:plugin-api', 'declared', 'present', {
      evidence: { state_after_plugin: result.state_after_plugin },
    }))

    const loaded = await withTimeout(fiber, putTimeoutMs)
    if (!loaded.ok) {
      records.push(capabilityRecord('put:apply', 'declared', 'unknown', {
        limitations: ['put-load-timeout'],
      }))
      limitations.push('put-load-timeout')
    } else if (loaded.error) {
      result.load_phase = 'host-apply'
      result.error = sanitizeError(loaded.error, { phase: 'host-apply' })
      records.push(capabilityRecord('put:apply', 'declared', 'absent', {
        evidence: result.error,
        limitations: ['put-apply-failed'],
      }))
      limitations.push('put-apply-failed')
    } else {
      records.push(capabilityRecord('put:apply', 'declared', 'present'))
    }
    result.state_after_load = mapState(fiber?.state)
    result.effects_count = typeof fiber?.getEffects === 'function' ? fiber.getEffects().length : null
    records.push(capabilityRecord('put:effect-registration',
      result.declared.capabilities.includes('effect') ? 'declared' : 'not-declared',
      result.effects_count == null ? 'unknown' : result.effects_count > 0 ? 'present' : 'absent',
      result.effects_count == null ? { limitations: ['effects-api-not-observable'] } : {}))
    result.put_state = redactValue(mod?.state ?? null, { maxDepth: 4, maxStringBytes: 1024 }).value
    result.loaded = result.state_after_load === 'ACTIVE' || result.state_after_load === 'FAILED'
  } finally {
    if (fiber && typeof fiber.dispose === 'function') {
      const disposed = await disposeWithTimeout(fiber, putTimeoutMs)
      if (!disposed.ok) {
        result.error = result.error ?? { phase: 'host-apply', message: disposed.reason }
        limitations.push(disposed.reason)
      }
    }
    result.state_after_dispose = mapState(fiber?.state)
    records.push(capabilityRecord('put:lifecycle-dispose', 'declared',
      fiber == null ? 'unknown' : result.state_after_dispose === 'DISPOSED' ? 'present'
        : result.state_after_dispose === 'FAILED' || result.state_after_dispose === 'ACTIVE' ? 'absent' : 'unknown',
      { evidence: { state_after_dispose: result.state_after_dispose, transitions } }))
    if (listener && root && typeof root.off === 'function') {
      try { root.off('internal/status', listener) } catch { /* best effort */ }
    }
    if (root && typeof root.dispose === 'function') {
      await disposeWithTimeout(root, putTimeoutMs)
    }
  }

  // Declared capabilities without a defined measurement stay unknown — never absent.
  const measured = new Set(['effect'])
  for (const declared of result.declared.capabilities) {
    if (measured.has(declared)) continue
    records.push(capabilityRecord(`put:declared:${declared}`, 'declared', 'unknown', {
      limitations: ['capability-measurement-not-defined'],
    }))
    limitations.push(`capability-measurement-not-defined:${declared}`)
  }
  result.transitions = transitions
  return result
}

function workerOpRecords(cases, envRecords, putPhase) {
  const envByKey = new Map(envRecords.map((record) => [record.capability_key, record]))
  const caseRecords = []
  for (const caseSpec of cases) {
    const testId = typeof caseSpec?.test_id === 'string' ? caseSpec.test_id : ''
    if (testId === '') continue
    const capabilities = []
    const limitations = []

    if (isPlainRecord(caseSpec.probe)) {
      const op = typeof caseSpec.probe.op === 'string' && caseSpec.probe.op.length > 0 ? caseSpec.probe.op : 'echo'
      if (['echo', 'error', 'sleep', 'env-audit'].includes(op)) {
        capabilities.push(capabilityRecord(`worker:op:${op}`, 'declared', 'present', { evidence: { built_in: true } }))
      } else if (op === 'load-put') {
        const runtimeRecord = envByKey.get('host:cordis-runtime')
        capabilities.push(runtimeRecord ?? capabilityRecord('host:cordis-runtime', 'declared', 'unknown', {
          limitations: ['runtime-capability-not-measured'],
        }))
        const importRecord = envByKey.get('host:cordis-import')
        if (importRecord) capabilities.push(importRecord)
        // "Can this worker execute the load-put op?" is the aggregate of every
        // load-boundary measurement; a failing PUT apply is a test observation,
        // not a missing harness capability.
        const loadKeys = ['put:entry', 'put:import', 'put:plugin-shape', 'put:cordis-context', 'put:plugin-api', 'put:load']
        const loadRecords = putPhase.records.filter((record) => loadKeys.includes(record.capability_key))
        if (loadRecords.length > 0) {
          capabilities.push(capabilityRecord('worker:op:load-put', 'declared',
            aggregateObserved(loadRecords),
            { limitations: loadRecords.flatMap((record) => record.limitations) }))
        } else {
          capabilities.push(capabilityRecord('worker:op:load-put', 'declared', 'unknown', {
            limitations: [putPhase.attempted ? 'put-load-capability-not-measured' : 'put-not-specified'],
          }))
        }
      } else {
        capabilities.push(capabilityRecord(`worker:op:${op}`, 'declared', 'absent', {
          limitations: ['worker-op-unsupported'],
        }))
      }
    } else if (isPlainRecord(caseSpec.tool)) {
      capabilities.push(capabilityRecord('worker:tool-runner:local-worker-json', 'declared', 'present', {
        evidence: { adapter: 'local-worker-json', argv_launch: true, shell: false },
      }))
      const requires = Array.isArray(caseSpec.tool.manifest?.requires) ? caseSpec.tool.manifest.requires : []
      for (const requirement of requires.slice(0, MAX_DECLARED_CAPABILITIES)) {
        if (typeof requirement !== 'string' || requirement.length === 0) continue
        const capabilityKey = requirement.includes(':') ? requirement : `target:${requirement}`
        capabilities.push(capabilityRecord(capabilityKey, 'declared', 'unknown', {
          external: true,
          limitations: ['target-capability-not-observed-by-worker'],
        }))
      }
      if (requires.length > 0) limitations.push('target-capability-not-observed-by-worker')
    } else {
      limitations.push('case-producer-not-specified')
    }

    const workerCapabilities = capabilities.filter((record) => record.external !== true)
    limitations.push(...workerCapabilities.flatMap((record) => record.limitations))
    const observed = workerCapabilities.length === 0 ? 'unknown' : aggregateObserved(workerCapabilities)
    const claim = workerCapabilities.length === 0 ? 'not-declared' : aggregateClaim(workerCapabilities)
    const evidenceRefs = capabilities.filter((record) => record.observed !== 'unknown')
      .map((record) => record.capability_key)
    caseRecords.push({
      test_id: testId,
      source: 'worker',
      claim,
      observed,
      phase: putPhase.attempted ? 'put' : 'env',
      probe_version: CAPABILITY_PROBE_VERSION,
      probe_time: null, // filled by the snapshot assembly below
      environment_fingerprint: null,
      worker_fingerprint: null,
      put_digest: putPhase.put_digest,
      evidence_ref: evidenceRefs[0] ?? null,
      capabilities,
      limitations: [...new Set(limitations)].slice(0, 32),
    })
  }
  return caseRecords
}

function probeTimeOf(options) {
  if (typeof options.probe_time === 'string' && Number.isFinite(Date.parse(options.probe_time))) {
    return { probe_time: new Date(Date.parse(options.probe_time)).toISOString(), source: 'caller' }
  }
  return { probe_time: new Date().toISOString(), source: 'worker' }
}

/**
 * Run the two-phase probe in this worker.
 *
 * @param {{cases:Array<object>, put?:{entry:string,digest?:string,config?:object}|null,
 *   runtime?:object|string|null, env?:Record<string,string|undefined>,
 *   environmentAudit?:object|null, probe_time?:string, signal?:AbortSignal,
 *   putTimeoutMs?:number, baseDir?:string}} options
 * @returns {Promise<{ok:true, snapshot:object} | {ok:false, errors:string[]}>}
 */
export async function probeWorkerCapabilities(options = {}) {
  const cases = options.cases
  if (!Array.isArray(cases)) return { ok: false, errors: ['probe-cases-not-array'] }
  if (cases.length > MAX_PROBE_CASES) return { ok: false, errors: [`probe-case-count-exceeds-limit:${MAX_PROBE_CASES}`] }
  const compactCases = []
  for (const caseSpec of cases) {
    if (!isPlainRecord(caseSpec) || typeof caseSpec.test_id !== 'string' || caseSpec.test_id.length === 0) {
      return { ok: false, errors: ['probe-case-invalid'] }
    }
    compactCases.push({
      test_id: caseSpec.test_id,
      probe: isPlainRecord(caseSpec.probe) ? { op: caseSpec.probe.op } : null,
      tool: isPlainRecord(caseSpec.tool) ? { manifest: { requires: caseSpec.tool.manifest?.requires } } : null,
    })
  }

  let runtime
  try {
    runtime = await resolveRuntimeAnchor({
      injection: options.runtime ?? null,
      env: options.env ?? process.env,
      baseDir: options.baseDir,
    })
  } catch {
    runtime = {
      status: 'unavailable',
      reason: 'runtime-anchor-invalid',
      anchor: null,
      provenance: {
        cordis_version: null, dsh_commit: null, source: 'none', runtime_kind: null,
        node_version: process.version, os_platform: process.platform, os_arch: process.arch,
        environment_fingerprint: 'sha256:' + sha256Hex(canonicalJson({
          anchor_status: 'unavailable', reason: 'runtime-anchor-invalid',
          node_version: process.version, os_platform: process.platform, os_arch: process.arch,
        })),
      },
      limitations: ['runtime-unavailable:runtime-anchor-invalid'],
    }
  }

  const { probe_time: probeTime, source: probeTimeSource } = probeTimeOf(options)
  const env = options.env ?? process.env
  const environmentPhase = await probeEnvironmentPhase({
    runtime,
    env,
    environmentAudit: options.environmentAudit ?? null,
    probeTime,
  })

  const putTimeoutMs = Math.min(
    MAX_PUT_TIMEOUT_MS,
    Math.max(1, Number(options.putTimeoutMs) || PROBE_DEFAULT_PUT_TIMEOUT_MS),
  )
  const putPhase = await probePutPhase({
    runtime,
    put: options.put ?? null,
    signal: options.signal,
    putTimeoutMs,
  })

  const caseRecords = workerOpRecords(compactCases, environmentPhase.records, putPhase)
  const workerFp = workerFingerprint()
  for (const record of caseRecords) {
    record.probe_time = probeTime
    record.environment_fingerprint = runtime.provenance.environment_fingerprint
    record.worker_fingerprint = workerFp
  }

  const limitations = [...new Set([
    ...environmentPhase.limitations,
    ...putPhase.limitations,
    ...(runtime.limitations ?? []),
    ...(probeTimeSource === 'caller' ? ['probe-time-caller-supplied'] : []),
  ])]

  const snapshot = {
    snapshot_version: CAPABILITY_SNAPSHOT_VERSION,
    source: 'worker',
    probe_version: CAPABILITY_PROBE_VERSION,
    probe_implementation: PROBE_IMPLEMENTATION,
    probe_time: probeTime,
    probe_time_source: probeTimeSource,
    phase: putPhase.attempted ? 'put' : 'env',
    environment_fingerprint: runtime.provenance.environment_fingerprint,
    worker_fingerprint: workerFp,
    put_digest: putPhase.put_digest,
    runtime: {
      status: runtime.status,
      reason: runtime.reason,
      source: runtime.provenance.source ?? 'none',
      runtime_kind: runtime.provenance.runtime_kind ?? null,
      cordis_version: runtime.provenance.cordis_version ?? null,
      cordis_version_verified: runtime.provenance.cordis_version_verified === true,
      dsh_commit: runtime.provenance.dsh_commit ?? null,
      dsh_commit_verified: false,
      cordis_entry: runtime.anchor?.cordis_entry
        ? truncateUtf8(redactText(runtime.anchor.cordis_entry), 512).text
        : null,
    },
    declarations: putPhase.declared,
    phases: {
      env: { records: environmentPhase.records, limitations: environmentPhase.limitations },
      put: {
        attempted: putPhase.attempted,
        loaded: putPhase.loaded,
        put_entry: putPhase.put_entry,
        put_digest: putPhase.put_digest,
        put_state: putPhase.put_state,
        state_after_plugin: putPhase.state_after_plugin,
        state_after_load: putPhase.state_after_load,
        state_after_dispose: putPhase.state_after_dispose,
        effects_count: putPhase.effects_count,
        transitions: putPhase.transitions ?? null,
        load_phase: putPhase.load_phase,
        error: putPhase.error,
        records: putPhase.records,
        limitations: putPhase.limitations,
      },
    },
    // Capability-level evidence (keyed by capability_key). Kept separate from
    // `cases` (the control face's per-test records) and deliberately NOT named
    // `records`, which the control face reserves for a `{records:[{test_id}]}`
    // envelope. Use `caseRecordsFromSnapshot()` to derive the freeze input.
    capability_records: [...environmentPhase.records, ...putPhase.records],
    cases: caseRecords,
    limitations,
  }

  // Negative invariant: the worker never leaks control-face authority fields.
  assertNoAuthorityFields(snapshot, { deep: true, label: 'capability snapshot' })
  return { ok: true, snapshot }
}

/**
 * Validate a worker capability snapshot and derive the per-test record map that
 * the control face freezes (compatible with `freezePlan({capabilitySnapshots})`).
 *
 * @param {unknown} snapshot
 * @returns {{ok:true, records:Record<string,object>} | {ok:false, errors:string[]}}
 */
export function caseRecordsFromSnapshot(snapshot) {
  const errors = []
  if (!isPlainRecord(snapshot)) return { ok: false, errors: ['snapshot-not-object'] }
  if (snapshot.snapshot_version !== CAPABILITY_SNAPSHOT_VERSION) {
    return { ok: false, errors: ['snapshot-version-unknown'] }
  }
  if (snapshot.source !== 'worker') return { ok: false, errors: ['snapshot-source-not-worker'] }
  try {
    assertNoAuthorityFields(snapshot, { deep: true, label: 'capability snapshot' })
  } catch (error) {
    return { ok: false, errors: [String(error.message)] }
  }
  if (!Array.isArray(snapshot.cases)) return { ok: false, errors: ['snapshot-cases-not-array'] }

  const records = Object.create(null)
  for (const record of snapshot.cases) {
    if (!isPlainRecord(record) || typeof record.test_id !== 'string' || record.test_id.length === 0) {
      errors.push('snapshot-case-invalid')
      continue
    }
    if (!CAPABILITY_CLAIM.includes(record.claim) || !CAPABILITY_OBSERVED.includes(record.observed)) {
      errors.push(`snapshot-case-capability-invalid:${record.test_id}`)
      continue
    }
    if (Object.hasOwn(records, record.test_id)) {
      errors.push(`snapshot-case-duplicate:${record.test_id}`)
      continue
    }
    const copy = Object.create(null)
    for (const [key, value] of Object.entries(record)) copy[key] = value
    copy.test_id = record.test_id
    records[record.test_id] = copy
  }
  if (errors.length > 0) return { ok: false, errors }
  return { ok: true, records }
}

function unknownRecordFor(testId, context, limitation) {
  const limitations = [limitation]
  if (context.environment_fingerprint == null) limitations.push('environment-fingerprint-unavailable')
  if (context.put_digest == null) limitations.push('put-digest-unavailable')
  return {
    test_id: testId,
    source: 'worker',
    claim: 'not-declared',
    observed: 'unknown',
    probe_version: typeof context.probe_version === 'string' && context.probe_version.length > 0
      ? context.probe_version
      : CAPABILITY_PROBE_VERSION,
    probe_time: typeof context.probe_time === 'string' && Number.isFinite(Date.parse(context.probe_time))
      ? new Date(Date.parse(context.probe_time)).toISOString()
      : new Date().toISOString(),
    environment_fingerprint: context.environment_fingerprint ?? null,
    worker_fingerprint: context.worker_fingerprint ?? workerFingerprint(),
    put_digest: context.put_digest ?? null,
    evidence_ref: null,
    limitations,
  }
}

/**
 * Produce worker records keyed by test_id for the control face.
 *
 * When `context.snapshot` is a real two-phase worker snapshot, its measured
 * `claim`/`observed` records are used verbatim (bound to the caller list). With
 * no snapshot (legacy call), the result is an explicit unknown record — the
 * worker never trusts caller-supplied capability declarations.
 *
 * @param {Array<{test_id:string}>} cases
 * @param {{snapshot?:object, put_digest?:string|null, probe_version?:string,
 *   probe_time?:string, environment_fingerprint?:string|null,
 *   worker_fingerprint?:string|null}} [context]
 * @returns {Record<string, object>}
 */
export function probeCapabilities(cases, context = {}) {
  const result = Object.create(null)
  if (!Array.isArray(cases)) return result
  const caseIds = []
  for (const caseSpec of cases) {
    const testId = caseSpec && typeof caseSpec.test_id === 'string' ? caseSpec.test_id : ''
    if (testId === '') continue
    caseIds.push(testId)
  }

  let measured = null
  if (context?.snapshot != null) {
    const derived = caseRecordsFromSnapshot(context.snapshot)
    if (derived.ok) measured = derived.records
  }

  for (const testId of caseIds) {
    const record = measured && Object.hasOwn(measured, testId)
      ? measured[testId]
      : unknownRecordFor(testId, context,
        measured ? 'case-not-in-probe-snapshot' : 'probe-snapshot-not-supplied')
    Object.defineProperty(result, testId, {
      value: { ...record, test_id: testId },
      enumerable: true,
      configurable: true,
      writable: true,
    })
  }
  return result
}
