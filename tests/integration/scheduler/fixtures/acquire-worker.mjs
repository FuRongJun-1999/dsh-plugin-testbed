/**
 * Multi-process acquire worker fixture.
 *
 * Opens the durable scheduler store shared with the parent process, registers
 * its owner identity, attempts one transactional lease acquire and exits
 * without releasing (simulating a competing worker that may crash mid-run).
 * Prints exactly one JSON result line.
 */
import { openSchedulerStore } from '../../../../src/scheduler/index.js'

const config = JSON.parse(process.argv[2])
let store = null
try {
  store = openSchedulerStore({ filePath: config.filePath, atIso: config.atIso })
  store.registerOwner({
    ownerId: config.ownerId,
    host: config.host,
    pid: process.pid,
    atIso: config.atIso,
  })
  const result = store.acquire({
    schedule: {
      scheduleId: config.scheduleId,
      planDigest: config.planDigest,
      targetDigest: config.targetDigest,
      policyDigest: config.policyDigest,
    },
    scope: {
      profile: config.profile,
      target_digest: config.targetDigest,
      tenant: 'local',
      max_concurrency: 1,
    },
    scopeKey: config.scopeKey,
    ownerId: config.ownerId,
    runId: config.runId,
    idempotencyKey: config.idempotencyKey,
    ttlMs: config.ttlMs,
    atIso: config.atIso,
    atMs: config.atMs,
    maxGlobalConcurrency: config.maxGlobalConcurrency,
    maxTargetConcurrency: config.maxTargetConcurrency,
    actor: { id: config.ownerId, role: 'scheduler' },
  })
  process.stdout.write(`${JSON.stringify({
    ok: result.ok === true,
    reason: result.ok === true ? null : result.reason,
    lease_id: result.ok === true ? result.lease.lease_id : null,
    fencing_token: result.ok === true ? result.lease.fencing_token : null,
    owner_id: config.ownerId,
    pid: process.pid,
  })}\n`)
} catch (err) {
  process.stdout.write(`${JSON.stringify({
    ok: false,
    reason: 'worker-error',
    error: err instanceof Error ? err.message : String(err),
    owner_id: config.ownerId,
    pid: process.pid,
  })}\n`)
} finally {
  try { store?.close() } catch { /* already closed */ }
}
