/**
 * Integration: genuine multi-process competition over the same durable SQLite
 * store. Three OS child processes race to acquire the same scope; exactly one
 * may win (transaction + unique active-scope index). A crashed winner is then
 * recovered by the next process using measured PID liveness.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  buildMonitoringObservation,
  isPidAlive,
  normalizeScope,
  openSchedulerStore,
} from '../../../src/scheduler/index.js'

const WORKER_FIXTURE = fileURLToPath(new URL('./fixtures/acquire-worker.mjs', import.meta.url))
const BASE_MS = Date.UTC(2026, 9, 19, 0, 0, 0)
const AT_ISO = new Date(BASE_MS).toISOString()
const TARGET_A = 'sha256:' + 'a'.repeat(64)
const PLAN_DIGEST = 'sha256:' + '1'.repeat(64)
const POLICY_DIGEST = 'sha256:' + '2'.repeat(64)
const PROFILE = 'local'

function runWorker(config, timeoutMs = 30_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [WORKER_FIXTURE, JSON.stringify(config)], {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    })
    let stdout = ''
    let stderr = ''
    const timer = setTimeout(() => {
      child.kill()
      reject(new Error(`worker timeout after ${timeoutMs}ms`))
    }, timeoutMs)
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', (chunk) => { stdout += chunk })
    child.stderr.on('data', (chunk) => { stderr += chunk })
    child.once('error', (error) => {
      clearTimeout(timer)
      reject(error)
    })
    child.once('close', (code) => {
      clearTimeout(timer)
      if (code !== 0) {
        reject(new Error(`worker exited ${code}: ${stderr}`))
        return
      }
      const line = stdout.trim().split(/\r?\n/).filter(Boolean).at(-1)
      try {
        resolve({ ...JSON.parse(line), worker_pid: child.pid })
      } catch {
        reject(new Error(`worker produced invalid JSON: ${stdout}`))
      }
    })
  })
}

function workerConfig({ filePath, runId, idempotencyKey, ownerId, scopeKey }) {
  return {
    filePath,
    atIso: AT_ISO,
    atMs: BASE_MS,
    scheduleId: 'sched-1',
    planDigest: PLAN_DIGEST,
    targetDigest: TARGET_A,
    policyDigest: POLICY_DIGEST,
    profile: PROFILE,
    scopeKey,
    ownerId,
    runId,
    idempotencyKey,
    ttlMs: 60_000,
    maxGlobalConcurrency: 5,
    maxTargetConcurrency: 5,
    host: 'test-host',
  }
}

test('multi-process: exactly one of three OS processes wins the same scope lease', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'testbed-scheduler-mp-'))
  const filePath = join(dir, 'scheduler.sqlite')
  let reopened = null
  t.after(() => {
    try { reopened?.close() } catch { /* closed */ }
    rmSync(dir, { recursive: true, force: true })
  })

  const store = openSchedulerStore({ filePath, atIso: AT_ISO })
  const scope = normalizeScope({ profile: PROFILE, target_digest: TARGET_A, max_concurrency: 1 })
  assert.equal(scope.ok, true)
  store.registerSchedule({
    scheduleId: 'sched-1',
    version: 1,
    contentDigest: 'sha256:' + 'c'.repeat(64),
    planDigest: PLAN_DIGEST,
    targetDigest: TARGET_A,
    policyDigest: POLICY_DIGEST,
    config: { schema_version: 'scheduler-schedule/v1', schedule_id: 'sched-1' },
    atIso: AT_ISO,
  })
  for (let index = 1; index <= 3; index += 1) {
    const enqueued = store.enqueue({
      schedule: { scheduleId: 'sched-1', planDigest: PLAN_DIGEST, targetDigest: TARGET_A, policyDigest: POLICY_DIGEST },
      scopeKey: scope.scopeKey,
      runId: `run-${index}`,
      idempotencyKey: `idem-${index}`,
      atIso: AT_ISO,
      maxQueueDepth: 10,
    })
    assert.equal(enqueued.ok, true)
  }
  store.close()

  // Start all three child processes before awaiting any: a genuine race.
  const workers = [
    runWorker(workerConfig({ filePath, runId: 'run-1', idempotencyKey: 'idem-1', ownerId: 'owner-1', scopeKey: scope.scopeKey })),
    runWorker(workerConfig({ filePath, runId: 'run-2', idempotencyKey: 'idem-2', ownerId: 'owner-2', scopeKey: scope.scopeKey })),
    runWorker(workerConfig({ filePath, runId: 'run-3', idempotencyKey: 'idem-3', ownerId: 'owner-3', scopeKey: scope.scopeKey })),
  ]
  const results = await Promise.all(workers)
  const winners = results.filter((result) => result.ok === true)
  assert.equal(winners.length, 1, `exactly one winner expected: ${JSON.stringify(results)}`)
  const winnersById = results.filter((result) => result.ok === false)
  for (const loser of winnersById) {
    assert.ok(
      ['lease-acquire-conflict', 'scheduler-duplicate-run', 'scheduler-concurrency-limit'].includes(loser.reason),
      `unexpected loser reason: ${JSON.stringify(loser)}`,
    )
  }

  const reopenedStore = openSchedulerStore({ filePath, atIso: AT_ISO })
  reopened = reopenedStore
  const active = reopenedStore.listActiveLeases()
  assert.equal(active.length, 1, 'DB partial unique index allows exactly one active lease in the scope')
  assert.equal(active[0].lease.fencing_token, 1)
  assert.equal(active[0].lease.owner_id, winners[0].owner_id)
  assert.equal(reopenedStore.verifyEvents().ok, true)
})

test('multi-process: crashed winner is recovered from measured PID liveness; fencing advances', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'testbed-scheduler-mp2-'))
  const filePath = join(dir, 'scheduler.sqlite')
  let reopened = null
  t.after(() => {
    try { reopened?.close() } catch { /* closed */ }
    rmSync(dir, { recursive: true, force: true })
  })

  const store = openSchedulerStore({ filePath, atIso: AT_ISO })
  const scope = normalizeScope({ profile: PROFILE, target_digest: TARGET_A, max_concurrency: 1 })
  store.registerSchedule({
    scheduleId: 'sched-1',
    version: 1,
    contentDigest: 'sha256:' + 'c'.repeat(64),
    planDigest: PLAN_DIGEST,
    targetDigest: TARGET_A,
    policyDigest: POLICY_DIGEST,
    config: { schema_version: 'scheduler-schedule/v1', schedule_id: 'sched-1' },
    atIso: AT_ISO,
  })
  store.enqueue({
    schedule: { scheduleId: 'sched-1', planDigest: PLAN_DIGEST, targetDigest: TARGET_A, policyDigest: POLICY_DIGEST },
    scopeKey: scope.scopeKey,
    runId: 'run-1',
    idempotencyKey: 'idem-1',
    atIso: AT_ISO,
    maxQueueDepth: 10,
  })
  store.close()

  const winner = await runWorker(workerConfig({
    filePath, runId: 'run-1', idempotencyKey: 'idem-1', ownerId: 'owner-crashed', scopeKey: scope.scopeKey,
  }))
  assert.equal(winner.ok, true, JSON.stringify(winner))
  assert.equal(isPidAlive(winner.worker_pid), false, 'worker process must have exited (crash simulation)')

  const reopenedStore = openSchedulerStore({ filePath, atIso: new Date(BASE_MS + 1_000).toISOString() })
  reopened = reopenedStore
  const owner = reopenedStore.owner('owner-crashed')
  assert.equal(owner.pid, winner.worker_pid)

  const recovered = reopenedStore.recover({
    atIso: new Date(BASE_MS + 1_000).toISOString(),
    atMs: BASE_MS + 1_000,
    isOwnerAlive: (ownerId) => {
      const row = reopenedStore.owner(ownerId)
      return row !== null && isPidAlive(row.pid)
    },
  })
  assert.equal(recovered.recovered.length, 1)
  assert.equal(recovered.recovered[0].lease_id, winner.lease_id)
  assert.equal(recovered.recovered[0].reason, 'owner-process-dead')

  const staleWrite = reopened.submitResult({
    leaseId: winner.lease_id,
    fencingToken: winner.fencing_token,
    runId: 'run-1',
    observation: buildMonitoringObservation(
      { status: 'healthy' },
      {
        scheduleId: 'sched-1',
        runId: 'run-1',
        leaseId: winner.lease_id,
        fencingToken: winner.fencing_token,
        atIso: new Date(BASE_MS + 1_500).toISOString(),
        binding: {
          schedule_id: 'sched-1',
          plan_digest: PLAN_DIGEST,
          policy_digest: POLICY_DIGEST,
          target_digest: TARGET_A,
        },
      },
    ).observation,
    resultDigest: 'sha256:' + 'd'.repeat(64),
    atIso: new Date(BASE_MS + 1_500).toISOString(),
    atMs: BASE_MS + 1_500,
    actor: { id: 'owner-crashed', role: 'scheduler' },
  })
  assert.equal(staleWrite.ok, false)
  assert.ok(['fencing-token-stale', 'lease-expired'].includes(staleWrite.reason))

  const reacquired = reopened.acquire({
    schedule: { scheduleId: 'sched-1', planDigest: PLAN_DIGEST, targetDigest: TARGET_A, policyDigest: POLICY_DIGEST },
    scope: { profile: PROFILE, target_digest: TARGET_A, tenant: 'local', max_concurrency: 1 },
    scopeKey: scope.scopeKey,
    ownerId: 'owner-next',
    runId: 'run-1',
    idempotencyKey: 'idem-1',
    ttlMs: 60_000,
    atIso: new Date(BASE_MS + 2_000).toISOString(),
    atMs: BASE_MS + 2_000,
    maxGlobalConcurrency: 5,
    maxTargetConcurrency: 5,
    actor: { id: 'owner-next', role: 'scheduler' },
  })
  assert.equal(reacquired.ok, true)
  assert.equal(reacquired.lease.fencing_token, winner.fencing_token + 1)
  assert.equal(reopened.verifyEvents().ok, true)
})
