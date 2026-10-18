/**
 * Scheduler entry semantics (t11): disabled by default; enabling requires
 * frozen policy + operator authorization + durable store. No cron/timer exists
 * and the entry never affects market eligibility.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { describeSchedulerEntry } from '../../../src/index.js'
import { DEFAULT_SCHEDULER_POLICY } from '../../../src/scheduler/index.js'
import { makeAuthorization, makePolicy } from '../../unit/scheduler/_helpers.js'

const ROOT = fileURLToPath(new URL('../../..', import.meta.url))

function tempDir(t) {
  const dir = mkdtempSync(join(tmpdir(), 'scheduler-entry-test-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function validAuthorization() {
  const now = Date.now()
  return makeAuthorization({
    action: 'enable-scheduler',
    scope: { profile: 'local', periodic: false },
    nowMs: now,
    issuedAtMs: now - 60_000,
    expiresAtMs: now + 3_600_000,
  })
}

test('scheduler entry: default is disabled with no timer/cron and stable reason', () => {
  const status = describeSchedulerEntry()
  assert.equal(status.schema_version, 'scheduler-entry/v1')
  assert.equal(status.status, 'disabled')
  assert.equal(status.scheduler_enabled, false)
  assert.equal(status.enabled_requested, false)
  assert.deepEqual(status.reason_codes, ['scheduler-disabled'])
  assert.equal(status.cron_enabled, false)
  assert.equal(status.background_loops, false)
  assert.equal(status.single_host, true)
  assert.equal(status.ha, false)
  assert.equal(status.market_auto_publish, false)
  assert.equal(status.scheduler_status?.state, 'disabled')
})

test('scheduler entry: valid policy + authorization + durable store enables without background loops', (t) => {
  const dir = tempDir(t)
  const storePath = join(dir, 'scheduler.sqlite')
  const status = describeSchedulerEntry({
    enabled: true,
    policy: makePolicy(),
    authorization: validAuthorization(),
    storePath,
  })
  assert.equal(status.status, 'enabled', JSON.stringify(status.reason_codes))
  assert.equal(status.scheduler_enabled, true)
  assert.equal(status.enabled_requested, true)
  assert.deepEqual(status.reason_codes, [])
  assert.equal(status.cron_enabled, false)
  assert.equal(status.background_loops, false)
  assert.equal(status.market_auto_publish, false)
  assert.match(String(status.policy_digest), /^sha256:[0-9a-f]{64}$/)
  assert.notEqual(status.authorization_id, null)
  assert.equal(status.store_path, storePath)
  assert.equal(existsSync(storePath), true)
  assert.equal(status.scheduler_status?.runtime?.cron_enabled, false)
  assert.equal(status.scheduler_status?.runtime?.background_loops, false)
  assert.deepEqual(status.scheduler_status?.policy?.periodic_enabled, DEFAULT_SCHEDULER_POLICY.periodic_enabled)
})

test('scheduler entry: missing authorization or store stays blocked (no enable)', (t) => {
  const dir = tempDir(t)
  const policy = makePolicy()
  const noAuth = describeSchedulerEntry({
    enabled: true,
    policy,
    storePath: join(dir, 'no-auth.sqlite'),
  })
  assert.notEqual(noAuth.status, 'enabled')
  assert.equal(noAuth.scheduler_enabled, false)
  assert.ok(
    noAuth.reason_codes.some((code) => code.startsWith('scheduler-authorization')),
    noAuth.reason_codes.join(','),
  )

  const noStore = describeSchedulerEntry({
    enabled: true,
    policy,
    authorization: validAuthorization(),
  })
  assert.notEqual(noStore.status, 'enabled')
  assert.equal(noStore.scheduler_enabled, false)
  assert.ok(
    noStore.reason_codes.includes('scheduler-store-required') ||
      noStore.reason_codes.includes('scheduler-store-unavailable'),
    noStore.reason_codes.join(','),
  )
})

test('scheduler CLI: default exit 2 disabled; explicit enable exit 0; partial/invalid input exit 3', (t) => {
  const dir = tempDir(t)
  const cli = join(ROOT, 'bin', 'selfcheck.js')

  const off = spawnSync(process.execPath, [cli, 'scheduler'], { cwd: ROOT, encoding: 'utf8' })
  assert.equal(off.status, 2, off.stderr)
  const offJson = JSON.parse(off.stdout)
  assert.equal(offJson.status, 'disabled')
  assert.equal(offJson.cron_enabled, false)
  assert.equal(offJson.background_loops, false)

  const policyPath = join(dir, 'policy.json')
  const authPath = join(dir, 'authorization.json')
  writeFileSync(policyPath, JSON.stringify(makePolicy(), null, 2), 'utf8')
  writeFileSync(authPath, JSON.stringify(validAuthorization(), null, 2), 'utf8')
  const on = spawnSync(process.execPath, [
    cli, 'scheduler',
    '--enable-policy', policyPath,
    '--authorization', authPath,
    '--store', join(dir, 'scheduler.sqlite'),
  ], { cwd: ROOT, encoding: 'utf8' })
  assert.equal(on.status, 0, on.stderr)
  const onJson = JSON.parse(on.stdout)
  assert.equal(onJson.status, 'enabled')
  assert.equal(onJson.scheduler_enabled, true)
  assert.equal(onJson.cron_enabled, false)

  const partial = spawnSync(process.execPath, [cli, 'scheduler', '--enable-policy', policyPath], {
    cwd: ROOT,
    encoding: 'utf8',
  })
  assert.equal(partial.status, 3)

  const unknown = spawnSync(process.execPath, [cli, 'scheduler', '--bogus'], { cwd: ROOT, encoding: 'utf8' })
  assert.equal(unknown.status, 3)
})
