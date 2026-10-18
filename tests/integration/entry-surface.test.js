/**
 * Final integration entry surface (t11): API exports, CLI verbs, anchor
 * version separation, and documentation commands. All checks are fail-closed:
 * nothing here claims market eligibility in the current environment.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import * as api from '../../src/index.js'
import { runSelfCheck } from '../../src/index.js'
import { makeRunSpec, passingRequired } from '../fixtures/run-specs.js'

const ROOT = fileURLToPath(new URL('../..', import.meta.url))
const CLI = join(ROOT, 'bin', 'selfcheck.js')

test('entry surface: public API exports every integrated entry', () => {
  for (const name of [
    'runSelfCheck',
    'project',
    'projectAll',
    'runMarketGate',
    'computeEligibility',
    'assessReceipt',
    'validateMarketPolicy',
    'verifyRuntimeEvidence',
    'assessIsolation',
    'assessProviders',
    'buildEvidencePackage',
    'verifyEvidencePackage',
    'describeSchedulerEntry',
  ]) {
    assert.equal(typeof api[name], 'function', `${name} must be exported`)
  }
  assert.equal(api.MARKET_CONDITION_IDS.length, 10)
  assert.equal(typeof api.MARKET_REASON_CODES, 'object')
  assert.equal(typeof api.FIXED_VECTOR_DIGEST, 'string')
})

test('entry surface: v2 market anchor is not silently accepted by the local v1 entry', async (t) => {
  const v2Anchor = JSON.parse(readFileSync(join(ROOT, 'cordis-runtime', 'runtime-anchor.json'), 'utf8'))
  const dir = join(ROOT, '.dsh-testbed-entry-surface-tmp')
  t.after(async () => {
    const { rmSync } = await import('node:fs')
    rmSync(dir, { recursive: true, force: true })
  })
  const result = await runSelfCheck(makeRunSpec([passingRequired('entry.anchor.check')]), {
    executionMode: 'in-process',
    receiptOutDir: dir,
    runtimeAnchor: v2Anchor,
  })
  assert.equal(result.exitCode, 2)
  assert.equal(result.gateDecision, 'blocked')
  assert.equal(result.marketEligible, false)
  assert.equal(result.trustScope, 'local-only')
  assert.ok(
    (result.limitations ?? []).some((item) => String(item).includes('runtime-unavailable')),
    JSON.stringify(result.limitations),
  )
})

test('entry surface: CLI verbs and usage/exit semantics are fail-closed', () => {
  const cases = [
    ['no verb', [], 3],
    ['market missing receipt', ['market'], 3],
    ['scheduler disabled', ['scheduler'], 2],
    ['project missing receipt', ['project'], 3],
    ['unknown scheduler flag', ['scheduler', '--bogus'], 3],
    ['market unknown flag', ['market', '--bogus'], 3],
  ]
  for (const [label, args, expected] of cases) {
    const out = spawnSync(process.execPath, [CLI, ...args], { cwd: ROOT, encoding: 'utf8' })
    assert.equal(out.status, expected, `${label}: ${out.stderr}`)
  }
  const marketUnknown = spawnSync(process.execPath, [CLI, 'market', '--bogus'], { cwd: ROOT, encoding: 'utf8' })
  assert.match(marketUnknown.stderr, /unknown or incomplete market arguments/)
  const schedulerOff = spawnSync(process.execPath, [CLI, 'scheduler'], { cwd: ROOT, encoding: 'utf8' })
  const status = JSON.parse(schedulerOff.stdout)
  assert.equal(status.status, 'disabled')
  assert.deepEqual(status.reason_codes, ['scheduler-disabled'])
})

test('entry surface: README documents the reproducible commands and truthful market status', () => {
  const readme = readFileSync(join(ROOT, 'README.md'), 'utf8')
  for (const needle of [
    'pnpm exec tsc --noEmit',
    'pnpm run build:ts',
    'node --test "tests/**/*.test.js"',
    'node --test "tests/integration/market/**/*.test.js"',
    'node bin/selfcheck.js market',
    'node bin/selfcheck.js scheduler',
    'non-eligible',
    'market-attestation',
    'scheduler-disabled',
  ]) {
    assert.ok(readme.includes(needle), `README missing: ${needle}`)
  }
})
