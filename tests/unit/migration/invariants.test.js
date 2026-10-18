/**
 * Migration behavior-comparison gate (TS-02/TS-06/TS-08).
 *
 * `baseline-vectors.json` was captured from the pre-migration JavaScript
 * implementation (see the fixture header). Every vector below is recomputed
 * through the migrated build and compared byte-for-byte:
 *
 *   - closed enums + protocol version constants;
 *   - receipt/v1 fixed digest vector and the canonical receipt digest;
 *   - every declarative JSON Schema (canonical bytes + SHA-256) and registry;
 *   - all four projection formats (JUnit/TAP/HTML/CI) body bytes;
 *   - the exit-code matrix and the real CLI exit codes.
 *
 * Anything that changes receipt/v1, test-tool/v1, run-spec/v1,
 * gate-policy/v1, projection bytes or fail-closed enum vocabulary fails here.
 */
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import {
  FIXED_VECTOR_DIGEST,
  FIXED_VECTOR_INPUT,
  canonicalJson,
  recordDigest,
  sha256Hex,
} from '../../../src/protocol/digest.js'
import * as enums from '../../../src/protocol/enums.js'
import * as schemas from '../../../src/protocol/schemas.js'
import { validateReceiptV1 } from '../../../src/protocol/contracts.js'
import { projectAll } from '../../../src/reports/project/index.js'
import { resolveExitCode } from '../../../src/reports/exit.js'
import { buildReceipt } from '../../../src/reports/shape.js'
import { CANONICAL_RECEIPT_EXAMPLE } from '../protocol/fixtures/canonical-receipt.js'
import { makeReceipt } from '../reports/project/_fixtures.js'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const BASELINE = JSON.parse(readFileSync(new URL('./baseline-vectors.json', import.meta.url), 'utf8'))

const sha = (text) => 'sha256:' + sha256Hex(text)
const bytes = (text) => Buffer.byteLength(text, 'utf8')

test('closed enums and protocol version constants are unchanged', () => {
  for (const [name, expected] of Object.entries(BASELINE.enums)) {
    assert.ok(Array.isArray(enums[name]), `enum ${name} disappeared`)
    assert.deepEqual([...enums[name]], expected, `enum ${name} changed (fail-closed vocabulary must not drift)`)
  }
  for (const [name, expected] of Object.entries(BASELINE.version_constants)) {
    assert.equal(enums[name], expected, `protocol version constant ${name} changed`)
  }
})

test('receipt/v1 fixed vector and canonical receipt digest are unchanged', () => {
  assert.equal(FIXED_VECTOR_DIGEST, BASELINE.receipt_vectors.fixed_vector_digest)
  assert.equal(recordDigest(FIXED_VECTOR_INPUT), BASELINE.receipt_vectors.fixed_vector_recomputed)
  assert.equal(recordDigest(CANONICAL_RECEIPT_EXAMPLE), BASELINE.receipt_vectors.canonical_example_record_digest)
  const canonical = canonicalJson(CANONICAL_RECEIPT_EXAMPLE)
  assert.equal(sha(canonical), BASELINE.receipt_vectors.canonical_example_canonical_json_digest)
  assert.equal(bytes(canonical), BASELINE.receipt_vectors.canonical_example_canonical_json_bytes)
})

test('declarative JSON Schema canonical bytes and registry are unchanged', () => {
  for (const [name, expected] of Object.entries(BASELINE.schema_vectors)) {
    const canonical = canonicalJson(schemas[name])
    assert.equal(sha(canonical), expected.canonical_digest, `schema ${name} changed`)
    assert.equal(bytes(canonical), expected.canonical_bytes, `schema ${name} byte size changed`)
  }
  const registry = {}
  for (const [version, schema] of Object.entries(schemas.SCHEMA_BY_VERSION)) {
    registry[version] = sha(canonicalJson(schema))
  }
  assert.deepEqual(registry, BASELINE.schema_registry)
  // deepFreeze semantics preserved by the TypeScript port
  assert.ok(Object.isFrozen(schemas.RECEIPT_V1_SCHEMA))
  assert.ok(Object.isFrozen(schemas.RECEIPT_V1_SCHEMA.properties))
})

test('projection bytes for all four formats are unchanged', () => {
  const receipt = makeReceipt()
  assert.equal(recordDigest(receipt), BASELINE.projection_vectors.receipt_record_digest)
  const projected = projectAll(receipt, 'migration-baseline')
  assert.deepEqual(Object.keys(projected).sort(), Object.keys(BASELINE.projection_vectors.formats).sort())
  for (const [format, expected] of Object.entries(BASELINE.projection_vectors.formats)) {
    const out = projected[format]
    assert.equal(out.format_version, expected.format_version)
    assert.equal(out.source_receipt_digest, expected.source_receipt_digest)
    assert.equal(out.exporter_id, expected.exporter_id)
    assert.equal(sha(out.body), expected.body_digest, `projection ${format} bytes changed`)
    assert.equal(bytes(out.body), expected.body_bytes, `projection ${format} size changed`)
  }
})

test('exit-code matrix is unchanged', () => {
  const passing = buildReceipt({
    shape: 'frozen',
    runId: 'run-baseline',
    planResolution: { plan_id: 'plan-sha256:' + '11'.repeat(32), test_cases: [] },
    reconciliation: { expected: [], executed: [], missing: [], waived: [], missing_required: [] },
    gateDecision: 'pass',
  })
  const rejecting = buildReceipt({
    shape: 'frozen',
    runId: 'run-baseline-reject',
    planResolution: { plan_id: 'plan-sha256:' + '22'.repeat(32), test_cases: [] },
    reconciliation: { expected: [], executed: [], missing: [], waived: [], missing_required: [] },
    gateDecision: 'reject',
  })
  const blocked = buildReceipt({
    shape: 'pre-plan-blocked',
    runId: 'run-baseline-blocked',
    blockedStage: 'pre-plan',
    reasonCodes: ['spec-invalid'],
  })
  const tampered = JSON.parse(JSON.stringify(passing))
  tampered.gate_decision = 'blocked'

  const actual = {
    'pass:local-selfcheck/v1': resolveExitCode({ kind: 'receipt', receipt: passing }, 'local-selfcheck/v1'),
    'reject:local-selfcheck/v1': resolveExitCode({ kind: 'receipt', receipt: rejecting }, 'local-selfcheck/v1'),
    'blocked:local-selfcheck/v1': resolveExitCode({ kind: 'receipt', receipt: blocked }, 'local-selfcheck/v1'),
    'tampered:local-selfcheck/v1': resolveExitCode({ kind: 'receipt', receipt: tampered }, 'local-selfcheck/v1'),
    'pass:market-required/v1': resolveExitCode({ kind: 'receipt', receipt: passing }, 'market-required/v1'),
    'blocked:market-required/v1': resolveExitCode({ kind: 'receipt', receipt: blocked }, 'market-required/v1'),
    'write-failure': resolveExitCode({ kind: 'write-failure' }, 'local-selfcheck/v1'),
    'unknown-profile': resolveExitCode({ kind: 'receipt', receipt: passing }, 'unknown/v9'),
    'invalid-input': resolveExitCode(null, 'local-selfcheck/v1'),
  }
  assert.deepEqual(actual, BASELINE.exit_matrix)
})

test('runtime receipt/v1 fail-closed guards survive the TypeScript migration', () => {
  const unsignedMarket = {
    ...CANONICAL_RECEIPT_EXAMPLE,
    market_eligible: true,
  }
  assert.equal(validateReceiptV1(unsignedMarket).ok, false)
  const signed = {
    ...CANONICAL_RECEIPT_EXAMPLE,
    integrity: { record_digest: 'sha256:' + '99'.repeat(32), signed: true },
  }
  const signedResult = validateReceiptV1(signed)
  assert.equal(signedResult.ok, false)
  assert.ok(signedResult.errors.some((error) => error.startsWith('integrity-signed-must-be-false')))
  const forbiddenSignature = { ...CANONICAL_RECEIPT_EXAMPLE, signature: 'forged' }
  assert.equal(validateReceiptV1(forbiddenSignature).ok, false)
})

function runCli(args, cwd) {
  const result = spawnSync(process.execPath, [join(REPO_ROOT, 'bin', 'selfcheck.js'), ...args], {
    cwd,
    encoding: 'utf8',
    timeout: 120_000,
    windowsHide: true,
  })
  return { status: result.status, signal: result.signal }
}

test('CLI exit codes are unchanged', () => {
  const work = mkdtempSync(join(tmpdir(), 'testbed-migration-cli-'))
  const receiptOut = mkdtempSync(join(tmpdir(), 'testbed-migration-out-'))
  try {
    const actual = {
      'usage:no-args': runCli([], work),
      'usage:project-without-receipt': runCli(['project'], work),
      'selfcheck:cli-smoke': runCli(
        ['selfcheck', '--spec', 'tests/fixtures/cli-smoke.json', '--receipt-out', receiptOut, '--probe-time', '2026-01-01T00:00:00.000Z'],
        REPO_ROOT,
      ),
    }
    assert.deepEqual(actual, BASELINE.cli_exit_codes)
  } finally {
    rmSync(work, { recursive: true, force: true })
    rmSync(receiptOut, { recursive: true, force: true })
  }
})
