/**
 * Shared fixtures for market-gate integration tests (t8).
 *
 * Real runtime/contract evidence is read from the t7 handoff paths; isolation
 * fixtures reuse the t4 contract fixtures (clearly synthetic, never market
 * evidence). Receipts are produced by the untouched local kernel so the
 * market gate is exercised on real `receipt/v1` bytes.
 */
import { createHash } from 'node:crypto'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { runSelfCheck } from '../../../src/index.js'
import { recordDigest } from '../../../src/protocol/digest.js'
import { MARKET_CONDITION_IDS } from '../../../src/protocol/market-schemas.js'
import { makeRunSpec } from '../../fixtures/run-specs.js'
import {
  baseHostFacts,
  externalDescriptor,
  fixtureA2Evidence,
  fixtureAttestation,
  fixtureProvider,
  policyDigest,
} from '../../unit/isolation/fixtures.js'

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
export const REAL_ANCHOR = join(ROOT, 'cordis-runtime', 'runtime-anchor.json')
export const REAL_ANCHOR_BASE = join(ROOT, 'cordis-runtime')
export const REAL_CONTRACT_EVIDENCE = join(ROOT, 'tests', 'integration', 'cordis-contract', 'evidence')
export const T4_EXECUTION_EVIDENCE = join(ROOT, 'tests', 'unit', 'isolation', 'evidence', 'windows-l2-execution.json')

export function deepMerge(base, overrides) {
  if (overrides === undefined) return structuredClone(base)
  if (Array.isArray(base) || Array.isArray(overrides) || base === null || typeof base !== 'object') {
    return structuredClone(overrides)
  }
  const out = structuredClone(base)
  for (const [key, value] of Object.entries(overrides)) {
    out[key] = key in out ? deepMerge(out[key], value) : structuredClone(value)
  }
  return out
}

/** A valid frozen policy; override individual fields in negative tests. */
export function validPolicy(overrides = {}) {
  return deepMerge({
    schema_version: 'market-gate-policy/v1',
    policy_id: 'testbed-market-policy',
    policy_version: '1.0.0',
    effective_from: '2026-01-01T00:00:00Z',
    effective_until: null,
    required_isolation: { minimum: 'L2', require_l3_for: ['high-risk', 'multi-tenant'] },
    isolation: {
      required_level: 'L2',
      max_attestation_age_ms: 3_000_000,
      denied_roots: ['C:/Windows', 'C:/Users/redacted/.dsh', 'C:/Users/redacted/.ssh'],
      network_allowlist: [],
      limits: { cpu_ms: 15000, memory_mb: 512, processes: 16, temp_bytes: 2097152, output_bytes: 2097152 },
    },
    allowed_runtimes: [{
      package: '@deepseek-ai/cordis',
      version: '4.0.5',
      integrity: 'sha512-Sktq5axy0owk9PdnivBRNOJjHEVEibCt0+TDDZcv0+UH2KS1M910fX4kn5y45YFsrpZIi1mJf/1s5VzywMUnyg==',
    }],
    allowed_launchers: [{ launcher_id: 'windows-appcontainer-l2', attestation_required: true }],
    allowed_signers: [{ key_id: 'kms-market-key-1', alg: 'ed25519', state: 'active' }],
    allowed_archives: [{ provider_id: 'worm-archive-1', mode: 'object-lock' }],
    required_suites: ['cordis-contract-suite/v1', 'A2'],
    waiver_rules: {
      pre_approved_only: true,
      max_ttl_hours: 72,
      forbidden_for: ['MKT-C01', 'MKT-C03', 'MKT-C05', 'MKT-C06'],
      approver_roles: ['security', 'release'],
    },
    separation_of_duties: true,
    approval_roles: ['security', 'release'],
    evidence_max_age_hours: 24,
    fail_closed: true,
    required_conditions: [...MARKET_CONDITION_IDS],
  }, overrides)
}

export function tempDir(t, prefix = 'market-test-') {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(async () => {
    const { rmSync } = await import('node:fs')
    rmSync(dir, { recursive: true, force: true })
  })
  return dir
}

export function writeJson(dir, name, value) {
  mkdirSync(dir, { recursive: true })
  const path = join(dir, name)
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
  return path
}

function toolManifest(artifactDigest) {
  return {
    schema_version: 'test-tool-manifest/v1',
    tool_id: 'market.echo-probe',
    tool_version: '1.0.0',
    artifact_digest: artifactDigest,
    role: 'probe',
    runner: { adapter: 'local-worker-json', entrypoint: 'run' },
    input_schema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object',
      properties: { value: { type: 'number' } },
      required: ['value'],
      additionalProperties: false,
    },
    observation_schema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object',
      properties: { status_code: { type: 'integer' } },
      required: ['status_code'],
      additionalProperties: false,
    },
    requires: ['target:plugin'],
    permissions: { filesystem: ['workspace:read'], network: [], subprocess: [], devices: [], secrets: [] },
    limits: {
      timeout_ms: 30000, cpu_ms: 15000, memory_mb: 256, temp_bytes: 8388608,
      output_bytes: 1048576, attachment_bytes: 1048576, processes: 1, concurrency: 1,
    },
    determinism: 'deterministic',
    retry: { safe: false, max_attempts: 1 },
  }
}

async function receiptWithTool(t, expectedStatusCode) {
  const dir = tempDir(t, 'market-receipt-')
  const source = 'export async function run(input) { return { status_code: input.value } }'
  const artifactPath = join(dir, 'probe-tool.mjs')
  writeFileSync(artifactPath, source, 'utf8')
  const artifactDigest = `sha256:${createHash('sha256').update(Buffer.from(source, 'utf8')).digest('hex')}`
  const spec = makeRunSpec([{
    test_id: 'market.req.pass',
    node_id: 'market.req.pass',
    classification: 'required',
    criteria: { assert: 'equals', path: 'status_code', expected: expectedStatusCode },
    tool: {
      manifest: toolManifest(artifactDigest),
      input: { value: 200 },
      artifactPath,
      workspaceRoot: dir,
    },
  }])
  const out = await runSelfCheck(spec, { executionMode: 'subprocess', receiptOutDir: dir })
  const receipt = JSON.parse(readFileSync(out.receiptPath, 'utf8'))
  return { receipt, path: out.receiptPath, out, dir }
}

/** Produce a real, frozen, gate=pass receipt through the untouched kernel. */
export async function makePassReceipt(t) {
  return receiptWithTool(t, 200)
}

/** Produce a real frozen receipt whose gate decision is `reject`. */
export async function makeRejectReceipt(t) {
  return receiptWithTool(t, 999)
}

export function earliestStartedAt(receipt) {
  let earliest = null
  for (const testCase of receipt?.test_cases ?? []) {
    for (const attempt of testCase.attempts ?? []) {
      const at = typeof attempt.started_at === 'string' ? Date.parse(attempt.started_at) : NaN
      if (Number.isFinite(at) && (earliest === null || at < earliest)) earliest = at
    }
  }
  return earliest
}

/**
 * Positive isolation *contract* fixture: all A2 cases pass, provider claims an
 * external E2 measurement and host facts are low-privilege. This is explicitly
 * a fixture — the real environment has no such availability record.
 */
export function positiveIsolation(receipt, policy, nowIso) {
  const descriptor = externalDescriptor()
  const hostFacts = baseHostFacts()
  const provider = fixtureProvider({ descriptor, hostFacts })
  const { attestation } = fixtureAttestation({
    run_id: receipt.run_id,
    plan_id: receipt.plan_id,
    issued_at: nowIso,
    worker: { worker_id: 'worker-market-contract', pid: 4242, started_at: nowIso },
    policy: {
      policy_version: 'market-gate-policy/v1',
      policy_digest: policyDigest(policy),
    },
  })
  const a2Evidence = fixtureA2Evidence({ provider, hostFacts })
  a2Evidence.started_at = nowIso
  a2Evidence.completed_at = nowIso
  return { descriptor, hostFacts, provider, attestation, a2Evidence }
}

export function approvalsFor(receipt, policy, nowIso, overrides = {}) {
  const target = receipt.target_ref.owner_put_digest
  const earliest = earliestStartedAt(receipt)
  const baseMs = earliest === null ? Date.parse(nowIso) - 3_600_000 : earliest - 120_000
  const at = new Date(baseMs).toISOString()
  const policyRef = { id: policy.policy_id, version: policy.policy_version, digest: policyDigest(policy) }
  const make = (role, principal, approvalId) => ({
    schema_version: 'market-approval/v1',
    approval_id: approvalId,
    run_id: receipt.run_id,
    receipt_digest: recordDigest(receipt),
    policy: policyRef,
    principal,
    role,
    decision: 'approve',
    scope: { target_digest: target, isolation_level: 'L2', test_ids: ['market.req.pass'] },
    at,
    expires_at: null,
    signature_ref: `sig:${approvalId}`,
    separation: { worker: false, signer: false, archive: false, self: false },
    ...(overrides[role] ?? {}),
  })
  return [make('security', 'security-reviewer-1', 'approval-security-1'), make('release', 'release-manager-1', 'approval-release-1')]
}

export function waiverFor(receipt, policy, nowIso, overrides = {}) {
  const target = receipt.target_ref.owner_put_digest
  const earliest = earliestStartedAt(receipt)
  const approvedAtMs = (earliest === null ? Date.parse(nowIso) : earliest) - 300_000
  return {
    schema_version: 'market-waiver/v1',
    waiver_id: 'waiver-fixture-1',
    policy: { id: policy.policy_id, version: policy.policy_version, digest: policyDigest(policy) },
    condition_id: 'MKT-C04',
    scope: { run_id: receipt.run_id, target_digest: target },
    reason: 'contract fixture: scoped pre-approval, never turns a required into pass',
    requested_by: 'requester-1',
    approved_by: 'security-approver-2',
    approver_role: 'security',
    approved_at: new Date(approvedAtMs).toISOString(),
    expires_at: new Date(approvedAtMs + 3_600_000).toISOString(),
    status: 'approved',
    evidence_refs: ['ev-waiver-fixture-1'],
    ...overrides,
  }
}

export { recordDigest, policyDigest }
