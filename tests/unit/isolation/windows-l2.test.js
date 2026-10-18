/** Windows L2 native backend preparation tests (no OS mutation). */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  WINDOWS_L2_PROFILE_NAME,
  createWindowsL2Transport,
  getWindowsL2Plan,
  inspectWindowsL2Backend,
  validateWindowsL2Authorization,
  windowsL2ProviderReadiness,
} from '../../../src/isolation/backends/windows-l2.js'
import { baseHostFacts, highIntegrityHostFacts, validPolicy } from './fixtures.js'

function authorization(overrides = {}) {
  return {
    schema_version: 'windows-l2-authorization/v1',
    approved_by: 'captain-fixture',
    approval_ref: 't4-fixture',
    profile_name: WINDOWS_L2_PROFILE_NAME,
    scope: [
      'create-appcontainer-profile',
      'launch-appcontainer-process',
      'assign-job-object',
      'create-temp-root',
      'delete-attempt-temp',
      'delete-appcontainer-profile',
    ],
    issued_at: '2026-10-18T00:00:00Z',
    expires_at: '2030-10-19T00:00:00Z',
    acknowledged_risks: ['per-user-profile', 'high-il-harness', 'temp-not-os-enforced'],
    ...overrides,
  }
}

test('windows-l2: plan enumerates mutations, impact, rollback and authorization scopes', () => {
  const plan = getWindowsL2Plan()
  assert.equal(plan.schema_version, 'windows-l2-plan/v1')
  assert.equal(plan.profile_name, WINDOWS_L2_PROFILE_NAME)
  assert.equal(plan.authorization_required, true)
  const operations = plan.operations
  for (const id of ['compile-inspect', 'create-profile', 'launch-worker', 'assign-job-object', 'create-temp-root', 'delete-attempt-temp', 'delete-profile']) {
    const operation = operations.find((item) => item.id === id)
    assert.ok(operation, `missing operation ${id}`)
    assert.ok(typeof operation.impact === 'string' && operation.impact.length > 0)
    assert.ok(typeof operation.rollback === 'string' && operation.rollback.length > 0)
    if (id !== 'compile-inspect') assert.ok(operation.authorization_scope, `${id} must be authorized`)
  }
  assert.equal(operations.find((item) => item.id === 'compile-inspect').authorization_scope, null)
  for (const forbidden of ['no new local user or group', 'no global or per-user firewall rule', 'no Windows optional feature or service']) {
    assert.ok(plan.not_changed.includes(forbidden), forbidden)
  }
  assert.ok(plan.limitations.some((item) => item.includes('High-IL')))
})

test('windows-l2: authorization validation enforces scope, profile, expiry and risks', () => {
  assert.deepEqual(validateWindowsL2Authorization(authorization()), { ok: true, errors: [] })
  assert.equal(validateWindowsL2Authorization(authorization({ expires_at: '2020-01-01T00:00:00Z' })).ok, false)
  assert.equal(validateWindowsL2Authorization(authorization({ profile_name: 'OtherProfile' })).ok, false)
  assert.equal(validateWindowsL2Authorization(authorization({ scope: ['create-appcontainer-profile'] })).ok, false)
  assert.equal(validateWindowsL2Authorization(authorization({ acknowledged_risks: [] })).ok, false)
  assert.equal(validateWindowsL2Authorization(authorization({ unknown: true })).ok, false)
  assert.equal(validateWindowsL2Authorization({}).ok, false)
})

test('windows-l2: read-only inspect compiles the native backend without mutation', async (t) => {
  const inspection = await inspectWindowsL2Backend()
  if (!inspection.ran && inspection.errors.some((message) => /ENOENT|pwsh/i.test(message))) {
    t.skip('pwsh is not available in this environment')
    return
  }
  assert.equal(inspection.ran, true, inspection.errors.join(','))
  assert.equal(inspection.status, 'ok', JSON.stringify(inspection.probe))
  assert.equal(inspection.mutations, false)
  assert.equal(inspection.evidence_grade, 'E0')
  assert.equal(inspection.probe.native_backend_compiled, true)
  assert.equal(inspection.probe.job_object_ready, true)
  assert.equal(inspection.probe.userenv_exports, true)
  assert.equal(typeof inspection.probe.profile_exists, 'boolean')
  if (inspection.probe.profile_exists) {
    assert.match(String(inspection.probe.profile_sid), /^S-1-15-2-/)
    assert.match(String(inspection.probe.profile_folder), /dshtestbedl2/i)
  }
  assert.equal(inspection.probe.current_user, 'redacted')
  assert.equal(inspection.probe.native_backend, 'windows-l2-appcontainer-jobobject/v1')
})

test('windows-l2: readiness is prepared but never market-available', async (t) => {
  const inspection = await inspectWindowsL2Backend()
  if (!inspection.ran) {
    t.skip('pwsh is not available in this environment')
    return
  }
  const readiness = windowsL2ProviderReadiness(highIntegrityHostFacts(), inspection)
  assert.equal(readiness.prepared, true)
  assert.equal(readiness.market_available, false)
  assert.equal(readiness.requires_authorization, true)
  assert.ok(readiness.reason_codes.includes('worker-identity-not-low-privilege'))
  assert.ok(readiness.reason_codes.includes('isolation-provider-not-measured'))
  assert.ok(readiness.reason_codes.includes('adversarial-suite-missing'))
  assert.ok(readiness.authorization_steps.some((operation) => operation.id === 'create-profile'))
  assert.ok(readiness.unenforced.includes('temp_bytes'))
  const lowPrivReadiness = windowsL2ProviderReadiness(baseHostFacts(), inspection)
  assert.equal(lowPrivReadiness.market_available, false)
  assert.ok(lowPrivReadiness.reason_codes.includes('isolation-provider-not-measured'))
})

test('windows-l2: transport refuses to launch without authorization', async () => {
  const transport = createWindowsL2Transport({
    authorization: null,
    policy: validPolicy(),
    workerNodePath: process.execPath,
    workerEntry: process.execPath,
    limits: { cpu_ms: 1000, memory_mb: 128, processes: 4, temp_bytes: 1048576, output_bytes: 1048576 },
  })
  const result = await transport.launch({
    request: { run_id: 'run-noauth' },
    descriptor: { launcher_id: 'windows-appcontainer-l2', launcher_version: '1', provider_digest: 'sha256:' + 'a'.repeat(64), isolation: { level: 'L2' } },
  })
  assert.equal(result.status, 'blocked')
  assert.equal(result.launch_attempted, false)
  assert.equal(result.fallback_used, false)
  assert.ok(result.detail.startsWith('authorization-required:'))
})

test('windows-l2: transport with authorization but missing worker entry stays blocked', async () => {
  const transport = createWindowsL2Transport({
    authorization: authorization(),
    policy: validPolicy(),
    workerNodePath: 'C:/does/not/exist/node.exe',
    workerEntry: 'C:/does/not/exist/worker.js',
    limits: { cpu_ms: 1000, memory_mb: 128, processes: 4, temp_bytes: 1048576, output_bytes: 1048576 },
  })
  const result = await transport.launch({
    request: {},
    descriptor: { launcher_id: 'windows-appcontainer-l2', launcher_version: '1', provider_digest: 'sha256:' + 'a'.repeat(64), isolation: { level: 'L2' } },
  })
  assert.equal(result.status, 'blocked')
  assert.equal(result.launch_attempted, false)
  assert.equal(result.detail, 'worker-node-path-missing')
})

test('windows-l2: adversarial cases are blocked until a measured A2 harness exists', async () => {
  const transport = createWindowsL2Transport({
    authorization: authorization(),
    policy: validPolicy(),
    workerNodePath: process.execPath,
    workerEntry: process.execPath,
    limits: { cpu_ms: 1000, memory_mb: 128, processes: 4, temp_bytes: 1048576, output_bytes: 1048576 },
  })
  const result = await transport.runAdversarialCase({ id: 'A2-01', category: 'filesystem', attack: 'x', expectation: 'deny', preconditions: [] })
  assert.equal(result.status, 'blocked')
  assert.ok(result.reason_codes.includes('adversarial-suite-missing'))
})
