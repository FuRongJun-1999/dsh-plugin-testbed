/**
 * Evidence regression for the authorized Windows L2 execution.
 *
 * The JSON file is produced by `authorized-runner.mjs` after explicit captain/
 * user authorization. This test only reads the recorded measurements and
 * asserts that the native L2 claims are backed by measured facts — it never
 * creates a profile or launches a process. The evidence remains E1/local test
 * evidence, not market eligibility.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const EVIDENCE_PATH = new URL('./evidence/windows-l2-execution.json', import.meta.url)
const ROLLBACK_PATH = new URL('./evidence/windows-l2-rollback.json', import.meta.url)
const evidence = JSON.parse(readFileSync(EVIDENCE_PATH, 'utf8'))
const rollback = JSON.parse(readFileSync(ROLLBACK_PATH, 'utf8'))

test('windows-l2 evidence: measured AppContainer identity + zero capabilities', () => {
  assert.equal(evidence.schema_version, 'windows-l2-execution-evidence/v1')
  assert.equal(evidence.launch.status, 'launched')
  assert.equal(evidence.launch.token_is_appcontainer, true)
  assert.equal(evidence.launch.identity_integrity, 'low')
  assert.equal(evidence.launch.capability_count, 0)
  assert.equal(evidence.launch.profile_name ?? 'DshTestbedL2', 'DshTestbedL2')
  assert.match(String(evidence.launch.appcontainer_sid ?? evidence.profile.sid), /^S-1-15-2-/)
})

test('windows-l2 evidence: Job Object limits are OS-measured, not requested', () => {
  const limits = evidence.launch.job_limits
  assert.ok(limits, 'job_limits missing')
  assert.equal(limits.measured, true)
  assert.equal(limits.kill_on_job_close, true)
  assert.ok(limits.process_time_100ns > 0)
  assert.ok(limits.process_memory_bytes > 0)
  assert.ok(limits.job_memory_bytes > 0)
  assert.ok(limits.active_process_limit > 0)
})

test('windows-l2 evidence: attempt ACL grants the AppContainer SID', () => {
  const sid = String(evidence.launch.appcontainer_sid ?? evidence.profile.sid)
  assert.match(String(evidence.launch.acl_sddl), /^D:/)
  assert.ok(String(evidence.launch.acl_sddl).includes(sid))
  assert.equal(evidence.launch.reparse_points, 0)
  assert.equal(evidence.launch.stdio_inherited, true)
})

test('windows-l2 evidence: A2 probes actually denied file/credential/network/process access', () => {
  const cases = evidence.probe?.cases ?? []
  assert.ok(cases.length >= 10, `expected >=10 probe results, got ${cases.length}`)
  const ids = new Set(cases.map((item) => item.case_id))
  for (const id of ['A2-01', 'A2-02', 'A2-03', 'A2-04', 'A2-05', 'A2-06', 'A2-11', 'A2-12']) {
    assert.ok(ids.has(id), `missing executed probe ${id}`)
  }
  for (const item of cases) {
    assert.equal(item.status, 'pass', `${item.case_id} failed: ${item.observed}`)
  }
})

test('windows-l2 evidence: measured attestation verifies and stays L2 (never L3/market)', () => {
  assert.equal(evidence.attestation.result, 'valid')
  assert.match(String(evidence.attestation.digest), /^sha256:[0-9a-f]{64}$/)
  const attestation = evidence.attestation.attestation
  assert.equal(attestation.isolation.level, 'L2')
  assert.equal(attestation.isolation.elevated, false)
  assert.equal(attestation.issuer.trust, 'control-plane-measured')
  assert.equal(attestation.signature, null)
  assert.equal(attestation.network.default, 'deny')
  assert.deepEqual(attestation.network.allowlist, [])
  assert.equal(attestation.secrets.ambient_credentials, 'none')
  assert.equal(attestation.process_tree.kill_on_close, true)
  assert.ok(evidence.attestation.checks.every((item) => item.status === 'pass'))
})

test('windows-l2 evidence: reap and cancel/reap both remove the process and temp root', () => {
  assert.equal(evidence.reap.reaped, true)
  assert.equal(evidence.reap.pid_alive, false)
  assert.equal(evidence.reap.temp_removed, true)
  assert.equal(evidence.cancel_reap.status, 'pass')
  assert.equal(evidence.cancel_reap.pid_alive_after_cancel, false)
  assert.equal(evidence.cancel_reap.temp_removed_by_control_plane, true)
})

test('windows-l2 evidence: A2 remains blocked/non-market and residual risks are explicit', () => {
  assert.equal(evidence.a2.evaluation_result, 'blocked')
  assert.equal(evidence.a2.market_evidence, false)
  assert.ok(evidence.a2.blocked_case_ids.length > 0)
  assert.ok(evidence.residual_risks.some((item) => item.includes('High-IL')))
  assert.ok(evidence.residual_risks.some((item) => item.includes('market_evidence=false')))
  assert.ok(evidence.rollback.required)
  assert.equal(evidence.profile.exists_after, true)
})

test('windows-l2 evidence: authorized profile rollback completed and was verified', () => {
  assert.equal(rollback.schema_version, 'windows-l2-rollback-evidence/v1')
  assert.equal(rollback.result, 'profile-deleted')
  assert.equal(rollback.package_folder_removed, true)
  assert.equal(rollback.post_rollback_profile_exists, false)
  assert.equal(evidence.rollback.result, 'profile-deleted')
  assert.equal(evidence.rollback.post_rollback_profile_exists, false)
  assert.ok(rollback.notes.some((item) => item.includes('no local user')))
})
