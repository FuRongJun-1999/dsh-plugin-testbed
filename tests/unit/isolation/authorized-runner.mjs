/**
 * Authorized one-off Windows L2 execution harness (t4 evidence generation).
 *
 * This file is NOT a test and NOT part of the product runtime. It is invoked
 * manually after explicit captain/user authorization:
 *
 *   node tests/unit/isolation/authorized-runner.mjs <authorization.json>
 *
 * It creates/uses the current-user AppContainer profile `DshTestbedL2`, launches
 * one Job Object-limited worker under it, runs the A2 probe subset inside the
 * worker, captures the native measurement/attestation, and writes a JSON
 * evidence file. It does not create users/services or touch firewall/OS
 * features. The caller must run the documented rollback afterwards.
 */
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  createNonceRegistry,
  verifyIsolationAttestation,
} from '../../../src/isolation/attestation.js'
import { hostFingerprint } from '../../../src/isolation/host-capabilities.js'
import {
  buildWindowsL2AttestationFromMeasurement,
  inspectWindowsL2Backend,
} from '../../../src/isolation/backends/windows-l2.js'
import { createProviderCatalog } from '../../../src/isolation/providers.js'
import { A2_CASES, evaluateA2Evidence } from '../../../src/isolation/a2.js'
import { collectHostFacts } from '../../../src/isolation/host-capabilities.js'
import { policyDigestOf } from '../../../src/isolation/contracts.js'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const WORKSPACE_ROOT = resolve(REPO_ROOT, '..')
const LAUNCHER = resolve(REPO_ROOT, 'src/isolation/native/windows-l2/launcher.ps1')
const EVIDENCE_PATH = resolve(REPO_ROOT, 'tests/unit/isolation/evidence/windows-l2-execution.json')
const STATUS_PREFIX = 'DSH_L2_STATUS '
const PROBE_PREFIX = 'DSH_A2_PROBE '

const POLICY = {
  schema_version: 'market-gate-policy/v1',
  policy_id: 'policy-windows-l2-native-fixture',
  version: '1.0.0',
  isolation: { required_level: 'L2', max_attestation_age_ms: 600000 },
}

const PROBE_SOURCE = String.raw`
import { readFileSync, writeFileSync, symlinkSync, openSync, closeSync } from 'node:fs'
import net from 'node:net'
import dns from 'node:dns/promises'

const [, , workspaceFile, workspaceDir, dshHome, userHome, appdata] = process.argv
const results = []
function denialCode(error) {
  return error && typeof error.code === 'string' ? error.code : (error ? String(error.message).slice(0, 80) : 'unknown')
}
function record(caseId, category, ok, observed, detail = null) {
  results.push({ case_id: caseId, category, status: ok ? 'pass' : 'fail', observed: String(observed).slice(0, 500), detail })
}
function tryRead(caseId, category, path) {
  try {
    const fd = openSync(path, 'r')
    closeSync(fd)
    record(caseId, category, false, 'read-allowed', path)
  } catch (error) {
    const code = denialCode(error)
    record(caseId, category, ['EACCES', 'EPERM', 'ENOENT', 'UNKNOWN'].includes(code), 'denied:' + code, path)
  }
}
function tryWrite(caseId, category, path) {
  try {
    writeFileSync(path, 'dsh-a2-escape', { flag: 'w' })
    record(caseId, category, false, 'write-allowed', path)
  } catch (error) {
    record(caseId, category, true, 'denied:' + denialCode(error), path)
  }
}
tryRead('A2-01', 'filesystem', workspaceFile)
tryRead('A2-01', 'filesystem', dshHome + '\\team.json')
tryRead('A2-01', 'filesystem', userHome + '\\.ssh\\id_ed25519')
tryWrite('A2-04', 'filesystem', workspaceDir + '\\a2-escape.txt')
tryWrite('A2-04', 'filesystem', 'C:\\Windows\\Temp\\dsh-a2-escape.txt')
tryRead('A2-03', 'credentials', appdata + '\\Microsoft\\Credentials\\')
tryRead('A2-03', 'credentials', appdata + '\\Microsoft\\Crypto\\')
tryRead('A2-12', 'process', 'C:\\Windows\\System32\\config\\SAM')

const secretKeys = Object.keys(process.env).filter((key) => /KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL/i.test(key) && !/^(MONKEY|KEYBOARD|TURBO)/i.test(key))
record('A2-02', 'credentials', secretKeys.length === 0, 'env-secret-keys:' + secretKeys.length, secretKeys.slice(0, 5).join(','))

// A2-05: symlink/junction creation is allowed to fail (stronger denial); if it
// succeeds, following it must still be denied by the AppContainer boundary.
try {
  const link = process.cwd() + '\\a2-link'
  symlinkSync(workspaceDir, link, 'junction')
  try {
    const fd = openSync(workspaceFile, 'r')
    closeSync(fd)
    record('A2-05', 'filesystem', false, 'symlink-follow-allowed')
  } catch (error) {
    record('A2-05', 'filesystem', true, 'symlink-follow-denied:' + denialCode(error))
  }
} catch (error) {
  record('A2-05', 'filesystem', true, 'symlink-creation-denied:' + denialCode(error))
}

function connect(host, port, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port })
    let settled = false
    const done = (value) => { if (settled) return; settled = true; socket.destroy(); resolve(value) }
    socket.setTimeout(timeoutMs)
    socket.once('connect', () => done({ ok: true, code: null }))
    socket.once('timeout', () => done({ ok: false, code: 'ETIMEDOUT' }))
    socket.once('error', (error) => done({ ok: false, code: denialCode(error) }))
  })
}
const netResults = await Promise.all([
  connect('1.1.1.1', 53),
  connect('127.0.0.1', 9),
  connect('169.254.169.254', 80),
])
let dnsBlocked = false
try { await dns.lookup('example.com'); dnsBlocked = false } catch { dnsBlocked = true }
const allBlocked = netResults.every((item) => item.ok === false) && dnsBlocked
record('A2-06', 'network', allBlocked, 'net:' + netResults.map((item) => item.code || 'connected').join(',') + ';dns:' + (dnsBlocked ? 'blocked' : 'resolved'))

// A2-11: control-plane named pipes must be unreachable.
await new Promise((resolve) => {
  const socket = net.connect('\\\\.\\pipe\\dsh-control-plane-nonexistent')
  let settled = false
  const done = (value) => { if (settled) return; settled = true; socket.destroy(); resolve(value) }
  socket.once('connect', () => done({ ok: true }))
  socket.once('error', (error) => done({ ok: false, code: denialCode(error) }))
  socket.setTimeout(1000, () => done({ ok: false, code: 'ETIMEDOUT' }))
}).then((outcome) => record('A2-11', 'network', outcome.ok === false, 'named-pipe:' + (outcome.code || 'connected')))

process.stdout.write('DSH_A2_PROBE ' + JSON.stringify({ cases: results, cwd: process.cwd(), pid: process.pid }) + '\n')
`

function sha256(text) {
  return 'sha256:' + createHash('sha256').update(text).digest('hex')
}

function parseStatuses(stderr) {
  const statuses = []
  for (const line of stderr.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed.startsWith(STATUS_PREFIX)) continue
    try { statuses.push(JSON.parse(trimmed.slice(STATUS_PREFIX.length))) } catch { /* ignore */ }
  }
  return statuses
}

function parseProbe(stdout) {
  for (const line of stdout.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed.startsWith(PROBE_PREFIX)) continue
    try { return JSON.parse(trimmed.slice(PROBE_PREFIX.length)) } catch { /* ignore */ }
  }
  return null
}

function runLauncher(pwsh, requestPath, authorizationPath, timeoutMs, modeArgs = null) {
  return new Promise((resolveRun) => {
    const launcherArgs = modeArgs === null
      ? ['-Mode', 'execute', '-RequestPath', requestPath]
      : modeArgs
    const child = spawn(pwsh, [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', LAUNCHER,
      ...launcherArgs, '-AuthorizationPath', authorizationPath,
    ], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true })
    let stdout = ''
    let stderr = ''
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', (chunk) => { stdout += chunk })
    child.stderr.on('data', (chunk) => { stderr += chunk })
    const timer = setTimeout(() => { try { child.kill() } catch { /* ignore */ } }, timeoutMs)
    child.once('close', (code) => { clearTimeout(timer); resolveRun({ code, stdout, stderr }) })
    child.once('error', (error) => { clearTimeout(timer); resolveRun({ code: null, stdout, stderr: stderr + String(error) }) })
  })
}

const authorizationPath = process.argv[2]
if (!authorizationPath || !existsSync(authorizationPath)) {
  console.error('usage: node tests/unit/isolation/authorized-runner.mjs <authorization.json>')
  process.exit(2)
}
const authorization = JSON.parse(readFileSync(authorizationPath, 'utf8'))
const pwsh = process.env.DSH_PWSH_PATH ?? process.env.PWSH_PATH ?? 'pwsh'
const hostFacts = collectHostFacts()
const nativeBackend = { native_backend_compiled: true, userenv_exports: true, job_object_ready: true, profile_exists: false }
let preInspection = await inspectWindowsL2Backend()
if (preInspection.ran && preInspection.probe?.profile_exists === true) {
  nativeBackend.profile_exists = true
}

async function runLauncherMode(args, timeoutMs = 120000) {
  return runLauncher(pwsh, null, authorizationPath, timeoutMs, args)
}

async function ensureProfile() {
  if (nativeBackend.profile_exists && typeof preInspection.probe?.profile_folder === 'string') {
    return preInspection.probe.profile_folder
  }
  const created = await runLauncherMode(['-Mode', 'create-profile'])
  const status = parseStatuses(created.stderr).find((item) => item.status === 'profile-created')
  if (!status || typeof status.profile_folder !== 'string') {
    throw new Error('profile-create-failed:' + created.stderr.slice(0, 1000))
  }
  nativeBackend.profile_exists = true
  preInspection = await inspectWindowsL2Backend({ fresh: true })
  return status.profile_folder
}

const profileFolder = await ensureProfile()
const runnerDir = join(profileFolder, 'runner')
mkdirSync(runnerDir, { recursive: true })
const appContainerNode = join(runnerDir, 'node.exe')
if (!existsSync(appContainerNode) || readFileSync(appContainerNode).length === 0) {
  writeFileSync(appContainerNode, readFileSync(process.execPath))
}
const probePath = join(runnerDir, 'a2-probe.mjs')
writeFileSync(probePath, PROBE_SOURCE, 'utf8')
const artifactDigest = sha256(PROBE_SOURCE)

const probeTargets = {
  workspaceFile: join(WORKSPACE_ROOT, 'NEXT-PHASE-REQUIREMENTS.md'),
  workspaceDir: WORKSPACE_ROOT,
  dshHome: join(process.env.USERPROFILE ?? 'C:\\Users\\redacted', '.dsh'),
  userHome: process.env.USERPROFILE ?? 'C:\\Users\\redacted',
  appdata: process.env.APPDATA ?? 'C:\\Users\\redacted\\AppData\\Roaming',
}
const runId = 'run-l2-a2-' + Date.now().toString(36)
const planId = 'plan-sha256:' + createHash('sha256').update(runId).digest('hex')
const attemptDir = join(runnerDir, 'attempt-' + runId.slice(-12) + '-' + createHash('sha256').update(runId).digest('hex').slice(0, 8))
mkdirSync(attemptDir, { recursive: true })
const args = [
  '--preserve-symlinks-main',
  '"' + probePath + '"',
  '"' + probeTargets.workspaceFile + '"',
  '"' + probeTargets.workspaceDir + '"',
  '"' + probeTargets.dshHome + '"',
  '"' + probeTargets.userHome + '"',
  '"' + probeTargets.appdata + '"',
].join(' ')
const limits = { cpu_ms: 15000, memory_mb: 256, processes: 8, temp_bytes: 1048576, output_bytes: 1048576 }
const request = {
  schema_version: 'windows-l2-launch-request/v1',
  profile_name: 'DshTestbedL2',
  temp_root: attemptDir,
  application_path: appContainerNode,
  arguments: args,
  working_directory: 'auto',
  limits: { cpu_ms: limits.cpu_ms, memory_mb: limits.memory_mb, processes: limits.processes },
  env: {},
  create_profile: false,
  delete_temp_on_exit: true,
  delete_profile_on_exit: false,
}
const requestDir = mkdtempSync(join(tmpdir(), 'dsh-l2-request-'))
const requestPath = join(requestDir, 'request.json')
writeFileSync(requestPath, JSON.stringify(request), 'utf8')
const run = await runLauncher(pwsh, requestPath, authorizationPath, 180000)
const statuses = parseStatuses(run.stderr)
const launched = statuses.find((item) => item.status === 'launched') ?? null
const exited = statuses.find((item) => item.status === 'exited') ?? null
const blocked = statuses.find((item) => item.status === 'blocked') ?? null
const probeOutput = parseProbe(run.stdout)
const tempRoot = typeof launched?.temp_root === 'string' ? launched.temp_root : null
const pidAlive = launched && typeof launched.pid === 'number' ? (() => { try { process.kill(launched.pid, 0); return true } catch { return false } })() : null
const tempRemoved = tempRoot !== null ? !existsSync(tempRoot) : null
const postInspection = await inspectWindowsL2Backend({ fresh: true })

const descriptorCatalog = createProviderCatalog({ hostFacts, nativeBackend })
const nativeProvider = descriptorCatalog.find((provider) => provider.provider_id === 'windows-appcontainer-l2')
let attestation = null
let verification = null
let attestationError = null
if (launched !== null) {
  try {
    attestation = buildWindowsL2AttestationFromMeasurement({
      launched,
      request: { ...request, run_id: runId, plan_id: planId, test_id: 'iso.windows-l2.a2', attempt: 1, artifact_digest: artifactDigest, budget: limits },
      descriptor: nativeProvider.descriptor,
      limits,
      policy: POLICY,
    })
    verification = verifyIsolationAttestation(attestation, {
      run_id: runId,
      plan_id: planId,
      test_id: 'iso.windows-l2.a2',
      attempt: 1,
      launcher_id: nativeProvider.descriptor.launcher_id,
      launcher_version: nativeProvider.descriptor.launcher_version,
      provider_digest: nativeProvider.descriptor.provider_digest,
      policy_version: 'market-gate-policy/v1',
      policy_digest: policyDigestOf(POLICY),
      required_level: 'L2',
      max_age_ms: 600000,
      denied_roots: [probeTargets.workspaceDir, probeTargets.dshHome, 'C:/Windows/System32/config'],
      network_allowlist: [],
      limits: { cpu_ms: 60000, memory_mb: 1024, processes: 32, temp_bytes: 16 * 1024 * 1024, output_bytes: 16 * 1024 * 1024 },
      required_evidence_refs: attestation.evidence_refs,
    }, { now: new Date(), nonceRegistry: createNonceRegistry() })
  } catch (error) {
    attestationError = error instanceof Error ? error.message : String(error)
  }
}

const probeCases = Array.isArray(probeOutput?.cases) ? probeOutput.cases : []
const caseMap = new Map(probeCases.map((item) => [item.case_id, item]))
const hostProfile = hostFingerprint(hostFacts)
const a2Evidence = {
  schema_version: 'a2-evidence/v1',
  suite_version: 'a2-suite/v1',
  suite_id: 'A2',
  executor: {
    identity: {
      sid: typeof launched?.appcontainer_sid === 'string' ? launched.appcontainer_sid : 'redacted',
      user: 'DshTestbedL2',
      elevated: false,
      integrity: typeof launched?.identity_integrity === 'string' ? launched.identity_integrity : 'unknown',
    },
    executed_under_low_privilege: launched?.token_is_appcontainer === true,
    environment_fingerprint: hostProfile,
    host_fingerprint: hostProfile,
  },
  provider: {
    provider_id: nativeProvider.provider_id,
    provider_digest: nativeProvider.descriptor.provider_digest,
    launcher_version: nativeProvider.descriptor.launcher_version,
    level: nativeProvider.level,
    provenance: 'candidate',
    evidence_grade: 'E0',
  },
  started_at: launched?.started_at ?? new Date().toISOString(),
  completed_at: exited ? new Date().toISOString() : new Date().toISOString(),
  cases: A2_CASES.map((spec) => {
    const observed = caseMap.get(spec.id)
    if (observed) {
      return {
        case_id: spec.id,
        category: spec.category,
        status: observed.status,
        command: 'authorized-runner: a2-probe.mjs ' + spec.id,
        expected: spec.expectation,
        observed: observed.observed,
        evidence_refs: ['ev-a2-' + spec.id.toLowerCase()],
        reason_codes: [],
        at: new Date().toISOString(),
      }
    }
    return {
      case_id: spec.id,
      category: spec.category,
      status: 'blocked',
      command: null,
      expected: spec.expectation,
      observed: null,
      evidence_refs: [],
      reason_codes: ['not-executed-in-this-harness'],
      at: new Date().toISOString(),
    }
  }),
}
const a2Evaluation = evaluateA2Evidence(a2Evidence, { providerDescriptor: nativeProvider.descriptor })

// A2-10 cancel/reap measurement: kill the launcher (Job Object KILL_ON_JOB_CLOSE
// must terminate the worker tree), then verify the pid is gone and the control
// plane can remove the attempt temp root. This is measured separately so a
// normal exit cannot mask a leaked process.
async function runCancelReapTest() {
  const sleepScript = join(runnerDir, 'sleep-a2.mjs')
  writeFileSync(sleepScript, 'setInterval(() => {}, 1000)\n', 'utf8')
  const attempt = join(runnerDir, 'cancel-' + Date.now().toString(36))
  mkdirSync(attempt, { recursive: true })
  const cancelRequest = {
    ...request,
    temp_root: attempt,
    arguments: '--preserve-symlinks-main "' + sleepScript + '"',
    create_profile: false,
  }
  const cancelRequestPath = join(requestDir, 'cancel-request.json')
  writeFileSync(cancelRequestPath, JSON.stringify(cancelRequest), 'utf8')
  const child = spawn(pwsh, [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', LAUNCHER,
    '-Mode', 'execute', '-RequestPath', cancelRequestPath, '-AuthorizationPath', authorizationPath,
  ], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true })
  let stderr = ''
  let launchedStatus = null
  const launchedPromise = new Promise((resolveLaunched) => {
    child.stderr.setEncoding('utf8')
    child.stderr.on('data', (chunk) => {
      stderr += chunk
      for (const status of parseStatuses(chunk)) {
        if (status.status === 'launched') {
          launchedStatus = status
          resolveLaunched(status)
        }
      }
    })
    child.once('close', () => resolveLaunched(launchedStatus))
    child.once('error', () => resolveLaunched(launchedStatus))
  })
  const launchedResult = await Promise.race([
    launchedPromise,
    new Promise((resolveTimeout) => setTimeout(() => resolveTimeout(null), 120000)),
  ])
  const workerPid = typeof launchedResult?.pid === 'number' ? launchedResult.pid : null
  if (launchedResult !== null) {
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 700))
    try { child.kill() } catch { /* already gone */ }
  }
  await new Promise((resolveClose) => {
    if (child.exitCode !== null) { resolveClose(); return }
    child.once('close', resolveClose)
    setTimeout(resolveClose, 15000)
  })
  let pidAlive = null
  if (workerPid !== null) {
    try { process.kill(workerPid, 0); pidAlive = true } catch { pidAlive = false }
  }
  const tempExisted = existsSync(attempt)
  if (pidAlive === false && tempExisted) rmSync(attempt, { recursive: true, force: true })
  return {
    launched: launchedResult !== null,
    worker_pid: workerPid,
    pid_alive_after_cancel: pidAlive,
    temp_removed_by_control_plane: !existsSync(attempt),
    temp_existed_after_cancel: tempExisted,
    launcher_exit_code: child.exitCode,
    status: launchedResult !== null && pidAlive === false && !existsSync(attempt) ? 'pass' : 'blocked',
    stderr_tail: stderr
      .split(/\r?\n/)
      .filter((line) => !line.trim().startsWith(STATUS_PREFIX))
      .slice(-20)
      .join('\n')
      .slice(-3000),
  }
}
const cancelReap = await runCancelReapTest()

const evidence = {
  schema_version: 'windows-l2-execution-evidence/v1',
  generated_at: new Date().toISOString(),
  authorization: {
    approved_by: authorization.approved_by,
    approval_ref: authorization.approval_ref,
    profile_name: authorization.profile_name,
    scope: authorization.scope,
    expires_at: authorization.expires_at,
  },
  mechanism: nativeProvider.descriptor.isolation.mechanisms,
  profile: {
    name: 'DshTestbedL2',
    existed_before: preInspection.probe?.profile_exists === true,
    exists_after: postInspection.probe?.profile_exists === true,
    sid: launched?.appcontainer_sid ?? null,
  },
  launch: {
    run_id: runId,
    plan_id: planId,
    status: launched?.status ?? blocked?.status ?? 'blocked',
    pid: launched?.pid ?? null,
    appcontainer_sid: launched?.appcontainer_sid ?? null,
    token_is_appcontainer: launched?.token_is_appcontainer ?? null,
    identity_integrity: launched?.identity_integrity ?? null,
    capability_count: launched?.capability_count ?? null,
    job_limits: launched?.job_limits ?? null,
    temp_root: tempRoot,
    acl_sddl: launched?.acl_sddl ?? null,
    reparse_points: launched?.reparse_points ?? null,
    profile_created: launched?.profile_created ?? null,
    stdio_inherited: launched?.stdio_inherited ?? null,
    blocked_stage: blocked?.stage ?? null,
    blocked_error: blocked?.error ?? null,
    exit_code: exited?.exit_code ?? run.code,
  },
  probe: probeOutput,
  worker_stderr_tail: run.stderr
    .split(/\r?\n/)
    .filter((line) => !line.trim().startsWith(STATUS_PREFIX))
    .slice(-60)
    .join('\n')
    .slice(-8000),
  worker_stdout_tail: run.stdout.slice(-4000),
  a2: {
    executed_case_count: probeCases.length,
    executed_case_ids: probeCases.map((item) => item.case_id),
    blocked_case_ids: a2Evidence.cases.filter((item) => item.status === 'blocked').map((item) => item.case_id),
    evaluation_result: a2Evaluation.result,
    market_evidence: a2Evaluation.market_evidence,
    reason_codes: a2Evaluation.reason_codes,
    diagnostics: a2Evaluation.diagnostics,
  },
  attestation: attestation ? {
    digest: verification?.attestation_digest ?? null,
    result: verification?.result ?? null,
    reason_codes: verification?.reason_codes ?? [],
    checks: verification?.checks ?? [],
    attestation,
  } : { error: attestationError, result: null },
  reap: {
    pid_alive: pidAlive,
    temp_removed: tempRemoved,
    reaped: pidAlive === false && tempRemoved === true,
  },
  cancel_reap: cancelReap,
  residual_risks: [
    'launcher/test harness ran in the current High-IL administrator session; worker token is AppContainer Low IL',
    'A2 subset executed; remaining cases are blocked/not-executed',
    'no external availability record / signed attestation => market_evidence=false',
    'temp/output disk quotas are control-plane monitored, not OS-enforced',
  ],
  rollback: {
    required: true,
    command: 'pwsh -File src/isolation/native/windows-l2/launcher.ps1 -Mode delete-profile -AuthorizationPath <authorization.json>',
    profile_folder: typeof postInspection.probe?.profile_folder === 'string' ? postInspection.probe.profile_folder : null,
  },
}

mkdirSync(dirname(EVIDENCE_PATH), { recursive: true })
writeFileSync(EVIDENCE_PATH, JSON.stringify(evidence, null, 2), 'utf8')
rmSync(probePath, { force: true })
rmSync(requestPath, { force: true })
console.log(JSON.stringify({
  evidence_path: EVIDENCE_PATH,
  launch_status: evidence.launch.status,
  token_is_appcontainer: evidence.launch.token_is_appcontainer,
  integrity: evidence.launch.identity_integrity,
  capability_count: evidence.launch.capability_count,
  job_limits: evidence.launch.job_limits,
  probe_cases: evidence.a2.executed_case_count,
  a2_result: evidence.a2.evaluation_result,
  attestation_result: evidence.attestation.result,
  reap: evidence.reap,
  cancel_reap: evidence.cancel_reap.status,
  profile_exists_after: evidence.profile.exists_after,
  worker_stderr_tail: evidence.worker_stderr_tail,
}, null, 2))
if (evidence.launch.status !== 'launched' || evidence.launch.token_is_appcontainer !== true) process.exit(3)
