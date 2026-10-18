/**
 * Read-only host capability facts for isolation provider diagnostics.
 *
 * This is a **probe**, not evidence: every result is graded `E0` and cannot be
 * used to claim L2/L3. Its only job is to explain *why* a provider is
 * unavailable and to feed the A2 precondition checks.
 *
 * All commands are fixed, read-only OS queries (`whoami`, `where`/`which`,
 * `id`) executed with `shell:false`, argument arrays, a timeout and
 * `windowsHide:true`. No user/container/VM/service is created, started or
 * modified, and no secret value is read into the result. Account names and SIDs
 * are redacted; only booleans/labels are reported.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/isolation/host-capabilities
 */
import { execFileSync } from 'node:child_process'
import { release as osRelease } from 'node:os'

import { HOST_FACTS_SCHEMA_VERSION, deepFreeze, digestDocument } from './contracts.js'

/** Read-only well-known binaries used only to decide "present / absent". */
export const CONTAINER_RUNTIME_CANDIDATES = Object.freeze([
  'docker', 'podman', 'nerdctl', 'containerd', 'ctr', 'runc', 'crun', 'buildah',
] as const)
export const VM_TOOL_CANDIDATES = Object.freeze([
  'qemu-system-x86_64', 'VBoxManage', 'vmrun', 'limactl', 'wsl',
] as const)

const DEFAULT_COMMAND_TIMEOUT_MS = 20_000
const HOST_FACTS_CACHE_MS = 60_000
let cachedHostFacts: Readonly<HostFacts> | null = null
let cachedHostFactsAtMs = 0
const PRIVILEGE_NAMES = Object.freeze([
  'SeAssignPrimaryTokenPrivilege',
  'SeIncreaseQuotaPrivilege',
  'SeDebugPrivilege',
  'SeImpersonatePrivilege',
] as const)

export interface HostSessionFacts {
  user: string
  sid: string
  elevated: boolean | null
  admin: boolean | null
  integrity: string
  source: string
}

export interface HostPrivilegeFacts {
  status: string
  enabled: string[]
  disabled: string[]
}

export interface AmbientCredentialFacts {
  status: 'absent' | 'present'
  count: number
  cloud: boolean
  vcs: boolean
  values_read: false
}

export interface HostFacts {
  schema_version: string
  platform: string
  arch: string
  os_release: string
  session: HostSessionFacts
  privileges: HostPrivilegeFacts
  dedicated_worker_identity: { status: string; detail: string }
  isolation_primitives: Record<string, string>
  container_runtimes: string[]
  vm_tools: string[]
  ambient_credentials: AmbientCredentialFacts
  evidence_grade: 'E0'
  market_evidence: false
  limitations: string[]
  collected_at: string
}

export interface CollectHostFactsOptions {
  platform?: NodeJS.Platform | string
  arch?: string
  env?: Record<string, string | undefined>
  runCommand?: (file: string, args: string[]) => string
  now?: () => Date
  includePrivileges?: boolean
}

interface InternalSessionProbe {
  elevated: boolean | null
  admin: boolean | null
  integrity: string
  source: string
}

/**
 * Default runner for a single read-only query. Never uses a shell.
 * @param {string} file
 * @param {string[]} args
 * @returns {string}
 */
export function runReadOnlyCommand(file: string, args: string[]): string {
  const result = execFileSync(file, args, {
    encoding: 'buffer',
    timeout: DEFAULT_COMMAND_TIMEOUT_MS,
    windowsHide: true,
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  return decodeCommandOutput(result)
}

/**
 * Decode fixed OS query output. Some Windows tools emit OEM/ANSI (e.g. GBK)
 * text even when redirected; fall back to GBK only when UTF-8 is not clean.
 */
function decodeCommandOutput(buffer: Buffer): string {
  const utf8 = new TextDecoder('utf-8').decode(buffer)
  if (!utf8.includes('\uFFFD')) return utf8
  try {
    return new TextDecoder('gbk').decode(buffer)
  } catch {
    return utf8
  }
}

/**
 * @param {CollectHostFactsOptions} [options]
 * @returns {Readonly<HostFacts>}
 */
export function collectHostFacts(options: CollectHostFactsOptions = {}): Readonly<HostFacts> {
  // The default probe uses two OS queries and takes a few seconds on this host;
  // cache it briefly so repeated provider/port construction does not re-probe.
  // Injected probes (tests) are never cached.
  const cacheable = options.platform === undefined && options.arch === undefined &&
    options.env === undefined && options.runCommand === undefined && options.now === undefined &&
    options.includePrivileges === undefined
  if (cacheable && cachedHostFacts !== null && Date.now() - cachedHostFactsAtMs < HOST_FACTS_CACHE_MS) {
    return cachedHostFacts
  }
  const platform = String(options.platform ?? process.platform)
  const arch = options.arch ?? process.arch
  const env = options.env ?? process.env
  const runCommand = options.runCommand ?? runReadOnlyCommand
  const now = typeof options.now === 'function' ? options.now : () => new Date()
  const includePrivileges = options.includePrivileges !== false

  const session = platform === 'win32'
    ? probeWindowsSession(runCommand)
    : probePosixSession(runCommand)
  const privileges: HostPrivilegeFacts = platform === 'win32' && includePrivileges
    ? probeWindowsPrivileges(runCommand)
    : { status: 'not-probed', enabled: [], disabled: [] }
  const containerRuntimes = detectPresentCommands(CONTAINER_RUNTIME_CANDIDATES, platform, runCommand)
  const vmTools = detectPresentCommands(VM_TOOL_CANDIDATES, platform, runCommand)
  const ambient = scanAmbientCredentials(env)

  const facts: HostFacts = {
    schema_version: HOST_FACTS_SCHEMA_VERSION,
    platform,
    arch,
    os_release: safeOsRelease(),
    session: {
      // Account names/SIDs are deliberately redacted in the audit output.
      user: 'redacted',
      sid: 'redacted',
      elevated: session.elevated,
      admin: session.admin,
      integrity: session.integrity,
      source: session.source,
    },
    privileges,
    dedicated_worker_identity: {
      status: 'unavailable',
      detail: 'no verified dedicated low-privilege identity was provisioned for this testbed',
    },
    isolation_primitives: {
      windows_restricted_token: platform === 'win32'
        ? (privileges.status === 'probed' &&
            privileges.enabled.includes('SeAssignPrimaryTokenPrivilege') &&
            privileges.enabled.includes('SeIncreaseQuotaPrivilege')
          ? 'os-supported-privileges-enabled-unmeasured'
          : 'os-supported-privileges-unavailable')
        : 'platform-mismatch',
      windows_appcontainer: platform === 'win32' ? 'os-supported-no-profile-verified' : 'platform-mismatch',
      windows_job_object: platform === 'win32' ? 'os-supported-unmeasured' : 'platform-mismatch',
      windows_firewall_per_user: platform === 'win32' ? 'not-configured' : 'platform-mismatch',
      user_namespace: platform === 'linux' ? 'present-unverified' : 'platform-mismatch',
      cgroup_v2: platform === 'linux' ? 'present-unverified' : 'platform-mismatch',
      rootless_container: containerRuntimes.length > 0 ? 'runtime-binary-present-unverified' : 'unavailable',
      micro_vm: vmTools.length > 0 ? 'tooling-present-unverified' : 'unavailable',
      remote_runner: 'unavailable',
    },
    container_runtimes: containerRuntimes,
    vm_tools: vmTools,
    ambient_credentials: ambient,
    evidence_grade: 'E0',
    market_evidence: false,
    limitations: [
      'host-observation-only',
      'does-not-prove-isolation',
      'account-and-sid-redacted',
      'no-low-privilege-identity-provisioned',
    ],
    collected_at: now().toISOString(),
  }
  const frozen = deepFreeze(facts)
  if (cacheable) {
    cachedHostFacts = frozen
    cachedHostFactsAtMs = Date.now()
  }
  return frozen
}

/**
 * Stable fingerprint of the environment facts (excludes collection time).
 * Binds A2/A3 evidence to the host shape that produced it.
 * @param {object} facts
 */
export function hostFingerprint(facts: object): string {
  if (!facts || typeof facts !== 'object') throw new TypeError('hostFingerprint: facts object required')
  return digestDocument(facts, ['collected_at'])
}

function safeOsRelease(): string {
  try {
    return osRelease()
  } catch {
    return 'unknown'
  }
}

function probeWindowsSession(runCommand: (file: string, args: string[]) => string): InternalSessionProbe {
  let output = ''
  try {
    // `/fo table` is used deliberately: in this harness `whoami /groups` with
    // CSV/list formatting can block on token group enumeration, while the table
    // form returns the same integrity label and group SIDs. The command is
    // fixed and read-only.
    output = runCommand('whoami', ['/groups', '/fo', 'table'])
  } catch {
    return { elevated: null, admin: null, integrity: 'unknown', source: 'whoami-groups-unavailable' }
  }
  const integrity = parseIntegrityLevel(output)
  const admin = /BUILTIN\\Administrators|S-1-5-32-544/i.test(output)
  const elevated = integrity === 'high' || integrity === 'system' || admin
  return { elevated, admin, integrity, source: 'whoami-groups' }
}

function probePosixSession(runCommand: (file: string, args: string[]) => string): InternalSessionProbe {
  let uid: string | null = null
  try {
    uid = runCommand('id', ['-u']).trim()
  } catch {
    return { elevated: null, admin: null, integrity: 'unknown', source: 'id-unavailable' }
  }
  const elevated = uid === '0'
  return { elevated, admin: elevated, integrity: elevated ? 'root' : 'user', source: 'id-u' }
}

function parseIntegrityLevel(output: string): string {
  if (/S-1-16-16384|System Mandatory Level/i.test(output)) return 'system'
  if (/S-1-16-12288|High Mandatory Level/i.test(output)) return 'high'
  if (/S-1-16-8448|Medium Plus Mandatory Level/i.test(output)) return 'medium-plus'
  if (/S-1-16-8192|Medium Mandatory Level/i.test(output)) return 'medium'
  if (/S-1-16-4096|Low Mandatory Level/i.test(output)) return 'low'
  return 'unknown'
}

function probeWindowsPrivileges(runCommand: (file: string, args: string[]) => string): HostPrivilegeFacts {
  let output = ''
  try {
    output = runCommand('whoami', ['/priv', '/fo', 'csv', '/nh'])
  } catch {
    return { status: 'probe-failed', enabled: [], disabled: [] }
  }  const enabled: string[] = []
  const disabled: string[] = []
  for (const privilege of PRIVILEGE_NAMES) {
    const line = output.split(/\r?\n/).find((row) => row.includes(privilege))
    if (!line) continue
    const enabledLabel = /Enabled|已启用/i.test(line)
    const disabledLabel = /Disabled|已禁用/i.test(line)
    if (enabledLabel && !disabledLabel) enabled.push(privilege)
    else disabled.push(privilege)
  }
  return { status: 'probed', enabled, disabled }
}

function detectPresentCommands(
  candidates: readonly string[],
  platform: string,
  runCommand: (file: string, args: string[]) => string,
): string[] {
  const locator = platform === 'win32' ? 'where.exe' : 'which'
  const present: string[] = []
  for (const candidate of candidates) {
    try {
      const output = runCommand(locator, [candidate])
      if (typeof output === 'string' && output.trim().length > 0) present.push(candidate)
    } catch {
      // absent is the expected/default result
    }
  }
  return present
}

function scanAmbientCredentials(env: Record<string, string | undefined> | undefined): AmbientCredentialFacts {
  const keys = env && typeof env === 'object' ? Object.keys(env) : []
  let count = 0
  let cloud = false
  let vcs = false
  for (const key of keys) {
    if (!/KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL/i.test(key)) continue
    // Ignore non-credential shell/runtime noise that meets the broad regex.
    if (/^(MONKEY|KEYBOARD|TURBO)/i.test(key)) continue
    count += 1
    if (/AWS|AZURE|GCP|GOOGLE|VAULT/i.test(key)) cloud = true
    if (/GITHUB|GITLAB|GH_|SSH_AUTH_SOCK/i.test(key)) vcs = true
  }
  return {
    status: count === 0 ? 'absent' : 'present',
    count,
    cloud,
    vcs,
    values_read: false,
  }
}
