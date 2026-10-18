/**
 * Worker environment boundary — minimal environment and ambient-credential handling.
 *
 * The L1 worker runs as an ordinary same-privilege child process. It is *not* a
 * security boundary (architecture §5.2/§5.3): files, network, subprocesses,
 * devices, CPU and memory are not enforced. One boundary that the worker can and
 * must still enforce for itself is the **environment**: no control-plane
 * credential, signing key, publish token or other ambient credential is kept in
 * the worker process, and the tool child only receives a minimal environment.
 *
 * Everything here reports **key names and counts only** — never environment
 * values, never a secret. Removal is fail-closed: anything that is not on the
 * system allowlist is dropped, so a new credential name cannot leak by default.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/worker/environment
 */

/** Environment keys that the operating system / Node itself may need. */
const WINDOWS_SYSTEM_ENV = Object.freeze([
  'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'SYSTEMDRIVE', 'TEMP', 'TMP', 'PATHEXT',
])
const POSIX_SYSTEM_ENV = Object.freeze([
  'TMPDIR', 'TEMP', 'TMP', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ', 'PATH',
])

/** Testbed runtime-injection keys (configuration, never credentials). */
export const TESTBED_RUNTIME_ENV_KEYS = Object.freeze([
  'DSH_TESTBED_RUNTIME_ANCHOR',
  'DSH_TESTBED_CORDIS_ENTRY',
  'DSH_TESTBED_CORDIS_VERSION',
  'DSH_TESTBED_DSH_COMMIT',
  'DSH_TESTBED_RUNTIME_KIND',
])

/**
 * Credential-looking environment names. Deliberately conservative: a name that
 * merely *looks* like a credential is removed too, because the worker must never
 * carry ambient credentials and cannot prove a negative after the fact.
 */
const CREDENTIAL_ENV_NAME = /(?:^|_)(?:api[_-]?key|apikey|key|token|secret|password|passwd|credential|credentials|private[_-]?key|access[_-]?key|auth[_-]?token|session[_-]?token|cookie|bearer|signature|signing[_-]?key|client[_-]?secret)(?:$|_)/i
const PROVIDER_ENV_PREFIX = /^(?:AWS_|AZURE_|GCP_|GOOGLE_|OPENAI_|ANTHROPIC_|DEEPSEEK_|GITHUB_|GH_|GITLAB_|NPM_|PYPI_|SSH_|HF_|HUGGINGFACE_|COHERE_|MISTRAL_|TOGETHER_|REPLICATE_|VERCEL_|NETLIFY_|CLOUDFLARE_|STRIPE_|TWILIO_|SENDGRID_|SLACK_)/i

/** @param {string} name @returns {boolean} */
export function isCredentialEnvName(name) {
  return typeof name === 'string' && name.length > 0 &&
    (CREDENTIAL_ENV_NAME.test(name) || PROVIDER_ENV_PREFIX.test(name))
}

/** @param {string|undefined} platform */
function systemAllowlist(platform) {
  return platform === 'win32' ? WINDOWS_SYSTEM_ENV : POSIX_SYSTEM_ENV
}

/** Windows environment names are case-insensitive; match them that way. */
function allowlistMatcher(platform) {
  const allowlist = new Set([...systemAllowlist(platform)])
  if (platform === 'win32') {
    const lowered = new Set([...allowlist].map((name) => name.toLowerCase()))
    return (name) => lowered.has(String(name).toLowerCase())
  }
  return (name) => allowlist.has(name)
}

/**
 * Snapshot the testbed runtime injection carried by the environment.
 * Returns configuration values (paths / versions) only; this is *not* a
 * credential source and the returned object contains no unrelated env keys.
 *
 * @param {Record<string, string|undefined>} [env]
 * @returns {{runtime_anchor?:string, cordis_entry?:string, cordis_version?:string,
 *   dsh_commit?:string, runtime_kind?:string}}
 */
export function captureRuntimeEnvironment(env = process.env) {
  const captured = {}
  if (!env || typeof env !== 'object') return captured
  const anchor = env.DSH_TESTBED_RUNTIME_ANCHOR
  const entry = env.DSH_TESTBED_CORDIS_ENTRY
  const version = env.DSH_TESTBED_CORDIS_VERSION
  const commit = env.DSH_TESTBED_DSH_COMMIT
  const kind = env.DSH_TESTBED_RUNTIME_KIND
  if (typeof anchor === 'string' && anchor.length > 0) captured.runtime_anchor = anchor
  if (typeof entry === 'string' && entry.length > 0) captured.cordis_entry = entry
  if (typeof version === 'string' && version.length > 0) captured.cordis_version = version
  if (typeof commit === 'string' && commit.length > 0) captured.dsh_commit = commit
  if (typeof kind === 'string' && kind.length > 0) captured.runtime_kind = kind
  return captured
}

/**
 * Remove every ambient variable that is not on the system allowlist. Never
 * returns values; the result is intentionally small enough to be recorded as
 * worker observation evidence.
 *
 * @param {Record<string, string|undefined>} [env] mutable environment object
 * @param {{platform?:string}} [options]
 * @returns {{removed_count:number, credential_name_count:number,
 *   kept_names:string[], ambient_credentials_observed:boolean}}
 */
export function scrubAmbientEnvironment(env = process.env, options = {}) {
  const platform = options.platform ?? process.platform
  const isAllowed = allowlistMatcher(platform)
  const keptNames = []
  let removedCount = 0
  let credentialNameCount = 0
  for (const name of Object.keys(env ?? {})) {
    if (isAllowed(name)) {
      keptNames.push(name)
      continue
    }
    if (isCredentialEnvName(name)) credentialNameCount += 1
    try {
      delete env[name]
    } catch {
      // A non-configurable property cannot be removed; the tool child still
      // receives only the minimal environment built below.
    }
    removedCount += 1
  }
  return {
    removed_count: removedCount,
    credential_name_count: credentialNameCount,
    kept_names: keptNames.sort(),
    ambient_credentials_observed: credentialNameCount > 0,
  }
}

/**
 * Build the environment passed to a tool child. Only allowlisted OS keys are
 * copied and credential-looking names are rejected even if someone adds one to
 * the allowlist by mistake. `NODE_NO_WARNINGS=1` keeps stdout clean.
 *
 * @param {Record<string, string|undefined>} [base]
 * @param {{platform?:string}} [options]
 * @returns {Record<string,string>} fresh object (no prototype inheritance)
 */
export function minimalChildEnvironment(base = process.env, options = {}) {
  const platform = options.platform ?? process.platform
  const isAllowed = allowlistMatcher(platform)
  const childEnv = Object.create(null)
  for (const [name, value] of Object.entries(base ?? {})) {
    if (!isAllowed(name) || isCredentialEnvName(name)) continue
    if (typeof value !== 'string') continue
    childEnv[name] = value
  }
  childEnv.NODE_NO_WARNINGS = '1'
  return Object.freeze(childEnv)
}
