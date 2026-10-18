/** Worker environment boundary tests (no credentials ever reported). */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  captureRuntimeEnvironment,
  isCredentialEnvName,
  minimalChildEnvironment,
  scrubAmbientEnvironment,
} from '../../../src/worker/environment.js'

test('credential-looking names are recognised across providers and generic tokens', () => {
  for (const name of [
    'OPENAI_API_KEY', 'DEEPSEEK_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'AWS_SECRET_ACCESS_KEY',
    'GITHUB_TOKEN', 'GH_TOKEN', 'NPM_TOKEN', 'SSH_PRIVATE_KEY', 'CLIENT_SECRET', 'API_KEY',
    'SIGNING_KEY', 'MY_PASSWORD', 'DATABASE_CREDENTIALS', 'COOKIE_JAR', 'BEARER_TOKEN',
  ]) {
    assert.equal(isCredentialEnvName(name), true, `${name} should look like a credential`)
  }
  for (const name of ['TEMP', 'SystemRoot', 'PATH', 'NODE_NO_WARNINGS', 'LANG', 'DSH_TESTBED_RUNTIME_ANCHOR']) {
    assert.equal(isCredentialEnvName(name), false, `${name} should not look like a credential`)
  }
})

test('scrubAmbientEnvironment keeps only system keys and reports counts, never values', () => {
  const env = {
    SystemRoot: 'C:\\Windows',
    WINDIR: 'C:\\Windows',
    windir: 'C:\\Windows',
    TEMP: 'C:\\Temp',
    OPENAI_API_KEY: 'sk-secret-value-must-not-surface',
    GITHUB_TOKEN: 'ghp_secretvalue',
    DSH_TESTBED_RUNTIME_ANCHOR: 'C:\\anchor.json',
    MY_CUSTOM_VAR: 'custom',
  }
  const audit = scrubAmbientEnvironment(env, { platform: 'win32' })
  assert.deepEqual(Object.keys(env).sort(), ['SystemRoot', 'TEMP', 'WINDIR', 'windir'])
  assert.equal(audit.removed_count, 4)
  assert.equal(audit.credential_name_count, 2)
  assert.equal(audit.ambient_credentials_observed, true)
  assert.deepEqual(audit.kept_names, ['SystemRoot', 'TEMP', 'WINDIR', 'windir'])
  const serialized = JSON.stringify(audit)
  assert.equal(serialized.includes('sk-secret-value-must-not-surface'), false)
  assert.equal(serialized.includes('ghp_secretvalue'), false)
  assert.equal(serialized.includes('C:\\anchor.json'), false)
})

test('scrubAmbientEnvironment on posix keeps TMPDIR/LANG only', () => {
  const env = { TMPDIR: '/tmp', LANG: 'C.UTF-8', PATH: '/usr/bin', HOME: '/home/dev', AWS_ACCESS_KEY_ID: 'x' }
  const audit = scrubAmbientEnvironment(env, { platform: 'linux' })
  assert.deepEqual(Object.keys(env).sort(), ['LANG', 'PATH', 'TMPDIR'])
  assert.equal(audit.credential_name_count, 1)
})

test('minimalChildEnvironment copies allowlisted system keys and drops credentials', () => {
  const childEnv = minimalChildEnvironment({
    SystemRoot: 'C:\\Windows',
    TEMP: 'C:\\Temp',
    PATHEXT: '.EXE',
    OPENAI_API_KEY: 'sk-nope',
    AWS_REGION: 'us-east-1',
    NODE_NO_WARNINGS: '0',
  }, { platform: 'win32' })
  assert.equal(childEnv.NODE_NO_WARNINGS, '1', 'worker forces quiet stdout')
  assert.equal(childEnv.SystemRoot, 'C:\\Windows')
  assert.equal(childEnv.TEMP, 'C:\\Temp')
  assert.equal(Object.hasOwn(childEnv, 'OPENAI_API_KEY'), false)
  assert.equal(Object.hasOwn(childEnv, 'AWS_REGION'), false)
  assert.equal(Object.values(childEnv).includes('sk-nope'), false)
})

test('captureRuntimeEnvironment captures only testbed runtime configuration', () => {
  const captured = captureRuntimeEnvironment({
    DSH_TESTBED_RUNTIME_ANCHOR: 'anchor.json',
    DSH_TESTBED_CORDIS_ENTRY: 'file:///runtime/cordis.js',
    DSH_TESTBED_CORDIS_VERSION: '4.0.5-alpha.2',
    DSH_TESTBED_DSH_COMMIT: '86a402200d95fecef4529d969836f1fe13c6cb0d',
    DSH_TESTBED_RUNTIME_KIND: 'locked-runtime',
    OPENAI_API_KEY: 'sk-ignored',
  })
  assert.deepEqual(Object.keys(captured).sort(), [
    'cordis_entry', 'cordis_version', 'dsh_commit', 'runtime_anchor', 'runtime_kind',
  ])
  assert.equal(JSON.stringify(captured).includes('sk-ignored'), false)
})
