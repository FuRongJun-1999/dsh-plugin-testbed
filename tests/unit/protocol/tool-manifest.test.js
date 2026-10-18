/**
 * 单元 · protocol/tool-manifest（node:test）。
 * 覆盖 CONTRACT-m5 §2/§4：digest 拒浮动 tag、缺字段/坏 role/坏 runner(shell 字符串)/
 * 路径逃逸(`..`+盘符+file://) 各自 fail、remote $ref 拒绝、合法 manifest→validated、pinTool→pinned。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  assertArtifactDigest,
  validateToolManifest,
  pinTool,
  MAX_MANIFEST_LIMITS,
  MAX_RETRY_ATTEMPTS,
} from '../../../src/protocol/tool-manifest.js'

const DIGEST = 'sha256:' + 'a'.repeat(64)

/** 合法 manifest 基线（§8.4.1 示例同形）。 */
function makeManifest(overrides = {}) {
  return {
    schema_version: 'test-tool-manifest/v1',
    tool_id: 'example.api-contract',
    tool_version: '1.0.0',
    artifact_digest: DIGEST,
    role: 'probe',
    tags: ['contract'],
    runner: { adapter: 'local-worker-json', entrypoint: 'run' },
    input_schema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object',
      properties: { fixture_ref: { type: 'string' } },
      required: ['fixture_ref'],
      additionalProperties: false,
    },
    observation_schema: {
      type: 'object',
      properties: { status_code: { type: 'integer' } },
      required: ['status_code'],
      additionalProperties: false,
    },
    requires: ['target:api'],
    permissions: { filesystem: ['workspace:read'], network: [], subprocess: [], devices: [], secrets: [] },
    limits: {
      timeout_ms: 30000, cpu_ms: 15000, memory_mb: 256, processes: 1,
      temp_bytes: 8388608, output_bytes: 1048576, attachment_bytes: 1048576, concurrency: 1,
    },
    determinism: 'deterministic',
    retry: { safe: false, max_attempts: 1 },
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// assertArtifactDigest
// ---------------------------------------------------------------------------

test('digest: 合法 sha256:<64hex> 通过', () => {
  assert.equal(assertArtifactDigest(DIGEST).ok, true)
})

test('digest: 拒绝浮动 tag（latest / main / semver）', () => {
  for (const dg of ['latest', 'main', 'v1.0.0', '1.0.0', 'sha256:abc', `sha256:${'g'.repeat(64)}`]) {
    const r = assertArtifactDigest(dg)
    assert.equal(r.ok, false, `should reject: ${dg}`)
    assert.ok(r.errors.some((e) => e.startsWith('artifact-digest-invalid')))
  }
})

test('digest: 拒绝非字符串', () => {
  assert.equal(assertArtifactDigest(null).ok, false)
  assert.equal(assertArtifactDigest(123).ok, false)
})

// ---------------------------------------------------------------------------
// validateToolManifest：合法 / 缺字段 / 坏字段
// ---------------------------------------------------------------------------

test('manifest: 合法 → validated', () => {
  const r = validateToolManifest(makeManifest())
  assert.equal(r.ok, true, JSON.stringify(r.errors))
  assert.equal(r.admission_stage, 'validated')
  assert.deepEqual(r.warnings, [])
})

test('manifest: 非对象 → draft（manifest-not-object）', () => {
  const r = validateToolManifest(null)
  assert.equal(r.ok, false)
  assert.equal(r.admission_stage, 'draft')
  assert.ok(r.errors.includes('manifest-not-object'))
})

test('manifest: 未知顶层字段 → warning 不 fail，仍 validated', () => {
  const r = validateToolManifest(makeManifest({ custom_extension: 'x' }))
  assert.equal(r.admission_stage, 'validated')
  assert.ok(r.warnings.includes('unknown-top-level-field:custom_extension'))
})

test('manifest: schema_version 错 → draft', () => {
  const r = validateToolManifest(makeManifest({ schema_version: 'test-tool-manifest/v2' }))
  assert.equal(r.admission_stage, 'draft')
  assert.ok(r.errors.includes('schema-version-invalid'))
})

test('manifest: 缺 artifact_digest / 浮动 tag → draft', () => {
  assert.equal(validateToolManifest(makeManifest({ artifact_digest: undefined })).admission_stage, 'draft')
  assert.equal(validateToolManifest(makeManifest({ artifact_digest: 'latest' })).admission_stage, 'draft')
})

test('manifest: 缺 tool_id / tool_version → draft', () => {
  assert.equal(validateToolManifest(makeManifest({ tool_id: '' })).admission_stage, 'draft')
  assert.equal(validateToolManifest(makeManifest({ tool_version: '' })).admission_stage, 'draft')
})

test('manifest: 坏 role → draft', () => {
  const r = validateToolManifest(makeManifest({ role: 'assertion' }))
  assert.equal(r.admission_stage, 'draft')
  assert.ok(r.errors.includes('role-invalid'))
})

// ---------------------------------------------------------------------------
// runner：shell 字符串拒绝
// ---------------------------------------------------------------------------

test('runner: 含 command/args/shell 字段 → 拒绝', () => {
  for (const field of ['command', 'args', 'shell']) {
    const r = validateToolManifest(makeManifest({ runner: { adapter: 'local-worker-json', entrypoint: 'run', [field]: 'rm -rf /' } }))
    assert.equal(r.admission_stage, 'draft', `runner.${field} must be forbidden`)
    assert.ok(r.errors.includes(`runner-${field}-forbidden`))
  }
})

test('runner: entrypoint 含 shell 元字符 → 拒绝', () => {
  for (const evil of ['run; rm -rf /', 'run && x', 'run|sh', 'run > out', 'run $X', '`x`', 'run x']) {
    const r = validateToolManifest(makeManifest({ runner: { adapter: 'local-worker-json', entrypoint: evil } }))
    assert.equal(r.admission_stage, 'draft', `entrypoint should reject: ${JSON.stringify(evil)}`)
    assert.ok(r.errors.some((e) => e.startsWith('runner-entrypoint-')))
  }
})

test('runner: adapter 含空白/shell 元字符 → 拒绝', () => {
  const r = validateToolManifest(makeManifest({ runner: { adapter: 'adapter; id', entrypoint: 'run' } }))
  assert.equal(r.admission_stage, 'draft')
  assert.ok(r.errors.some((e) => e.startsWith('runner-adapter-')))
})

test('runner: 非对象 / 缺字段 → 拒绝', () => {
  assert.equal(validateToolManifest(makeManifest({ runner: 'run.sh' })).admission_stage, 'draft')
  assert.equal(validateToolManifest(makeManifest({ runner: { adapter: 'local-worker-json' } })).admission_stage, 'draft')
})

// ---------------------------------------------------------------------------
// permissions：路径逃逸
// ---------------------------------------------------------------------------

test('permissions: `..` 段 → 拒绝', () => {
  const r = validateToolManifest(makeManifest({ permissions: { filesystem: ['../secret'], network: [] } }))
  assert.equal(r.admission_stage, 'draft')
  assert.ok(r.errors.some((e) => e.startsWith('permissions-filesystem-escape:')))
})

test('permissions: 盘符绝对路径 → 拒绝', () => {
  for (const p of ['C:\\secret', 'C:/secret', 'D:\\x']) {
    const r = validateToolManifest(makeManifest({ permissions: { filesystem: [p], network: [] } }))
    assert.equal(r.admission_stage, 'draft', `should reject drive path: ${p}`)
  }
})

test('permissions: file:// → 拒绝', () => {
  const r = validateToolManifest(makeManifest({ permissions: { filesystem: ['file:///etc/passwd'], network: [] } }))
  assert.equal(r.admission_stage, 'draft')
})

test('permissions: POSIX 绝对路径 / UNC → 拒绝', () => {
  for (const p of ['/etc/passwd', '\\\\server\\share', '//server/share']) {
    const r = validateToolManifest(makeManifest({ permissions: { filesystem: [p], network: [] } }))
    assert.equal(r.admission_stage, 'draft', `should reject absolute: ${p}`)
  }
})

test('permissions: workspace:read 与相对路径 → 允许', () => {
  const r = validateToolManifest(makeManifest({
    permissions: { filesystem: ['workspace:read', 'logs/out.txt'], network: ['127.0.0.1:4001'], subprocess: [] },
  }))
  assert.equal(r.admission_stage, 'validated', JSON.stringify(r.errors))
})

test('permissions: 未知键 → 拒绝（fail）', () => {
  const r = validateToolManifest(makeManifest({ permissions: { filesystem: [], cap_sys_admin: ['all'] } }))
  assert.equal(r.admission_stage, 'draft')
  assert.ok(r.errors.includes('permissions-unknown-key:cap_sys_admin'))
})

test('permissions: 值非 string[] → 拒绝', () => {
  assert.equal(validateToolManifest(makeManifest({ permissions: { filesystem: 'workspace:read' } })).admission_stage, 'draft')
  assert.equal(validateToolManifest(makeManifest({ permissions: { filesystem: [1] } })).admission_stage, 'draft')
})

// ---------------------------------------------------------------------------
// limits / determinism / retry / schema
// ---------------------------------------------------------------------------

test('limits: 非正数 / processes / concurrency < 1 → 拒绝', () => {
  assert.equal(validateToolManifest(makeManifest({ limits: { ...makeManifest().limits, timeout_ms: 0 } })).admission_stage, 'draft')
  assert.equal(validateToolManifest(makeManifest({ limits: { ...makeManifest().limits, processes: 0 } })).admission_stage, 'draft')
  assert.equal(validateToolManifest(makeManifest({ limits: { ...makeManifest().limits, concurrency: 0 } })).admission_stage, 'draft')
  assert.equal(validateToolManifest(makeManifest({ limits: undefined })).admission_stage, 'draft')
})

test('limits: every declared field accepts its fixed ceiling and rejects one above', () => {
  for (const [field, maximum] of Object.entries(MAX_MANIFEST_LIMITS)) {
    const atMaximum = validateToolManifest(makeManifest({ limits: { ...makeManifest().limits, [field]: maximum } }))
    assert.equal(atMaximum.ok, true, `${field} at maximum`)
    const overMaximum = validateToolManifest(makeManifest({ limits: { ...makeManifest().limits, [field]: maximum + 1 } }))
    assert.equal(overMaximum.ok, false, `${field} over maximum`)
    assert.ok(overMaximum.errors.includes(`limits-${field}-exceeds-limit`), field)
  }
})

test('limits: reject fractions and unsafe integer magnitudes', () => {
  for (const [field] of Object.entries(MAX_MANIFEST_LIMITS)) {
    for (const value of [1.5, Number.MAX_SAFE_INTEGER + 1]) {
      const result = validateToolManifest(makeManifest({ limits: { ...makeManifest().limits, [field]: value } }))
      assert.equal(result.ok, false, `${field}=${value}`)
      assert.ok(result.errors.includes(`limits-${field}-invalid`), field)
    }
  }
})

test('determinism: 坏值 → 拒绝', () => {
  const r = validateToolManifest(makeManifest({ determinism: 'flaky' }))
  assert.equal(r.admission_stage, 'draft')
  assert.ok(r.errors.includes('determinism-invalid'))
})

test('retry: safe 非布尔 / max_attempts 非正整数或超过固定上限 → 拒绝', () => {
  assert.equal(validateToolManifest(makeManifest({ retry: { safe: 'yes', max_attempts: 1 } })).admission_stage, 'draft')
  assert.equal(validateToolManifest(makeManifest({ retry: { safe: false, max_attempts: 0 } })).admission_stage, 'draft')
  assert.equal(validateToolManifest(makeManifest({ retry: undefined })).admission_stage, 'draft')
  assert.equal(validateToolManifest(makeManifest({ retry: { safe: true, max_attempts: MAX_RETRY_ATTEMPTS } })).ok, true)
  const over = validateToolManifest(makeManifest({ retry: { safe: true, max_attempts: MAX_RETRY_ATTEMPTS + 1 } }))
  assert.equal(over.ok, false)
  assert.ok(over.errors.includes('retry-max-attempts-exceeds-limit'))
  const unsafe = validateToolManifest(makeManifest({ retry: { safe: true, max_attempts: Number.MAX_SAFE_INTEGER + 1 } }))
  assert.equal(unsafe.ok, false)
  assert.ok(unsafe.errors.includes('retry-max-attempts-invalid'))
})

test('schema: input_schema 含 remote $ref → 拒绝', () => {
  const r = validateToolManifest(makeManifest({
    input_schema: { type: 'object', properties: { a: { $ref: 'http://evil/x.json' } } },
  }))
  assert.equal(r.admission_stage, 'draft')
  assert.ok(r.errors.some((e) => e.startsWith('input_schema-remote-$ref:')))
})

// ---------------------------------------------------------------------------
// pinTool
// ---------------------------------------------------------------------------

test('pinTool: 合法 + 匹配摘要 → pinned', () => {
  const m = makeManifest()
  const r = pinTool(m, DIGEST, { fingerprint: 'fp' })
  assert.equal(r.ok, true)
  assert.equal(r.admission_stage, 'pinned')
  assert.deepEqual(r.tool_ref, { tool_id: 'example.api-contract', version: '1.0.0', artifact_digest: DIGEST })
  assert.equal(r.adapter, 'local-worker-json')
  assert.equal(r.entrypoint, 'run')
})

test('pinTool: 非法 manifest → draft', () => {
  const r = pinTool(makeManifest({ role: 'bad' }), DIGEST, null)
  assert.equal(r.admission_stage, 'draft')
})

test('pinTool: 摘要不匹配 → draft（pin-digest-mismatch）', () => {
  const other = 'sha256:' + 'b'.repeat(64)
  const r = pinTool(makeManifest(), other, null)
  assert.equal(r.admission_stage, 'draft')
  assert.ok(r.errors.includes('pin-digest-mismatch'))
})

test('pinTool: env 缺省 → null', () => {
  const r = pinTool(makeManifest(), DIGEST)
  assert.equal(r.admission_stage, 'pinned')
  assert.equal(r.env, null)
})
// ---------------------------------------------------------------------------
// 严格字段/枚举补充（tool_version 语义版本、runner 闭集、
// evidence/compatibility 可选但必须是对象；tags 类型受检）
// ---------------------------------------------------------------------------

test('manifest: tags 缺失仅告警（M5 兼容），出现时必须是非空字符串数组', () => {
  const missing = validateToolManifest(makeManifest({ tags: undefined }))
  assert.equal(missing.admission_stage, 'validated')
  assert.ok(missing.warnings.includes('missing-required-field:tags'))

  assert.equal(validateToolManifest(makeManifest({ tags: 'contract' })).admission_stage, 'draft')
  assert.equal(validateToolManifest(makeManifest({ tags: [''] })).admission_stage, 'draft')
  assert.equal(validateToolManifest(makeManifest({ tags: [1] })).admission_stage, 'draft')
  assert.equal(validateToolManifest(makeManifest({ tags: ['contract', 'smoke'] })).ok, true)
})

test('manifest: tool_version 必须是语义版本（拒绝浮动/非法版本）', () => {
  for (const value of ['1.0', 'latest', 'v1.0.0', 'main', '1.0.0.0']) {
    const result = validateToolManifest(makeManifest({ tool_version: value }))
    assert.equal(result.ok, false, value)
    assert.ok(result.errors.includes('tool-version-invalid'), value)
  }
  for (const value of ['0.0.0', '1.2.3', '1.0.0-beta.1', '1.0.0+build.5']) {
    assert.equal(validateToolManifest(makeManifest({ tool_version: value })).ok, true, value)
  }
})

test('manifest: runner 是闭集，未知字段拒绝', () => {
  const result = validateToolManifest(makeManifest({
    runner: { adapter: 'local-worker-json', entrypoint: 'run', extra: 'x' },
  }))
  assert.equal(result.ok, false)
  assert.ok(result.errors.includes('runner-unknown-field:extra'))
})

test('manifest: evidence/compatibility 可选，但出现时必须是对象', () => {
  assert.equal(validateToolManifest(makeManifest({ evidence: { kind: 'log' }, compatibility: { node: '>=20' } })).ok, true)
  assert.equal(validateToolManifest(makeManifest({ evidence: 'log' })).ok, false)
  assert.equal(validateToolManifest(makeManifest({ compatibility: ['node'] })).ok, false)
})

test('manifest: 声明式 schema 与可执行校验一致', async () => {
  const { validateValue } = await import('../../../src/protocol/jsonschema.js')
  const { TEST_TOOL_MANIFEST_V1_SCHEMA } = await import('../../../src/protocol/schemas.js')
  const valid = makeManifest()
  assert.equal(validateValue(valid, TEST_TOOL_MANIFEST_V1_SCHEMA).ok, true)
  assert.equal(validateToolManifest(valid).ok, true)

  const noTags = makeManifest()
  delete noTags.tags
  assert.equal(validateValue(noTags, TEST_TOOL_MANIFEST_V1_SCHEMA).ok, true)
  assert.equal(validateToolManifest(noTags).ok, true)
  assert.ok(validateToolManifest(noTags).warnings.includes('missing-required-field:tags'))

  const badRole = makeManifest({ role: 'assertion' })
  assert.equal(validateValue(badRole, TEST_TOOL_MANIFEST_V1_SCHEMA).ok, false)
  assert.equal(validateToolManifest(badRole).ok, false)

  const badVersion = makeManifest({ tool_version: 'v1' })
  assert.equal(validateValue(badVersion, TEST_TOOL_MANIFEST_V1_SCHEMA).ok, false)
  assert.equal(validateToolManifest(badVersion).ok, false)

  // Namespaced extension candidates stay warnings in the executable validator;
  // the declarative schema does not reject them (§8.4.1 extension rule).
  const extension = makeManifest({ 'example.com/feature': true })
  assert.equal(validateValue(extension, TEST_TOOL_MANIFEST_V1_SCHEMA).ok, true)
  assert.equal(validateToolManifest(extension).ok, true)
  assert.ok(validateToolManifest(extension).warnings.includes('unknown-top-level-field:example.com/feature'))
})
