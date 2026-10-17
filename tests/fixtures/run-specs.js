/**
 * run-spec/v1 fixture factories for integration closure tests.
 *
 * 纯工厂（无副作用、无秘密、确定性输入）。字段/枚举以 architecture.md +
 * CONTRACT.md 逐字约定为准，不在此另造同义名。
 *
 * 覆盖负向回归来源：
 *  - development.md「必测负向用例」（全表）
 *  - development-plan.md「必须纳入自动化回归的负向场景」（全七类）
 *  - architecture.md §16.1（执行与对账 / 准入与启动证据 / 权威记录与协议 / 入口与发布）
 */

export const RUN_SPEC_VERSION = 'run-spec/v1'

/** criteria：白名单断言 DSL（equals）。`path` 为可选点路径。 */
export function criteriaEquals(expected, path) {
  const c = { assert: 'equals', expected }
  if (path !== undefined) c.path = path
  return c
}

/** probe：进程内 observation 生产者（L0），携带单条 value。 */
export function probeValue(value, overrides = {}) {
  return { observations: [{ value }], ...overrides }
}

/**
 * case spec 工厂。`probe` 缺席 → adapters 归一化为
 * `admission_status=rejected, execution_status=error, invocation_status=not-started`。
 */
export function makeCase({ test_id, node_id, classification = 'required', criteria, probe, needs }) {
  const c = { test_id, node_id, classification }
  if (needs !== undefined) c.needs = needs
  if (criteria !== undefined) c.criteria = criteria
  if (probe !== undefined) c.probe = probe
  return c
}

/** run-spec/v1 工厂。target/digest 仅为无秘密占位，不触碰任何真实凭据。 */
export function makeRunSpec(cases, overrides = {}) {
  return {
    schema_version: RUN_SPEC_VERSION,
    target: { kind: 'plugin', put_digest: 'sha256:' + 'ab'.repeat(32) },
    profile_ref: { id: 'smoke', version: '1.0.0' },
    policy_ref: { id: 'gate-policy', version: '1.0.0' },
    scenario: { cases },
    ...overrides,
  }
}

/** 单个判据匹配的 required 用例（probe value=200；适配器的 started 仍须独立核验）。 */
export function passingRequired(id) {
  return makeCase({
    test_id: id,
    node_id: id,
    classification: 'required',
    criteria: criteriaEquals(200),
    probe: probeValue(200),
  })
}