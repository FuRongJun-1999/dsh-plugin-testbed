/**
 * launch_record 权限/上限留痕（node:test）。
 *
 * 验证 architecture §8.4.1/§8.4.3 与 adapters 设计 §4：
 * - `granted = policy_allowed ∩ tool_requested`，L1 无法强制的项记 `unenforced` + basis；
 * - 权限声明不是权限证明，结论固定 `local-only` / `market_conclusion=none`，不产生市场结论；
 * - 上限 `granted = min(adapter cap, frozen manifest 声明)`，无 OS 强制力的项如实 unenforced。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  ADAPTER_REF,
  ENFORCED_LIMITS,
  UNENFORCED_RESOURCES,
  makeSubprocessAdapter,
} from '../../../src/adapters/subprocess.js'
import {
  HOST_ENTRY,
  LEGACY_FIXTURE,
  cleanupDirs,
  makePinnedToolCase,
  unique,
} from './_helpers.js'

function grantOf(record, permission) {
  return record.grants.find((entry) => entry.permission === permission)
}

function limitOf(record, limit) {
  return record.limits_enforcement.find((entry) => entry.limit === limit)
}

const REQUESTED_PERMISSIONS = Object.freeze({
  filesystem: ['workspace:read'],
  network: ['127.0.0.1:4001'],
  subprocess: [],
  devices: [],
  secrets: ['api-key:example'],
})

test('权限留痕：requested ∩ policy ∩ L1 可强制子集 + basis + unenforced', (t) => {
  const pinned = makePinnedToolCase({
    manifestOverrides: { permissions: REQUESTED_PERMISSIONS },
    adapterOptions: {
      policyAllowed: { filesystem: ['workspace:read'], network: [], subprocess: [], devices: [], secrets: [] },
    },
  })
  cleanupDirs(t, [pinned.workspaceRoot])
  const record = pinned.adapter.launchRecord

  const filesystem = grantOf(record, 'filesystem')
  assert.deepEqual(filesystem.requested, ['workspace:read'])
  assert.deepEqual(filesystem.policy_allowed, ['workspace:read'])
  assert.deepEqual(filesystem.granted, ['workspace:read'])
  assert.equal(filesystem.enforced, false)
  assert.equal(filesystem.marking, 'unenforced')
  assert.match(filesystem.basis, /L1/)

  const network = grantOf(record, 'network')
  assert.deepEqual(network.requested, ['127.0.0.1:4001'])
  assert.deepEqual(network.granted, [])
  assert.equal(network.enforced, false)
  assert.match(network.basis, /network/)

  // secrets 请求被 policy 拒绝 → 无凭据注入是可真实兑现的 enforced 事实。
  const secrets = grantOf(record, 'secrets')
  assert.deepEqual(secrets.requested, ['api-key:example'])
  assert.deepEqual(secrets.granted, [])
  assert.equal(secrets.enforced, true)
  assert.equal(secrets.marking, 'enforced')
  assert.match(secrets.basis, /no credentials/i)

  assert.deepEqual(record.policy_allowed, {
    devices: [], filesystem: ['workspace:read'], network: [], secrets: [], subprocess: [],
  })
  assert.deepEqual([...record.enforceable], ENFORCED_LIMITS)
  assert.deepEqual([...record.unenforced], UNENFORCED_RESOURCES)
})

test('权限留痕：policy 授予 secret 时无隔离可兑现 → unenforced', (t) => {
  const pinned = makePinnedToolCase({
    manifestOverrides: { permissions: REQUESTED_PERMISSIONS },
    adapterOptions: {
      policyAllowed: { filesystem: [], network: [], subprocess: [], devices: [], secrets: ['api-key:example'] },
    },
  })
  cleanupDirs(t, [pinned.workspaceRoot])
  const secrets = grantOf(pinned.adapter.launchRecord, 'secrets')
  assert.deepEqual(secrets.granted, ['api-key:example'])
  assert.equal(secrets.enforced, false)
  assert.equal(secrets.marking, 'unenforced')
  assert.match(secrets.basis, /ambient credentials/)
})

test('默认 policy 不允许任何权限：granted 全为空，requested 仍如实保留', (t) => {
  const pinned = makePinnedToolCase({ manifestOverrides: { permissions: REQUESTED_PERMISSIONS } })
  cleanupDirs(t, [pinned.workspaceRoot])
  const record = pinned.adapter.launchRecord
  for (const grant of record.grants) {
    assert.deepEqual(grant.policy_allowed, [], `${grant.permission} policy 应为空`)
    assert.deepEqual(grant.granted, [], `${grant.permission} granted 应为空`)
  }
  assert.deepEqual(grantOf(record, 'filesystem').requested, ['workspace:read'])
  assert.deepEqual(grantOf(record, 'network').requested, ['127.0.0.1:4001'])
  // 非 secrets 权限在 L1 下永远不能声称 enforced；secrets 仅在无授予时由 launcher 兑现。
  for (const permission of ['filesystem', 'network', 'subprocess', 'devices']) {
    assert.equal(grantOf(record, permission).marking, 'unenforced', `${permission} 在 L1 下不得标记 enforced`)
  }
  assert.equal(grantOf(record, 'secrets').enforced, true)
})

test('上限留痕：granted = min(adapter, manifest)；OS 不可强制项 unenforced', (t) => {
  const pinned = makePinnedToolCase({
    adapterOptions: {
      maxFrameBytes: 1024,
      maxOutputBytes: 2048,
      maxAttachmentBytes: 4096,
      timeoutMs: 4000,
      maxContextBytes: 3072,
    },
  })
  cleanupDirs(t, [pinned.workspaceRoot])
  const record = pinned.adapter.launchRecord

  assert.equal(limitOf(record, 'max_frame_bytes').granted, 1024)
  assert.equal(limitOf(record, 'max_frame_bytes').enforced, true)

  const output = limitOf(record, 'max_output_bytes')
  assert.equal(output.requested, 1048576)
  assert.equal(output.granted, 2048)
  assert.equal(output.enforced, true)

  const attachment = limitOf(record, 'attachment_bytes')
  assert.equal(attachment.granted, 4096)
  assert.equal(attachment.enforced, true)

  const timeout = limitOf(record, 'timeout_ms')
  assert.equal(timeout.requested, 10000)
  assert.equal(timeout.granted, 4000)
  assert.equal(timeout.enforced, true)

  assert.equal(limitOf(record, 'concurrency').granted, 1)
  assert.equal(limitOf(record, 'concurrency').enforced, true)
  assert.equal(limitOf(record, 'max_context_bytes').granted, 3072)
  assert.equal(limitOf(record, 'max_context_bytes').enforced, true)

  for (const limit of ['processes', 'cpu_ms', 'memory_mb', 'temp_bytes']) {
    const entry = limitOf(record, limit)
    assert.equal(entry.enforced, false, `${limit} 在 L1 下不能声称 OS 强制`)
    assert.match(entry.mechanism, /L1|launcher|worker/)
  }
  for (const entry of record.limits_enforcement) {
    assert.ok('limit' in entry && 'requested' in entry && 'granted' in entry && 'enforced' in entry && 'mechanism' in entry)
  }
})

test('结论纪律：local-only / market_conclusion=none / 无沙箱措辞 / 记录冻结', (t) => {
  const pinned = makePinnedToolCase()
  cleanupDirs(t, [pinned.workspaceRoot])
  const record = pinned.adapter.launchRecord

  assert.equal(record.adapter_ref, ADAPTER_REF)
  assert.equal(record.trust_scope, 'local-only')
  assert.equal(record.market_conclusion, 'none')
  assert.equal(record.isolation, 'L1-subprocess')
  assert.equal(record.isolation_level, 'L1')
  assert.ok(record.limitations.includes('l1-fault-isolation-is-not-a-security-boundary'))
  assert.ok(!('market_eligible' in record), 'adapter 不得下发 market_eligible')

  const serialized = JSON.stringify(record).toLowerCase()
  assert.ok(!serialized.includes('sandbox'), 'L1 不得表述为 sandbox')
  assert.ok(!serialized.includes('secure isolation'), 'L1 不得表述为安全隔离')
  assert.ok(!serialized.includes('market eligible'), 'L1 不得产生市场结论')

  assert.ok(Object.isFrozen(record))
  assert.ok(Object.isFrozen(record.grants))
  assert.ok(Object.isFrozen(record.grants[0]))
  assert.ok(Object.isFrozen(record.limits_enforcement))
  assert.ok(Object.isFrozen(record.limits_enforcement[0]))
})

test('policyAllowed 非法输入 fail-closed', () => {
  assert.throws(
    () => makeSubprocessAdapter({ workerEntry: HOST_ENTRY, policyAllowed: { filesystem: 'workspace:read' } }),
    /must be an array/,
  )
  assert.throws(
    () => makeSubprocessAdapter({ workerEntry: HOST_ENTRY, policyAllowed: { unknown: [] } }),
    /unknown policyAllowed permission/,
  )
  assert.throws(
    () => makeSubprocessAdapter({ workerEntry: HOST_ENTRY, policyAllowed: { secrets: [1] } }),
    /non-empty strings/,
  )
  assert.throws(
    () => makeSubprocessAdapter({ workerEntry: HOST_ENTRY, policyAllowed: [] }),
    /must be a record/,
  )
})

test('无 pinned tool：grants 仍逐个权限留痕（requested 为空）', () => {
  const adapter = makeSubprocessAdapter({ workerEntry: LEGACY_FIXTURE, runId: unique('no-tools') })
  const record = adapter.launchRecord
  assert.equal(record.grants.length, 5)
  for (const grant of record.grants) {
    assert.deepEqual(grant.requested, [])
    assert.deepEqual(grant.granted, [])
  }
  assert.equal(record.process_mode, 'run-worker')
})
