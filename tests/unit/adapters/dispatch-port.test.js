/**
 * `src/adapters/index.js` 的 DispatchPort 门面（control 设计 §13.1）单元测试。
 *
 * 只验证转发/生命周期契约：不产生 verdict/GateDecision，不把 L1 描述为安全边界。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  ADAPTER_REF,
  IN_PROCESS_ISOLATION_LEVEL,
  INVOCATION_START_KIND,
  ISOLATION_LEVEL,
  makeInProcessPort,
  makeLocalWorkerDispatchPort,
} from '../../../src/adapters/index.js'
import {
  CAPABILITY_REF,
  HOST_ENTRY,
  cleanupDirs,
  makeManifest,
  makeTempDir,
  makeToolRequest,
  toolRefFor,
  unique,
  writeToolArtifact,
} from './_helpers.js'

test('门面重新导出两个本地 port 与见证契约', () => {
  assert.equal(ADAPTER_REF, 'local-worker-json@1.0.0')
  assert.equal(ISOLATION_LEVEL, 'L1-subprocess')
  assert.equal(IN_PROCESS_ISOLATION_LEVEL, 'L0-in-process')
  assert.equal(INVOCATION_START_KIND, 'invocation-start/v1')
  assert.equal(typeof makeInProcessPort, 'function')
  assert.equal(typeof makeLocalWorkerDispatchPort, 'function')
})

test('DispatchPort：startWorker → dispatchToolRequest → reportInvocationStart → cleanup', async (t) => {
  const workspaceRoot = makeTempDir('testbed-port-')
  cleanupDirs(t, [workspaceRoot])
  const artifact = writeToolArtifact(workspaceRoot)
  const manifest = makeManifest({ artifact_digest: artifact.artifactDigest })
  const toolRef = toolRefFor(manifest)
  const port = makeLocalWorkerDispatchPort({
    workerEntry: HOST_ENTRY,
    runId: unique('port'),
    toolBindings: { 't.port': { manifest, artifactPath: artifact.artifactPath, workspaceRoot, toolRef } },
    capabilitySnapshotRefs: { 't.port': CAPABILITY_REF },
  })

  await assert.rejects(
    async () => port.dispatchToolRequest(undefined, makeToolRequest({ testId: 't.port', toolRef })),
    /startWorker/,
  )

  const workerRef = port.startWorker()
  assert.equal(workerRef.adapter_ref, ADAPTER_REF)
  assert.equal(typeof workerRef.run_id, 'string')

  const precheck = port.precheckEnvironment(workerRef)
  assert.equal(precheck.isolation, 'L1-subprocess')
  assert.equal(precheck.trust_scope, 'local-only')
  assert.equal(precheck.market_conclusion, 'none')
  assert.ok(!('verdict' in precheck) && !('gate_decision' in precheck))

  const request = makeToolRequest({ testId: 't.port', toolRef, requestId: 'req-port-1' })
  const outcome = await port.dispatchToolRequest(workerRef, request, new AbortController().signal)
  assert.equal(outcome.execution_status, 'completed')
  assert.equal(outcome.invocation_status, 'started')

  const event = port.reportInvocationStart(workerRef, 't.port', 1)
  assert.ok(event)
  assert.deepEqual(event, outcome.invocation_evidence)
  assert.equal(port.reportInvocationStart(workerRef, 't.port', 2), null)

  const report = await port.cleanup(workerRef)
  assert.equal(report.pid_alive, false)
  assert.equal(report.temp_removed, true)
  assert.equal(port.launchRecord().state, 'reaped')
})
