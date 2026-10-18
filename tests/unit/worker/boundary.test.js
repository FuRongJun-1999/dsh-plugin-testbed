/** Worker lifecycle boundary tests (init → ready → busy → idle → teardown). */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createWorkerLifecycle, installSignalHandlers, LIFECYCLE_STATES } from '../../../src/worker/boundary.js'

test('lifecycle transitions and serial operation handles are observable', () => {
  const lifecycle = createWorkerLifecycle()
  assert.equal(lifecycle.state, 'init')
  assert.deepEqual(lifecycle.markReady(), { ok: true })
  assert.equal(lifecycle.markReady().ok, false, 'ready is not re-entrant')
  assert.equal(lifecycle.state, 'ready')

  const begun = lifecycle.beginOp('echo')
  assert.equal(begun.ok, true)
  assert.equal(lifecycle.state, 'busy')
  assert.equal(lifecycle.currentOp, 'echo')
  assert.equal(lifecycle.beginOp('second').reason, 'worker-busy')
  assert.equal(begun.handle.abort('cancel'), true)
  assert.equal(begun.handle.signal.aborted, true)
  assert.equal(begun.handle.abort('again'), false, 'abort is idempotent')
  assert.equal(begun.handle.end('completed'), true)
  assert.equal(begun.handle.end('completed'), false, 'end is idempotent')
  assert.equal(lifecycle.state, 'idle')
  assert.equal(lifecycle.currentOp, null)

  const snapshot = lifecycle.snapshot()
  assert.ok(LIFECYCLE_STATES.includes(snapshot.state))
  assert.ok(snapshot.transitions.length >= 3)
})

test('shutdown aborts the in-flight signal and cleans up exactly once (idempotent)', async () => {
  let cleanupCalls = 0
  let cleanupReason = null
  const lifecycle = createWorkerLifecycle({
    onShutdown: async (reason) => {
      cleanupCalls += 1
      cleanupReason = reason
    },
  })
  lifecycle.markReady()
  const begun = lifecycle.beginOp('probe-capabilities')
  const first = lifecycle.shutdown('SIGTERM')
  const second = lifecycle.shutdown('SIGTERM')
  assert.equal(first, second, 'concurrent shutdown calls share one promise')
  const report = await first
  assert.deepEqual(report, { ok: true, reason: 'SIGTERM', cleanup_error: null })
  assert.equal(cleanupCalls, 1)
  assert.equal(cleanupReason, 'SIGTERM')
  assert.equal(begun.handle.signal.aborted, true)
  assert.equal(lifecycle.state, 'terminated')
  assert.equal(lifecycle.beginOp('later').reason, 'worker-shutting-down')

  const again = await lifecycle.shutdown('again')
  assert.equal(again.ok, true)
  assert.equal(cleanupCalls, 1, 'second shutdown does not re-run cleanup')
})

test('cleanup failures are reported, not swallowed', async () => {
  const lifecycle = createWorkerLifecycle({
    onShutdown: () => { throw new Error('cleanup exploded') },
  })
  lifecycle.markReady()
  const report = await lifecycle.shutdown('failure-path')
  assert.equal(report.ok, false)
  assert.equal(report.cleanup_error, 'cleanup exploded')
  assert.equal(lifecycle.state, 'terminated')
})

test('signal handlers tear down once and exit with the cleanup status', async () => {
  const listeners = new Map()
  const processRef = {
    on(signal, handler) { listeners.set(signal, handler) },
    off(signal) { listeners.delete(signal) },
  }
  const exited = []
  const lifecycle = createWorkerLifecycle()
  lifecycle.markReady()
  const uninstall = installSignalHandlers(lifecycle, {
    processRef,
    exit: (code) => exited.push(code),
  })
  assert.equal(typeof listeners.get('SIGTERM'), 'function')
  assert.equal(typeof listeners.get('SIGINT'), 'function')
  listeners.get('SIGTERM')()
  await new Promise((resolve) => setTimeout(resolve, 0))
  assert.deepEqual(exited, [0])
  assert.equal(lifecycle.state, 'terminated')
  uninstall()
  assert.equal(listeners.size, 0)
})
