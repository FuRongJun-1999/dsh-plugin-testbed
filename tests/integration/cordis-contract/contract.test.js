/**
 * `cordis-contract-suite/v1` executed against the exact locked Cordis entry.
 *
 * The suite is intentionally a single top-level test: it materializes one
 * anchor, runs every case as an awaited subtest-like record, writes the full
 * `cordis-contract-results/v1` evidence even when a case fails, and only then
 * fails the test. A missing or mismatched runtime throws a blocked error before
 * any case runs — no fixture fallback exists.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { pathToFileURL } from 'node:url'
import {
  ANCHOR_PATH,
  buildApiCatalog,
  buildRuntimeAnchor,
  EVIDENCE_DIR,
  errorDetail,
  environmentSummary,
  loadRealRuntime,
  materializeSuite,
  readInstalledRuntime,
  readSuiteDefinition,
  resultsDocument,
  sha256Value,
  writeEvidence,
  writeRuntimeAnchor,
} from './_runtime.js'
import { runtimeAnchorV2Digest } from '../../../src/worker/runtime.js'

const STATE = Object.freeze({ PENDING: 0, LOADING: 1, ACTIVE: 2, FAILED: 3, DISPOSED: 4, UNLOADING: 5 })

async function waitFor(predicate, { timeoutMs = 2000, label = 'condition' } = {}) {
  const started = Date.now()
  while (Date.now() - started < timeoutMs) {
    if (await predicate()) return true
    await sleep(5)
  }
  throw new Error(`timed out waiting for ${label}`)
}

function hasTransition(statuses, from, to) {
  return statuses.some(([oldState, newState]) => oldState === from && newState === to)
}

async function disposeQuietly(...fibers) {
  for (const fiber of fibers) {
    try {
      await fiber?.dispose?.()
    } catch {
      // Teardown of an already-disposed/odd fiber must not mask the case result.
    }
  }
}

/** Case 0: real module identity, and the workspace stub cannot impersonate it. */
async function caseRuntimeModuleIdentity({ cordis }) {
  const requiredExports = ['Context', 'Fiber', 'Service', 'EventsService', 'RegistryService', 'CordisError', 'ValidationError']
  const missing = requiredExports.filter((name) => !(name in cordis))
  assert.deepEqual(missing, [], `real Cordis exports missing: ${missing.join(', ')}`)
  const root = new cordis.Context()
  assert.equal(cordis.Context.is(root), true)
  assert.ok(root.registry instanceof cordis.RegistryService)
  assert.ok(root.events instanceof cordis.EventsService)
  assert.equal(typeof root.plugin, 'function')
  assert.equal(typeof root.get, 'function')

  // Counterexample only: the workspace fixture must NOT satisfy the identity
  // surface. Its result never enters the suite as evidence; this assertion
  // proves substitution is detected rather than silently accepted.
  const stub = await import(new URL('../../fixtures/fake-cordis-stub.mjs', import.meta.url).href)
  const stubMissing = requiredExports.filter((name) => !(name in stub))
  assert.deepEqual(stubMissing.sort(), ['CordisError', 'EventsService', 'RegistryService', 'Service', 'ValidationError'])
  assert.equal(typeof stub.Context.is, 'undefined')
  return {
    real_exports: requiredExports,
    real_context_identity: true,
    stub_exports: Object.keys(stub).sort(),
    stub_missing_exports: stubMissing,
    fixture_substitution_rejected: true,
  }
}

/** Case 1: event bus dispatch modes and fiber-owned listener cleanup. */
async function caseContextEvents({ cordis }) {
  const { Context } = cordis
  const root = new Context()
  const emitted = []
  const order = []
  const owner = root.plugin({
    name: 'contract/events-owner',
    apply(ctx) {
      ctx.on('contract/event', (value) => { order.push(['a', value]); return null }, true)
      ctx.on('contract/event', (value) => { order.push(['b', value]); return 'b-bail' })
      ctx.on('contract/event', async (value) => { order.push(['c', value]); return 'c-bail' })
      ctx.on('contract/event', (value) => { emitted.push(value) })
    },
  })
  const waterfallOwner = root.plugin({
    name: 'contract/waterfall-owner',
    apply(ctx) {
      ctx.on('contract/waterfall', (value, next) => { order.push(['outer', value]); return next() + 1 })
      ctx.on('contract/waterfall', (value, next) => { order.push(['inner', value]); return next() + 2 })
    },
  })
  try {
    await owner
    await waterfallOwner
    root.emit('contract/event', 1)
    assert.deepEqual(emitted, [1])
    assert.deepEqual(order.filter(([tag]) => tag !== 'outer' && tag !== 'inner'), [['a', 1], ['b', 1], ['c', 1]])
    order.length = 0
    assert.equal(root.bail('contract/event', 2), 'b-bail')
    assert.equal(await root.serial('contract/event', 3), 'b-bail')
    await root.parallel('contract/event', 4)
    assert.equal(root.waterfall('contract/waterfall', 10, () => 0), 3)
    assert.deepEqual(order.filter(([tag]) => tag === 'outer' || tag === 'inner'), [['outer', 10], ['inner', 10]])
    await waterfallOwner.dispose()
    await owner.dispose()
    const before = emitted.length
    root.emit('contract/event', 99)
    assert.equal(emitted.length, before, 'disposed owner must not leak listeners')
    return {
      emit_values: before,
      bail: 'b-bail',
      serial: 'b-bail',
      parallel_awaited: true,
      waterfall_result: 3,
      listener_cleanup: 'pass',
    }
  } finally {
    await disposeQuietly(owner, waterfallOwner)
  }
}

/** Case 2: context/registry/service basics. */
async function caseContextServiceRegistry({ cordis }) {
  const { Context } = cordis
  const root = new Context()
  const alpha = function contractAlpha() {}
  const beta = { name: 'contract-beta', apply() {} }
  const alphaFiber = root.plugin(alpha)
  const betaFiber = root.plugin(beta)
  try {
    await alphaFiber
    await betaFiber
    assert.equal(alphaFiber.state, STATE.ACTIVE)
    assert.equal(betaFiber.state, STATE.ACTIVE)
    assert.equal(root.registry.has(alpha), true)
    assert.equal(root.registry.get(alpha)?.fibers.length, 1)
    assert.equal(root.registry.has(beta), true)
    assert.equal([...root.registry.keys()].length, 2)
    assert.equal([...root.registry.entries()].length, 2)
    assert.equal(root.registry.size, 2)
    const removed = root.registry.delete(alpha)
    assert.ok(removed)
    await waitFor(() => alphaFiber.state === STATE.DISPOSED, { label: 'registry.delete disposal' })
    assert.equal(root.registry.has(alpha), false)
    assert.equal(root.registry.size, 1)
    const registrySizeAfterDelete = root.registry.size
    await disposeQuietly(betaFiber)

    const duplicateRoot = new Context()
    let duplicateMessage = null
    const duplicateFiber = duplicateRoot.plugin({
      name: 'contract/duplicate',
      apply(ctx) {
        ctx.provide('contractDup', 1)
        try {
          ctx.provide('contractDup', 2)
        } catch (error) {
          duplicateMessage = error.message
        }
      },
    })
    await duplicateFiber
    assert.match(duplicateMessage, /has been registered/i)
    await disposeQuietly(duplicateFiber)
    return {
      active_plugins: 2,
      registry_size_after_delete: registrySizeAfterDelete,
      duplicate_provide_rejected: true,
      service_value: root.get('contractNone') === undefined ? 'undefined-as-expected' : 'unexpected',
    }
  } finally {
    await disposeQuietly(alphaFiber, betaFiber)
  }
}

/** Case 3: service isolation scopes and inject-driven activation. */
async function caseServiceIsolation({ cordis }) {
  const { Context } = cordis
  const root = new Context()
  const isoA = root.isolate('contractIso')
  const isoB = root.isolate('contractIso')
  const rootProvider = root.plugin((ctx) => { ctx.provide('contractIso', 'root-value') })
  const aProvider = isoA.plugin((ctx) => { ctx.provide('contractIso', 'a-value') })
  const bProvider = isoB.plugin((ctx) => { ctx.provide('contractIso', 'b-value') })
  const consumerLog = []
  let consumer
  try {
    await Promise.all([rootProvider, aProvider, bProvider])
    assert.equal(root.get('contractIso'), 'root-value')
    assert.equal(isoA.get('contractIso'), 'a-value')
    assert.equal(isoB.get('contractIso'), 'b-value')
    consumer = root.plugin({
      name: 'contract/isolation-consumer',
      inject: ['contractIso'],
      apply(ctx) {
        consumerLog.push('active')
        ctx.effect(() => () => consumerLog.push('cleanup'))
      },
    })
    await consumer
    await waitFor(() => consumer.state === STATE.ACTIVE, { label: 'consumer active' })
    await rootProvider.dispose()
    await waitFor(() => consumer.state === STATE.PENDING, { label: 'consumer parked' })
    assert.deepEqual(consumerLog, ['active', 'cleanup'])
    assert.equal(root.get('contractIso'), undefined)

    const rootProviderAgain = root.plugin((ctx) => { ctx.provide('contractIso', 'root-again') })
    try {
      await rootProviderAgain
      await waitFor(() => consumer.state === STATE.ACTIVE, { label: 'consumer reactivated' })
      assert.deepEqual(consumerLog, ['active', 'cleanup', 'active'])
      return { scopes: ['root-value', 'a-value', 'b-value'], parked_state: STATE.PENDING, reactivated_state: STATE.ACTIVE }
    } finally {
      await disposeQuietly(rootProviderAgain)
    }
  } finally {
    await disposeQuietly(consumer, rootProvider, aProvider, bProvider)
  }
}

/** Case 4: PENDING -> LOADING -> ACTIVE -> UNLOADING -> DISPOSED, and no restart after DISPOSED. */
async function caseFiberLifecycle({ cordis }) {
  const { Context } = cordis
  const root = new Context()
  const statuses = []
  root.on('internal/status', (fiber, oldState) => statuses.push([oldState, fiber.state]))
  let applied = 0
  const fiber = root.plugin({
    name: 'contract/lifecycle',
    inject: ['contractLifecycleSvc'],
    apply() { applied += 1 },
  })
  let provider
  try {
    await sleep(20)
    assert.equal(fiber.state, STATE.PENDING, 'fiber with an unmet inject must stay PENDING')
    provider = root.plugin((ctx) => { ctx.provide('contractLifecycleSvc', { ok: true }) })
    await provider
    await waitFor(() => fiber.state === STATE.ACTIVE, { label: 'lifecycle ACTIVE' })
    assert.equal(applied, 1)
    assert.ok(hasTransition(statuses, STATE.PENDING, STATE.LOADING))
    assert.ok(hasTransition(statuses, STATE.LOADING, STATE.ACTIVE))

    await fiber.dispose()
    assert.equal(fiber.state, STATE.DISPOSED)
    assert.equal(fiber.uid, null)
    assert.ok(hasTransition(statuses, STATE.ACTIVE, STATE.UNLOADING))
    assert.ok(hasTransition(statuses, STATE.UNLOADING, STATE.DISPOSED))

    await assert.rejects(fiber.restart(), (error) => error?.code === 'INACTIVE_EFFECT')
    assert.throws(() => fiber.effect(() => {}), (error) => error?.code === 'INACTIVE_EFFECT')
    await fiber.dispose() // idempotent
    return {
      states: statuses,
      final_state: fiber.state,
      final_uid: fiber.uid,
      disposed_restart_rejected: true,
    }
  } finally {
    await disposeQuietly(fiber, provider)
  }
}

/** Case 5: LOADING -> FAILED, plus the locked version's restart-recovery behavior. */
async function caseFiberFailureRecovery({ cordis }) {
  const { Context } = cordis
  const root = new Context()
  const statuses = []
  root.on('internal/status', (fiber, oldState) => statuses.push([oldState, fiber.state]))
  let attempts = 0
  const fiber = root.plugin({
    name: 'contract/flaky',
    apply() {
      attempts += 1
      if (attempts === 1) throw new Error('contract-first-activation-boom')
    },
  })
  try {
    await assert.rejects(async () => { await fiber }, /contract-first-activation-boom/)
    assert.equal(fiber.state, STATE.FAILED)
    assert.ok(hasTransition(statuses, STATE.LOADING, STATE.UNLOADING))
    assert.ok(hasTransition(statuses, STATE.UNLOADING, STATE.FAILED))

    let restartError = null
    try {
      await fiber.restart()
    } catch (error) {
      restartError = errorDetail(error)
    }
    await waitFor(() => fiber.state === STATE.ACTIVE, { label: 'failed fiber restart' })
    assert.equal(attempts, 2, 'restart must re-execute the plugin callback')
    // Locked-version observation: restart() can reject with the cached startup
    // error even though the callback re-ran and the fiber reached ACTIVE.
    if (restartError !== null) {
      assert.match(restartError.message, /contract-first-activation-boom/)
    }
    const logicalDispose = await fiber.dispose()
    const disposal = { state_after_dispose: fiber.state, uid_after_dispose: fiber.uid }
    void logicalDispose
    return {
      states: statuses,
      failed_state: STATE.FAILED,
      recovered_state: STATE.ACTIVE,
      attempts,
      restart_promise_rejected_with: restartError?.message ?? null,
      locked_version_note: 'restart() re-executes the callback and reaches ACTIVE; the locked 4.0.5 promise may still reject with the cached startup error, and the fiber state field is not refreshed to DISPOSED after this recovery path (uid clears).',
      ...disposal,
    }
  } finally {
    // Best-effort teardown; the quirky post-restart fiber may not refresh state.
    try {
      await fiber.dispose()
    } catch {
      // ignore teardown failure of the already-unloaded fiber
    }
  }
}

/** Case 6: effect registration, reverse-order async disposal, abort/resource release. */
async function caseFiberEffects({ cordis }) {
  const { Context } = cordis
  const root = new Context()
  const order = []
  const controller = new AbortController()
  const fiber = root.plugin({
    name: 'contract/effects',
    apply(ctx) {
      order.push('apply')
      ctx.effect(() => {
        order.push('sync-effect')
        return () => { order.push('sync-dispose') }
      }, 'contract/effect-sync')
      ctx.effect(async () => {
        order.push('async-effect')
        return async () => {
          await sleep(10)
          order.push('async-dispose')
        }
      }, 'contract/effect-async')
      ctx.effect(() => {
        order.push('abort-effect')
        return () => { controller.abort() }
      }, 'contract/effect-abort')
      return () => { order.push('plugin-return-disposer') }
    },
  })
  try {
    await fiber
    const effects = fiber.getEffects().map((entry) => entry.label)
    assert.ok(effects.includes('contract/effect-sync'))
    assert.ok(effects.includes('contract/effect-async'))
    await fiber.dispose()
    assert.deepEqual(order, [
      'apply',
      'sync-effect',
      'async-effect',
      'abort-effect',
      'plugin-return-disposer',
      'sync-dispose',
      'async-dispose',
    ])
    assert.equal(controller.signal.aborted, true)
    assert.equal(fiber.getEffects().length, 0)
    assert.equal(fiber.state, STATE.DISPOSED)
    return {
      effect_labels: effects,
      disposal_order: order,
      abort_signal_aborted: controller.signal.aborted,
    }
  } finally {
    await disposeQuietly(fiber)
  }
}

/** Case 7: real loader entry create/update/remove. */
async function caseLoaderDynamicEntries({ modules, fixtureUrl }) {
  const { Context } = modules.cordis
  const Loader = modules.loader.default
  const root = new Context()
  const loaderFiber = root.plugin(Loader, { baseUrl: pathToFileURL(fixtureUrl).href })
  try {
    await loaderFiber
    const loader = root.get('loader')
    assert.ok(loader, 'loader service must be active')
    const config = { serviceName: 'contractLoaderSvc', label: 'v1' }
    await loader.create({ id: 'contract-entry', name: fixtureUrl, config })
    await loader.await()
    const first = root.get('contractLoaderSvc')
    assert.equal(first?.label, 'v1')
    assert.ok(first.activation >= 1)

    await loader.update('contract-entry', { config: { serviceName: 'contractLoaderSvc', label: 'v2' } })
    await loader.await()
    const second = root.get('contractLoaderSvc')
    assert.equal(second?.label, 'v2')
    assert.ok(second.activation > first.activation)
    assert.equal(first.released, true, 'the replaced activation must release its effect')

    loader.remove('contract-entry')
    await loader.await()
    await waitFor(() => second.released === true, { label: 'removed loader entry effect release' })
    assert.equal(root.get('contractLoaderSvc'), undefined)
    assert.equal([...loader.entries()].length, 0)
    return { first_activation: first.activation, second_activation: second.activation, entries_after_remove: 0 }
  } finally {
    await disposeQuietly(loaderFiber)
  }
}

/** Case 8: real loader group carrier with a nested entry. */
async function caseLoaderGroupEntries({ modules, fixtureUrl }) {
  const { Context } = modules.cordis
  const Loader = modules.loader.default
  const Group = modules.loader.Group
  const root = new Context()
  const loaderFiber = root.plugin(Loader, { baseUrl: pathToFileURL(fixtureUrl).href })
  try {
    await loaderFiber
    const loader = root.get('loader')
    assert.ok(loader)
    loader.builtins.group = Group
    await loader.create({
      id: 'contract-group',
      group: true,
      name: 'cordis:group',
      config: [{
        id: 'contract-child',
        name: fixtureUrl,
        config: { serviceName: 'contractGroupSvc', label: 'child' },
      }],
    })
    await loader.await()
    const child = root.get('contractGroupSvc')
    assert.equal(child?.label, 'child')
    const entries = [...loader.entries()]
    assert.equal(entries.length, 2)
    assert.ok(entries.some((entry) => entry.options.group === true))

    loader.remove('contract-group')
    await loader.await()
    await waitFor(() => child.released === true, { label: 'group child effect release' })
    await waitFor(() => root.get('contractGroupSvc') === undefined, { label: 'group child service removal' })
    assert.equal([...loader.entries()].length, 0)
    return { entries_with_group: entries.length, child_released: child.released }
  } finally {
    await disposeQuietly(loaderFiber)
  }
}

/** Case 9: real timer plugin disposal clears interval/timeout effects. */
async function caseTimerDisposal({ modules }) {
  const { Context } = modules.cordis
  const TimerService = modules.timer.default
  const root = new Context()
  const timerFiber = root.plugin(TimerService)
  let ticks = 0
  let timeoutFired = false
  const fiber = root.plugin({
    name: 'contract/timer-user',
    inject: ['timer'],
    apply(ctx) {
      ctx.setInterval(() => { ticks += 1 }, 10)
      ctx.timeout(() => { timeoutFired = true }, 120)
    },
  })
  try {
    await timerFiber
    assert.ok(root.get('timer'), 'timer service must be active')
    await fiber
    await sleep(35)
    assert.ok(ticks >= 1, 'interval must tick while active')
    const ticksAtDispose = ticks
    await fiber.dispose()
    await sleep(50)
    assert.equal(ticks, ticksAtDispose, 'disposal must clear the interval')
    await sleep(120)
    assert.equal(timeoutFired, false, 'disposal must clear the pending timeout')
    return { ticks_at_dispose: ticksAtDispose, ticks_after_dispose: ticks, timeout_fired_after_dispose: timeoutFired }
  } finally {
    await disposeQuietly(fiber, timerFiber)
  }
}

/**
 * Build a minimal Cordis host composition around the real dynamic runner.
 * `tools` is a minimal peer-service provider (the runner declares it as an
 * inject but tool registration is outside this contract case); Cordis itself,
 * the runner service and the host-half VM are the locked real packages.
 */
async function setupDynamicRunner(modules) {
  const { Context } = modules.cordis
  const { DynamicCordisRunnerService } = modules.hostRunner
  const root = new Context()
  const toolsProvider = root.plugin({
    name: 'contract/tools-provider',
    apply(ctx) {
      ctx.provide('tools', {
        register: () => () => {},
        schemas: () => [],
      })
    },
  })
  await toolsProvider
  const runnerFiber = root.plugin({
    name: 'contract/dynamic-runner',
    inject: ['tools'],
    apply(ctx) {
      new DynamicCordisRunnerService(ctx, { vmTimeoutMs: 2000, clientInspectTimeoutMs: 1000 })
    },
  })
  await runnerFiber
  const runner = root.get('dynamicCordisRunner')
  assert.ok(runner, 'dynamicCordisRunner service must be active')
  return {
    root,
    runner,
    agent: { id: 'contract-session-1' },
    async dispose() {
      await disposeQuietly(runnerFiber, toolsProvider)
    },
  }
}

const HOST_HALF_OK = `
return {
  name: 'contract/dynamic-host',
  apply(ctx) {
    ctx.provide('contractDynamicSvc', { ping: () => 'pong' })
    ctx.effect(() => () => {})
  }
}
`

/** Case 10: define -> run -> stop -> undefine with the real DSH dynamic runner. */
async function caseDynamicRunnerLifecycle({ modules }) {
  const harness = await setupDynamicRunner(modules)
  try {
    const receipt = harness.runner.define({
      sessionId: 'contract-session-1',
      plugin: { kind: 'new', idPrefix: 'ctr' },
      name: 'contract dynamic package',
      purpose: 'cordis contract suite',
      code: { host: HOST_HALF_OK },
    })
    assert.equal(receipt.hasHostHalf, true)
    assert.equal(receipt.hasClientHalf, false)
    const run = await harness.runner.run(harness.agent, receipt.pluginId, receipt.packageId, 'run')
    assert.equal(run.ok, true)
    assert.equal(run.status, 'running')
    assert.deepEqual(run.waitingFor, [])
    assert.equal(harness.root.get('contractDynamicSvc')?.ping(), 'pong')

    const snapshot = harness.runner.snapshot(harness.agent)
    assert.equal(snapshot.length, 1)
    assert.equal(snapshot[0].activeRun?.packageId, receipt.packageId)
    const hostFiber = snapshot[0].activeRun?.fiber
    assert.ok(hostFiber, 'the host half must run as a real Cordis fiber')
    const fiberStateWhileRunning = hostFiber.state

    const stopped = await harness.runner.stop(harness.agent, receipt.pluginId)
    assert.equal(stopped.ok, true)
    assert.equal(harness.root.get('contractDynamicSvc'), undefined)
    assert.equal(hostFiber.state, STATE.DISPOSED)
    assert.equal(hostFiber.uid, null)
    const secondStop = await harness.runner.stop(harness.agent, receipt.pluginId)
    assert.equal(secondStop.ok, false)
    assert.equal(secondStop.reason, 'not-running')
    const undefine = await harness.runner.undefine(harness.agent, receipt.pluginId)
    assert.equal(undefine.ok, true)
    assert.equal(undefine.wasRunning, false)
    assert.deepEqual(harness.runner.inventory(), [])
    const stopAfterUndefine = await harness.runner.stop(harness.agent, receipt.pluginId)
    assert.equal(stopAfterUndefine.reason, 'plugin-missing')
    return {
      plugin_id: receipt.pluginId,
      package_id: receipt.packageId,
      run_id: run.pluginRunId,
      host_fiber_state_while_running: fiberStateWhileRunning,
      host_fiber_state_after_stop: hostFiber.state,
      second_stop_reason: secondStop.reason,
      inventory_after_undefine: 0,
      stop_after_undefine_reason: stopAfterUndefine.reason,
    }
  } finally {
    await harness.dispose()
  }
}

/** Case 11: dynamic-runner host failure and pre-aborted cancellation. */
async function caseDynamicRunnerErrorAndCancel({ modules }) {
  const harness = await setupDynamicRunner(modules)
  try {
    const failing = harness.runner.define({
      sessionId: 'contract-session-1',
      plugin: { kind: 'new', idPrefix: 'fail' },
      name: 'contract failing package',
      purpose: 'cordis contract failure path',
      code: { host: `throw new Error('contract dynamic host boom')` },
    })
    const failedRun = await harness.runner.run(harness.agent, failing.pluginId, failing.packageId, 'run')
    assert.equal(failedRun.ok, false)
    assert.equal(failedRun.reason, 'host-half-failed')
    assert.match(failedRun.message ?? '', /contract dynamic host boom/)
    assert.equal(harness.root.get('contractDynamicSvc'), undefined)

    const cancelledPackage = harness.runner.define({
      sessionId: 'contract-session-1',
      plugin: { kind: 'existing', pluginId: failing.pluginId },
      name: 'contract cancelled package',
      purpose: 'cordis contract cancel path',
      code: { host: HOST_HALF_OK },
    })
    const controller = new AbortController()
    controller.abort()
    const cancelledRun = await harness.runner.run(
      harness.agent,
      failing.pluginId,
      cancelledPackage.packageId,
      'run',
      controller.signal,
    )
    assert.equal(cancelledRun.ok, false)
    assert.equal(cancelledRun.reason, 'cancelled')

    const stop = await harness.runner.stop(harness.agent, failing.pluginId)
    assert.equal(stop.ok, false)
    assert.equal(stop.reason, 'not-running')
    const undefine = await harness.runner.undefine(harness.agent, failing.pluginId)
    assert.equal(undefine.ok, true)
    assert.equal(undefine.wasRunning, false)
    const stopAfterUndefine = await harness.runner.stop(harness.agent, failing.pluginId)
    assert.equal(stopAfterUndefine.reason, 'plugin-missing')
    return {
      failed_reason: failedRun.reason,
      failed_message: failedRun.message,
      cancelled_reason: cancelledRun.reason,
      stop_after_undefine_reason: stopAfterUndefine.reason,
    }
  } finally {
    await harness.dispose()
  }
}

const CASE_IMPLEMENTATIONS = Object.freeze({
  'runtime.module-identity': caseRuntimeModuleIdentity,
  'context.events-dispatch': caseContextEvents,
  'context.service-registry': caseContextServiceRegistry,
  'service.isolation': caseServiceIsolation,
  'fiber.lifecycle': caseFiberLifecycle,
  'fiber.failure-recovery': caseFiberFailureRecovery,
  'fiber.effects-resource-release': caseFiberEffects,
  'loader.dynamic-entries': caseLoaderDynamicEntries,
  'loader.group-entries': caseLoaderGroupEntries,
  'timer.disposal': caseTimerDisposal,
  'dynamic-runner.define-run-stop-undefine': caseDynamicRunnerLifecycle,
  'dynamic-runner.error-and-cancel': caseDynamicRunnerErrorAndCancel,
})

test('cordis-contract-suite/v1 executes against the locked Cordis runtime', async (t) => {
  const startedAt = new Date().toISOString()
  const installed = await readInstalledRuntime()
  const cordis = await loadRealRuntime({
    entry: installed.cordisEntryUrl,
    package_name: '@deepseek-ai/cordis',
    package_version: installed.installed['@deepseek-ai/cordis'].package.version,
  })
  const catalog = buildApiCatalog(cordis.cordis, installed.installed['@deepseek-ai/cordis'].package.version)
  await writeEvidence('cordis-api-catalog.v1.json', catalog.catalog)
  const { anchor, anchorDigest } = await buildRuntimeAnchor({
    catalogRef: { id: catalog.catalog.catalog_id, version: catalog.catalog.catalog_version, digest: catalog.digest },
  })
  await writeRuntimeAnchor(anchor)

  const definition = await readSuiteDefinition()
  const { suite, suiteDigest } = materializeSuite(definition, { anchor, anchorDigest })
  await writeEvidence('cordis-contract-suite.v1.json', suite)

  const suiteCaseIds = suite.cases.map((entry) => entry.case_id)
  const implementationIds = Object.keys(CASE_IMPLEMENTATIONS)
  assert.deepEqual([...suiteCaseIds].sort(), [...implementationIds].sort(), 'every suite case must have exactly one real implementation')

  const caseRecords = []
  for (const entry of suite.cases) {
    const caseStarted = new Date().toISOString()
    let status = 'pass'
    let detail
    try {
      detail = await CASE_IMPLEMENTATIONS[entry.case_id]({
        ...cordis,
        modules: cordis,
        fixtureUrl: new URL('./fixtures/loader-plugin.mjs', import.meta.url).href,
      })
      t.diagnostic(`pass ${entry.case_id}`)
    } catch (error) {
      status = 'fail'
      detail = { error: errorDetail(error) }
      t.diagnostic(`fail ${entry.case_id}: ${detail.error.message}`)
    }
    caseRecords.push({
      case_id: entry.case_id,
      area: entry.area,
      required: entry.required,
      status,
      started_at: caseStarted,
      ended_at: new Date().toISOString(),
      evidence_refs: [`evidence/cordis-contract-results.v1.json#${entry.case_id}`],
      detail,
    })
  }

  const results = resultsDocument({
    suite,
    suiteDigest,
    anchor,
    anchorDigest,
    cases: caseRecords,
    startedAt,
    endedAt: new Date().toISOString(),
    environment: environmentSummary(),
  })
  const evidencePath = await writeEvidence('cordis-contract-results.v1.json', results)
  assert.equal(results.summary.required_failed, 0, `contract failures: ${JSON.stringify(results.cases.filter((item) => item.required && item.status !== 'pass').map((item) => item.case_id))}`)
  assert.equal(results.summary.passed, suite.cases.length)
  assert.equal(runtimeAnchorV2Digest(anchor), anchorDigest)

  // Evidence-to-run binding: the catalog on disk is exactly the catalog the
  // anchor binds, and the committed anchor is exactly the verified anchor.
  const catalogOnDisk = JSON.parse(await readFile(join(EVIDENCE_DIR, 'cordis-api-catalog.v1.json'), 'utf8'))
  assert.equal(sha256Value(catalogOnDisk), anchor.catalog_ref.digest, 'API catalog digest must bind the catalog that ran')
  const anchorOnDisk = JSON.parse(await readFile(ANCHOR_PATH, 'utf8'))
  assert.equal(runtimeAnchorV2Digest(anchorOnDisk), anchorDigest, 'evidence anchor must equal the verified anchor')
  t.diagnostic(`evidence: ${evidencePath}`)
})
