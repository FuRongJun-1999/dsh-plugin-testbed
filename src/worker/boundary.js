/**
 * Worker lifecycle boundary — init → ready → load/execute → teardown.
 *
 * The worker is a single serial L1 child process. This module keeps the
 * lifecycle observable and makes teardown idempotent: cancellation aborts the
 * in-flight operation's signal, cleanup runs exactly once, and a second signal
 * cannot produce a second cleanup. Process-tree reclamation itself belongs to
 * the adapter/launcher (control face); the worker only cooperates and reports.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/worker/boundary
 */

export const LIFECYCLE_STATES = Object.freeze(['init', 'ready', 'busy', 'idle', 'tearing-down', 'terminated'])

/**
 * @param {{onShutdown?:(reason:string)=>void|Promise<void>, maxTransitions?:number}} [options]
 */
export function createWorkerLifecycle(options = {}) {
  const maxTransitions = options.maxTransitions ?? 64
  let state = 'init'
  let current = null
  let shutdownPromise = null
  const transitions = []

  const setState = (next) => {
    if (transitions.length < maxTransitions) transitions.push({ from: state, to: next })
    state = next
  }

  return {
    get state() { return state },
    get currentOp() { return current?.name ?? null },
    snapshot() {
      return { state, current_op: current?.name ?? null, transitions: transitions.map((item) => ({ ...item })) }
    },

    markReady() {
      if (state !== 'init') return { ok: false, reason: 'invalid-lifecycle-transition' }
      setState('ready')
      return { ok: true }
    },

    /**
     * Start one serial operation. The handle's signal is aborted on shutdown.
     * @param {string} name
     * @returns {{ok:true, handle:{name:string, signal:AbortSignal, end:(outcome?:string)=>void,
     *   abort:(reason:string)=>boolean}}
     *   | {ok:false, reason:string}}
     */
    beginOp(name) {
      if (state === 'tearing-down' || state === 'terminated') return { ok: false, reason: 'worker-shutting-down' }
      if (current !== null) return { ok: false, reason: 'worker-busy' }
      const controller = new AbortController()
      setState('busy')
      let finished = false
      const handle = {
        name: String(name ?? 'op').slice(0, 64),
        signal: controller.signal,
        end(outcome = 'completed') {
          if (finished) return false
          finished = true
          if (current === handle) {
            current = null
            if (state === 'busy') setState('idle')
          }
          if (transitions.length < maxTransitions) {
            transitions.push({ from: 'busy', to: 'idle', op: handle.name, outcome: String(outcome).slice(0, 64) })
          }
          return true
        },
        abort(reason) {
          if (finished || controller.signal.aborted) return false
          controller.abort(reason)
          return true
        },
      }
      current = handle
      return { ok: true, handle }
    },

    /** Idempotent teardown. Resolves once cleanup completed (or failed). */
    shutdown(reason = 'shutdown') {
      if (shutdownPromise) return shutdownPromise
      setState('tearing-down')
      if (current) current.abort(reason)
      current = null
      shutdownPromise = (async () => {
        let cleanupError = null
        try {
          await options.onShutdown?.(reason)
        } catch (error) {
          cleanupError = error instanceof Error ? error.message : String(error)
        }
        setState('terminated')
        return { ok: cleanupError === null, reason, cleanup_error: cleanupError }
      })()
      return shutdownPromise
    },
  }
}

/**
 * Install SIGTERM/SIGINT handlers that tear down exactly once. Returns an
 * uninstall function (tests and hosts use it instead of leaking listeners).
 *
 * @param {ReturnType<typeof createWorkerLifecycle>} lifecycle
 * @param {{processRef?:NodeJS.Process, signals?:string[],
 *   exit?:(code:number)=>void}} [options]
 */
export function installSignalHandlers(lifecycle, options = {}) {
  const processRef = options.processRef ?? process
  const signals = options.signals ?? ['SIGTERM', 'SIGINT']
  const exit = options.exit ?? ((code) => processRef.exit(code))
  const handlers = []
  for (const signal of signals) {
    const handler = () => {
      lifecycle.shutdown(signal).then(() => exit(0), () => exit(1))
    }
    handlers.push([signal, handler])
    processRef.on(signal, handler)
  }
  return () => {
    for (const [signal, handler] of handlers) {
      try { processRef.off(signal, handler) } catch { /* listener already gone */ }
    }
  }
}
