/**
 * TEST DOUBLE — not Cordis.
 *
 * Minimal `Context` / `Fiber` implementation with the lifecycle surface the
 * worker relies on (`plugin()`, awaitable fiber, numeric `state`,
 * `getEffects()`, `dispose()`, `internal/status` events). It exists only so
 * worker unit tests can exercise the load/apply/dispose code path without a
 * locked DSH/Cordis runtime in this environment.
 *
 * The worker records it as a non-locked injected runtime (`runtime_kind`
 * `test-fixture`) and never labels it `real-cordis`. Do not import it from
 * production code paths.
 */
const STATE = Object.freeze({ PENDING: 0, LOADING: 1, ACTIVE: 2, FAILED: 3, DISPOSED: 4, UNLOADING: 5 })

class Context {
  #listeners = new Map()
  #effects = []

  on(event, listener) {
    if (typeof listener !== 'function') throw new TypeError('listener must be a function')
    const list = this.#listeners.get(event) ?? []
    list.push(listener)
    this.#listeners.set(event, list)
    return this
  }

  off(event, listener) {
    const list = this.#listeners.get(event) ?? []
    this.#listeners.set(event, list.filter((item) => item !== listener))
    return this
  }

  emit(event, ...args) {
    for (const listener of [...(this.#listeners.get(event) ?? [])]) listener(...args)
    return this
  }

  effect(effect) {
    if (typeof effect !== 'function') throw new TypeError('effect must be a function')
    const disposer = effect()
    this.#effects.push({ effect, disposer: typeof disposer === 'function' ? disposer : null })
    return () => {}
  }

  plugin(plugin, config = {}) {
    if (plugin == null || (typeof plugin !== 'function' &&
        (typeof plugin !== 'object' || (typeof plugin.apply !== 'function' && typeof plugin.setup !== 'function')))) {
      throw new Error('invalid plugin')
    }
    return new Fiber(this, plugin, config)
  }

  async dispose() {
    this.emit('context/dispose')
  }
}

class Fiber {
  constructor(root, plugin, config) {
    this.root = root
    this.plugin = plugin
    this.config = config
    this.state = STATE.PENDING
    this.error = null
    this.#effects = []
    this.#startPromise = null
  }

  #effects = []
  #startPromise = null

  #setState(next) {
    const old = this.state
    this.state = next
    this.root.emit('internal/status', this, old)
  }

  #context() {
    const fiber = this
    return {
      effect(effect) {
        const disposer = effect()
        fiber.#effects.push({ effect, disposer: typeof disposer === 'function' ? disposer : null })
        return () => {}
      },
      on: (...args) => this.root.on(...args),
      off: (...args) => this.root.off(...args),
      emit: (...args) => this.root.emit(...args),
      get: () => undefined,
      set: () => {},
    }
  }

  async #start() {
    this.#setState(STATE.LOADING)
    try {
      const apply = typeof this.plugin === 'function' ? this.plugin : (this.plugin.apply ?? this.plugin.setup)
      await apply.call(this.plugin, this.#context(), this.config)
      this.#setState(STATE.ACTIVE)
      // Resolve with a non-thenable: the Fiber itself is awaitable, so returning
      // `this` would make promise assimilation recurse forever.
      return undefined
    } catch (error) {
      this.error = error
      this.#setState(STATE.FAILED)
      throw error
    }
  }

  then(resolve, reject) {
    if (this.#startPromise === null) this.#startPromise = this.#start()
    return this.#startPromise.then(resolve, reject)
  }

  catch(reject) {
    return this.then(undefined, reject)
  }

  getEffects() {
    return this.#effects.map((entry) => entry.effect)
  }

  async dispose() {
    if (this.state === STATE.DISPOSED) return undefined
    this.#setState(STATE.UNLOADING)
    for (const entry of [...this.#effects].reverse()) {
      try { await entry.disposer?.() } catch { /* disposers are best effort in the double */ }
    }
    this.#effects = []
    this.#setState(STATE.DISPOSED)
    return undefined
  }
}

export { Context, Fiber, STATE }
