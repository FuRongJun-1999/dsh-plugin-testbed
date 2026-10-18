/**
 * Worker-owned fixture PUT that declares plugin capabilities.
 *
 * Used by `tests/unit/worker/probe.test.js` to verify that the worker keeps
 * declarations (`claim`) separate from measurements (`observed`): `requires`
 * and `capabilities` below are declarations only, while the probe measures the
 * plugin shape / apply / effect / dispose path itself.
 */
export const requires = ['target:plugin', 'host:event-loop']
export const capabilities = ['effect', 'service:example']

export default {
  name: 'put-worker-declared',
  apply(ctx) {
    ctx.effect(() => () => {})
    ctx.effect(() => () => {}, 'put-worker-declared: second effect')
  },
}

export const state = 'put-worker-declared: loaded'
