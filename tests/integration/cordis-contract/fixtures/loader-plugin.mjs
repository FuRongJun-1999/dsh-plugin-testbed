/**
 * TEST FIXTURE — a real ESM plugin module loaded through the real
 * `@deepseek-ai/cordis-plugin-loader`. It is not a Cordis substitute: the
 * runtime executing it is the exact locked package recorded in the anchor.
 */
let activations = 0

export function apply(ctx, config) {
  activations += 1
  const state = {
    label: config.label,
    serviceName: config.serviceName,
    activation: activations,
    released: false,
  }
  ctx.provide(config.serviceName, state)
  ctx.effect(() => () => {
    state.released = true
  })
}
