/**
 * worker-owner 自有 fixture PUT（真实 Cordis 合规插件）。
 *
 * 仅用于 `src/worker/host.js` 的 `load-put` 单测（tests/unit/worker/host.test.js）。
 * 与 tests-owner 的 `put-compliant.js` 不同名，避免写作用域冲突。
 *
 * 导出约定（CONTRACT-m3 §1）：`export default <plugin>`；可选 `export const state`
 * （worker 会把 `mod.state` 原样透传到 observation 的 `put_state`）。
 */
export default {
  name: 'put-host-compliant',
  apply(ctx) {
    // 注册一个 effect，使 `fiber.getEffects().length >= 1`（证明 apply 真实跑过）。
    ctx.effect(() => () => {})
    ctx.effect(() => () => {}, 'put-host-compliant: second effect')
  },
}

export const state = 'put-host-compliant: loaded'