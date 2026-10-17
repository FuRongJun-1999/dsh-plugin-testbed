/**
 * fixture-put-compliant：合规 PUT（M3 真实 Cordis 生命周期契约）。
 *
 * 注册一个 effect（disposer 为空），使 `fiber.getEffects().length >= 1`，
 * 加载后应走到 `ACTIVE`，卸载后 `DISPOSED`。无秘密、无副作用、确定性。
 *
 * 导出约定见 CONTRACT-m3 §1：`export default <plugin>`。
 */
export default {
  name: 'fixture-put-compliant',
  apply(ctx) {
    ctx.effect(() => () => {})
  },
}