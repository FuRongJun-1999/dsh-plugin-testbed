/**
 * fixture-put-failing：故意缺陷 PUT（M3 失败 fail-closed 负向）。
 *
 * `apply()` 直接抛错 → Cordis 加载结算 reject → `state_after_load === 'FAILED'`，
 * `error` 含 'intentional'。这是待断言的观测值，不是传输错误（execution_status 仍 completed）。
 *
 * 导出约定见 CONTRACT-m3 §1：`export default <plugin>`。
 */
export default {
  name: 'fixture-put-failing',
  apply() {
    throw new Error('fixture-put-failing: intentional')
  },
}