/**
 * Fixture PUT exporting an oversized state value.
 *
 * The worker must bound/summarize the observation value instead of writing an
 * unbounded frame. `apply` registers a normal effect so lifecycle still works.
 */
const HUGE = 'x'.repeat(700 * 1024)

export default {
  name: 'put-huge-state',
  apply(ctx) {
    ctx.effect(() => () => {})
  },
}

export const state = HUGE
