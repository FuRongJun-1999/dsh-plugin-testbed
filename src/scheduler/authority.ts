/**
 * Scheduler-local authority-field guard.
 *
 * The scheduler must never accept a worker/caller payload that tries to smuggle
 * a control-plane authority fact (`verdict`, `gate_decision`, `required`, ...)
 * into a schedule, event payload or monitoring observation. The list below
 * mirrors `src/control/state.js`'s `AUTHORITY_FIELDS` on purpose: the scheduler,
 * as a *consumer*, may not broaden the authority surface, and it must not import
 * the still-unmigrated legacy control module from typed code (the migration
 * build only type-checks `.ts` sources). A divergence test in
 * `tests/unit/scheduler/governance.test.js` compares both lists.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/scheduler/authority
 */

import { isPlainRecord } from './lease.js'

/** Fields a schedule/event/observation may never carry as authority. */
export const SCHEDULER_AUTHORITY_FIELDS: readonly string[] = Object.freeze([
  'verdict', 'gate_decision', 'required', 'expected', 'plan', 'plan_resolution',
  'run_status', 'gate', 'worker_verdict', 'admission_decision', 'admission_source',
])

/**
 * Recursively collect paths that try to smuggle an authority field. Arrays are
 * traversed; primitives are ignored.
 *
 * @param value trust-boundary input
 * @param path internal recursion path
 * @returns dotted paths of offending fields (empty when safe)
 */
export function findSchedulerAuthorityFields(value: unknown, path = ''): string[] {
  const hits: string[] = []
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      hits.push(...findSchedulerAuthorityFields(item, path === '' ? `[${index}]` : `${path}[${index}]`))
    })
    return hits
  }
  if (!isPlainRecord(value)) return hits
  for (const [key, child] of Object.entries(value)) {
    const childPath = path === '' ? key : `${path}.${key}`
    if (SCHEDULER_AUTHORITY_FIELDS.includes(key)) hits.push(childPath)
    hits.push(...findSchedulerAuthorityFields(child, childPath))
  }
  return hits
}
