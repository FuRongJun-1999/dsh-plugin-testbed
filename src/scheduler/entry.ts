/**
 * Scheduler entry semantics for the final integration (t11).
 *
 * Scheduling stays **disabled by default**: without an explicit `enable`
 * request, no store is opened, no timer/cron exists and the entry reports
 * `scheduler-disabled`. Enabling requires the frozen policy + a non-expired
 * operator authorization with separation of duties; any missing/invalid input
 * keeps the scheduler `blocked`/disabled with stable reason codes. The entry
 * only reports status and closes the store; it never starts a background loop.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/scheduler/entry
 */
import { hostname } from 'node:os'

import { createScheduler } from './manager.js'
import type { SchedulerOptions } from './manager.js'
import type { SchedulerStatus } from './types.js'
import { SCHEDULER_LIMITATIONS } from './limits.js'

export interface SchedulerEntryOptions {
  enabled?: boolean
  storePath?: string
  policy?: unknown
  authorization?: unknown
  ownerId?: string
  host?: string
  pid?: number
  clock?: SchedulerOptions['clock']
  capability?: SchedulerOptions['capability']
  maxClockSkewMs?: number
  maxForwardJumpMs?: number
}

export interface SchedulerEntryStatus {
  schema_version: 'scheduler-entry/v1'
  status: 'disabled' | 'blocked' | 'enabled'
  scheduler_enabled: boolean
  enabled_requested: boolean
  reason_codes: string[]
  cron_enabled: false
  background_loops: false
  single_host: true
  ha: false
  market_auto_publish: false
  limitations: string[]
  policy_digest: string | null
  authorization_id: string | null
  store_path: string | null
  scheduler_status: SchedulerStatus | null
  detail: string | null
}

function baseStatus(): SchedulerEntryStatus {
  return {
    schema_version: 'scheduler-entry/v1',
    status: 'disabled',
    scheduler_enabled: false,
    enabled_requested: false,
    reason_codes: [],
    cron_enabled: false,
    background_loops: false,
    single_host: true,
    ha: false,
    market_auto_publish: false,
    limitations: [...SCHEDULER_LIMITATIONS],
    policy_digest: null,
    authorization_id: null,
    store_path: null,
    scheduler_status: null,
    detail: null,
  }
}

function errorDetail(error: unknown): string {
  return error instanceof Error ? error.message.slice(0, 300) : String(error).slice(0, 300)
}

/**
 * Report the governed scheduler's current entry state.
 *
 * @param {SchedulerEntryOptions} [options]
 * @returns {Readonly<SchedulerEntryStatus>}
 */
export function describeSchedulerEntry(options: SchedulerEntryOptions = {}): Readonly<SchedulerEntryStatus> {
  const status = baseStatus()
  const enabledRequested = options.enabled === true
  status.enabled_requested = enabledRequested

  const createOptions: SchedulerOptions = {
    enabled: enabledRequested,
    ownerId: options.ownerId ?? 'scheduler-entry',
    host: options.host ?? hostname(),
    pid: options.pid ?? process.pid,
    policy: options.policy,
    authorization: options.authorization,
    ...(options.storePath === undefined ? {} : { storePath: options.storePath }),
    ...(options.clock === undefined ? {} : { clock: options.clock }),
    ...(options.capability === undefined ? {} : { capability: options.capability }),
    ...(options.maxClockSkewMs === undefined ? {} : { maxClockSkewMs: options.maxClockSkewMs }),
    ...(options.maxForwardJumpMs === undefined ? {} : { maxForwardJumpMs: options.maxForwardJumpMs }),
  }

  let scheduler: ReturnType<typeof createScheduler> | null = null
  try {
    scheduler = createScheduler(createOptions)
    const schedulerStatus = scheduler.status()
    status.scheduler_status = schedulerStatus
    status.scheduler_enabled = schedulerStatus.enabled === true
    status.status = schedulerStatus.state
    status.reason_codes = [...schedulerStatus.reason_codes]
    status.limitations = [...new Set([...status.limitations, ...(schedulerStatus.limitations ?? [])])]
    const policy = schedulerStatus.policy
    status.policy_digest = policy !== null && typeof policy.digest === 'string' ? policy.digest : null
    status.authorization_id = schedulerStatus.authorization !== null &&
      typeof schedulerStatus.authorization.authorization_id === 'string'
      ? schedulerStatus.authorization.authorization_id
      : null
    if (schedulerStatus.store !== null && typeof schedulerStatus.store.path === 'string') {
      status.store_path = schedulerStatus.store.path
    }
    if (status.status === 'disabled' && status.reason_codes.length === 0) {
      status.reason_codes = ['scheduler-disabled']
    }
    return status
  } catch (error) {
    status.status = 'blocked'
    status.scheduler_enabled = false
    status.reason_codes = ['scheduler-invalid-input']
    status.detail = errorDetail(error)
    return status
  } finally {
    if (scheduler !== null) scheduler.close()
  }
}
