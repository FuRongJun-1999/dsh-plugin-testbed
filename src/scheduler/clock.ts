/**
 * Monotonic-aware clock guard for the durable scheduler.
 *
 * Lease TTL must survive wall-clock rollback and drift (NEXT-PHASE-REQUIREMENTS
 * SCH-03, T-14). The guard samples a wall clock (persisted timestamps) and a
 * monotonic clock (process-local TTL) and trips **fail-closed** on:
 *   - wall-clock rollback beyond `maxSkewMs` relative to the highest wall value
 *     already observed while this process owns the store;
 *   - a forward wall jump larger than monotonic progress plus tolerance;
 *   - wall-vs-monotonic drift larger than tolerance;
 *   - a monotonic regression / non-finite clock sample.
 *
 * A tripped guard never self-heals: the scheduler stays `blocked` until an
 * explicit operator `recoverClockFault` re-bases the guard (the fault is also
 * persisted in the store so a crash/restart cannot silently clear it).
 *
 * @module @deepseek-ai/dsh-plugin-testbed/scheduler/clock
 */

import type { Clock, ClockFaultCode, ClockSample } from './types.js'
import { DEFAULT_MAX_CLOCK_FORWARD_JUMP_MS, DEFAULT_MAX_CLOCK_SKEW_MS } from './limits.js'

const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/

/**
 * Production clock: wall ms from `Date.now()`; monotonic ms from
 * `process.hrtime.bigint()` (never affected by wall-clock changes).
 */
export function createSystemClock(): Clock {
  return Object.freeze({
    wallNow: (): number => Date.now(),
    monoNow: (): number => Number(process.hrtime.bigint() / 1000n) / 1000,
    iso: (wallMs: number): string => new Date(wallMs).toISOString(),
    parse: (iso: string): number => Date.parse(iso),
  })
}

/**
 * @param value candidate timestamp
 * @returns true for an RFC 3339 UTC/offset timestamp string
 */
export function isRfc3339(value: unknown): value is string {
  return typeof value === 'string' && RFC3339_RE.test(value) && Number.isFinite(Date.parse(value))
}

/** @param wallMs epoch milliseconds */
export function isoFromWallMs(wallMs: number): string {
  return new Date(wallMs).toISOString()
}

/** @param iso RFC 3339 timestamp */
export function wallMsFromIso(iso: string): number {
  return Date.parse(iso)
}

/** Clock fault codes (mapped by the manager to `scheduler-clock-skew`). */
export const CLOCK_FAULT = {
  ROLLBACK: 'wall-clock-rollback',
  FORWARD_JUMP: 'wall-clock-forward-jump',
  DRIFT: 'wall-vs-monotonic-drift',
  MONOTONIC_REGRESSION: 'monotonic-regression',
  NON_FINITE: 'clock-non-finite',
} as const satisfies Record<string, ClockFaultCode>

interface ClockGuardOptions {
  clock?: Clock
  maxSkewMs?: number
  maxForwardJumpMs?: number
}

interface ClockResetResult {
  ok: boolean
  faults: ClockFaultCode[]
  wallMs: number | null
  monoMs: number | null
}

/**
 * Stateful wall+monotonic sampler. One guard belongs to one scheduler instance;
 * it is not persisted itself — only the resulting fault flag is persisted.
 */
export class ClockGuard {
  clock: Clock
  maxSkewMs: number
  maxForwardJumpMs: number
  last: { wallMs: number; monoMs: number } | null
  maxWallMs: number | null
  faults: Set<ClockFaultCode>
  samples: number

  constructor(options: ClockGuardOptions = {}) {
    this.clock = options.clock ?? createSystemClock()
    this.maxSkewMs = Number.isFinite(options.maxSkewMs) && (options.maxSkewMs as number) >= 0
      ? (options.maxSkewMs as number)
      : DEFAULT_MAX_CLOCK_SKEW_MS
    this.maxForwardJumpMs = Number.isFinite(options.maxForwardJumpMs) && (options.maxForwardJumpMs as number) >= 0
      ? (options.maxForwardJumpMs as number)
      : DEFAULT_MAX_CLOCK_FORWARD_JUMP_MS
    this.last = null
    this.maxWallMs = null
    this.faults = new Set()
    this.samples = 0
  }

  /** Sample both clocks and update the fault set. */
  sample(): ClockSample {
    const wallMs = Number(this.clock.wallNow())
    const monoMs = Number(this.clock.monoNow())
    this.samples += 1

    if (!Number.isFinite(wallMs) || !Number.isFinite(monoMs)) {
      this.faults.add(CLOCK_FAULT.NON_FINITE)
      return this.#snapshot()
    }

    if (this.maxWallMs === null || wallMs > this.maxWallMs) this.maxWallMs = wallMs

    if (this.last !== null) {
      const wallDelta = wallMs - this.last.wallMs
      const monoDelta = monoMs - this.last.monoMs
      if (monoDelta < 0) this.faults.add(CLOCK_FAULT.MONOTONIC_REGRESSION)
      if (wallMs < this.last.wallMs && Math.abs(wallDelta) > this.maxSkewMs) {
        this.faults.add(CLOCK_FAULT.ROLLBACK)
      }
      if (this.maxWallMs !== null && wallMs < this.maxWallMs && this.maxWallMs - wallMs > this.maxSkewMs) {
        this.faults.add(CLOCK_FAULT.ROLLBACK)
      }
      if (monoDelta >= 0) {
        if (wallDelta - monoDelta > this.maxForwardJumpMs) this.faults.add(CLOCK_FAULT.FORWARD_JUMP)
        if (monoDelta - wallDelta > this.maxSkewMs) this.faults.add(CLOCK_FAULT.DRIFT)
      }
    }

    this.last = { wallMs, monoMs }
    return this.#snapshot()
  }

  /**
   * Re-base the guard on a fresh sane sample after an operator acknowledged the
   * fault. Refuses if the current sample is still behind the highest wall value
   * or if the monotonic clock regressed.
   */
  reset(options: { reason?: string } = {}): ClockResetResult {
    void options
    const wallMs = Number(this.clock.wallNow())
    const monoMs = Number(this.clock.monoNow())
    if (!Number.isFinite(wallMs) || !Number.isFinite(monoMs)) {
      return { ok: false, faults: [CLOCK_FAULT.NON_FINITE], wallMs: null, monoMs: null }
    }
    if (this.maxWallMs !== null && wallMs < this.maxWallMs) {
      return { ok: false, faults: [CLOCK_FAULT.ROLLBACK], wallMs, monoMs }
    }
    if (this.last !== null && monoMs < this.last.monoMs) {
      return { ok: false, faults: [CLOCK_FAULT.MONOTONIC_REGRESSION], wallMs, monoMs }
    }
    this.faults.clear()
    this.last = { wallMs, monoMs }
    this.maxWallMs = wallMs
    return { ok: true, faults: [], wallMs, monoMs }
  }

  status(): { ok: boolean; faults: ClockFaultCode[]; samples: number } {
    return { ok: this.faults.size === 0, faults: [...this.faults], samples: this.samples }
  }

  /** Fresh wall/mono pair for a single operation (does not clear faults). */
  now(): { wallMs: number | null; monoMs: number | null; ok: boolean } {
    const sample = this.sample()
    return { wallMs: sample.wallMs, monoMs: sample.monoMs, ok: sample.ok }
  }

  #snapshot(): ClockSample {
    const faults = [...this.faults]
    return {
      ok: faults.length === 0,
      wallMs: this.last?.wallMs ?? null,
      monoMs: this.last?.monoMs ?? null,
      faults,
      fault_codes: faults,
      reason_codes: faults.length === 0 ? [] : ['scheduler-clock-skew'],
    }
  }
}

/** Convenience factory. */
export function createClockGuard(options: ClockGuardOptions = {}): ClockGuard {
  return new ClockGuard(options)
}
