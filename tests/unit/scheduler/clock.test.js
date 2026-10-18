/**
 * Monotonic clock guard: rollback / forward jump / drift / regression and
 * explicit operator re-basing.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  CLOCK_FAULT,
  ClockGuard,
  createClockGuard,
  createSystemClock,
  isRfc3339,
  isoFromWallMs,
  wallMsFromIso,
} from '../../../src/scheduler/index.js'
import { createManualClock } from './_helpers.js'

test('clock: system clock is finite and RFC3339 helpers round-trip', () => {
  const clock = createSystemClock()
  const wall = clock.wallNow()
  assert.equal(Number.isFinite(wall), true)
  assert.equal(Number.isFinite(clock.monoNow()), true)
  const iso = isoFromWallMs(wall)
  assert.equal(isRfc3339(iso), true)
  assert.equal(wallMsFromIso(iso), wall)
  assert.equal(isRfc3339('2026-10-19 00:00:00'), false)
  assert.equal(isRfc3339('not-a-time'), false)
  assert.equal(isRfc3339(42), false)
})

test('clock: steady advance (wall + monotonic) never trips', () => {
  const clock = createManualClock()
  const guard = new ClockGuard({ clock, maxSkewMs: 1_000, maxForwardJumpMs: 1_000 })
  for (let i = 0; i < 10; i += 1) {
    clock.advance(500)
    const sample = guard.sample()
    assert.equal(sample.ok, true, sample.faults.join(','))
  }
  assert.equal(guard.status().ok, true)
  assert.equal(guard.samples, 10)
})

test('clock: wall-only rollback trips a persistent fault', () => {
  const clock = createManualClock()
  const guard = createClockGuard({ clock, maxSkewMs: 1_000 })
  assert.equal(guard.sample().ok, true)
  clock.shiftWall(-60_000)
  const sample = guard.sample()
  assert.equal(sample.ok, false)
  assert.ok(sample.faults.includes(CLOCK_FAULT.ROLLBACK))
  assert.deepEqual(sample.reason_codes, ['scheduler-clock-skew'])

  // Fault is sticky until reset.
  clock.advance(1_000)
  assert.equal(guard.sample().ok, false)
  assert.equal(guard.status().ok, false)
})

test('clock: forward wall jump beyond monotonic progress trips FORWARD_JUMP', () => {
  const clock = createManualClock()
  const guard = createClockGuard({ clock, maxSkewMs: 1_000, maxForwardJumpMs: 5_000 })
  guard.sample()
  clock.shiftWall(120_000)
  const sample = guard.sample()
  assert.equal(sample.ok, false)
  assert.ok(sample.faults.includes(CLOCK_FAULT.FORWARD_JUMP))
})

test('clock: monotonic regression and non-finite samples trip', () => {
  const clock = createManualClock()
  const guard = createClockGuard({ clock })
  guard.sample()
  clock.setMono(clock.monoNow() - 10)
  const regression = guard.sample()
  assert.equal(regression.ok, false)
  assert.ok(regression.faults.includes(CLOCK_FAULT.MONOTONIC_REGRESSION))

  const broken = createClockGuard({
    clock: { wallNow: () => Number.NaN, monoNow: () => 1, iso: () => '', parse: () => 0 },
  })
  const nonFinite = broken.sample()
  assert.equal(nonFinite.ok, false)
  assert.ok(nonFinite.faults.includes(CLOCK_FAULT.NON_FINITE))
})

test('clock: reset refuses while still behind the high-water mark, then clears', () => {
  const clock = createManualClock()
  const guard = createClockGuard({ clock, maxSkewMs: 1_000 })
  const highWater = clock.wallNow()
  guard.sample()
  clock.shiftWall(-30_000)
  assert.equal(guard.sample().ok, false)

  const refused = guard.reset({ reason: 'still broken' })
  assert.equal(refused.ok, false)
  assert.ok(refused.faults.includes(CLOCK_FAULT.ROLLBACK))

  clock.setWall(highWater + 1_000)
  const cleared = guard.reset({ reason: 'operator verified wall clock' })
  assert.equal(cleared.ok, true)
  assert.deepEqual(cleared.faults, [])
  assert.equal(guard.status().ok, true)
})
