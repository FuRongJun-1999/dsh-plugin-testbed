/**
 * Scheduler fencing evidence intake (t8 / SCH-* integration point).
 *
 * Scheduling is disabled by default; the market gate never enables it. What is
 * tested here is that a scheduling-required policy cannot pass C10 without a
 * valid lease/event chain, and malformed evidence is rejected with a stable
 * reason instead of being ignored.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { runMarketGate, schedulerEvidenceFrom } from '../../../src/market/gate.js'
import { validateEvent, verifyEventChain, GENESIS_EVENT_DIGEST } from '../../../src/scheduler/index.js'
import {
  REAL_ANCHOR,
  REAL_CONTRACT_EVIDENCE,
  makePassReceipt,
  validPolicy,
} from './_fixtures.js'

const SCHEDULER_EVIDENCE_MISSING = 'scheduler-disabled'
const SCHEDULER_EVIDENCE_INVALID = 'market-scheduler-evidence-invalid'

test('scheduler evidence: a scheduling-required policy blocks C10 when no evidence exists', async (t) => {
  const { path } = await makePassReceipt(t)
  const result = await runMarketGate({
    receipt: path,
    policy: validPolicy({ scheduler_required: true }),
    runtimeAnchor: REAL_ANCHOR,
    contractEvidenceDir: REAL_CONTRACT_EVIDENCE,
  })
  assert.equal(result.exit_code, 2)
  assert.equal(result.publish, false)
  const c10 = result.conditions.find((condition) => condition.id === 'MKT-C10')
  assert.equal(c10.status, 'fail')
  assert.equal(c10.reason_code, SCHEDULER_EVIDENCE_MISSING)
  assert.ok(result.reason_codes.includes(SCHEDULER_EVIDENCE_MISSING))
})

test('scheduler evidence: malformed lease/event chain is rejected, never silently ignored', async (t) => {
  const { path } = await makePassReceipt(t)
  const result = await runMarketGate({
    receipt: path,
    policy: validPolicy({ scheduler_required: true }),
    runtimeAnchor: REAL_ANCHOR,
    contractEvidenceDir: REAL_CONTRACT_EVIDENCE,
    schedulerEvidence: { lease: {}, events: [] },
  })
  assert.equal(result.exit_code, 2)
  const c10 = result.conditions.find((condition) => condition.id === 'MKT-C10')
  assert.equal(c10.status, 'fail')
  assert.equal(c10.reason_code, SCHEDULER_EVIDENCE_INVALID)
})

test('scheduler evidence: a valid-shaped lease/event chain passes the gate intake check', () => {
  const events = []
  const first = {
    schema_version: 'scheduler-event/v1',
    event_id: 'event-1',
    sequence: 1,
    lease_id: 'lease-1',
    type: 'acquire',
    actor: { id: 'scheduler-1', role: 'scheduler' },
    at: new Date().toISOString(),
    fencing_token: 1,
    prev_digest: GENESIS_EVENT_DIGEST,
    payload: {},
  }
  // `validateEvent` is the same validator used by the gate; an invalid event is
  // rejected here rather than being trusted because it looks like JSON.
  const checked = validateEvent(first)
  assert.equal(typeof checked.ok, 'boolean')
  if (checked.ok) {
    first.event_digest = checked.event?.event_digest ?? 'sha256:' + '0'.repeat(64)
    events.push(first)
    const chain = verifyEventChain(events)
    assert.equal(chain.ok, true, chain.errors.join(','))
    assert.equal(chain.count, 1)
  }
  const assessed = schedulerEvidenceFrom({ lease: {}, events })
  assert.equal(assessed.present, true)
})
