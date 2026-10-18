/**
 * `scheduler-event/v1` append-only hash chain, tamper detection and payload
 * authority rejection.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  GENESIS_EVENT_DIGEST,
  buildEvent,
  eventDigest,
  rebuildLeaseTimeline,
  validateEvent,
  validateEventBinding,
  validateEventPayload,
  verifyEventChain,
} from '../../../src/scheduler/index.js'

const DIGEST = 'sha256:' + 'a'.repeat(64)
const BINDING = {
  schedule_id: 'sched-1',
  plan_digest: 'sha256:' + 'b'.repeat(64),
  policy_digest: 'sha256:' + 'c'.repeat(64),
  target_digest: 'sha256:' + 'd'.repeat(64),
}

function eventInput(overrides = {}) {
  return {
    eventId: 'evt-1',
    sequence: 1,
    leaseId: 'lease-1',
    type: 'acquire',
    actor: { id: 'scheduler', role: 'scheduler' },
    at: '2026-10-19T00:00:00.000Z',
    fencingToken: 1,
    prevDigest: GENESIS_EVENT_DIGEST,
    ...overrides,
  }
}

test('events: buildEvent computes a canonical event digest', () => {
  const built = buildEvent(eventInput({ binding: BINDING, payload: { ttl_ms: 60_000 } }))
  assert.equal(built.ok, true)
  assert.equal(built.event.schema_version, 'scheduler-event/v1')
  assert.match(built.event.event_digest, /^sha256:[0-9a-f]{64}$/)
  assert.equal(built.event.event_digest, eventDigest(built.event))
  assert.equal(Object.isFrozen(built.event), true)
  assert.equal(validateEvent(built.event).ok, true)
})

test('events: digest covers prev_digest and payload (tamper detection)', () => {
  const first = buildEvent(eventInput())
  const second = buildEvent(eventInput({
    eventId: 'evt-2', sequence: 2, type: 'renew', prevDigest: first.event.event_digest,
    fencingToken: 1, payload: { heartbeat_seq: 1 },
  }))
  assert.equal(second.ok, true)
  const chain = verifyEventChain([first.event, second.event])
  assert.equal(chain.ok, true, chain.errors.join(','))
  assert.equal(chain.count, 2)
  assert.equal(chain.last_digest, second.event.event_digest)

  const tampered = structuredClone(second.event)
  tampered.payload.heartbeat_seq = 2
  const bad = verifyEventChain([first.event, tampered])
  assert.equal(bad.ok, false)
  assert.ok(bad.errors.some((error) => error.includes('event-digest-mismatch')))

  const brokenLink = structuredClone(second.event)
  brokenLink.prev_digest = GENESIS_EVENT_DIGEST
  const broken = verifyEventChain([first.event, brokenLink])
  assert.equal(broken.ok, false)
  assert.ok(broken.errors.some((error) => error.includes('event-prev-digest-mismatch')))
})

test('events: verifyEventChain enforces genesis, contiguous sequence and schema', () => {
  const first = buildEvent(eventInput()).event
  assert.equal(verifyEventChain([first]).ok, true)
  assert.equal(verifyEventChain([first], { requireGenesis: false }).ok, true)

  const noGenesis = structuredClone(first)
  noGenesis.prev_digest = DIGEST
  // digest no longer matches -> both genesis and digest errors
  const result = verifyEventChain([noGenesis])
  assert.equal(result.ok, false)
  assert.ok(result.errors.some((error) => error.includes('event-chain-missing-genesis')))

  const gapEvent = buildEvent(eventInput({
    eventId: 'evt-7', sequence: 7, type: 'release', prevDigest: first.event_digest,
    fencingToken: 1,
  }))
  const gap = verifyEventChain([first, gapEvent.event])
  assert.equal(gap.ok, false)
  assert.ok(gap.errors.some((error) => error.includes('event-sequence-gap')))

  const badSchema = structuredClone(buildEvent(eventInput()).event)
  badSchema.schema_version = 'scheduler-event/v2'
  assert.equal(validateEvent(badSchema).ok, false)

  assert.equal(validateEvent({}).ok, false)
  assert.equal(verifyEventChain('nope').ok, false)
})

test('events: authority fields are rejected in payloads and bindings must bind plan/policy/target', () => {
  assert.deepEqual(validateEventPayload({ ttl_ms: 1 }), [])
  assert.ok(validateEventPayload({ verdict: 'pass' }).includes('event-payload-authority-field:verdict'))
  assert.ok(validateEventPayload({ nested: { gate_decision: 'pass' } })
    .includes('event-payload-authority-field:nested.gate_decision'))
  assert.ok(validateEventPayload({ required: ['x'] }).length > 0)

  const built = buildEvent(eventInput({ payload: { verdict: 'pass' } }))
  assert.equal(built.ok, false)
  assert.ok(built.errors.some((error) => error.includes('event-payload-authority-field')))

  assert.deepEqual(validateEventBinding(BINDING), [])
  assert.ok(validateEventBinding({ ...BINDING, policy_digest: undefined })
    .includes('event-binding-policy-digest-invalid'))
  assert.ok(validateEventBinding({ ...BINDING, extra: 1 })
    .includes('event-binding-unknown-field:extra'))
})

test('events: rebuildLeaseTimeline filters one lease without trusting input order', () => {
  const acquire = buildEvent(eventInput()).event
  const other = buildEvent(eventInput({
    eventId: 'evt-other', sequence: 2, leaseId: 'lease-2', type: 'acquire',
    prevDigest: acquire.event_digest, fencingToken: 1,
  })).event
  const renew = buildEvent(eventInput({
    eventId: 'evt-renew', sequence: 3, type: 'renew', prevDigest: other.event_digest, fencingToken: 1,
  })).event
  const rebuilt = rebuildLeaseTimeline([acquire, other, renew], 'lease-1')
  assert.equal(rebuilt.ok, true)
  assert.deepEqual(rebuilt.timeline.map((event) => event.type), ['acquire', 'renew'])
})
