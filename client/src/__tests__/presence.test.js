/**
 * presence.test.js — PresenceManager + STATUS_* constants
 *
 * Covers:
 *   • join() broadcasts an initial presence frame over the fabric
 *   • Heartbeat frames from remote peers update the roster
 *   • Leave frames remove peers from the roster
 *   • The 'roster' event fires with the current full roster (including self)
 *   • Unknown channel frames are ignored (no roster contamination)
 *   • Self-echo (same accountId) is ignored
 *   • Peer GC removes stale peers after TIMEOUT_MS
 *   • setStatus() updates local status and re-broadcasts
 *   • STATUS_* constants are exported correctly
 *   • fullRoster includes self with isSelf:true
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  PresenceManager,
  STATUS_ONLINE,
  STATUS_AWAY,
  STATUS_DND,
  STATUS_IN_CALL,
} from '../presence.js'

// ── Fake FabricClient ─────────────────────────────────────────────────────────

class FakeFabric extends EventTarget {
  constructor() {
    super()
    this.sent = []
  }

  send(data) { this.sent.push(data) }
  sendTo(/* peerId, data */) {}

  /** Simulate incoming message from a remote peer */
  _deliver(from, data) {
    this.dispatchEvent(new CustomEvent('message', { detail: { from, data } }))
  }

  /** Simulate a peer state change */
  _peerState(peerId, state) {
    this.dispatchEvent(new CustomEvent('state', { detail: { peerId, state } }))
  }
}

function makePresence(opts = {}) {
  const fabric = new FakeFabric()
  const pm = new PresenceManager({
    fabric,
    localIdentity: { accountId: 'alice', displayName: 'Alice', isGuest: false },
    ...opts,
  })
  return { pm, fabric }
}

function presenceFrame(accountId, displayName, type = 'join', extras = {}) {
  return JSON.stringify({
    channel: 'presence',
    payload: {
      accountId,
      displayName,
      color: 'hsl(100, 65%, 50%)',
      online: true,
      status: STATUS_ONLINE,
      statusText: '',
      isGuest: false,
      ts: Date.now(),
      type,
      ...extras,
    },
  })
}

beforeEach(() => {
  vi.useFakeTimers()
  try { localStorage.clear() } catch { /* jsdom */ }
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('STATUS_* constants', () => {
  it('STATUS_ONLINE is "online"', () => expect(STATUS_ONLINE).toBe('online'))
  it('STATUS_AWAY is "away"',    () => expect(STATUS_AWAY).toBe('away'))
  it('STATUS_DND is "dnd"',      () => expect(STATUS_DND).toBe('dnd'))
  it('STATUS_IN_CALL is "in-a-call"', () => expect(STATUS_IN_CALL).toBe('in-a-call'))
})

describe('PresenceManager — join() and heartbeat', () => {
  it('join() immediately sends a presence frame', () => {
    const { pm, fabric } = makePresence()
    pm.join()

    expect(fabric.sent).toHaveLength(1)
    const frame = JSON.parse(fabric.sent[0])
    expect(frame.channel).toBe('presence')
    expect(frame.payload.type).toBe('join')
    expect(frame.payload.accountId).toBe('alice')
    pm.leave()
  })

  it('heartbeat is sent repeatedly on interval', () => {
    const { pm, fabric } = makePresence()
    pm.join()
    const initial = fabric.sent.length

    vi.advanceTimersByTime(10_000)
    expect(fabric.sent.length).toBeGreaterThan(initial)
    pm.leave()
  })

  it('leave() stops the heartbeat timer', () => {
    const { pm, fabric } = makePresence()
    pm.join()
    pm.leave()
    const count = fabric.sent.length

    vi.advanceTimersByTime(30_000)
    // No more sends after leave
    expect(fabric.sent.length).toBe(count)
  })
})

describe('PresenceManager — roster updates', () => {
  it('remote heartbeat frame adds peer to roster', () => {
    const { pm, fabric } = makePresence()
    pm.join()

    const rosterEvents = []
    pm.addEventListener('roster', ({ detail }) => rosterEvents.push(detail))

    fabric._deliver('bob-peer', presenceFrame('bob', 'Bob'))

    expect(rosterEvents).toHaveLength(1)
    const roster = rosterEvents[0]
    const bob = roster.find(p => p.accountId === 'bob')
    expect(bob).toBeTruthy()
    expect(bob.displayName).toBe('Bob')
    pm.leave()
  })

  it('self-echo (same accountId) is ignored', () => {
    const { pm, fabric } = makePresence()
    pm.join()

    const rosterEvents = []
    pm.addEventListener('roster', ({ detail }) => rosterEvents.push(detail))

    // Alice receives a frame from herself (server echo)
    fabric._deliver('alice-peer', presenceFrame('alice', 'Alice'))

    expect(rosterEvents).toHaveLength(0)
    pm.leave()
  })

  it('leave frame removes peer from roster', () => {
    const { pm, fabric } = makePresence()
    pm.join()

    // Add bob
    fabric._deliver('bob-peer', presenceFrame('bob', 'Bob', 'join'))

    const rosterEvents = []
    pm.addEventListener('roster', ({ detail }) => rosterEvents.push(detail))

    // Bob leaves
    fabric._deliver('bob-peer', presenceFrame('bob', 'Bob', 'leave'))

    const lastRoster = rosterEvents[rosterEvents.length - 1] || pm.fullRoster
    expect(lastRoster.find(p => p.accountId === 'bob')).toBeUndefined()
    pm.leave()
  })

  it('unknown channel frames are ignored', () => {
    const { pm, fabric } = makePresence()
    pm.join()

    const rosterEvents = []
    pm.addEventListener('roster', ({ detail }) => rosterEvents.push(detail))

    // Message on a different channel
    fabric._deliver('bob-peer', JSON.stringify({
      channel: 'cursors',   // wrong channel
      payload: { accountId: 'bob', displayName: 'Bob', type: 'join' },
    }))

    expect(rosterEvents).toHaveLength(0)
    pm.leave()
  })

  it('non-JSON messages are silently ignored', () => {
    const { pm, fabric } = makePresence()
    pm.join()

    const rosterEvents = []
    pm.addEventListener('roster', ({ detail }) => rosterEvents.push(detail))

    fabric._deliver('bob-peer', 'not-json')

    expect(rosterEvents).toHaveLength(0)
    pm.leave()
  })

  it('fullRoster includes self with isSelf:true', () => {
    const { pm } = makePresence()
    pm.join()

    const full = pm.fullRoster
    const self = full.find(p => p.isSelf)
    expect(self).toBeTruthy()
    expect(self.accountId).toBe('alice')
    pm.leave()
  })

  it('roster getter excludes self', () => {
    const { pm, fabric } = makePresence()
    pm.join()

    fabric._deliver('bob-peer', presenceFrame('bob', 'Bob'))

    const r = pm.roster
    expect(r.find(p => p.accountId === 'alice')).toBeUndefined()
    expect(r.find(p => p.accountId === 'bob')).toBeTruthy()
    pm.leave()
  })
})

describe('PresenceManager — GC / timeout', () => {
  it('stale peer is removed after TIMEOUT_MS without heartbeat', () => {
    const { pm, fabric } = makePresence()
    pm.join()

    fabric._deliver('bob-peer', presenceFrame('bob', 'Bob'))

    const rosterBefore = pm.roster
    expect(rosterBefore.find(p => p.accountId === 'bob')).toBeTruthy()

    // Advance time past the 25 s timeout + one GC tick (10 s)
    vi.advanceTimersByTime(36_000)

    const rosterAfter = pm.roster
    expect(rosterAfter.find(p => p.accountId === 'bob')).toBeUndefined()
    pm.leave()
  })

  it('peer re-heartbeating is not GC-ed', () => {
    const { pm, fabric } = makePresence()
    pm.join()

    fabric._deliver('bob-peer', presenceFrame('bob', 'Bob'))

    // Advance 20 s, deliver heartbeat, advance another 20 s
    vi.advanceTimersByTime(20_000)
    fabric._deliver('bob-peer', presenceFrame('bob', 'Bob'))
    vi.advanceTimersByTime(20_000)

    const r = pm.roster
    expect(r.find(p => p.accountId === 'bob')).toBeTruthy()
    pm.leave()
  })
})

describe('PresenceManager — setStatus()', () => {
  it('setStatus() updates local status and re-broadcasts immediately', () => {
    const { pm, fabric } = makePresence()
    pm.join()

    const before = fabric.sent.length
    pm.setStatus(STATUS_AWAY, 'lunch')

    // A new frame should have been sent
    expect(fabric.sent.length).toBeGreaterThan(before)
    const latest = JSON.parse(fabric.sent[fabric.sent.length - 1])
    expect(latest.payload.status).toBe(STATUS_AWAY)
    expect(latest.payload.statusText).toBe('lunch')
    pm.leave()
  })

  it('setStatus() with no args defaults to STATUS_ONLINE', () => {
    const { pm, fabric } = makePresence()
    pm.join()
    pm.setStatus()

    const latest = JSON.parse(fabric.sent[fabric.sent.length - 1])
    expect(latest.payload.status).toBe(STATUS_ONLINE)
    pm.leave()
  })
})

describe('PresenceManager — state event re-broadcast', () => {
  it('re-broadcasts on new peer connected event', () => {
    const { pm, fabric } = makePresence()
    pm.join()

    const before = fabric.sent.length
    fabric._peerState('bob-peer', 'connected')

    expect(fabric.sent.length).toBeGreaterThan(before)
    pm.leave()
  })

  it('re-broadcasts on relay state event', () => {
    const { pm, fabric } = makePresence()
    pm.join()

    const before = fabric.sent.length
    fabric._peerState('bob-peer', 'relay')

    expect(fabric.sent.length).toBeGreaterThan(before)
    pm.leave()
  })

  it('does not re-broadcast on disconnected state', () => {
    const { pm, fabric } = makePresence()
    pm.join()

    const before = fabric.sent.length
    fabric._peerState('bob-peer', 'disconnected')

    expect(fabric.sent.length).toBe(before)
    pm.leave()
  })
})
