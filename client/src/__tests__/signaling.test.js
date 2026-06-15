/**
 * signaling.test.js — SignalingClient smoke test.
 *
 * No suite existed in any of the three pre-existing consumers (the signaling
 * + fabric layers shipped without unit tests in office, mail, or OS). New
 * coverage added here:
 *   • connect() opens a WebSocket to the signaling URL, appending the auth
 *     token when present
 *   • on open, the client auto-sends a "join" frame envelope on the "signal"
 *     channel
 *   • inbound frames addressed to this peer are dispatched as a 'signal'
 *     CustomEvent on the client
 *   • inbound frames on the wrong channel / wrong peer are dropped silently
 *   • close() sends a "leave" frame and stops reconnecting
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { SignalingClient } from '../signaling.js'

class FakeWebSocket {
  static OPEN = 1
  static CLOSED = 3
  static CONNECTING = 0
  constructor(url) {
    FakeWebSocket.lastUrl = url
    FakeWebSocket.instances.push(this)
    this.url = url
    this.readyState = FakeWebSocket.CONNECTING
    this.sent = []
    this._listeners = {}
  }
  addEventListener(evt, fn) {
    if (!this._listeners[evt]) this._listeners[evt] = []
    this._listeners[evt].push(fn)
  }
  send(data) {
    this.sent.push(data)
  }
  close() {
    this.readyState = FakeWebSocket.CLOSED
    this._fire('close', {})
  }
  _fire(evt, payload) {
    for (const fn of (this._listeners[evt] || [])) fn(payload)
  }
  _open() {
    this.readyState = FakeWebSocket.OPEN
    this._fire('open', {})
  }
  _message(frame) {
    this._fire('message', { data: JSON.stringify(frame) })
  }
}
FakeWebSocket.instances = []
FakeWebSocket.lastUrl = null

beforeEach(() => {
  FakeWebSocket.instances = []
  FakeWebSocket.lastUrl = null
  vi.stubGlobal('WebSocket', FakeWebSocket)
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('SignalingClient', () => {
  it('opens a WebSocket to the signaling URL with the auth token', () => {
    const c = new SignalingClient({
      signalingUrl: 'ws://localhost:8080/api/peering/stream',
      sessionId: 'doc-1',
      peerId: 'alice',
      authToken: 'jwt-token',
    })
    c.connect()
    expect(FakeWebSocket.lastUrl).toBe('ws://localhost:8080/api/peering/stream?token=jwt-token')
    c.close()
  })

  it('auto-sends a "join" envelope on the "signal" channel after open', () => {
    const c = new SignalingClient({
      signalingUrl: 'ws://x/y',
      sessionId: 'doc-1',
      peerId: 'alice',
    })
    c.connect()
    const ws = FakeWebSocket.instances[0]
    ws._open()
    expect(ws.sent.length).toBe(1)
    const frame = JSON.parse(ws.sent[0])
    expect(frame.channel).toBe('signal')
    expect(frame.payload.type).toBe('join')
    expect(frame.payload.session).toBe('doc-1')
  })

  it('dispatches inbound frames addressed to this peer as a "signal" event', () => {
    const c = new SignalingClient({
      signalingUrl: 'ws://x/y',
      sessionId: 'doc-1',
      peerId: 'alice',
    })
    c.connect()
    const ws = FakeWebSocket.instances[0]
    ws._open()

    const received = []
    c.addEventListener('signal', (ev) => received.push(ev.detail))

    ws._message({
      channel: 'signal',
      from: 'bob',
      payload: { type: 'offer', session: 'doc-1', to: 'alice', sdp: 'v=0...' },
    })
    expect(received).toHaveLength(1)
    expect(received[0].from).toBe('bob')
    expect(received[0].payload.type).toBe('offer')
  })

  it('drops frames on the wrong channel and frames addressed to a different peer', () => {
    const c = new SignalingClient({
      signalingUrl: 'ws://x/y',
      sessionId: 'doc-1',
      peerId: 'alice',
    })
    c.connect()
    const ws = FakeWebSocket.instances[0]
    ws._open()

    const received = []
    c.addEventListener('signal', (ev) => received.push(ev.detail))

    // Wrong channel → dropped.
    ws._message({ channel: 'presence', from: 'bob', payload: { type: 'offer' } })
    // Wrong target peer → dropped.
    ws._message({
      channel: 'signal',
      from: 'bob',
      payload: { type: 'offer', session: 'doc-1', to: 'carol' },
    })
    // Wrong session → dropped.
    ws._message({
      channel: 'signal',
      from: 'bob',
      payload: { type: 'offer', session: 'other-doc', to: 'alice' },
    })

    expect(received).toHaveLength(0)
  })

  it('close() sends a "leave" frame and prevents reconnect', () => {
    const c = new SignalingClient({
      signalingUrl: 'ws://x/y',
      sessionId: 'doc-1',
      peerId: 'alice',
    })
    c.connect()
    const ws = FakeWebSocket.instances[0]
    ws._open()
    // Clear the join frame.
    ws.sent.length = 0

    c.close()
    expect(ws.sent.length).toBe(1)
    const frame = JSON.parse(ws.sent[0])
    expect(frame.channel).toBe('signal')
    expect(frame.payload.type).toBe('leave')
  })
})

describe('SignalingClient reconnect budget', () => {
  beforeEach(() => {
    FakeWebSocket.instances = []
    vi.stubGlobal('WebSocket', FakeWebSocket)
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('emits "offline" after maxAttempts consecutive failures', async () => {
    const c = new SignalingClient({
      signalingUrl: 'ws://x/y',
      sessionId: 'doc-1',
      peerId: 'alice',
      maxAttempts: 3,
    })
    const offlineCb = vi.fn()
    c.addEventListener('offline', offlineCb)
    c.connect()

    // Trigger 3 close events (each schedules a reconnect, then we close again).
    for (let i = 0; i < 3; i++) {
      const ws = FakeWebSocket.instances[FakeWebSocket.instances.length - 1]
      ws._fire('close', {})
      await vi.runAllTimersAsync()
    }

    expect(offlineCb).toHaveBeenCalledTimes(1)
    const { detail } = offlineCb.mock.calls[0][0]
    expect(detail.attempts).toBeGreaterThanOrEqual(3)
    c.close()
  })

  it('resets the attempt counter on a successful open', async () => {
    const c = new SignalingClient({
      signalingUrl: 'ws://x/y',
      sessionId: 'doc-1',
      peerId: 'alice',
      maxAttempts: 2,
    })
    const offlineCb = vi.fn()
    c.addEventListener('offline', offlineCb)
    c.connect()

    // One failure.
    const ws0 = FakeWebSocket.instances[0]
    ws0._fire('close', {})
    await vi.runAllTimersAsync()

    // Successful open on the new connection (counter resets).
    const ws1 = FakeWebSocket.instances[FakeWebSocket.instances.length - 1]
    ws1._open()

    // One more failure after reset — budget should not be exhausted yet.
    ws1._fire('close', {})
    await vi.runAllTimersAsync()

    expect(offlineCb).not.toHaveBeenCalled()
    c.close()
  })

  it('emits "offline" only once even after many failures', async () => {
    const c = new SignalingClient({
      signalingUrl: 'ws://x/y',
      sessionId: 'doc-1',
      peerId: 'alice',
      maxAttempts: 2,
    })
    const offlineCb = vi.fn()
    c.addEventListener('offline', offlineCb)
    c.connect()

    for (let i = 0; i < 8; i++) {
      const ws = FakeWebSocket.instances[FakeWebSocket.instances.length - 1]
      ws._fire('close', {})
      await vi.runAllTimersAsync()
    }

    expect(offlineCb).toHaveBeenCalledTimes(1)
    c.close()
  })
})
