/**
 * fabricSignaling.test.js — tests for the joinSignalingSession transport
 * selection and the real-network SignalingClient bridge.
 *
 * We stub out WebSocket and BroadcastChannel so no real network is required.
 * The key assertions:
 *   • When window.__VULOS_ENDPOINTS__.signalingUrl is set, the 'ws' transport
 *     is used (SignalingClient is instantiated).
 *   • When no URL is available, the 'bc-stub' transport is used (BC fallback).
 *   • networkSession bridges peer-join / peer-leave / message correctly from
 *     the SignalingClient 'signal' CustomEvent to the session Emitter.
 *   • The SignalingError is thrown when neither transport is available.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

// ─── WebSocket class stub ────────────────────────────────────────────────────

/**
 * FakeWebSocket must be a real class (not an arrow function) because SignalingClient
 * calls `new WebSocket(url)`. We track the most-recent instance via `.lastInstance`
 * so tests can drive open/message events after construction.
 */
class FakeWebSocket {
  static OPEN = 1
  static CONNECTING = 0
  static lastInstance = null

  constructor(url) {
    this.url = url
    this.readyState = FakeWebSocket.CONNECTING
    this._listeners = {}
    this.send = vi.fn()
    this.close = vi.fn()
    FakeWebSocket.lastInstance = this
  }

  addEventListener(evt, fn) {
    if (!this._listeners[evt]) this._listeners[evt] = []
    this._listeners[evt].push(fn)
  }

  _fire(evt, data) {
    ;(this._listeners[evt] || []).forEach((fn) => fn(data))
  }
}

// ─── BroadcastChannel stub ───────────────────────────────────────────────────

function makeBCStub() {
  const channels = {} // name → [stub, ...]

  function BroadcastChannelStub(name) {
    if (!channels[name]) channels[name] = []
    this._name = name
    this.onmessage = null
    this.postMessage = vi.fn((data) => {
      for (const peer of channels[name]) {
        if (peer !== this && peer.onmessage) peer.onmessage({ data })
      }
    })
    this.close = vi.fn()
    channels[name].push(this)
  }

  return { BroadcastChannelStub, channels }
}

// ─── Module refresh helper ────────────────────────────────────────────────────

async function freshFabricSignaling() {
  vi.resetModules()
  return import('../call/fabricSignaling.js')
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('joinSignalingSession — transport selection', () => {
  let origWS
  let origBC
  let origLocation

  beforeEach(() => {
    origWS = globalThis.WebSocket
    origBC = globalThis.BroadcastChannel
    FakeWebSocket.lastInstance = null
    if (typeof window !== 'undefined') {
      delete window.__VULOS_ENDPOINTS__
      origLocation = window.location
    }
  })

  afterEach(() => {
    globalThis.WebSocket = origWS
    globalThis.BroadcastChannel = origBC
    if (typeof window !== 'undefined') {
      delete window.__VULOS_ENDPOINTS__
      if (origLocation) {
        Object.defineProperty(globalThis.window, 'location', {
          value: origLocation, configurable: true,
        })
      }
    }
    vi.restoreAllMocks()
  })

  it('uses bc-stub when no signalingUrl is resolvable', async () => {
    const { BroadcastChannelStub } = makeBCStub()
    globalThis.BroadcastChannel = BroadcastChannelStub

    // jsdom has window.location.hostname = 'localhost' which would derive a WS URL.
    // Override with empty hostname for this test.
    if (globalThis.window) {
      Object.defineProperty(globalThis.window, 'location', {
        value: { protocol: 'http:', host: '', hostname: '' },
        configurable: true,
      })
    }

    const { joinSignalingSession } = await freshFabricSignaling()
    const session = await joinSignalingSession('room-1', null)
    expect(session.transport).toBe('bc-stub')
    session.close()
  })

  it('uses ws transport when __VULOS_ENDPOINTS__.signalingUrl is set', async () => {
    globalThis.WebSocket = FakeWebSocket

    if (typeof window !== 'undefined') {
      window.__VULOS_ENDPOINTS__ = { signalingUrl: 'ws://localhost:9999/api/peering/stream' }
    }

    const { joinSignalingSession } = await freshFabricSignaling()
    const session = await joinSignalingSession('room-ws', { peerId: 'peer-a' })
    expect(session.transport).toBe('ws')
    expect(FakeWebSocket.lastInstance).not.toBeNull()
    session.close()
  })

  it('bridges peer-join from SignalingClient signal event', async () => {
    globalThis.WebSocket = FakeWebSocket

    if (typeof window !== 'undefined') {
      window.__VULOS_ENDPOINTS__ = { signalingUrl: 'ws://localhost:9999/api/peering/stream' }
    }

    const { joinSignalingSession } = await freshFabricSignaling()
    const session = await joinSignalingSession('room-join', { peerId: 'local' })
    const ws = FakeWebSocket.lastInstance

    const joinCb = vi.fn()
    session.on('peer-join', joinCb)

    // Simulate the server delivering a 'join' signal frame.
    ws._fire('message', {
      data: JSON.stringify({
        channel: 'signal',
        from: 'remote-peer',
        payload: {
          type: 'join',
          session: 'room-join',
          identity: { name: 'Alice' },
        },
      }),
    })

    expect(joinCb).toHaveBeenCalledWith('remote-peer', { name: 'Alice' })
    session.close()
  })

  it('bridges peer-leave from SignalingClient signal event', async () => {
    globalThis.WebSocket = FakeWebSocket

    if (typeof window !== 'undefined') {
      window.__VULOS_ENDPOINTS__ = { signalingUrl: 'ws://localhost:9999/api/peering/stream' }
    }

    const { joinSignalingSession } = await freshFabricSignaling()
    const session = await joinSignalingSession('room-leave', { peerId: 'local' })
    const ws = FakeWebSocket.lastInstance

    const leaveCb = vi.fn()
    session.on('peer-leave', leaveCb)

    // First add the peer via join.
    ws._fire('message', {
      data: JSON.stringify({
        channel: 'signal',
        from: 'remote-peer',
        payload: { type: 'join', session: 'room-leave' },
      }),
    })
    // Then remove via leave.
    ws._fire('message', {
      data: JSON.stringify({
        channel: 'signal',
        from: 'remote-peer',
        payload: { type: 'leave', session: 'room-leave' },
      }),
    })

    expect(leaveCb).toHaveBeenCalledWith('remote-peer')
    session.close()
  })

  it('bridges sdp/ice messages to the message event', async () => {
    globalThis.WebSocket = FakeWebSocket

    if (typeof window !== 'undefined') {
      window.__VULOS_ENDPOINTS__ = { signalingUrl: 'ws://localhost:9999/api/peering/stream' }
    }

    const { joinSignalingSession } = await freshFabricSignaling()
    const session = await joinSignalingSession('room-sdp', { peerId: 'local' })
    const ws = FakeWebSocket.lastInstance

    const msgCb = vi.fn()
    session.on('message', msgCb)

    ws._fire('message', {
      data: JSON.stringify({
        channel: 'signal',
        from: 'remote-peer',
        payload: {
          type: 'sdp',
          session: 'room-sdp',
          to: 'local',
          data: { type: 'offer', sdp: 'v=0...' },
        },
      }),
    })

    expect(msgCb).toHaveBeenCalledTimes(1)
    const msg = msgCb.mock.calls[0][0]
    expect(msg.kind).toBe('sdp')
    expect(msg.from).toBe('remote-peer')
    expect(msg.data.sdp).toBe('v=0...')
    session.close()
  })

  it('throws SignalingError when neither WS URL nor BroadcastChannel is available', async () => {
    const savedWindow = globalThis.window
    globalThis.window = undefined
    globalThis.BroadcastChannel = undefined

    const { joinSignalingSession } = await freshFabricSignaling()
    await expect(joinSignalingSession('x', null)).rejects.toMatchObject({
      name: 'SignalingError',
      code: 'NO_TRANSPORT',
    })

    globalThis.window = savedWindow
    globalThis.BroadcastChannel = origBC
  })
})
