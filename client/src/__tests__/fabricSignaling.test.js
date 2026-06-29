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

// ── Call-path signing (HIGH audit fix #2) ─────────────────────────────────────

describe('networkSession (call path) — E2E identity binding + DTLS pinning', () => {
  let origWS
  let origBC

  beforeEach(() => {
    origWS = globalThis.WebSocket
    origBC = globalThis.BroadcastChannel
    FakeWebSocket.lastInstance = null
    if (typeof window !== 'undefined') {
      window.__VULOS_ENDPOINTS__ = { signalingUrl: 'ws://localhost:9999/api/peering/stream' }
    }
    globalThis.WebSocket = FakeWebSocket
  })

  afterEach(() => {
    globalThis.WebSocket = origWS
    globalThis.BroadcastChannel = origBC
    if (typeof window !== 'undefined') delete window.__VULOS_ENDPOINTS__
    vi.restoreAllMocks()
  })

  it('publishes a depositPubKey in the join frame (per-session ECDSA key)', async () => {
    const { joinSignalingSession } = await freshFabricSignaling()
    const session = await joinSignalingSession('room-sign', { peerId: 'caller' })
    const ws = FakeWebSocket.lastInstance

    // SignalingClient._send() checks this._ws.readyState !== WebSocket.OPEN before
    // sending; we must set readyState = OPEN before firing 'open' so _send works.
    ws.readyState = FakeWebSocket.OPEN
    ws._fire('open', {})
    // Allow the async signFrame (sign 'join' via WebCrypto threadpool) to complete
    await new Promise(r => setTimeout(r, 30))

    // The join frame must carry a non-null depositPubKey.
    // SignalingClient sends the initial join via _send (synchronous, no signing)
    // and networkSession sends a second join via sc.signal (signed, async).
    // Either may carry depositPubKey; find the one that does.
    const joinRaw = ws.send.mock.calls.find(([raw]) => {
      try { return JSON.parse(raw).payload?.depositPubKey != null } catch { return false }
    })
    expect(joinRaw).toBeTruthy()
    const joinFrame = JSON.parse(joinRaw[0])
    expect(typeof joinFrame.payload.depositPubKey).toBe('string')
    expect(joinFrame.payload.depositPubKey.length).toBeGreaterThan(0)

    session.close()
  })

  it('outgoing send() includes pubKey and sig on the WS frame', async () => {
    const { joinSignalingSession } = await freshFabricSignaling()
    const session = await joinSignalingSession('room-sign2', { peerId: 'caller' })
    const ws = FakeWebSocket.lastInstance
    ws.readyState = FakeWebSocket.OPEN
    ws._fire('open', {})

    // Allow join signing to complete, then clear so only the sdp frame is visible
    await new Promise(r => setTimeout(r, 30))
    ws.send.mockClear()

    // Call layer sends an sdp message
    session.send({
      kind: 'sdp',
      to: 'remote-peer',
      data: { type: 'offer', sdp: 'v=0 call-offer' },
    })

    // signFrame is async (WebCrypto) — wait for the signed frame to land
    await new Promise(r => setTimeout(r, 30))

    expect(ws.send).toHaveBeenCalled()
    const raw = ws.send.mock.calls[ws.send.mock.calls.length - 1][0]
    const frame = JSON.parse(raw)
    const p = frame.payload

    // Must carry a nonce and signature (signed frame)
    expect(typeof p.nonce).toBe('string')
    expect(typeof p.sig).toBe('string')
    expect(p.sig.length).toBeGreaterThan(0)
    // Must publish the session pubkey
    expect(typeof p.pubKey).toBe('string')
    expect(p.pubKey.length).toBeGreaterThan(0)
    // SDP mirrored to top level for DTLS fingerprint pinning
    expect(p.sdp).toBe('v=0 call-offer')

    session.close()
  })

  it('outgoing offer signature verifies against the session pubkey', async () => {
    const { joinSignalingSession } = await freshFabricSignaling()
    const session = await joinSignalingSession('room-sign3', { peerId: 'caller' })
    const ws = FakeWebSocket.lastInstance
    ws.readyState = FakeWebSocket.OPEN
    ws._fire('open', {})
    await new Promise(r => setTimeout(r, 30))
    ws.send.mockClear()

    const testSdp = 'v=0\r\na=fingerprint:sha-256 AA:BB:CC:DD:EE:FF'
    session.send({ kind: 'sdp', to: 'remote', data: { type: 'offer', sdp: testSdp } })
    await new Promise(r => setTimeout(r, 30))

    const raw = ws.send.mock.calls[ws.send.mock.calls.length - 1][0]
    const { payload: p } = JSON.parse(raw)

    // Import the session pubkey from the frame
    const rawPub = Uint8Array.from(atob(p.pubKey), c => c.charCodeAt(0))
    const verifyKey = await crypto.subtle.importKey(
      'raw', rawPub, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'],
    )

    // Reconstruct the exact canonical message that was signed
    const canonicalMsg = JSON.stringify({
      type: p.type,
      session: 'room-sign3',
      to: 'remote',
      from: 'caller',
      nonce: p.nonce,
      sdp: p.sdp,
      pubKey: p.pubKey,
    })
    const sigBuf = Uint8Array.from(atob(p.sig), c => c.charCodeAt(0))
    const msgBuf = new TextEncoder().encode(canonicalMsg)
    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, verifyKey, sigBuf, msgBuf,
    )

    expect(valid).toBe(true)
    session.close()
  })
})
