/**
 * fabric.security.test.js — signaling message security validation
 *
 * Covers:
 *   • Self-echo suppression (frames from own peerId are ignored)
 *   • Malformed frames (non-JSON, missing payload) are rejected silently
 *   • Cross-session isolation — frames for a different session are dropped
 *   • Wrong target peer — frames addressed to someone else are dropped
 *   • Cross-session leakage — two FabricClients on different sessions do not
 *     receive each other's relay messages
 *   • Identity/auth: the JWT is wired as a subprotocol (not URL) on the WS
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { FabricClient } from '../fabric.js'
import { SignalingClient } from '../signaling.js'

// ── Fake WebSocket ────────────────────────────────────────────────────────────

class FakeWebSocket {
  static OPEN = 1
  static CONNECTING = 0
  static CLOSED = 3
  static instances = []

  constructor(url, protocols) {
    this.url = url
    this.protocols = protocols || []
    this.readyState = FakeWebSocket.CONNECTING
    this.sent = []
    this._listeners = {}
    FakeWebSocket.instances.push(this)
    FakeWebSocket.last = this
  }

  addEventListener(evt, fn) {
    if (!this._listeners[evt]) this._listeners[evt] = []
    this._listeners[evt].push(fn)
  }

  send(data) { this.sent.push(data) }
  close() { this.readyState = FakeWebSocket.CLOSED; this._fire('close', {}) }

  _fire(evt, payload) { for (const fn of (this._listeners[evt] || [])) fn(payload) }

  _open() {
    this.readyState = FakeWebSocket.OPEN
    this._fire('open', {})
  }

  _message(frame) {
    this._fire('message', { data: typeof frame === 'string' ? frame : JSON.stringify(frame) })
  }
}

class FakePC {
  static instances = []
  constructor() {
    this._listeners = {}
    this.connectionState = 'connecting'
    this.localDescription = null
    this.remoteDescription = null
    FakePC.instances.push(this)
  }
  addEventListener(evt, fn) {
    if (!this._listeners[evt]) this._listeners[evt] = []
    this._listeners[evt].push(fn)
  }
  createOffer() { return Promise.resolve({ type: 'offer', sdp: 'v=0' }) }
  createAnswer() { return Promise.resolve({ type: 'answer', sdp: 'v=0' }) }
  setLocalDescription(d) { this.localDescription = d; return Promise.resolve() }
  setRemoteDescription(d) { this.remoteDescription = d; return Promise.resolve() }
  addIceCandidate() { return Promise.resolve() }
  close() {}
  createDataChannel() {
    return { readyState: 'connecting', binaryType: 'arraybuffer', sent: [],
      addEventListener() {}, send(d) { this.sent.push(d) }, close() {} }
  }
}

function makeFabric(peerId = 'local-peer', sessionId = 'sess-A') {
  return new FabricClient({
    sessionId,
    peerId,
    signalingUrl: 'ws://localhost/sig',
    iceUrl: '/api/peering/ice',
    relayBaseUrl: '',
  })
}

function flush() { return new Promise(r => setTimeout(r, 0)) }

beforeEach(() => {
  FakeWebSocket.instances = []
  FakeWebSocket.last = null
  FakePC.instances = []

  vi.stubGlobal('WebSocket', FakeWebSocket)
  vi.stubGlobal('RTCPeerConnection', FakePC)
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ ice_servers: [] }) })))
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => { vi.restoreAllMocks() })

describe('SignalingClient — JWT auth on WebSocket (not URL)', () => {
  it('JWT is carried in the Sec-WebSocket-Protocol header, not the URL', () => {
    const c = new SignalingClient({
      signalingUrl: 'ws://localhost/sig',
      sessionId: 'doc-1',
      peerId: 'alice',
      authToken: 'my-jwt',
    })
    c.connect()
    const ws = FakeWebSocket.last
    expect(ws.url).not.toContain('token')
    expect(ws.url).not.toContain('jwt')
    expect(ws.protocols).toContain('vula.token.my-jwt')
    c.close()
  })
})

describe('FabricClient — self-echo suppression', () => {
  it('ignores signals where from === own peerId', async () => {
    const fc = makeFabric('same-peer')
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    ws._message({
      channel: 'signal',
      from: 'same-peer',       // echoed back from the server
      payload: { type: 'join', session: 'sess-A' },
    })
    await flush()

    // No peer should have been created for self
    expect(fc._peers.has('same-peer')).toBe(false)
    fc.leave()
  })
})

describe('FabricClient — malformed signaling frame rejection', () => {
  it('non-JSON message is silently discarded (no crash)', async () => {
    const fc = makeFabric()
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    // Deliver a raw non-JSON string
    ws._fire('message', { data: '}{not-json' })
    await flush()

    // No peers created, no crash
    expect(fc._peers.size).toBe(0)
    fc.leave()
  })

  it('frame with missing payload is silently discarded', async () => {
    const fc = makeFabric()
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    ws._message({ channel: 'signal', from: 'bob' /* no payload */ })
    await flush()

    expect(fc._peers.size).toBe(0)
    fc.leave()
  })

  it('frame with null payload is silently discarded', async () => {
    const fc = makeFabric()
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    ws._message({ channel: 'signal', from: 'bob', payload: null })
    await flush()

    expect(fc._peers.size).toBe(0)
    fc.leave()
  })

  it('frame with unknown type does not crash', async () => {
    const fc = makeFabric()
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    ws._message({
      channel: 'signal',
      from: 'bob',
      payload: { type: '__unknown__', session: 'sess-A', to: 'local-peer' },
    })
    await flush()

    // No crash; peer entry may or may not be created (impl detail)
    fc.leave()
  })
})

describe('FabricClient — cross-session isolation', () => {
  it('drops frames carrying a different session id', async () => {
    const fc = makeFabric('local-peer', 'sess-A')
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    const signals = []
    fc._signaling.addEventListener('signal', ({ detail }) => signals.push(detail))

    ws._message({
      channel: 'signal',
      from: 'other',
      payload: { type: 'join', session: 'sess-B' },   // wrong session
    })
    await flush()

    // SignalingClient filters by session — no signal event dispatched
    expect(signals).toHaveLength(0)
    expect(fc._peers.has('other')).toBe(false)
    fc.leave()
  })

  it('drops frames addressed to a different peer', async () => {
    const fc = makeFabric('alice', 'sess-A')
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    const signals = []
    fc._signaling.addEventListener('signal', ({ detail }) => signals.push(detail))

    ws._message({
      channel: 'signal',
      from: 'bob',
      payload: { type: 'offer', session: 'sess-A', to: 'carol', sdp: 'v=0' },  // to=carol, not alice
    })
    await flush()

    expect(signals).toHaveLength(0)
    fc.leave()
  })
})

describe('FabricClient — cross-session relay leakage', () => {
  it('relay blobs from a different session are not dispatched', async () => {
    let capturedFetch
    vi.stubGlobal('fetch', vi.fn(async (url, opts) => {
      if (String(url).includes('pickup')) {
        capturedFetch = { url, opts }
        // Return a blob from a DIFFERENT session
        const msg = { session: 'OTHER-SESSION', data: 'secret-data' }
        const blob_b64 = btoa(JSON.stringify(msg))
        return {
          ok: true,
          json: async () => ({
            blobs: [{ id: 'b1', from: 'attacker', blob_b64 }],
          }),
        }
      }
      return { ok: true, json: async () => ({ ice_servers: [] }) }
    }))

    const fc = makeFabric('local-peer', 'sess-A')

    const received = []
    fc.addEventListener('message', ({ detail }) => received.push(detail))

    // Force relay mode
    fc._peers.set('remote-peer', {
      id: 'remote-peer', state: 'relay', dc: null, pc: null,
      relayTimer: null, pendingCandidates: [], reset() {},
    })

    await fc._relayPoll()

    // Blob from 'OTHER-SESSION' must be silently dropped
    expect(received).toHaveLength(0)
    fc.leave()
  })

  it('relay blobs from the correct session are dispatched', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (String(url).includes('pickup')) {
        const msg = { session: 'sess-A', data: 'hello-from-relay' }
        const blob_b64 = btoa(JSON.stringify(msg))
        return {
          ok: true,
          json: async () => ({
            blobs: [{ id: 'b2', from: 'remote-peer', blob_b64 }],
          }),
        }
      }
      return { ok: true, json: async () => ({ ice_servers: [] }) }
    }))

    const fc = makeFabric('local-peer', 'sess-A')

    const received = []
    fc.addEventListener('message', ({ detail }) => received.push(detail))

    fc._peers.set('remote-peer', {
      id: 'remote-peer', state: 'relay', dc: null, pc: null,
      relayTimer: null, pendingCandidates: [], reset() {},
    })

    await fc._relayPoll()

    expect(received).toHaveLength(1)
    expect(received[0].data).toBe('hello-from-relay')
    expect(received[0].from).toBe('remote-peer')
    fc.leave()
  })
})

describe('FabricClient — identity validation on join', () => {
  it('authToken is emitted in the join frame as a WS subprotocol', async () => {
    const fc = new FabricClient({
      sessionId: 'sess-auth',
      peerId: 'alice',
      signalingUrl: 'ws://localhost/sig',
      iceUrl: '/api/peering/ice',
      authToken: 'my-jwt-token',
    })
    await fc.join()
    const ws = FakeWebSocket.last
    expect(ws.protocols).toContain('vula.token.my-jwt-token')
    expect(ws.url).not.toContain('token')
    fc.leave()
  })

  it('unauthenticated client opens WS with no subprotocol token', async () => {
    const fc = new FabricClient({
      sessionId: 'sess-anon',
      peerId: 'anon',
      signalingUrl: 'ws://localhost/sig',
      iceUrl: '/api/peering/ice',
    })
    await fc.join()
    const ws = FakeWebSocket.last
    expect(ws.protocols || []).not.toContain(
      (ws.protocols || []).find(p => p.startsWith('vula.token.'))
    )
    fc.leave()
  })
})
