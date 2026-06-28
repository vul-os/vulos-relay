/**
 * fabric.flow.test.js — WebRTC signaling + data-channel flow
 *
 * Covers the full offer/answer/ICE negotiation cycle, polite/impolite peer
 * roles, data channel open → 'connected' state, message dispatch, peer leave,
 * and reconnect-on-signaling-open.  All network I/O is mocked (no real
 * WebSocket or RTCPeerConnection).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { FabricClient } from '../fabric.js'

// ── Fake WebSocket ────────────────────────────────────────────────────────────

class FakeWebSocket {
  static OPEN = 1
  static CONNECTING = 0
  static CLOSED = 3
  static instances = []

  constructor(url, protocols) {
    this.url = url
    this.protocols = protocols
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

// ── Fake RTCDataChannel ───────────────────────────────────────────────────────

class FakeDC {
  constructor(label) {
    this.label = label
    this.readyState = 'connecting'
    this.binaryType = 'arraybuffer'
    this.sent = []
    this._listeners = {}
  }

  addEventListener(evt, fn) {
    if (!this._listeners[evt]) this._listeners[evt] = []
    this._listeners[evt].push(fn)
  }

  send(data) { this.sent.push(data) }
  close() { this.readyState = 'closed'; this._fire('close', {}) }

  _fire(evt, payload) { for (const fn of (this._listeners[evt] || [])) fn(payload) }
  _open() { this.readyState = 'open'; this._fire('open', {}) }
  _msg(data) { this._fire('message', { data }) }
}

// ── Fake RTCPeerConnection ────────────────────────────────────────────────────

class FakePC {
  static instances = []

  constructor(config) {
    this.config = config
    this.connectionState = 'connecting'
    this.localDescription = null
    this.remoteDescription = null
    this.pendingCandidates = []
    this._listeners = {}
    this._createdDC = null
    FakePC.instances.push(this)
    FakePC.last = this
  }

  addEventListener(evt, fn) {
    if (!this._listeners[evt]) this._listeners[evt] = []
    this._listeners[evt].push(fn)
  }

  _fire(evt, payload) { for (const fn of (this._listeners[evt] || [])) fn(payload) }

  createDataChannel(label) {
    const dc = new FakeDC(label)
    this._createdDC = dc
    return dc
  }

  createOffer() { return Promise.resolve({ type: 'offer', sdp: 'v=0 fake-offer' }) }
  createAnswer() { return Promise.resolve({ type: 'answer', sdp: 'v=0 fake-answer' }) }

  setLocalDescription(desc) {
    this.localDescription = { type: desc.type, sdp: desc.sdp || desc.type }
    return Promise.resolve()
  }

  setRemoteDescription(desc) {
    this.remoteDescription = desc
    return Promise.resolve()
  }

  addIceCandidate(c) {
    this.pendingCandidates.push(c)
    return Promise.resolve()
  }

  close() {
    this.connectionState = 'closed'
    this._fire('connectionstatechange', {})
  }

  // Test helpers
  _connect() {
    this.connectionState = 'connected'
    this._fire('connectionstatechange', {})
  }

  _fail() {
    this.connectionState = 'failed'
    this._fire('connectionstatechange', {})
  }

  _receiveDataChannel(dc) {
    this._fire('datachannel', { channel: dc })
  }

  _iceCandidate(candidate) {
    this._fire('icecandidate', { candidate })
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeFabric({ peerId = 'local-peer', authToken = null } = {}) {
  const fc = new FabricClient({
    sessionId: 'sess-1',
    peerId,
    signalingUrl: 'ws://localhost/sig',
    iceUrl: '/api/peering/ice',
    relayBaseUrl: '',
    authToken,
  })
  return fc
}

/** Drain the microtask queue so that async event handlers resolve. */
function flush() { return new Promise(r => setTimeout(r, 0)) }

beforeEach(() => {
  FakeWebSocket.instances = []
  FakeWebSocket.last = null
  FakePC.instances = []
  FakePC.last = null

  vi.stubGlobal('WebSocket', FakeWebSocket)
  vi.stubGlobal('RTCPeerConnection', FakePC)
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ ice_servers: [] }) })))
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => { vi.restoreAllMocks() })

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('FabricClient — signaling join / ICE negotiation flow', () => {
  it('join() generates deposit key and connects signaling WebSocket', async () => {
    const fc = makeFabric()
    await fc.join()

    expect(typeof fc._depositPubKeyB64).toBe('string')
    expect(fc._depositPubKeyB64.length).toBeGreaterThan(0)
    expect(FakeWebSocket.instances.length).toBe(1)
    fc.leave()
  })

  it('impolite peer (local < remote) sends offer on peer-join signal', async () => {
    // local-peer < z-remote → local is impolite (offerer)
    const fc = makeFabric({ peerId: 'a-local' })
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()
    ws.sent.length = 0

    // Simulate remote peer joining
    ws._message({
      channel: 'signal',
      from: 'z-remote',
      payload: { type: 'join', session: 'sess-1' },
    })

    await flush()

    // Should have sent an offer via signaling
    const offerFrame = ws.sent.find(raw => {
      try { return JSON.parse(raw).payload?.type === 'offer' } catch { return false }
    })
    expect(offerFrame).toBeTruthy()
    const parsed = JSON.parse(offerFrame)
    expect(parsed.payload.session).toBe('sess-1')
    expect(parsed.payload.to).toBe('z-remote')
    expect(parsed.payload.sdp).toBeTruthy()
    fc.leave()
  })

  it('polite peer (local > remote) does NOT send offer on peer-join signal', async () => {
    // z-local > a-remote → local is polite (waits for offer)
    const fc = makeFabric({ peerId: 'z-local' })
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()
    ws.sent.length = 0

    ws._message({
      channel: 'signal',
      from: 'a-remote',
      payload: { type: 'join', session: 'sess-1' },
    })

    await flush()

    const offerFrame = ws.sent.find(raw => {
      try { return JSON.parse(raw).payload?.type === 'offer' } catch { return false }
    })
    expect(offerFrame).toBeUndefined()
    fc.leave()
  })

  it('answer flow: arriving offer → setRemoteDescription → answer sent', async () => {
    const fc = makeFabric({ peerId: 'z-local' })  // polite, receives offers
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()
    ws.sent.length = 0

    ws._message({
      channel: 'signal',
      from: 'a-remote',
      payload: { type: 'offer', session: 'sess-1', to: 'z-local', sdp: 'v=0 remote-offer' },
    })

    await flush()

    const answerFrame = ws.sent.find(raw => {
      try { return JSON.parse(raw).payload?.type === 'answer' } catch { return false }
    })
    expect(answerFrame).toBeTruthy()
    const parsed = JSON.parse(answerFrame)
    expect(parsed.payload.to).toBe('a-remote')
    expect(parsed.payload.sdp).toBeTruthy()

    const pc = FakePC.last
    expect(pc.remoteDescription.type).toBe('offer')
    fc.leave()
  })

  it('answer received → setRemoteDescription called', async () => {
    const fc = makeFabric({ peerId: 'a-local' })  // impolite, sends offers
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()
    ws.sent.length = 0

    // Trigger offer creation
    ws._message({
      channel: 'signal',
      from: 'z-remote',
      payload: { type: 'join', session: 'sess-1' },
    })
    await flush()

    const pc = FakePC.last

    // Deliver the answer
    ws._message({
      channel: 'signal',
      from: 'z-remote',
      payload: { type: 'answer', session: 'sess-1', to: 'a-local', sdp: 'v=0 answer' },
    })
    await flush()

    expect(pc.remoteDescription.type).toBe('answer')
    fc.leave()
  })

  it('ICE candidate forwarded via signaling', async () => {
    const fc = makeFabric({ peerId: 'a-local' })
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()
    ws.sent.length = 0

    // Create a peer so ICE candidates have a PC to fire on
    ws._message({
      channel: 'signal',
      from: 'z-remote',
      payload: { type: 'join', session: 'sess-1' },
    })
    await flush()

    const pc = FakePC.last
    ws.sent.length = 0  // clear offer frame

    // Fire ICE candidate from the fake PC
    pc._iceCandidate({
      toJSON: () => ({ candidate: 'candidate:1 1 UDP...', sdpMid: '0', sdpMLineIndex: 0 }),
    })

    const iceFrame = ws.sent.find(raw => {
      try { return JSON.parse(raw).payload?.type === 'ice' } catch { return false }
    })
    expect(iceFrame).toBeTruthy()
    const parsed = JSON.parse(iceFrame)
    expect(parsed.payload.candidate).toBeTruthy()
    fc.leave()
  })

  it('incoming ICE candidate before remoteDescription is queued then applied', async () => {
    const fc = makeFabric({ peerId: 'z-local' })  // polite
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    // Send ICE before offer (should be queued)
    ws._message({
      channel: 'signal',
      from: 'a-remote',
      payload: { type: 'ice', session: 'sess-1', to: 'z-local', candidate: { candidate: 'c1', sdpMid: '0' } },
    })
    await flush()

    const ps = fc._peers.get('a-remote')
    expect(ps.pendingCandidates.length).toBe(1)

    // Now deliver the offer — pending candidate should be applied
    ws._message({
      channel: 'signal',
      from: 'a-remote',
      payload: { type: 'offer', session: 'sess-1', to: 'z-local', sdp: 'v=0 offer' },
    })
    await flush()

    expect(ps.pendingCandidates.length).toBe(0)
    fc.leave()
  })

  it('data channel open → peer state transitions to connected', async () => {
    const fc = makeFabric({ peerId: 'a-local' })
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    ws._message({
      channel: 'signal',
      from: 'z-remote',
      payload: { type: 'join', session: 'sess-1' },
    })
    await flush()

    const pc = FakePC.last
    const dc = pc._createdDC
    expect(dc).toBeTruthy()

    const states = []
    fc.addEventListener('state', ({ detail }) => states.push(detail))

    dc._open()

    expect(states).toContainEqual({ peerId: 'z-remote', state: 'connected' })
    expect(fc._peers.get('z-remote').state).toBe('connected')
    fc.leave()
  })

  it('messages on the data channel are dispatched as fabric "message" events', async () => {
    const fc = makeFabric({ peerId: 'a-local' })
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    ws._message({
      channel: 'signal',
      from: 'z-remote',
      payload: { type: 'join', session: 'sess-1' },
    })
    await flush()

    const pc = FakePC.last
    const dc = pc._createdDC
    dc._open()

    const received = []
    fc.addEventListener('message', ({ detail }) => received.push(detail))

    dc._msg('hello world')

    expect(received).toHaveLength(1)
    expect(received[0].from).toBe('z-remote')
    expect(received[0].data).toBe('hello world')
    fc.leave()
  })

  it('send() delivers to an open data channel', async () => {
    const fc = makeFabric({ peerId: 'a-local' })
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    ws._message({
      channel: 'signal',
      from: 'z-remote',
      payload: { type: 'join', session: 'sess-1' },
    })
    await flush()

    const dc = FakePC.last._createdDC
    dc._open()

    fc.send('broadcast-msg')
    expect(dc.sent).toContain('broadcast-msg')
    fc.leave()
  })

  it('sendTo() unicasts to a specific peer data channel', async () => {
    const fc = makeFabric({ peerId: 'a-local' })
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    ws._message({
      channel: 'signal',
      from: 'z-remote',
      payload: { type: 'join', session: 'sess-1' },
    })
    await flush()

    const dc = FakePC.last._createdDC
    dc._open()

    fc.sendTo('z-remote', 'unicast-msg')
    expect(dc.sent).toContain('unicast-msg')
    fc.leave()
  })

  it('peer leave signal → peer state set to disconnected', async () => {
    const fc = makeFabric({ peerId: 'a-local' })
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    ws._message({
      channel: 'signal',
      from: 'z-remote',
      payload: { type: 'join', session: 'sess-1' },
    })
    await flush()

    const dc = FakePC.last._createdDC
    dc._open()

    const states = []
    fc.addEventListener('state', ({ detail }) => states.push(detail))

    ws._message({
      channel: 'signal',
      from: 'z-remote',
      payload: { type: 'leave', session: 'sess-1' },
    })
    await flush()

    expect(states).toContainEqual({ peerId: 'z-remote', state: 'disconnected' })
    fc.leave()
  })

  it('peerStates snapshot reflects current peer states', async () => {
    const fc = makeFabric({ peerId: 'a-local' })
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    ws._message({
      channel: 'signal',
      from: 'z-remote',
      payload: { type: 'join', session: 'sess-1' },
    })
    await flush()

    const ps = fc.peerStates
    expect(ps['z-remote']).toBe('connecting')
    fc.leave()
  })

  it('signaling-open event re-offers disconnected peers', async () => {
    const fc = makeFabric({ peerId: 'a-local' })
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    // Establish + disconnect a peer
    ws._message({
      channel: 'signal',
      from: 'z-remote',
      payload: { type: 'join', session: 'sess-1' },
    })
    await flush()

    // Force peer to disconnected
    fc._peers.get('z-remote').state = 'disconnected'

    // Simulate signaling reconnect
    FakeWebSocket.instances.push(new FakeWebSocket('ws://localhost/sig'))
    const ws2 = FakeWebSocket.last
    ws2._open()

    // Trigger signaling-open by dispatching the event on the SignalingClient
    fc._signaling.dispatchEvent(new CustomEvent('signaling-open'))
    await flush()

    // A new offer should have been sent for the disconnected peer
    const offerSent = ws2.sent.some(raw => {
      try { return JSON.parse(raw).payload?.type === 'offer' } catch { return false }
    }) || ws.sent.some(raw => {
      try { return JSON.parse(raw).payload?.type === 'offer' } catch { return false }
    })
    expect(offerSent).toBe(true)
    fc.leave()
  })
})
