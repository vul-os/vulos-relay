/**
 * replay-timestamp.test.js — Fix 2: signed-timestamp replay protection.
 *
 * Before the fix the canonical signed form carried no time, so a captured
 * signed offer/answer/ice frame was valid forever and became replayable again
 * once its (from,nonce) entry was evicted from the FIFO nonce cache.
 *
 * After the fix every signed frame carries a signed `ts`, and the receiver
 * rejects frames outside a bounded clock-skew window — even if the nonce is
 * fresh / evicted.  The nonce cache remains as defense-in-depth.
 *
 * Real WebCrypto is used so signatures are genuine.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { SignalingClient } from '../signaling.js'

// Canonical form — MUST match signaling.js _canonical (now includes ts).
function canonical({ type, session, to, from, nonce, ts, sdp, candidate, pubKey }) {
  const msg = { type, session, to: to ?? null, from, nonce, ts }
  if (sdp !== undefined) msg.sdp = sdp
  if (candidate !== undefined) msg.candidate = candidate
  if (pubKey !== undefined) msg.pubKey = pubKey
  return JSON.stringify(msg)
}

async function generatePeerKey() {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
}
async function exportPubKeyB64(kp) {
  const raw = await crypto.subtle.exportKey('raw', kp.publicKey)
  return btoa(String.fromCharCode(...new Uint8Array(raw)))
}
async function signMsg(privateKey, msg) {
  const buf = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, privateKey, new TextEncoder().encode(msg),
  )
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
}

class FakeWebSocket {
  static OPEN = 1
  static CONNECTING = 0
  static CLOSED = 3
  static last = null
  constructor() {
    this.readyState = FakeWebSocket.CONNECTING
    this.sent = []
    this._listeners = {}
    FakeWebSocket.last = this
  }
  addEventListener(e, f) { (this._listeners[e] ||= []).push(f) }
  send(d) { this.sent.push(d) }
  close() { this.readyState = FakeWebSocket.CLOSED; this._fire('close', {}) }
  _fire(e, p) { for (const f of (this._listeners[e] || [])) f(p) }
  _open() { this.readyState = FakeWebSocket.OPEN; this._fire('open', {}) }
  _message(frame) { this._fire('message', { data: typeof frame === 'string' ? frame : JSON.stringify(frame) }) }
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms))
async function waitFor(cond, { timeout = 500, interval = 5 } = {}) {
  const end = Date.now() + timeout
  while (Date.now() < end) { if (cond()) return; await sleep(interval) }
  throw new Error('waitFor: condition never true within ' + timeout + 'ms')
}

async function makeKeyedClient() {
  const aliceKP = await generatePeerKey()
  const alicePubB64 = await exportPubKeyB64(aliceKP)

  const sc = new SignalingClient({
    signalingUrl: 'ws://localhost/sig',
    sessionId: 'sess-1',
    peerId: 'bob',
    requirePeerAuth: false,
  })
  const offers = []
  sc.addEventListener('signal', ({ detail }) => {
    if (detail.payload.type === 'offer') offers.push(detail)
  })
  sc.connect()
  const ws = FakeWebSocket.last
  ws._open()

  // Register alice's key via join.
  ws._message({ channel: 'signal', from: 'alice', payload: { type: 'join', session: 'sess-1', depositPubKey: alicePubB64 } })
  await waitFor(() => sc._peerKeys.has('alice'))

  return { sc, ws, aliceKP, alicePubB64, offers }
}

function signedOfferFrame({ nonce, ts, sdp = 'v=0 ts-test', sig, pubKey }) {
  return {
    channel: 'signal',
    from: 'alice',
    payload: { type: 'offer', session: 'sess-1', to: 'bob', sdp, nonce, ts, sig, pubKey },
  }
}

beforeEach(() => {
  FakeWebSocket.last = null
  vi.stubGlobal('WebSocket', FakeWebSocket)
})
afterEach(() => { vi.restoreAllMocks() })

describe('Signaling replay protection — signed timestamp', () => {
  it('accepts a fresh signed frame (ts within window)', async () => {
    const { ws, aliceKP, alicePubB64, offers } = await makeKeyedClient()

    const nonce = crypto.randomUUID()
    const ts = Date.now()
    const sdp = 'v=0 fresh'
    const sig = await signMsg(aliceKP.privateKey, canonical({
      type: 'offer', session: 'sess-1', to: 'bob', from: 'alice', nonce, ts, sdp, pubKey: alicePubB64,
    }))
    ws._message(signedOfferFrame({ nonce, ts, sdp, sig, pubKey: alicePubB64 }))
    await waitFor(() => offers.length === 1)
    expect(offers).toHaveLength(1)
  })

  it('rejects a stale signed frame (ts older than the freshness window) even with a fresh nonce', async () => {
    const { ws, aliceKP, alicePubB64, offers } = await makeKeyedClient()

    const nonce = crypto.randomUUID()   // brand-new nonce — NOT in the cache
    const ts = Date.now() - 120_000     // 2 minutes old (> 30 s window)
    const sdp = 'v=0 stale'
    // Sign the OLD ts honestly — this models a captured-and-replayed frame.
    const sig = await signMsg(aliceKP.privateKey, canonical({
      type: 'offer', session: 'sess-1', to: 'bob', from: 'alice', nonce, ts, sdp, pubKey: alicePubB64,
    }))
    ws._message(signedOfferFrame({ nonce, ts, sdp, sig, pubKey: alicePubB64 }))
    await sleep(80)

    // Valid signature + unused nonce, but stale ts → dropped.
    expect(offers).toHaveLength(0)
  })

  it('rejects an implausibly future-dated frame', async () => {
    const { ws, aliceKP, alicePubB64, offers } = await makeKeyedClient()

    const nonce = crypto.randomUUID()
    const ts = Date.now() + 120_000     // 2 minutes in the future
    const sdp = 'v=0 future'
    const sig = await signMsg(aliceKP.privateKey, canonical({
      type: 'offer', session: 'sess-1', to: 'bob', from: 'alice', nonce, ts, sdp, pubKey: alicePubB64,
    }))
    ws._message(signedOfferFrame({ nonce, ts, sdp, sig, pubKey: alicePubB64 }))
    await sleep(80)
    expect(offers).toHaveLength(0)
  })

  it('rejects a signed frame that omits ts entirely (cannot be freshness-checked)', async () => {
    const { ws, aliceKP, alicePubB64, offers } = await makeKeyedClient()

    const nonce = crypto.randomUUID()
    // Sign a canonical form WITHOUT ts (a pre-fix sender) — the receiver now
    // requires ts on the signed path, so this is dropped.
    const sig = await signMsg(aliceKP.privateKey, JSON.stringify({
      type: 'offer', session: 'sess-1', to: 'bob', from: 'alice', nonce, sdp: 'v=0 nots', pubKey: alicePubB64,
    }))
    ws._message({
      channel: 'signal', from: 'alice',
      payload: { type: 'offer', session: 'sess-1', to: 'bob', sdp: 'v=0 nots', nonce, sig, pubKey: alicePubB64 },
    })
    await sleep(80)
    expect(offers).toHaveLength(0)
  })

  it('a captured frame stays rejected after its nonce would have been evicted (core regression)', async () => {
    // The pre-fix vulnerability: once the FIFO nonce cache evicts an old entry,
    // a captured frame becomes replayable.  With a signed ts the frame is stale
    // and rejected regardless of nonce-cache state.
    const { ws, aliceKP, alicePubB64, offers } = await makeKeyedClient()

    const nonce = crypto.randomUUID()
    const ts = Date.now() - 60_000      // stale
    const sdp = 'v=0 captured'
    const sig = await signMsg(aliceKP.privateKey, canonical({
      type: 'offer', session: 'sess-1', to: 'bob', from: 'alice', nonce, ts, sdp, pubKey: alicePubB64,
    }))
    const frame = signedOfferFrame({ nonce, ts, sdp, sig, pubKey: alicePubB64 })

    // Even on the very first delivery (nonce definitely not cached), staleness drops it.
    ws._message(frame)
    await sleep(80)
    expect(offers).toHaveLength(0)
  })

  it('outgoing signed frames carry a numeric ts in the canonical and payload', async () => {
    const localKP = await generatePeerKey()
    const sc = new SignalingClient({
      signalingUrl: 'ws://localhost/sig',
      sessionId: 'sess-1',
      peerId: 'local',
      signFrame: (msg) => signMsg(localKP.privateKey, msg),
    })
    sc.connect()
    const ws = FakeWebSocket.last
    ws._open()
    ws.sent.length = 0

    await sc.signal('offer', 'remote', { sdp: 'v=0 out' })
    const frame = JSON.parse(ws.sent[ws.sent.length - 1])
    expect(typeof frame.payload.ts).toBe('number')
    expect(frame.payload.ts).toBeGreaterThan(0)
    sc.close()
  })
})
