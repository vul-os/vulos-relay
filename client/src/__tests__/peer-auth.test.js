/**
 * peer-auth.test.js — E2E peer authentication (security audit MEDIUM)
 *
 * Hermetic tests (mock transport, real WebCrypto) covering:
 *
 *   1. IMPERSONATION REJECTED
 *      A malicious signaling server stamps `from: 'alice'` on a frame it
 *      synthesised without alice's private key.  The unsigned frame (no sig)
 *      and the mis-signed frame (wrong key) must both be dropped.
 *
 *   2. DTLS FINGERPRINT-MISMATCH REJECTED
 *      Alice correctly signs an offer whose SDP contains fingerprint F1.  A
 *      MITM signaling server replaces the SDP with one containing fingerprint
 *      F2 (different fingerprint).  Since the signature was computed over the
 *      original SDP the canonical message reconstructed by the receiver differs
 *      → signature mismatch → frame dropped before setRemoteDescription.
 *
 *   3. VALID SIGNED PEER ACCEPTED
 *      Full happy path: alice generates a real ECDSA P-256 key, signs a join
 *      (pubkey), then a correctly-signed offer; bob verifies and proceeds.
 *
 *   4. UNSIGNED RELAY-AUTH FALLBACK OFF BY DEFAULT
 *      allowUnsignedRelayAuth defaults to false; the forgeable
 *      "Vula-Relay <peerId>.<ts>" auth header must not be emitted.
 *      (Belt-and-suspenders test alongside fabric.relay.test.js.)
 *
 * All I/O is mocked (FakeWebSocket, FakeRTCPeerConnection).
 * Real crypto.subtle is used so signature construction/verification is genuine.
 *
 * Note on timing: Node's native WebCrypto (used by jsdom v29) runs sign/verify
 * through the libuv threadpool — the Promise resolves in a future macrotask,
 * NOT in the current microtask queue.  Tests use `waitFor` (polling on a real
 * condition) and `sleep` (fixed delay for negative tests) rather than a single
 * `flush()` (setTimeout 0).
 *
 * Note on FakePC creation: FabricClient calls _buildPC (which instantiates a
 * FakePC) even for the polite peer when a 'join' signal arrives.  That PC is
 * created BEFORE any offer processing.  Rejection tests therefore assert on
 * `pc.remoteDescription === null` (setRemoteDescription was never called)
 * rather than on FakePC.instances.length.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { FabricClient } from '../fabric.js'
import { SignalingClient } from '../signaling.js'

// ── Canonical message helper (must match signaling.js _canonical exactly) ─────
// Re-implemented here so the test can construct the exact string that was signed
// by the sender, and then tamper with specific fields for negative test cases.
function canonical({ type, session, to, from, nonce, ts, sdp, candidate, pubKey }) {
  const msg = { type, session, to: to ?? null, from, nonce, ts }
  if (sdp !== undefined) msg.sdp = sdp
  if (candidate !== undefined) msg.candidate = candidate
  if (pubKey !== undefined) msg.pubKey = pubKey
  return JSON.stringify(msg)
}

// ── WebCrypto test helpers ─────────────────────────────────────────────────────

async function generatePeerKey() {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )
}

async function exportPubKeyB64(kp) {
  const raw = await crypto.subtle.exportKey('raw', kp.publicKey)
  return btoa(String.fromCharCode(...new Uint8Array(raw)))
}

async function signMsg(privateKey, msg) {
  const buf = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    new TextEncoder().encode(msg),
  )
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
}

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

// ── Fake RTCPeerConnection ────────────────────────────────────────────────────

class FakePC {
  static instances = []

  constructor() {
    this._listeners = {}
    this.connectionState = 'connecting'
    this.localDescription = null
    this.remoteDescription = null
    FakePC.instances.push(this)
    FakePC.last = this
  }

  addEventListener(evt, fn) {
    if (!this._listeners[evt]) this._listeners[evt] = []
    this._listeners[evt].push(fn)
  }

  _fire(evt, payload) { for (const fn of (this._listeners[evt] || [])) fn(payload) }

  createOffer()  { return Promise.resolve({ type: 'offer',  sdp: 'v=0 fake-offer' }) }
  createAnswer() { return Promise.resolve({ type: 'answer', sdp: 'v=0 fake-answer' }) }

  setLocalDescription(d)  { this.localDescription  = d; return Promise.resolve() }
  setRemoteDescription(d) { this.remoteDescription = d; return Promise.resolve() }
  addIceCandidate()       { return Promise.resolve() }
  close()                 { this.connectionState = 'closed' }

  createDataChannel() {
    return {
      readyState: 'connecting', binaryType: 'arraybuffer', sent: [],
      addEventListener() {}, send(d) { this.sent.push(d) }, close() {},
    }
  }
}

// ── Async wait helpers ────────────────────────────────────────────────────────

/**
 * Poll `condition()` until truthy, or throw after `timeout` ms.
 * Needed because Node's native WebCrypto resolves via the libuv threadpool
 * (a macrotask), not in the current microtask queue.  A single setTimeout(0)
 * may fire before crypto operations complete.
 */
async function waitFor(condition, { timeout = 500, interval = 5 } = {}) {
  const deadline = Date.now() + timeout
  while (Date.now() < deadline) {
    if (condition()) return
    await new Promise(r => setTimeout(r, interval))
  }
  throw new Error('waitFor: condition never true within ' + timeout + 'ms')
}

/**
 * Fixed-duration sleep for negative tests — lets crypto ops complete, then
 * we confirm that the expected side-effect did NOT occur.
 */
const sleep = ms => new Promise(r => setTimeout(r, ms))

// ── Setup / teardown ──────────────────────────────────────────────────────────

/**
 * Build a FabricClient for `peerId`.  'bob' > 'alice' lexicographically, so
 * bob is always the POLITE peer in these tests (waits for alice's offer).
 * FabricClient._initiatePeer() calls _buildPC even for the polite peer, so a
 * FakePC IS created when bob processes alice's 'join' — but setRemoteDescription
 * is NOT called until a valid offer arrives.
 */
function makeFabric(peerId = 'bob', sessionId = 'sess-1') {
  return new FabricClient({
    sessionId,
    peerId,
    signalingUrl: 'ws://localhost/sig',
    iceUrl: '/api/peering/ice',
    relayBaseUrl: '',
  })
}

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

// ── 1. IMPERSONATION REJECTED ─────────────────────────────────────────────────

describe('Peer authentication — impersonation rejected', () => {
  it('drops an unsigned offer from a peer whose pubkey is already known (via join)', async () => {
    // Alice's real key pair
    const aliceKP = await generatePeerKey()
    const alicePubKeyB64 = await exportPubKeyB64(aliceKP)

    const fc = makeFabric('bob')
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    // Step 1: receive alice's join → her key is stored (TOFU via importKey).
    // This also causes bob (polite) to create a FakePC via _buildPC but not
    // set any remote description (bob is polite and waits for alice's offer).
    ws._message({
      channel: 'signal',
      from: 'alice',
      payload: { type: 'join', session: 'sess-1', depositPubKey: alicePubKeyB64 },
    })
    // Wait for the async importKey (libuv) to complete
    await waitFor(() => fc._signaling._peerKeys.has('alice'))

    // Step 2: malicious server sends an offer claiming `from: alice` with NO sig
    ws._message({
      channel: 'signal',
      from: 'alice',
      payload: {
        type: 'offer', session: 'sess-1', to: 'bob',
        sdp: 'v=0 fake-offer-from-attacker',
        pubKey: alicePubKeyB64,
        // no nonce, no sig — unsigned frame from a peer with a known key
      },
    })
    // Wait long enough for any async verify to complete; the offer should be dropped.
    await sleep(50)

    // The unsigned offer must be dropped: signaling returns before dispatchEvent,
    // so _onSignal is never called for this offer and setRemoteDescription is
    // never invoked.  The FakePC (created on alice's join) has null remoteDescription.
    expect(FakePC.last?.remoteDescription).toBeNull()
    fc.leave()
  })

  it('drops a mis-signed offer (signature made with a different key than alice\'s)', async () => {
    const aliceKP   = await generatePeerKey()
    const malloryKP = await generatePeerKey()
    const alicePubKeyB64 = await exportPubKeyB64(aliceKP)

    const fc = makeFabric('bob')
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    // Register alice's real key
    ws._message({
      channel: 'signal',
      from: 'alice',
      payload: { type: 'join', session: 'sess-1', depositPubKey: alicePubKeyB64 },
    })
    await waitFor(() => fc._signaling._peerKeys.has('alice'))

    // Mallory signs the frame body with HER key but stamps `from: alice`
    const nonce = crypto.randomUUID()
    const sdp = 'v=0 mallory-offer'
    const sigMsg = canonical({
      type: 'offer', session: 'sess-1', to: 'bob', from: 'alice',
      nonce, sdp, pubKey: alicePubKeyB64,
    })
    // Signed with mallory's private key — won't verify against alice's stored pubkey
    const badSig = await signMsg(malloryKP.privateKey, sigMsg)

    ws._message({
      channel: 'signal',
      from: 'alice',
      payload: { type: 'offer', session: 'sess-1', to: 'bob', sdp, nonce, sig: badSig, pubKey: alicePubKeyB64 },
    })
    await sleep(50)

    // Signature mismatch → offer dropped → setRemoteDescription never called
    expect(FakePC.last?.remoteDescription).toBeNull()
    fc.leave()
  })

  it('drops an offer where the server stamps a wrong `from` (identity misroute)', async () => {
    // Alice signs an offer with from:'alice' in the canonical message.
    // Malicious server delivers the same frame with from:'carol' (different identity).
    // Receiver reconstructs canonical with from:'carol' → mismatch with alice's sig → drop.
    const aliceKP = await generatePeerKey()
    const alicePubKeyB64 = await exportPubKeyB64(aliceKP)

    const fc = makeFabric('bob')
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    // Register alice
    ws._message({
      channel: 'signal',
      from: 'alice',
      payload: { type: 'join', session: 'sess-1', depositPubKey: alicePubKeyB64 },
    })
    await waitFor(() => fc._signaling._peerKeys.has('alice'))

    // Alice legitimately signs an offer with from:'alice' in the canonical msg
    const nonce = crypto.randomUUID()
    const sdp = 'v=0 alice-offer'
    const aliceCanonical = canonical({
      type: 'offer', session: 'sess-1', to: 'bob', from: 'alice',
      nonce, sdp, pubKey: alicePubKeyB64,
    })
    const aliceSig = await signMsg(aliceKP.privateKey, aliceCanonical)

    // Server re-stamps from:'carol' — receiver reconstructs canonical with
    // from:'carol' which ≠ from:'alice' → sig mismatch → drop
    ws._message({
      channel: 'signal',
      from: 'carol',    // ← wrong identity stamped by malicious server
      payload: {
        type: 'offer', session: 'sess-1', to: 'bob',
        sdp, nonce, sig: aliceSig, pubKey: alicePubKeyB64,
      },
    })
    // carol's offer: pubKey carries alice's key → TOFU import under 'carol' →
    // verify({from:'carol',...}) vs aliceSig({from:'alice',...}) → FAIL → drop
    await sleep(50)

    // Carol's signal was dropped before dispatchEvent → no peer state for carol
    expect(fc._peers.has('carol')).toBe(false)
    fc.leave()
  })
})

// ── 2. DTLS FINGERPRINT-MISMATCH REJECTED ────────────────────────────────────

describe('Peer authentication — DTLS fingerprint pinning', () => {
  it('rejects an offer whose SDP was replaced by a MITM server after signing', async () => {
    // Alice signs an offer containing SDP with fingerprint FP-original.
    // A MITM server replaces the SDP with FP-swapped.
    // The signature was over originalSdp → mismatch → bob rejects.
    const aliceKP = await generatePeerKey()
    const alicePubKeyB64 = await exportPubKeyB64(aliceKP)

    const fc = makeFabric('bob')
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    // Register alice
    ws._message({
      channel: 'signal',
      from: 'alice',
      payload: { type: 'join', session: 'sess-1', depositPubKey: alicePubKeyB64 },
    })
    await waitFor(() => fc._signaling._peerKeys.has('alice'))

    const nonce = crypto.randomUUID()
    const originalSdp = 'v=0\r\na=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78'
    const swappedSdp  = 'v=0\r\na=fingerprint:sha-256 99:88:77:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78'

    // Alice signs the canonical message that includes originalSdp
    const aliceCanonical = canonical({
      type: 'offer', session: 'sess-1', to: 'bob', from: 'alice',
      nonce, sdp: originalSdp, pubKey: alicePubKeyB64,
    })
    const sig = await signMsg(aliceKP.privateKey, aliceCanonical)

    // MITM server replaces SDP (and thus the DTLS fingerprint)
    ws._message({
      channel: 'signal',
      from: 'alice',
      payload: {
        type: 'offer', session: 'sess-1', to: 'bob',
        sdp: swappedSdp,    // ← fingerprint swapped by MITM
        nonce, sig,
        pubKey: alicePubKeyB64,
      },
    })
    // Receiver reconstructs canonical with swappedSdp ≠ originalSdp → sig mismatch → drop
    await sleep(50)

    // setRemoteDescription was never called — DTLS fingerprint pinning held
    expect(FakePC.last?.remoteDescription).toBeNull()
    fc.leave()
  })
})

// ── 3. VALID SIGNED PEER ACCEPTED ─────────────────────────────────────────────

describe('Peer authentication — valid signed offer accepted', () => {
  it('processes a correctly signed offer from a peer (with prior join)', async () => {
    const aliceKP = await generatePeerKey()
    const alicePubKeyB64 = await exportPubKeyB64(aliceKP)

    const fc = makeFabric('bob')
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    // Register alice via join → bob creates a PC (polite, no offer sent)
    ws._message({
      channel: 'signal',
      from: 'alice',
      payload: { type: 'join', session: 'sess-1', depositPubKey: alicePubKeyB64 },
    })
    await waitFor(() => fc._signaling._peerKeys.has('alice'))

    // Alice sends a valid signed offer
    const nonce = crypto.randomUUID()
    const ts = Date.now()
    const sdp = 'v=0 valid-offer'
    const aliceCanonical = canonical({
      type: 'offer', session: 'sess-1', to: 'bob', from: 'alice',
      nonce, ts, sdp, pubKey: alicePubKeyB64,
    })
    const sig = await signMsg(aliceKP.privateKey, aliceCanonical)

    ws._message({
      channel: 'signal',
      from: 'alice',
      payload: { type: 'offer', session: 'sess-1', to: 'bob', sdp, nonce, ts, sig, pubKey: alicePubKeyB64 },
    })

    // When the offer is accepted, _onSignal calls setRemoteDescription(offer).
    // Wait for it to be set (verify + _onSignal are both async).
    await waitFor(() => FakePC.last?.remoteDescription?.type === 'offer')

    expect(FakePC.last.remoteDescription.type).toBe('offer')
    fc.leave()
  })

  it('verifies using pubKey embedded in the offer even without a prior join', async () => {
    // Out-of-order delivery: offer arrives before the join.
    // The offer carries pubKey inline → TOFU import → verify → accept.
    const aliceKP = await generatePeerKey()
    const alicePubKeyB64 = await exportPubKeyB64(aliceKP)

    const fc = makeFabric('bob')
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    // No prior join for alice — key will be imported from the offer's pubKey field

    const nonce = crypto.randomUUID()
    const ts = Date.now()
    const sdp = 'v=0 first-offer-no-join'
    const aliceCanonical = canonical({
      type: 'offer', session: 'sess-1', to: 'bob', from: 'alice',
      nonce, ts, sdp, pubKey: alicePubKeyB64,
    })
    const sig = await signMsg(aliceKP.privateKey, aliceCanonical)

    ws._message({
      channel: 'signal',
      from: 'alice',
      payload: { type: 'offer', session: 'sess-1', to: 'bob', sdp, nonce, ts, sig, pubKey: alicePubKeyB64 },
    })

    // importKey + verify + _onSignal + setRemoteDescription all run via crypto
    // threadpool — wait until setRemoteDescription is actually called.
    await waitFor(() => FakePC.last?.remoteDescription?.type === 'offer')

    expect(FakePC.last.remoteDescription.type).toBe('offer')
    // Alice's key must have been stored during TOFU import
    expect(fc._signaling._peerKeys.has('alice')).toBe(true)
    fc.leave()
  })

  it('requirePeerAuth=false allows unsigned frames (backward-compat / fabricSignaling path)', async () => {
    // SignalingClient without signFrame/requirePeerAuth — replicates fabricSignaling.js usage
    const sc = new SignalingClient({
      signalingUrl: 'ws://localhost/sig',
      sessionId: 'sess-1',
      peerId: 'bob',
      // no signFrame, requirePeerAuth defaults to false
    })
    const signals = []
    sc.addEventListener('signal', ({ detail }) => signals.push(detail))
    sc.connect()

    const ws = FakeWebSocket.last
    ws._open()

    // Unsigned offer (no sig, no nonce) — passes through:
    //   bob has no stored key for alice and requirePeerAuth=false
    ws._message({
      channel: 'signal',
      from: 'alice',
      payload: { type: 'offer', session: 'sess-1', to: 'bob', sdp: 'v=0' },
    })
    // No WebCrypto ops in this path → one setTimeout(0) is sufficient
    await new Promise(r => setTimeout(r, 0))

    expect(signals).toHaveLength(1)
    expect(signals[0].payload.type).toBe('offer')
    sc.close()
  })
})

// ── 4. UNSIGNED RELAY-AUTH FALLBACK OFF BY DEFAULT ────────────────────────────

describe('FabricClient — unsigned relay-auth fallback disabled by default', () => {
  it('relay pickup sends NO Authorization header when authToken absent and allowUnsignedRelayAuth is false (default)', async () => {
    let capturedAuthHeader = 'SENTINEL'

    vi.stubGlobal('fetch', vi.fn(async (url, opts) => {
      if (String(url).includes('pickup')) {
        capturedAuthHeader = opts?.headers?.['Authorization']
        return { ok: true, json: async () => ({ blobs: [] }) }
      }
      return { ok: true, json: async () => ({ ice_servers: [] }) }
    }))

    const fc = new FabricClient({
      sessionId: 'sess-1',
      peerId: 'local',
      signalingUrl: 'ws://localhost/sig',
      iceUrl: '/api/peering/ice',
      // authToken: omitted — no JWT
      // allowUnsignedRelayAuth: omitted — default false
    })

    fc._peers.set('remote', {
      id: 'remote', state: 'relay', dc: null, pc: null,
      relayTimer: null, pendingCandidates: [], reset() {},
    })

    await fc._relayPoll()

    // Must be undefined — the forgeable "Vula-Relay <peerId>.<ts>" header
    // must NOT be emitted when allowUnsignedRelayAuth is false (default).
    expect(capturedAuthHeader).toBeUndefined()
    fc.leave()
  })

  it('relay deposit sends NO Authorization header when authToken absent (default)', async () => {
    let depositAuthHeader = 'SENTINEL'

    vi.stubGlobal('fetch', vi.fn(async (url, opts) => {
      if (String(url).includes('deposit')) {
        depositAuthHeader = opts?.headers?.['Authorization']
      }
      return { ok: true, json: async () => ({ ice_servers: [] }) }
    }))

    const fc = new FabricClient({
      sessionId: 'sess-1',
      peerId: 'local',
      signalingUrl: 'ws://localhost/sig',
      iceUrl: '/api/peering/ice',
    })

    await fc._ensureDepositKey()
    // Register a recipient box key so the deposit is not skipped (fail-closed
    // E2E path requires the peer's X25519 key to encrypt to).
    fc._signaling._peerBoxKeys.set('remote', fc._boxPubKeyB64)
    await fc._relayDeposit('remote', 'hello')

    // No JWT → no Authorization header on deposit either
    expect(depositAuthHeader).toBeUndefined()
    fc.leave()
  })

  it('the forgeable Vula-Relay header is only emitted when allowUnsignedRelayAuth=true (explicit opt-in)', async () => {
    let capturedHeader

    vi.stubGlobal('fetch', vi.fn(async (url, opts) => {
      if (String(url).includes('pickup')) {
        capturedHeader = opts?.headers?.['Authorization']
        return { ok: true, json: async () => ({ blobs: [] }) }
      }
      return { ok: true, json: async () => ({ ice_servers: [] }) }
    }))

    const fc = new FabricClient({
      sessionId: 'sess-1',
      peerId: 'local',
      signalingUrl: 'ws://localhost/sig',
      iceUrl: '/api/peering/ice',
      allowUnsignedRelayAuth: true,  // explicit opt-in
    })

    fc._peers.set('remote', {
      id: 'remote', state: 'relay', dc: null, pc: null,
      relayTimer: null, pendingCandidates: [], reset() {},
    })

    await fc._relayPoll()

    // With explicit opt-in, the header is present
    expect(capturedHeader).toMatch(/^Vula-Relay local\.\d+$/)
    fc.leave()
  })
})

// ── 5. FabricClient E2E: outgoing signals are signed ─────────────────────────

describe('FabricClient — outgoing signals carry signature and nonce', () => {
  it('join() sends the deposit pubkey in the join frame', async () => {
    const fc = makeFabric('local')
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    const join = JSON.parse(ws.sent[0])
    expect(join.payload.type).toBe('join')
    expect(join.payload.depositPubKey).toBe(fc._depositPubKeyB64)
    fc.leave()
  })

  it('outgoing offer (as impolite peer) carries nonce, sig, and pubKey', async () => {
    // a-local < z-remote → a-local is impolite (sends offer)
    const aliceKP = await generatePeerKey()
    const alicePubKeyB64 = await exportPubKeyB64(aliceKP)

    const fc = makeFabric('a-local')
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()
    ws.sent.length = 0

    // Trigger offer by delivering z-remote's join
    ws._message({
      channel: 'signal',
      from: 'z-remote',
      payload: { type: 'join', session: 'sess-1', depositPubKey: alicePubKeyB64 },
    })

    // Wait for the signed offer to appear in ws.sent (real WebCrypto → macrotask)
    await waitFor(() => ws.sent.some(raw => {
      try { return JSON.parse(raw).payload?.type === 'offer' } catch { return false }
    }))

    const offerFrame = ws.sent
      .map(raw => { try { return JSON.parse(raw) } catch { return null } })
      .find(f => f?.payload?.type === 'offer')

    expect(offerFrame).toBeTruthy()
    const p = offerFrame.payload
    expect(typeof p.nonce).toBe('string')
    expect(p.nonce.length).toBeGreaterThan(0)
    expect(typeof p.sig).toBe('string')
    expect(p.sig.length).toBeGreaterThan(0)
    expect(p.pubKey).toBe(fc._depositPubKeyB64)
    fc.leave()
  })

  it('the outgoing offer signature verifies against the local deposit pubkey', async () => {
    const fc = makeFabric('a-local')
    await fc.join()
    await fc._ensureDepositKey()

    const aliceKP = await generatePeerKey()
    const alicePubKeyB64 = await exportPubKeyB64(aliceKP)

    const ws = FakeWebSocket.last
    ws._open()
    ws.sent.length = 0

    ws._message({
      channel: 'signal',
      from: 'z-remote',
      payload: { type: 'join', session: 'sess-1', depositPubKey: alicePubKeyB64 },
    })

    await waitFor(() => ws.sent.some(raw => {
      try { return JSON.parse(raw).payload?.type === 'offer' } catch { return false }
    }))

    const offerFrame = ws.sent
      .map(raw => { try { return JSON.parse(raw) } catch { return null } })
      .find(f => f?.payload?.type === 'offer')

    expect(offerFrame).toBeTruthy()
    const p = offerFrame.payload

    // Export and import the local pubkey in a form suitable for verify()
    const localPubKeyRaw = await crypto.subtle.exportKey('raw', fc._depositKeyPair.publicKey)
    const localPubKey = await crypto.subtle.importKey(
      'raw', localPubKeyRaw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'],
    )

    const reconstructed = canonical({
      type: 'offer',
      session: 'sess-1',
      to: 'z-remote',
      from: 'a-local',
      nonce: p.nonce,
      ts: p.ts,
      sdp: p.sdp,
      pubKey: p.pubKey,
    })

    const sigBuf = Uint8Array.from(atob(p.sig), c => c.charCodeAt(0))
    const msgBuf = new TextEncoder().encode(reconstructed)
    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      localPubKey,
      sigBuf,
      msgBuf,
    )

    expect(valid).toBe(true)
    fc.leave()
  })
})

// ── 6. requirePeerAuth=true (FabricClient default) ────────────────────────────

describe('FabricClient — requirePeerAuth=true (default) rejects unknown peers', () => {
  it('drops an offer from a peer with no stored key when requirePeerAuth=true (default)', async () => {
    // makeFabric creates a FabricClient without explicit requirePeerAuth,
    // so it defaults to true (changed from the previous hardcoded false).
    const fc = makeFabric('bob')
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    // alice sends an unsigned offer without a prior join (no pubKey stored, no sig)
    ws._message({
      channel: 'signal',
      from: 'alice',
      payload: {
        type: 'offer', session: 'sess-1', to: 'bob',
        sdp: 'v=0 unsigned-from-unknown-peer',
        // No pubKey, no nonce, no sig — unknown peer
      },
    })
    await sleep(50)

    // requirePeerAuth=true: no key for alice and no inline pubKey → offer is dropped
    // at the SignalingClient layer before _onSignal is called, so no peer state is
    // created for alice and no PC is instantiated.
    expect(fc._peers.has('alice')).toBe(false)
    expect(FakePC.instances.length).toBe(0)
    fc.leave()
  })

  it('still accepts an offer carrying a valid pubKey+sig (TOFU import on first offer)', async () => {
    // requirePeerAuth=true but the offer carries pubKey inline → TOFU import →
    // verify sig → if valid, accept.  This is the upgrade path: on first contact
    // the offer itself bootstraps trust.
    const aliceKP = await generatePeerKey()
    const alicePubKeyB64 = await exportPubKeyB64(aliceKP)

    const fc = makeFabric('bob')
    await fc.join()
    const ws = FakeWebSocket.last
    ws._open()

    // alice sends a signed offer with her inline pubKey (no prior join needed)
    const nonce = crypto.randomUUID()
    const ts = Date.now()
    const sdp = 'v=0 inline-pubkey-offer'
    const sig = await signMsg(aliceKP.privateKey, canonical({
      type: 'offer', session: 'sess-1', to: 'bob', from: 'alice',
      nonce, ts, sdp, pubKey: alicePubKeyB64,
    }))

    ws._message({
      channel: 'signal',
      from: 'alice',
      payload: {
        type: 'offer', session: 'sess-1', to: 'bob',
        sdp, nonce, ts, sig, pubKey: alicePubKeyB64,
      },
    })

    // TOFU import + verify + _onSignal + setRemoteDescription are all async
    await waitFor(() => FakePC.last?.remoteDescription?.type === 'offer')
    expect(FakePC.last.remoteDescription.type).toBe('offer')
    fc.leave()
  })

  it('FabricClient with explicit requirePeerAuth=false allows unsigned frames (legacy mode)', async () => {
    // Operators who need to interoperate with pre-auth SDK peers can opt out.
    const signals = []
    const sc = new SignalingClient({
      signalingUrl: 'ws://localhost/sig',
      sessionId: 'sess-1',
      peerId: 'bob',
      requirePeerAuth: false,
    })
    sc.addEventListener('signal', ({ detail }) => signals.push(detail))
    sc.connect()
    const ws = FakeWebSocket.last
    ws._open()

    ws._message({
      channel: 'signal',
      from: 'alice',
      payload: { type: 'offer', session: 'sess-1', to: 'bob', sdp: 'v=0 unsigned' },
    })
    // No WebCrypto ops on this path → a single tick is enough
    await new Promise(r => setTimeout(r, 0))

    expect(signals).toHaveLength(1)
    expect(signals[0].payload.type).toBe('offer')
    sc.close()
  })
})

// ── 7. Replay protection — nonce deduplication ───────────────────────────────

describe('SignalingClient — replay protection', () => {
  it('drops a frame whose (from, nonce) pair has already been processed', async () => {
    const aliceKP = await generatePeerKey()
    const alicePubKeyB64 = await exportPubKeyB64(aliceKP)

    const sc = new SignalingClient({
      signalingUrl: 'ws://localhost/sig',
      sessionId: 'sess-1',
      peerId: 'bob',
      requirePeerAuth: false,
    })
    // Track only offer/answer/ice signals — join frames are also dispatched as
    // 'signal' events and would inflate the count if not filtered out.
    const offerSignals = []
    sc.addEventListener('signal', ({ detail }) => {
      if (detail.payload.type === 'offer' || detail.payload.type === 'answer') {
        offerSignals.push(detail)
      }
    })
    sc.connect()

    const ws = FakeWebSocket.last
    ws._open()

    // Register alice's key via join (this ALSO dispatches a 'signal' event, hence the filter)
    ws._message({
      channel: 'signal',
      from: 'alice',
      payload: { type: 'join', session: 'sess-1', depositPubKey: alicePubKeyB64 },
    })
    await waitFor(() => sc._peerKeys.has('alice'))

    // Build a valid signed offer
    const nonce = crypto.randomUUID()
    const ts = Date.now()
    const sdp = 'v=0 replay-test'
    const sig = await signMsg(aliceKP.privateKey, canonical({
      type: 'offer', session: 'sess-1', to: 'bob', from: 'alice',
      nonce, ts, sdp, pubKey: alicePubKeyB64,
    }))

    const frame = {
      channel: 'signal',
      from: 'alice',
      payload: { type: 'offer', session: 'sess-1', to: 'bob', sdp, nonce, ts, sig, pubKey: alicePubKeyB64 },
    }

    // First delivery — should be accepted.
    // Poll the nonce cache directly (populated before dispatchEvent) so we know
    // the nonce is definitely stored when we attempt the replay below.
    ws._message(frame)
    await waitFor(() => sc._seenNonces.size > 0, { timeout: 500 })
    expect(offerSignals).toHaveLength(1)
    expect(sc._seenNonces.has(`alice:${nonce}`)).toBe(true)

    // Second delivery (exact replay) — must be dropped by the nonce cache.
    ws._message(frame)
    await sleep(100)
    expect(offerSignals).toHaveLength(1)   // still 1; replay was silently dropped

    sc.close()
  })

  it('accepts two offers with the same content but different nonces (not a replay)', async () => {
    const aliceKP = await generatePeerKey()
    const alicePubKeyB64 = await exportPubKeyB64(aliceKP)

    const sc = new SignalingClient({
      signalingUrl: 'ws://localhost/sig',
      sessionId: 'sess-1',
      peerId: 'bob',
      requirePeerAuth: false,
    })
    const offerSignals = []
    sc.addEventListener('signal', ({ detail }) => {
      if (detail.payload.type === 'offer' || detail.payload.type === 'answer') {
        offerSignals.push(detail)
      }
    })
    sc.connect()

    const ws = FakeWebSocket.last
    ws._open()

    ws._message({
      channel: 'signal',
      from: 'alice',
      payload: { type: 'join', session: 'sess-1', depositPubKey: alicePubKeyB64 },
    })
    await waitFor(() => sc._peerKeys.has('alice'))

    const sdp = 'v=0 two-offers'

    // First offer with nonce-1
    const nonce1 = crypto.randomUUID()
    const ts1 = Date.now()
    const sig1 = await signMsg(aliceKP.privateKey, canonical({
      type: 'offer', session: 'sess-1', to: 'bob', from: 'alice',
      nonce: nonce1, ts: ts1, sdp, pubKey: alicePubKeyB64,
    }))
    ws._message({
      channel: 'signal',
      from: 'alice',
      payload: { type: 'offer', session: 'sess-1', to: 'bob', sdp, nonce: nonce1, ts: ts1, sig: sig1, pubKey: alicePubKeyB64 },
    })
    await waitFor(() => offerSignals.length === 1, { timeout: 500 })

    // Second offer with nonce-2 — different nonce, so it is NOT a replay.
    const nonce2 = crypto.randomUUID()
    const ts2 = Date.now()
    const sig2 = await signMsg(aliceKP.privateKey, canonical({
      type: 'offer', session: 'sess-1', to: 'bob', from: 'alice',
      nonce: nonce2, ts: ts2, sdp, pubKey: alicePubKeyB64,
    }))
    ws._message({
      channel: 'signal',
      from: 'alice',
      payload: { type: 'offer', session: 'sess-1', to: 'bob', sdp, nonce: nonce2, ts: ts2, sig: sig2, pubKey: alicePubKeyB64 },
    })
    await waitFor(() => offerSignals.length === 2, { timeout: 500 })

    expect(offerSignals).toHaveLength(2)
    sc.close()
  })
})
