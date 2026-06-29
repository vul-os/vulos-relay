/**
 * fabric.js — Vulos Office fabric client adapter (OFFICE-20).
 *
 * Joins a Vulos fabric session for a given document/session id:
 *  1. Fetches ICE/TURN credentials from the OS relay  (/api/peering/ice  or
 *     the cloud /api/turn/credentials as fallback).
 *  2. Opens a SignalingClient to the OS peering WebSocket stream.
 *  3. Negotiates a WebRTC RTCPeerConnection per remote peer (offer/answer/ICE
 *     via the "signal" channel).
 *  4. Opens an RTCDataChannel for duplex application messages.
 *  5. Falls back to a relay circuit (via the Vulos relay deposit/pickup HTTP
 *     API) when the data channel cannot be established within RELAY_TIMEOUT_MS.
 *
 * Usage:
 *   const fc = new FabricClient({ sessionId, peerId, signalingUrl, iceUrl })
 *   fc.addEventListener('message', ({ detail: { from, data } }) => …)
 *   fc.addEventListener('state',   ({ detail: { peerId, state } }) => …)
 *   await fc.join()
 *   fc.send(data)           // broadcast to all connected peers
 *   fc.sendTo(peerId, data) // unicast
 *   fc.leave()
 *
 * State values: 'connecting' | 'connected' | 'relay' | 'disconnected'
 *
 * Pure JS/JSX — no CGO, no native deps.
 */

import { SignalingClient } from './signaling.js'
import { fetchIce, resolveStunFallback } from './call/ice.js'

/**
 * Byte-length of a relay payload datum.  Used by the billing meter to count
 * application-payload bytes without HTTP framing or base64 expansion.
 *
 * @param {string|ArrayBuffer|ArrayBufferView|any} data
 * @returns {number}
 */
function _byteSize(data) {
  if (data == null) return 0
  if (data instanceof ArrayBuffer) return data.byteLength
  if (ArrayBuffer.isView(data)) return data.byteLength
  const s = typeof data === 'string' ? data : JSON.stringify(data)
  try {
    return new TextEncoder().encode(s).byteLength
  } catch {
    return s.length   // safe fallback when TextEncoder unavailable
  }
}

const DATA_CHANNEL_LABEL = 'vulos-office-fabric'
const RELAY_TIMEOUT_MS = 8_000        // give P2P this long before falling back
const RELAY_POLL_MS = 2_000           // relay pickup polling interval
const RELAY_TTL_HOURS = 1

// ── DoS / resource caps ───────────────────────────────────────────────────────
const MAX_PENDING_CANDIDATES = 50     // per-peer ICE candidate queue (MED-DoS)
const MAX_PEERS = 50                  // per-session peer map (MED-DoS)
const MAX_PAYLOAD_BYTES = 256 * 1024  // data-channel + relay blob cap, 256 KB (MED-DoS)

export class FabricClient extends EventTarget {
  /**
   * @param {object} opts
   * @param {string}   opts.sessionId      - document / room id
   * @param {string}   opts.peerId         - this peer's identity
   * @param {string}   opts.signalingUrl   - ws[s]://host/api/peering/stream
   * @param {string}  [opts.iceUrl]        - GET URL returning { ice_servers: [...] }
   *                                         defaults to /api/peering/ice
   * @param {string}  [opts.relayBaseUrl]  - base URL for relay deposit/pickup
   *                                         defaults to '' (same origin)
   * @param {string}  [opts.authToken]     - Bearer JWT (optional)
   * @param {boolean} [opts.allowUnsignedRelayAuth]
   *        - opt in to the unsigned "Vula-Relay <peerId>.<ts>" fallback auth
   *          header when no authToken is configured. This header is forgeable
   *          (anyone can claim any peerId), so it is OFF by default; without it
   *          and without a JWT, the relay request is sent with no Authorization
   *          header and the server's accept policy decides.
   * @param {boolean} [opts.requirePeerAuth=true]
   *        - when true (default), offer/answer/ice frames from peers with no
   *          stored public key are dropped — only keyed (signed) peers can
   *          establish WebRTC connections. Set to false to revert to TOFU-only
   *          behaviour and accept unsigned frames from unknown peers (needed
   *          when interoperating with pre-auth SDK versions).
   */
  constructor({
    sessionId,
    peerId,
    signalingUrl,
    iceUrl = '/api/peering/ice',
    relayBaseUrl = '',
    authToken = null,
    allowUnsignedRelayAuth = false,
    requirePeerAuth = true,
  }) {
    super()
    this._session = sessionId
    this._peerId = peerId
    this._iceUrl = iceUrl
    this._relayBase = relayBaseUrl
    this._authToken = authToken
    this._allowUnsignedRelayAuth = allowUnsignedRelayAuth
    this._requirePeerAuth = requirePeerAuth

    /** @type {Map<string, PeerState>} */
    this._peers = new Map()
    this._iceServers = []
    this._relayPollTimer = null
    this._stopped = false
    /** @type {CryptoKeyPair|null} — lazily generated on first deposit */
    this._depositKeyPair = null
    /** @type {string|null} — base64 raw public key for signaling announce */
    this._depositPubKeyB64 = null

    // ── Billing G-1: authoritative relay byte meter ───────────────────────────
    // Counts payload bytes transported via the relay fallback path.  These are
    // the bytes of the application `data` argument (not HTTP framing or base64
    // overhead).  The host backend reads these via relayByteCount / emits them
    // to CP as usage.  See docs/RELAY_BYTE_METER.md for the full contract.
    /** @type {number} bytes deposited (sent) via relay in this session */
    this._relayedBytesOut = 0
    /** @type {number} bytes picked up (received) via relay in this session */
    this._relayedBytesIn = 0

    this._signaling = new SignalingClient({
      signalingUrl,
      sessionId,
      peerId,
      authToken,
      // Publish the deposit signing public key in the join frame so the relay
      // server can bind it to our authenticated peerId and verify deposit sigs.
      getDepositPubKey: () => this._depositPubKeyB64,
      // ── E2E peer authentication (security audit MEDIUM) ────────────────────
      // Wire the per-session ECDSA signing key into the signaling layer so that
      // all outgoing offer/answer/ice frames are signed.  The canonical signing
      // message includes `from` (binding sender identity) and, for offer/answer,
      // the full SDP (pinning the DTLS fingerprint).  Receivers verify using the
      // sender's pubkey from the prior 'join' frame or the embedded pubKey field.
      signFrame: (msg) => this._signDeposit(msg),
      // Surface the caller-supplied requirePeerAuth (default true).  When true,
      // offer/answer/ice frames from peers with no stored public key are dropped
      // outright — no TOFU fallback for unkeyed peers.  Frames from peers whose
      // key IS stored are always verified regardless of this flag.
      requirePeerAuth: this._requirePeerAuth,
    })
    this._signaling.addEventListener('signal', (ev) => this._onSignal(ev.detail))
    this._signaling.addEventListener('signaling-open', () => {
      // Re-offer to any existing peers after a reconnect.
      for (const [id, ps] of this._peers) {
        if (ps.state === 'disconnected') this._initiatePeer(id)
      }
    })
    this._signaling.addEventListener('signaling-close', () => {
      // Signaling dropped — data channels may still be alive.
    })
  }

  // ─── Public API ────────────────────────────────────────────────────────────

  /** Connect to the fabric session.  Resolves once signaling is up. */
  async join() {
    this._iceServers = await this._fetchICE()
    // Generate the deposit signing key up front so its public key is available
    // for the signaling "join" frame (the server binds it to our peerId).
    await this._ensureDepositKey()
    this._signaling.connect()
  }

  /** Broadcast a message to all connected peers. */
  send(data) {
    for (const ps of this._peers.values()) {
      this._sendToPeer(ps, data)
    }
  }

  /** Send a message to one specific peer. */
  sendTo(peerId, data) {
    const ps = this._peers.get(peerId)
    if (ps) this._sendToPeer(ps, data)
  }

  /** Disconnect from all peers and the signaling channel. */
  leave() {
    this._stopped = true
    clearInterval(this._relayPollTimer)
    for (const ps of this._peers.values()) {
      ps.dc?.close()
      ps.pc?.close()
    }
    this._peers.clear()
    this._signaling.close()
  }

  /** Read-only snapshot of current peer states. */
  get peerStates() {
    const out = {}
    for (const [id, ps] of this._peers) out[id] = ps.state
    return out
  }

  // ── Billing G-1: relay byte meter ─────────────────────────────────────────

  /**
   * Authoritative relay byte count for this session.
   *
   * Contract (see docs/RELAY_BYTE_METER.md):
   *   • `out` — total application-payload bytes deposited to the relay server.
   *   • `in`  — total application-payload bytes picked up from the relay server.
   *   • `total` — `out + in` (useful for cap enforcement / billing period quota).
   *
   * "Payload bytes" means the byte length of the `data` argument to send() /
   * sendTo() that was routed through the relay; HTTP framing and base64
   * expansion are NOT counted.  This is the number CP should debit against the
   * session's relay allowance.
   *
   * The host backend should read this counter at the end of a session (or on a
   * periodic flush) and emit it to CP via the usage-report endpoint.
   *
   * @returns {{ out: number, in: number, total: number }}
   */
  get relayByteCount() {
    return {
      out: this._relayedBytesOut,
      in:  this._relayedBytesIn,
      total: this._relayedBytesOut + this._relayedBytesIn,
    }
  }

  /**
   * Reset the relay byte counters to zero.
   * Call at the start of each billing period / usage-report flush window so
   * the host backend can report incremental usage rather than cumulative totals.
   */
  resetRelayByteCount() {
    this._relayedBytesOut = 0
    this._relayedBytesIn = 0
  }

  // ─── ICE / TURN ────────────────────────────────────────────────────────────

  async _fetchICE() {
    const headers = this._authToken ? { Authorization: `Bearer ${this._authToken}` } : {}
    return fetchIce(this._iceUrl, {
      responseKey: 'ice_servers',
      fetchOptions: { headers },
      fallbackIceServers: resolveStunFallback(),
    })
  }

  // ─── Peer management ───────────────────────────────────────────────────────

  _getOrCreatePeer(remoteId) {
    if (this._peers.has(remoteId)) return this._peers.get(remoteId)
    if (this._peers.size >= MAX_PEERS) {
      console.warn('[fabric] peer limit reached, dropping peer', remoteId)
      return null
    }
    const ps = new PeerState(remoteId)
    this._peers.set(remoteId, ps)
    return ps
  }

  /** Initiate an offer to a remote peer (called when we see their 'join'). */
  async _initiatePeer(remoteId) {
    const ps = this._getOrCreatePeer(remoteId)
    if (!ps) return                       // peer limit reached
    if (ps.state === 'connected') return
    ps.reset()

    const pc = this._buildPC(remoteId, ps)
    ps.pc = pc

    // Polite peer: lexicographically smaller peerId defers (impolite = offerer).
    const impolite = this._peerId < remoteId
    if (!impolite) return  // wait for the other side to offer

    const dc = pc.createDataChannel(DATA_CHANNEL_LABEL)
    ps.dc = dc
    this._wireDataChannel(dc, remoteId, ps)

    try {
      const offer = await pc.createOffer()
      await pc.setLocalDescription(offer)
      this._setRelayTimer(remoteId, ps)
      // Include pubKey so the recipient can verify even before our 'join'
      // was processed (handles out-of-order delivery).  The SDP embeds the
      // DTLS fingerprint; signing the full payload pins it end-to-end.
      await this._signaling.signal('offer', remoteId, {
        sdp: pc.localDescription.sdp,
        pubKey: this._depositPubKeyB64,
      })
      this._setPeerState(remoteId, ps, 'connecting')
    } catch (err) {
      console.error('[fabric] offer error:', err)
    }
  }

  _buildPC(remoteId, ps) {
    const pc = new RTCPeerConnection({ iceServers: this._iceServers })

    pc.addEventListener('icecandidate', ({ candidate }) => {
      if (candidate) {
        // signal() is async (signs the frame); fire-and-forget from this sync
        // event handler.  ICE candidates are best-effort — a dropped candidate
        // only delays connectivity, it does not break the session.
        this._signaling.signal('ice', remoteId, { candidate: candidate.toJSON() })
          .catch(err => console.warn('[fabric] ICE signal error:', err))
      }
    })

    pc.addEventListener('connectionstatechange', () => {
      const s = pc.connectionState
      if (s === 'connected') {
        clearTimeout(ps.relayTimer)
        this._setPeerState(remoteId, ps, 'connected')
      } else if (s === 'failed' || s === 'closed') {
        clearTimeout(ps.relayTimer)
        if (!this._stopped && ps.state !== 'relay') {
          this._activateRelay(remoteId, ps)
        }
      }
    })

    pc.addEventListener('datachannel', ({ channel }) => {
      ps.dc = channel
      this._wireDataChannel(channel, remoteId, ps)
    })

    return pc
  }

  _wireDataChannel(dc, remoteId, ps) {
    dc.binaryType = 'arraybuffer'

    dc.addEventListener('open', () => {
      clearTimeout(ps.relayTimer)
      this._setPeerState(remoteId, ps, 'connected')
    })

    dc.addEventListener('message', ({ data }) => {
      if (_byteSize(data) > MAX_PAYLOAD_BYTES) {
        console.warn('[fabric] oversized data-channel payload from', remoteId, '— dropped')
        return
      }
      this.dispatchEvent(new CustomEvent('message', { detail: { from: remoteId, data } }))
    })

    dc.addEventListener('close', () => {
      if (!this._stopped) {
        this._setPeerState(remoteId, ps, 'disconnected')
        // Attempt reconnect after a short back-off.
        setTimeout(() => {
          if (!this._stopped) this._initiatePeer(remoteId)
        }, 2_000)
      }
    })

    dc.addEventListener('error', (ev) => {
      console.warn('[fabric] data channel error:', ev)
    })
  }

  // ─── Signaling handler ─────────────────────────────────────────────────────

  async _onSignal({ from, payload }) {
    const { type, sdp, candidate } = payload
    if (from === this._peerId) return   // ignore self-echoes

    if (type === 'join') {
      await this._initiatePeer(from)
      return
    }

    if (type === 'leave') {
      const ps = this._peers.get(from)
      if (ps) {
        ps.dc?.close()
        ps.pc?.close()
        this._setPeerState(from, ps, 'disconnected')
      }
      return
    }

    const ps = this._getOrCreatePeer(from)
    if (!ps) return                       // peer limit reached

    if (type === 'offer') {
      ps.reset()
      const pc = this._buildPC(from, ps)
      ps.pc = pc
      try {
        await pc.setRemoteDescription({ type: 'offer', sdp })
        // Apply any queued candidates.
        for (const c of ps.pendingCandidates) await pc.addIceCandidate(c)
        ps.pendingCandidates = []
        const answer = await pc.createAnswer()
        await pc.setLocalDescription(answer)
        this._setRelayTimer(from, ps)
        // Include pubKey in answer for the same reason as in the offer: allows
        // the offerer to verify even if they missed our 'join'.  The signed SDP
        // also pins the answerer's DTLS fingerprint against MITM swap.
        await this._signaling.signal('answer', from, {
          sdp: pc.localDescription.sdp,
          pubKey: this._depositPubKeyB64,
        })
        this._setPeerState(from, ps, 'connecting')
      } catch (err) {
        console.error('[fabric] answer error:', err)
      }
    } else if (type === 'answer') {
      if (!ps.pc) return
      try {
        await ps.pc.setRemoteDescription({ type: 'answer', sdp })
        for (const c of ps.pendingCandidates) await ps.pc.addIceCandidate(c)
        ps.pendingCandidates = []
      } catch (err) {
        console.error('[fabric] setRemoteDescription answer error:', err)
      }
    } else if (type === 'ice') {
      if (!candidate) return
      if (ps.pc && ps.pc.remoteDescription) {
        try { await ps.pc.addIceCandidate(candidate) } catch { /* ignore stale */ }
      } else if (ps.pendingCandidates.length < MAX_PENDING_CANDIDATES) {
        ps.pendingCandidates.push(candidate)
      }
      // else: silently drop — candidates beyond the cap are best-effort anyway
    }
  }

  // ─── Relay fallback ────────────────────────────────────────────────────────

  _setRelayTimer(remoteId, ps) {
    clearTimeout(ps.relayTimer)
    ps.relayTimer = setTimeout(() => {
      if (ps.state !== 'connected') {
        this._activateRelay(remoteId, ps)
      }
    }, RELAY_TIMEOUT_MS)
  }

  _activateRelay(remoteId, ps) {
    if (ps.state === 'relay') return
    console.info(`[fabric] P2P failed for ${remoteId}; switching to relay circuit`)
    this._setPeerState(remoteId, ps, 'relay')
    this._startRelayPolling()
  }

  /** Start polling the relay pickup endpoint for any peers in relay mode. */
  _startRelayPolling() {
    if (this._relayPollTimer) return
    this._relayPollTimer = setInterval(() => this._relayPoll(), RELAY_POLL_MS)
  }

  async _relayPoll() {
    const relayPeers = [...this._peers.entries()].filter(([, ps]) => ps.state === 'relay')
    if (relayPeers.length === 0) {
      clearInterval(this._relayPollTimer)
      this._relayPollTimer = null
      return
    }
    try {
      const headers = { 'Content-Type': 'application/json' }
      if (this._authToken) {
        // Bearer JWT takes precedence when present.
        headers['Authorization'] = `Bearer ${this._authToken}`
      } else if (this._allowUnsignedRelayAuth) {
        // Forgeable unsigned fallback: "Vula-Relay <peerId>.<ts>" (anyone can
        // claim any peerId). Only emitted when the caller has explicitly opted
        // in via allowUnsignedRelayAuth; relay accept policy decides the rest.
        headers['Authorization'] = `Vula-Relay ${this._peerId}.${Math.floor(Date.now() / 1000)}`
      }

      const res = await fetch(`${this._relayBase}/api/peering/relay/pickup`, {
        method: 'GET',
        headers,
      })
      if (!res.ok) return
      const { blobs } = await res.json()
      if (!Array.isArray(blobs)) return

      const ackIds = []
      for (const blob of blobs) {
        try {
          // ── MED-DoS: relay blob size cap ────────────────────────────────────
          const rawPayload = atob(blob.blob_b64)
          if (rawPayload.length > MAX_PAYLOAD_BYTES) continue  // oversized → drop
          const msg = JSON.parse(rawPayload)
          if (msg.session !== this._session) continue

          // ── MED: verify relay-blob inbound signature ─────────────────────────
          // The depositor signs { to, from, nonce, blob_b64 } (see _relayDeposit).
          // If we hold a key for the sender (imported via signaling join / TOFU),
          // the blob MUST carry a valid signature.  Unknown senders (no key held)
          // are allowed through for backward compat with pre-auth relay clients.
          if (blob.sig && blob.nonce) {
            const sigMsg = JSON.stringify({
              to: this._peerId,
              from: blob.from,
              nonce: blob.nonce,
              blob_b64: blob.blob_b64,
            })
            const result = await this._signaling.verifyPeerSig(blob.from, sigMsg, blob.sig)
            if (result === false) continue  // key held + sig invalid → tamper/impersonation
            // result === null: no key stored → allow through (backward compat)
          } else if (this._signaling.hasPeerKey(blob.from)) {
            // Sender published a key via signaling but blob is unsigned.
            // Reject: prevents server-injected blobs and pre-auth-era replays
            // from being accepted once the sender has upgraded to signed deposits.
            continue
          }

          // ── billing meter: count inbound payload bytes ─────────────────────
          this._relayedBytesIn += _byteSize(msg.data)
          this.dispatchEvent(new CustomEvent('message', { detail: { from: blob.from, data: msg.data } }))
          ackIds.push(blob.id)
        } catch { /* malformed blob, skip */ }
      }

      if (ackIds.length) {
        await fetch(`${this._relayBase}/api/peering/relay/ack`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ blob_ids: ackIds }),
        }).catch(() => { /* best-effort */ })
      }
    } catch (err) {
      console.warn('[fabric] relay poll error:', err.message)
    }
  }

  /**
   * Deposit a message via the Vulos relay for a specific peer.
   *
   * Integrity signature: the deposit payload (blob_b64 + nonce + to + from)
   * is signed with a per-session ECDSA P-256 key held in memory.  The relay
   * server SHOULD verify this signature using the public key exchanged during
   * the signaling join — see `depositPubKey` in the join payload (published by
   * signaling.js, bound server-side to the authenticated peerId).  If the
   * relay does not yet enforce signature verification it MUST at minimum check
   * that the `from` field matches the authenticated peerId (JWT sub or
   * Vula-Relay header).
   *
   * Trust model: unsigned deposits are rejected by a correctly-configured
   * relay server.  Signed-but-unverified (relay not updated) degrades to the
   * previous unsigned behaviour until the server enforces verification.
   */
  async _relayDeposit(toPeerId, data) {
    // ── billing meter: count outbound payload bytes before encoding ──────────
    this._relayedBytesOut += _byteSize(data)
    try {
      const headers = { 'Content-Type': 'application/json' }
      if (this._authToken) headers['Authorization'] = `Bearer ${this._authToken}`
      const payload = { session: this._session, data }
      const blob_b64 = btoa(JSON.stringify(payload))
      const nonce = crypto.randomUUID()

      // Build the signing message: canonical JSON of the fields the server
      // can reconstruct independently (to, from, nonce, blob_b64).
      const signingMsg = JSON.stringify({
        to: toPeerId,
        from: this._peerId,
        nonce,
        blob_b64,
      })

      // Sign with the session signing key (lazily generated ECDSA P-256).
      // The corresponding public key is published in the signaling join payload.
      const sigB64 = await this._signDeposit(signingMsg)

      await fetch(`${this._relayBase}/api/peering/relay/deposit`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          to: toPeerId,
          from: this._peerId,
          blob_b64,
          ttl_hours: RELAY_TTL_HOURS,
          nonce,
          sig: sigB64,
        }),
      })
    } catch (err) {
      console.warn('[fabric] relay deposit error:', err.message)
    }
  }

  /**
   * Lazily generate (or reuse) a per-session ECDSA P-256 signing key and export
   * its raw public key as base64 into `_depositPubKeyB64`.
   *
   * Called eagerly from join() so the public key is available for the signaling
   * "join" announcement — the server binds it to the authenticated peerId and
   * uses it to verify deposit signatures.
   */
  async _ensureDepositKey() {
    if (this._depositKeyPair) return
    // Non-extractable: the private signing key must never leave the crypto
    // subsystem. Per the WebCrypto spec, generateKey() always marks the public
    // key of an asymmetric pair as extractable regardless of this flag, so the
    // public key can still be exported below while the private key cannot.
    this._depositKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,      // private key non-extractable; public key stays exportable
      ['sign', 'verify'],
    )
    // Export the public key for signaling announcement.
    const rawPub = await crypto.subtle.exportKey('raw', this._depositKeyPair.publicKey)
    this._depositPubKeyB64 = btoa(String.fromCharCode(...new Uint8Array(rawPub)))
  }

  /**
   * Sign `message` with the per-session ECDSA P-256 signing key and return a
   * base64 signature. Ensures the key exists first.
   *
   * @param {string} message
   * @returns {Promise<string>} base64 signature
   */
  async _signDeposit(message) {
    await this._ensureDepositKey()
    const enc = new TextEncoder()
    const sigBuf = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      this._depositKeyPair.privateKey,
      enc.encode(message),
    )
    return btoa(String.fromCharCode(...new Uint8Array(sigBuf)))
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  _setPeerState(peerId, ps, state) {
    ps.state = state
    this.dispatchEvent(new CustomEvent('state', { detail: { peerId, state } }))
  }

  _sendToPeer(ps, data) {
    if (ps.state === 'connected' && ps.dc && ps.dc.readyState === 'open') {
      ps.dc.send(data)
    } else if (ps.state === 'relay') {
      // Relay path: encode and deposit.
      this._relayDeposit(ps.id, data)
    }
    // 'connecting' / 'disconnected' → silently drop (caller should buffer).
  }
}

// ─── Internal per-peer state ────────────────────────────────────────────────

class PeerState {
  constructor(id) {
    this.id = id
    this.pc = null            // RTCPeerConnection
    this.dc = null            // RTCDataChannel
    this.state = 'disconnected'
    this.relayTimer = null
    this.pendingCandidates = []
  }

  reset() {
    clearTimeout(this.relayTimer)
    this.dc?.close()
    this.pc?.close()
    this.pc = null
    this.dc = null
    this.pendingCandidates = []
  }
}
