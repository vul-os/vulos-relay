/**
 * signaling.js — Vulos RELAY signaling client for vulos-office.
 *
 * Opens a WebSocket to the Vulos OS signaling stream
 * (GET /api/peering/stream) and multiplexes offer/answer/ICE frames
 * over the "signal" channel defined by the OS ws.go Hub.
 *
 * Frame envelope (mirrors ws.go):
 *   { channel: "signal", from: <userID>, payload: <SignalPayload> }
 *
 * SignalPayload:
 *   { type: "offer"|"answer"|"ice"|"join"|"leave",
 *     session: <sessionID>,
 *     to: <peerID>,          // targeted delivery (optional; omit = broadcast)
 *     sdp: <string>,         // offer / answer
 *     candidate: <RTCIceCandidateInit>,
 *     nonce: <uuid>,         // replay-protection nonce (required when sig present)
 *     sig: <base64>,         // ECDSA P-256 signature over canonical payload
 *     pubKey: <base64>,      // sender's raw ECDSA public key (offer/answer only)
 *   }
 *
 * ── E2E peer authentication (security audit MEDIUM) ──────────────────────────
 *
 * Problem: the `frame.from` field is stamped by the signaling server.  A
 * malicious server can set any `from` value to misroute or impersonate.
 * The `p.to` delivery filter is not sufficient protection.
 *
 * Solution implemented here:
 *
 *   1. PEER IDENTITY BINDING
 *      Each peer publishes its ECDSA P-256 public key in the "join" frame
 *      (`depositPubKey`).  The key is stored on first use (TOFU).  All
 *      subsequent offer/answer/ice frames from that peer must carry a valid
 *      ECDSA signature over a deterministic canonical message that includes
 *      the `from` field.  A server that stamps the wrong `from` causes the
 *      canonical reconstruction to differ → verification fails → frame dropped.
 *
 *   2. DTLS FINGERPRINT PINNING
 *      The canonical message for offer/answer includes the full SDP string,
 *      which in turn contains the DTLS fingerprint line
 *      (`a=fingerprint:sha-256 …`).  Signing the SDP implicitly pins the
 *      fingerprint: if a MITM signaling server replaces the SDP (and thus the
 *      fingerprint) the signature mismatch causes the frame to be dropped
 *      before `setRemoteDescription` is called.
 *
 *   3. KEY STORAGE MODEL (TOFU)
 *      The first pubkey seen for a given `from` is trusted.  Later joins from
 *      the same peer with a different key are ignored.  The security boundary
 *      is the server's JWT authentication, which binds `from` to an
 *      authenticated identity on the initial join.  A server that is honest at
 *      join time but dishonest later cannot forge frames because it does not
 *      hold the peer's private key.
 *
 *   Backward compatibility: when `signFrame` is null (e.g. fabricSignaling.js
 *   / BroadcastChannel stub), signing is skipped.  When `requirePeerAuth` is
 *   false (default) unsigned frames from peers without a stored key pass
 *   through.  Frames from peers WITH a stored key are always verified
 *   regardless of `requirePeerAuth`.
 */

const RECONNECT_BASE_MS = 1_000
const RECONNECT_MAX_MS = 30_000
const RECONNECT_MAX_ATTEMPTS = 10  // after this many failures emit 'offline'
const SIGNAL_CHANNEL = 'signal'

// Maximum seen-(from,nonce) entries across all peers (FIFO eviction at cap).
// 1 000 entries accommodate ≥ 16 concurrent peers each sending ~60 signed
// frames before the oldest entries are evicted.
const NONCE_CACHE_MAX = 1_000

// Prefix for carrying the auth JWT as a WebSocket subprotocol token. The full
// JWT is base64url (chars A-Za-z0-9-_ plus '.' segment separators) and unpadded,
// so `vula.token.<jwt>` is a valid RFC 6455 / RFC 7230 subprotocol token.
//
// ─── Server contract (audit MED — JWT in WS query string) ───────────────────
//   Default transport: the JWT is sent in the `Sec-WebSocket-Protocol` request
//   header, NOT the URL query string (which leaks into access logs, the browser
//   history/Referer, and proxies). The server MUST, during the WS upgrade:
//     1. Read `Sec-WebSocket-Protocol` (a comma-separated list of offered
//        subprotocols).
//     2. Find the entry beginning with `vula.token.`, strip that prefix, and
//        validate the remaining string as the Bearer JWT.
//     3. Complete the upgrade. Echoing a selected subprotocol back is optional
//        for browsers (an omitted response header still completes the
//        handshake); if the server does echo, it should echo a stable protocol
//        name and not the token value.
//   Tokens remain short-lived regardless of transport.
//
//   Legacy fallback: backends that cannot yet read the header may opt the
//   client back into the `?token=` query string by constructing the client with
//   `tokenTransport: 'query'`. This is OFF by default and exists only as a
//   migration shim.
const TOKEN_SUBPROTOCOL_PREFIX = 'vula.token.'

// ─── Canonical signing message ────────────────────────────────────────────────
//
// Deterministic JSON string signed over for offer/answer/ice frames.
// Field insertion order is fixed so sender and receiver produce identical JSON.
// The `from` field is included so a server that stamps the wrong `from` causes
// a canonical-message mismatch and the signature to not verify.
// For offer/answer, including `sdp` also pins the DTLS fingerprint.
//
// @internal — exported only for tests via peer-auth.test.js which re-implements it.
function _canonical({ type, session, to, from, nonce, sdp, candidate, pubKey }) {
  const msg = { type, session, to: to ?? null, from, nonce }
  if (sdp !== undefined) msg.sdp = sdp
  if (candidate !== undefined) msg.candidate = candidate
  if (pubKey !== undefined) msg.pubKey = pubKey
  return JSON.stringify(msg)
}

export class SignalingClient extends EventTarget {
  /**
   * @param {object} opts
   * @param {string}   opts.signalingUrl     - WebSocket URL, e.g. "ws://localhost:8080/api/peering/stream"
   * @param {string}   opts.sessionId        - fabric session / document id
   * @param {string}   opts.peerId           - this client's identity token (injected by auth)
   * @param {string}  [opts.authToken]       - Bearer JWT (if auth is enabled)
   * @param {'subprotocol'|'query'} [opts.tokenTransport='subprotocol']
   *        - how the auth JWT is delivered. 'subprotocol' (default) sends it in
   *          the Sec-WebSocket-Protocol header so it never appears in the URL.
   *          'query' is a legacy migration shim that appends ?token=<jwt> for
   *          backends that cannot yet read the header — see the server contract
   *          note at the top of this file.
   * @param {number}  [opts.maxAttempts]     - max reconnect attempts before 'offline' (default 10)
   * @param {() => (string|null)} [opts.getDepositPubKey]
   *        - optional callback returning this peer's base64 raw deposit signing
   *          public key. When it returns a non-null value, the key is published
   *          in the "join" frame so the server can bind it to the authenticated
   *          peerId and verify deposit signatures.
   * @param {((msg: string) => Promise<string>)|null} [opts.signFrame]
   *        - optional async callback that signs a canonical string and returns a
   *          base64 ECDSA signature. When provided, all outgoing offer/answer/ice
   *          frames are signed. Typically wired to FabricClient._signDeposit().
   * @param {boolean} [opts.requirePeerAuth=false]
   *        - when true, offer/answer/ice frames from peers with no stored public
   *          key are dropped (no TOFU fallback for unknown peers). Frames from
   *          peers with a stored key are ALWAYS verified regardless of this flag.
   *          Set to true in FabricClient for E2E peer authentication.
   */
  constructor({
    signalingUrl,
    sessionId,
    peerId,
    authToken = null,
    tokenTransport = 'subprotocol',
    maxAttempts = RECONNECT_MAX_ATTEMPTS,
    getDepositPubKey = null,
    signFrame = null,
    requirePeerAuth = false,
  }) {
    super()
    this._url = signalingUrl
    this._session = sessionId
    this._peerId = peerId
    this._authToken = authToken
    this._tokenTransport = tokenTransport === 'query' ? 'query' : 'subprotocol'
    this._getDepositPubKey = getDepositPubKey
    this._signFrame = signFrame
    this._requirePeerAuth = requirePeerAuth
    this._ws = null
    this._reconnectDelay = RECONNECT_BASE_MS
    this._reconnectAttempts = 0
    this._maxAttempts = maxAttempts
    this._stopped = false
    this._degraded = false

    // ── E2E peer key registry (TOFU) ─────────────────────────────────────────
    // Maps peerId → imported CryptoKey (ECDSA P-256 public key).
    // Populated on receiving 'join' frames that carry depositPubKey.
    // Also populated on first offer/answer receipt when the frame carries pubKey.
    // First key seen wins; subsequent different keys for the same peer are ignored.
    /** @type {Map<string, CryptoKey>} */
    this._peerKeys = new Map()

    // ── Replay protection: bounded seen-(from,nonce) cache ───────────────────
    // Stores composite keys "<from>:<nonce>" for every successfully-verified
    // signed frame.  FIFO eviction when the Map exceeds NONCE_CACHE_MAX entries
    // (Map preserves insertion order; keys().next().value is the oldest entry).
    // Only populated after a successful signature check — unsigned frames on the
    // requirePeerAuth=false path are not cached, avoiding cache poisoning.
    /** @type {Map<string, true>} */
    this._seenNonces = new Map()
  }

  /** Connect (or reconnect) to the signaling WebSocket. */
  connect() {
    if (this._stopped) return

    // Default: carry the JWT as a WebSocket subprotocol so it never lands in the
    // URL (and thus access logs / Referer / history). 'query' is a legacy shim.
    let ws
    if (this._authToken && this._tokenTransport === 'subprotocol') {
      ws = new WebSocket(this._url, [TOKEN_SUBPROTOCOL_PREFIX + this._authToken])
    } else if (this._authToken && this._tokenTransport === 'query') {
      ws = new WebSocket(`${this._url}?token=${encodeURIComponent(this._authToken)}`)
    } else {
      ws = new WebSocket(this._url)
    }
    this._ws = ws

    ws.addEventListener('open', () => {
      this._reconnectDelay = RECONNECT_BASE_MS
      this._reconnectAttempts = 0
      this._degraded = false
      this.dispatchEvent(new CustomEvent('signaling-open'))
      // Announce ourselves to the session room. Publish the deposit signing
      // public key (when available) so the server can bind it to our
      // authenticated peerId and verify relay deposit signatures.
      const join = { type: 'join', session: this._session }
      const depositPubKey = this._getDepositPubKey?.()
      if (depositPubKey) join.depositPubKey = depositPubKey
      this._send(join)
    })

    ws.addEventListener('message', async (ev) => {
      let frame
      try { frame = JSON.parse(ev.data) } catch { return }
      if (frame.channel !== SIGNAL_CHANNEL) return
      // Only deliver frames addressed to this session and this peer (or broadcast).
      const p = frame.payload
      if (!p) return
      if (p.session && p.session !== this._session) return
      if (p.to && p.to !== this._peerId) return

      const senderPeerId = frame.from

      // ── TOFU key import on 'join' ───────────────────────────────────────────
      // When a peer announces with a depositPubKey, store it (first key wins).
      // This is the primary identity-binding step: the server's JWT auth ensures
      // `from` is the authenticated peerId; we bind their pubkey to that identity.
      if (p.type === 'join' && p.depositPubKey) {
        if (!this._peerKeys.has(senderPeerId)) {
          try {
            const key = await this._importPeerKey(p.depositPubKey)
            this._peerKeys.set(senderPeerId, key)
          } catch { /* invalid key format — ignore */ }
        }
      }

      // ── Signature verification for offer / answer / ice ─────────────────────
      // These frame types carry signed payloads when the sender uses signFrame.
      // Verification uses the stored pubkey for the server-stamped `from`.
      // If the server stamps the wrong `from`, the canonical message differs
      // from what was signed → mismatch → frame dropped.
      if (p.type === 'offer' || p.type === 'answer' || p.type === 'ice') {
        let verifyKey = this._peerKeys.get(senderPeerId) || null

        // offer/answer frames carry the sender's pubkey so we can verify even
        // before their 'join' was received (handles out-of-order delivery).
        // Key is stored TOFU: only if we don't already have one for this peer.
        if (!verifyKey && p.pubKey) {
          try {
            verifyKey = await this._importPeerKey(p.pubKey)
            this._peerKeys.set(senderPeerId, verifyKey)
          } catch { verifyKey = null }
        }

        if (verifyKey) {
          // We have a key for this peer — enforce signature verification.
          // Unsigned frames (no sig/nonce) from a known peer are rejected:
          // they indicate either a replay of an old pre-auth frame or a server
          // injecting an unsigned frame under a previously-trusted identity.
          if (!p.sig || !p.nonce) {
            // Drop: unsigned frame from a peer whose key we hold.
            return
          }
          const canonical = _canonical({
            type: p.type,
            session: p.session,
            to: p.to,
            from: senderPeerId,
            nonce: p.nonce,
            sdp: p.sdp,
            candidate: p.candidate,
            pubKey: p.pubKey,
          })
          const valid = await this._verifyFrame(verifyKey, canonical, p.sig)
          if (!valid) {
            // Signature mismatch — impersonation attempt or MITM SDP/candidate
            // swap.  Drop silently to avoid leaking verification timing.
            return
          }
          // ── Replay protection ────────────────────────────────────────────────
          // A replayed frame has a valid signature but a nonce we have already
          // processed.  Check after verification so we only track nonces for
          // authenticated peers and never poison the cache on the unsigned path.
          const _nonceKey = `${senderPeerId}:${p.nonce}`
          if (this._seenNonces.has(_nonceKey)) {
            return  // replay — silently drop
          }
          // FIFO eviction: oldest entry is keys().next().value in insertion order
          if (this._seenNonces.size >= NONCE_CACHE_MAX) {
            this._seenNonces.delete(this._seenNonces.keys().next().value)
          }
          this._seenNonces.set(_nonceKey, true)
        } else if (this._requirePeerAuth) {
          // requirePeerAuth=true but no key available for this peer.  Drop to
          // prevent a server from injecting frames for a peer that hasn't
          // completed a keyed join.
          return
        }
        // else: no key, requirePeerAuth=false → allow through for backward
        // compatibility (fabricSignaling.js / BroadcastChannel paths).
      }

      this.dispatchEvent(new CustomEvent('signal', { detail: { from: senderPeerId, payload: p } }))
    })

    ws.addEventListener('close', () => {
      if (this._stopped) return
      this.dispatchEvent(new CustomEvent('signaling-close'))
      this._scheduleReconnect()
    })

    ws.addEventListener('error', () => {
      // 'close' will follow; handled there.
    })
  }

  /**
   * Send a signal payload to a specific peer (or broadcast to session).
   *
   * When `signFrame` is configured, the payload is signed with a per-frame
   * nonce using ECDSA P-256.  The nonce is included in both the canonical
   * signing message and the sent payload so recipients can verify.
   *
   * @returns {Promise<void>}
   */
  async signal(type, toId, data = {}) {
    const payload = { type, session: this._session, to: toId, ...data }

    if (this._signFrame) {
      const nonce = crypto.randomUUID()
      payload.nonce = nonce
      // Build canonical message — field order is fixed (see _canonical).
      // Including `from` binds the sender's identity: a server that stamps the
      // wrong `from` causes the receiver's canonical reconstruction to differ.
      // Including `sdp` (for offer/answer) pins the DTLS fingerprint.
      const canonical = _canonical({
        type,
        session: this._session,
        to: toId,
        from: this._peerId,
        nonce,
        sdp: data.sdp,
        candidate: data.candidate,
        pubKey: data.pubKey,
      })
      payload.sig = await this._signFrame(canonical)
    }

    this._send(payload)
  }

  /** Cleanly stop reconnecting and close the socket. */
  close() {
    this._stopped = true
    if (this._ws) {
      this._send({ type: 'leave', session: this._session })
      this._ws.close()
      this._ws = null
    }
  }

  // ─── public peer-key helpers (used by FabricClient for relay-blob auth) ────

  /**
   * Return true when a public key has been stored for `fromPeerId` (via a
   * 'join' frame or TOFU import on an offer/answer).
   *
   * Used by FabricClient to decide whether to enforce a relay-blob signature.
   *
   * @param {string} fromPeerId
   * @returns {boolean}
   */
  hasPeerKey(fromPeerId) {
    return this._peerKeys.has(fromPeerId)
  }

  /**
   * Verify a relay-deposit blob signature using the stored public key for
   * `fromPeerId` (populated via signaling join / TOFU).
   *
   * @param {string} fromPeerId
   * @param {string} message   — the exact canonical string that was signed
   * @param {string} sigB64    — base64 ECDSA P-256 DER signature
   * @returns {Promise<boolean|null>}
   *   true  — valid signature
   *   false — invalid signature (impersonation / tamper → drop blob)
   *   null  — no key stored for this peer (caller applies its own policy)
   */
  async verifyPeerSig(fromPeerId, message, sigB64) {
    const key = this._peerKeys.get(fromPeerId)
    if (!key) return null
    return this._verifyFrame(key, message, sigB64)
  }

  // ─── private ───────────────────────────────────────────────────────────────

  _send(payload) {
    if (!this._ws || this._ws.readyState !== WebSocket.OPEN) return
    const frame = JSON.stringify({
      channel: SIGNAL_CHANNEL,
      payload,
    })
    this._ws.send(frame)
  }

  _scheduleReconnect() {
    this._reconnectAttempts++

    // Once the budget is exhausted, emit a terminal 'offline' event so
    // consumers can show a degraded-mode banner rather than waiting forever.
    if (this._reconnectAttempts >= this._maxAttempts) {
      if (!this._degraded) {
        this._degraded = true
        this.dispatchEvent(new CustomEvent('offline', {
          detail: { attempts: this._reconnectAttempts },
        }))
      }
      // Continue trying — but at the max delay — so the connection recovers
      // automatically when the network comes back, while consumers know we are
      // in degraded mode.
    }

    const delay = this._reconnectDelay
    this._reconnectDelay = Math.min(this._reconnectDelay * 2, RECONNECT_MAX_MS)
    setTimeout(() => this.connect(), delay)
  }

  // ── E2E crypto helpers ─────────────────────────────────────────────────────

  /**
   * Import a base64-encoded raw ECDSA P-256 public key as a CryptoKey for
   * verification only.
   *
   * @param {string} b64PubKey  — base64 raw public key (65 bytes uncompressed)
   * @returns {Promise<CryptoKey>}
   */
  async _importPeerKey(b64PubKey) {
    const raw = Uint8Array.from(atob(b64PubKey), c => c.charCodeAt(0))
    return crypto.subtle.importKey(
      'raw',
      raw,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    )
  }

  /**
   * Verify a base64-encoded ECDSA P-256 signature over `canonical` using
   * `pubKey`.  Returns false on any error (malformed sig, wrong key, etc.)
   * so callers can treat it as a boolean rejection.
   *
   * @param {CryptoKey} pubKey
   * @param {string}    canonical  — deterministic JSON string that was signed
   * @param {string}    sigB64     — base64 ECDSA signature
   * @returns {Promise<boolean>}
   */
  async _verifyFrame(pubKey, canonical, sigB64) {
    try {
      const sigBuf = Uint8Array.from(atob(sigB64), c => c.charCodeAt(0))
      const msgBuf = new TextEncoder().encode(canonical)
      return await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        pubKey,
        sigBuf,
        msgBuf,
      )
    } catch {
      return false
    }
  }
}
