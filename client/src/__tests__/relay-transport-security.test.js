/**
 * relay-transport-security.test.js — credential-transport (TLS/wss) enforcement.
 *
 * THREAT: the relay client holds a short-lived Bearer JWT (the box/app session
 * token). It attaches that token to
 *   • the signaling WebSocket   (Sec-WebSocket-Protocol header / ?token= shim)
 *   • the ICE + relay HTTP calls (Authorization: Bearer …)
 * If the target URL is plaintext (`ws://` / `http://`) to a NON-loopback host,
 * the credential travels in the clear — readable by any on-path attacker and
 * captured in proxy / access logs.
 *
 * FIX under test (secureTransport.js, wired into SignalingClient + FabricClient
 * constructors): a client that WOULD leak its token over an insecure transport
 * fails CLOSED at construction — it never opens a socket or sends a request.
 * wss:// / https:// are required; ws:// / http:// are permitted only to a
 * loopback host for local dev. A client with NO token may use plaintext freely
 * (the signaling frames are ECDSA-signed, so there is no credential to protect).
 *
 * Also asserts the token VALUE is never emitted to the console on any path.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { SignalingClient } from '../signaling.js'
import { FabricClient } from '../fabric.js'
import { SignalingError, RelayDepositError } from '../errors.js'
import { tokenTransportSecure, isLoopbackHost } from '../secureTransport.js'

// ── Fake WebSocket so a *permitted* client can actually connect ────────────────
class FakeWebSocket {
  static OPEN = 1
  static CONNECTING = 0
  static CLOSED = 3
  constructor(url, protocols) {
    this.url = url
    this.protocols = protocols || []
    this.readyState = FakeWebSocket.CONNECTING
    this.sent = []
    this._listeners = {}
    FakeWebSocket.last = this
  }
  addEventListener(evt, fn) { (this._listeners[evt] ||= []).push(fn) }
  send(data) { this.sent.push(data) }
  close() { this.readyState = FakeWebSocket.CLOSED }
}

const TOKEN = 'super-secret-jwt.header.payload'

beforeEach(() => {
  FakeWebSocket.last = null
  vi.stubGlobal('WebSocket', FakeWebSocket)
})
afterEach(() => { vi.restoreAllMocks() })

// ─── the pure guard ────────────────────────────────────────────────────────────

describe('tokenTransportSecure()', () => {
  it('allows same-origin ("") and relative paths', () => {
    expect(tokenTransportSecure('')).toBe(true)
    expect(tokenTransportSecure('/api/peering/ice')).toBe(true)
    expect(tokenTransportSecure(null)).toBe(true)
  })
  it('allows wss:// and https:// to any host', () => {
    expect(tokenTransportSecure('wss://relay.vulos.app/api/peering/stream')).toBe(true)
    expect(tokenTransportSecure('https://box.vulos.org/api/peering/ice')).toBe(true)
  })
  it('rejects ws:// / http:// to a non-loopback host', () => {
    expect(tokenTransportSecure('ws://evil.example/stream')).toBe(false)
    expect(tokenTransportSecure('ws://x/y')).toBe(false)
    expect(tokenTransportSecure('http://relay.vulos.app/api')).toBe(false)
  })
  it('permits ws:// / http:// to a loopback host (local dev)', () => {
    expect(tokenTransportSecure('ws://localhost:8080/stream')).toBe(true)
    expect(tokenTransportSecure('ws://127.0.0.1/stream')).toBe(true)
    expect(tokenTransportSecure('http://127.0.0.5:3000/api')).toBe(true)
    expect(tokenTransportSecure('ws://[::1]/stream')).toBe(true)
    expect(tokenTransportSecure('http://dev.localhost/api')).toBe(true)
  })
  it('rejects non-network schemes outright', () => {
    expect(tokenTransportSecure('javascript:alert(1)')).toBe(false)
    expect(tokenTransportSecure('file:///etc/passwd')).toBe(false)
    expect(tokenTransportSecure('data:text/plain,x')).toBe(false)
  })
  it('isLoopbackHost recognises the loopback range and rejects public hosts', () => {
    expect(isLoopbackHost('localhost')).toBe(true)
    expect(isLoopbackHost('127.0.0.1')).toBe(true)
    expect(isLoopbackHost('127.255.255.254')).toBe(true)
    expect(isLoopbackHost('[::1]')).toBe(true)
    expect(isLoopbackHost('evil.example')).toBe(false)
    expect(isLoopbackHost('127.example.com')).toBe(false)   // not a 127.x IP
    expect(isLoopbackHost('notlocalhost.com')).toBe(false)
  })
})

// ─── SignalingClient constructor guard ─────────────────────────────────────────

describe('SignalingClient — refuses to leak the token over plaintext', () => {
  it('throws INSECURE_TOKEN_TRANSPORT for a token over ws:// to a remote host', () => {
    let thrown
    try {
      new SignalingClient({ signalingUrl: 'ws://evil.example/stream', sessionId: 's', peerId: 'a', authToken: TOKEN })
    } catch (e) { thrown = e }
    expect(thrown).toBeInstanceOf(SignalingError)
    expect(thrown.code).toBe('INSECURE_TOKEN_TRANSPORT')
    // The thrown message must NOT contain the token value.
    expect(thrown.message).not.toContain(TOKEN)
  })

  it('also throws on the legacy query transport over plaintext remote', () => {
    expect(() => new SignalingClient({
      signalingUrl: 'ws://evil.example/stream', sessionId: 's', peerId: 'a',
      authToken: TOKEN, tokenTransport: 'query',
    })).toThrow(/insecure signaling transport/i)
  })

  it('constructs + connects a token client over wss://', () => {
    const c = new SignalingClient({ signalingUrl: 'wss://relay.vulos.app/stream', sessionId: 's', peerId: 'a', authToken: TOKEN })
    c.connect()
    expect(FakeWebSocket.last).toBeTruthy()
    expect(FakeWebSocket.last.protocols).toContain('vula.token.' + TOKEN)
    expect(FakeWebSocket.last.url).not.toContain(TOKEN)   // never in the URL
    c.close()
  })

  it('permits a token over ws:// to a loopback host (local dev)', () => {
    const c = new SignalingClient({ signalingUrl: 'ws://localhost:8080/stream', sessionId: 's', peerId: 'a', authToken: TOKEN })
    c.connect()
    expect(FakeWebSocket.last.protocols).toContain('vula.token.' + TOKEN)
    c.close()
  })

  it('allows an UNAUTHENTICATED client over ws:// to a remote host (no credential to protect)', () => {
    // Frames are ECDSA-signed; a tokenless plaintext socket leaks nothing.
    const c = new SignalingClient({ signalingUrl: 'ws://relay.vulos.app/stream', sessionId: 's', peerId: 'a' })
    expect(() => c.connect()).not.toThrow()
    c.close()
  })
})

// ─── FabricClient constructor guard (ICE + relay base) ─────────────────────────

describe('FabricClient — refuses to leak the token over plaintext', () => {
  it('throws for a token with an insecure relay base URL', () => {
    let thrown
    try {
      new FabricClient({
        sessionId: 's', peerId: 'a', signalingUrl: 'wss://relay.vulos.app/stream',
        relayBaseUrl: 'http://evil.example', authToken: TOKEN,
      })
    } catch (e) { thrown = e }
    expect(thrown).toBeInstanceOf(RelayDepositError)
    expect(thrown.code).toBe('INSECURE_TOKEN_TRANSPORT')
    expect(thrown.message).not.toContain(TOKEN)
  })

  it('throws for a token with an insecure ICE URL', () => {
    expect(() => new FabricClient({
      sessionId: 's', peerId: 'a', signalingUrl: 'wss://relay.vulos.app/stream',
      iceUrl: 'http://evil.example/ice', authToken: TOKEN,
    })).toThrow(/insecure ICE URL/i)
  })

  it('propagates the signaling guard (insecure signaling URL) through the fabric ctor', () => {
    expect(() => new FabricClient({
      sessionId: 's', peerId: 'a', signalingUrl: 'ws://evil.example/stream', authToken: TOKEN,
    })).toThrow(SignalingError)
  })

  it('constructs with a token over all-secure URLs (wss + https + relative ICE)', () => {
    expect(() => new FabricClient({
      sessionId: 's', peerId: 'a',
      signalingUrl: 'wss://relay.vulos.app/stream',
      relayBaseUrl: 'https://box.vulos.org',
      iceUrl: '/api/peering/ice',
      authToken: TOKEN,
    })).not.toThrow()
  })

  it('constructs a tokenless client even with an insecure relay base (nothing to leak)', () => {
    expect(() => new FabricClient({
      sessionId: 's', peerId: 'a', signalingUrl: 'ws://localhost/stream',
      relayBaseUrl: 'http://evil.example',
    })).not.toThrow()
  })
})

// ─── no-secret-logging regression ──────────────────────────────────────────────

describe('token value is never written to the console', () => {
  it('no console sink receives the token across construct/connect/close', () => {
    const sinks = ['log', 'info', 'warn', 'error', 'debug'].map(
      (m) => vi.spyOn(console, m).mockImplementation(() => {}),
    )
    const c = new SignalingClient({ signalingUrl: 'wss://relay.vulos.app/stream', sessionId: 's', peerId: 'a', authToken: TOKEN })
    c.connect()
    c.close()
    // And the rejected path must not log it either.
    try { new SignalingClient({ signalingUrl: 'ws://evil.example/s', sessionId: 's', peerId: 'a', authToken: TOKEN }) } catch { /* expected */ }
    for (const s of sinks) {
      for (const call of s.mock.calls) {
        for (const arg of call) {
          expect(String(arg)).not.toContain(TOKEN)
        }
      }
    }
  })
})
