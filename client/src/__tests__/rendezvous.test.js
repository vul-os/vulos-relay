import { describe, it, expect, vi, afterEach } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import {
  RendezvousClient,
  RendezvousIdentity,
  canonicalMessage,
  b64urlEncode,
  b64urlDecode,
  RENDEZVOUS_DOMAINS,
} from '../rendezvous.js'
import { FabricClient } from '../fabric.js'

// The SAME canonical vector asserted by the Go node (tunnel/rendezvous/
// canonical_test.go). This locks the JS↔Go signing-message encoding.
const CANONICAL_VECTOR_HEX =
  '0000001476756c6f732d7264762f616e6e6f756e63652f31' +
  '00000004414141410000000a313730303030303030300000000333303000000008' +
  '6e6f6e6365313233000000066d6574612d78000000077773733a2f2f6100000009' +
  '68747470733a2f2f62'

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

afterEach(() => vi.restoreAllMocks())

describe('canonical message (cross-language interop)', () => {
  it('matches the Go node vector byte-for-byte', () => {
    const msg = canonicalMessage('vulos-rdv/announce/1', [
      'AAAA', '1700000000', '300', 'nonce123', 'meta-x', 'wss://a', 'https://b',
    ])
    expect(toHex(msg)).toBe(CANONICAL_VECTOR_HEX)
  })
})

describe('base64url', () => {
  it('round-trips arbitrary bytes unpadded', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255])
    const enc = b64urlEncode(bytes)
    expect(enc).not.toMatch(/[+/=]/)
    expect(Array.from(b64urlDecode(enc))).toEqual(Array.from(bytes))
  })
})

describe('RendezvousIdentity', () => {
  it('produces a 32-byte-key base64url address and a verifiable signature', () => {
    const id = RendezvousIdentity.generate()
    expect(b64urlDecode(id.key).length).toBe(32)
    const msg = canonicalMessage('vulos-rdv/announce/1', ['x', '1', '0', 'n', ''])
    const sigB64 = id.sign(msg)
    expect(ed25519.verify(b64urlDecode(sigB64), msg, id.publicKey)).toBe(true)
  })

  it('can be reconstructed from a fixed secret key (deterministic key)', () => {
    const seed = new Uint8Array(32).fill(7)
    const a = new RendezvousIdentity(seed)
    const b = new RendezvousIdentity(seed)
    expect(a.key).toBe(b.key)
  })
})

function mockFetchCapture(responder) {
  const calls = []
  const fetchImpl = vi.fn(async (url, opts) => {
    const body = opts && opts.body ? JSON.parse(opts.body) : null
    calls.push({ url, method: opts?.method || 'GET', body, headers: opts?.headers })
    return responder({ url, opts, body }) || jsonResponse(200, { ok: true })
  })
  return { fetchImpl, calls }
}

function jsonResponse(status, obj) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: '',
    json: async () => obj,
  }
}

describe('RendezvousClient.announce', () => {
  it('sends a correctly-signed announce the relay can verify', async () => {
    const id = RendezvousIdentity.generate()
    const { fetchImpl, calls } = mockFetchCapture(() =>
      jsonResponse(200, { ok: true, key: id.key, ttl: 300, expires_at: 1 }),
    )
    const rdv = new RendezvousClient({ baseUrl: 'https://relay.test', identity: id, fetch: fetchImpl })
    await rdv.announce({ endpoints: ['wss://box/tunnel'], meta: 'caps=x', ttl: 300 })

    expect(calls).toHaveLength(1)
    const c = calls[0]
    expect(c.url).toBe('https://relay.test/rendezvous/announce')
    expect(c.method).toBe('POST')
    expect(c.body.key).toBe(id.key)

    // The captured request signature verifies over the reconstructed canonical.
    const fields = [c.body.key, String(c.body.ts), String(c.body.ttl), c.body.nonce, c.body.meta, ...c.body.endpoints]
    const msg = canonicalMessage(RENDEZVOUS_DOMAINS.announce, fields)
    expect(ed25519.verify(b64urlDecode(c.body.sig), msg, id.publicKey)).toBe(true)
  })
})

describe('RendezvousClient.resolve', () => {
  it('GETs the key and returns presence', async () => {
    const id = RendezvousIdentity.generate()
    const peer = RendezvousIdentity.generate().key
    const { fetchImpl, calls } = mockFetchCapture(({ url }) => {
      if (url.includes('/resolve/')) {
        return jsonResponse(200, { key: peer, online: true, endpoints: ['wss://p'], expires_at: 9 })
      }
    })
    const rdv = new RendezvousClient({ baseUrl: 'https://relay.test', identity: id, fetch: fetchImpl })
    const res = await rdv.resolve(peer)
    expect(res.online).toBe(true)
    expect(res.endpoints).toEqual(['wss://p'])
    expect(calls[0].url).toContain('/rendezvous/resolve/')
  })

  it('returns online:false on 404', async () => {
    const id = RendezvousIdentity.generate()
    const { fetchImpl } = mockFetchCapture(() => jsonResponse(404, { key: 'k', online: false }))
    const rdv = new RendezvousClient({ baseUrl: 'https://relay.test', identity: id, fetch: fetchImpl })
    const res = await rdv.resolve('k')
    expect(res.online).toBe(false)
  })
})

describe('RendezvousClient signal deposit/poll/ack', () => {
  it('deposits an opaque signed blob to a recipient', async () => {
    const id = RendezvousIdentity.generate()
    const peer = RendezvousIdentity.generate().key
    const { fetchImpl, calls } = mockFetchCapture(() => jsonResponse(201, { ok: true, id: 'blob1', expires_at: 5 }))
    const rdv = new RendezvousClient({ baseUrl: 'https://relay.test', identity: id, fetch: fetchImpl })

    const payload = new Uint8Array([9, 8, 7])
    const res = await rdv.signalDeposit(peer, payload)
    expect(res.id).toBe('blob1')
    const c = calls[0]
    expect(c.url).toBe('https://relay.test/rendezvous/signal/' + encodeURIComponent(peer))
    expect(c.body.from).toBe(id.key)
    expect(c.body.to).toBe(peer)
    expect(b64urlDecode(c.body.payload)).toEqual(payload)
    // Signature verifies over the deposit canonical.
    const msg = canonicalMessage(RENDEZVOUS_DOMAINS.signalDeposit, [
      c.body.from, c.body.to, String(c.body.ts), String(c.body.ttl), c.body.nonce, c.body.payload,
    ])
    expect(ed25519.verify(b64urlDecode(c.body.sig), msg, id.publicKey)).toBe(true)
  })

  it('polls own inbox (recipient-signed) and decodes payloads', async () => {
    const id = RendezvousIdentity.generate()
    const blobPayload = b64urlEncode(new Uint8Array([1, 2, 3]))
    const { fetchImpl, calls } = mockFetchCapture(() =>
      jsonResponse(200, { key: id.key, blobs: [{ id: 'b1', from: 'sender', payload: blobPayload, ts: 1, exp: 2 }] }),
    )
    const rdv = new RendezvousClient({ baseUrl: 'https://relay.test', identity: id, fetch: fetchImpl })
    const blobs = await rdv.signalPoll({ wait: 5 })
    expect(blobs).toHaveLength(1)
    expect(Array.from(blobs[0].payload)).toEqual([1, 2, 3])
    const c = calls[0]
    expect(c.url).toBe('https://relay.test/rendezvous/signal/' + encodeURIComponent(id.key) + '/poll')
    expect(c.body.wait).toBe(5)
    const msg = canonicalMessage(RENDEZVOUS_DOMAINS.signalPoll, [c.body.key, String(c.body.ts), c.body.nonce])
    expect(ed25519.verify(b64urlDecode(c.body.sig), msg, id.publicKey)).toBe(true)
  })

  it('acks consumed blob ids', async () => {
    const id = RendezvousIdentity.generate()
    const { fetchImpl, calls } = mockFetchCapture(() => jsonResponse(200, { deleted: 2 }))
    const rdv = new RendezvousClient({ baseUrl: 'https://relay.test', identity: id, fetch: fetchImpl })
    const res = await rdv.signalAck(['a', 'b'])
    expect(res.deleted).toBe(2)
    const c = calls[0]
    expect(c.body.ids).toEqual(['a', 'b'])
    const msg = canonicalMessage(RENDEZVOUS_DOMAINS.signalAck, [c.body.key, String(c.body.ts), c.body.nonce, 'a', 'b'])
    expect(ed25519.verify(b64urlDecode(c.body.sig), msg, id.publicKey)).toBe(true)
  })
})

describe('RendezvousClient.ice', () => {
  it('fetches ice_servers with the key hint', async () => {
    const id = RendezvousIdentity.generate()
    const { fetchImpl, calls } = mockFetchCapture(() => jsonResponse(200, { ice_servers: [{ urls: ['stun:x'] }] }))
    const rdv = new RendezvousClient({ baseUrl: 'https://relay.test', identity: id, fetch: fetchImpl })
    const servers = await rdv.ice()
    expect(servers).toEqual([{ urls: ['stun:x'] }])
    expect(calls[0].url).toContain('/rendezvous/ice?key=')
  })
})

describe('security', () => {
  it('refuses an auth token on an insecure (plaintext non-loopback) base URL', () => {
    const id = RendezvousIdentity.generate()
    expect(() => new RendezvousClient({ baseUrl: 'http://relay.test', identity: id, authToken: 'jwt' }))
      .toThrow(/INSECURE_TOKEN_TRANSPORT|insecure/)
  })

  it('surfaces a non-2xx error with the relay reason', async () => {
    const id = RendezvousIdentity.generate()
    const { fetchImpl } = mockFetchCapture(() => jsonResponse(401, { error: 'signature verification failed' }))
    const rdv = new RendezvousClient({ baseUrl: 'https://relay.test', identity: id, fetch: fetchImpl })
    await expect(rdv.announce({})).rejects.toThrow(/signature verification failed/)
  })
})

describe('FabricClient rendezvous integration', () => {
  it('exposes a RendezvousClient and derives iceUrl from the relay when rendezvousBaseUrl is set', () => {
    const fc = new FabricClient({
      sessionId: 's', peerId: 'p',
      signalingUrl: 'wss://host/api/peering/stream',
      rendezvousBaseUrl: 'https://relay.test',
    })
    expect(fc.rendezvous).toBeInstanceOf(RendezvousClient)
    expect(fc.rendezvous.baseUrl).toBe('https://relay.test')
    // ICE was derived from the relay (not the /api/peering default).
    expect(fc._iceUrl).toBe('https://relay.test/rendezvous/ice')
  })

  it('leaves the existing /api/peering path unchanged when rendezvousBaseUrl is absent', () => {
    const fc = new FabricClient({
      sessionId: 's', peerId: 'p',
      signalingUrl: 'wss://host/api/peering/stream',
    })
    expect(fc.rendezvous).toBe(null)
    expect(fc._iceUrl).toBe('/api/peering/ice')
  })

  it('honors an explicit iceUrl override even with rendezvousBaseUrl', () => {
    const fc = new FabricClient({
      sessionId: 's', peerId: 'p',
      signalingUrl: 'wss://host/api/peering/stream',
      rendezvousBaseUrl: 'https://relay.test',
      iceUrl: 'https://custom/ice',
    })
    expect(fc._iceUrl).toBe('https://custom/ice')
  })
})
