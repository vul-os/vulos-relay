/**
 * fabric.meter.test.js — authoritative relay byte counter (billing G-1)
 *
 * Contract:
 *   FabricClient.relayByteCount   → { out: number, in: number, total: number }
 *   FabricClient.resetRelayByteCount() → resets both counters to 0
 *
 * Byte accounting rules (mirroring docs/RELAY_BYTE_METER.md):
 *   • out  = byte length of the `data` argument at the point of _relayDeposit()
 *   • in   = byte length of the `data` field decoded from each picked-up blob
 *   • Byte length uses TextEncoder.encode().byteLength for strings, byteLength
 *     for ArrayBuffer/ArrayBufferView.
 *   • HTTP framing and base64 expansion are NOT counted.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { FabricClient } from '../fabric.js'

class FakeWebSocket {
  static OPEN = 1
  static CONNECTING = 0
  constructor() {
    this.readyState = FakeWebSocket.CONNECTING
    this._listeners = {}
    this.sent = []
    FakeWebSocket.last = this
  }
  addEventListener(e, f) { if (!this._listeners[e]) this._listeners[e] = []; this._listeners[e].push(f) }
  send(d) { this.sent.push(d) }
  close() {}
  _open() { this.readyState = FakeWebSocket.OPEN; for (const f of (this._listeners['open'] || [])) f({}) }
}

function makeFabric(sessionId = 'sess-meter') {
  return new FabricClient({
    sessionId,
    peerId: 'local-peer',
    signalingUrl: 'ws://localhost/sig',
    iceUrl: '/api/peering/ice',
    relayBaseUrl: '',
    authToken: 'jwt',
  })
}

function relayPeer(fc) {
  fc._peers.set('remote', {
    id: 'remote', state: 'relay', dc: null, pc: null,
    relayTimer: null, pendingCandidates: [], reset() {},
  })
}

beforeEach(() => {
  vi.stubGlobal('WebSocket', FakeWebSocket)
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ ice_servers: [] }) })))
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

afterEach(() => { vi.restoreAllMocks() })

describe('FabricClient — relayByteCount (billing G-1)', () => {
  it('starts at zero for all fields', () => {
    const fc = makeFabric()
    expect(fc.relayByteCount).toEqual({ out: 0, in: 0, total: 0 })
    fc.leave()
  })

  it('relayByteCount.total === out + in', () => {
    const fc = makeFabric()
    fc._relayedBytesOut = 100
    fc._relayedBytesIn = 75
    const { out, in: inBytes, total } = fc.relayByteCount
    expect(out).toBe(100)
    expect(inBytes).toBe(75)
    expect(total).toBe(175)
    fc.leave()
  })

  it('resetRelayByteCount() zeros all fields', () => {
    const fc = makeFabric()
    fc._relayedBytesOut = 500
    fc._relayedBytesIn = 300
    fc.resetRelayByteCount()
    expect(fc.relayByteCount).toEqual({ out: 0, in: 0, total: 0 })
    fc.leave()
  })

  it('_relayDeposit() increments out by string byte size', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ ice_servers: [] }) })))

    const fc = makeFabric()
    await fc._ensureDepositKey()

    const payload = 'hello-world'       // 11 bytes ASCII
    await fc._relayDeposit('remote', payload)

    const expected = new TextEncoder().encode(payload).byteLength
    expect(fc.relayByteCount.out).toBe(expected)
    fc.leave()
  })

  it('_relayDeposit() increments out for UTF-8 multi-byte string', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ ice_servers: [] }) })))

    const fc = makeFabric()
    await fc._ensureDepositKey()

    const payload = '🔥 relay' // fire emoji is 4 bytes
    await fc._relayDeposit('remote', payload)

    const expected = new TextEncoder().encode(payload).byteLength
    expect(fc.relayByteCount.out).toBe(expected)
    fc.leave()
  })

  it('_relayDeposit() increments out for ArrayBuffer', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ ice_servers: [] }) })))

    const fc = makeFabric()
    await fc._ensureDepositKey()

    const buf = new ArrayBuffer(64)
    await fc._relayDeposit('remote', buf)

    expect(fc.relayByteCount.out).toBe(64)
    fc.leave()
  })

  it('multiple deposits accumulate out bytes', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ ice_servers: [] }) })))

    const fc = makeFabric()
    await fc._ensureDepositKey()

    await fc._relayDeposit('remote', 'abc')     // 3 bytes
    await fc._relayDeposit('remote', 'defghi')  // 6 bytes

    expect(fc.relayByteCount.out).toBe(9)
    fc.leave()
  })

  it('relay pickup increments in by decoded data byte size', async () => {
    const data = 'relay-received-data'
    const msg = { session: 'sess-meter', data }
    const blob_b64 = btoa(JSON.stringify(msg))

    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (String(url).includes('pickup')) {
        return {
          ok: true,
          json: async () => ({ blobs: [{ id: 'b1', from: 'remote', blob_b64 }] }),
        }
      }
      if (String(url).includes('ack')) return { ok: true }
      return { ok: true, json: async () => ({ ice_servers: [] }) }
    }))

    const fc = makeFabric()
    relayPeer(fc)

    await fc._relayPoll()

    const expected = new TextEncoder().encode(data).byteLength
    expect(fc.relayByteCount.in).toBe(expected)
    fc.leave()
  })

  it('multiple pickup blobs accumulate in bytes', async () => {
    const d1 = 'aaa'  // 3 bytes
    const d2 = 'bbbbbb'  // 6 bytes
    const mkBlob = (data, id) => ({
      id,
      from: 'remote',
      blob_b64: btoa(JSON.stringify({ session: 'sess-meter', data })),
    })

    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (String(url).includes('pickup')) {
        return {
          ok: true,
          json: async () => ({ blobs: [mkBlob(d1, 'b1'), mkBlob(d2, 'b2')] }),
        }
      }
      if (String(url).includes('ack')) return { ok: true }
      return { ok: true, json: async () => ({ ice_servers: [] }) }
    }))

    const fc = makeFabric()
    relayPeer(fc)

    await fc._relayPoll()

    expect(fc.relayByteCount.in).toBe(9)
    fc.leave()
  })

  it('out and in counters are independent', async () => {
    const data = 'in-data'
    const msg = { session: 'sess-meter', data }
    const blob_b64 = btoa(JSON.stringify(msg))

    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (String(url).includes('deposit')) return { ok: true }
      if (String(url).includes('pickup')) {
        return {
          ok: true,
          json: async () => ({ blobs: [{ id: 'b1', from: 'remote', blob_b64 }] }),
        }
      }
      if (String(url).includes('ack')) return { ok: true }
      return { ok: true, json: async () => ({ ice_servers: [] }) }
    }))

    const fc = makeFabric()
    await fc._ensureDepositKey()
    relayPeer(fc)

    await fc._relayDeposit('remote', 'outbound-payload')
    await fc._relayPoll()

    const { out, in: inBytes } = fc.relayByteCount
    expect(out).toBeGreaterThan(0)
    expect(inBytes).toBeGreaterThan(0)
    expect(out).not.toBe(inBytes)  // independent counters
    fc.leave()
  })

  it('resetRelayByteCount() allows fresh accumulation after reset', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ ice_servers: [] }) })))

    const fc = makeFabric()
    await fc._ensureDepositKey()

    await fc._relayDeposit('remote', 'first-batch')
    expect(fc.relayByteCount.out).toBeGreaterThan(0)

    fc.resetRelayByteCount()
    expect(fc.relayByteCount.out).toBe(0)

    await fc._relayDeposit('remote', 'x')
    expect(fc.relayByteCount.out).toBe(1)
    fc.leave()
  })
})
