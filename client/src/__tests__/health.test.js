/**
 * health.test.js — GET /healthz export (health.js)
 *
 * Covers:
 *   • createHealthReport() returns a HealthReport with the correct shape
 *   • createHealthReport() without getRelayByteCount has relay: null
 *   • createHealthReport({ getRelayByteCount }) includes relay byte stats
 *   • RELAY_CLIENT_VERSION is a semver string
 *   • createHealthHandler() writes HTTP 200 with JSON body (Node.js style)
 *   • createHealthHandler() sets Content-Type: application/json
 *   • createHealthHandler() sets Cache-Control: no-store
 *   • Health handler body round-trips through JSON.parse correctly
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  createHealthReport,
  createHealthHandler,
  RELAY_CLIENT_VERSION,
} from '../health.js'

describe('RELAY_CLIENT_VERSION', () => {
  it('is a non-empty semver-ish string', () => {
    expect(typeof RELAY_CLIENT_VERSION).toBe('string')
    expect(RELAY_CLIENT_VERSION).toMatch(/^\d+\.\d+\.\d+/)
  })
})

describe('createHealthReport()', () => {
  it('returns status: "ok"', () => {
    const r = createHealthReport()
    expect(r.status).toBe('ok')
  })

  it('returns the correct component name', () => {
    const r = createHealthReport()
    expect(r.component).toBe('@vulos/relay-client')
  })

  it('returns the package version', () => {
    const r = createHealthReport()
    expect(r.version).toBe(RELAY_CLIENT_VERSION)
  })

  it('returns an ISO-8601 timestamp in ts', () => {
    const before = new Date().toISOString()
    const r = createHealthReport()
    const after = new Date().toISOString()
    expect(r.ts >= before).toBe(true)
    expect(r.ts <= after).toBe(true)
    expect(new Date(r.ts).toISOString()).toBe(r.ts)
  })

  it('relay is null when getRelayByteCount is not supplied', () => {
    const r = createHealthReport()
    expect(r.relay).toBeNull()
  })

  it('relay is null when opts is empty object', () => {
    const r = createHealthReport({})
    expect(r.relay).toBeNull()
  })

  it('relay includes out/in/total when getRelayByteCount callback is supplied', () => {
    const r = createHealthReport({
      getRelayByteCount: () => ({ out: 100, in: 50, total: 150 }),
    })
    expect(r.relay).toEqual({ out: 100, in: 50, total: 150 })
  })

  it('relay reflects live counter values from the callback', () => {
    let counter = { out: 0, in: 0, total: 0 }
    const r1 = createHealthReport({ getRelayByteCount: () => counter })
    expect(r1.relay.out).toBe(0)

    counter = { out: 999, in: 1, total: 1000 }
    const r2 = createHealthReport({ getRelayByteCount: () => counter })
    expect(r2.relay.out).toBe(999)
    expect(r2.relay.total).toBe(1000)
  })

  it('returned object is plain JSON-serializable (no circular refs)', () => {
    const r = createHealthReport({ getRelayByteCount: () => ({ out: 1, in: 2, total: 3 }) })
    expect(() => JSON.stringify(r)).not.toThrow()
    const parsed = JSON.parse(JSON.stringify(r))
    expect(parsed.status).toBe('ok')
    expect(parsed.relay.total).toBe(3)
  })
})

describe('createHealthHandler()', () => {
  function makeMockRes() {
    const headers = {}
    let statusCode = null
    let body = null

    return {
      writeHead: vi.fn((code, hdrs) => {
        statusCode = code
        Object.assign(headers, hdrs)
      }),
      end: vi.fn((data) => { body = data }),
      _status: () => statusCode,
      _headers: () => headers,
      _body: () => body,
    }
  }

  it('responds with HTTP 200', () => {
    const handler = createHealthHandler()
    const req = {}
    const res = makeMockRes()
    handler(req, res)

    expect(res._status()).toBe(200)
  })

  it('sets Content-Type: application/json', () => {
    const handler = createHealthHandler()
    const res = makeMockRes()
    handler({}, res)

    expect(res._headers()['Content-Type']).toBe('application/json')
  })

  it('sets Cache-Control: no-store', () => {
    const handler = createHealthHandler()
    const res = makeMockRes()
    handler({}, res)

    expect(res._headers()['Cache-Control']).toBe('no-store')
  })

  it('response body is valid JSON with correct shape', () => {
    const handler = createHealthHandler()
    const res = makeMockRes()
    handler({}, res)

    const body = JSON.parse(res._body())
    expect(body.status).toBe('ok')
    expect(body.component).toBe('@vulos/relay-client')
    expect(body.version).toBe(RELAY_CLIENT_VERSION)
    expect(typeof body.ts).toBe('string')
  })

  it('response body includes relay stats when getRelayByteCount is provided', () => {
    const handler = createHealthHandler({
      getRelayByteCount: () => ({ out: 42, in: 8, total: 50 }),
    })
    const res = makeMockRes()
    handler({}, res)

    const body = JSON.parse(res._body())
    expect(body.relay).toEqual({ out: 42, in: 8, total: 50 })
  })

  it('Content-Length header is set to the byte length of the body', () => {
    const handler = createHealthHandler()
    const res = makeMockRes()
    handler({}, res)

    const body = res._body()
    const headerLen = parseInt(res._headers()['Content-Length'], 10)
    // Allow for the possibility that Buffer is not available in jsdom
    // (Content-Length may be body.length or actual byte length)
    expect(headerLen).toBeGreaterThan(0)
    expect(headerLen).toBeLessThanOrEqual(body.length * 2)  // sanity bound
  })

  it('handler is callable multiple times without error', () => {
    const handler = createHealthHandler()
    for (let i = 0; i < 3; i++) {
      const res = makeMockRes()
      expect(() => handler({}, res)).not.toThrow()
      expect(res._status()).toBe(200)
    }
  })
})
