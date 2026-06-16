/**
 * endpoints.test.js — cloud↔LAN failover (frozen contract).
 *
 * Union of the pre-existing test suites:
 *   • vulos-office/src/__tests__/endpoints.test.js (6 cases)
 *   • vulos/src/__tests__/endpoints.test.js        (13 cases)
 *
 * Deduped — every distinct behaviour from both is covered exactly once.
 * Adds three new cases for the @vulos/relay-client migration seams:
 *   • configure() lsKeyPrefix overrides the localStorage namespace
 *   • configure() healthPath overrides the probe URL
 *   • default lsKeyPrefix is 'vulos.relay-client.endpoints.v1'
 *
 * Covers the frozen contract:
 *   • both endpoints cached
 *   • reachable chosen automatically
 *   • cloud-down → LAN
 *   • LAN-down → cloud
 *   • prefer LAN-direct when both are reachable (latency)
 *   • 401/403 counts as reachable (box is up)
 *   • invalidation re-probes on next selectEndpoint call
 *   • re-selects on the window 'online' event
 *   • cached pair survives a "reload" (fresh module, no injection/env)
 *   • seedFromResolveBackend() persists a fresh BackendTarget
 *   • no-LAN response (cloud-only target) still works
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

const CLOUD = 'https://box.vulos.org'
const LAN = 'https://box.abc.lan.vulos.org'
const DEFAULT_LS_KEY = 'vulos.relay-client.endpoints.v1'

// Each test gets a fresh module instance so internal selection state is reset.
async function freshModule() {
  vi.resetModules()
  return import('../endpoints.js')
}

function setEndpoints({ cloud = CLOUD, lan = LAN } = {}) {
  globalThis.window = globalThis.window || {}
  window.__VULOS_ENDPOINTS__ = { cloud, lan }
}

beforeEach(() => {
  // jsdom provides localStorage; clear it so cached pairs don't leak across tests.
  try { localStorage.clear() } catch { /* ignore */ }
  globalThis.window = globalThis.window || {}
  if (!window.addEventListener) window.addEventListener = () => {}
  globalThis.navigator = globalThis.navigator || {}
})

afterEach(() => {
  vi.restoreAllMocks()
  delete window.__VULOS_ENDPOINTS__
})

describe('endpoint failover (frozen contract)', () => {
  it('caches BOTH cloud + LAN endpoints under the default lsKeyPrefix', async () => {
    setEndpoints()
    const ep = await freshModule()
    const pair = ep.resolveEndpoints()
    expect(pair.cloud).toBe(CLOUD)
    expect(pair.lan).toBe(LAN)
    // Persisted under the shared default namespace.
    const cached = JSON.parse(localStorage.getItem(DEFAULT_LS_KEY))
    expect(cached.cloud).toBe(CLOUD)
    expect(cached.lan).toBe(LAN)
  })

  it('prefers LAN-direct when both are reachable', async () => {
    setEndpoints()
    const ep = await freshModule()
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200 })))
    const selected = await ep.selectEndpoint({ force: true })
    expect(selected).toBe(LAN)
  })

  it('falls back to cloud when LAN is down', async () => {
    setEndpoints()
    const ep = await freshModule()
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (String(url).startsWith(LAN)) throw new Error('LAN unreachable')
      return { ok: true, status: 200 }
    }))
    const selected = await ep.selectEndpoint({ force: true })
    expect(selected).toBe(CLOUD)
  })

  it('falls back to LAN when cloud is down', async () => {
    setEndpoints()
    const ep = await freshModule()
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (String(url).startsWith(CLOUD)) throw new Error('cloud route down')
      return { ok: true, status: 200 }
    }))
    const selected = await ep.selectEndpoint({ force: true })
    expect(selected).toBe(LAN)
  })

  it('falls back to same-origin when both remote endpoints are down', async () => {
    setEndpoints()
    const ep = await freshModule()
    // navigator.onLine is a read-only getter in jsdom; override it for the probe.
    Object.defineProperty(navigator, 'onLine', { value: false, configurable: true })
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('no network') }))
    const selected = await ep.selectEndpoint({ force: true })
    expect(selected).toBe('')
  })

  it('counts a 401/403 as reachable (the box is up)', async () => {
    setEndpoints({ cloud: '', lan: LAN })
    const ep = await freshModule()
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false, status: 401 })))
    const selected = await ep.selectEndpoint({ force: true })
    expect(selected).toBe(LAN)
  })

  it('invalidateEndpoint forces a re-probe on the next selectEndpoint call', async () => {
    setEndpoints()
    const ep = await freshModule()
    const fetchMock = vi.fn(async () => ({ ok: true, status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    await ep.selectEndpoint({ force: true })
    const firstCalls = fetchMock.mock.calls.length
    expect(firstCalls).toBeGreaterThan(0)

    // Without invalidation: cached, no extra probe within REVALIDATE_AFTER_MS.
    await ep.selectEndpoint()
    expect(fetchMock.mock.calls.length).toBe(firstCalls)

    // After invalidate: next call re-probes.
    ep.invalidateEndpoint()
    await ep.selectEndpoint()
    expect(fetchMock.mock.calls.length).toBeGreaterThan(firstCalls)
  })

  it('re-selects on the window "online" event (debounced)', async () => {
    setEndpoints()
    let onlineHandler = null
    const addEventListener = vi.fn((evt, fn) => {
      if (evt === 'online') onlineHandler = fn
    })
    globalThis.window.addEventListener = addEventListener

    vi.useFakeTimers()
    const ep = await freshModule()
    expect(typeof onlineHandler).toBe('function')

    const fetchMock = vi.fn(async () => ({ ok: true, status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    // Fire the online event — debounced; fetch should NOT run immediately.
    onlineHandler()
    await Promise.resolve()
    await Promise.resolve()
    // fetch not yet called (still in debounce window).
    // Advance past the 400 ms debounce.
    await vi.runAllTimersAsync()
    expect(fetchMock).toHaveBeenCalled()

    vi.useRealTimers()
    const selected = await ep.selectEndpoint()
    expect(selected).toBe(LAN)
  })

  it('cached pair survives a "reload" — no injection or env, only localStorage', async () => {
    // First load: inject + persist a known pair.
    setEndpoints()
    {
      const ep = await freshModule()
      ep.resolveEndpoints()
    }
    // Second load: drop the injected globals — only the localStorage cache
    // should survive, and the pair must still be available to fail over between.
    delete window.__VULOS_ENDPOINTS__
    const ep = await freshModule()
    const pair = ep.resolveEndpoints()
    expect(pair.cloud).toBe(CLOUD)
    expect(pair.lan).toBe(LAN)
  })

  it('seedFromResolveBackend persists a fresh BackendTarget', async () => {
    const ep = await freshModule()
    const target = {
      Endpoint: CLOUD,
      LANCandidate: { BoxID: 'abc', Endpoint: LAN },
    }
    const pair = ep.seedFromResolveBackend(target)
    expect(pair.cloud).toBe(CLOUD)
    expect(pair.lan).toBe(LAN)
    const cached = JSON.parse(localStorage.getItem(DEFAULT_LS_KEY))
    expect(cached.cloud).toBe(CLOUD)
    expect(cached.lan).toBe(LAN)
  })

  it('handles a BackendTarget with no LANCandidate (cloud-only)', async () => {
    const ep = await freshModule()
    const target = { Endpoint: CLOUD, LANCandidate: null }
    const pair = ep.seedFromResolveBackend(target)
    expect(pair.cloud).toBe(CLOUD)
    expect(pair.lan).toBe('')

    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200 })))
    const selected = await ep.selectEndpoint({ force: true })
    // With no LAN candidate cloud is the highest-priority reachable endpoint.
    expect(selected).toBe(CLOUD)
  })
})

describe('configure() — migration seams for the three consumers', () => {
  it('configure({ lsKeyPrefix }) routes cache reads + writes to the legacy namespace', async () => {
    const ep = await freshModule()
    // Seed the legacy OS namespace with a known pair before configuring.
    localStorage.setItem('vulos.os.endpoints.v1', JSON.stringify({ cloud: CLOUD, lan: LAN }))
    ep.configure({ lsKeyPrefix: 'vulos.os.endpoints.v1' })

    // No injection / env → resolveEndpoints should read straight from the
    // legacy cache, proving the migration consumer doesn't lose its pair.
    const pair = ep.resolveEndpoints()
    expect(pair.cloud).toBe(CLOUD)
    expect(pair.lan).toBe(LAN)
    // And nothing should land under the default namespace.
    expect(localStorage.getItem(DEFAULT_LS_KEY)).toBeNull()
  })

  it('configure({ healthPath }) overrides the probe URL', async () => {
    const ep = await freshModule()
    ep.configure({ healthPath: '/api/auth/me' })
    setEndpoints({ cloud: '', lan: LAN })
    const fetchMock = vi.fn(async () => ({ ok: true, status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    await ep.selectEndpoint({ force: true })

    expect(fetchMock).toHaveBeenCalled()
    const calledUrls = fetchMock.mock.calls.map(([u]) => String(u))
    // Every remote probe must hit the configured /api/auth/me path, never the
    // default /api/auth/status.
    for (const u of calledUrls) {
      expect(u.endsWith('/api/auth/me')).toBe(true)
    }
  })

  it('default lsKeyPrefix is "vulos.relay-client.endpoints.v1"', async () => {
    const ep = await freshModule()
    setEndpoints()
    ep.resolveEndpoints()
    // Only the default namespace key is populated.
    expect(localStorage.getItem(DEFAULT_LS_KEY)).not.toBeNull()
    expect(localStorage.getItem('vulos.os.endpoints.v1')).toBeNull()
    expect(localStorage.getItem('vulos.office.endpoints.v1')).toBeNull()
    expect(localStorage.getItem('vulos.custom.endpoints.v1')).toBeNull()
  })
})
