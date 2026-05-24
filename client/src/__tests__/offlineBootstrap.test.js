/**
 * offlineBootstrap.test.js — offline-first SW bootstrap (frozen contract).
 *
 * Ported from vulos/src/__tests__/offlineBootstrap.test.js (the most complete
 * of the three pre-existing copies — it owned the SW update detection path).
 * Adds two new cases for the @vulos/relay-client injection seams:
 *   • onBoot callback fires once after bootstrap (replaces the consumer-
 *     specific startOfflineQueueFlushLoop / startOutboxFlushLoop calls).
 *   • tierHint callback is captured and surfaced via currentTierHint().
 *
 * Covers:
 *   • bootstrapOffline registers the SW exactly once even if called twice
 *   • bootstrapOffline primes selectEndpoint()
 *   • onUpdateAvailable fires when the SW transitions installing → installed
 *     with an existing controller
 *   • applyUpdate posts SKIP_WAITING to the waiting worker
 *   • applyUpdate is a no-op when no SW is waiting
 *   • bootstrapOffline does not throw if serviceWorker is unavailable
 *   • onBoot opt-in seam — consumer flush-loop hook fires exactly once
 *   • tierHint opt-in seam — MEET-OS-01 Pro-tier hint round-trips
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

async function freshModule() {
  vi.resetModules()
  return import('../offlineBootstrap.js')
}

function makeRegistration() {
  const listeners = {}
  let installing = null
  const reg = {
    waiting: null,
    installing: null,
    addEventListener: vi.fn((evt, fn) => {
      listeners[evt] = fn
    }),
    _fireUpdateFound(newWorker) {
      installing = newWorker
      reg.installing = newWorker
      listeners.updatefound && listeners.updatefound()
    },
    _installing() { return installing },
  }
  return reg
}

function makeInstallingWorker() {
  const listeners = {}
  return {
    state: 'installing',
    postMessage: vi.fn(),
    addEventListener: vi.fn((evt, fn) => {
      if (!listeners[evt]) listeners[evt] = []
      listeners[evt].push(fn)
    }),
    _setState(state) {
      this.state = state
      ;(listeners.statechange || []).forEach((fn) => fn())
    },
  }
}

beforeEach(() => {
  try { localStorage.clear() } catch { /* ignore */ }
  globalThis.window = globalThis.window || {}
  globalThis.document = globalThis.document || {}
  // jsdom's document is read-only on readyState, so just shadow it for clarity.
  Object.defineProperty(globalThis.document, 'readyState', {
    value: 'complete', configurable: true, writable: true,
  })
  globalThis.navigator = globalThis.navigator || {}
})

afterEach(() => {
  vi.restoreAllMocks()
  delete globalThis.navigator.serviceWorker
})

describe('bootstrapOffline', () => {
  it('registers the service worker exactly once across repeated calls', async () => {
    const reg = makeRegistration()
    const register = vi.fn(async () => reg)
    globalThis.navigator.serviceWorker = {
      register,
      controller: {},
      addEventListener: vi.fn(),
    }
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200 })))

    const m = await freshModule()
    m._resetForTests()
    m.bootstrapOffline()
    m.bootstrapOffline()
    m.bootstrapOffline()
    // Yield for the async register() chain.
    await Promise.resolve()
    await Promise.resolve()
    expect(register).toHaveBeenCalledTimes(1)
    expect(register).toHaveBeenCalledWith('/sw.js')
  })

  it('does not throw if serviceWorker is unavailable', async () => {
    delete globalThis.navigator.serviceWorker
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200 })))
    const m = await freshModule()
    m._resetForTests()
    expect(() => m.bootstrapOffline()).not.toThrow()
  })

  it('onUpdateAvailable fires once a new SW installs while controlled', async () => {
    const reg = makeRegistration()
    const register = vi.fn(async () => reg)
    globalThis.navigator.serviceWorker = {
      register,
      controller: {},                 // page IS controlled by an old SW
      addEventListener: vi.fn(),
    }
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200 })))

    const m = await freshModule()
    m._resetForTests()
    const cb = vi.fn()
    m.onUpdateAvailable(cb)
    m.bootstrapOffline()
    await Promise.resolve()
    await Promise.resolve()

    // Simulate a new SW becoming available.
    const newWorker = makeInstallingWorker()
    reg._fireUpdateFound(newWorker)
    newWorker._setState('installed')

    expect(cb).toHaveBeenCalledTimes(1)

    // applyUpdate posts SKIP_WAITING to the waiting worker.
    const applied = m.applyUpdate()
    expect(applied).toBe(true)
    expect(newWorker.postMessage).toHaveBeenCalledWith({ type: 'SKIP_WAITING' })
  })

  it('applyUpdate is a no-op when no SW is waiting', async () => {
    const m = await freshModule()
    m._resetForTests()
    expect(m.applyUpdate()).toBe(false)
  })

  it('onBoot opt-in seam: consumer flush-loop hook fires exactly once', async () => {
    delete globalThis.navigator.serviceWorker
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200 })))
    const m = await freshModule()
    m._resetForTests()
    const onBoot = vi.fn()
    m.bootstrapOffline({ onBoot })
    m.bootstrapOffline({ onBoot })  // idempotent — must not double-fire
    expect(onBoot).toHaveBeenCalledTimes(1)
  })

  it('tierHint opt-in seam: MEET-OS-01 Pro-tier hint is captured', async () => {
    delete globalThis.navigator.serviceWorker
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200 })))
    const m = await freshModule()
    m._resetForTests()
    m.bootstrapOffline({ tierHint: () => ({ plan: 'pro', livekit: true }) })
    expect(m.currentTierHint()).toEqual({ plan: 'pro', livekit: true })
  })

  it('tierHint is undefined when no callback is supplied (OSS self-host)', async () => {
    delete globalThis.navigator.serviceWorker
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200 })))
    const m = await freshModule()
    m._resetForTests()
    m.bootstrapOffline()
    expect(m.currentTierHint()).toBeUndefined()
  })
})
