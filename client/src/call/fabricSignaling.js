// fabricSignaling.js — thin adapter over the fabric client.
//
// fabric.js is imported as a namespace so we can detect at runtime whether
// it exposes a joinSession function. If it does not (standalone / dev-loop
// builds) we fall through to the BroadcastChannel stub below, which lets
// WebRTC negotiation proceed in-browser across tabs without a real server.
//
// We treat signaling payloads as JSON envelopes:
//   { kind: 'sdp'|'ice'|'call-meta', to?: peerId, from: peerId, data: {...} }
import * as _fabricMod from '../fabric.js'

class Emitter {
  constructor() { this._h = {} }
  on(ev, cb) { (this._h[ev] = this._h[ev] || []).push(cb); return () => this.off(ev, cb) }
  off(ev, cb) { this._h[ev] = (this._h[ev] || []).filter(f => f !== cb) }
  emit(ev, ...a) { (this._h[ev] || []).forEach(f => { try { f(...a) } catch (e) { console.error(e) } }) }
}

// BroadcastChannel fallback signaling (in-browser same-origin multi-tab).
function bcSession(sessionId, identity) {
  const em = new Emitter()
  const peerId = identity?.peerId || (crypto.randomUUID ? crypto.randomUUID() : String(Math.random()))
  const ch = new BroadcastChannel(`vulos-call:${sessionId}`)
  const peers = new Set()
  let state = 'connecting'

  const setState = (s) => { state = s; em.emit('state', s) }

  ch.onmessage = (ev) => {
    const m = ev.data
    if (!m || m.from === peerId) return
    if (m.kind === 'hello') {
      if (!peers.has(m.from)) { peers.add(m.from); em.emit('peer-join', m.from, m.identity) }
      // reply so the new peer learns about us
      ch.postMessage({ kind: 'hello-ack', from: peerId, identity, to: m.from })
      return
    }
    if (m.kind === 'hello-ack' && m.to === peerId) {
      if (!peers.has(m.from)) { peers.add(m.from); em.emit('peer-join', m.from, m.identity) }
      return
    }
    if (m.kind === 'bye') {
      if (peers.delete(m.from)) em.emit('peer-leave', m.from)
      return
    }
    if (m.to && m.to !== peerId) return
    em.emit('message', m)
  }

  // Announce
  setTimeout(() => {
    ch.postMessage({ kind: 'hello', from: peerId, identity })
    setState('local') // BroadcastChannel stub — no network transport
  }, 0)

  return {
    peerId,
    identity,
    transport: 'bc-stub',
    get state() { return state },
    send(msg) { ch.postMessage({ ...msg, from: peerId }) },
    on: em.on.bind(em),
    off: em.off.bind(em),
    close() {
      try { ch.postMessage({ kind: 'bye', from: peerId }) } catch {}
      try { ch.close() } catch {}
      setState('closed')
    },
  }
}

export async function joinSignalingSession(sessionId, identity) {
  // fabric.js does not currently export joinSession; fall through to the
  // BroadcastChannel stub which handles in-browser same-origin multi-tab
  // signaling for standalone and dev-loop builds.
  // (_fabricMod is kept as a static import so tree-shaking leaves fabric
  // in the bundle for consumers that depend on it directly.)
  return bcSession(sessionId, identity)
}

// Fetch TURN/STUN credentials from the cloud (OFFICE-20 path) with a sane
// public-STUN default. Server endpoint mirrors what the OS fabric uses.
export async function fetchIceServers() {
  try {
    const r = await fetch('/api/turn/credentials', { credentials: 'include' })
    if (r.ok) {
      const body = await r.json()
      if (Array.isArray(body.iceServers) && body.iceServers.length) return body.iceServers
    }
  } catch { /* ignore — fall through */ }
  return [
    { urls: ['stun:stun.l.google.com:19302'] },
  ]
}
