/**
 * e2e/harness/main.jsx — a CONSUMER of the BUILT @vulos/relay-client.
 *
 * WHY A HARNESS AND NOT A "BOOT GUARD": this package is a library. It has no UI
 * and no root element to render, so "does the app boot" is not a question that
 * can be asked of it. The honest equivalent — and the one that catches the class
 * of defect that shipped blank screens in this suite — is:
 *
 *     can a consumer IMPORT the built entry points in a real browser, and USE
 *     them, without anything throwing?
 *
 * Every import below is a BARE specifier resolved through the package `exports`
 * map, so this file pulls dist-lib/ — never src/. There is deliberately no alias
 * back to source; an alias would turn this into another source test, which is
 * what the existing vitest suite already is (and which cannot see build defects).
 *
 * What this catches that vitest+jsdom cannot:
 *
 *  1. A BUILT ENTRY THAT THROWS ON LOAD. Module-level code runs at import time.
 *     A bad build (or an import the bundler couldn't resolve) makes the very
 *     first `import` blow up in the consumer's app. Office/Meet/Talk would go
 *     blank; the relay unit suite would stay green.
 *
 *  2. AN `exports` MAP THAT DRIFTS FROM THE BUILD. Every subpath here is bare,
 *     so if `exports` advertises a subpath that vite.config.lib.js no longer
 *     emits (add a module to src/ + exports, forget the build entry — an easy
 *     miss with 12 entries), THIS BUILD FAILS. Loudly, here — instead of as an
 *     unresolvable import inside a consumer's bundle.
 *
 *  3. A DUPLICATED REACT. `react` is an optional peer, declared external in the
 *     lib build. If that ever breaks, dist-lib carries its own React, and
 *     useLiveCursors — a hooks API — runs against a different React than the
 *     consumer's tree: "Invalid hook call", uncaught exception, blank host app.
 *     Mounting the built hook in the harness's own React root is what detects it.
 *
 *  4. jsdom-ONLY CORRECTNESS. The unit suite runs in jsdom, whose WebSocket /
 *     RTCPeerConnection / crypto are fakes or absent. Constructing FabricClient,
 *     SignalingClient and PresenceManager in real chromium proves the classes
 *     actually stand up against the browser's real platform objects.
 *
 * NOT IMPORTED HERE: `@vulos/relay-client/roundTripCheck`. It statically imports
 * `xlsx`, an OPTIONAL peerDependency that is intentionally not installed (only
 * consumers who use the spreadsheet round-trip checks add it). Importing it here
 * would fail to resolve — which is the package working as designed, not a defect.
 * Its built artifact is instead asserted in the spec: it must exist, be served as
 * JS, and keep `xlsx` external. See e2e/library.e2e.js.
 */

import { StrictMode, useState } from 'react'
import * as React from 'react'
import { createRoot } from 'react-dom/client'

// The root barrel.
import * as index from '@vulos/relay-client'

// Every published subpath, as a consumer would import it.
import * as errors from '@vulos/relay-client/errors'
import * as endpoints from '@vulos/relay-client/endpoints'
import * as health from '@vulos/relay-client/health'
import * as offlineBootstrap from '@vulos/relay-client/offlineBootstrap'
import * as signaling from '@vulos/relay-client/signaling'
import * as fabric from '@vulos/relay-client/fabric'
import * as presence from '@vulos/relay-client/presence'
import * as call from '@vulos/relay-client/call'
import * as regionPop from '@vulos/relay-client/regionPop'
import { useLiveCursors } from '@vulos/relay-client/useLiveCursors'

const record = { imported: {}, constructed: {}, pure: {}, hook: null, reactVersion: React.version, errors: [] }

// ── 1. Every subpath evaluated, and its public surface is really there. ──────
// (A build that emits an EMPTY module — a real rollup failure mode when an entry
// is misconfigured — would import "fine" and export nothing. Count the exports.)
for (const [name, mod] of Object.entries({
  index, errors, endpoints, health, offlineBootstrap, signaling, fabric, presence, call, regionPop,
})) {
  record.imported[name] = Object.keys(mod).sort()
}
record.imported.useLiveCursors = typeof useLiveCursors === 'function' ? ['useLiveCursors'] : []

// ── 2. The real classes stand up against the BROWSER's platform objects. ─────
// None of these connect: FabricClient/SignalingClient only open a socket on an
// explicit .connect(). Construction alone is what we want — it is where a bad
// build or a jsdom-only assumption surfaces.
// Report `instanceof`, NOT constructor.name: the library build minifies, so class
// names are mangled ("FabricClient" → "Kr"). Asserting on the mangled name would
// be brittle nonsense; asserting the instance really IS the exported class is the
// thing that matters — and it also proves the class we imported is the class the
// bundle constructs (no stale duplicate module in the graph).
try {
  const f = new fabric.FabricClient({
    sessionId: 'harness-session',
    peerId: 'harness-peer',
    signalingUrl: 'ws://127.0.0.1:9/api/peering/stream', // never dialled
    authToken: null,
    requirePeerAuth: false,
  })
  record.constructed.FabricClient = f instanceof fabric.FabricClient

  const s = new signaling.SignalingClient({
    signalingUrl: 'ws://127.0.0.1:9/api/peering/stream', // never dialled
    sessionId: 'harness-session',
    peerId: 'harness-peer',
  })
  record.constructed.SignalingClient = s instanceof signaling.SignalingClient
  // SignalingClient extends EventTarget — the browser must agree.
  record.constructed.signalingIsEventTarget = s instanceof EventTarget

  const pm = new presence.PresenceManager({
    fabric: f,
    localIdentity: { accountId: 'acct_harness', displayName: 'Harness' },
  })
  record.constructed.PresenceManager = pm instanceof presence.PresenceManager
  record.constructed.presenceIsEventTarget = pm instanceof EventTarget

  // The root barrel must re-export the SAME class objects as the subpaths — not
  // a second copy from a duplicated module in the bundle graph. If it ever does,
  // `instanceof` checks in consumer code start failing at random.
  record.constructed.barrelIdentity =
    index.FabricClient === fabric.FabricClient &&
    index.SignalingClient === signaling.SignalingClient &&
    index.PresenceManager === presence.PresenceManager
} catch (e) {
  record.errors.push(`construct: ${e?.message ?? String(e)}`)
}

// ── 3. Pure exports actually compute in a browser. ───────────────────────────
try {
  record.pure.version = health.RELAY_CLIENT_VERSION
  record.pure.healthStatus = health.createHealthReport()?.status
  // regionPop maps a region to its nearest PoP — a pure lookup used to pick a
  // relay. If the built module lost its data table, selectPop silently returns
  // the caller's default and every consumer routes to the wrong PoP: a
  // performance/sovereignty regression with no error anywhere.
  record.pure.popMapSize = Object.keys(regionPop.REGION_POP_MAP ?? {}).length
  record.pure.popMapEu = regionPop.REGION_POP_MAP?.eu ?? null
  record.pure.popForEu = regionPop.selectPop('eu', 'default-pop')
  // …and an unknown region must still fall back to the caller's default.
  record.pure.popForUnknown = regionPop.selectPop('nowhere-1', 'default-pop')
} catch (e) {
  record.errors.push(`pure: ${e?.message ?? String(e)}`)
}

// ── 4. The exported REACT HOOK runs inside the consumer's own React tree. ────
// This is the duplicate-React detector. With a second React inside dist-lib this
// component throws "Invalid hook call" and #root stays empty.
function CursorsProbe() {
  // fabric=null is the documented "not connected yet" path: the hook must still
  // return a stable API rather than throw (consumers render before connecting).
  const { remoteCursors, broadcastDocCursor } = useLiveCursors({
    fabric: null,
    localIdentity: { accountId: 'acct_harness', displayName: 'Harness' },
    color: '#c96442',
  })
  // Prove the hook's own state machinery works under the consumer's React.
  const [clicked, setClicked] = useState(false)

  return (
    <div>
      <p data-testid="hook-ok">
        useLiveCursors mounted · remoteCursors={remoteCursors instanceof Map ? 'Map' : typeof remoteCursors} · size=
        {remoteCursors?.size ?? -1}
      </p>
      <button
        data-testid="broadcast"
        onClick={() => {
          // Must be a no-op (not a throw) with no fabric attached.
          broadcastDocCursor?.({ from: 0, to: 3 })
          setClicked(true)
        }}
      >
        broadcast
      </button>
      {clicked && <p data-testid="broadcast-ok">broadcast did not throw</p>}
    </div>
  )
}

window.__relayHarness = record

const rootEl = document.getElementById('root')
if (rootEl) {
  createRoot(rootEl).render(
    <StrictMode>
      <CursorsProbe />
    </StrictMode>,
  )
}
