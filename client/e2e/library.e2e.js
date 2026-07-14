/**
 * library.e2e.js — THE BOOT GUARD, in the only form that makes sense for a
 * library: can a consumer IMPORT the built package in a real browser and USE it
 * without anything throwing?
 *
 * @vulos/relay-client has no UI, so there is no root element to render and no
 * "blank screen" of its own. But it is imported by Office, Meet and Talk — and
 * a library whose built entry point throws on load takes THEIR app blank. That
 * is precisely how one of the two shipped blank screens happened: an unresolved
 * import became a module that throws the moment it is evaluated. The 22-file
 * vitest suite here cannot see it, because it imports from src/ and never builds.
 *
 * Everything below drives e2e/harness/ — a stand-in consumer that imports the
 * BUILT dist-lib/ through the package `exports` map (bare specifiers, no
 * aliases). See harness/main.jsx for the full rationale.
 */

import { test, expect } from '@playwright/test'
import { readFile, access } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { resolve, dirname } from 'node:path'

const pkgDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const readPkg = async () => JSON.parse(await readFile(resolve(pkgDir, 'package.json'), 'utf8'))

/** Record uncaught exceptions + dead requests for the page's life. */
function watchForCrashes(page) {
  const pageErrors = []
  const failedRequests = []
  page.on('pageerror', (err) => pageErrors.push(`${err.name}: ${err.message}`))
  page.on('requestfailed', (req) => {
    if (req.url().startsWith('http://localhost')) {
      failedRequests.push(`${req.url()} — ${req.failure()?.errorText}`)
    }
  })
  return { pageErrors, failedRequests }
}

test('a consumer can import every BUILT entry point in a real browser', async ({ page }) => {
  const { pageErrors, failedRequests } = watchForCrashes(page)

  await page.goto('/')

  const h = await page.evaluate(() => window.__relayHarness)

  // If any built entry threw while being evaluated, module execution stops and
  // the harness never publishes its record. That is the failure that takes a
  // consumer's whole app blank — surfaced here as a clear message.
  expect(h, 'a built entry point threw on import — the harness never finished loading').toBeTruthy()
  expect(h.errors, 'the built library threw while being used').toEqual([])

  // Each subpath evaluated AND actually exports something. A misconfigured build
  // entry can emit an EMPTY module: it imports "fine" and exports nothing, so a
  // consumer's `import { FabricClient }` silently yields undefined and blows up
  // later, far from the cause.
  expect(h.imported.index.length, 'the root barrel exports nothing').toBeGreaterThan(10)
  expect(h.imported.errors).toEqual(
    expect.arrayContaining(['EndpointError', 'FabricError', 'RelayDepositError', 'SignalingError']),
  )
  expect(h.imported.fabric).toContain('FabricClient')
  expect(h.imported.signaling).toContain('SignalingClient')
  expect(h.imported.presence).toContain('PresenceManager')
  expect(h.imported.endpoints).toEqual(expect.arrayContaining(['selectEndpoint', 'resolveEndpoints']))
  expect(h.imported.offlineBootstrap).toContain('bootstrapOffline')
  expect(h.imported.health).toContain('createHealthReport')
  expect(h.imported.regionPop).toEqual(expect.arrayContaining(['REGION_POP_MAP', 'selectPop']))
  expect(h.imported.call.length, 'the call entry exports nothing').toBeGreaterThan(0)
  expect(h.imported.useLiveCursors).toEqual(['useLiveCursors'])

  expect(pageErrors, 'the built library threw in a real browser').toEqual([])
  expect(failedRequests, 'an advertised artifact failed to load').toEqual([])
})

test('the built classes stand up against the browser, not just jsdom', async ({ page }) => {
  // The unit suite runs in jsdom, whose WebSocket / RTCPeerConnection / crypto
  // are fakes or missing outright. A class that only constructs under jsdom is a
  // crash in a consumer's real browser — and this is the only test that would
  // notice. (None of these connect: a socket is opened only on .connect().)
  watchForCrashes(page)
  await page.goto('/')

  const h = await page.evaluate(() => window.__relayHarness)
  expect(h.errors).toEqual([])

  // `instanceof`, not constructor.name — the lib build minifies class names
  // ("FabricClient" → "Kr"), so a name assertion would be brittle noise. This
  // also proves the constructed object IS the exported class.
  expect(h.constructed.FabricClient, 'new FabricClient() did not produce a FabricClient').toBe(true)
  expect(h.constructed.SignalingClient).toBe(true)
  expect(h.constructed.PresenceManager).toBe(true)
  // Both extend EventTarget — the browser must agree (jsdom's EventTarget is a
  // different object, so this is a genuinely different check than the unit suite).
  expect(h.constructed.signalingIsEventTarget).toBe(true)
  expect(h.constructed.presenceIsEventTarget).toBe(true)

  // The root barrel re-exports the SAME class objects as the subpaths. If the
  // bundle ever contains two copies of a module, `instanceof` in consumer code
  // starts failing seemingly at random — a miserable bug to chase downstream.
  expect(h.constructed.barrelIdentity, 'the root barrel exports different class objects than the subpaths').toBe(true)

  // Pure exports really compute from the BUILT bundle. A build that dropped the
  // region→PoP data table would still import cleanly and silently route every
  // consumer to the default PoP.
  expect(h.pure.healthStatus).toBe('ok')
  expect(h.pure.version, 'RELAY_CLIENT_VERSION missing from the built bundle').toBeTruthy()
  expect(h.pure.popMapSize, 'REGION_POP_MAP is empty in the built bundle').toBeGreaterThan(0)
  expect(h.pure.popMapEu, 'REGION_POP_MAP lost its "eu" entry in the built bundle').toBeTruthy()
  // A known region resolves to its PoP from the built data table…
  expect(h.pure.popForEu, 'selectPop("eu") fell through to the default — is the data table intact?')
    .toBe(h.pure.popMapEu)
  // …and an unknown one still falls back to the caller's default.
  expect(h.pure.popForUnknown).toBe('default-pop')
})

test('the exported React hook runs in the consumer\'s own React tree', async ({ page }) => {
  // THE DUPLICATED-REACT GUARD. `react` is an optional peer, declared external in
  // vite.config.lib.js. If that externalization ever breaks, dist-lib ships its
  // own React; useLiveCursors then calls hooks against a different React instance
  // than the consumer's root → "Invalid hook call" → uncaught exception → the
  // consumer's app (Office/Meet/Talk), not just this component, goes blank.
  // That is one of the two blank screens that shipped. The build stays green.
  const { pageErrors } = watchForCrashes(page)

  await page.goto('/')

  // The hook mounted and returned its documented shape.
  const probe = page.getByTestId('hook-ok')
  await expect(probe).toBeVisible()
  await expect(probe).toContainText('remoteCursors=Map')
  await expect(probe).toContainText('size=0')

  // Its returned broadcasters must be safe to call before a fabric is attached —
  // consumers render before they connect, so a throw here is a real crash path.
  await page.getByTestId('broadcast').click()
  await expect(page.getByTestId('broadcast-ok')).toBeVisible()

  expect(pageErrors, 'the exported hook threw — is React bundled into the library?').toEqual([])
})

test('the built ESM keeps react and xlsx external instead of bundling them', async ({ page }) => {
  // The static half of the duplicated-React guard, plus its xlsx twin.
  //
  // If someone drops `react` from rollupOptions.external in vite.config.lib.js,
  // the library silently starts SHIPPING React. Consumers then run two Reacts and
  // every hook breaks — while `npm run build` still exits 0 and every unit test
  // still passes. Same story for `xlsx`: it is a heavyweight OPTIONAL peer, and
  // bundling it would bloat (and break) every consumer that never asked for it.
  await page.goto('/') // ensure the build under test is the one being served

  const esm = await readFile(resolve(pkgDir, 'dist-lib/useLiveCursors.js'), 'utf8')
  expect(esm, 'useLiveCursors.js does not import react — is React bundled into the library?')
    .toMatch(/from\s*["']react["']/)
  expect(esm, 'React internals are bundled into the library')
    .not.toMatch(/__SECRET_INTERNALS|ReactCurrentDispatcher|react-dom\.production/)

  const rtc = await readFile(resolve(pkgDir, 'dist-lib/roundTripCheck.js'), 'utf8')
  expect(rtc, 'roundTripCheck.js does not import xlsx — is xlsx bundled into the library?')
    .toMatch(/from\s*["']xlsx["']/)
})

test('every subpath the exports map advertises is actually emitted by the build', async ({ page }) => {
  // THE DRIFT GUARD — and the closest analogue in this repo to the defect that
  // shipped: "an unresolved import that the bundler turned into a module that
  // throws on load".
  //
  // package.json advertises 12 subpaths; vite.config.lib.js has to emit an entry
  // for each, and tsconfig.dts.json a .d.ts. Add a module to src/ and to
  // `exports`, forget the build entry, and the package publishes a subpath that
  // POINTS AT A FILE THAT DOES NOT EXIST. The consumer's bundler then fails to
  // resolve it — or, depending on their config, stubs it into a throwing module
  // and blanks their app. Nothing in this repo would have caught that; `npm run
  // build` exits 0 and every unit test passes.
  //
  // The harness build already proves the `import` conditions resolve (it imports
  // them all as bare specifiers). This closes the loop on the `require` (CJS) and
  // `types` conditions, which no browser test can reach.
  const pkg = await readPkg()
  const missing = []

  for (const [subpath, cond] of Object.entries(pkg.exports)) {
    if (typeof cond !== 'object' || subpath === './package.json') continue
    for (const field of ['import', 'require', 'types', 'default']) {
      const target = cond[field]
      if (!target) continue
      try {
        await access(resolve(pkgDir, target))
      } catch {
        missing.push(`exports["${subpath}"].${field} → ${target} (not emitted by the build)`)
      }
    }
  }

  expect(missing, 'the exports map advertises files the build does not emit').toEqual([])

  // And the "files" allow-list must actually ship dist-lib/, or every one of the
  // above resolves locally and 404s for anyone who installs the package.
  expect(pkg.files).toEqual(expect.arrayContaining(['dist-lib/']))
})
