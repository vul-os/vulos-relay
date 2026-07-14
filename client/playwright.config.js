/**
 * Playwright config — @vulos/relay-client.
 *
 * This package is a LIBRARY (no UI), so a conventional "boot guard" — load the
 * app, assert the root isn't empty — is meaningless for it. The honest
 * equivalent, and the one that catches the defect class that shipped blank
 * screens elsewhere in this suite, is:
 *
 *     can a CONSUMER import the BUILT entry points in a real browser, and use
 *     them, without anything throwing?
 *
 * So there is exactly one server here: a tiny consumer harness (e2e/harness/)
 * that imports `@vulos/relay-client` and every published subpath as BARE
 * specifiers through the package `exports` map — i.e. what Office, Meet and Talk
 * actually get — and exercises them in chromium. See e2e/harness/main.jsx.
 *
 * The existing vitest suite (22 files) is good and stays the primary safety net
 * for behaviour. But it imports from src/ and runs in jsdom, so it cannot see:
 * a built entry that throws on load, an `exports` map that drifted from the
 * build, a React accidentally bundled into the library, or a class that only
 * stands up against jsdom's fake WebSocket/RTCPeerConnection. This does.
 *
 * Prereqs:  npm run build && npm run build:harness   (`pretest:e2e` does both)
 *           npx playwright install chromium
 * Run:      npm run test:e2e
 */

import { defineConfig, devices } from '@playwright/test'

// Uncommon port: a stale preview of another Vulos app must never be mistaken
// for this harness.
const PORT = Number(process.env.E2E_PORT ?? 47371)
const BASE_URL = `http://localhost:${PORT}`

export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.e2e.js',
  timeout: 30_000,
  expect: { timeout: 7_000 },
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? [['github'], ['list']] : [['list']],
  use: {
    baseURL: BASE_URL,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    serviceWorkers: 'block',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `npx vite preview --outDir dist-harness --port ${PORT} --strictPort`,
    url: BASE_URL,
    reuseExistingServer: false,
    timeout: 60_000,
  },
})
