/**
 * vitest.config.js — test runner config for @vulos/relay-client.
 *
 * Split from vite.config.lib.js so the library build (`npm run build`) and the
 * test runner (`npm test`) don't share each other's transform pipeline — the
 * lib build externalises react/livekit/xlsx, but the test runner needs them
 * resolved in-process.
 */

import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['src/**/*.test.{js,jsx}', 'src/__tests__/**/*.test.{js,jsx}'],
  },
})
