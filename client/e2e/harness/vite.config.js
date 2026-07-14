/**
 * vite.config.js — build config for the built-library CONSUMER harness.
 *
 * Deliberately behaves like a downstream app (Office/Meet/Talk), not like this
 * package: `@vulos/relay-client` and its subpaths are left to resolve as BARE
 * specifiers through the package's own `exports` map (self-reference). If the
 * exports map and the library build ever drift apart, THIS BUILD FAILS — which
 * is exactly the red test we want, instead of an unresolvable import surfacing
 * inside a consumer's bundle (or, worse, a module that throws on load and takes
 * their whole app blank).
 *
 * There is intentionally NO resolve.alias back to src/ or to dist-lib/ paths.
 * An alias would make this a source test — which is what vitest already does,
 * and which structurally cannot see build-output defects.
 */

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

const dir = import.meta.dirname

export default defineConfig({
  root: dir,
  plugins: [react()],
  build: {
    outDir: resolve(dir, '../../dist-harness'),
    emptyOutDir: true,
    // Keep the output readable if a failure ever has to be debugged here.
    minify: false,
  },
})
