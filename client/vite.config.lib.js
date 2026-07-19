/**
 * vite.config.lib.js — library build for @vulos/relay-client.
 *
 * Produces dist-lib/ with ESM + CJS bundles, one entry per subpath.
 * Externalizes react / xlsx so consumers can dedupe
 * (they're declared as optional peerDependencies in package.json).
 *
 * Usage: vite build --config vite.config.lib.js
 */

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

const dir = import.meta.dirname

const entries = {
  index:             resolve(dir, 'src/index.js'),
  errors:            resolve(dir, 'src/errors.js'),
  endpoints:         resolve(dir, 'src/endpoints.js'),
  health:            resolve(dir, 'src/health.js'),
  offlineBootstrap:  resolve(dir, 'src/offlineBootstrap.js'),
  signaling:         resolve(dir, 'src/signaling.js'),
  fabric:            resolve(dir, 'src/fabric.js'),
  rendezvous:        resolve(dir, 'src/rendezvous.js'),
  presence:          resolve(dir, 'src/presence.js'),
  call:              resolve(dir, 'src/call/index.js'),
  useLiveCursors:    resolve(dir, 'src/useLiveCursors.js'),
  roundTripCheck:    resolve(dir, 'src/roundTripCheck.js'),
  regionPop:         resolve(dir, 'src/regionPop.js'),
}

export default defineConfig({
  plugins: [react()],
  define: {
    'import.meta.env.VITE_BUILD_TARGET': JSON.stringify('lib'),
  },
  build: {
    lib: {
      entry: entries,
      formats: ['es', 'cjs'],
      fileName: (format, entryName) =>
        format === 'es' ? `${entryName}.js` : `${entryName}.cjs`,
    },
    outDir: 'dist-lib',
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      external: [
        'react',
        'react-dom',
        'react/jsx-runtime',
        'xlsx',
      ],
      output: {
        // Keep the upstream `@license` / `@preserve` banners in the bundled
        // output. MIT, BSD and ISC all require the copyright notice to travel
        // with every copy, and a bundle IS a copy. Vite 8 bundles with
        // rolldown, whose minifier drops every comment unless this is set —
        // note that `esbuild.legalComments` does NOT do it, because in Vite 8
        // the esbuild options only reach the CSS pipeline.
        comments: { legal: true },
        exports: 'named',
        globals: {
          react: 'React',
          'react-dom': 'ReactDOM',
          'react/jsx-runtime': 'ReactJSXRuntime',
          xlsx: 'XLSX',
        },
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['src/**/*.test.{js,jsx}', 'src/__tests__/**/*.test.{js,jsx}'],
  },
})
