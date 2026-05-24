/**
 * src/index.js — @vulos/relay-client root barrel.
 *
 * Re-exports every subpath so consumers can choose between:
 *
 *   import { selectEndpoint } from '@vulos/relay-client'
 *   import { selectEndpoint } from '@vulos/relay-client/endpoints'   // tree-shake
 *
 * Subpaths are also published individually via the `exports` map in
 * package.json so a consumer that only needs one module (e.g. mail just wants
 * `./endpoints` + `./offlineBootstrap`) doesn't pay the cost of the rest.
 */

export * from './endpoints.js'
export * from './offlineBootstrap.js'
export * from './signaling.js'
export * from './fabric.js'
export * from './presence.js'
export * from './call/index.js'
export * from './useLiveCursors.js'
export * from './roundTripCheck.js'
