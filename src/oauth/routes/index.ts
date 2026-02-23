/**
 * Route modules for the OAuth 2.1 server
 *
 * Each module returns a Hono sub-app with related endpoints grouped together.
 * The main server.ts composes these into a single app.
 */

export { createDiscoveryRoutes } from './discovery'
export { createAuthorizeRoutes } from './authorize'
export { createTokenRoutes } from './token'
export { createClientRoutes } from './clients'
export { createDeviceRoutes } from './device'
export { createIntrospectRoutes } from './introspect'
