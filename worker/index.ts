/**
 * id.org.ai — Agent-First Identity
 *
 * Cloudflare Worker entry point.
 * Routes: id.org.ai, auth.org.ai
 */

import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { IdentityDO } from '../src/do/Identity'

export { IdentityDO }

interface Env {
  IDENTITY: DurableObjectNamespace
  DB: D1Database
  SESSIONS: KVNamespace
  WORKOS_API_KEY: string
  WORKOS_CLIENT_ID: string
  AUTH_SECRET: string
  JWKS_SECRET: string
  GITHUB_APP_ID?: string
  GITHUB_APP_PRIVATE_KEY?: string
  GITHUB_WEBHOOK_SECRET?: string
}

const app = new Hono<{ Bindings: Env }>()

app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  credentials: true,
}))

// Health
app.get('/health', (c) => c.json({ status: 'ok', service: 'id.org.ai' }))

// OIDC Discovery
app.get('/.well-known/openid-configuration', (c) => {
  const base = 'https://id.org.ai'
  return c.json({
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    userinfo_endpoint: `${base}/oauth/userinfo`,
    jwks_uri: `${base}/.well-known/jwks.json`,
    registration_endpoint: `${base}/oauth/register`,
    device_authorization_endpoint: `${base}/oauth/device`,
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256', 'ES256'],
  })
})

// Forward all identity operations to the IdentityDO
app.all('/api/*', async (c) => {
  const id = c.env.IDENTITY.idFromName('global')
  const stub = c.env.IDENTITY.get(id)
  return stub.fetch(c.req.raw)
})

// OAuth endpoints → IdentityDO
app.all('/oauth/*', async (c) => {
  const id = c.env.IDENTITY.idFromName('global')
  const stub = c.env.IDENTITY.get(id)
  return stub.fetch(c.req.raw)
})

// GitHub webhook endpoint
app.post('/webhook/github', async (c) => {
  // TODO: Verify signature, parse event, handle push
  return c.json({ received: true })
})

// Fallback
app.all('*', (c) => c.json({
  error: 'not_found',
  service: 'id.org.ai',
  tagline: 'Humans. Agents. Identity.',
}, 404))

export default app
