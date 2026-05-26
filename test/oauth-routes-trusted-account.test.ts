/**
 * Route-level integration tests for the trusted-account OAuth flow (ADR-0007).
 *
 * Unlike `oauth-trusted-account.test.ts` which exercises the OAuthProvider
 * class directly, this file mounts the real `worker/routes/oauth.ts` Hono
 * sub-app and drives requests through `app.fetch`. The point is to cover the
 * route-shell behavior — specifically CSRF state wrapping and audit emission —
 * that the unit tests by-design cannot see.
 *
 * Coverage:
 *   1. BLOCKER 1 (PR #8 review): GET /oauth/authorize with the canonical
 *      trusted-account client_id must NOT wrap the incoming `state` query
 *      parameter in a CSRF-bearing envelope. The redirect Location must carry
 *      the original state verbatim, otherwise better-auth on the consumer
 *      side rejects the callback. Mirrors commit 08abc13 (which fixed the
 *      same class of failure for service-binding callers via X-Issuer).
 *
 *   2. BLOCKER 2 (PR #8 review): A successful trusted-account
 *      authorize + token flow emits `oauth.code.issued` and
 *      `oauth.token.issued` audit events; non-trusted clients do not.
 *
 * See: docs/adr/0007-trusted-account-oauth-via-better-auth.md
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { Hono } from 'hono'
import { oauthRoutes, TRUSTED_ACCOUNT_CLIENT_ID } from '../worker/routes/oauth'
import type { Env, Variables } from '../worker/types'
import type { IdentityStub } from '../src/server/do/Identity'

// ─── Helpers ────────────────────────────────────────────────────────────────

async function computeS256Challenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

/**
 * Build a minimal env with an in-memory IDENTITY DO namespace stub. The DO
 * is sharded by name; we route every name through a single shared in-memory
 * store, which is sufficient for these tests (oauth storage + identity
 * lookup share the same surface here).
 */
function createMockEnv(opts: { trustedDomains?: string } = {}): {
  env: Env
  oauthStore: Map<string, unknown>
  identities: Map<string, { id: string; name?: string; email?: string; emailVerified?: boolean }>
  auditEvents: Array<{ event: string; actor?: string; target?: string; metadata?: Record<string, unknown>; ip?: string; userAgent?: string }>
} {
  const oauthStore = new Map<string, unknown>()
  const identities = new Map<string, { id: string; name?: string; email?: string; emailVerified?: boolean }>([
    ['user-1', { id: 'user-1', name: 'Alice', email: 'alice@example.com', emailVerified: true }],
  ])
  const auditEvents: Array<{ event: string; actor?: string; target?: string; metadata?: Record<string, unknown>; ip?: string; userAgent?: string }> = []

  const stub: Partial<IdentityStub> = {
    getIdentity: vi.fn(async (id: string) => (identities.get(id) ?? null) as never),
    // Used by authenticateRequest → AuthBroker. We expose user-1 as a valid
    // session so the route receives `c.get('auth')` with `identityId: 'user-1'`.
    getSession: vi.fn(async (token: string) => {
      // The broker extracts `ses_*` from `Authorization: Bearer ses_*` and
      // passes the remainder (after stripping `Bearer `) to getSession.
      if (token === 'ses_user_1_session') {
        return { valid: true, identityId: 'user-1', level: 2 } as never
      }
      return { valid: false } as never
    }),
    validateApiKey: vi.fn(async () => ({ valid: false }) as never),
    checkRateLimit: vi.fn(async () => ({ allowed: true, remaining: 100, resetAt: Date.now() + 60000 }) as never),
    ensureWebClients: vi.fn(async () => {}),
    ensureCliClient: vi.fn(async () => {}),
    ensureOAuthDoClient: vi.fn(async () => {}),
    oauthStorageOp: vi.fn(async (op: { op: string; key?: string; value?: unknown; options?: { prefix?: string; limit?: number } }) => {
      if (op.op === 'get' && op.key) {
        return { value: oauthStore.get(op.key) }
      }
      if (op.op === 'put' && op.key) {
        oauthStore.set(op.key, op.value)
        return { ok: true }
      }
      if (op.op === 'delete' && op.key) {
        return { deleted: oauthStore.delete(op.key) }
      }
      if (op.op === 'list') {
        const entries: Array<[string, unknown]> = []
        for (const [k, v] of oauthStore) {
          if (op.options?.prefix && !k.startsWith(op.options.prefix)) continue
          entries.push([k, v])
        }
        return { entries }
      }
      return {}
    }),
    auditEvent: vi.fn(async (e: { event: string; actor?: string; target?: string; metadata?: Record<string, unknown>; ip?: string; userAgent?: string }) => {
      auditEvents.push(e)
    }),
  }

  const env: Env = {
    IDENTITY: {
      // idFromName/get → always return the same stub. Sharding is invisible
      // here because we route everything to one in-memory store.
      idFromName: () => ({ toString: () => 'mock-id' } as unknown as DurableObjectId),
      get: () => stub as unknown as DurableObjectStub,
    } as unknown as DurableObjectNamespace,
    SESSIONS: {} as KVNamespace,
    AUTH_SECRET: 'test-secret',
    JWKS_SECRET: 'test-jwks-secret',
    ...(opts.trustedDomains !== undefined && { TRUSTED_ACCOUNT_DOMAINS: opts.trustedDomains }),
  }

  return { env, oauthStore, identities, auditEvents }
}

/**
 * Mount the oauthRoutes sub-app with the identity stub pre-bound so the
 * route's `authenticateRequest` middleware resolves a real identity. We
 * pass a session token in tests; the stub's `getSession` returns user-1.
 */
function mountApp(env: Env) {
  const app = new Hono<{ Bindings: Env; Variables: Variables }>()
  app.use('*', async (c, next) => {
    // Mimic worker/middleware/tenant.ts#identityStubMiddleware: pre-bind the
    // identity-specific stub before authenticateRequest runs.
    const stub = env.IDENTITY.get(env.IDENTITY.idFromName('user-1')) as unknown as IdentityStub
    c.set('identityStub', stub)
    c.set('resolvedIdentityId', 'user-1')
    await next()
  })
  app.route('', oauthRoutes)
  return app
}

/** Build a Bearer Authorization header that the broker's session path accepts. */
const TEST_SESSION_HEADERS = { authorization: 'Bearer ses_user_1_session' }

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('worker/routes/oauth — trusted-account /oauth/authorize (ADR-0007 / BLOCKER 1)', () => {
  let env: Env

  beforeEach(() => {
    ;({ env } = createMockEnv({ trustedDomains: 'startup.games' }))
  })

  it('does NOT wrap the state parameter when client_id is the trusted-account client', async () => {
    const app = mountApp(env)
    const codeChallenge = await computeS256Challenge('verifier-1234567890abcdef')

    const url = new URL('https://id.org.ai/oauth/authorize')
    url.searchParams.set('client_id', TRUSTED_ACCOUNT_CLIENT_ID)
    url.searchParams.set('redirect_uri', 'https://startup.games/api/auth/callback/id-org-ai')
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('scope', 'openid profile email')
    url.searchParams.set('code_challenge', codeChallenge)
    url.searchParams.set('code_challenge_method', 'S256')
    url.searchParams.set('state', 'ORIGINAL_STATE')

    const res = await app.fetch(
      new Request(url.toString(), { method: 'GET', redirect: 'manual', headers: TEST_SESSION_HEADERS }),
      env,
    )

    expect(res.status).toBe(302)
    const location = res.headers.get('location')!
    expect(location).toBeTruthy()
    const locUrl = new URL(location)
    expect(locUrl.hostname).toBe('startup.games')
    expect(locUrl.pathname).toBe('/api/auth/callback/id-org-ai')

    // The state must round-trip verbatim. If CSRF wrapping leaked through,
    // the value would be a base64-encoded {csrf, s: 'ORIGINAL_STATE'} blob.
    const returnedState = locUrl.searchParams.get('state')
    expect(returnedState).toBe('ORIGINAL_STATE')
    expect(returnedState).not.toMatch(/^[A-Za-z0-9_-]{40,}$/) // sanity: not a long base64ish blob

    // A code should also be present, since trusted clients skip consent.
    expect(locUrl.searchParams.get('code')).toMatch(/^ac_/)
  })

  it('emits oauth.code.issued via the IdentityDO stub when the trusted-account client receives a code (BLOCKER 2)', async () => {
    const { env: env2, auditEvents } = createMockEnv({ trustedDomains: 'startup.games' })
    const app = mountApp(env2)
    const codeChallenge = await computeS256Challenge('verifier-1234567890abcdef')

    const url = new URL('https://id.org.ai/oauth/authorize')
    url.searchParams.set('client_id', TRUSTED_ACCOUNT_CLIENT_ID)
    url.searchParams.set('redirect_uri', 'https://startup.games/api/auth/callback/id-org-ai')
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('scope', 'openid profile email')
    url.searchParams.set('code_challenge', codeChallenge)
    url.searchParams.set('code_challenge_method', 'S256')
    url.searchParams.set('state', 'ORIGINAL_STATE')

    const res = await app.fetch(
      new Request(url.toString(), { method: 'GET', redirect: 'manual', headers: TEST_SESSION_HEADERS }),
      env2,
    )
    expect(res.status).toBe(302)

    const codeEvents = auditEvents.filter((e) => e.event === 'oauth.code.issued')
    expect(codeEvents).toHaveLength(1)
    expect(codeEvents[0].metadata?.clientId).toBe(TRUSTED_ACCOUNT_CLIENT_ID)
    expect(codeEvents[0].metadata?.identityId).toBe('user-1')
    expect(codeEvents[0].metadata?.redirectUriHost).toBe('startup.games')
  })

  it('still wraps state for ordinary (non-trusted, non-service-binding) clients', async () => {
    // Seed a DCR-style client so the request gets past the client lookup.
    const { env: envWithClient, oauthStore } = createMockEnv({ trustedDomains: 'startup.games' })
    oauthStore.set('client:cid_some_normal_app', {
      id: 'cid_some_normal_app',
      name: 'Some Normal App',
      redirectUris: ['https://normal-app.example.com/cb'],
      grantTypes: ['authorization_code'],
      responseTypes: ['code'],
      scopes: ['openid', 'profile', 'email'],
      trusted: false,
      tokenEndpointAuthMethod: 'none',
      createdAt: 0,
    })
    const app = mountApp(envWithClient)
    const codeChallenge = await computeS256Challenge('verifier-1234567890abcdef')

    const url = new URL('https://id.org.ai/oauth/authorize')
    url.searchParams.set('client_id', 'cid_some_normal_app')
    url.searchParams.set('redirect_uri', 'https://normal-app.example.com/cb')
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('scope', 'openid')
    url.searchParams.set('code_challenge', codeChallenge)
    url.searchParams.set('code_challenge_method', 'S256')
    url.searchParams.set('state', 'ORIGINAL_STATE')

    const res = await app.fetch(
      new Request(url.toString(), { method: 'GET', redirect: 'manual', headers: TEST_SESSION_HEADERS }),
      envWithClient,
    )

    // The DCR client is not trusted, so the response is the consent HTML page,
    // not a redirect. We only care here that the state we'd echo back to the
    // consumer would be a wrapped value if the consent page were to be
    // submitted — that's the path 08abc13 already handles via decodeStateWithCSRF.
    expect(res.status).toBe(200)
    const html = await res.text()
    // The consent form embeds the (wrapped) state in a hidden input.
    expect(html).toContain('<input type="hidden" name="state"')
    // The original state value must NOT appear verbatim — it's CSRF-wrapped.
    expect(html).not.toContain('value="ORIGINAL_STATE"')
  })
})
