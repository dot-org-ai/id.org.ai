/**
 * id.org.ai as an authorization server for remote MCP clients (api.sb):
 *
 *   1. RFC 9207 — every authorization response (code, error, denial) carries
 *      `iss`, the issuer the client discovered.
 *   2. RFC 8707 — `resource` is validated and becomes the token's audience,
 *      reported as `aud` by introspection; the token endpoint cannot re-target
 *      a grant.
 *   3. `sb:read` / `sb:do` — only for an api.sb resource, always consented,
 *      never through client_credentials or the device flow, with a read-only
 *      choice and a step-up to `sb:do`.
 *
 * Plus the hardening they need: the consent POST is re-validated, the consent
 * page escapes scope names and cannot be framed, and a code redeems once.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { OAuthProvider, type OAuthConfig } from '../src/sdk/oauth/provider'
import {
  SB_RESOURCES,
  DEFAULT_SB_RESOURCE,
  parseResourceIndicators,
  bindSbScopes,
  canonicalResource,
  SCOPES_SUPPORTED,
} from '../src/sdk/oauth/delegation'

type Store = Map<string, unknown>

function createStorage(withTake = false) {
  const store: Store = new Map()
  const storage = {
    store,
    async get<T = unknown>(key: string): Promise<T | undefined> {
      return store.get(key) as T | undefined
    },
    async put(key: string, value: unknown): Promise<void> {
      store.set(key, structuredClone(value))
    },
    async delete(key: string): Promise<boolean> {
      return store.delete(key)
    },
    async list<T = unknown>(options?: { prefix?: string }): Promise<Map<string, T>> {
      const out = new Map<string, T>()
      for (const [k, v] of store) if (!options?.prefix || k.startsWith(options.prefix)) out.set(k, v as T)
      return out
    },
  }
  if (!withTake) return storage
  return Object.assign(storage, {
    async take<T = unknown>(key: string): Promise<T | undefined> {
      const v = store.get(key) as T | undefined
      store.delete(key)
      return v
    },
  })
}

const CONFIG: OAuthConfig = {
  issuer: 'https://id.org.ai',
  authorizationEndpoint: 'https://id.org.ai/oauth/authorize',
  tokenEndpoint: 'https://id.org.ai/oauth/token',
  userinfoEndpoint: 'https://id.org.ai/oauth/userinfo',
  registrationEndpoint: 'https://id.org.ai/oauth/register',
  deviceAuthorizationEndpoint: 'https://id.org.ai/oauth/device',
  revocationEndpoint: 'https://id.org.ai/oauth/revoke',
  introspectionEndpoint: 'https://id.org.ai/oauth/introspect',
  jwksUri: 'https://id.org.ai/.well-known/jwks.json',
}

const PERSON = 'human:user_person_1'
const REDIRECT = 'https://client.example/cb'
const VERIFIER = 'delegation-test-verifier-0123456789-abcdefghijklmnop'

async function s256(v: string): Promise<string> {
  const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v))
  return btoa(String.fromCharCode(...new Uint8Array(h))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function makeProvider(storage = createStorage(), extra: Partial<ConstructorParameters<typeof OAuthProvider>[0]> = {}) {
  return new OAuthProvider({
    storage,
    config: CONFIG,
    getIdentity: async (id) => ({ id, name: 'Ada', email: 'ada@example.com', emailVerified: true, level: 2 }),
    ...extra,
  })
}

async function register(provider: OAuthProvider, meta: Record<string, unknown> = {}): Promise<string> {
  const res = await provider.handleRegister(
    new Request('https://id.org.ai/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: 'MCP Client', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none', ...meta }),
    }),
  )
  expect(res.status).toBe(201)
  return ((await res.json()) as { client_id: string }).client_id
}

async function authorizeUrl(clientId: string, params: Record<string, string | string[]> = {}): Promise<string> {
  const u = new URL('https://id.org.ai/oauth/authorize')
  const base: Record<string, string> = {
    client_id: clientId,
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: 'openid profile email',
    state: 'st-1',
    code_challenge: await s256(VERIFIER),
    code_challenge_method: 'S256',
  }
  for (const [k, v] of Object.entries(base)) u.searchParams.set(k, v)
  for (const [k, v] of Object.entries(params)) {
    u.searchParams.delete(k)
    for (const one of Array.isArray(v) ? v : [v]) u.searchParams.append(k, one)
  }
  return u.toString()
}

function consentBody(fields: Record<string, string>): Request {
  return new Request('https://id.org.ai/oauth/authorize', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields).toString(),
  })
}

function hiddenFields(html: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const m of html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)) {
    out[m[1]!] = m[2]!.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
  }
  return out
}

/** Authorize → (consent page → approve) → the redirect back. */
async function authorizeThroughConsent(
  provider: OAuthProvider,
  clientId: string,
  params: Record<string, string | string[]> = {},
  approved = 'true',
): Promise<URL> {
  const page = await provider.handleAuthorize(new Request(await authorizeUrl(clientId, params)), PERSON)
  if (page.status === 302) return new URL(page.headers.get('location')!)
  expect(page.status).toBe(200)
  const fields = hiddenFields(await page.text())
  const res = await provider.handleAuthorizeConsent(consentBody({ ...fields, approved }), PERSON)
  expect(res.status).toBe(302)
  return new URL(res.headers.get('location')!)
}

async function redeem(provider: OAuthProvider, clientId: string, code: string, extra: Record<string, string> = {}) {
  const res = await provider.handleToken(
    new Request('https://id.org.ai/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: VERIFIER, ...extra }).toString(),
    }),
  )
  return { status: res.status, body: (await res.json()) as Record<string, any> }
}

async function introspect(provider: OAuthProvider, token: string) {
  const res = await provider.handleIntrospect(
    new Request('https://id.org.ai/oauth/introspect', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token }).toString(),
    }),
  )
  return (await res.json()) as Record<string, any>
}

// ─────────────────────────────────────────────────────────────────────────────

describe('delegation module', () => {
  it('advertises the OIDC scopes then sb:read and sb:do', () => {
    expect(SCOPES_SUPPORTED).toEqual(['openid', 'profile', 'email', 'offline_access', 'sb:read', 'sb:do'])
  })

  it('parses resource indicators per RFC 8707 §2', () => {
    expect(parseResourceIndicators([])).toEqual({ ok: true })
    expect(parseResourceIndicators([null, ''])).toEqual({ ok: true })
    expect(parseResourceIndicators(['https://api.sb/mcp'])).toEqual({ ok: true, resource: 'https://api.sb/mcp' })
    expect(parseResourceIndicators(['http://localhost:8787/mcp'])).toMatchObject({ ok: true })
    expect(parseResourceIndicators(['http://127.0.0.1:8787/mcp'])).toMatchObject({ ok: true })
    expect(parseResourceIndicators(['api.sb'])).toMatchObject({ ok: false })
    expect(parseResourceIndicators(['https://api.sb/mcp#frag'])).toMatchObject({ ok: false })
    expect(parseResourceIndicators(['https://api.sb/mcp#'])).toMatchObject({ ok: false })
    expect(parseResourceIndicators(['http://api.sb/mcp'])).toMatchObject({ ok: false })
    expect(parseResourceIndicators(['https://user:pw@api.sb/mcp'])).toMatchObject({ ok: false })
    expect(parseResourceIndicators(['javascript:alert(1)'])).toMatchObject({ ok: false })
    // One audience per token: two distinct resources are refused, the same one twice is fine.
    expect(parseResourceIndicators(['https://api.sb/mcp', 'https://id.org.ai/mcp'])).toMatchObject({ ok: false })
    expect(parseResourceIndicators(['https://api.sb/mcp', 'https://API.sb/mcp/'])).toMatchObject({ ok: true })
  })

  it('binds sb scopes to api.sb only', () => {
    expect(bindSbScopes(['openid'], undefined)).toEqual({ ok: true, scopes: ['openid'] })
    expect(bindSbScopes(['sb:read'], undefined)).toEqual({ ok: true, scopes: ['sb:read'], resource: DEFAULT_SB_RESOURCE })
    for (const r of SB_RESOURCES) expect(bindSbScopes(['sb:do'], r)).toMatchObject({ ok: true, resource: r })
    expect(bindSbScopes(['sb:read'], 'https://api.sb.evil.example')).toMatchObject({ ok: false, error: 'invalid_target' })
    expect(bindSbScopes(['sb:read'], 'https://id.org.ai/mcp')).toMatchObject({ ok: false, error: 'invalid_target' })
    expect(bindSbScopes(['sb:read'], 'https://api.sb/other')).toMatchObject({ ok: false, error: 'invalid_target' })
    expect(bindSbScopes(['sb:read'], 'https://api.sb:8443/mcp')).toMatchObject({ ok: false, error: 'invalid_target' })
  })

  it('canonicalizes resources for comparison', () => {
    expect(canonicalResource('https://API.SB/')).toBe(canonicalResource('https://api.sb'))
    expect(canonicalResource('https://api.sb./mcp/')).toBe(canonicalResource('https://api.sb/mcp'))
    expect(canonicalResource('https://api.sb/MCP')).not.toBe(canonicalResource('https://api.sb/mcp'))
  })
})

describe('1. RFC 9207 iss in the authorization response', () => {
  let provider: OAuthProvider
  let clientId: string
  beforeEach(async () => {
    provider = makeProvider()
    clientId = await register(provider)
  })

  it('a code redirect carries iss = the issuer', async () => {
    const back = await authorizeThroughConsent(provider, clientId)
    expect(back.searchParams.get('code')).toMatch(/^ac_/)
    expect(back.searchParams.get('state')).toBe('st-1')
    expect(back.searchParams.get('iss')).toBe('https://id.org.ai')
  })

  it('a code issued straight from recorded consent carries iss', async () => {
    await authorizeThroughConsent(provider, clientId)
    const res = await provider.handleAuthorize(new Request(await authorizeUrl(clientId, { state: 'again' })), PERSON)
    expect(res.status).toBe(302)
    const back = new URL(res.headers.get('location')!)
    expect(back.searchParams.get('code')).toBeTruthy()
    expect(back.searchParams.get('iss')).toBe('https://id.org.ai')
  })

  it('an error redirect carries iss', async () => {
    const res = await provider.handleAuthorize(new Request(await authorizeUrl(clientId, { scope: 'openid admin:everything' })), PERSON)
    const back = new URL(res.headers.get('location')!)
    expect(back.searchParams.get('error')).toBe('invalid_scope')
    expect(back.searchParams.get('iss')).toBe('https://id.org.ai')
  })

  it('a denial carries iss and the original state', async () => {
    const back = await authorizeThroughConsent(provider, clientId, {}, 'false')
    expect(back.searchParams.get('error')).toBe('access_denied')
    expect(back.searchParams.get('state')).toBe('st-1')
    expect(back.searchParams.get('iss')).toBe('https://id.org.ai')
  })

  it('iss follows X-Issuer (the issuer that proxy advertises in its metadata)', async () => {
    const url = await authorizeUrl(clientId)
    const page = await provider.handleAuthorize(new Request(url, { headers: { 'X-Issuer': 'https://oauth.do/' } }), PERSON)
    const fields = hiddenFields(await page.text())
    const res = await provider.handleAuthorizeConsent(
      new Request('https://id.org.ai/oauth/authorize', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', 'X-Issuer': 'https://oauth.do/' },
        body: new URLSearchParams({ ...fields, approved: 'true' }).toString(),
      }),
      PERSON,
    )
    expect(new URL(res.headers.get('location')!).searchParams.get('iss')).toBe('https://oauth.do')
  })

  it('an unknown client or unregistered redirect_uri gets a 400, never a redirect', async () => {
    const bad = await provider.handleAuthorize(new Request(await authorizeUrl('cid_nope')), PERSON)
    expect(bad.status).toBe(400)
    const wrongRedirect = await provider.handleAuthorize(new Request(await authorizeUrl(clientId, { redirect_uri: 'https://evil.example/cb' })), PERSON)
    expect(wrongRedirect.status).toBe(400)
  })
})

describe('2. RFC 8707 resource indicators and audience', () => {
  let provider: OAuthProvider
  let clientId: string
  beforeEach(async () => {
    provider = makeProvider()
    clientId = await register(provider)
  })

  it('a token for resource=https://api.sb/mcp introspects with aud = that resource', async () => {
    const back = await authorizeThroughConsent(provider, clientId, { resource: 'https://api.sb/mcp' })
    const { status, body } = await redeem(provider, clientId, back.searchParams.get('code')!, { resource: 'https://api.sb/mcp' })
    expect(status).toBe(200)
    const at = await introspect(provider, body.access_token)
    expect(at.active).toBe(true)
    expect(at.aud).toBe('https://api.sb/mcp')
    expect(at.sub).toBe(PERSON)
    expect(at.client_id).toBe(clientId)
    const rt = await introspect(provider, body.refresh_token)
    expect(rt.aud).toBe('https://api.sb/mcp')
  })

  it('a token with no resource has no aud (unchanged)', async () => {
    const back = await authorizeThroughConsent(provider, clientId)
    const { body } = await redeem(provider, clientId, back.searchParams.get('code')!)
    const at = await introspect(provider, body.access_token)
    expect(at.active).toBe(true)
    expect(at.aud).toBeUndefined()
  })

  it('an invalid resource is refused with invalid_target (and iss)', async () => {
    for (const r of ['not a uri', 'https://api.sb/mcp#x', 'http://api.sb/mcp']) {
      const res = await provider.handleAuthorize(new Request(await authorizeUrl(clientId, { resource: r })), PERSON)
      const back = new URL(res.headers.get('location')!)
      expect(back.searchParams.get('error')).toBe('invalid_target')
      expect(back.searchParams.get('iss')).toBe('https://id.org.ai')
    }
  })

  it('two distinct resources are refused', async () => {
    const res = await provider.handleAuthorize(new Request(await authorizeUrl(clientId, { resource: ['https://api.sb/mcp', 'https://id.org.ai/mcp'] })), PERSON)
    expect(new URL(res.headers.get('location')!).searchParams.get('error')).toBe('invalid_target')
  })

  it('the token endpoint refuses to re-target a code to another resource', async () => {
    const back = await authorizeThroughConsent(provider, clientId, { resource: 'https://id.org.ai/mcp' })
    const { status, body } = await redeem(provider, clientId, back.searchParams.get('code')!, { resource: 'https://api.sb/mcp' })
    expect(status).toBe(400)
    expect(body.error).toBe('invalid_target')
  })

  it('a code granted with no resource can be bound at the token endpoint; the refresh token stays unbound', async () => {
    const back = await authorizeThroughConsent(provider, clientId, { scope: 'openid offline_access' })
    const { body } = await redeem(provider, clientId, back.searchParams.get('code')!, { resource: 'https://id.org.ai/mcp' })
    expect((await introspect(provider, body.access_token)).aud).toBe('https://id.org.ai/mcp')
    expect((await introspect(provider, body.refresh_token)).aud).toBeUndefined()
  })

  it('refresh keeps the audience and refuses a different one', async () => {
    const back = await authorizeThroughConsent(provider, clientId, { resource: 'https://api.sb/mcp' })
    const first = (await redeem(provider, clientId, back.searchParams.get('code')!)).body
    const refresh = (extra: Record<string, string>, rt: string) =>
      provider.handleToken(
        new Request('https://id.org.ai/oauth/token', {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rt, client_id: clientId, ...extra }).toString(),
        }),
      )
    const wrong = await refresh({ resource: 'https://id.org.ai/mcp' }, first.refresh_token)
    expect(wrong.status).toBe(400)
    expect(((await wrong.json()) as any).error).toBe('invalid_target')
    // The refused attempt did not rotate the token away.
    const ok = await refresh({}, first.refresh_token)
    expect(ok.status).toBe(200)
    const second = (await ok.json()) as any
    expect((await introspect(provider, second.access_token)).aud).toBe('https://api.sb/mcp')
  })

  it('client_credentials validates the resource it binds', async () => {
    const reg = await provider.handleRegister(
      new Request('https://id.org.ai/oauth/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ client_name: 'svc', grant_types: ['client_credentials'], token_endpoint_auth_method: 'client_secret_post', scope: 'read' }),
      }),
    )
    const svc = (await reg.json()) as { client_id: string; client_secret: string }
    const cc = (resource: string) =>
      provider.handleToken(
        new Request('https://id.org.ai/oauth/token', {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ grant_type: 'client_credentials', client_id: svc.client_id, client_secret: svc.client_secret, resource }).toString(),
        }),
      )
    expect((await cc('nope')).status).toBe(400)
    const good = await cc('https://svc.example/api')
    expect(good.status).toBe(200)
    expect((await introspect(provider, ((await good.json()) as any).access_token)).aud).toBe('https://svc.example/api')
  })
})

describe('3. sb:read / sb:do', () => {
  let provider: OAuthProvider
  let storage: ReturnType<typeof createStorage>
  let clientId: string
  beforeEach(async () => {
    storage = createStorage()
    provider = makeProvider(storage)
    // Registered like most MCP clients: without the sb scopes.
    clientId = await register(provider, { scope: 'openid profile email' })
  })

  it('any registered client may ask; the consent screen names what is delegated and for whom', async () => {
    const res = await provider.handleAuthorize(new Request(await authorizeUrl(clientId, { scope: 'openid sb:read', resource: 'https://api.sb/mcp' })), PERSON)
    expect(res.status).toBe(200)
    const html = await res.text()
    expect(html).toContain('Read your Startups on api.sb')
    expect(html).toContain('Access for api.sb')
    expect(html).toContain('Returns to client.example')
    expect(html).not.toContain('Allow read only') // nothing to downgrade without sb:do
  })

  it('a token for sb:read is bound to api.sb even when no resource was sent', async () => {
    const back = await authorizeThroughConsent(provider, clientId, { scope: 'openid sb:read' })
    const { body } = await redeem(provider, clientId, back.searchParams.get('code')!)
    expect(body.scope).toBe('openid sb:read')
    const at = await introspect(provider, body.access_token)
    expect(at.aud).toBe(DEFAULT_SB_RESOURCE)
    expect(at.scope).toBe('openid sb:read')
  })

  it('the default api.sb audience may be narrowed to https://api.sb/mcp at the token endpoint', async () => {
    const back = await authorizeThroughConsent(provider, clientId, { scope: 'sb:read' })
    const { status, body } = await redeem(provider, clientId, back.searchParams.get('code')!, { resource: 'https://api.sb/mcp' })
    expect(status).toBe(200)
    expect((await introspect(provider, body.access_token)).aud).toBe('https://api.sb/mcp')
  })

  it('sb scopes for any other resource are refused', async () => {
    for (const r of ['https://id.org.ai/mcp', 'https://api.sb.evil.example/mcp', 'https://evil.example/']) {
      const res = await provider.handleAuthorize(new Request(await authorizeUrl(clientId, { scope: 'sb:do', resource: r })), PERSON)
      const back = new URL(res.headers.get('location')!)
      expect(back.searchParams.get('error')).toBe('invalid_target')
    }
  })

  it('sb:do on the consent screen offers "Allow read only", which grants without sb:do', async () => {
    const page = await provider.handleAuthorize(new Request(await authorizeUrl(clientId, { scope: 'sb:read sb:do', resource: 'https://api.sb/mcp' })), PERSON)
    const html = await page.text()
    expect(html).toContain('Act for you on api.sb')
    expect(html).toContain('Allow read only')
    const res = await provider.handleAuthorizeConsent(consentBody({ ...hiddenFields(html), approved: 'read' }), PERSON)
    const back = new URL(res.headers.get('location')!)
    const { body } = await redeem(provider, clientId, back.searchParams.get('code')!)
    expect(body.scope).toBe('sb:read')
    expect((await storage.get<{ scopes: string[] }>(`consent:${PERSON}:${clientId}`))!.scopes).toEqual(['sb:read'])
  })

  it('step-up: consent to sb:read does not cover sb:do; asking for it shows the screen again', async () => {
    await authorizeThroughConsent(provider, clientId, { scope: 'sb:read', resource: 'https://api.sb/mcp' })
    // sb:read alone: consent on record, a code comes straight back.
    const again = await provider.handleAuthorize(new Request(await authorizeUrl(clientId, { scope: 'sb:read', resource: 'https://api.sb/mcp' })), PERSON)
    expect(again.status).toBe(302)
    // sb:do: the Person is asked.
    const step = await provider.handleAuthorize(new Request(await authorizeUrl(clientId, { scope: 'sb:read sb:do', resource: 'https://api.sb/mcp' })), PERSON)
    expect(step.status).toBe(200)
    const res = await provider.handleAuthorizeConsent(consentBody({ ...hiddenFields(await step.text()), approved: 'true' }), PERSON)
    const { body } = await redeem(provider, clientId, new URL(res.headers.get('location')!).searchParams.get('code')!)
    expect(body.scope).toBe('sb:read sb:do')
  })

  it('a first-party (trusted) client still gets the consent screen for sb scopes', async () => {
    await storage.put('client:first_party', {
      id: 'first_party',
      name: 'First Party',
      redirectUris: [REDIRECT],
      grantTypes: ['authorization_code'],
      responseTypes: ['code'],
      scopes: ['openid', 'profile', 'email'],
      trusted: true,
      tokenEndpointAuthMethod: 'none',
      createdAt: 0,
    })
    // OIDC scopes: no consent screen (unchanged).
    const oidc = await provider.handleAuthorize(new Request(await authorizeUrl('first_party')), PERSON)
    expect(oidc.status).toBe(302)
    // sb scopes: the Person is asked.
    const sb = await provider.handleAuthorize(new Request(await authorizeUrl('first_party', { scope: 'openid sb:read' })), PERSON)
    expect(sb.status).toBe(200)
    expect(await sb.text()).toContain('Read your Startups on api.sb')
  })

  it('the shared trusted-account client cannot ask for sb scopes', async () => {
    const p = makeProvider(createStorage(), { trustedAccount: { clientId: 'cid_trusted_account_v1', allowedDomains: new Set(['client.example']) } })
    const res = await p.handleAuthorize(new Request(await authorizeUrl('cid_trusted_account_v1', { scope: 'openid sb:read' })), PERSON)
    expect(new URL(res.headers.get('location')!).searchParams.get('error')).toBe('invalid_scope')
    // Its OIDC flow is unchanged.
    const ok = await p.handleAuthorize(new Request(await authorizeUrl('cid_trusted_account_v1')), PERSON)
    expect(new URL(ok.headers.get('location')!).searchParams.get('code')).toBeTruthy()
  })

  it('client_credentials cannot carry sb scopes (no Person)', async () => {
    const reg = await provider.handleRegister(
      new Request('https://id.org.ai/oauth/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ client_name: 'svc', grant_types: ['client_credentials'], token_endpoint_auth_method: 'client_secret_post', scope: 'sb:do' }),
      }),
    )
    const svc = (await reg.json()) as { client_id: string; client_secret: string }
    for (const scope of ['sb:do', '']) {
      const res = await provider.handleToken(
        new Request('https://id.org.ai/oauth/token', {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ grant_type: 'client_credentials', client_id: svc.client_id, client_secret: svc.client_secret, ...(scope && { scope }) }).toString(),
        }),
      )
      expect(res.status).toBe(400)
      expect(((await res.json()) as any).error).toBe('invalid_scope')
    }
  })

  it('the device flow cannot carry sb scopes (its approval page names none)', async () => {
    const reg = await provider.handleRegister(
      new Request('https://id.org.ai/oauth/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ client_name: 'cli', grant_types: ['urn:ietf:params:oauth:grant-type:device_code'], token_endpoint_auth_method: 'none' }),
      }),
    )
    const cli = ((await reg.json()) as { client_id: string }).client_id
    const res = await provider.handleDeviceAuthorization(
      new Request('https://id.org.ai/oauth/device', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: cli, scope: 'openid sb:do' }).toString(),
      }),
    )
    expect(res.status).toBe(400)
    expect(((await res.json()) as any).error).toBe('invalid_scope')
    // Without sb scopes the device flow is unchanged.
    const ok = await provider.handleDeviceAuthorization(
      new Request('https://id.org.ai/oauth/device', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: cli, scope: 'openid' }).toString(),
      }),
    )
    expect(ok.status).toBe(200)
  })
})

describe('the consent POST is validated again', () => {
  let provider: OAuthProvider
  let clientId: string
  let fields: Record<string, string>
  beforeEach(async () => {
    provider = makeProvider()
    clientId = await register(provider)
    const page = await provider.handleAuthorize(new Request(await authorizeUrl(clientId, { scope: 'openid sb:read', resource: 'https://api.sb/mcp' })), PERSON)
    fields = hiddenFields(await page.text())
  })

  it('a redirect_uri the client never registered: 400, no code', async () => {
    const res = await provider.handleAuthorizeConsent(consentBody({ ...fields, redirect_uri: 'https://evil.example/cb', approved: 'true' }), PERSON)
    expect(res.status).toBe(400)
    // Denial too: an error is never sent to an unregistered redirect_uri.
    const deny = await provider.handleAuthorizeConsent(consentBody({ ...fields, redirect_uri: 'https://evil.example/cb', approved: 'false' }), PERSON)
    expect(deny.status).toBe(400)
  })

  it('a public client with the code_challenge dropped: error, no code', async () => {
    const { code_challenge, code_challenge_method, ...rest } = fields
    const res = await provider.handleAuthorizeConsent(consentBody({ ...rest, approved: 'true' }), PERSON)
    const back = new URL(res.headers.get('location')!)
    expect(back.searchParams.get('code')).toBeNull()
    expect(back.searchParams.get('error')).toBe('invalid_request')
  })

  it('an sb scope with the resource swapped for another audience: invalid_target', async () => {
    const res = await provider.handleAuthorizeConsent(consentBody({ ...fields, resource: 'https://evil.example/mcp', approved: 'true' }), PERSON)
    expect(new URL(res.headers.get('location')!).searchParams.get('error')).toBe('invalid_target')
  })

  it('a scope added in the form that the client may not have: invalid_scope', async () => {
    const res = await provider.handleAuthorizeConsent(consentBody({ ...fields, scope: 'openid sb:read admin', approved: 'true' }), PERSON)
    expect(new URL(res.headers.get('location')!).searchParams.get('error')).toBe('invalid_scope')
  })

  it('the form as rendered still works', async () => {
    const res = await provider.handleAuthorizeConsent(consentBody({ ...fields, approved: 'true' }), PERSON)
    expect(new URL(res.headers.get('location')!).searchParams.get('code')).toMatch(/^ac_/)
  })
})

describe('the consent page', () => {
  it('escapes a registered scope name (no stored XSS on id.org.ai)', async () => {
    const provider = makeProvider()
    const evil = '<img/src=x/onerror=alert(1)>'
    const clientId = await register(provider, { scope: `openid ${evil}` })
    const res = await provider.handleAuthorize(new Request(await authorizeUrl(clientId, { scope: `openid ${evil}` })), PERSON)
    const html = await res.text()
    expect(html).not.toContain(evil)
    expect(html).toContain('&lt;img/src=x/onerror=alert(1)&gt;')
  })

  it('cannot be framed', async () => {
    const provider = makeProvider()
    const clientId = await register(provider)
    const res = await provider.handleAuthorize(new Request(await authorizeUrl(clientId)), PERSON)
    expect(res.status).toBe(200)
    expect(res.headers.get('x-frame-options')).toBe('DENY')
    expect(res.headers.get('content-security-policy')).toContain("frame-ancestors 'none'")
  })
})

describe('an authorization code redeems once', () => {
  it('with take (the IdentityDO path), of parallel redemptions exactly one succeeds', async () => {
    const provider = makeProvider(createStorage(true))
    const clientId = await register(provider)
    const back = await authorizeThroughConsent(provider, clientId)
    const code = back.searchParams.get('code')!
    const results = await Promise.all(Array.from({ length: 5 }, () => redeem(provider, clientId, code)))
    expect(results.filter((r) => r.status === 200)).toHaveLength(1)
    expect(results.filter((r) => r.status === 400).every((r) => r.body.error === 'invalid_grant')).toBe(true)
  })

  it('a failed redemption spends the code', async () => {
    const provider = makeProvider(createStorage(true))
    const clientId = await register(provider)
    const back = await authorizeThroughConsent(provider, clientId)
    const code = back.searchParams.get('code')!
    expect((await redeem(provider, clientId, code, { code_verifier: 'wrong-verifier-wrong-verifier-wrong-verifier' })).status).toBe(400)
    expect((await redeem(provider, clientId, code)).body.error).toBe('invalid_grant')
  })
})
