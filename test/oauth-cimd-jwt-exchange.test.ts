/**
 * Part 2 of id.org.ai as the authorization server for api.sb and remote MCP
 * clients (provider level; test/mcp-authorization-server-2.test.ts drives the
 * real worker):
 *
 *   4. Client ID Metadata Documents — an https client_id is fetched,
 *      validated, cached; DCR unchanged.
 *   5. RFC 9068 JWT access tokens for api.sb — typ at+jwt, crit aud_bound,
 *      iss/sub/aud/client_id/scope/iat/exp/jti, 15 minutes; introspectable;
 *      rejected by every identity-JWT verifier that has not opted in.
 *   6. RFC 8693 token exchange — sub stays the Person, act names the agent
 *      (nested), narrowing only.
 *   7. Revocation — revoking a client's grant kills its refresh tokens and
 *      makes its access tokens inactive.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import * as jose from 'jose'
import { OAuthProvider, type OAuthConfig, type ClientMetadataFetcher } from '../src/sdk/oauth/provider'
import { SigningKeyManager, verifyJWTWithKeyManager } from '../src/sdk/jwt/signing'
import { verifyJWT } from '../src/sdk/oauth/jwt-verify'
import { cimdClientIdProblem, cimdRedirectMatches, cimdTtlSeconds, parseClientMetadataDocument } from '../src/sdk/oauth/cimd'
import { isAccessTokenJwt, unrecognizedCrit, ACCESS_TOKEN_JWT_TTL } from '../src/sdk/oauth/access-token-jwt'

// ── harness ───────────────────────────────────────────────────────────────────

function createStorage() {
  const store = new Map<string, unknown>()
  const claimed = new Set<string>()
  return {
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
    async take<T = unknown>(key: string): Promise<T | undefined> {
      const v = store.get(key) as T | undefined
      store.delete(key)
      return v
    },
    async claimOnce(key: string): Promise<boolean> {
      if (claimed.has(key)) return false
      claimed.add(key)
      return true
    },
  }
}

function createKeyManager() {
  const kv = new Map<string, unknown>()
  return new SigningKeyManager(async (op) => {
    if (op.op === 'get') return { value: kv.get(op.key!) }
    if (op.op === 'put') {
      kv.set(op.key!, op.value)
      return { ok: true }
    }
    return {}
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

const PERSON = 'human:user_person_2'
const VERIFIER = 'part-two-verifier-0123456789-abcdefghijklmnopqrstuv'
const CLAUDE_CODE = 'https://claude.ai/oauth/claude-code-client-metadata'
const CHATGPT = 'https://chatgpt.com/oauth/client.json'

const DOCS: Record<string, unknown> = {
  [CLAUDE_CODE]: {
    client_id: CLAUDE_CODE,
    client_name: 'Claude Code',
    client_uri: 'https://claude.ai',
    redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
  },
  [CHATGPT]: {
    client_id: CHATGPT,
    client_uri: 'https://chatgpt.com/',
    redirect_uris: ['https://chatgpt.com/connector_platform_oauth_redirect'],
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    client_name: 'ChatGPT',
    jwks_uri: 'https://chatgpt.com/oauth/jwks.json',
  },
}

function makeFetcher(docs: Record<string, unknown> = DOCS) {
  const calls: string[] = []
  const fetcher: ClientMetadataFetcher = async (url) => {
    calls.push(url)
    if (!(url in docs)) return { ok: false, error: 'HTTP 404' }
    return { ok: true, doc: structuredClone(docs[url]), cacheControl: 'max-age=600' }
  }
  return { fetcher, calls }
}

async function s256(v: string): Promise<string> {
  const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v))
  return btoa(String.fromCharCode(...new Uint8Array(h))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function makeProvider(opts: { fetcher?: ClientMetadataFetcher; storage?: ReturnType<typeof createStorage>; keys?: SigningKeyManager } = {}) {
  return new OAuthProvider({
    storage: opts.storage ?? createStorage(),
    config: CONFIG,
    getIdentity: async (id) => ({ id, name: 'Ada', email: 'ada@example.com', emailVerified: true, level: 2 }),
    signingKeyManager: opts.keys ?? createKeyManager(),
    ...(opts.fetcher && { fetchClientMetadata: opts.fetcher }),
  })
}

async function authorizeUrl(clientId: string, redirectUri: string, params: Record<string, string> = {}) {
  const u = new URL('https://id.org.ai/oauth/authorize')
  const all: Record<string, string> = {
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid profile email',
    state: 'st',
    code_challenge: await s256(VERIFIER),
    code_challenge_method: 'S256',
    ...params,
  }
  for (const [k, v] of Object.entries(all)) u.searchParams.set(k, v)
  return u.toString()
}

function hiddenFields(html: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const m of html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)) {
    out[m[1]!] = m[2]!.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
  }
  return out
}

function form(url: string, fields: Record<string, string>, headers: Record<string, string> = {}) {
  return new Request(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams(fields).toString() })
}

/** authorize → consent (approve) → code → tokens */
async function tokensFor(provider: OAuthProvider, clientId: string, redirectUri: string, params: Record<string, string> = {}) {
  const page = await provider.handleAuthorize(new Request(await authorizeUrl(clientId, redirectUri, params)), PERSON)
  let back: URL
  if (page.status === 302) back = new URL(page.headers.get('location')!)
  else {
    expect(page.status).toBe(200)
    const res = await provider.handleAuthorizeConsent(form('https://id.org.ai/oauth/authorize', { ...hiddenFields(await page.text()), approved: 'true' }), PERSON, undefined, { interactive: true })
    back = new URL(res.headers.get('location')!)
  }
  const code = back.searchParams.get('code')
  expect(code).toBeTruthy()
  const res = await provider.handleToken(
    form('https://id.org.ai/oauth/token', { grant_type: 'authorization_code', code: code!, redirect_uri: redirectUri, client_id: clientId, code_verifier: VERIFIER }),
  )
  expect(res.status).toBe(200)
  return (await res.json()) as Record<string, any>
}

async function introspect(provider: OAuthProvider, token: string) {
  return (await (await provider.handleIntrospect(form('https://id.org.ai/oauth/introspect', { token }))).json()) as Record<string, any>
}

async function register(provider: OAuthProvider, meta: Record<string, unknown> = {}) {
  const res = await provider.handleRegister(
    new Request('https://id.org.ai/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: 'DCR client', redirect_uris: ['https://dcr.example/cb'], token_endpoint_auth_method: 'none', ...meta }),
    }),
  )
  return ((await res.json()) as { client_id: string }).client_id
}

function decode(jwt: string) {
  const [h, p] = jwt.split('.')
  const dec = (s: string) => JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)))
  return { header: dec(h!), payload: dec(p!) }
}

// ── 4. CIMD ───────────────────────────────────────────────────────────────────

describe('4. Client ID Metadata Documents', () => {
  it('validates client_id URLs', () => {
    expect(cimdClientIdProblem(CLAUDE_CODE)).toBeNull()
    expect(cimdClientIdProblem(CHATGPT)).toBeNull()
    for (const bad of [
      'http://claude.ai/x',
      'https://claude.ai',
      'https://claude.ai/',
      'https://claude.ai/x?y=1',
      'https://claude.ai/x#f',
      'https://user:pw@claude.ai/x',
      'https://CLAUDE.ai/x',
      'https://claude.ai/a/../x',
      'https://claude.ai/a/%2e%2e/x',
      'https://claude.ai:443/x',
    ])
      expect(cimdClientIdProblem(bad), bad).not.toBeNull()
  })

  it('validates documents', () => {
    expect(parseClientMetadataDocument(CLAUDE_CODE, DOCS[CLAUDE_CODE])).toMatchObject({ ok: true, client: { id: CLAUDE_CODE, trusted: false, tokenEndpointAuthMethod: 'none', scopes: [] } })
    // ChatGPT says private_key_jwt but lists none: a public client here (PKCE).
    expect(parseClientMetadataDocument(CHATGPT, DOCS[CHATGPT])).toMatchObject({ ok: true })
    const base = DOCS[CLAUDE_CODE] as Record<string, unknown>
    const bad: Array<[string, unknown]> = [
      ['client_id mismatch', { ...base, client_id: 'https://evil.example/x' }],
      ['secret', { ...base, client_secret: 's' }],
      ['secret basic', { ...base, token_endpoint_auth_method: 'client_secret_basic' }],
      ['pkjwt only', { ...base, token_endpoint_auth_method: 'private_key_jwt' }],
      ['no redirects', { ...base, redirect_uris: [] }],
      ['http redirect', { ...base, redirect_uris: ['http://evil.example/cb'] }],
      ['custom scheme', { ...base, redirect_uris: ['cursor://cb'] }],
      ['no auth code', { ...base, grant_types: ['client_credentials'] }],
      ['array', [base]],
    ]
    for (const [why, doc] of bad) expect(parseClientMetadataDocument(CLAUDE_CODE, doc).ok, why).toBe(false)
    // Only browser grants survive.
    const cc = parseClientMetadataDocument(CLAUDE_CODE, { ...base, grant_types: ['authorization_code', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code'] })
    expect(cc.ok && cc.client.grantTypes).toEqual(['authorization_code'])
  })

  it('matches loopback redirects on any port, everything else exactly', () => {
    const reg = ['http://localhost/callback', 'http://127.0.0.1/callback', 'https://app.example/cb']
    expect(cimdRedirectMatches(reg, 'http://localhost:53682/callback')).toBe(true)
    expect(cimdRedirectMatches(reg, 'http://127.0.0.1:8080/callback')).toBe(true)
    expect(cimdRedirectMatches(reg, 'http://localhost/callback')).toBe(true)
    expect(cimdRedirectMatches(reg, 'https://app.example/cb')).toBe(true)
    expect(cimdRedirectMatches(reg, 'http://localhost:1/other')).toBe(false)
    expect(cimdRedirectMatches(reg, 'http://localhost:1/callback?x=1')).toBe(false)
    expect(cimdRedirectMatches(reg, 'http://127.0.0.1.evil.example:1/callback')).toBe(false)
    expect(cimdRedirectMatches(reg, 'https://app.example:444/cb')).toBe(false)
    expect(cimdRedirectMatches(reg, 'http://user@localhost:1/callback')).toBe(false)
    expect(cimdRedirectMatches(['http://localhost/callback'], 'http://127.0.0.1:5/callback')).toBe(false)
  })

  it('clamps cache lifetimes', () => {
    expect(cimdTtlSeconds(null)).toBe(3600)
    expect(cimdTtlSeconds('max-age=5')).toBe(300)
    expect(cimdTtlSeconds('public, max-age=999999')).toBe(86400)
    expect(cimdTtlSeconds('no-store')).toBe(300)
  })

  it('Claude Code (loopback, any port) signs in: consent names claude.ai, code, token, refresh', async () => {
    const { fetcher, calls } = makeFetcher()
    const provider = makeProvider({ fetcher })
    const redirect = 'http://localhost:61234/callback'
    const page = await provider.handleAuthorize(new Request(await authorizeUrl(CLAUDE_CODE, redirect, { scope: 'sb:read', resource: 'https://api.sb/mcp' })), PERSON)
    expect(page.status).toBe(200)
    const html = await page.text()
    expect(html).toContain('<div class="app-name">claude.ai</div>')
    expect(html).toContain('Calls itself “Claude Code”')
    const res = await provider.handleAuthorizeConsent(form('https://id.org.ai/oauth/authorize', { ...hiddenFields(html), approved: 'true' }), PERSON, undefined, { interactive: true })
    const back = new URL(res.headers.get('location')!)
    expect(`${back.origin}${back.pathname}`).toBe('http://localhost:61234/callback')
    expect(back.searchParams.get('iss')).toBe('https://id.org.ai')
    const tok = await provider.handleToken(
      form('https://id.org.ai/oauth/token', { grant_type: 'authorization_code', code: back.searchParams.get('code')!, redirect_uri: redirect, client_id: CLAUDE_CODE, code_verifier: VERIFIER }),
    )
    expect(tok.status).toBe(200)
    const t = (await tok.json()) as any
    expect((await introspect(provider, t.access_token)).client_id).toBe(CLAUDE_CODE)
    const ref = await provider.handleToken(form('https://id.org.ai/oauth/token', { grant_type: 'refresh_token', refresh_token: t.refresh_token, client_id: CLAUDE_CODE }))
    expect(ref.status).toBe(200)
    // One fetch served authorize, consent and the token calls (cached).
    expect(calls).toEqual([CLAUDE_CODE])
  })

  it('ChatGPT (private_key_jwt + none) is a public client here: PKCE works, no secret', async () => {
    const { fetcher } = makeFetcher()
    const provider = makeProvider({ fetcher })
    const t = await tokensFor(provider, CHATGPT, 'https://chatgpt.com/connector_platform_oauth_redirect')
    expect((await introspect(provider, t.access_token)).client_id).toBe(CHATGPT)
  })

  it('a redirect_uri the document does not list is refused with 400 (no redirect)', async () => {
    const { fetcher } = makeFetcher()
    const provider = makeProvider({ fetcher })
    for (const r of ['https://evil.example/cb', 'http://localhost:1/other', 'http://evil.example/callback']) {
      const res = await provider.handleAuthorize(new Request(await authorizeUrl(CLAUDE_CODE, r)), PERSON)
      expect(res.status).toBe(400)
    }
  })

  it('a document that does not name itself is refused, and the failure is cached briefly', async () => {
    const url = 'https://evil.example/client.json'
    const { fetcher, calls } = makeFetcher({ [url]: { ...(DOCS[CLAUDE_CODE] as object), client_id: CLAUDE_CODE } })
    const provider = makeProvider({ fetcher })
    for (let i = 0; i < 3; i++) {
      const res = await provider.handleAuthorize(new Request(await authorizeUrl(url, 'http://localhost:1/callback')), PERSON)
      expect(res.status).toBe(400)
      expect(((await res.json()) as any).error).toBe('invalid_client')
    }
    expect(calls).toHaveLength(1)
  })

  it('a bad client_id URL is refused without any fetch', async () => {
    const { fetcher, calls } = makeFetcher()
    const provider = makeProvider({ fetcher })
    for (const id of ['https://claude.ai', 'https://claude.ai/x?y=1', 'https://CLAUDE.ai/oauth/claude-code-client-metadata']) {
      const res = await provider.handleAuthorize(new Request(await authorizeUrl(id, 'http://localhost:1/callback')), PERSON)
      expect(res.status).toBe(400)
    }
    expect(calls).toEqual([])
  })

  it('CIMD clients cannot use the device flow or client_credentials, and those never fetch', async () => {
    const { fetcher, calls } = makeFetcher()
    const provider = makeProvider({ fetcher })
    const dev = await provider.handleDeviceAuthorization(form('https://id.org.ai/oauth/device', { client_id: CLAUDE_CODE }))
    expect(dev.status).toBe(400)
    const cc = await provider.handleToken(form('https://id.org.ai/oauth/token', { grant_type: 'client_credentials', client_id: CLAUDE_CODE, client_secret: 'x' }))
    expect(cc.status).toBe(401)
    const dc = await provider.handleToken(form('https://id.org.ai/oauth/token', { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', client_id: CLAUDE_CODE, device_code: 'dc_x' }))
    expect(dc.status).toBe(400)
    expect(calls).toEqual([])
  })

  it('without a fetcher an https client_id is simply unknown (and metadata does not advertise CIMD)', async () => {
    const provider = new OAuthProvider({ storage: createStorage(), config: CONFIG, getIdentity: async () => null })
    const res = await provider.handleAuthorize(new Request(await authorizeUrl(CLAUDE_CODE, 'http://localhost:1/callback')), PERSON)
    expect(res.status).toBe(400)
    expect(((await provider.getOpenIDConfiguration().json()) as any).client_id_metadata_document_supported).toBeUndefined()
    const { fetcher } = makeFetcher()
    expect(((await makeProvider({ fetcher }).getOpenIDConfiguration().json()) as any).client_id_metadata_document_supported).toBe(true)
  })

  it('DCR still works next to CIMD', async () => {
    const { fetcher, calls } = makeFetcher()
    const provider = makeProvider({ fetcher })
    const id = await register(provider)
    expect(id).toMatch(/^cid_/)
    const t = await tokensFor(provider, id, 'https://dcr.example/cb')
    expect(t.access_token).toMatch(/^at_/)
    expect(calls).toEqual([])
  })
})

// ── 5. JWT access tokens ──────────────────────────────────────────────────────

describe('5. RFC 9068 JWT access tokens for api.sb', () => {
  let keys: SigningKeyManager
  let provider: OAuthProvider
  let clientId: string
  beforeEach(async () => {
    keys = createKeyManager()
    provider = makeProvider({ keys })
    clientId = await register(provider)
  })

  it('an api.sb token is a JWT with the RFC 9068 header and claims, 15 minutes', async () => {
    const t = await tokensFor(provider, clientId, 'https://dcr.example/cb', { scope: 'openid sb:read', resource: 'https://api.sb/mcp' })
    const { header, payload } = decode(t.access_token)
    expect(header).toMatchObject({ alg: 'RS256', typ: 'at+jwt', crit: ['aud_bound'], aud_bound: true })
    expect(typeof header.kid).toBe('string')
    expect(payload).toMatchObject({ iss: 'https://id.org.ai', sub: PERSON, aud: 'https://api.sb/mcp', client_id: clientId, scope: 'openid sb:read' })
    expect(typeof payload.jti).toBe('string')
    expect(payload.exp - payload.iat).toBe(ACCESS_TOKEN_JWT_TTL)
    expect(t.expires_in).toBe(ACCESS_TOKEN_JWT_TTL)
    expect(payload.act).toBeUndefined()
    // The id_token's at_hash is over the JWT that was issued.
    const h = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t.access_token))).slice(0, 16)
    expect(decode(t.id_token).payload.at_hash).toBe(btoa(String.fromCharCode(...h)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, ''))
  })

  it('verifies against the JWKS with jose, given typ, crit, audience and issuer', async () => {
    const t = await tokensFor(provider, clientId, 'https://dcr.example/cb', { scope: 'sb:read', resource: 'https://api.sb/mcp' })
    const jwks = jose.createLocalJWKSet((await keys.getJWKS()) as jose.JSONWebKeySet)
    const { payload } = await jose.jwtVerify(t.access_token, jwks, { issuer: 'https://id.org.ai', audience: 'https://api.sb/mcp', typ: 'at+jwt', crit: { aud_bound: true } })
    expect(payload.sub).toBe(PERSON)
    await expect(jose.jwtVerify(t.access_token, jwks, { issuer: 'https://id.org.ai', audience: 'https://api.sb', typ: 'at+jwt', crit: { aud_bound: true } })).rejects.toThrow()
  })

  it('is refused by verifiers that did not opt in: jose without crit, verifyJWT, verifyJWTWithKeyManager', async () => {
    const t = await tokensFor(provider, clientId, 'https://dcr.example/cb', { scope: 'sb:read', resource: 'https://api.sb/mcp' })
    const jwksDoc = (await keys.getJWKS()) as jose.JSONWebKeySet
    const jwks = jose.createLocalJWKSet(jwksDoc)
    // The `auth` worker / AuthService / cookie paths call jose.jwtVerify like this:
    await expect(jose.jwtVerify(t.access_token, jwks)).rejects.toThrow(/crit|Extension/i)
    await expect(jose.jwtVerify(t.access_token, jwks, { issuer: 'https://id.org.ai' })).rejects.toThrow()
    // id.org.ai's hand-rolled verifiers (AuthIdentity, AAP, key manager):
    const publicKey = await crypto.subtle.importKey('jwk', jwksDoc.keys[0] as JsonWebKey, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'])
    expect((await verifyJWT(t.access_token, { publicKey, issuer: 'https://id.org.ai' })).valid).toBe(false)
    expect((await verifyJWT(t.access_token, { publicKey, issuer: 'https://id.org.ai', crit: ['aud_bound'] })).valid).toBe(true)
    expect(await verifyJWTWithKeyManager(t.access_token, keys, { issuer: 'https://id.org.ai' })).toBeNull()
    // The id_token still verifies everywhere (unchanged).
    expect((await verifyJWT(t.id_token ?? '', { publicKey, issuer: 'https://id.org.ai' })).valid || !t.id_token).toBe(true)
    expect(isAccessTokenJwt(t.access_token)).toBe(true)
  })

  it('introspects as active with aud and jti; tokens for other resources stay opaque', async () => {
    const t = await tokensFor(provider, clientId, 'https://dcr.example/cb', { scope: 'sb:read', resource: 'https://api.sb' })
    const i = await introspect(provider, t.access_token)
    expect(i).toMatchObject({ active: true, sub: PERSON, aud: 'https://api.sb', client_id: clientId, scope: 'sb:read', iss: 'https://id.org.ai' })
    const other = await tokensFor(provider, clientId, 'https://dcr.example/cb', { resource: 'https://id.org.ai/mcp' })
    expect(other.access_token).toMatch(/^at_/)
    const plain = await tokensFor(provider, clientId, 'https://dcr.example/cb')
    expect(plain.access_token).toMatch(/^at_/)
  })

  it('a forged or tampered JWT does not introspect', async () => {
    const t = await tokensFor(provider, clientId, 'https://dcr.example/cb', { scope: 'sb:read', resource: 'https://api.sb' })
    const [h, p, s] = t.access_token.split('.')
    const payload = decode(t.access_token).payload
    const forgedPayload = btoa(JSON.stringify({ ...payload, sub: 'human:someone_else' })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
    expect((await introspect(provider, `${h}.${forgedPayload}.${s}`)).active).toBe(false)
    const other = createKeyManager() // a different key, same kid scheme
    const key = await other.getCurrentKey()
    const { signAccessTokenJwt } = await import('../src/sdk/oauth/access-token-jwt')
    const foreign = await signAccessTokenJwt(key, { ...payload, jti: crypto.randomUUID() })
    expect((await introspect(provider, foreign)).active).toBe(false)
  })

  it('unrecognizedCrit follows RFC 7515', () => {
    expect(unrecognizedCrit({ alg: 'RS256' })).toEqual([])
    expect(unrecognizedCrit({ crit: ['aud_bound'], aud_bound: true })).toEqual(['aud_bound'])
    expect(unrecognizedCrit({ crit: ['aud_bound'], aud_bound: true }, ['aud_bound'])).toEqual([])
    expect(unrecognizedCrit({ crit: ['aud_bound'] }, ['aud_bound'])).toEqual(['aud_bound']) // named but absent
    expect(unrecognizedCrit({ crit: [] })).not.toEqual([])
    expect(unrecognizedCrit({ crit: 'aud_bound' })).not.toEqual([])
  })
})

// ── 6. Token exchange ─────────────────────────────────────────────────────────

describe('6. RFC 8693 token exchange (AuthService binding)', () => {
  const ACCESS = 'urn:ietf:params:oauth:token-type:access_token'
  let provider: OAuthProvider
  let clientId: string
  let subject: Record<string, any>
  beforeEach(async () => {
    provider = makeProvider()
    clientId = await register(provider)
    subject = await tokensFor(provider, clientId, 'https://dcr.example/cb', { scope: 'sb:read sb:do', resource: 'https://api.sb/mcp' })
  })

  it('sub stays the Person, act names the agent, client_id stays the client; scope narrows', async () => {
    const r = await provider.exchangeToken({ subject_token: subject.access_token, subject_token_type: ACCESS, actor: { sub: 'workers/sextant' }, scope: 'sb:read' })
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r).toMatchObject({ issued_token_type: ACCESS, token_type: 'Bearer', scope: 'sb:read' })
    expect(r.expires_in).toBeLessThanOrEqual(ACCESS_TOKEN_JWT_TTL)
    const { header, payload } = decode(r.access_token)
    expect(header.typ).toBe('at+jwt')
    expect(payload).toMatchObject({ sub: PERSON, client_id: clientId, aud: 'https://api.sb/mcp', scope: 'sb:read', act: { sub: 'workers/sextant' } })
    expect(payload.exp).toBeLessThanOrEqual(decode(subject.access_token).payload.exp)
    expect((await introspect(provider, r.access_token)).act).toEqual({ sub: 'workers/sextant' })
    expect((r as any).refresh_token).toBeUndefined()
  })

  it('chains nest act (current actor outermost)', async () => {
    const one = await provider.exchangeToken({ subject_token: subject.access_token, subject_token_type: ACCESS, actor: { sub: 'workers/sextant' } })
    if (!one.ok) throw new Error(one.error_description)
    const two = await provider.exchangeToken({ subject_token: one.access_token, subject_token_type: ACCESS, actor: { sub: 'claude-runner/abc' } })
    if (!two.ok) throw new Error(two.error_description)
    expect(decode(two.access_token).payload.act).toEqual({ sub: 'claude-runner/abc', act: { sub: 'workers/sextant' } })
    // bounded depth
    let t = two.access_token
    let last: Awaited<ReturnType<OAuthProvider['exchangeToken']>> | undefined
    for (let i = 0; i < 4; i++) {
      last = await provider.exchangeToken({ subject_token: t, subject_token_type: ACCESS, actor: { sub: `a${i}` } })
      if (!last.ok) break
      t = last.access_token
    }
    expect(last && !last.ok && last.error).toBe('invalid_request')
  })

  it('can only narrow: more scope, another audience or another kind of subject are refused', async () => {
    const readOnly = await provider.exchangeToken({ subject_token: subject.access_token, subject_token_type: ACCESS, actor: { sub: 'w' }, scope: 'sb:read' })
    if (!readOnly.ok) throw new Error('setup')
    const cases: Array<[string, Parameters<OAuthProvider['exchangeToken']>[0], string]> = [
      ['scope up', { subject_token: readOnly.access_token, subject_token_type: ACCESS, actor: { sub: 'w' }, scope: 'sb:read sb:do' }, 'invalid_scope'],
      ['new scope', { subject_token: subject.access_token, subject_token_type: ACCESS, actor: { sub: 'w' }, scope: 'openid' }, 'invalid_scope'],
      ['other aud', { subject_token: subject.access_token, subject_token_type: ACCESS, actor: { sub: 'w' }, resource: 'https://id.org.ai/mcp' }, 'invalid_target'],
      ['id-jag', { subject_token: subject.access_token, subject_token_type: 'urn:ietf:params:oauth:token-type:id-jag', actor: { sub: 'w' } }, 'invalid_request'],
      ['id_token', { subject_token: subject.access_token, subject_token_type: 'urn:ietf:params:oauth:token-type:id_token', actor: { sub: 'w' } }, 'invalid_request'],
      ['no actor', { subject_token: subject.access_token, subject_token_type: ACCESS }, 'invalid_request'],
      ['blank actor', { subject_token: subject.access_token, subject_token_type: ACCESS, actor: { sub: 'a b' } }, 'invalid_request'],
      ['refresh token', { subject_token: subject.refresh_token, subject_token_type: ACCESS, actor: { sub: 'w' } }, 'invalid_grant'],
      ['garbage', { subject_token: 'x.y.z', subject_token_type: ACCESS, actor: { sub: 'w' } }, 'invalid_grant'],
    ]
    for (const [why, input, error] of cases) {
      const r = await provider.exchangeToken(input)
      expect(r.ok, why).toBe(false)
      if (!r.ok) expect(r.error, why).toBe(error)
    }
    // An id_token (signed by the same key) is not an access token.
    if (subject.id_token) {
      const r = await provider.exchangeToken({ subject_token: subject.id_token, subject_token_type: ACCESS, actor: { sub: 'w' } })
      expect(r.ok).toBe(false)
    }
  })

  it('a token that is not for api.sb cannot be exchanged', async () => {
    const other = await tokensFor(provider, clientId, 'https://dcr.example/cb', { resource: 'https://id.org.ai/mcp' })
    const r = await provider.exchangeToken({ subject_token: other.access_token, subject_token_type: ACCESS, actor: { sub: 'w' } })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error).toBe('invalid_target')
  })

  it("an exchanged token dies with the Person's grant", async () => {
    const r = await provider.exchangeToken({ subject_token: subject.access_token, subject_token_type: ACCESS, actor: { sub: 'w' } })
    if (!r.ok) throw new Error('setup')
    expect((await introspect(provider, r.access_token)).active).toBe(true)
    await provider.revokeGrant(PERSON, clientId)
    expect((await introspect(provider, r.access_token)).active).toBe(false)
    expect((await introspect(provider, subject.access_token)).active).toBe(false)
    const again = await provider.exchangeToken({ subject_token: subject.access_token, subject_token_type: ACCESS, actor: { sub: 'w' } })
    expect(again.ok).toBe(false)
  })
})

// ── 7. Revocation ─────────────────────────────────────────────────────────────

describe('7. revoking a client grant', () => {
  let provider: OAuthProvider
  let clientId: string
  beforeEach(async () => {
    provider = makeProvider()
    clientId = await register(provider)
  })

  const refresh = (p: OAuthProvider, id: string, rt: string) =>
    p.handleToken(form('https://id.org.ai/oauth/token', { grant_type: 'refresh_token', refresh_token: rt, client_id: id }))

  it('kills refresh tokens, opaque and JWT access tokens, and the consent', async () => {
    const opaque = await tokensFor(provider, clientId, 'https://dcr.example/cb', { scope: 'openid offline_access' })
    const jwt = await tokensFor(provider, clientId, 'https://dcr.example/cb', { scope: 'sb:read', resource: 'https://api.sb/mcp' })
    expect((await provider.listGrants(PERSON)).map((g) => g.client_id)).toEqual([clientId])

    const result = await provider.revokeGrant(PERSON, clientId)
    expect(result.revoked_families).toBe(2)

    for (const t of [opaque, jwt]) {
      expect((await introspect(provider, t.access_token)).active).toBe(false)
      expect((await introspect(provider, t.refresh_token)).active).toBe(false)
      const r = await refresh(provider, clientId, t.refresh_token)
      expect(r.status).toBe(400)
    }
    expect(await provider.listGrants(PERSON)).toEqual([])
    // The next authorization asks the Person again.
    const page = await provider.handleAuthorize(new Request(await authorizeUrl(clientId, 'https://dcr.example/cb')), PERSON)
    expect(page.status).toBe(200)
  })

  it("does not touch the Person's other clients or other Persons", async () => {
    const other = await register(provider, { client_name: 'Other' })
    const keep = await tokensFor(provider, other, 'https://dcr.example/cb', { scope: 'openid offline_access' })
    await tokensFor(provider, clientId, 'https://dcr.example/cb', { scope: 'openid offline_access' })
    await provider.revokeGrant(PERSON, clientId)
    expect((await introspect(provider, keep.access_token)).active).toBe(true)
    expect((await refresh(provider, other, keep.refresh_token)).status).toBe(200)
    await provider.revokeGrant('human:someone_else', other)
    expect((await provider.listGrants(PERSON)).map((g) => g.client_id)).toEqual([other])
  })

  it('RFC 7009: revoking a refresh token also invalidates the access tokens issued from its grant', async () => {
    const t = await tokensFor(provider, clientId, 'https://dcr.example/cb', { scope: 'sb:read', resource: 'https://api.sb/mcp' })
    await provider.handleRevoke(form('https://id.org.ai/oauth/revoke', { token: t.refresh_token }))
    expect((await introspect(provider, t.access_token)).active).toBe(false)
  })

  it('revoking one JWT access token makes it inactive at introspection', async () => {
    const t = await tokensFor(provider, clientId, 'https://dcr.example/cb', { scope: 'sb:read', resource: 'https://api.sb/mcp' })
    await provider.handleRevoke(form('https://id.org.ai/oauth/revoke', { token: t.access_token }))
    expect((await introspect(provider, t.access_token)).active).toBe(false)
    expect((await refresh(provider, clientId, t.refresh_token)).status).toBe(200)
  })
})

describe('PR #31 review round 1 regressions', () => {
  const ACCESS = 'urn:ietf:params:oauth:token-type:access_token'
  const refreshReq = (id: string, rt: string) => form('https://id.org.ai/oauth/token', { grant_type: 'refresh_token', refresh_token: rt, client_id: id })

  it('B1: a code issued before the grant was revoked cannot be redeemed after', async () => {
    const provider = makeProvider()
    const clientId = await register(provider)
    const page = await provider.handleAuthorize(new Request(await authorizeUrl(clientId, 'https://dcr.example/cb', { scope: 'openid sb:read sb:do', resource: 'https://api.sb/mcp' })), PERSON)
    const res = await provider.handleAuthorizeConsent(form('https://id.org.ai/oauth/authorize', { ...hiddenFields(await page.text()), approved: 'true' }), PERSON, undefined, { interactive: true })
    const code = new URL(res.headers.get('location')!).searchParams.get('code')!
    await provider.revokeGrant(PERSON, clientId)
    const tok = await provider.handleToken(form('https://id.org.ai/oauth/token', { grant_type: 'authorization_code', code, redirect_uri: 'https://dcr.example/cb', client_id: clientId, code_verifier: VERIFIER }))
    expect(tok.status).toBe(400)
    expect(((await tok.json()) as any).error).toBe('invalid_grant')
  })

  it('B1: a refresh token written by a rotation that raced the revocation is dead, and so is its access token', async () => {
    const storage = createStorage()
    const provider = makeProvider({ storage })
    const clientId = await register(provider)
    const t = await tokensFor(provider, clientId, 'https://dcr.example/cb', { scope: 'sb:read', resource: 'https://api.sb/mcp' })
    // Simulate the race: the revocation lists the index BEFORE the rotation writes
    // its new refresh token (hide the index from revokeGrant's listing).
    const realList = storage.list.bind(storage)
    let hide = true
    storage.list = (async (opts?: { prefix?: string }) => (hide && opts?.prefix?.startsWith('grant:') ? new Map() : realList(opts))) as typeof storage.list
    await provider.revokeGrant(PERSON, clientId)
    hide = false
    // …then a rotation that had already passed its checks writes a new pair
    // (forge it the way the racing rotation would: same family, same grantedAt).
    const rt = (await storage.get<any>(`refresh:${t.refresh_token}`))!
    const newRt = 'rt_raced_' + crypto.randomUUID().replace(/-/g, '')
    await storage.put(`refresh:${newRt}`, { ...rt, id: newRt, revoked: false, createdAt: Date.now() + 5 })
    const r = await provider.handleToken(refreshReq(clientId, newRt))
    expect(r.status).toBe(400)
    expect((await introspect(provider, newRt)).active).toBe(false)
    expect((await introspect(provider, t.access_token)).active).toBe(false)
  })

  it('B1: a legacy opaque token (no family, no grantedAt) dies with revokeGrant', async () => {
    const storage = createStorage()
    const provider = makeProvider({ storage })
    const clientId = await register(provider)
    await storage.put('access:at_legacy', { id: 'at_legacy', clientId, identityId: PERSON, scopes: ['sb:read'], resource: 'https://api.sb', expiresAt: Date.now() + 3600_000, createdAt: Date.now() - 1000 })
    expect((await introspect(provider, 'at_legacy')).active).toBe(true)
    await provider.revokeGrant(PERSON, clientId)
    expect((await introspect(provider, 'at_legacy')).active).toBe(false)
    const ex = await provider.exchangeToken({ subject_token: 'at_legacy', subject_token_type: ACCESS, actor: { sub: 'w' } })
    expect(ex.ok).toBe(false)
  })

  it('B1: after revocation the Person can grant again (new consent, new tokens work)', async () => {
    const provider = makeProvider()
    const clientId = await register(provider)
    await tokensFor(provider, clientId, 'https://dcr.example/cb', { scope: 'openid offline_access' })
    await provider.revokeGrant(PERSON, clientId)
    await new Promise((r) => setTimeout(r, 5))
    const again = await tokensFor(provider, clientId, 'https://dcr.example/cb', { scope: 'openid offline_access' })
    expect((await introspect(provider, again.access_token)).active).toBe(true)
    expect((await provider.handleToken(refreshReq(clientId, again.refresh_token))).status).toBe(200)
  })

  it('RFC 7009: a refresh token revoked mid-rotation takes the racing successor with it', async () => {
    const storage = createStorage()
    const provider = makeProvider({ storage })
    const clientId = await register(provider)
    const t = await tokensFor(provider, clientId, 'https://dcr.example/cb', { scope: 'openid offline_access' })
    const rt = (await storage.get<any>(`refresh:${t.refresh_token}`))!
    await provider.handleRevoke(form('https://id.org.ai/oauth/revoke', { token: t.refresh_token }))
    const successor = 'rt_succ_' + crypto.randomUUID().replace(/-/g, '')
    await storage.put(`refresh:${successor}`, { ...rt, id: successor, revoked: false, createdAt: Date.now() + 5 })
    expect((await provider.handleToken(refreshReq(clientId, successor))).status).toBe(400)
  })

  it('S2: a CIMD client with a loopback redirect always gets the consent screen, even with consent on record', async () => {
    const { fetcher } = makeFetcher()
    const provider = makeProvider({ fetcher })
    await tokensFor(provider, CLAUDE_CODE, 'http://localhost:61234/callback', { scope: 'sb:read sb:do', resource: 'https://api.sb/mcp' })
    const again = await provider.handleAuthorize(new Request(await authorizeUrl(CLAUDE_CODE, 'http://localhost:1337/callback', { scope: 'sb:read sb:do', resource: 'https://api.sb/mcp' })), PERSON)
    expect(again.status).toBe(200)
    // An https-redirect CIMD client (bound to its domain) is approved from recorded consent as usual.
    await tokensFor(provider, CHATGPT, 'https://chatgpt.com/connector_platform_oauth_redirect')
    const chat = await provider.handleAuthorize(new Request(await authorizeUrl(CHATGPT, 'https://chatgpt.com/connector_platform_oauth_redirect')), PERSON)
    expect(chat.status).toBe(302)
  })

  it('S1: IP-literal, trailing-dot, dotless and non-443 client_ids are refused before any fetch', async () => {
    for (const bad of [
      'https://[::ffff:a9fe:a9fe]/c.json',
      'https://[::ffff:7f00:1]/c.json',
      'https://[64:ff9b::a9fe:a9fe]/c.json',
      'https://169.254.169.254/latest',
      'https://2130706433/c.json',
      'https://0x7f000001/c.json',
      'https://localhost./c.json',
      'https://metadata.google.internal./c.json',
      'https://localhost/c.json',
      'https://claude.ai:8443/x',
    ])
      expect(cimdClientIdProblem(bad), bad).not.toBeNull()
    const { fetcher, calls } = makeFetcher()
    const provider = makeProvider({ fetcher })
    const res = await provider.handleAuthorize(new Request(await authorizeUrl('https://[::ffff:a9fe:a9fe]/c.json', 'http://localhost:1/callback')), PERSON)
    expect(res.status).toBe(400)
    expect(calls).toEqual([])
  })

  it('S3: an exchange cannot move the audience sideways or wider; root → /mcp narrows', async () => {
    const provider = makeProvider()
    const clientId = await register(provider)
    const mcp = await tokensFor(provider, clientId, 'https://dcr.example/cb', { scope: 'sb:read', resource: 'https://api.sb/mcp' })
    const wider = await provider.exchangeToken({ subject_token: mcp.access_token, subject_token_type: ACCESS, actor: { sub: 'w' }, resource: 'https://api.sb' })
    expect(wider.ok).toBe(false)
    if (!wider.ok) expect(wider.error).toBe('invalid_target')
    const root = await tokensFor(provider, clientId, 'https://dcr.example/cb', { scope: 'sb:read', resource: 'https://api.sb' })
    const narrow = await provider.exchangeToken({ subject_token: root.access_token, subject_token_type: ACCESS, actor: { sub: 'w' }, resource: 'https://api.sb/mcp' })
    expect(narrow.ok).toBe(true)
  })
})
