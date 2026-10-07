/**
 * The workspace a Person picks on the consent screen (`org_id`,
 * docs/product-update/spec/backend.md#b2 and #b6) rides the grant into every
 * token type:
 *
 *   - the consent POST validates it against the Person's memberships
 *     (`validateOrgMembership`; the worker asks WorkOS for an active
 *     membership) and refuses any other with an `invalid_request` redirect;
 *   - the authorization code, the opaque access token, the refresh token and
 *     the grant index record store it as `orgId`, and refresh rotation keeps it;
 *   - the id_token, the RFC 9068 JWT access token (re-checked against its
 *     record), introspection (opaque, JWT and refresh) and userinfo emit it as
 *     `org_id`, and an exchanged token (RFC 8693) keeps the subject's;
 *   - a grant made without one is byte-for-byte what it was: no `org_id`
 *     anywhere it was not before.
 *
 * Provider level first (in-memory storage), then through the real worker
 * (SELF, real IdentityDO + signing keys; WorkOS faked with fetchMock).
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest'
import { SELF, fetchMock } from 'cloudflare:test'
import { OAuthProvider, type OAuthConfig } from '../src/sdk/oauth/provider'
import { SigningKeyManager } from '../src/sdk/jwt/signing'
import { signAccessTokenJwt } from '../src/sdk/oauth/access-token-jwt'
import { encodeStateWithCSRF } from '../src/sdk/csrf'

// ── shared helpers ──────────────────────────────────────────────────────────

const ORG = 'org_01CHOSEN'
const OTHER_ORG = 'org_01NOTMINE'
const ACCESS = 'urn:ietf:params:oauth:token-type:access_token'

function decode(jwt: string): { header: Record<string, any>; payload: Record<string, any> } {
  const dec = (s: string) => JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)))
  const [h, p] = jwt.split('.')
  return { header: dec(h!), payload: dec(p!) }
}

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

async function s256(v: string): Promise<string> {
  return b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v))))
}

function form(url: string, fields: Record<string, string>, headers: Record<string, string> = {}): Request {
  return new Request(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body: new URLSearchParams(fields).toString(),
  })
}

// ── provider level ──────────────────────────────────────────────────────────

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

const PERSON = 'human:user_orgid_person'
const REDIRECT = 'https://org-client.example/cb'
const VERIFIER = 'org-id-test-verifier-0123456789-abcdefghijklmnopqrst'

type Hook = (identityId: string, orgId: string) => Promise<boolean>

/** The Person is a member of ORG and nothing else. */
const memberOfOrg: Hook = async (identityId, orgId) => identityId === PERSON && orgId === ORG

/** `keys: null` and `hook: null` leave the signing key or the membership hook out. */
function makeProvider(opts: { storage?: ReturnType<typeof createStorage>; keys?: SigningKeyManager | null; hook?: Hook | null } = {}) {
  const hook = opts.hook === null ? undefined : (opts.hook ?? memberOfOrg)
  const keys = opts.keys === null ? undefined : (opts.keys ?? createKeyManager())
  return new OAuthProvider({
    storage: opts.storage ?? createStorage(),
    config: CONFIG,
    getIdentity: async (id) => ({ id, name: 'Ada', email: 'ada@example.com', emailVerified: true, level: 2 }),
    ...(keys && { signingKeyManager: keys }),
    ...(hook && { validateOrgMembership: hook }),
  })
}

async function register(provider: OAuthProvider): Promise<string> {
  const res = await provider.handleRegister(
    new Request('https://id.org.ai/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: 'Org client', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' }),
    }),
  )
  expect(res.status).toBe(201)
  return ((await res.json()) as { client_id: string }).client_id
}

/**
 * The consent form's POST, built from the request's own parameters (the
 * provider re-validates every field, so it does not depend on how the consent
 * page renders them).
 */
async function consent(provider: OAuthProvider, clientId: string, extra: Record<string, string> = {}): Promise<URL> {
  const fields: Record<string, string> = {
    client_id: clientId,
    redirect_uri: REDIRECT,
    scope: 'openid profile email offline_access',
    state: 'st-org',
    nonce: 'n-org',
    code_challenge: await s256(VERIFIER),
    code_challenge_method: 'S256',
    approved: 'true',
    ...extra,
  }
  const res = await provider.handleAuthorizeConsent(form('https://id.org.ai/oauth/authorize', fields), PERSON, undefined, { interactive: true })
  expect(res.status).toBe(302)
  return new URL(res.headers.get('location')!)
}

async function redeem(provider: OAuthProvider, clientId: string, code: string) {
  const res = await provider.handleToken(
    form('https://id.org.ai/oauth/token', { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: VERIFIER }),
  )
  expect(res.status).toBe(200)
  return (await res.json()) as Record<string, any>
}

async function refresh(provider: OAuthProvider, clientId: string, refreshToken: string) {
  const res = await provider.handleToken(form('https://id.org.ai/oauth/token', { grant_type: 'refresh_token', refresh_token: refreshToken, client_id: clientId }))
  expect(res.status).toBe(200)
  return (await res.json()) as Record<string, any>
}

async function introspect(provider: OAuthProvider, token: string) {
  return (await (await provider.handleIntrospect(form('https://id.org.ai/oauth/introspect', { token }))).json()) as Record<string, any>
}

async function userinfo(provider: OAuthProvider, token: string) {
  const res = await provider.handleUserinfo(new Request('https://id.org.ai/oauth/userinfo', { headers: { authorization: `Bearer ${token}` } }))
  expect(res.status).toBe(200)
  return (await res.json()) as Record<string, any>
}

function recordsWithPrefix(storage: ReturnType<typeof createStorage>, prefix: string): Array<Record<string, unknown>> {
  return [...storage.store].filter(([k]) => k.startsWith(prefix)).map(([, v]) => v as Record<string, unknown>)
}

describe('provider: org_id only while the person is still in the workspace (phase 5 review S1)', () => {
  it('a refresh after leaving the workspace is refused, without spending the token; back in, it works', async () => {
    let member = true
    const provider = makeProvider({ hook: async (id, org) => member && id === PERSON && org === ORG })
    const clientId = await register(provider)
    const back = await consent(provider, clientId, { org_id: ORG, scope: 'openid offline_access' })
    const t = await redeem(provider, clientId, back.searchParams.get('code')!)
    member = false
    const res = await provider.handleToken(form('https://id.org.ai/oauth/token', { grant_type: 'refresh_token', refresh_token: t.refresh_token, client_id: clientId }))
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: string }).error).toBe('invalid_grant')
    member = true // e.g. a WorkOS blip, or re-added: the same refresh token still works
    expect((await refresh(provider, clientId, t.refresh_token)).access_token).toBeTruthy()
  })

  it('a token exchange after leaving the workspace is refused', async () => {
    let member = true
    const provider = makeProvider({ hook: async (id, org) => member && id === PERSON && org === ORG })
    const clientId = await register(provider)
    const back = await consent(provider, clientId, { org_id: ORG, scope: 'sb:read', resource: 'https://api.sb/mcp' })
    const t = await redeem(provider, clientId, back.searchParams.get('code')!)
    member = false
    const ex = await provider.exchangeToken({ subject_token: t.access_token, subject_token_type: ACCESS, actor: { sub: 'w' } })
    expect(ex.ok).toBe(false)
    expect(!ex.ok && ex.error).toBe('invalid_grant')
  })
})

describe('provider: org_id chosen on consent', () => {
  let storage: ReturnType<typeof createStorage>
  let keys: SigningKeyManager
  let provider: OAuthProvider
  let clientId: string
  beforeEach(async () => {
    storage = createStorage()
    keys = createKeyManager()
    provider = makeProvider({ storage, keys })
    clientId = await register(provider)
  })

  it('is stored on the code, the tokens and the grant, and emitted in the id_token, introspection and userinfo', async () => {
    const back = await consent(provider, clientId, { org_id: ORG })
    const code = back.searchParams.get('code')!
    expect(code).toMatch(/^ac_/)
    expect((storage.store.get(`code:${code}`) as Record<string, unknown>).orgId).toBe(ORG)

    const t = await redeem(provider, clientId, code)
    expect(t.access_token).toMatch(/^at_/)
    expect(decode(t.id_token).payload.org_id).toBe(ORG)
    expect((storage.store.get(`access:${t.access_token}`) as Record<string, unknown>).orgId).toBe(ORG)
    expect((storage.store.get(`refresh:${t.refresh_token}`) as Record<string, unknown>).orgId).toBe(ORG)
    const grants = recordsWithPrefix(storage, 'grant:')
    expect(grants.length).toBe(1)
    expect(grants[0]!.orgId).toBe(ORG)

    expect(await introspect(provider, t.access_token)).toMatchObject({ active: true, sub: PERSON, org_id: ORG })
    expect(await introspect(provider, t.refresh_token)).toMatchObject({ active: true, token_type: 'refresh_token', org_id: ORG })
    expect((await userinfo(provider, t.access_token)).org_id).toBe(ORG)
  })

  it('survives refresh rotation (twice)', async () => {
    const back = await consent(provider, clientId, { org_id: ORG })
    const first = await redeem(provider, clientId, back.searchParams.get('code')!)
    const second = await refresh(provider, clientId, first.refresh_token)
    expect(decode(second.id_token).payload.org_id).toBe(ORG)
    expect((await introspect(provider, second.access_token)).org_id).toBe(ORG)
    expect((await userinfo(provider, second.access_token)).org_id).toBe(ORG)
    const third = await refresh(provider, clientId, second.refresh_token)
    expect(decode(third.id_token).payload.org_id).toBe(ORG)
    expect((await introspect(provider, third.refresh_token)).org_id).toBe(ORG)
  })

  it('rides the api.sb JWT access token, its introspection, its refresh and a token exchange', async () => {
    const back = await consent(provider, clientId, { org_id: ORG, scope: 'openid sb:read sb:do', resource: 'https://api.sb/mcp' })
    const t = await redeem(provider, clientId, back.searchParams.get('code')!)
    const { header, payload } = decode(t.access_token)
    expect(header.typ).toBe('at+jwt')
    expect(payload).toMatchObject({ sub: PERSON, aud: 'https://api.sb/mcp', org_id: ORG })
    expect(decode(t.id_token).payload.org_id).toBe(ORG)
    expect(await introspect(provider, t.access_token)).toMatchObject({ active: true, jti: payload.jti, org_id: ORG })

    const r = await refresh(provider, clientId, t.refresh_token)
    expect(decode(r.access_token).payload.org_id).toBe(ORG)
    expect((await introspect(provider, r.access_token)).org_id).toBe(ORG)

    const ex = await provider.exchangeToken({ subject_token: r.access_token, subject_token_type: ACCESS, actor: { sub: 'workers/sextant' }, scope: 'sb:read' })
    if (!ex.ok) throw new Error(ex.error_description)
    expect(decode(ex.access_token).payload).toMatchObject({ sub: PERSON, org_id: ORG, act: { sub: 'workers/sextant' } })
    expect((await introspect(provider, ex.access_token)).org_id).toBe(ORG)
  })

  it('a JWT access token whose org_id disagrees with its record does not introspect', async () => {
    const back = await consent(provider, clientId, { org_id: ORG, scope: 'sb:read', resource: 'https://api.sb/mcp' })
    const t = await redeem(provider, clientId, back.searchParams.get('code')!)
    const { payload } = decode(t.access_token)
    const key = await keys.getCurrentKey()
    const moved = await signAccessTokenJwt(key, { ...(payload as any), org_id: OTHER_ORG })
    expect((await introspect(provider, moved)).active).toBe(false)
    const { org_id: _dropped, ...withoutOrg } = payload
    const stripped = await signAccessTokenJwt(key, withoutOrg as any)
    expect((await introspect(provider, stripped)).active).toBe(false)
    // The token as issued still introspects.
    expect((await introspect(provider, t.access_token)).active).toBe(true)
  })

  it('an opaque access token exchanged for api.sb keeps the grant org_id', async () => {
    // An api.sb grant gets an opaque at_ token when signing is unavailable
    // (issueTokenPair falls back); a provider without keys stands in for that.
    const plain = makeProvider({ storage, keys: null })
    const back = await consent(plain, clientId, { org_id: ORG, scope: 'sb:read', resource: 'https://api.sb/mcp' })
    const t = await redeem(plain, clientId, back.searchParams.get('code')!)
    expect(t.access_token).toMatch(/^at_/)
    expect((await introspect(plain, t.access_token)).org_id).toBe(ORG)
    // Exchange through a provider over the same storage that can sign.
    const ex = await provider.exchangeToken({ subject_token: t.access_token, subject_token_type: ACCESS, actor: { sub: 'w' } })
    if (!ex.ok) throw new Error(ex.error_description)
    expect(decode(ex.access_token).payload.org_id).toBe(ORG)
  })
})

describe('provider: org_id the Person may not choose', () => {
  async function refused(provider: OAuthProvider, storage: ReturnType<typeof createStorage>, clientId: string, orgId: string) {
    const back = await consent(provider, clientId, { org_id: orgId })
    expect(`${back.origin}${back.pathname}`).toBe(REDIRECT)
    expect(back.searchParams.get('error')).toBe('invalid_request')
    expect(back.searchParams.get('error_description')).toBe('org_id is not one of your workspaces')
    expect(back.searchParams.get('state')).toBe('st-org')
    expect(back.searchParams.get('iss')).toBe('https://id.org.ai')
    expect(back.searchParams.get('code')).toBeNull()
    expect([...storage.store.keys()].filter((k) => k.startsWith('code:'))).toEqual([])
  }

  it('an org the Person is not a member of is refused, with no code issued', async () => {
    const storage = createStorage()
    const provider = makeProvider({ storage })
    await refused(provider, storage, await register(provider), OTHER_ORG)
  })

  it('without a membership hook every org_id is refused', async () => {
    const storage = createStorage()
    const provider = makeProvider({ storage, hook: null })
    await refused(provider, storage, await register(provider), ORG)
  })

  it('a hook that fails counts as not a member', async () => {
    const storage = createStorage()
    const provider = makeProvider({
      storage,
      hook: async () => {
        throw new Error('WorkOS is down')
      },
    })
    await refused(provider, storage, await register(provider), ORG)
  })

  it('the hook is asked about this Person and this org', async () => {
    const calls: Array<[string, string]> = []
    const provider = makeProvider({
      hook: async (identityId, orgId) => {
        calls.push([identityId, orgId])
        return true
      },
    })
    const back = await consent(provider, await register(provider), { org_id: ORG })
    expect(back.searchParams.get('code')).toMatch(/^ac_/)
    expect(calls).toEqual([[PERSON, ORG]])
  })
})

describe('provider: no org_id (clients as they are today)', () => {
  it('adds org_id to nothing: code, records, id_token, JWT, introspection, userinfo, refresh, exchange', async () => {
    const storage = createStorage()
    const calls: string[] = []
    const provider = makeProvider({
      storage,
      hook: async (_i, o) => {
        calls.push(o)
        return true
      },
    })
    const clientId = await register(provider)

    // Opaque flow; an empty org_id (a select left on its blank option) is no org_id.
    for (const extra of [{}, { org_id: '' }] as Array<Record<string, string>>) {
      const back = await consent(provider, clientId, extra)
      const code = back.searchParams.get('code')!
      expect(code).toMatch(/^ac_/)
      expect('orgId' in (storage.store.get(`code:${code}`) as object)).toBe(false)
      const t = await redeem(provider, clientId, code)
      const id = decode(t.id_token).payload
      expect(Object.keys(id).sort()).toEqual(['at_hash', 'aud', 'email', 'email_verified', 'exp', 'iat', 'iss', 'name', 'nonce', 'sub', 'tier'].sort())
      expect('orgId' in (storage.store.get(`access:${t.access_token}`) as object)).toBe(false)
      expect('orgId' in (storage.store.get(`refresh:${t.refresh_token}`) as object)).toBe(false)
      expect(await introspect(provider, t.access_token)).not.toHaveProperty('org_id')
      expect(await introspect(provider, t.refresh_token)).not.toHaveProperty('org_id')
      expect(await userinfo(provider, t.access_token)).not.toHaveProperty('org_id')
      const r = await refresh(provider, clientId, t.refresh_token)
      expect(decode(r.id_token).payload).not.toHaveProperty('org_id')
    }
    for (const g of recordsWithPrefix(storage, 'grant:')) expect(g).toEqual({ createdAt: expect.any(Number) })

    // JWT flow and exchange.
    const back = await consent(provider, clientId, { scope: 'sb:read', resource: 'https://api.sb/mcp' })
    const t = await redeem(provider, clientId, back.searchParams.get('code')!)
    const { payload } = decode(t.access_token)
    expect(Object.keys(payload).sort()).toEqual(['aud', 'client_id', 'exp', 'iat', 'iss', 'jti', 'scope', 'sub'])
    expect(await introspect(provider, t.access_token)).not.toHaveProperty('org_id')
    for (const rec of recordsWithPrefix(storage, 'access-jwt:')) expect('orgId' in rec).toBe(false)
    const ex = await provider.exchangeToken({ subject_token: t.access_token, subject_token_type: ACCESS, actor: { sub: 'w' } })
    if (!ex.ok) throw new Error(ex.error_description)
    expect(decode(ex.access_token).payload).not.toHaveProperty('org_id')

    // The hook was never consulted.
    expect(calls).toEqual([])
  })
})

// ── through the worker ──────────────────────────────────────────────────────

const BASE = 'https://id.org.ai'
const WORKOS = 'https://api.workos.com'
const RP_REDIRECT = 'https://org-rp.example/cb'
/** What the mocked WorkOS sign-in reports as the session's (and the identity's) org. */
const SESSION_ORG = 'org_01TEST'

function setCookies(res: Response): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(';')
    const i = pair!.indexOf('=')
    out[pair!.slice(0, i).trim()] = pair!.slice(i + 1)
  }
  return out
}

const cookieHeader = (c: Record<string, string>) =>
  Object.entries(c)
    .filter(([, v]) => v !== '')
    .map(([k, v]) => `${k}=${v}`)
    .join('; ')

let seq = 0
/** Sign in through /login → (fake) WorkOS → /api/callback. */
async function signIn(): Promise<{ cookies: Record<string, string>; userId: string }> {
  const userId = `user_01ORGID_${++seq}`
  const login = await SELF.fetch(`${BASE}/login?provider=GitHubOAuth`, { redirect: 'manual' })
  const state = new URL(login.headers.get('location')!).searchParams.get('state')!
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'POST', path: '/user_management/authenticate' })
    .reply(
      200,
      JSON.stringify({
        access_token: 'at_w',
        refresh_token: 'rt_w',
        user: { id: userId, email: `${userId.toLowerCase()}@example.com`, first_name: 'Ada', last_name: 'L' },
        organization_id: SESSION_ORG,
        authentication_method: 'GitHubOAuth',
      }),
      { headers: { 'content-type': 'application/json' } },
    )
  const cb = await SELF.fetch(`${BASE}/api/callback?code=wos_code&state=${encodeURIComponent(state)}`, { redirect: 'manual' })
  expect(cb.status).toBe(302)
  return { cookies: { auth: setCookies(cb).auth! }, userId }
}

function mockMemberships(userId: string, rows: Array<{ org: string; status: string }>) {
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'GET', path: '/user_management/organization_memberships', query: { user_id: userId, limit: '100' } })
    .reply(
      200,
      JSON.stringify({
        data: rows.map((r, i) => ({ id: `om_${i}`, user_id: userId, organization_id: r.org, role: { slug: 'member' }, status: r.status, created_at: 't', updated_at: 't' })),
      }),
      { headers: { 'content-type': 'application/json' } },
    )
    // The consent page lists the workspaces (GET) and the POST checks org_id: both read them.
    .persist()
}

async function registerRp(): Promise<string> {
  const res = await SELF.fetch(`${BASE}/oauth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: 'Org RP', redirect_uris: [RP_REDIRECT], token_endpoint_auth_method: 'none', scope: 'openid profile email offline_access' }),
  })
  expect(res.status).toBe(201)
  return ((await res.json()) as { client_id: string }).client_id
}

/**
 * GET /oauth/authorize (the consent page sets the CSRF cookie), then POST the
 * consent with the CSRF-wrapped state, as the consent form does.
 */
async function consentThroughWorker(
  clientId: string,
  cookies: Record<string, string>,
  challenge: string,
  extra: Record<string, string> = {},
): Promise<URL> {
  const params: Record<string, string> = {
    response_type: 'code',
    client_id: clientId,
    redirect_uri: RP_REDIRECT,
    scope: 'openid profile email offline_access',
    state: 'rp-state',
    nonce: 'rp-nonce',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...(extra.resource ? { resource: extra.resource } : {}),
    ...(extra.scope ? { scope: extra.scope } : {}),
  }
  const page = await SELF.fetch(`${BASE}/oauth/authorize?${new URLSearchParams(params)}`, { redirect: 'manual', headers: { cookie: cookieHeader(cookies) } })
  expect(page.status).toBe(200)
  await page.arrayBuffer()
  const csrf = setCookies(page).__csrf!
  expect(csrf).toBeTruthy()
  const { response_type: _rt, ...fields } = params
  const res = await SELF.fetch(`${BASE}/oauth/authorize`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader({ ...cookies, __csrf: csrf }) },
    body: new URLSearchParams({ ...fields, ...extra, state: encodeStateWithCSRF(csrf, 'rp-state'), approved: 'true' }).toString(),
  })
  expect(res.status).toBe(302)
  return new URL(res.headers.get('location')!)
}

async function token(body: Record<string, string>) {
  const res = await SELF.fetch(`${BASE}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body).toString() })
  expect(res.status).toBe(200)
  return (await res.json()) as Record<string, any>
}

async function introspectViaWorker(t: string) {
  return (await (await SELF.fetch(`${BASE}/oauth/introspect`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token: t }).toString() })).json()) as Record<
    string,
    any
  >
}

async function userinfoViaWorker(t: string) {
  const res = await SELF.fetch(`${BASE}/oauth/userinfo`, { headers: { authorization: `Bearer ${t}` } })
  expect(res.status).toBe(200)
  return (await res.json()) as Record<string, any>
}

async function pkce() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)))
  return { verifier, challenge: await s256(verifier) }
}

describe('worker: org_id on consent', () => {
  beforeAll(() => {
    fetchMock.activate()
    fetchMock.disableNetConnect()
    // Profile / org enrichment at sign-in null-falls-back on failure.
    fetchMock.get(WORKOS).intercept({ path: /^\/user_management\/users\// }).reply(500, '').persist()
    fetchMock.get(WORKOS).intercept({ path: /^\/organizations\// }).reply(500, '').persist()
  })
  afterAll(() => fetchMock.deactivate())

  it('an active membership: org_id reaches the id_token, introspection, userinfo, and survives refresh', async () => {
    const clientId = await registerRp()
    const { cookies, userId } = await signIn()
    const { verifier, challenge } = await pkce()
    mockMemberships(userId, [
      { org: SESSION_ORG, status: 'active' },
      { org: ORG, status: 'active' },
    ])
    const back = await consentThroughWorker(clientId, cookies, challenge, { org_id: ORG })
    expect(back.searchParams.get('state')).toBe('rp-state')
    const code = back.searchParams.get('code')!
    expect(code).toMatch(/^ac_/)

    const t = await token({ grant_type: 'authorization_code', code, redirect_uri: RP_REDIRECT, client_id: clientId, code_verifier: verifier })
    expect(decode(t.id_token).payload.org_id).toBe(ORG)
    expect(await introspectViaWorker(t.access_token)).toMatchObject({ active: true, org_id: ORG })
    // The grant's workspace, not the identity's first-login org.
    expect((await userinfoViaWorker(t.access_token)).org_id).toBe(ORG)

    const r = await token({ grant_type: 'refresh_token', refresh_token: t.refresh_token, client_id: clientId })
    expect(decode(r.id_token).payload.org_id).toBe(ORG)
    expect((await introspectViaWorker(r.access_token)).org_id).toBe(ORG)
    expect((await userinfoViaWorker(r.access_token)).org_id).toBe(ORG)
  })

  it('an api.sb grant: the JWT access token carries org_id', async () => {
    const clientId = await registerRp()
    const { cookies, userId } = await signIn()
    const { verifier, challenge } = await pkce()
    mockMemberships(userId, [{ org: ORG, status: 'active' }])
    const back = await consentThroughWorker(clientId, cookies, challenge, { org_id: ORG, scope: 'openid sb:read', resource: 'https://api.sb/mcp' })
    const t = await token({ grant_type: 'authorization_code', code: back.searchParams.get('code')!, redirect_uri: RP_REDIRECT, client_id: clientId, code_verifier: verifier })
    expect(decode(t.access_token).header.typ).toBe('at+jwt')
    expect(decode(t.access_token).payload.org_id).toBe(ORG)
    expect((await introspectViaWorker(t.access_token)).org_id).toBe(ORG)
  })

  for (const [why, rows] of [
    ['an inactive membership', [{ org: ORG, status: 'inactive' }]],
    ['no membership in that org', [{ org: SESSION_ORG, status: 'active' }]],
  ] as const) {
    it(`${why} is refused: invalid_request back to the client, no code`, async () => {
      const clientId = await registerRp()
      const { cookies, userId } = await signIn()
      const { challenge } = await pkce()
      mockMemberships(userId, [...rows])
      const back = await consentThroughWorker(clientId, cookies, challenge, { org_id: ORG })
      // Refused on the memberships WorkOS returned (the mock was consumed), not on a failed fetch.
      expect(fetchMock.pendingInterceptors()).toEqual([])
      expect(`${back.origin}${back.pathname}`).toBe(RP_REDIRECT)
      expect(back.searchParams.get('error')).toBe('invalid_request')
      expect(back.searchParams.get('state')).toBe('rp-state')
      expect(back.searchParams.get('code')).toBeNull()
    })
  }

  it('without org_id nothing changes: no org_id in tokens, introspection or userinfo', async () => {
    const clientId = await registerRp()
    const { cookies } = await signIn()
    const { verifier, challenge } = await pkce()
    const back = await consentThroughWorker(clientId, cookies, challenge)
    const t = await token({ grant_type: 'authorization_code', code: back.searchParams.get('code')!, redirect_uri: RP_REDIRECT, client_id: clientId, code_verifier: verifier })
    expect(decode(t.id_token).payload).not.toHaveProperty('org_id')
    expect(await introspectViaWorker(t.access_token)).not.toHaveProperty('org_id')
    expect(await introspectViaWorker(t.refresh_token)).not.toHaveProperty('org_id')
    // Userinfo's fallback is the identity's organizationId, as before. The
    // identity record has one (SESSION_ORG), but getIdentity does not map it,
    // so today it is absent: the response is unchanged.
    expect(await userinfoViaWorker(t.access_token)).not.toHaveProperty('org_id')
    const r = await token({ grant_type: 'refresh_token', refresh_token: t.refresh_token, client_id: clientId })
    expect(decode(r.id_token).payload).not.toHaveProperty('org_id')
  })
})
