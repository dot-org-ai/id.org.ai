/**
 * Phase 5 · Consent v2, the POST contract (docs/product-update/spec/backend.md#b2),
 * on the provider directly:
 *   - access=read|act (read maps onto the existing sb:do → sb:read downgrade);
 *   - consent remembered per client per workspace, a legacy record meaning "any org";
 *   - the step-up hook: a stale sign-in granting sb:do parks the consent as a
 *     single-use resume record and goes to /step-up; resuming issues the code.
 */
import { describe, it, expect } from 'vitest'
import { OAuthProvider, type OAuthConfig } from '../src/sdk/oauth/provider'
import type { ConsentViewModel } from '../src/sdk/oauth/consent-view'

function createStorage() {
  const store = new Map<string, unknown>()
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
  }
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
const VERIFIER = 'consent-v2-post-verifier-0123456789-abcdefghijklmnop'
const INTERACTIVE = { interactive: true }
const MEMBER_OF = new Set(['org_A', 'org_B'])

async function s256(v: string): Promise<string> {
  const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v))
  return btoa(String.fromCharCode(...new Uint8Array(h))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function makeProvider(extra: Partial<ConstructorParameters<typeof OAuthProvider>[0]> = {}, members = MEMBER_OF) {
  const storage = createStorage()
  const seen: ConsentViewModel[] = []
  const provider = new OAuthProvider({
    storage,
    config: CONFIG,
    getIdentity: async (id) => ({ id, name: 'Ada', email: 'ada@example.com', emailVerified: true, level: 2 }),
    validateOrgMembership: async (_id, orgId) => members.has(orgId),
    // A renderer that records the view model and answers with the hidden fields as JSON.
    renderConsent: (vm) => {
      seen.push(vm)
      return new Response(JSON.stringify(vm.fields), { status: 200, headers: { 'content-type': 'text/html' } })
    },
    ...extra,
  })
  return { provider, storage, seen }
}

async function register(provider: OAuthProvider): Promise<string> {
  const res = await provider.handleRegister(
    new Request('https://id.org.ai/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: 'Client', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' }),
    }),
  )
  return ((await res.json()) as { client_id: string }).client_id
}

async function authorize(provider: OAuthProvider, clientId: string, params: Record<string, string> = {}): Promise<Response> {
  const u = new URL('https://id.org.ai/oauth/authorize')
  for (const [k, v] of Object.entries({ client_id: clientId, redirect_uri: REDIRECT, response_type: 'code', scope: 'openid profile email', state: 'st-1', code_challenge: await s256(VERIFIER), code_challenge_method: 'S256', ...params }))
    u.searchParams.set(k, v)
  return provider.handleAuthorize(new Request(u.toString()), PERSON)
}

function consentPost(fields: Record<string, string>): Request {
  return new Request('https://id.org.ai/oauth/authorize', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(fields).toString() })
}

/** GET (the renderer answers with the fields) → POST with `extra` → the redirect. */
async function consent(provider: OAuthProvider, clientId: string, params: Record<string, string>, extra: Record<string, string>, signIn?: { authTime?: number }): Promise<Response> {
  const page = await authorize(provider, clientId, params)
  expect(page.status).toBe(200)
  const fields = (await page.json()) as Record<string, string>
  return provider.handleAuthorizeConsent(consentPost({ ...fields, approved: 'true', ...extra }), PERSON, signIn, INTERACTIVE)
}

async function redeem(provider: OAuthProvider, clientId: string, code: string): Promise<Record<string, any>> {
  const res = await provider.handleToken(
    new Request('https://id.org.ai/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: VERIFIER }).toString(),
    }),
  )
  expect(res.status).toBe(200)
  return (await res.json()) as Record<string, any>
}
const codeOf = (res: Response) => new URL(res.headers.get('location')!).searchParams.get('code')!
async function introspect(provider: OAuthProvider, token: string): Promise<Record<string, any>> {
  const res = await provider.handleIntrospect(
    new Request('https://id.org.ai/oauth/introspect', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token }).toString() }),
  )
  return (await res.json()) as Record<string, any>
}
const SB = { scope: 'openid sb:read sb:do', resource: 'https://api.sb/mcp' }

describe('access=read|act', () => {
  it('access=read downgrades sb:do to sb:read; access=act keeps it', async () => {
    const { provider } = makeProvider()
    const clientId = await register(provider)
    const read = await consent(provider, clientId, SB, { access: 'read' })
    expect((await redeem(provider, clientId, codeOf(read))).scope.split(' ').sort()).toEqual(['openid', 'sb:read'])
    const act = await consent(provider, clientId, SB, { access: 'act' })
    expect((await redeem(provider, clientId, codeOf(act))).scope.split(' ').sort()).toEqual(['openid', 'sb:do', 'sb:read'])
  })

  it('any other access value is refused with invalid_request, and no code is issued', async () => {
    const { provider } = makeProvider()
    const clientId = await register(provider)
    const res = await consent(provider, clientId, SB, { access: 'admin' })
    const back = new URL(res.headers.get('location')!)
    expect(back.searchParams.get('error')).toBe('invalid_request')
    expect(back.searchParams.get('code')).toBeNull()
  })
})

describe('consent remembered per client per workspace', () => {
  it('a consent for org_A is reused silently for org_A (and as the remembered org), but org_B asks again', async () => {
    const { provider, seen } = makeProvider()
    const clientId = await register(provider)
    await consent(provider, clientId, {}, { org_id: 'org_A' })

    const forA = await authorize(provider, clientId, { organization_id: 'org_A' })
    expect(forA.status).toBe(302)
    expect(await introspect(provider, (await redeem(provider, clientId, codeOf(forA))).access_token)).toMatchObject({ active: true, org_id: 'org_A' })

    const remembered = await authorize(provider, clientId)
    expect(remembered.status).toBe(302) // no hint: the remembered workspace
    expect(await introspect(provider, (await redeem(provider, clientId, codeOf(remembered))).access_token)).toMatchObject({ org_id: 'org_A' })

    const forB = await authorize(provider, clientId, { organization_id: 'org_B' })
    expect(forB.status).toBe(200)
    expect(seen.at(-1)!.rememberedOrgId).toBe('org_A')
  })

  it('a workspace the person has left is never reused silently', async () => {
    const members = new Set(['org_A'])
    const { provider } = makeProvider({}, members)
    const clientId = await register(provider)
    await consent(provider, clientId, {}, { org_id: 'org_A' })
    members.delete('org_A')
    expect((await authorize(provider, clientId, { organization_id: 'org_A' })).status).toBe(200)
    expect((await authorize(provider, clientId)).status).toBe(200)
  })

  it('a legacy consent means any org until re-consented with a workspace', async () => {
    const { provider, storage } = makeProvider()
    const clientId = await register(provider)
    await storage.put(`consent:${PERSON}:${clientId}`, { scopes: ['openid', 'profile', 'email'], createdAt: 1 })
    expect((await authorize(provider, clientId)).status).toBe(302) // unchanged behaviour

    // Re-consent with a workspace (forced by a new scope here) drops the any-org grant.
    await consent(provider, clientId, { scope: 'openid profile email offline_access' }, { org_id: 'org_B' })
    const rec = storage.store.get(`consent:${PERSON}:${clientId}`) as { scopes: string[]; orgs?: Record<string, { scopes: string[] }> }
    expect(rec.scopes).toEqual([])
    expect(rec.orgs?.org_B?.scopes).toContain('offline_access')
    // The grants list still shows the client with what it was granted.
    const grants = await provider.listGrants(PERSON)
    expect(grants.find((g) => g.client_id === clientId)?.scopes).toContain('offline_access')
  })
})

describe('step-up before granting act permissions (FEATURE_STEP_UP)', () => {
  const STALE = { authTime: Math.floor(Date.now() / 1000) - 3600 }
  const FRESH = { authTime: Math.floor(Date.now() / 1000) - 60 }

  it('a stale sign-in granting sb:do goes to /step-up with a single-use resume record; resuming issues the code', async () => {
    const { provider, storage } = makeProvider({ stepUpMaxAgeSeconds: 600 })
    const clientId = await register(provider)
    const res = await consent(provider, clientId, SB, { access: 'act', org_id: 'org_A' }, STALE)
    expect(res.status).toBe(302)
    const to = new URL(res.headers.get('location')!)
    expect(`${to.origin}${to.pathname}`).toBe('https://id.org.ai/step-up')
    expect(to.searchParams.get('reason')).toBe('act_permissions')
    const resume = to.searchParams.get('resume')!
    expect(resume).toMatch(/^rsm_/)
    expect(storage.store.has(`consent:${PERSON}:${clientId}`)).toBe(false) // nothing granted yet

    expect((await provider.resumeAuthorizeConsent(resume, 'human:someone_else', FRESH)).status).toBe(400)
    const done = await provider.resumeAuthorizeConsent(resume, PERSON, FRESH)
    expect(done.status).toBe(302)
    const back = new URL(done.headers.get('location')!)
    expect(back.searchParams.get('state')).toBe('st-1')
    const tokens = await redeem(provider, clientId, back.searchParams.get('code')!)
    expect(tokens.scope.split(' ')).toContain('sb:do')
    expect((await provider.resumeAuthorizeConsent(resume, PERSON, FRESH)).status).toBe(400) // single use
  })

  it('no step-up for a fresh sign-in, for read-only access, or with the flag off', async () => {
    const on = makeProvider({ stepUpMaxAgeSeconds: 600 })
    expect(codeOf(await consent(on.provider, await register(on.provider), SB, { access: 'act' }, FRESH))).toMatch(/^ac_/)
    expect(codeOf(await consent(on.provider, await register(on.provider), SB, { access: 'read' }, STALE))).toMatch(/^ac_/)
    const off = makeProvider()
    const b = await register(off.provider)
    expect(codeOf(await consent(off.provider, b, SB, { access: 'act' }, STALE))).toMatch(/^ac_/)
  })
})
