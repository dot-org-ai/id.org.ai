/**
 * Phase 6 · Device flow v2 (docs/product-update/spec/backend.md#b3), on the
 * provider: readable codes, device metadata, the decision (approve / deny,
 * idempotent, org_id validated and carried into the tokens), slow_down, and
 * revoking a device's grant, even before the CLI has collected its tokens.
 */
import { describe, it, expect } from 'vitest'
import { OAuthProvider, formatUserCode, normalizeUserCode, type OAuthConfig } from '../src/sdk/oauth/provider'

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
const PERSON = 'human:user_device_person'
const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code'

function makeProvider(members = new Set(['org_A'])) {
  return new OAuthProvider({
    storage: createStorage(),
    config: CONFIG,
    getIdentity: async (id) => ({ id, name: 'Ada', email: 'ada@example.com', emailVerified: true, level: 2 }),
    validateOrgMembership: async (_id, org) => members.has(org),
  })
}

function form(url: string, fields: Record<string, string>, headers: Record<string, string> = {}): Request {
  return new Request(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams(fields).toString() })
}

async function setup(provider: OAuthProvider, extra: Record<string, string> = {}, headers: Record<string, string> = {}, cf?: Record<string, string>) {
  const reg = await provider.handleRegister(
    new Request('https://id.org.ai/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: 'CLI', grant_types: [DEVICE_GRANT, 'refresh_token'], redirect_uris: [], token_endpoint_auth_method: 'none', scope: 'openid profile email offline_access' }),
    }),
  )
  const clientId = ((await reg.json()) as { client_id: string }).client_id
  const req = form('https://id.org.ai/oauth/device', { client_id: clientId, scope: 'openid profile email offline_access', ...extra }, headers)
  if (cf) Object.defineProperty(req, 'cf', { value: cf })
  const d = (await (await provider.handleDeviceAuthorization(req)).json()) as Record<string, any>
  return { clientId, d }
}

const poll = (provider: OAuthProvider, clientId: string, deviceCode: string) =>
  provider.handleToken(form('https://id.org.ai/oauth/token', { grant_type: DEVICE_GRANT, device_code: deviceCode, client_id: clientId }))

describe('readable codes', () => {
  it('formats as XXXX-XXXX and normalises input with or without the hyphen or spaces', () => {
    expect(formatUserCode('WDJBMJHT')).toBe('WDJB-MJHT')
    for (const typed of ['wdjb-mjht', 'WDJB MJHT', ' wdjbmjht ', 'WDJB–MJHT'.replace('–', '-')]) expect(normalizeUserCode(typed)).toBe('WDJBMJHT')
  })

  it('the device authorization answers XXXX-XXXX and a verification_uri_complete with ?code=', async () => {
    const { d } = await setup(makeProvider())
    expect(d.user_code).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/)
    expect(d.verification_uri_complete).toBe(`https://id.org.ai/device?code=${d.user_code}`)
  })
})

describe('device metadata', () => {
  it('captures the OS (device_name, else the User-Agent), the place, the IP and the time', async () => {
    const provider = makeProvider()
    const { d } = await setup(provider, { device_name: 'macOS · bryants-mbp' }, { 'cf-connecting-ip': '203.0.113.7' }, { city: 'Miami', regionCode: 'FL', country: 'US' })
    const view = await provider.getDeviceRequest(d.user_code)
    expect(view?.meta).toMatchObject({ os: 'macOS · bryants-mbp', city: 'Miami', region: 'FL', country: 'US', ip: '203.0.113.7' })
    expect(view!.meta!.requestedAt).toBeGreaterThan(Date.now() - 5000)

    const ua = makeProvider()
    const { d: d2 } = await setup(ua, {}, { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' })
    expect((await ua.getDeviceRequest(d2.user_code))?.meta?.os).toBe('Windows')
  })

  it('a device_name is trimmed, length-capped and stripped of control characters', async () => {
    const provider = makeProvider()
    const { d } = await setup(provider, { device_name: `  evil\u0000\u001b[31m name ${'x'.repeat(200)}` })
    const os = (await provider.getDeviceRequest(d.user_code))!.meta!.os!
    expect(os).not.toMatch(/[\u0000-\u001f]/)
    expect(os.length).toBeLessThanOrEqual(64)
  })
})

describe('the decision', () => {
  it('approve with a workspace → poll → tokens carrying org_id; approving again is idempotent', async () => {
    const provider = makeProvider()
    const { clientId, d } = await setup(provider)
    expect(await provider.decideDevice({ code: d.user_code, identityId: PERSON, decision: 'approve', orgId: 'org_A' })).toMatchObject({ ok: true, state: 'approved' })
    expect(await provider.decideDevice({ code: d.user_code.replace('-', ''), identityId: PERSON, decision: 'approve', orgId: 'org_A' })).toMatchObject({ ok: true, state: 'approved' })
    const res = await poll(provider, clientId, d.device_code)
    expect(res.status).toBe(200)
    const t = (await res.json()) as Record<string, any>
    const intro = (await (await provider.handleIntrospect(form('https://id.org.ai/oauth/introspect', { token: t.access_token }))).json()) as Record<string, any>
    expect(intro).toMatchObject({ active: true, sub: PERSON, org_id: 'org_A' })
  })

  it('deny → poll gives access_denied; a different decision afterwards is already_used', async () => {
    const provider = makeProvider()
    const { clientId, d } = await setup(provider)
    expect(await provider.decideDevice({ code: d.user_code, identityId: PERSON, decision: 'deny' })).toMatchObject({ ok: true, state: 'denied' })
    expect(await provider.decideDevice({ code: d.user_code, identityId: PERSON, decision: 'approve' })).toMatchObject({ ok: false, error: 'already_used' })
    expect(((await (await poll(provider, clientId, d.device_code)).json()) as { error: string }).error).toBe('access_denied')
  })

  it('a workspace the person isn’t in is refused, and the code stays pending', async () => {
    const provider = makeProvider()
    const { d } = await setup(provider)
    expect(await provider.decideDevice({ code: d.user_code, identityId: PERSON, decision: 'approve', orgId: 'org_X' })).toMatchObject({ ok: false, error: 'invalid_org' })
    expect((await provider.getDeviceRequest(d.user_code))?.status).toBe('pending')
  })

  it('an unknown or expired code is refused', async () => {
    const provider = makeProvider()
    expect(await provider.decideDevice({ code: 'ZZZZ-ZZZZ', identityId: PERSON, decision: 'approve' })).toMatchObject({ ok: false, error: 'expired' })
  })
})

describe('slow_down (RFC 8628 §3.5)', () => {
  it('polling faster than the interval gets slow_down and a longer interval; at the interval it is pending', async () => {
    const provider = makeProvider()
    const { clientId, d } = await setup(provider)
    expect(((await (await poll(provider, clientId, d.device_code)).json()) as { error: string }).error).toBe('authorization_pending')
    expect(((await (await poll(provider, clientId, d.device_code)).json()) as { error: string }).error).toBe('slow_down')
    expect((await provider.getDeviceRequest(d.user_code))?.interval).toBe(10)
  })
})

describe('signing a device out', () => {
  it('revoking the device’s grant before the CLI collects its tokens leaves it nothing', async () => {
    const provider = makeProvider()
    const { clientId, d } = await setup(provider)
    const view = await provider.getDeviceRequest(d.user_code)
    await provider.decideDevice({ code: d.user_code, identityId: PERSON, decision: 'approve' })
    expect(await provider.revokeDeviceGrant(view!.family, 'human:someone_else')).toBe(false)
    expect(await provider.revokeDeviceGrant(view!.family, PERSON)).toBe(true)
    const res = await poll(provider, clientId, d.device_code)
    expect(((await res.json()) as { error: string }).error).toBe('invalid_grant')
  })

  it('revoking after the CLI has its tokens ends its refresh token', async () => {
    const provider = makeProvider()
    const { clientId, d } = await setup(provider)
    const view = await provider.getDeviceRequest(d.user_code)
    await provider.decideDevice({ code: d.user_code, identityId: PERSON, decision: 'approve' })
    const t = (await (await poll(provider, clientId, d.device_code)).json()) as Record<string, any>
    expect(await provider.revokeDeviceGrant(view!.family, PERSON)).toBe(true)
    const r = await provider.handleToken(form('https://id.org.ai/oauth/token', { grant_type: 'refresh_token', refresh_token: t.refresh_token, client_id: clientId }))
    expect(r.status).toBe(400)
  })
})
