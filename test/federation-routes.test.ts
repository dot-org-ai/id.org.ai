/**
 * /federation/* wire surface — drives the Hono sub-app directly (the
 * credentials-routes / aap-routes pattern) against a Map-backed fake
 * IdentityDO, with the Microsoft JWKS injected.
 *
 * This is the closest thing to an end-to-end test that can exist without a
 * live Entra app registration: it exercises the real start → callback →
 * identity-row → signed-cookie path, and the real email-code path, with only
 * the two genuinely external things (Entra's token endpoint, WorkOS's mail)
 * mocked at the fetch boundary.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { Hono } from 'hono'
import * as jose from 'jose'
import { createFederationApp } from '../worker/routes/federation'
import type { Env, Variables } from '../worker/types'
import { MICROSOFT_AUTHORITY } from '../src/sdk/federation/microsoft'

const ZEBRA_TID = '1cd51b26-8a29-4b1f-9e7a-6f2c05a3d417'
const ZEBRA_OID = '7c1b0d34-2f55-4c9a-b3e1-9a4d8f2e6b70'
const CLIENT_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

// ── Fake IdentityDO ───────────────────────────────────────────────────────

interface FakeDo {
  store: Map<string, unknown>
  oauthStorageOp(op: { op: string; key?: string; value?: unknown; options?: unknown }): Promise<Record<string, unknown>>
  getIdentity(id: string): Promise<unknown>
}

function makeStub(): FakeDo {
  const store = new Map<string, unknown>()
  return {
    store,
    async oauthStorageOp(op) {
      if (op.op === 'get' && op.key) return { value: store.get(op.key) }
      if (op.op === 'put' && op.key) {
        store.set(op.key, op.value)
        return { ok: true }
      }
      if (op.op === 'delete' && op.key) return { deleted: store.delete(op.key) }
      if (op.op === 'list') return { entries: Array.from(store.entries()) }
      throw new Error(`unknown op ${op.op}`)
    },
    async getIdentity(id: string) {
      return store.get(`identity:${id}`) ?? null
    },
  }
}

/**
 * One shared store across every shard: the federation transaction lives in the
 * `federation` shard and the identity row in the principal's own shard, and a
 * single Map lets one test observe both.
 */
function makeEnv(stub: FakeDo, overrides: Partial<Env> = {}): Env {
  return {
    IDENTITY: {
      idFromName: vi.fn(() => ({})),
      get: vi.fn(() => stub),
    },
    MICROSOFT_CLIENT_ID: CLIENT_ID,
    MICROSOFT_CLIENT_SECRET: 'entra-secret',
    WORKOS_API_KEY: 'sk_test_workos',
    WORKOS_CLIENT_ID: 'client_test',
    ...overrides,
  } as unknown as Env
}

async function makeSigner() {
  const { privateKey, publicKey } = await jose.generateKeyPair('RS256', { extractable: true })
  const jwk = await jose.exportJWK(publicKey)
  jwk.kid = 'ms-test-key'
  jwk.alg = 'RS256'
  const keySet = jose.createLocalJWKSet({ keys: [jwk] })
  const sign = (claims: Record<string, unknown>) =>
    new jose.SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: 'ms-test-key' })
      .setIssuedAt()
      .setExpirationTime('5m')
      .setIssuer(`${MICROSOFT_AUTHORITY}/${ZEBRA_TID}/v2.0`)
      .setAudience(CLIENT_ID)
      .sign(privateKey)
  return { sign, verifyDeps: { getKeySet: () => keySet } }
}

function makeApp(verifyDeps?: { getKeySet: () => jose.JWTVerifyGetKey }) {
  const app = new Hono<{ Bindings: Env; Variables: Variables }>()
  app.route('', createFederationApp({ microsoftVerify: verifyDeps }))
  return app
}

function get(app: ReturnType<typeof makeApp>, path: string, env: Env, init: RequestInit = {}) {
  return app.fetch(new Request(`https://id.org.ai${path}`, { redirect: 'manual', ...init }), env)
}

function postJson(app: ReturnType<typeof makeApp>, path: string, body: unknown, env: Env) {
  return app.fetch(
    new Request(`https://id.org.ai${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
    env,
  )
}

// ── GET /federation/status ────────────────────────────────────────────────

describe('GET /federation/status', () => {
  it('reports Microsoft configured and echoes the exact redirect URI the app registration needs', async () => {
    const res = await get(makeApp(), '/federation/status', makeEnv(makeStub()))
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.microsoft.configured).toBe(true)
    expect(body.microsoft.redirectUri).toBe('https://id.org.ai/federation/microsoft/callback')
    expect(body.microsoft.tenant).toBe('organizations')
    expect(body.emailCode.configured).toBe(true)
  })

  it('reports Microsoft unconfigured when no client id is set — no 500', async () => {
    const env = makeEnv(makeStub(), { MICROSOFT_CLIENT_ID: undefined })
    const body = (await (await get(makeApp(), '/federation/status', env)).json()) as any
    expect(body.microsoft.configured).toBe(false)
    // The fallback is still live — which is the whole point.
    expect(body.emailCode.configured).toBe(true)
  })

  it('leaks no secret', async () => {
    const text = await (await get(makeApp(), '/federation/status', makeEnv(makeStub()))).text()
    expect(text).not.toContain('entra-secret')
    expect(text).not.toContain('sk_test_workos')
  })
})

// ── GET /federation/microsoft/start ───────────────────────────────────────

describe('GET /federation/microsoft/start', () => {
  it('redirects to Entra with PKCE and minimal scopes, and stores the transaction', async () => {
    const stub = makeStub()
    const res = await get(makeApp(), '/federation/microsoft/start?continue=/deck', makeEnv(stub))

    expect(res.status).toBe(302)
    const location = new URL(res.headers.get('location')!)
    expect(location.origin + location.pathname).toBe(`${MICROSOFT_AUTHORITY}/organizations/oauth2/v2.0/authorize`)
    expect(location.searchParams.get('scope')).toBe('openid profile email')
    expect(location.searchParams.get('code_challenge_method')).toBe('S256')
    expect(location.searchParams.get('redirect_uri')).toBe('https://id.org.ai/federation/microsoft/callback')

    const state = location.searchParams.get('state')!
    const tx = stub.store.get(`fed-ms-tx:${state}`) as any
    expect(tx.continueUrl).toBe('/deck')
    expect(tx.codeVerifier).toBeTruthy()
    expect(tx.nonce).toBe(location.searchParams.get('nonce'))
  })

  it('refuses an off-site continue URL rather than becoming an open redirect', async () => {
    const stub = makeStub()
    const res = await get(makeApp(), '/federation/microsoft/start?continue=https://evil.example/x', makeEnv(stub))
    const state = new URL(res.headers.get('location')!).searchParams.get('state')!
    expect((stub.store.get(`fed-ms-tx:${state}`) as any).continueUrl).toBe('/')
  })

  it('refuses a protocol-relative continue URL', async () => {
    const stub = makeStub()
    const res = await get(makeApp(), '/federation/microsoft/start?continue=//evil.example/x', makeEnv(stub))
    const state = new URL(res.headers.get('location')!).searchParams.get('state')!
    expect((stub.store.get(`fed-ms-tx:${state}`) as any).continueUrl).toBe('/')
  })

  it('allows an org.ai host, and any host FEDERATION_CONTINUE_HOSTS opts in', async () => {
    const stub = makeStub()
    const env = makeEnv(stub, { FEDERATION_CONTINUE_HOSTS: 'pitch.visibility.cloud' } as Partial<Env>)

    for (const target of ['https://deck.org.ai/x', 'https://pitch.visibility.cloud/deck']) {
      const res = await get(makeApp(), `/federation/microsoft/start?continue=${encodeURIComponent(target)}`, env)
      const state = new URL(res.headers.get('location')!).searchParams.get('state')!
      expect((stub.store.get(`fed-ms-tx:${state}`) as any).continueUrl).toBe(target)
    }
  })

  it('sends the viewer to the email fallback when Microsoft is not configured', async () => {
    const env = makeEnv(makeStub(), { MICROSOFT_CLIENT_ID: undefined })
    const res = await get(makeApp(), '/federation/microsoft/start?continue=/deck', env)
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toContain('/federation/email')
    expect(res.headers.get('location')).toContain('reason=not-configured')
  })
})

// ── GET /federation/microsoft/callback ────────────────────────────────────

describe('GET /federation/microsoft/callback', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })
  afterEach(() => vi.restoreAllMocks())

  /** Run start, then hand back the state + the stub holding the transaction. */
  async function begin(app: ReturnType<typeof makeApp>, env: Env, stub: FakeDo) {
    const res = await get(app, '/federation/microsoft/start?continue=/deck', env)
    const url = new URL(res.headers.get('location')!)
    return { state: url.searchParams.get('state')!, nonce: url.searchParams.get('nonce')!, stub }
  }

  it('completes the sign-in: exchanges the code, verifies the token, writes the identity, sets the cookie', async () => {
    const { sign, verifyDeps } = await makeSigner()
    const app = makeApp(verifyDeps)
    const stub = makeStub()
    const env = makeEnv(stub)
    const { state, nonce } = await begin(app, env, stub)

    const idToken = await sign({
      tid: ZEBRA_TID,
      oid: ZEBRA_OID,
      nonce,
      email: 'Alice@Zebra.com',
      name: 'Alice Anders',
    })
    mockFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ id_token: idToken }), { headers: { 'Content-Type': 'application/json' } }),
    )

    const res = await get(app, `/federation/microsoft/callback?code=abc&state=${state}`, env)

    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toBe('/deck')

    // The identity row landed, with provenance and the L2 ceiling.
    const row = stub.store.get(`identity:human:ms:${ZEBRA_TID}:${ZEBRA_OID}`) as any
    expect(row.email).toBe('alice@zebra.com')
    expect(row.type).toBe('human')
    expect(row.level).toBe(2)
    expect(row.federation.assurance).toBe('federated-idp')
    expect(row.federation.tenantId).toBe(ZEBRA_TID)
    expect(row.federation.emailDomain).toBe('zebra.com')

    // An auth cookie was set…
    const cookies = res.headers.getSetCookie()
    expect(cookies.some((c) => c.startsWith('auth='))).toBe(true)

    // …and its JWT carries a sub that resolveIdentityId turns back into the
    // shard key (`human:${sub}`). Getting this wrong mints tokens that verify
    // but resolve to nobody.
    const jwt = cookies.find((c) => c.startsWith('auth='))!.split(';')[0]!.slice('auth='.length)
    const claims = jose.decodeJwt(jwt)
    expect(`human:${claims.sub}`).toBe(`human:ms:${ZEBRA_TID}:${ZEBRA_OID}`)
    expect((claims.fed as any).assurance).toBe('federated-idp')
    expect((claims.fed as any).emailDomain).toBe('zebra.com')
  })

  it('routes a consent-blocked tenant to the email fallback instead of an error page', async () => {
    const app = makeApp()
    const stub = makeStub()
    const env = makeEnv(stub)
    const { state } = await begin(app, env, stub)

    const res = await get(
      app,
      `/federation/microsoft/callback?state=${state}&error=access_denied&error_description=${encodeURIComponent('AADSTS65001: The user or administrator has not consented')}`,
      env,
    )

    expect(res.status).toBe(302)
    const location = res.headers.get('location')!
    expect(location).toContain('/federation/email')
    expect(location).toContain('reason=consent-required')
    expect(location).toContain('continue=%2Fdeck')
  })

  it('routes an admin-consent-required token failure to the fallback too', async () => {
    const app = makeApp()
    const stub = makeStub()
    const env = makeEnv(stub)
    const { state } = await begin(app, env, stub)

    mockFetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ error: 'invalid_grant', error_description: 'AADSTS90094: The grant requires admin permission.' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      ),
    )

    const res = await get(app, `/federation/microsoft/callback?code=abc&state=${state}`, env)
    expect(res.headers.get('location')).toContain('reason=consent-required')
  })

  it('rejects a callback with no state', async () => {
    const res = await get(makeApp(), '/federation/microsoft/callback?code=abc', makeEnv(makeStub()))
    expect(res.status).toBe(400)
  })

  it('rejects a callback whose state was never issued', async () => {
    const res = await get(makeApp(), '/federation/microsoft/callback?code=abc&state=forged', makeEnv(makeStub()))
    expect(res.status).toBe(400)
  })

  it('consumes the transaction so the same state cannot be replayed', async () => {
    const { sign, verifyDeps } = await makeSigner()
    const app = makeApp(verifyDeps)
    const stub = makeStub()
    const env = makeEnv(stub)
    const { state, nonce } = await begin(app, env, stub)

    const idToken = await sign({ tid: ZEBRA_TID, oid: ZEBRA_OID, nonce, email: 'alice@zebra.com' })
    mockFetch.mockResolvedValue(
      new Response(JSON.stringify({ id_token: idToken }), { headers: { 'Content-Type': 'application/json' } }),
    )

    const first = await get(app, `/federation/microsoft/callback?code=abc&state=${state}`, env)
    expect(first.status).toBe(302)
    expect(first.headers.get('location')).toBe('/deck')

    const replay = await get(app, `/federation/microsoft/callback?code=abc&state=${state}`, env)
    expect(replay.status).toBe(400)
  })

  it('rejects an expired transaction', async () => {
    const app = makeApp()
    const stub = makeStub()
    const env = makeEnv(stub)
    const { state } = await begin(app, env, stub)

    const tx = stub.store.get(`fed-ms-tx:${state}`) as any
    stub.store.set(`fed-ms-tx:${state}`, { ...tx, expiresAt: Date.now() - 1 })

    const res = await get(app, `/federation/microsoft/callback?code=abc&state=${state}`, env)
    expect(res.status).toBe(400)
  })

  it('sends a token that fails verification to the fallback, never to a raw error', async () => {
    const { verifyDeps } = await makeSigner()
    const other = await makeSigner()
    const app = makeApp(verifyDeps)
    const stub = makeStub()
    const env = makeEnv(stub)
    const { state, nonce } = await begin(app, env, stub)

    // Signed by a key the resolver does not know.
    const idToken = await other.sign({ tid: ZEBRA_TID, oid: ZEBRA_OID, nonce, email: 'alice@zebra.com' })
    mockFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ id_token: idToken }), { headers: { 'Content-Type': 'application/json' } }),
    )

    const res = await get(app, `/federation/microsoft/callback?code=abc&state=${state}`, env)
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toContain('/federation/email')
    expect(stub.store.get(`identity:human:ms:${ZEBRA_TID}:${ZEBRA_OID}`)).toBeUndefined()
  })
})

// ── GET /federation/email ─────────────────────────────────────────────────

describe('GET /federation/email', () => {
  it('renders the code page and names the tenant policy without calling it an error', async () => {
    const res = await get(makeApp(), '/federation/email?reason=consent-required&continue=/deck', makeEnv(makeStub()))
    expect(res.status).toBe(200)
    const html = await res.text()
    expect(html).toContain('Verify your email')
    expect(html).toContain('sign-in policy blocks apps it hasn')
    expect(html).toContain('pre-approved')
    expect(html.toLowerCase()).not.toContain('<h1>error')
  })

  it('offers the Microsoft path back when it is configured', async () => {
    const html = await (await get(makeApp(), '/federation/email', makeEnv(makeStub()))).text()
    expect(html).toContain('/federation/microsoft/start')
  })

  it('hides the Microsoft path when it is not configured', async () => {
    const env = makeEnv(makeStub(), { MICROSOFT_CLIENT_ID: undefined })
    const html = await (await get(makeApp(), '/federation/email', env)).text()
    expect(html).not.toContain('/federation/microsoft/start')
  })

  it('escapes a hostile prefill rather than reflecting it into the page', async () => {
    const html = await (
      await get(makeApp(), '/federation/email?email=' + encodeURIComponent('"><script>alert(1)</script>@x.com'), makeEnv(makeStub()))
    ).text()
    expect(html).not.toContain('<script>alert(1)</script>')
  })
})

// ── POST /federation/email/send ───────────────────────────────────────────

describe('POST /federation/email/send', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })
  afterEach(() => vi.restoreAllMocks())

  it('sends a code through WorkOS Magic Auth', async () => {
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({ id: 'ma_1' }), { headers: { 'Content-Type': 'application/json' } }))
    const res = await postJson(makeApp(), '/federation/email/send', { email: 'alice@zebra.com' }, makeEnv(makeStub()))
    expect(res.status).toBe(200)
    expect(mockFetch.mock.calls[0][0]).toBe('https://api.workos.com/user_management/magic_auth')
  })

  it('rejects a malformed address before touching the transport', async () => {
    const res = await postJson(makeApp(), '/federation/email/send', { email: 'not-an-email' }, makeEnv(makeStub()))
    expect(res.status).toBe(400)
    expect(mockFetch).not.toHaveBeenCalled()
  })

  it('throttles repeated sends to the same mailbox', async () => {
    mockFetch.mockResolvedValue(new Response('{}', { headers: { 'Content-Type': 'application/json' } }))
    const app = makeApp()
    const env = makeEnv(makeStub())
    for (let i = 0; i < 5; i++) {
      expect((await postJson(app, '/federation/email/send', { email: 'alice@zebra.com' }, env)).status).toBe(200)
    }
    expect((await postJson(app, '/federation/email/send', { email: 'alice@zebra.com' }, env)).status).toBe(429)
  })

  it('503s when no email transport is configured', async () => {
    const env = makeEnv(makeStub(), { WORKOS_API_KEY: undefined })
    const res = await postJson(makeApp(), '/federation/email/send', { email: 'alice@zebra.com' }, env)
    expect(res.status).toBe(503)
  })
})

// ── POST /federation/email/verify ─────────────────────────────────────────

describe('POST /federation/email/verify', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })
  afterEach(() => vi.restoreAllMocks())

  it('verifies the code, writes an email-code identity at L1, and sets the cookie', async () => {
    mockFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ user: { id: 'user_01H', first_name: 'Alice', last_name: 'Anders' } }), {
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    const stub = makeStub()
    const env = makeEnv(stub)
    const res = await postJson(
      makeApp(),
      '/federation/email/verify',
      { email: 'Alice@Zebra.com', code: '123456', continue: '/deck' },
      env,
    )

    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.ok).toBe(true)
    expect(body.continue).toBe('/deck')
    expect(body.assurance).toBe('email-code')

    const row = stub.store.get('identity:human:email:alice@zebra.com') as any
    expect(row.federation.assurance).toBe('email-code')
    expect(row.federation.emailDomain).toBe('zebra.com')
    // L1, not L2 — lower assurance, lower ceiling, written down.
    expect(row.level).toBe(1)

    const cookies = res.headers.getSetCookie()
    const jwt = cookies.find((c) => c.startsWith('auth='))!.split(';')[0]!.slice('auth='.length)
    const claims = jose.decodeJwt(jwt)
    expect(`human:${claims.sub}`).toBe('human:email:alice@zebra.com')
    expect((claims.fed as any).assurance).toBe('email-code')
  })

  it('401s on a wrong code without minting anything', async () => {
    mockFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ code: 'invalid_one_time_code' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    const stub = makeStub()
    const res = await postJson(makeApp(), '/federation/email/verify', { email: 'alice@zebra.com', code: '000000' }, makeEnv(stub))
    expect(res.status).toBe(401)
    expect(stub.store.get('identity:human:email:alice@zebra.com')).toBeUndefined()
  })

  it('rejects a non-6-digit code before touching the transport', async () => {
    const res = await postJson(makeApp(), '/federation/email/verify', { email: 'alice@zebra.com', code: 'abc' }, makeEnv(makeStub()))
    expect(res.status).toBe(400)
    expect(mockFetch).not.toHaveBeenCalled()
  })

  it('refuses an off-site continue URL', async () => {
    mockFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ user: { id: 'user_01H' } }), { headers: { 'Content-Type': 'application/json' } }),
    )
    const res = await postJson(
      makeApp(),
      '/federation/email/verify',
      { email: 'alice@zebra.com', code: '123456', continue: 'https://evil.example/x' },
      makeEnv(makeStub()),
    )
    expect(((await res.json()) as any).continue).toBe('/')
  })
})
