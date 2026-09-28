/**
 * Relying-party fixes surfaced by api.sb's integration (StartupsStudio/sb):
 *
 *   1. A registered (DCR) client receives exactly the `state` it sent, through
 *      the full authorize → login → consent → redirect flow (it used to receive
 *      base64url({csrf, s})).
 *   2. /login?continue= is no longer an open redirect.
 *   3. The id_token and userinfo say how the person signed in (amr, idp,
 *      auth_time) and the id_token carries email_verified.
 *   4. POST /api/magic-link: WorkOS Magic Auth sign-in for relying parties
 *      (callers: service bindings and the clients MAGIC_LINK_CLIENTS lists).
 *
 * Runs the real worker in-process (SELF, real IdentityDO + KV); only WorkOS is
 * faked (fetchMock).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock, env } from 'cloudflare:test'
import { describeWorkOSSignIn } from '../src/sdk/workos/upstream'

const BASE = 'https://id.org.ai'
const WORKOS = 'https://api.workos.com'
const RP_REDIRECT = 'https://rp.example/cb'

// ── helpers ──────────────────────────────────────────────────────────────────

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

async function pkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)))
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return { verifier, challenge: b64url(new Uint8Array(hash)) }
}

function decodeJwt(jwt: string): Record<string, any> {
  const part = jwt.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/')
  return JSON.parse(atob(part + '='.repeat((4 - (part.length % 4)) % 4)))
}

function decodeState(state: string): Record<string, any> {
  const padded = state.replace(/-/g, '+').replace(/_/g, '/')
  return JSON.parse(atob(padded + '='.repeat((4 - (padded.length % 4)) % 4)))
}

/** name=value pairs from a response's Set-Cookie headers. */
function setCookies(res: Response): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(';')
    const i = pair!.indexOf('=')
    out[pair!.slice(0, i).trim()] = pair!.slice(i + 1)
  }
  return out
}

function cookieHeader(cookies: Record<string, string>): string {
  return Object.entries(cookies)
    .filter(([, v]) => v !== '')
    .map(([k, v]) => `${k}=${v}`)
    .join('; ')
}

async function register(meta: Record<string, unknown>): Promise<{ client_id: string; client_secret?: string }> {
  const res = await SELF.fetch(`${BASE}/oauth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(meta),
  })
  expect(res.status).toBe(201)
  return (await res.json()) as { client_id: string; client_secret?: string }
}

let workosUserSeq = 0
/** Queue one WorkOS authenticate answer (single use). */
function mockWorkOSAuthenticate(user: { id: string; email: string }, authenticationMethod?: string, check?: (body: URLSearchParams) => boolean) {
  fetchMock
    .get(WORKOS)
    .intercept({
      method: 'POST',
      path: '/user_management/authenticate',
      ...(check ? { body: (b: string) => check(new URLSearchParams(b)) } : {}),
    })
    .reply(
      200,
      JSON.stringify({
        access_token: 'at_opaque_workos',
        refresh_token: 'rt_workos',
        user: { ...user, first_name: 'Ada', last_name: 'Lovelace' },
        organization_id: 'org_01TEST',
        ...(authenticationMethod ? { authentication_method: authenticationMethod } : {}),
      }),
      { headers: { 'content-type': 'application/json' } },
    )
}

/** Sign in through /login?provider=… → (fake) WorkOS → /api/callback. Returns the id.org.ai cookies. */
async function signIn(opts: { provider?: string; method?: string; continueUrl?: string } = {}): Promise<{ cookies: Record<string, string>; location: string; userId: string }> {
  const userId = `user_01RP${++workosUserSeq}`
  const qs = new URLSearchParams({ provider: opts.provider ?? 'GitHubOAuth' })
  if (opts.continueUrl) qs.set('continue', opts.continueUrl)
  const login = await SELF.fetch(`${BASE}/login?${qs}`, { redirect: 'manual' })
  expect(login.status).toBe(302)
  const state = new URL(login.headers.get('location')!).searchParams.get('state')!
  mockWorkOSAuthenticate({ id: userId, email: `${userId.toLowerCase()}@example.com` }, opts.method ?? 'GitHubOAuth')
  const cb = await SELF.fetch(`${BASE}/api/callback?code=wos_code&state=${encodeURIComponent(state)}`, { redirect: 'manual' })
  expect(cb.status).toBe(302)
  const cookies = setCookies(cb)
  expect(cookies.auth).toBeTruthy()
  return { cookies: { auth: cookies.auth! }, location: cb.headers.get('location')!, userId }
}

function authorizeUrl(clientId: string, challenge: string, state: string, extra: Record<string, string> = {}): string {
  const u = new URL(`${BASE}/oauth/authorize`)
  for (const [k, v] of Object.entries({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: RP_REDIRECT,
    scope: 'openid profile email offline_access',
    state,
    nonce: 'n-0S6_WzA2Mj',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...extra,
  }))
    u.searchParams.set(k, v)
  return u.toString()
}

/** Parse the consent page's hidden form fields. */
function consentFields(html: string): Record<string, string> {
  const fields: Record<string, string> = {}
  for (const m of html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)) {
    fields[m[1]!] = m[2]!.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
  }
  return fields
}

beforeAll(() => {
  fetchMock.activate()
  fetchMock.disableNetConnect()
  // Profile / org enrichment: the callback null-falls-back on failure.
  fetchMock.get(WORKOS).intercept({ path: /^\/user_management\/users\// }).reply(500, '').persist()
  fetchMock.get(WORKOS).intercept({ path: /^\/organizations\// }).reply(500, '').persist()
})

afterAll(() => {
  fetchMock.deactivate()
})

// ── 1. state round-trip ───────────────────────────────────────────────────────

describe('fix 1: a registered client receives exactly the state it sent', () => {
  it('full authorize → login → consent → redirect → token → userinfo', async () => {
    const client = await register({
      client_name: 'RP test',
      redirect_uris: [RP_REDIRECT],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      scope: 'openid profile email offline_access',
    })
    const { verifier, challenge } = await pkce()
    const STATE = 'rp-state_AbC123-xyz'
    const url = authorizeUrl(client.client_id, challenge, STATE, { login_hint: 'ada@example.com' })

    // Not signed in: sent to /login, carrying the ORIGINAL state inside continue and the login_hint.
    const r1 = await SELF.fetch(url, { redirect: 'manual' })
    expect(r1.status).toBe(302)
    const toLogin = new URL(r1.headers.get('location')!)
    expect(toLogin.pathname).toBe('/login')
    expect(toLogin.searchParams.get('login_hint')).toBe('ada@example.com')
    const cont = toLogin.searchParams.get('continue')!
    expect(new URL(cont).searchParams.get('state')).toBe(STATE)

    // /login forwards login_hint to WorkOS.
    const loginRes = await SELF.fetch(`${BASE}/login?provider=authkit&continue=${encodeURIComponent(cont)}&login_hint=ada%40example.com`, { redirect: 'manual' })
    expect(new URL(loginRes.headers.get('location')!).searchParams.get('login_hint')).toBe('ada@example.com')

    // Sign in (GitHub via WorkOS) and come back to the authorize URL.
    const { cookies, location } = await signIn({ continueUrl: cont })
    expect(location).toBe(cont)

    // Authorize again, signed in: the consent page.
    const r2 = await SELF.fetch(location, { redirect: 'manual', headers: { cookie: cookieHeader(cookies) } })
    expect(r2.status).toBe(200)
    const html = await r2.text()
    const csrfCookie = setCookies(r2).__csrf!
    expect(csrfCookie).toBeTruthy()
    const fields = consentFields(html)
    expect(fields.state).not.toBe(STATE) // wrapped for the CSRF check inside the form …

    // Approve.
    const form = new URLSearchParams({ ...fields, approved: 'true' })
    const r3 = await SELF.fetch(`${BASE}/oauth/authorize`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader({ ...cookies, __csrf: csrfCookie }) },
      body: form.toString(),
    })
    expect(r3.status).toBe(302)
    const back = new URL(r3.headers.get('location')!)
    expect(`${back.origin}${back.pathname}`).toBe(RP_REDIRECT)
    expect(back.searchParams.get('state')).toBe(STATE) // … and unwrapped on the way out
    const code = back.searchParams.get('code')!
    expect(code).toMatch(/^ac_/)

    // Consent on record: the next authorize issues a code directly, state still verbatim.
    const again = await SELF.fetch(authorizeUrl(client.client_id, challenge, 'second-state'), { redirect: 'manual', headers: { cookie: cookieHeader(cookies) } })
    expect(again.status).toBe(302)
    expect(new URL(again.headers.get('location')!).searchParams.get('state')).toBe('second-state')

    // Token: id_token says how they signed in and that the email is verified.
    const tok = await SELF.fetch(`${BASE}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: RP_REDIRECT, code_verifier: verifier, client_id: client.client_id }).toString(),
    })
    expect(tok.status).toBe(200)
    const tokens = (await tok.json()) as { access_token: string; refresh_token: string; id_token: string }
    const idToken = decodeJwt(tokens.id_token)
    expect(idToken.amr).toEqual(['oauth'])
    expect(idToken.idp).toBe('github')
    expect(idToken.email_verified).toBe(true)
    expect(typeof idToken.auth_time).toBe('number')
    expect(idToken.nonce).toBe('n-0S6_WzA2Mj')

    // Userinfo carries the same.
    const ui = await SELF.fetch(`${BASE}/oauth/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } })
    const info = (await ui.json()) as Record<string, unknown>
    expect(info.amr).toEqual(['oauth'])
    expect(info.idp).toBe('github')
    expect(info.email_verified).toBe(true)

    // Refresh keeps it.
    const ref = await SELF.fetch(`${BASE}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: client.client_id }).toString(),
    })
    const refreshed = (await ref.json()) as { id_token: string }
    expect(decodeJwt(refreshed.id_token).idp).toBe('github')
  })

  it('a denied consent also returns the original state', async () => {
    const client = await register({ client_name: 'RP deny', redirect_uris: [RP_REDIRECT], token_endpoint_auth_method: 'none' })
    const { challenge } = await pkce()
    const { cookies } = await signIn()
    const page = await SELF.fetch(authorizeUrl(client.client_id, challenge, 'deny-state'), { headers: { cookie: cookieHeader(cookies) } })
    const csrf = setCookies(page).__csrf!
    const fields = consentFields(await page.text())
    const res = await SELF.fetch(`${BASE}/oauth/authorize`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader({ ...cookies, __csrf: csrf }) },
      body: new URLSearchParams({ ...fields, approved: 'false' }).toString(),
    })
    const loc = new URL(res.headers.get('location')!)
    expect(loc.searchParams.get('error')).toBe('access_denied')
    expect(loc.searchParams.get('state')).toBe('deny-state')
  })

  it('still refuses a consent POST without the CSRF cookie', async () => {
    const client = await register({ client_name: 'RP csrf', redirect_uris: [RP_REDIRECT], token_endpoint_auth_method: 'none' })
    const { challenge } = await pkce()
    const { cookies } = await signIn()
    const page = await SELF.fetch(authorizeUrl(client.client_id, challenge, 's'), { headers: { cookie: cookieHeader(cookies) } })
    const fields = consentFields(await page.text())
    const res = await SELF.fetch(`${BASE}/oauth/authorize`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(cookies) },
      body: new URLSearchParams({ ...fields, approved: 'true' }).toString(),
    })
    expect(res.status).toBe(403)
  })
})

// ── 2. open redirect ──────────────────────────────────────────────────────────

/** The continue URL /login would use, read back from the state it hands WorkOS. */
async function loginContinue(cont: string, extra = ''): Promise<string> {
  const res = await SELF.fetch(`${BASE}/login?provider=GitHubOAuth&continue=${encodeURIComponent(cont)}${extra}`, { redirect: 'manual' })
  expect(res.status).toBe(302)
  return decodeState(new URL(res.headers.get('location')!).searchParams.get('state')!).continue
}

describe('fix 2: /login?continue= is not an open redirect', () => {
  const refused = [
    '//evil.com',
    '//evil.com/path',
    '/\\evil.com',
    '\\\\evil.com',
    '/\t/evil.com',
    '\t//evil.com',
    ' //evil.com',
    'https://evil.com',
    'https://evil.com/login?continue=/',
    'HTTPS://EVIL.COM',
    'http://evil.com',
    'https://id.org.ai.evil.com',
    'https://id.org.ai@evil.com',
    'https://evil.com@id.org.ai',
    'https://evil.com%2F@id.org.ai',
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    'java\nscript:alert(1)',
    'javascript%3Aalert(1)',
    'data:text/html,<script>alert(1)</script>',
    '%2F%2Fevil.com',
    '%2f%2fevil.com',
    'https%3A%2F%2Fevil.com',
    'ftp://evil.com',
  ]
  for (const target of refused) {
    it(`refuses ${JSON.stringify(target)}`, async () => {
      expect(await loginContinue(target)).toBe('/dash/profile')
    })
  }

  // A scheme-relative "https:evil.com" is a PATH relative to the current origin
  // (WHATWG URL, as a browser resolves a Location header): it stays on id.org.ai.
  for (const target of ['https:evil.com', 'https:/evil.com']) {
    it(`keeps ${JSON.stringify(target)} on id.org.ai`, async () => {
      expect(new URL(await loginContinue(target), BASE).origin).toBe(BASE)
    })
  }

  it('refuses a double-encoded //evil.com passed through the query', async () => {
    // continue=%252F%252Fevil.com → the handler sees "%2F%2Fevil.com"
    const res = await SELF.fetch(`${BASE}/login?provider=GitHubOAuth&continue=%252F%252Fevil.com`, { redirect: 'manual' })
    expect(decodeState(new URL(res.headers.get('location')!).searchParams.get('state')!).continue).toBe('/dash/profile')
  })

  it('refuses via the redirect_uri alias too', async () => {
    const res = await SELF.fetch(`${BASE}/login?provider=GitHubOAuth&redirect_uri=${encodeURIComponent('https://evil.com')}`, { redirect: 'manual' })
    expect(decodeState(new URL(res.headers.get('location')!).searchParams.get('state')!).continue).toBe('/dash/profile')
  })

  const accepted = [
    '/dash/keys',
    '/oauth/authorize?client_id=x&state=y',
    'https://id.org.ai/device?user_code=ABCD',
    'https://auth.org.ai/anything',
    'https://oauth.do/x',
    'https://startup.games/after-login', // TRUSTED_ACCOUNT_DOMAINS
  ]
  for (const target of accepted) {
    it(`accepts ${target}`, async () => {
      expect(await loginContinue(target)).toBe(target)
    })
  }

  it("accepts a registered client's redirect origin, and nothing else on that host's neighbours", async () => {
    await register({ client_name: 'Waitlist', redirect_uris: ['https://waitlist.example/auth/cb'], token_endpoint_auth_method: 'none' })
    expect(await loginContinue('https://waitlist.example/welcome')).toBe('https://waitlist.example/welcome')
    expect(await loginContinue('https://evil.waitlist.example/welcome')).toBe('/dash/profile')
    expect(await loginContinue('http://waitlist.example/welcome')).toBe('/dash/profile')
  })

  it('accepts a client registered before the origin index existed (one-time backfill)', async () => {
    const oauth = env.IDENTITY.get(env.IDENTITY.idFromName('oauth')) as unknown as { oauthStorageOp(op: unknown): Promise<unknown> }
    await oauth.oauthStorageOp({
      op: 'put',
      key: 'client:cid_legacy',
      value: { id: 'cid_legacy', name: 'Legacy', redirectUris: ['https://legacy.example/cb'], grantTypes: ['authorization_code'], responseTypes: ['code'], scopes: ['openid'], trusted: false, tokenEndpointAuthMethod: 'none', createdAt: 0 },
    })
    expect(await loginContinue('https://legacy.example/home')).toBe('https://legacy.example/home')
  })

  it('an already signed-in visitor is not bounced off-site either', async () => {
    const { cookies } = await signIn()
    const res = await SELF.fetch(`${BASE}/login?continue=${encodeURIComponent('https://evil.com/x')}`, { redirect: 'manual', headers: { cookie: cookieHeader(cookies) } })
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toBe(`${BASE}/dash/profile`)
  })

  it('the provider picker links carry only the safe fallback', async () => {
    const res = await SELF.fetch(`${BASE}/login?continue=${encodeURIComponent('https://evil.com')}`)
    const html = await res.text()
    expect(html).not.toContain('evil.com')
  })
})

// ── 3. amr / idp mapping ──────────────────────────────────────────────────────

describe('fix 3: sign-in method (amr / idp)', () => {
  it('maps WorkOS authentication methods', () => {
    expect(describeWorkOSSignIn('GitHubOAuth', 'authkit')).toEqual({ amr: ['oauth'], idp: 'github' })
    expect(describeWorkOSSignIn('GoogleOAuth', 'GoogleOAuth')).toEqual({ amr: ['oauth'], idp: 'google' })
    expect(describeWorkOSSignIn('MicrosoftOAuth', undefined)).toEqual({ amr: ['oauth'], idp: 'microsoft' })
    expect(describeWorkOSSignIn('AppleOAuth', undefined)).toEqual({ amr: ['oauth'], idp: 'apple' })
    expect(describeWorkOSSignIn('MagicAuth', 'authkit')).toEqual({ amr: ['email_otp'], idp: 'authkit' })
    expect(describeWorkOSSignIn('MagicAuth', 'magic_link')).toEqual({ amr: ['magic_link'], idp: 'magic_link' })
    expect(describeWorkOSSignIn('Password', 'authkit')).toEqual({ amr: ['pwd'], idp: 'authkit' })
    expect(describeWorkOSSignIn('SSO', 'authkit')).toEqual({ amr: ['sso'], idp: 'authkit' })
    // WorkOS silent: fall back to what we asked for
    expect(describeWorkOSSignIn(undefined, 'GoogleOAuth')).toEqual({ amr: ['oauth'], idp: 'google' })
    expect(describeWorkOSSignIn(undefined, 'authkit')).toEqual({ idp: 'authkit' })
    expect(describeWorkOSSignIn(undefined, undefined)).toEqual({})
  })

  it('the session cookie carries amr / idp / auth_time from WorkOS (Google via AuthKit)', async () => {
    const { cookies } = await signIn({ provider: 'authkit', method: 'GoogleOAuth' })
    const claims = decodeJwt(cookies.auth!)
    expect(claims.amr).toEqual(['oauth'])
    expect(claims.idp).toBe('google')
    expect(typeof claims.auth_time).toBe('number')
  })

  it('an AuthKit email code is reported as email_otp via authkit', async () => {
    const { cookies } = await signIn({ provider: 'authkit', method: 'MagicAuth' })
    const claims = decodeJwt(cookies.auth!)
    expect(claims.amr).toEqual(['email_otp'])
    expect(claims.idp).toBe('authkit')
  })

  it('discovery advertises the new claims', async () => {
    const res = await SELF.fetch(`${BASE}/.well-known/openid-configuration`)
    const doc = (await res.json()) as { claims_supported: string[] }
    expect(doc.claims_supported).toEqual(expect.arrayContaining(['amr', 'idp', 'auth_time', 'email_verified']))
  })
})

// ── 4. magic link ─────────────────────────────────────────────────────────────

const WAITLIST_CB = 'https://waitlist.example/auth/cb'

let magicLinkClientSeq = 0
/**
 * A confidential client listed in MAGIC_LINK_CLIENTS (vitest.config.ts lists
 * cid_magiclink_test_01..20). Registration hands out random ids, so the test
 * stores the record a registration would under the next listed id.
 */
async function confidentialClient(): Promise<{ id: string; secret: string; basic: string }> {
  const id = `cid_magiclink_test_${String(++magicLinkClientSeq).padStart(2, '0')}`
  const secret = `cs_${crypto.randomUUID().replace(/-/g, '')}`
  const oauth = env.IDENTITY.get(env.IDENTITY.idFromName('oauth')) as unknown as {
    oauthStorageOp(op: { op: 'put'; key: string; value: unknown }): Promise<unknown>
  }
  await oauth.oauthStorageOp({
    op: 'put',
    key: `client:${id}`,
    value: {
      id,
      name: 'Startup waitlist',
      secret,
      redirectUris: [WAITLIST_CB],
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      scopes: ['openid', 'profile', 'email'],
      trusted: false,
      tokenEndpointAuthMethod: 'client_secret_basic',
      createdAt: Date.now(),
    },
  })
  return { id, secret, basic: `Basic ${btoa(`${id}:${secret}`)}` }
}

function mockMagicAuthCreate(status = 201, onEmail?: (email: string) => void) {
  fetchMock
    .get(WORKOS)
    .intercept({
      method: 'POST',
      path: '/user_management/magic_auth',
      body: (b: string) => {
        onEmail?.(JSON.parse(b).email)
        return true
      },
    })
    .reply(status, status < 300 ? JSON.stringify({ id: 'magic_auth_01', user_id: 'user_01X', email: 'x', code: '123456', expires_at: new Date(Date.now() + 600_000).toISOString() }) : '{"code":"x"}', {
      headers: { 'content-type': 'application/json' },
    })
}

async function sendMagicLink(body: Record<string, unknown>, headers: Record<string, string> = {}, base = BASE): Promise<Response> {
  return SELF.fetch(`${base}/api/magic-link`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  })
}

describe('fix 4: POST /api/magic-link', () => {
  it('refuses callers that are not a confidential client or a service binding', async () => {
    const c = await confidentialClient()
    const pub = await register({ client_name: 'public', redirect_uris: [WAITLIST_CB], token_endpoint_auth_method: 'none' })
    const body = { email: 'ada@example.com', continue: '/dash/profile' }

    expect((await sendMagicLink(body)).status).toBe(401)
    expect((await sendMagicLink({ ...body, client_id: c.id })).status).toBe(401)
    expect((await sendMagicLink({ ...body, client_id: c.id, client_secret: 'cs_wrong' })).status).toBe(401)
    expect((await sendMagicLink({ ...body, client_id: pub.client_id })).status).toBe(401)
    // A spoofed X-Issuer on a public host is not a service binding.
    expect((await sendMagicLink(body, { 'x-issuer': 'https://internal.example' })).status).toBe(401)
  })

  it('sends, answers the same for any address, and never leaks the code', async () => {
    const c = await confidentialClient()
    const sentTo: string[] = []
    mockMagicAuthCreate(201, (e) => sentTo.push(e))
    const r1 = await sendMagicLink({ email: 'New.Person@Example.com', continue: 'https://waitlist.example/welcome', client_id: c.id }, { authorization: c.basic })
    expect(r1.status).toBe(202)
    const j1 = (await r1.json()) as Record<string, unknown>
    expect(new Set(sentTo)).toEqual(new Set(['new.person@example.com']))
    expect(j1.sent).toBe(true)
    expect(j1.verify_url).toMatch(/^https:\/\/id\.org\.ai\/magic-link\/[0-9a-f]{48}$/)
    expect(JSON.stringify(j1)).not.toContain('123456')
    expect(JSON.stringify(j1)).not.toContain('user_01X')

    // WorkOS refuses this address (4xx): the caller sees exactly the same shape.
    mockMagicAuthCreate(422)
    const r2 = await sendMagicLink({ email: 'someone@example.com', continue: '/dash/profile', client_id: c.id, client_secret: c.secret })
    expect(r2.status).toBe(202)
    expect(Object.keys((await r2.json()) as object).sort()).toEqual(Object.keys(j1).sort())
  })

  it('validates continue like /login', async () => {
    const c = await confidentialClient()
    for (const bad of ['https://evil.com', '//evil.com', 'javascript:alert(1)']) {
      const r = await sendMagicLink({ email: 'a@example.com', continue: bad, client_id: c.id }, { authorization: c.basic })
      expect(r.status).toBe(400)
    }
  })

  it('rate-limits per email', async () => {
    const c = await confidentialClient()
    for (let i = 0; i < 5; i++) {
      mockMagicAuthCreate()
      expect((await sendMagicLink({ email: 'busy@example.com', client_id: c.id }, { authorization: c.basic })).status).toBe(202)
    }
    const r = await sendMagicLink({ email: 'BUSY@example.com', client_id: c.id }, { authorization: c.basic })
    expect(r.status).toBe(429)
    expect(Number(r.headers.get('retry-after'))).toBeGreaterThan(0)
  })

  it('rate-limits per client', async () => {
    const c = await confidentialClient()
    for (let i = 0; i < 100; i++) {
      mockMagicAuthCreate()
      expect((await sendMagicLink({ email: `p${i}@example.com`, client_id: c.id }, { authorization: c.basic })).status).toBe(202)
    }
    expect((await sendMagicLink({ email: 'p100@example.com', client_id: c.id }, { authorization: c.basic })).status).toBe(429)
  })

  it('a service binding may send without a secret', async () => {
    mockMagicAuthCreate()
    const r = await sendMagicLink({ email: 'bound@example.com', continue: 'https://internal.example/after' }, {}, 'https://internal.example')
    expect(r.status).toBe(202)
  })

  it('clicking through signs the person in (L2, amr magic_link) and continues; the flow works once', async () => {
    const c = await confidentialClient()
    mockMagicAuthCreate()
    const sent = (await (await sendMagicLink({ email: 'grace@example.com', continue: 'https://waitlist.example/welcome', client_id: c.id }, { authorization: c.basic })).json()) as { verify_url: string }
    const path = new URL(sent.verify_url).pathname

    const pageRes = await SELF.fetch(`${BASE}${path}?code=654321`)
    expect(pageRes.status).toBe(200)
    const html = await pageRes.text()
    expect(html).toContain('value="654321"')
    expect(html).not.toContain('grace@example.com') // masked
    const flowCookie = setCookies(pageRes).__mlf!

    // Without the browser-bound cookie: refused.
    const noCookie = await SELF.fetch(`${BASE}${path}`, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'code=654321' })
    expect(noCookie.status).toBe(403)

    mockWorkOSAuthenticate({ id: 'user_01GRACE', email: 'grace@example.com' }, 'MagicAuth', (b) =>
      b.get('grant_type') === 'urn:workos:oauth:grant-type:magic-auth:code' && b.get('code') === '654321' && b.get('email') === 'grace@example.com',
    )
    const done = await SELF.fetch(`${BASE}${path}`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `__mlf=${flowCookie}` },
      body: 'code=654321',
    })
    expect(done.status).toBe(302)
    expect(done.headers.get('location')).toBe('https://waitlist.example/welcome')
    const session = decodeJwt(setCookies(done).auth!)
    expect(session.sub).toBe('user_01GRACE')
    expect(session.amr).toEqual(['magic_link'])
    expect(session.idp).toBe('magic_link')

    // The identity is L2 (claimed).
    const who = env.IDENTITY.get(env.IDENTITY.idFromName('human:user_01GRACE')) as unknown as { getIdentity(id: string): Promise<{ level: number; verified: boolean } | null> }
    const identity = await who.getIdentity('human:user_01GRACE')
    expect(identity?.level).toBe(2)
    expect(identity?.verified).toBe(true)

    // Single use.
    const reuse = await SELF.fetch(`${BASE}${path}`)
    expect(reuse.status).toBe(410)
  })

  it('a wrong code keeps the flow for a retry, and five wrong codes end it', async () => {
    const c = await confidentialClient()
    mockMagicAuthCreate()
    const sent = (await (await sendMagicLink({ email: 'guess@example.com', client_id: c.id }, { authorization: c.basic })).json()) as { verify_url: string }
    const path = new URL(sent.verify_url).pathname
    const flowCookie = setCookies(await SELF.fetch(`${BASE}${path}`)).__mlf!
    for (let i = 0; i < 5; i++) {
      fetchMock.get(WORKOS).intercept({ method: 'POST', path: '/user_management/authenticate' }).reply(400, '{"code":"invalid_one_time_code"}')
      const r = await SELF.fetch(`${BASE}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `__mlf=${flowCookie}` },
        body: `code=00000${i}`,
      })
      expect(r.status).toBe(i < 4 ? 400 : 410)
    }
    expect((await SELF.fetch(`${BASE}${path}`)).status).toBe(410)
  })

  it('an unknown or malformed flow is an expired link', async () => {
    expect((await SELF.fetch(`${BASE}/magic-link/${'a'.repeat(48)}`)).status).toBe(410)
    expect((await SELF.fetch(`${BASE}/magic-link/not-a-flow`)).status).toBe(410)
  })
})
