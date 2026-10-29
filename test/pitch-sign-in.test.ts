/**
 * pitch.startups.studio's sign-in (the Fund I deck), end to end through the
 * real worker (SELF, real IdentityDO + KV); only WorkOS is faked. The deck asks
 * for the email or Google on its own page; id.org.ai shows no picker and no
 * consent, only the code screen (1b) for email, with WorkOS's 6-digit code.
 *
 *   1. The deck's hosts are trusted-account hosts: a signed-in person gets the
 *      code straight back, with no consent page.
 *   2. provider=email + login_hint: WorkOS sends the code, 1b, then the code
 *      goes back to the deck.
 *   3. provider=GoogleOAuth: straight to Google through WorkOS, and back.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock, env } from 'cloudflare:test'
import { authService } from './helpers/auth-service'
import { parseTrustedAccountDomains, TRUSTED_ACCOUNT_CLIENT_ID } from '../worker/routes/oauth'
import { continueOrigins } from '../worker/routes/login-email'

const BASE = 'https://id.org.ai'
const WORKOS = 'https://api.workos.com'
const PITCH = 'https://pitch.startups.studio'
const PREVIEW = 'https://pitch-startups-studio-preview.metad.workers.dev'

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

async function pkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)))
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return { verifier, challenge: b64url(new Uint8Array(hash)) }
}

function setCookies(res: Response): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(';')
    const i = pair!.indexOf('=')
    out[pair!.slice(0, i).trim()] = pair!.slice(i + 1)
  }
  return out
}

const cookieHeader = (cookies: Record<string, string>) =>
  Object.entries(cookies)
    .filter(([, v]) => v !== '')
    .map(([k, v]) => `${k}=${v}`)
    .join('; ')

function authorizeUrl(origin: string, challenge: string, extra: Record<string, string> = {}): string {
  const u = new URL(`${BASE}/oauth/authorize`)
  u.search = new URLSearchParams({
    response_type: 'code',
    client_id: TRUSTED_ACCOUNT_CLIENT_ID,
    redirect_uri: `${origin}/auth/callback`,
    scope: 'openid profile email',
    state: 'deck-state',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...extra,
  }).toString()
  return u.toString()
}

/** Count WorkOS Magic Auth sends to one address (each succeeds). */
function mockSends(email: string): { n: number } {
  const calls = { n: 0 }
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'POST', path: '/user_management/magic_auth', body: (b: string) => JSON.parse(b).email === email })
    .reply(() => {
      calls.n++
      return { statusCode: 201, data: JSON.stringify({ id: `magic_auth_${calls.n}` }), responseOptions: { headers: { 'content-type': 'application/json' } } }
    })
    .persist()
  return calls
}

/** WorkOS magic-auth:code checks for `email`: right when the code is `right`; counted. */
function mockCodeCheck(email: string, right: string, userId: string): { n: number } {
  const calls = { n: 0 }
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'POST', path: '/user_management/authenticate', body: (b: string) => new URLSearchParams(b).get('email') === email })
    .reply((opts) => {
      calls.n++
      const code = new URLSearchParams(String(opts.body)).get('code')
      if (code !== right) return { statusCode: 400, data: '{"code":"invalid_one_time_code"}' }
      return {
        statusCode: 200,
        data: JSON.stringify({
          access_token: 'at_opaque_workos',
          refresh_token: 'rt_workos',
          user: { id: userId, email, first_name: 'Lee', last_name: 'Partner', email_verified: true },
          organization_id: 'org_01PITCH',
          authentication_method: 'MagicAuth',
        }),
        responseOptions: { headers: { 'content-type': 'application/json' } },
      }
    })
    .persist()
  return calls
}

/** The deck's "Email me a code": authorize with provider=email → /login → 1b. The flow's 303 and cookies. */
async function startEmail(origin: string, email: string, challenge: string) {
  const r1 = await SELF.fetch(authorizeUrl(origin, challenge, { provider: 'email', login_hint: email }), { redirect: 'manual' })
  expect(r1.status).toBe(302)
  const login = new URL(r1.headers.get('location')!)
  const r2 = await SELF.fetch(login.toString(), { redirect: 'manual' })
  return { login, r2, cookies: setCookies(r2) }
}

const enterCode = (path: string, cookies: Record<string, string>, code: string) =>
  SELF.fetch(`${BASE}${path}`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(cookies) },
    body: code.split('').map((d) => `code=${d}`).join('&'),
  })

beforeAll(() => {
  fetchMock.activate()
  fetchMock.disableNetConnect()
  fetchMock.get(WORKOS).intercept({ path: /^\/user_management\/users\// }).reply(500, '').persist()
  fetchMock.get(WORKOS).intercept({ path: /^\/organizations\// }).reply(500, '').persist()
})

afterAll(() => {
  fetchMock.deactivate()
})

describe('the deck’s hosts are trusted-account hosts', () => {
  it('lists the production and preview hosts', () => {
    const hosts = parseTrustedAccountDomains(env.TRUSTED_ACCOUNT_DOMAINS)
    expect(hosts.has('pitch.startups.studio')).toBe(true)
    expect(hosts.has('pitch-startups-studio-preview.metad.workers.dev')).toBe(true)
    expect(hosts.has('startup.games')).toBe(true)
  })
})

describe('email: WorkOS’s code, and only the code screen', () => {
  it('provider=email → WorkOS sends the code → 1b → right code → a code for the deck, no consent → tokens → userinfo', async () => {
    const email = 'lee@fund-one.example'
    const sends = mockSends(email)
    const { verifier, challenge } = await pkce()

    const { login, r2, cookies } = await startEmail(PREVIEW, email, challenge)
    expect(login.pathname).toBe('/login')
    expect(login.searchParams.get('provider')).toBe('email')
    expect(login.searchParams.get('prompt')).toBe('login')
    expect(login.searchParams.get('login_hint')).toBe(email)
    const cont = login.searchParams.get('continue')!
    expect(new URL(cont).searchParams.has('provider')).toBe(false)

    // no picker, no email form: straight to the code screen, the code already sent
    expect(r2.status).toBe(303)
    const codePath = r2.headers.get('location')!
    // the flow cookie must reach the code screen when the deck's own page started the flow (another site):
    // a Strict cookie is not sent on a navigation another site started, and the screen would read as expired
    const flowSetCookie = r2.headers.getSetCookie().find((l) => /id_code=/.test(l))!
    expect(flowSetCookie).toMatch(/SameSite=Lax/i)
    expect(flowSetCookie).not.toMatch(/SameSite=Strict/i)
    expect(codePath).toMatch(/^\/login\/code\/[0-9a-f]{48}$/)
    expect(sends.n).toBe(1)

    const page = await SELF.fetch(`${BASE}${codePath}`, { headers: { cookie: cookieHeader(cookies) } })
    expect(page.status).toBe(200)
    const html = await page.text()
    expect(html).toContain(email)
    expect(html).not.toContain('Or open the link in the email')
    // "Use a different email" goes back to the deck, not to an id.org.ai form
    expect(html).toContain(`href="${PREVIEW}/"`)
    // Verify's redirects end at the deck: the page's CSP lets the form's redirect chain reach it
    expect(page.headers.get('content-security-policy')).toContain(`form-action 'self' ${PREVIEW}`)

    mockCodeCheck(email, '424242', 'user_01PITCHLP')
    const r3 = await enterCode(codePath, cookies, '424242')
    expect(r3.status).toBe(302)
    expect(r3.headers.get('location')).toBe(cont)
    const session = setCookies(r3).auth!
    expect(session).toBeTruthy()

    const r4 = await SELF.fetch(cont, { redirect: 'manual', headers: { cookie: `auth=${session}` } })
    expect(r4.status).toBe(302)
    const back = new URL(r4.headers.get('location')!)
    expect(`${back.origin}${back.pathname}`).toBe(`${PREVIEW}/auth/callback`)
    expect(back.searchParams.get('state')).toBe('deck-state')
    const code = back.searchParams.get('code')!
    expect(code).toMatch(/^ac_/)

    const tok = await SELF.fetch(`${BASE}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: `${PREVIEW}/auth/callback`, client_id: TRUSTED_ACCOUNT_CLIENT_ID, code_verifier: verifier }).toString(),
    })
    expect(tok.status).toBe(200)
    const { access_token } = (await tok.json()) as { access_token: string }
    const ui = (await (await SELF.fetch(`${BASE}/oauth/userinfo`, { headers: { authorization: `Bearer ${access_token}` } })).json()) as Record<string, unknown>
    expect(ui.email).toBe(email)
    expect(ui.email_verified).toBe(true)
  })

  it('binds the code screen to the browser that asked; ?code= prefills without a check; a wrong code is refused', async () => {
    const email = 'bound@fund-one.example'
    mockSends(email)
    const checks = mockCodeCheck(email, '000001', 'user_01BOUND')
    const { challenge } = await pkce()
    const { r2, cookies } = await startEmail(PITCH, email, challenge)
    const path = r2.headers.get('location')!
    // another browser
    expect((await SELF.fetch(`${BASE}${path}`)).status).toBe(410)
    expect((await enterCode(path, {}, '111111')).status).toBe(410)
    // the RP-initiated magic-link path doesn't serve these flows
    expect((await SELF.fetch(`${BASE}${path.replace('/login/code/', '/magic-link/')}`)).status).toBe(410)
    // prefill
    const page = await SELF.fetch(`${BASE}${path}?code=987654`, { headers: { cookie: cookieHeader(cookies) } })
    const html = await page.text()
    for (const d of '987654') expect(html).toContain(`value="${d}"`)
    expect(checks.n).toBe(0)
    // wrong
    const wrong = await enterCode(path, cookies, '999999')
    expect(wrong.status).toBe(400)
    expect(await wrong.text()).toContain('didn’t match')
  })

  it('needs a login_hint and the trusted client; /login won’t send for anyone else’s continue', async () => {
    const { challenge } = await pkce()
    // no hint: no shortcut
    const noHint = await SELF.fetch(authorizeUrl(PITCH, challenge, { provider: 'email' }), { redirect: 'manual' })
    expect(new URL(noHint.headers.get('location')!).searchParams.has('provider')).toBe(false)
    // straight to /login with a continue that isn't a trusted authorize: the picker, nothing sent
    const sends = mockSends('direct@fund-one.example')
    const direct = await SELF.fetch(`${BASE}/login?provider=email&login_hint=direct%40fund-one.example&continue=%2Fdash%2Fprofile`, { redirect: 'manual' })
    expect(direct.status).toBe(200)
    expect(await direct.text()).toContain('Choose a provider')
    expect(sends.n).toBe(0)
  })

  it("sends on the 'web' path have their own budget (5 an hour), then the picker; magic-link's is untouched", async () => {
    const email = 'budget@fund-one.example'
    const sends = mockSends(email)
    const { challenge } = await pkce()
    for (let i = 0; i < 5; i++) expect((await startEmail(PITCH, email, challenge)).r2.status).toBe(303)
    const sixth = await startEmail(PITCH, email, challenge)
    expect(sixth.r2.status).toBe(200)
    expect(sends.n).toBe(5)
    const ml = await authService().sendMagicLink({ email })
    expect(ml.ok).toBe(true)
    expect(sends.n).toBe(6)
  })
})

describe('Google: provider=GoogleOAuth, straight through', () => {
  it('goes through /login to WorkOS with provider=GoogleOAuth and the hint, and comes back to authorize without provider', async () => {
    const { challenge } = await pkce()
    const r1 = await SELF.fetch(authorizeUrl(PITCH, challenge, { provider: 'GoogleOAuth', login_hint: 'lp@gmail.com' }), { redirect: 'manual' })
    const login = new URL(r1.headers.get('location')!)
    expect(login.pathname).toBe('/login')
    expect(login.searchParams.get('provider')).toBe('GoogleOAuth')
    expect(login.searchParams.get('prompt')).toBe('login')
    expect(new URL(login.searchParams.get('continue')!).searchParams.has('provider')).toBe(false)
    const r2 = await SELF.fetch(login.toString(), { redirect: 'manual' })
    expect(r2.status).toBe(302)
    const workos = new URL(r2.headers.get('location')!)
    expect(workos.pathname).toBe('/user_management/authorize')
    expect(workos.searchParams.get('provider')).toBe('GoogleOAuth')
    expect(workos.searchParams.get('login_hint')).toBe('lp@gmail.com')
  })

  it('an unknown provider gets no shortcut', async () => {
    const { challenge } = await pkce()
    const odd = await SELF.fetch(authorizeUrl(PITCH, challenge, { provider: 'EvilOAuth' }), { redirect: 'manual' })
    expect(new URL(odd.headers.get('location')!).searchParams.has('provider')).toBe(false)
  })

  it('a host off the allowlist is refused', async () => {
    const { challenge } = await pkce()
    const off = await SELF.fetch(authorizeUrl('https://pitch.evil.example', challenge, { provider: 'GoogleOAuth' }), { redirect: 'manual' })
    expect(off.status).toBe(400)
  })
})

describe('continueOrigins (1b form-action)', () => {
  it('adds an absolute continue’s origin, or an authorize continue’s redirect_uri origin, and nothing for a local path', () => {
    expect(continueOrigins('/dash/profile', BASE)).toEqual([])
    expect(continueOrigins('https://headless.ly/after', BASE)).toEqual(['https://headless.ly'])
    expect(continueOrigins(`${BASE}/oauth/authorize?redirect_uri=${encodeURIComponent(`${PITCH}/auth/callback`)}`, BASE)).toEqual([PITCH])
    expect(continueOrigins(`${BASE}/oauth/authorize?redirect_uri=javascript%3Aalert(1)`, BASE)).toEqual([])
  })
})
