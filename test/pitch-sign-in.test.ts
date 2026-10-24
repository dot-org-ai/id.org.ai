/**
 * pitch.startups.studio's sign-in (the Fund I deck), end to end through the
 * real worker (SELF, real IdentityDO + KV); only WorkOS and DNS are faked.
 *
 *   1. The deck is a trusted-account client (ADR-0007): its hosts are in
 *      worker/wrangler.jsonc's TRUSTED_ACCOUNT_DOMAINS, and a signed-in person
 *      gets a code straight back, with no consent page.
 *   2. /login routes a login_hint: a Google address (gmail, or a domain on
 *      Google Workspace's MX) straight to Google; anything else to the email
 *      form, filled in. No hint: "Continue with Google" first.
 *   3. The email form (POST /login/email → /login/code/:flow): CSRF, the
 *      'web' budget path, the flow bound to the browser that asked, ?code=
 *      prefill without submitting.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock, env } from 'cloudflare:test'
import { authService } from './helpers/auth-service'
import { parseTrustedAccountDomains, TRUSTED_ACCOUNT_CLIENT_ID } from '../worker/routes/oauth'

const BASE = 'https://id.org.ai'
const WORKOS = 'https://api.workos.com'
const DOH = 'https://cloudflare-dns.com'
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

function authorizeUrl(origin: string, challenge: string, state: string, loginHint?: string): string {
  const u = new URL(`${BASE}/oauth/authorize`)
  u.search = new URLSearchParams({
    response_type: 'code',
    client_id: TRUSTED_ACCOUNT_CLIENT_ID,
    redirect_uri: `${origin}/auth/callback`,
    scope: 'openid profile email',
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...(loginHint ? { login_hint: loginHint } : {}),
  }).toString()
  return u.toString()
}

/** Answer DoH MX queries for `domain` with these hosts (none: an empty answer). */
function mockMx(domain: string, hosts: string[]) {
  fetchMock
    .get(DOH)
    .intercept({ path: (p: string) => p.startsWith('/dns-query') && new URL(p, DOH).searchParams.get('name') === domain })
    .reply(200, JSON.stringify({ Status: 0, Answer: hosts.map((h, i) => ({ name: domain, type: 15, TTL: 300, data: `${(i + 1) * 10} ${h}.` })) }), {
      headers: { 'content-type': 'application/dns-json' },
    })
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

/** One WorkOS magic-auth:code check for `email`: right when the code is `right`. */
function mockCodeCheck(email: string, right: string, userId: string) {
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'POST', path: '/user_management/authenticate', body: (b: string) => new URLSearchParams(b).get('email') === email })
    .reply((opts) => {
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
}

/** GET /login, then POST its email form: the 303 and the cookies it set. */
async function askForCode(email: string, continueUrl = '/dash/profile'): Promise<{ res: Response; cookies: Record<string, string> }> {
  const page = await SELF.fetch(`${BASE}/login?continue=${encodeURIComponent(continueUrl)}`)
  expect(page.status).toBe(200)
  const csrf = (await page.text()).match(/name="csrf" value="([^"]+)"/)![1]!
  const cookies = setCookies(page)
  const res = await SELF.fetch(`${BASE}/login/email`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(cookies) },
    body: new URLSearchParams({ csrf, email, continue: continueUrl }).toString(),
  })
  return { res, cookies: { ...cookies, ...setCookies(res) } }
}

const enterCode = (path: string, cookies: Record<string, string>, code: string) =>
  SELF.fetch(`${BASE}${path}`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(cookies) },
    // six boxes, each named code
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

describe('1. the deck is a trusted-account client', () => {
  it('lists the production and preview hosts in TRUSTED_ACCOUNT_DOMAINS', () => {
    const hosts = parseTrustedAccountDomains(env.TRUSTED_ACCOUNT_DOMAINS)
    expect(hosts.has('pitch.startups.studio')).toBe(true)
    expect(hosts.has('pitch-startups-studio-preview.metad.workers.dev')).toBe(true)
    expect(hosts.has('startup.games')).toBe(true)
  })

  it('signed out → email code → a code for the deck with no consent page → tokens → userinfo', async () => {
    const email = 'lee@fund-one.example'
    mockMx('fund-one.example', ['mx.fund-one.example'])
    const { verifier, challenge } = await pkce()
    const start = authorizeUrl(PREVIEW, challenge, 'deck-state', email)

    // Signed out: to /login with the hint and the authorize request to come back to.
    const r1 = await SELF.fetch(start, { redirect: 'manual' })
    expect(r1.status).toBe(302)
    const toLogin = new URL(r1.headers.get('location')!)
    expect(toLogin.pathname).toBe('/login')
    expect(toLogin.searchParams.get('login_hint')).toBe(email)
    const cont = toLogin.searchParams.get('continue')!

    // Not a Google address: the email form, filled in, first.
    const loginPage = await SELF.fetch(toLogin.toString(), { redirect: 'manual' })
    expect(loginPage.status).toBe(200)
    const html = await loginPage.text()
    expect(html).toContain(`value="${email}"`)
    expect(html.indexOf('Continue with email')).toBeLessThan(html.indexOf('Google'))
    const csrf = html.match(/name="csrf" value="([^"]+)"/)![1]!

    // Ask for the code.
    const sends = mockSends(email)
    const r2 = await SELF.fetch(`${BASE}/login/email`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(setCookies(loginPage)) },
      body: new URLSearchParams({ csrf, email, continue: cont }).toString(),
    })
    expect(r2.status).toBe(303)
    expect(sends.n).toBe(1)
    const codePath = r2.headers.get('location')!
    expect(codePath).toMatch(/^\/login\/code\/[0-9a-f]{48}$/)
    const flowCookies = setCookies(r2)

    // 1b, then the right code: signed in, back to the authorize request.
    const codePage = await SELF.fetch(`${BASE}${codePath}`, { headers: { cookie: cookieHeader(flowCookies) } })
    expect(codePage.status).toBe(200)
    expect(await codePage.text()).toContain(email)
    mockCodeCheck(email, '424242', 'user_01PITCHLP')
    const r3 = await enterCode(codePath, flowCookies, '424242')
    expect(r3.status).toBe(302)
    expect(r3.headers.get('location')).toBe(cont)
    const session = setCookies(r3).auth!
    expect(session).toBeTruthy()

    // Signed in: the code comes straight back. No consent page, state verbatim.
    const r4 = await SELF.fetch(cont, { redirect: 'manual', headers: { cookie: `auth=${session}` } })
    expect(r4.status).toBe(302)
    const back = new URL(r4.headers.get('location')!)
    expect(`${back.origin}${back.pathname}`).toBe(`${PREVIEW}/auth/callback`)
    expect(back.searchParams.get('state')).toBe('deck-state')
    const code = back.searchParams.get('code')!
    expect(code).toMatch(/^ac_/)

    // The deck's own exchange (PKCE, no secret), then its userinfo read.
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
    expect(ui.amr).toEqual(['magic_link'])
  })

  it('the production host gets a code with no consent page too; a host off the list does not', async () => {
    const email = 'prod-lp@fund-two.example'
    mockMx('fund-two.example', [])
    mockSends(email)
    const { res, cookies } = await askForCode(email)
    mockCodeCheck(email, '135790', 'user_01PITCHPROD')
    const signedIn = await enterCode(res.headers.get('location')!, cookies, '135790')
    const session = setCookies(signedIn).auth!

    const { challenge } = await pkce()
    const ok = await SELF.fetch(authorizeUrl(PITCH, challenge, 's1'), { redirect: 'manual', headers: { cookie: `auth=${session}` } })
    expect(ok.status).toBe(302)
    expect(new URL(ok.headers.get('location')!).searchParams.get('code')).toMatch(/^ac_/)

    const off = await SELF.fetch(authorizeUrl('https://pitch.evil.example', challenge, 's2'), { redirect: 'manual', headers: { cookie: `auth=${session}` } })
    expect(off.status).toBe(400)
  })
})

describe('2. /login routes a login_hint', () => {
  const login = (hint?: string) =>
    SELF.fetch(`${BASE}/login?continue=%2Fdash%2Fprofile${hint ? `&login_hint=${encodeURIComponent(hint)}` : ''}`, { redirect: 'manual' })

  it('a gmail address goes straight to Google, preselected', async () => {
    const res = await login('someone@gmail.com')
    expect(res.status).toBe(302)
    const to = new URL(res.headers.get('location')!)
    expect(to.pathname).toBe('/user_management/authorize')
    expect(to.searchParams.get('provider')).toBe('GoogleOAuth')
    expect(to.searchParams.get('login_hint')).toBe('someone@gmail.com')
  })

  it('a Google Workspace domain (MX on google.com) goes straight to Google', async () => {
    mockMx('workspace-fund.example', ['aspmx.l.google.com', 'alt1.aspmx.l.google.com'])
    const res = await login('gp@workspace-fund.example')
    expect(res.status).toBe(302)
    expect(new URL(res.headers.get('location')!).searchParams.get('provider')).toBe('GoogleOAuth')
  })

  it('a Microsoft 365 domain gets the email form (MicrosoftOAuth is not enabled in WorkOS yet)', async () => {
    mockMx('m365-fund.example', ['m365-fund-example.mail.protection.outlook.com'])
    const res = await login('gp@m365-fund.example')
    expect(res.status).toBe(200)
    expect(await res.text()).toContain('value="gp@m365-fund.example"')
  })

  it('a DNS failure falls back to the email form', async () => {
    // no DoH mock for this domain: the lookup throws under disableNetConnect
    const res = await login('gp@unreachable-dns.example')
    expect(res.status).toBe(200)
    expect(await res.text()).toContain('value="gp@unreachable-dns.example"')
  })

  it('no hint: one screen, "Continue with Google" first, then the email field, then the rest', async () => {
    const res = await login()
    expect(res.status).toBe(200)
    const html = await res.text()
    const google = html.indexOf('Continue with Google')
    const email = html.indexOf('name="email"')
    expect(google).toBeGreaterThan(-1)
    expect(google).toBeLessThan(email)
    for (const name of ['Microsoft', 'GitHub']) expect(html.indexOf(`>${name}<`)).toBeGreaterThan(email)
    // the provider links keep continue
    expect(html).toContain('/login?provider=GoogleOAuth&amp;continue=%2Fdash%2Fprofile')
  })

  it('an explicit provider still wins over the hint', async () => {
    const res = await SELF.fetch(`${BASE}/login?provider=GitHubOAuth&login_hint=someone%40gmail.com`, { redirect: 'manual' })
    expect(new URL(res.headers.get('location')!).searchParams.get('provider')).toBe('GitHubOAuth')
  })
})

describe('3. the email form', () => {
  it('needs the page’s CSRF token', async () => {
    const res = await SELF.fetch(`${BASE}/login/email`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'email=nocsrf%40example.com&csrf=forgedforgedforged1',
    })
    expect(res.status).toBe(403)
  })

  it('binds the flow to the browser that asked, and /magic-link/:flow refuses it', async () => {
    const email = 'bound@example.com'
    mockSends(email)
    const { res, cookies } = await askForCode(email)
    const path = res.headers.get('location')!
    // another browser (no flow cookie)
    expect((await SELF.fetch(`${BASE}${path}`)).status).toBe(410)
    expect((await enterCode(path, {}, '111111')).status).toBe(410)
    // the RP-initiated path doesn't serve web flows
    expect((await SELF.fetch(`${BASE}${path.replace('/login/code/', '/magic-link/')}`)).status).toBe(410)
    // this browser
    expect((await SELF.fetch(`${BASE}${path}`, { headers: { cookie: cookieHeader(cookies) } })).status).toBe(200)
  })

  it('?code= prefills the boxes and never submits', async () => {
    const email = 'prefill@example.com'
    mockSends(email)
    const checks = { n: 0 }
    fetchMock
      .get(WORKOS)
      .intercept({ method: 'POST', path: '/user_management/authenticate', body: (b: string) => new URLSearchParams(b).get('email') === email })
      .reply(() => {
        checks.n++
        return { statusCode: 400, data: '{}' }
      })
      .persist()
    const { res, cookies } = await askForCode(email)
    const page = await SELF.fetch(`${BASE}${res.headers.get('location')}?code=987654`, { headers: { cookie: cookieHeader(cookies) } })
    expect(page.status).toBe(200)
    const html = await page.text()
    for (const d of '987654') expect(html).toContain(`value="${d}"`)
    expect(html).not.toContain('Or open the link in the email')
    expect(checks.n).toBe(0)
  })

  it('a wrong code is refused and spends the guess budget', async () => {
    const email = 'wrong@example.com'
    mockSends(email)
    mockCodeCheck(email, '000001', 'user_01WRONG')
    const { res, cookies } = await askForCode(email)
    const path = res.headers.get('location')!
    const r = await enterCode(path, cookies, '999999')
    expect(r.status).toBe(400)
    expect(await r.text()).toContain('didn’t match')
  })

  it("sends on the 'web' path have their own budget: 5 an hour, and magic-link's is untouched", async () => {
    const email = 'budget@example.com'
    const sends = mockSends(email)
    for (let i = 0; i < 5; i++) expect((await askForCode(email)).res.status).toBe(303)
    const sixth = await askForCode(email)
    expect(sixth.res.status).toBe(429)
    expect(await sixth.res.text()).toContain('Too many codes sent')
    expect(sends.n).toBe(5)
    // the RP path still sends to that address
    const ml = await authService().sendMagicLink({ email })
    expect(ml.ok).toBe(true)
    expect(sends.n).toBe(6)
  })
})
