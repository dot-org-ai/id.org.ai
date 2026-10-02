/**
 * Phase 6 · Device flow v2 through the real worker (docs/product-update/spec/backend.md#b3):
 * device authorization → the 4b page (CSRF-bound) → the decision → the poll,
 * with the workspace carried into the tokens; the no-JS results (4d), the
 * code entry (4c), signing a device out, and no CORS on the device pages.
 * WorkOS is faked with fetchMock.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock, env } from 'cloudflare:test'
import { getStubForIdentity } from '../worker/middleware/tenant'
import type { Env } from '../worker/types'

const BASE = 'https://id.org.ai'
const WORKOS = 'https://api.workos.com'
const CLI = 'id_org_ai_cli'
const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code'

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
const field = (html: string, name: string) => html.match(new RegExp(`<input type="hidden" name="${name}" value="([^"]*)"`))?.[1]

async function signIn(userId: string): Promise<Record<string, string>> {
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'GET', path: '/user_management/organization_memberships', query: { user_id: userId, limit: '100' } })
    .reply(200, JSON.stringify({ data: [{ id: 'om_a', user_id: userId, organization_id: 'org_ACME', role: { slug: 'admin' }, status: 'active', created_at: 't', updated_at: 't' }] }), {
      headers: { 'content-type': 'application/json' },
    })
    .persist()
  const login = await SELF.fetch(`${BASE}/login?provider=GitHubOAuth`, { redirect: 'manual' })
  const state = new URL(login.headers.get('location')!).searchParams.get('state')!
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'POST', path: '/user_management/authenticate' })
    .reply(200, JSON.stringify({ access_token: 'at_w', refresh_token: 'rt_w', user: { id: userId, email: `${userId.toLowerCase()}@example.com`, first_name: 'Ada', last_name: 'Lovelace' } }), {
      headers: { 'content-type': 'application/json' },
    })
  const cb = await SELF.fetch(`${BASE}/api/callback?code=wos_code&state=${encodeURIComponent(state)}`, { redirect: 'manual' })
  expect(cb.status).toBe(302)
  return { auth: setCookies(cb).auth! }
}

async function deviceAuth(): Promise<{ device_code: string; user_code: string; verification_uri_complete: string }> {
  const res = await SELF.fetch(`${BASE}/oauth/device`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'user-agent': 'id.org.ai-cli/1.0 (darwin)' },
    body: new URLSearchParams({ client_id: CLI, scope: 'openid profile email offline_access', device_name: 'macOS · test-mbp' }).toString(),
  })
  expect(res.status).toBe(200)
  return (await res.json()) as { device_code: string; user_code: string; verification_uri_complete: string }
}

const poll = async (deviceCode: string) =>
  (await (
    await SELF.fetch(`${BASE}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: DEVICE_GRANT, device_code: deviceCode, client_id: CLI }).toString(),
    })
  ).json()) as Record<string, any>

/** Open 4b: the page, and its page token (bound to the person; no cookie). */
async function open(cookies: Record<string, string>, code: string) {
  const page = await SELF.fetch(`${BASE}/device?code=${code}`, { redirect: 'manual', headers: { cookie: cookieHeader(cookies) } })
  expect(page.status).toBe(200)
  const html = await page.text()
  return { html, csrf: field(html, 'csrf')!, cookies }
}

const decide = (cookies: Record<string, string>, fields: Record<string, string>, headers: Record<string, string> = {}) =>
  SELF.fetch(`${BASE}/device/decision`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(cookies), ...headers },
    body: new URLSearchParams(fields).toString(),
  })

beforeAll(() => {
  fetchMock.activate()
  fetchMock.disableNetConnect()
  fetchMock.get(WORKOS).intercept({ path: '/organizations/org_ACME' }).reply(200, JSON.stringify({ id: 'org_ACME', name: 'Acme', domains: [] }), { headers: { 'content-type': 'application/json' } }).persist()
  fetchMock.get(WORKOS).intercept({ path: /^\/user_management\/users\// }).reply(500, '').persist()
})
afterAll(() => fetchMock.deactivate())

describe('device flow v2 through the worker', () => {
  it('authorize → 4b → approve (the page’s fetch) → poll: tokens carry the chosen workspace', async () => {
    const cookies = await signIn('user_01DEVICE_A')
    const d = await deviceAuth()
    expect(d.user_code).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/)
    expect(d.verification_uri_complete).toBe(`${BASE}/device?code=${d.user_code}`)

    const page = await open(cookies, d.user_code)
    expect(page.html).toContain('<title>Confirm id.org.ai CLI · id.org.ai</title>')
    // The client's separators are dropped and a place is always shown (review S5).
    expect(page.html).toContain('macOS test-mbp · location unknown · requested just now')
    expect(page.html).toMatch(/<option value="org_ACME"[^>]*>Acme<\/option>/)
    expect(page.html).toContain('action="/device/decision"')

    const res = await decide(page.cookies, { code: d.user_code, org_id: 'org_ACME', decision: 'approve' }, { 'x-csrf-token': page.csrf, accept: 'application/json', 'sec-fetch-site': 'same-origin' })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ok: true, state: 'approved' })

    const t = await poll(d.device_code)
    expect(t.access_token).toBeTruthy()
    const intro = (await (
      await SELF.fetch(`${BASE}/oauth/introspect`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token: t.access_token }).toString() })
    ).json()) as Record<string, any>
    expect(intro).toMatchObject({ active: true, org_id: 'org_ACME' })
    // The CLI's "Workspace" line reads org_name (next to org_id) from userinfo.
    const me = (await (await SELF.fetch(`${BASE}/oauth/userinfo`, { headers: { authorization: `Bearer ${t.access_token}` } })).json()) as Record<string, unknown>
    expect(me).toMatchObject({ org_id: 'org_ACME', org_name: 'Acme' })
  })

  it('a decision without the CSRF token is refused and the code stays pending', async () => {
    const cookies = await signIn('user_01DEVICE_B')
    const d = await deviceAuth()
    const page = await open(cookies, d.user_code)
    const bare = await decide(cookies, { code: d.user_code, decision: 'approve' }, { accept: 'application/json', 'sec-fetch-site': 'same-origin' })
    expect(bare.status).toBe(403)
    const wrong = await decide(page.cookies, { code: d.user_code, decision: 'approve', csrf: 'not-the-token' })
    expect(wrong.status).toBe(403)
    expect((await poll(d.device_code)).error).toBe('authorization_pending')
  })

  it('deny without JS: 303 to the cancelled page (4d), and the poll gets access_denied', async () => {
    const cookies = await signIn('user_01DEVICE_C')
    const d = await deviceAuth()
    const page = await open(cookies, d.user_code)
    const res = await decide(page.cookies, { code: d.user_code, decision: 'deny', csrf: page.csrf })
    expect(res.status).toBe(303)
    expect(res.headers.get('location')).toBe(`/device/cancelled?code=${d.user_code}`)
    const cancelled = await SELF.fetch(`${BASE}${res.headers.get('location')}`, { headers: { cookie: cookieHeader(cookies) } })
    expect(await cancelled.text()).toContain('Sign-in cancelled')
    expect((await poll(d.device_code)).error).toBe('access_denied')
  })

  it('approve without JS: 303 to 4d, which still shows after the device has collected its tokens', async () => {
    const cookies = await signIn('user_01DEVICE_D')
    const d = await deviceAuth()
    const page = await open(cookies, d.user_code)
    const res = await decide(page.cookies, { code: d.user_code, org_id: 'org_ACME', decision: 'approve', csrf: page.csrf })
    expect(res.headers.get('location')).toBe(`/device/done?code=${d.user_code}`)
    expect((await poll(d.device_code)).access_token).toBeTruthy()
    const done = await SELF.fetch(`${BASE}${res.headers.get('location')}`, { headers: { cookie: cookieHeader(cookies) } })
    const html = await done.text()
    expect(html).toContain('id.org.ai CLI is signed in')
    expect(html).toContain('Acme')
  })

  it('4c: entering a code (with or without the hyphen) goes to 4b; an unknown code is an error on 4c', async () => {
    const cookies = await signIn('user_01DEVICE_E')
    const d = await deviceAuth()
    const entry = await SELF.fetch(`${BASE}/device`, { headers: { cookie: cookieHeader(cookies) } })
    const html = await entry.text()
    const withCsrf = cookies
    const typed = new URLSearchParams({ csrf: field(html, 'csrf')! })
    for (const ch of d.user_code.replace('-', '').toLowerCase()) typed.append('code', ch)
    const go = await SELF.fetch(`${BASE}/device`, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(withCsrf) }, body: typed.toString() })
    expect(go.status).toBe(303)
    expect(go.headers.get('location')).toBe(`/device?code=${d.user_code}`)

    const unknown = await SELF.fetch(`${BASE}/device?code=ZZZZ-ZZZZ`, { headers: { cookie: cookieHeader(cookies) } })
    expect(unknown.status).toBe(400)
    expect(await unknown.text()).toContain('That code is invalid or has expired')
  })

  it('signed out, the page sends you to sign in and back to the same code', async () => {
    const res = await SELF.fetch(`${BASE}/device?code=ABCD-EFGH`, { redirect: 'manual' })
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toBe(`/login?continue=${encodeURIComponent('/device?code=ABCD-EFGH')}`)
  })

  it('“Sign this device out” asks first, then revokes the grant: the device gets nothing', async () => {
    const cookies = await signIn('user_01DEVICE_F')
    const d = await deviceAuth()
    const page = await open(cookies, d.user_code)
    const revokeHref = page.html.match(/href="(\/device\/[^"]+\/revoke)"/)?.[1]
    expect(revokeHref).toBeTruthy()
    await decide(page.cookies, { code: d.user_code, decision: 'approve', csrf: page.csrf })

    const ask = await SELF.fetch(`${BASE}${revokeHref}`, { headers: { cookie: cookieHeader(cookies) } })
    expect(ask.status).toBe(200)
    const askHtml = await ask.text()
    expect(askHtml).toContain('Sign this device out?')
    const post = await SELF.fetch(`${BASE}${revokeHref}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(cookies) },
      body: new URLSearchParams({ csrf: field(askHtml, 'csrf')! }).toString(),
    })
    expect(await post.text()).toContain('Device signed out')
    expect((await poll(d.device_code)).error).toBe('invalid_grant')
  })

  it('no other origin can read the device pages or the decision', async () => {
    const cookies = await signIn('user_01DEVICE_G')
    const d = await deviceAuth()
    const page = await SELF.fetch(`${BASE}/device?code=${d.user_code}`, { headers: { cookie: cookieHeader(cookies), origin: 'https://evil.headless.ly' } })
    expect(page.headers.get('access-control-allow-origin')).toBeNull()
    const res = await decide(cookies, { code: d.user_code, decision: 'approve' }, { origin: 'https://evil.headless.ly', accept: 'application/json', 'sec-fetch-site': 'same-site' })
    expect(res.headers.get('access-control-allow-origin')).toBeNull()
  })
})

describe('phase 6 review: the device routes’ guards', () => {
  const jsonHeaders = (csrf: string) => ({ 'x-csrf-token': csrf, accept: 'application/json', 'sec-fetch-site': 'same-origin' })

  it('S8/M6: only the page’s own fetch gets JSON; a same-site one gets the redirect', async () => {
    const cookies = await signIn('user_01DEVICE_H')
    const d = await deviceAuth()
    const page = await open(cookies, d.user_code)
    const res = await decide(cookies, { code: d.user_code, decision: 'deny' }, { 'x-csrf-token': page.csrf, accept: 'application/json', 'sec-fetch-site': 'same-site' })
    expect(res.status).toBe(303)
  })

  it('S2/M13: a page token answers one POST', async () => {
    const cookies = await signIn('user_01DEVICE_I')
    const d = await deviceAuth()
    const page = await open(cookies, d.user_code)
    expect((await decide(cookies, { code: d.user_code, decision: 'deny' }, jsonHeaders(page.csrf))).status).toBe(200)
    expect((await decide(cookies, { code: d.user_code, decision: 'deny' }, jsonHeaders(page.csrf))).status).toBe(403)
  })

  it('S1: a token from someone else’s page is refused', async () => {
    const mallory = await signIn('user_01DEVICE_J')
    const victim = await signIn('user_01DEVICE_K')
    const d = await deviceAuth()
    const malloryPage = await open(mallory, d.user_code)
    expect((await decide(victim, { code: d.user_code, decision: 'approve' }, jsonHeaders(malloryPage.csrf))).status).toBe(403)
    expect((await poll(d.device_code)).error).toBe('authorization_pending')
  })

  it('N5: the token in both the header and the field is refused', async () => {
    const cookies = await signIn('user_01DEVICE_L')
    const d = await deviceAuth()
    const page = await open(cookies, d.user_code)
    expect((await decide(cookies, { code: d.user_code, decision: 'deny', csrf: page.csrf }, jsonHeaders(page.csrf))).status).toBe(403)
  })

  it('S8/M16: no session, no decision', async () => {
    const d = await deviceAuth()
    expect((await decide({}, { code: d.user_code, decision: 'approve', csrf: 'x'.repeat(64) })).status).toBe(401)
  })

  it('S8/M15 and N4: 4d is the approver’s; a reload re-reads the state', async () => {
    const cookies = await signIn('user_01DEVICE_M')
    const other = await signIn('user_01DEVICE_N')
    const d = await deviceAuth()
    const page = await open(cookies, d.user_code)
    await decide(cookies, { code: d.user_code, decision: 'approve', csrf: page.csrf })
    const theirs = await SELF.fetch(`${BASE}/device/done?code=${d.user_code}`, { headers: { cookie: cookieHeader(other) } })
    expect(theirs.status).toBe(409)
    const wrongPage = await SELF.fetch(`${BASE}/device/cancelled?code=${d.user_code}`, { redirect: 'manual', headers: { cookie: cookieHeader(cookies) } })
    expect(wrongPage.headers.get('location')).toBe(`/device/done?code=${d.user_code}`)
  })

  it('S8/M17: signing a device out needs the page token', async () => {
    const cookies = await signIn('user_01DEVICE_O')
    const d = await deviceAuth()
    const page = await open(cookies, d.user_code)
    const revokeHref = page.html.match(/href="(\/device\/[^"]+\/revoke)"/)![1]!
    await decide(cookies, { code: d.user_code, decision: 'approve', csrf: page.csrf })
    const res = await SELF.fetch(`${BASE}${revokeHref}`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(cookies) }, body: '' })
    expect(res.status).toBe(403)
    expect((await poll(d.device_code)).access_token).toBeTruthy()
  })

  it('an expired code shows 7b in place', async () => {
    const cookies = await signIn('user_01DEVICE_P')
    const d = await deviceAuth()
    const stub = getStubForIdentity(env as unknown as Env, 'oauth')
    const rec = (await stub.oauthStorageOp({ op: 'get', key: `device:${d.device_code}` })).value as Record<string, unknown>
    await stub.oauthStorageOp({ op: 'put', key: `device:${d.device_code}`, value: { ...rec, expiresAt: Date.now() - 1000 } })
    const res = await SELF.fetch(`${BASE}/device?code=${d.user_code}`, { headers: { cookie: cookieHeader(cookies) } })
    expect(res.status).toBe(410)
    expect(await res.text()).toContain('This code has expired')
  })

  it('S3: code lookups spend a guess budget per person', async () => {
    const cookies = await signIn('user_01DEVICE_Q')
    const statuses: number[] = []
    for (let i = 0; i < 31; i++) statuses.push((await SELF.fetch(`${BASE}/device?code=ZZZZ-ZZZZ`, { headers: { cookie: cookieHeader(cookies) } })).status)
    expect(statuses.slice(0, 30).every((s) => s === 400)).toBe(true)
    expect(statuses[30]).toBe(429)
  })
})
