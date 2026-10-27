/**
 * Trusted-account sign-in with nothing of id.org.ai's shown (the Fund I deck,
 * pitch.startups.studio): the headless sign-in link
 * (worker/routes/trusted-magic-link.ts) and provider=GoogleOAuth on
 * /oauth/authorize. Runs the real worker (real IdentityDO + KV); WorkOS is
 * faked with fetchMock and the EMAIL binding with a recorder.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, env, fetchMock, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test'
import worker from '../worker/index'
import type { Env } from '../worker/types'
import { TRUSTED_ACCOUNT_CLIENT_ID } from '../worker/routes/oauth'

const BASE = 'https://id.org.ai'
const WORKOS = 'https://api.workos.com'
const PITCH = 'https://pitch.startups.studio'
const PREVIEW = 'https://pitch-startups-studio-preview.metad.workers.dev'

type Sent = { from: { name: string; email: string }; to: string; subject: string; html: string; text: string }

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

async function pkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)))
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return { verifier, challenge: b64url(new Uint8Array(hash)) }
}

/** The worker with a recording EMAIL binding (`fail`: Email Service refuses). */
function withMail(opts: { fail?: boolean } = {}) {
  const sent: Sent[] = []
  const EMAIL = {
    async send(m: Sent) {
      if (opts.fail) throw Object.assign(new Error('refused'), { code: 'E_SENDER_NOT_VERIFIED' })
      sent.push(m)
      return { messageId: `m${sent.length}` }
    },
  }
  const fetchWorker = async (path: string, init?: RequestInit) => {
    const ctx = createExecutionContext()
    const res = await worker.fetch(new Request(`${BASE}${path}`, init), { ...(env as unknown as Env), EMAIL } as never, ctx)
    await waitOnExecutionContext(ctx)
    return res
  }
  return { sent, fetchWorker }
}

const ask = (fetchWorker: ReturnType<typeof withMail>['fetchWorker'], body: Record<string, string>) =>
  fetchWorker('/oauth/magic-link', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })

const params = (origin: string, challenge: string, state = 'deck-state') => ({
  client_id: TRUSTED_ACCOUNT_CLIENT_ID,
  redirect_uri: `${origin}/auth/callback`,
  response_type: 'code',
  scope: 'openid profile email',
  state,
  code_challenge: challenge,
  code_challenge_method: 'S256',
})

const linkIn = (m: Sent) => m.text.match(/https:\/\/id\.org\.ai\/oauth\/magic-link\/[A-Za-z0-9_-]{43}/)![0]

/** WorkOS knows no user for `email` until it's created; counts the creates. */
function workosUsers(email: string, id: string) {
  const calls = { creates: 0 }
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'GET', path: (p: string) => p.startsWith('/user_management/users?') && new URL(p, WORKOS).searchParams.get('email') === email })
    .reply(200, JSON.stringify({ data: [] }), { headers: { 'content-type': 'application/json' } })
    .persist()
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'POST', path: '/user_management/users', body: (b: string) => JSON.parse(b).email === email })
    .reply(() => {
      calls.creates++
      return { statusCode: 201, data: JSON.stringify({ id, email, email_verified: true }), responseOptions: { headers: { 'content-type': 'application/json' } } }
    })
    .persist()
  return calls
}

async function linkKey(link: string): Promise<string> {
  const token = link.split('/').pop()!
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)))
  return `trusted-link:${Array.from(hash, (b) => b.toString(16).padStart(2, '0')).join('')}`
}
const oauthShard = () => (env as unknown as Env).IDENTITY.get((env as unknown as Env).IDENTITY.idFromName('oauth')) as unknown as {
  oauthStorageOp(op: { op: string; key: string; value?: unknown }): Promise<{ value?: unknown }>
}

beforeAll(() => {
  fetchMock.activate()
  fetchMock.disableNetConnect()
})

afterAll(() => {
  fetchMock.deactivate()
})

describe('the headless sign-in link', () => {
  it('emails a link from the app, then the link alone signs in and redirects to the app with the code', async () => {
    const { sent, fetchWorker } = withMail()
    const email = 'lee@fund-one.example'
    const workos = workosUsers(email, 'user_01LINKLEE')
    const { verifier, challenge } = await pkce()

    const res = await ask(fetchWorker, { email: 'Lee@Fund-One.example', ...params(PREVIEW, challenge) })
    expect(res.status).toBe(202)
    expect(res.headers.get('content-type')).toContain('application/json')
    expect(await res.json()).toEqual({ sent: true, expires_in: 900 })

    expect(sent).toHaveLength(1)
    const m = sent[0]!
    expect(m.to).toBe(email)
    expect(m.from).toEqual({ name: 'Startups.Studio Fund I', email: 'fund@startups.studio' })
    expect(m.subject).toBe('Your sign-in link for the Startups.Studio Fund I deck (preview)')
    expect(m.text).toContain('works once, for 15 minutes, on any device')
    const link = linkIn(m)
    expect(m.html).toContain(link)

    // Opened (on any device: no cookie): straight to the app with the code. No page of ours.
    const open = await SELF.fetch(link, { redirect: 'manual' })
    expect(open.status).toBe(302)
    expect(open.headers.get('content-type') ?? '').not.toContain('text/html')
    const back = new URL(open.headers.get('location')!)
    expect(`${back.origin}${back.pathname}`).toBe(`${PREVIEW}/auth/callback`)
    expect(back.searchParams.get('state')).toBe('deck-state')
    expect(back.searchParams.get('iss')).toBe(BASE)
    const code = back.searchParams.get('code')!
    expect(code).toMatch(/^ac_/)
    expect(workos.creates).toBe(1)

    // The app redeems it with its verifier, then reads who signed in.
    const tok = await SELF.fetch(`${BASE}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: `${PREVIEW}/auth/callback`, client_id: TRUSTED_ACCOUNT_CLIENT_ID, code_verifier: verifier }).toString(),
    })
    expect(tok.status).toBe(200)
    const { access_token } = (await tok.json()) as { access_token: string }
    const who = (await (await SELF.fetch(`${BASE}/oauth/userinfo`, { headers: { authorization: `Bearer ${access_token}` } })).json()) as Record<string, unknown>
    expect(who.email).toBe(email)
    expect(who.email_verified).toBe(true)
    expect(who.amr).toEqual(['magic_link'])

    // Once: opened again, nothing (and no HTML).
    const again = await SELF.fetch(link, { redirect: 'manual' })
    expect(again.status).toBe(410)
    expect(again.headers.get('content-type')).toContain('text/plain')
  })

  it('opened twice at once, signs in once', async () => {
    const { sent, fetchWorker } = withMail()
    const email = 'race@fund-one.example'
    workosUsers(email, 'user_01LINKRACE')
    const { challenge } = await pkce()
    await ask(fetchWorker, { email, ...params(PITCH, challenge) })
    const link = linkIn(sent[0]!)
    const both = await Promise.all([SELF.fetch(link, { redirect: 'manual' }), SELF.fetch(link, { redirect: 'manual' })])
    expect(both.map((r) => r.status).sort()).toEqual([302, 410])
  })

  it('expires after 15 minutes: back to the app with error=access_denied, no code', async () => {
    const { sent, fetchWorker } = withMail()
    const email = 'late@fund-one.example'
    const workos = workosUsers(email, 'user_01LINKLATE')
    const { challenge } = await pkce()
    await ask(fetchWorker, { email, ...params(PITCH, challenge, 'late-state') })
    const link = linkIn(sent[0]!)
    const key = await linkKey(link)
    const rec = (await oauthShard().oauthStorageOp({ op: 'get', key })).value as { expiresAt: number }
    expect(rec.expiresAt - Date.now()).toBeGreaterThan(14 * 60_000)
    expect(rec.expiresAt - Date.now()).toBeLessThanOrEqual(15 * 60_000)
    await oauthShard().oauthStorageOp({ op: 'put', key, value: { ...rec, expiresAt: Date.now() - 1 } })

    const res = await SELF.fetch(link, { redirect: 'manual' })
    expect(res.status).toBe(302)
    const back = new URL(res.headers.get('location')!)
    expect(`${back.origin}${back.pathname}`).toBe(`${PITCH}/auth/callback`)
    expect(back.searchParams.get('error')).toBe('access_denied')
    expect(back.searchParams.get('error_description')).toBe('link_expired')
    expect(back.searchParams.get('state')).toBe('late-state')
    expect(back.searchParams.has('code')).toBe(false)
    expect(workos.creates).toBe(0)
  })

  it('an unknown link is a plain 410, never a page', async () => {
    const res = await SELF.fetch(`${BASE}/oauth/magic-link/${'x'.repeat(43)}`, { redirect: 'manual' })
    expect(res.status).toBe(410)
    expect(res.headers.get('content-type')).toContain('text/plain')
  })

  it('only for the trusted-account client, an allowlisted redirect and S256 PKCE', async () => {
    const { sent, fetchWorker } = withMail()
    const { challenge } = await pkce()
    const base = { email: 'x@fund-one.example', ...params(PITCH, challenge) }
    const cases: Array<[Record<string, string>, string]> = [
      [{ ...base, client_id: 'cid_someone_else' }, 'unauthorized_client'],
      [{ ...base, redirect_uri: 'https://pitch.evil.example/auth/callback' }, 'invalid_request'],
      [{ ...base, code_challenge: '' }, 'invalid_request'],
      [{ ...base, code_challenge_method: 'plain' }, 'invalid_request'],
      [{ ...base, scope: 'openid sb:do' }, 'invalid_scope'],
      [{ ...base, email: 'not-an-address' }, 'invalid_request'],
    ]
    for (const [body, error] of cases) {
      const res = await ask(fetchWorker, body)
      expect(res.status, JSON.stringify(body)).toBe(400)
      expect(((await res.json()) as { error: string }).error).toBe(error)
    }
    expect(sent).toHaveLength(0)
  })

  it('sends 5 links an hour to one address, then 429', async () => {
    const { sent, fetchWorker } = withMail()
    const { challenge } = await pkce()
    const statuses: number[] = []
    for (let i = 0; i < 6; i++) statuses.push((await ask(fetchWorker, { email: 'flood@fund-one.example', ...params(PITCH, challenge) })).status)
    expect(statuses).toEqual([202, 202, 202, 202, 202, 429])
    expect(sent).toHaveLength(5)
  })

  it('a refused send is a 502 and leaves no working link', async () => {
    const { sent, fetchWorker } = withMail({ fail: true })
    const { challenge } = await pkce()
    const res = await ask(fetchWorker, { email: 'refused@fund-one.example', ...params(PITCH, challenge) })
    expect(res.status).toBe(502)
    expect(sent).toHaveLength(0)
  })
})

describe('provider=GoogleOAuth on /oauth/authorize, for the trusted client', () => {
  const authorize = (extra: Record<string, string>, challenge: string) => {
    const u = new URL(`${BASE}/oauth/authorize`)
    u.search = new URLSearchParams({ ...params(PITCH, challenge), ...extra }).toString()
    return u.toString()
  }

  it('goes straight to Google through WorkOS, with no id.org.ai page, and comes back to authorize without provider', async () => {
    const { challenge } = await pkce()
    const r1 = await SELF.fetch(authorize({ provider: 'GoogleOAuth', login_hint: 'lp@gmail.com' }, challenge), { redirect: 'manual' })
    expect(r1.status).toBe(302)
    const login = new URL(r1.headers.get('location')!)
    expect(login.pathname).toBe('/login')
    expect(login.searchParams.get('provider')).toBe('GoogleOAuth')
    expect(login.searchParams.get('prompt')).toBe('login')
    expect(login.searchParams.get('login_hint')).toBe('lp@gmail.com')
    const back = new URL(login.searchParams.get('continue')!)
    expect(back.pathname).toBe('/oauth/authorize')
    expect(back.searchParams.has('provider')).toBe(false)
    expect(back.searchParams.get('state')).toBe('deck-state')

    const r2 = await SELF.fetch(login.toString(), { redirect: 'manual' })
    expect(r2.status).toBe(302)
    const workos = new URL(r2.headers.get('location')!)
    expect(workos.pathname).toBe('/user_management/authorize')
    expect(workos.searchParams.get('provider')).toBe('GoogleOAuth')
    expect(workos.searchParams.get('login_hint')).toBe('lp@gmail.com')
  })

  it('an unknown provider gets no shortcut', async () => {
    const { challenge } = await pkce()
    const odd = await SELF.fetch(authorize({ provider: 'EvilOAuth' }, challenge), { redirect: 'manual' })
    expect(new URL(odd.headers.get('location')!).searchParams.has('provider')).toBe(false)
  })
})
