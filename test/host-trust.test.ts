/**
 * No trust from a request's host (round-2 review, B1).
 *
 * POST /api/magic-link used to treat any request whose host was outside the
 * worker's public route names as a service binding. Cloudflare also serves
 * public traffic on the fully-qualified spelling of those names (id.org.ai.,
 * oauth.do.) with the dot kept in request.url, so an unauthenticated
 * `POST https://id.org.ai./api/magic-link` was served as a binding and had
 * WorkOS email a code. Now:
 *
 *   - HTTP POST /api/magic-link takes only an authenticated confidential client
 *     that MAGIC_LINK_CLIENTS lists (401 otherwise, 403 when unlisted), on
 *     every host and every spelling of it;
 *   - workers in the account call AuthService.sendMagicLink over RPC, which no
 *     public request can reach;
 *   - every trust or redirect decision compares hosts in canonical spelling
 *     (lowercase, no trailing dot).
 *
 * Runs the real worker (SELF, real IdentityDO); only WorkOS is faked.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock, env } from 'cloudflare:test'
import { authService } from './helpers/auth-service'
import { canonicalHostname, canonicalOrigin, isAllowedOrigin } from '../src/sdk/csrf'
import { resolveContinue, isListedContinueHost } from '../worker/utils/relying-parties'
import { getRootDomain } from '../worker/utils/cookies'
import { canonicalizeResourceUri } from '../worker/utils/mcp-resource'
import { parseTrustedAccountDomains } from '../worker/routes/oauth'
import type { Env } from '../worker/types'

const BASE = 'https://id.org.ai'
const WORKOS = 'https://api.workos.com'
const CB = 'https://waitlist.example/auth/cb'

type OAuthStub = { oauthStorageOp(op: { op: 'put' | 'get'; key: string; value?: unknown }): Promise<Record<string, unknown>> }
const oauth = () => env.IDENTITY.get(env.IDENTITY.idFromName('oauth')) as unknown as OAuthStub

beforeAll(() => {
  fetchMock.activate()
  fetchMock.disableNetConnect()
})

afterAll(() => {
  fetchMock.deactivate()
})

function countSends(match: (email: string) => boolean): { n: number } {
  const calls = { n: 0 }
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'POST', path: '/user_management/magic_auth', body: (b: string) => match(JSON.parse(b).email) })
    .reply(() => {
      calls.n++
      return { statusCode: 201, data: JSON.stringify({ id: `ma_${calls.n}` }), responseOptions: { headers: { 'content-type': 'application/json' } } }
    })
    .persist()
  return calls
}

function post(url: string, body: Record<string, unknown>, headers: Record<string, string> = {}): Promise<Response> {
  return SELF.fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) })
}

/** A confidential client record; `listed` picks an id MAGIC_LINK_CLIENTS names (vitest.config.ts: 01..20; this file uses 11..14). */
let listedSeq = 10
async function confidentialClient(listed: boolean): Promise<{ id: string; basic: string }> {
  const id = listed ? `cid_magiclink_test_${String(++listedSeq).padStart(2, '0')}` : `cid_unlisted_${crypto.randomUUID().replace(/-/g, '')}`
  const secret = `cs_${crypto.randomUUID().replace(/-/g, '')}`
  await oauth().oauthStorageOp({
    op: 'put',
    key: `client:${id}`,
    value: { id, name: 'Waitlist', secret, redirectUris: [CB], grantTypes: ['authorization_code'], responseTypes: ['code'], scopes: ['openid'], trusted: false, tokenEndpointAuthMethod: 'client_secret_basic', createdAt: Date.now() },
  })
  return { id, basic: `Basic ${btoa(`${id}:${secret}`)}` }
}

// Every spelling a public request can arrive on, and hosts outside the routes.
const HOSTS = [
  'https://id.org.ai.',
  'https://ID.ORG.AI.',
  'https://Id.Org.Ai',
  'https://oauth.do.',
  'https://auth.org.ai..',
  'https://oauth.dotdo.workers.dev.',
  'https://internal.example',
  'https://Internal.Example.',
]

describe('B1: HTTP POST /api/magic-link never infers trust from the host', () => {
  it('an unauthenticated POST is 401 on every host spelling, and nothing is sent', async () => {
    const sends = countSends((e) => e.endsWith('@nohost.example'))
    for (const host of HOSTS) {
      const res = await post(`${host}/api/magic-link`, { email: 'victim@nohost.example', continue: '/dash/profile' })
      expect(res.status, host).toBe(401)
    }
    expect(sends.n).toBe(0)
  })

  it('an authenticated but unlisted client is 403 on every host spelling', async () => {
    const sends = countSends((e) => e.endsWith('@unlisted.example'))
    const c = await confidentialClient(false)
    for (const host of HOSTS) {
      const res = await post(`${host}/api/magic-link`, { email: 'victim@unlisted.example' }, { authorization: c.basic })
      expect(res.status, host).toBe(403)
    }
    expect(sends.n).toBe(0)
  })

  it('a listed client is served on the trailing-dot host too (the credential decides, not the host)', async () => {
    const sends = countSends((e) => e.endsWith('@listed-host.example'))
    const c = await confidentialClient(true)
    const res = await post('https://id.org.ai./api/magic-link', { email: 'ada@listed-host.example', continue: 'https://waitlist.example/in' }, { authorization: c.basic })
    expect(res.status).toBe(202)
    expect(((await res.json()) as { verify_url: string }).verify_url).toMatch(/^https:\/\/id\.org\.ai\/magic-link\/[0-9a-f]{48}$/)
    expect(sends.n).toBe(1)
  })
})

describe('B1: AuthService.sendMagicLink (the binding path)', () => {
  it('sends, and the flow it opens is a working sign-in page', async () => {
    const sends = countSends((e) => e === 'rpc@bound.example')
    const r = await authService().sendMagicLink({ email: 'RPC@Bound.example', continue: '/dash/profile' })
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.sent).toBe(true)
    expect(r.expires_in).toBe(600)
    expect(r.verify_url).toMatch(/^https:\/\/id\.org\.ai\/magic-link\/[0-9a-f]{48}$/)
    expect(sends.n).toBe(1)
    const page = await SELF.fetch(`${BASE}${new URL(r.verify_url).pathname}`)
    expect(page.status).toBe(200)
  })

  it('lends a named client its redirect origins, and refuses an unknown client', async () => {
    countSends((e) => e.endsWith('@rpc-client.example'))
    const c = await confidentialClient(false) // a binding needs no listing
    const ok = await authService().sendMagicLink({ email: 'a@rpc-client.example', continue: 'https://waitlist.example/welcome', clientId: c.id })
    expect(ok.ok).toBe(true)
    const unknown = await authService().sendMagicLink({ email: 'b@rpc-client.example', clientId: 'cid_nobody' })
    expect(unknown).toMatchObject({ ok: false, status: 400, error: 'invalid_client' })
  })

  it('refuses a continue off every allowed origin, and an origin that is not http(s)', async () => {
    const sends = countSends((e) => e.endsWith('@rpc-bad.example'))
    for (const bad of ['https://evil.example/', '//evil.example', 'javascript:alert(1)']) {
      expect(await authService().sendMagicLink({ email: 'a@rpc-bad.example', continue: bad })).toMatchObject({ ok: false, status: 400 })
    }
    expect(await authService().sendMagicLink({ email: 'a@rpc-bad.example', origin: 'javascript:alert(1)' })).toMatchObject({ ok: false, status: 400 })
    expect(sends.n).toBe(0)
  })

  it("canonicalises the binding's origin before comparing continue to it", async () => {
    countSends((e) => e.endsWith('@rpc-origin.example'))
    const r = await authService().sendMagicLink({ email: 'a@rpc-origin.example', continue: 'https://App.Example./after', origin: 'https://app.example' })
    expect(r.ok).toBe(true)
  })
})

describe('B1: hosts are compared in canonical spelling everywhere', () => {
  it('canonicalHostname / canonicalOrigin', () => {
    expect(canonicalHostname('ID.org.AI.')).toBe('id.org.ai')
    expect(canonicalHostname('id.org.ai..')).toBe('id.org.ai')
    expect(canonicalOrigin('https://ID.org.ai./x?y')).toBe('https://id.org.ai')
    expect(canonicalOrigin('http://localhost:8787/')).toBe('http://localhost:8787')
    expect(canonicalOrigin('not a url')).toBeNull()
  })

  it('CORS / Origin allowlist: trailing dot and case are the same origin; paths and userinfo are not origins', () => {
    expect(isAllowedOrigin('https://id.org.ai.')).toBe(true)
    expect(isAllowedOrigin('https://ID.ORG.AI')).toBe(true)
    expect(isAllowedOrigin('https://evil.example.')).toBe(false)
    expect(isAllowedOrigin('https://id.org.ai/evil')).toBe(false)
    expect(isAllowedOrigin('https://evil.example@id.org.ai')).toBe(false)
    expect(isAllowedOrigin('https://id.org.ai.evil.example')).toBe(false)
  })

  it('continue policy: accepts and returns the canonical spelling; refuses what it refused before', async () => {
    const e = env as unknown as Env
    expect(await resolveContinue(e, 'https://ID.org.ai./dash', { requestOrigin: 'https://id.org.ai' })).toBe('https://id.org.ai/dash')
    expect(await resolveContinue(e, 'https://oauth.do./x', { requestOrigin: 'https://id.org.ai.' })).toBe('https://oauth.do/x')
    // A relative path on the trailing-dot host is this host.
    expect(await resolveContinue(e, '/dash', { requestOrigin: 'https://id.org.ai.' })).toBe('/dash')
    expect(await resolveContinue(e, 'https://evil.example./', { requestOrigin: 'https://id.org.ai.' })).toBeNull()
    expect(await resolveContinue(e, 'https://id.org.ai.evil.example/', { requestOrigin: 'https://id.org.ai' })).toBeNull()
    expect(isListedContinueHost({ LOGIN_CONTINUE_HOSTS: 'Management.Studio.,*.dotdo.workers.dev.' } as Env, 'app.DOTDO.workers.dev.')).toBe(true)
    expect(isListedContinueHost({ LOGIN_CONTINUE_HOSTS: 'management.studio' } as Env, 'Management.Studio.')).toBe(true)
  })

  it('trusted-account domains, cookie domain and MCP audience', () => {
    expect(parseTrustedAccountDomains('Startup.Games.').has('startup.games')).toBe(true)
    expect(getRootDomain('id.org.ai.')).toBeNull()
    expect(getRootDomain('Api.Headless.LY.')).toBe('.headless.ly')
    expect(canonicalizeResourceUri('https://ID.org.ai./mcp')).toBe('https://id.org.ai/mcp')
  })

  it('a login started on the trailing-dot host binds the canonical origin (no bounce to a dotted host)', async () => {
    const res = await SELF.fetch('https://id.org.ai./login?provider=GitHubOAuth&continue=/dash', { redirect: 'manual' })
    expect(res.status).toBe(302)
    const location = new URL(res.headers.get('location')!)
    expect(location.searchParams.get('redirect_uri')).toBe('https://id.org.ai/api/callback')
    const state = location.searchParams.get('state')!
    const padded = state.replace(/-/g, '+').replace(/_/g, '/')
    const decoded = JSON.parse(atob(padded + '='.repeat((4 - (padded.length % 4)) % 4))) as { csrf: string; origin: string }
    expect(decoded.origin).toBe('https://id.org.ai')
    const record = (await oauth().oauthStorageOp({ op: 'get', key: `login-csrf:${decoded.csrf}` })).value as { origin: string }
    expect(record.origin).toBe('https://id.org.ai')
  })
})
