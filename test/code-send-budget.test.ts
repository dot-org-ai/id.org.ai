/**
 * One send budget per address, atomic (round-2 review, B2), on the magic-link
 * path.
 *
 * The send throttle used to be a get and a separate put against the Durable
 * Object, so parallel sends all read the same count and all passed; and every
 * successful send starts the address's guess budget afresh
 * (worker/utils/code-guard.ts), so unbounded sends meant unbounded guesses.
 * Now every send reserves, atomically with IdentityDO.consumeBudget and before
 * WorkOS is asked, from the per-address counter `code-send:ml:<email>`,
 * 5 per hour, shared by POST /api/magic-link (listed clients) and
 * AuthService.sendMagicLink (service bindings).
 *
 * On the live branch these repros drove the public /federation/email/send
 * route; main has no federation routes, so they drive the magic-link path,
 * which spends the same budget through the same code.
 *
 * Runs the real worker (SELF, real IdentityDO); only WorkOS is faked, and the
 * fake counts every send and every code check.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock, env } from 'cloudflare:test'
import { authService } from './helpers/auth-service'

const BASE = 'https://id.org.ai'
const WORKOS = 'https://api.workos.com'
const SEND_BUDGET = 5
const GUESSES_PER_SEND = 5
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

/** Fake WorkOS for one address (any spelling): sends succeed, every code check is a wrong code. */
function fakeWorkOS(email: string): { sends: number; checks: number } {
  const seen = { sends: 0, checks: 0 }
  const same = (e: string | null | undefined) => (e ?? '').trim().toLowerCase() === email
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'POST', path: '/user_management/magic_auth', body: (b: string) => same(JSON.parse(b).email) })
    .reply(() => {
      seen.sends++
      return { statusCode: 201, data: JSON.stringify({ id: `ma_${seen.sends}` }), responseOptions: { headers: { 'content-type': 'application/json' } } }
    })
    .persist()
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'POST', path: '/user_management/authenticate', body: (b: string) => same(new URLSearchParams(b).get('email')) })
    .reply(() => {
      seen.checks++
      return { statusCode: 400, data: '{"code":"invalid_one_time_code"}' }
    })
    .persist()
  return seen
}

async function listedClient(): Promise<string> {
  const id = 'cid_magiclink_test_09'
  const secret = `cs_${crypto.randomUUID().replace(/-/g, '')}`
  await oauth().oauthStorageOp({
    op: 'put',
    key: `client:${id}`,
    value: { id, name: 'Listed', secret, redirectUris: [CB], grantTypes: ['authorization_code'], responseTypes: ['code'], scopes: ['openid'], trusted: false, tokenEndpointAuthMethod: 'client_secret_basic', createdAt: Date.now() },
  })
  return `Basic ${btoa(`${id}:${secret}`)}`
}

/** AuthService.sendMagicLink over the binding; the verify_url on success. */
async function mlSendRpc(email: string): Promise<string | null> {
  const r = await authService().sendMagicLink({ email })
  return r.ok ? r.verify_url : null
}

/** POST /api/magic-link as a listed client. */
function mlSendHttp(email: string, basic: string): Promise<Response> {
  return SELF.fetch(`${BASE}/api/magic-link`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: basic },
    body: JSON.stringify({ email }),
  })
}

/** Open a flow's page in "this browser": the flow cookie a guess must carry. */
async function openFlow(verifyUrl: string): Promise<{ path: string; cookie: string }> {
  const path = new URL(verifyUrl).pathname
  const page = await SELF.fetch(`${BASE}${path}`)
  expect(page.status).toBe(200)
  const cookie = page.headers.getSetCookie().find((c) => c.startsWith('__mlf='))!.split(';')[0]!
  return { path, cookie }
}

function mlGuess(path: string, cookie: string, code: string, ip: string): Promise<Response> {
  return SELF.fetch(`${BASE}${path}`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie, 'cf-connecting-ip': ip },
    body: `code=${code}`,
  })
}

const wrong = (i: number) => String(100000 + i)

describe('B2: sends to one address are capped atomically', () => {
  it(`20 parallel sends to one address: at most ${SEND_BUDGET} succeed, and only those reach WorkOS`, async () => {
    const email = 'flood@send.example'
    const workos = fakeWorkOS(email)
    const results = await Promise.all(Array.from({ length: 20 }, () => authService().sendMagicLink({ email })))
    const ok = results.filter((r) => r.ok).length
    expect(ok).toBe(SEND_BUDGET)
    expect(workos.sends).toBe(ok)
    const refused = results.filter((r) => !r.ok)
    expect(refused.length).toBe(20 - ok)
    for (const r of refused) expect(r).toMatchObject({ ok: false, status: 429 })
    expect((refused[0] as { retryAfterSec?: number }).retryAfterSec).toBeGreaterThan(0)
  })

  it('case variants share the budget', async () => {
    const workos = fakeWorkOS('casey@send.example')
    const spellings = ['casey@send.example', 'CASEY@send.example', ' Casey@Send.Example ', 'casey@SEND.example']
    const results = await Promise.all(Array.from({ length: 12 }, (_, i) => authService().sendMagicLink({ email: spellings[i % spellings.length]! })))
    expect(results.filter((r) => r.ok).length).toBe(SEND_BUDGET)
    expect(workos.sends).toBe(SEND_BUDGET)
  })

  it('one counter for the path: POST /api/magic-link and the RPC share it', async () => {
    const email = 'shared@send.example'
    const workos = fakeWorkOS(email)
    const basic = await listedClient()
    const results = await Promise.all([
      ...Array.from({ length: 7 }, () => authService().sendMagicLink({ email }).then((r) => r.ok)),
      ...Array.from({ length: 6 }, () => mlSendHttp(email, basic).then((r) => r.status === 202)),
    ])
    expect(results.filter(Boolean).length).toBe(SEND_BUDGET)
    expect(workos.sends).toBe(SEND_BUDGET)
    // ...and afterwards both callers are refused the address.
    expect((await mlSendHttp(email, basic)).status).toBe(429)
    expect(await authService().sendMagicLink({ email })).toMatchObject({ ok: false, status: 429 })
    expect(workos.sends).toBe(SEND_BUDGET)
  })
})

describe('B2: racing sends cannot buy guesses', () => {
  it(`parallel sends and guesses: WorkOS code checks never exceed ${GUESSES_PER_SEND} x successful sends`, async () => {
    const email = 'race@guess.example'
    const workos = fakeWorkOS(email)
    let guessN = 0
    // Each send, the moment it succeeds, fires 10 guesses on its own flow
    // (twice its per-flow budget), from its own IP, while the other sends are
    // still racing to restart the address's guess budget.
    const burst = (i: number) =>
      mlSendRpc(email).then(async (url) => {
        if (!url) return false
        const f = await openFlow(url)
        await Promise.all(Array.from({ length: 10 }, () => mlGuess(f.path, f.cookie, wrong(guessN++), `198.51.100.${i + 1}`)))
        return true
      })
    const outcomes = await Promise.all(Array.from({ length: 20 }, (_, i) => burst(i)))
    const successfulSends = outcomes.filter(Boolean).length
    expect(successfulSends).toBeLessThanOrEqual(SEND_BUDGET)
    expect(workos.sends).toBe(successfulSends)
    expect(workos.checks).toBeGreaterThan(0)
    expect(workos.checks).toBeLessThanOrEqual(GUESSES_PER_SEND * successfulSends)

    // With the send budget spent, no further guess budget can be opened.
    expect(await mlSendRpc(email)).toBeNull()
    expect(workos.sends).toBe(successfulSends)
  })
})
