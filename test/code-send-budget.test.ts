/**
 * One send budget per address, shared and atomic (round-2 review, B2).
 *
 * /federation/email/send throttled with a get and a separate put against the
 * Durable Object, so parallel sends all read the same count and all passed;
 * and every successful send starts the address's guess budget afresh
 * (worker/utils/code-guard.ts), so unbounded sends meant unbounded guesses.
 * Now both routes that have a code emailed, /federation/email/send and
 * magic-link (HTTP and AuthService.sendMagicLink), reserve each send from ONE
 * per-address counter (`code-send:<normalised email>`, 5 per hour) with
 * IdentityDO.consumeBudget, before WorkOS is asked.
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

/** Fake WorkOS for one address: sends succeed, every code check is a wrong code. */
function fakeWorkOS(email: string): { sends: number; checks: number } {
  const seen = { sends: 0, checks: 0 }
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'POST', path: '/user_management/magic_auth', body: (b: string) => JSON.parse(b).email === email })
    .reply(() => {
      seen.sends++
      return { statusCode: 201, data: JSON.stringify({ id: `ma_${seen.sends}` }), responseOptions: { headers: { 'content-type': 'application/json' } } }
    })
    .persist()
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'POST', path: '/user_management/authenticate', body: (b: string) => new URLSearchParams(b).get('email') === email })
    .reply(() => {
      seen.checks++
      return { statusCode: 400, data: '{"code":"invalid_one_time_code"}' }
    })
    .persist()
  return seen
}

function fedSend(email: string): Promise<Response> {
  return SELF.fetch(`${BASE}/federation/email/send`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email }),
  })
}

const fecCookie = (res: Response) => res.headers.getSetCookie().find((c) => c.startsWith('__fec='))?.split(';')[0] ?? ''

function fedVerify(email: string, code: string, cookie: string, ip: string): Promise<Response> {
  return SELF.fetch(`${BASE}/federation/email/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'cf-connecting-ip': ip, cookie },
    body: JSON.stringify({ email, code, continue: '/' }),
  })
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

const wrong = (i: number) => String(100000 + i)

describe('B2: sends to one address are capped atomically', () => {
  it(`20 parallel /federation/email/send to one address: at most ${SEND_BUDGET} succeed, and only those reach WorkOS`, async () => {
    const email = 'flood@send.example'
    const workos = fakeWorkOS(email)
    const results = await Promise.all(Array.from({ length: 20 }, () => fedSend(email)))
    const ok = results.filter((r) => r.status === 200).length
    expect(ok).toBeLessThanOrEqual(SEND_BUDGET)
    expect(ok).toBe(SEND_BUDGET)
    expect(workos.sends).toBe(ok)
    const refused = results.filter((r) => r.status === 429)
    expect(refused.length).toBe(20 - ok)
    expect(Number(refused[0]!.headers.get('retry-after'))).toBeGreaterThan(0)
  })

  it('case variants share the budget', async () => {
    const workos = fakeWorkOS('casey@send.example')
    const spellings = ['casey@send.example', 'CASEY@send.example', ' Casey@Send.Example ', 'casey@SEND.example']
    const results = await Promise.all(Array.from({ length: 12 }, (_, i) => fedSend(spellings[i % spellings.length]!)))
    expect(results.filter((r) => r.status === 200).length).toBe(SEND_BUDGET)
    expect(workos.sends).toBe(SEND_BUDGET)
  })

  it('the budget is ONE counter across /federation/email/send, POST /api/magic-link and the RPC', async () => {
    const email = 'shared@send.example'
    const workos = fakeWorkOS(email)
    const basic = await listedClient()
    const results = await Promise.all([
      ...Array.from({ length: 7 }, () => fedSend(email).then((r) => r.status === 200)),
      ...Array.from({ length: 7 }, () => authService().sendMagicLink({ email }).then((r) => r.ok)),
      ...Array.from({ length: 6 }, () =>
        SELF.fetch(`${BASE}/api/magic-link`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization: basic },
          body: JSON.stringify({ email }),
        }).then((r) => r.status === 202),
      ),
    ])
    expect(results.filter(Boolean).length).toBe(SEND_BUDGET)
    expect(workos.sends).toBe(SEND_BUDGET)
    // ...and afterwards every route refuses the address.
    expect((await fedSend(email)).status).toBe(429)
    expect(await authService().sendMagicLink({ email })).toMatchObject({ ok: false, status: 429 })
  })
})

describe('B2: racing sends cannot buy guesses', () => {
  it(`parallel sends and guesses: WorkOS code checks never exceed ${GUESSES_PER_SEND} x successful sends`, async () => {
    const email = 'race@guess.example'
    const workos = fakeWorkOS(email)
    let guessN = 0
    // Each send, the moment it succeeds, fires 10 guesses with its own
    // transaction (twice its per-transaction budget), from its own IP, while
    // the other sends are still racing to restart the address's budget.
    const burst = (i: number) =>
      fedSend(email).then(async (res) => {
        if (res.status !== 200) return false
        const cookie = fecCookie(res)
        await Promise.all(Array.from({ length: 10 }, () => fedVerify(email, wrong(guessN++), cookie, `198.51.100.${i + 1}`)))
        return true
      })
    const outcomes = await Promise.all(Array.from({ length: 20 }, (_, i) => burst(i)))
    const successfulSends = outcomes.filter(Boolean).length
    expect(successfulSends).toBeLessThanOrEqual(SEND_BUDGET)
    expect(workos.sends).toBe(successfulSends)
    expect(workos.checks).toBeGreaterThan(0)
    expect(workos.checks).toBeLessThanOrEqual(GUESSES_PER_SEND * successfulSends)

    // With the send budget spent, no route can open another guess budget.
    expect((await fedSend(email)).status).toBe(429)
    expect(await authService().sendMagicLink({ email })).toMatchObject({ ok: false, status: 429 })
    expect(workos.sends).toBe(successfulSends)
  })
})
