/**
 * Brute force of emailed sign-in codes (security review S1), on the
 * magic-link path.
 *
 * POST /magic-link/:flow turns a correct WorkOS Magic Auth code into an
 * id.org.ai session. Every guess:
 *
 *   - must present the flow's browser cookie (the browser that opened the
 *     flow's page), and a flow allows 5 guesses;
 *   - reserves one of 5 guesses per address per 15 minutes (a new send starts
 *     it afresh) and one of 50 per IP per hour, atomically, before WorkOS is
 *     asked (worker/utils/code-guard.ts).
 *
 * On the live branch these repros drove the public /federation/email/verify
 * route, the other path that spends the same guess budgets; main has no
 * federation routes, so they drive /magic-link/:flow.
 *
 * Runs the real worker (SELF, real IdentityDO); only WorkOS is faked, and the
 * fake counts every code check.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock } from 'cloudflare:test'
import { authService } from './helpers/auth-service'

const BASE = 'https://id.org.ai'
const WORKOS = 'https://api.workos.com'
const GOOD_CODE = '424242'

beforeAll(() => {
  fetchMock.activate()
  fetchMock.disableNetConnect()
  fetchMock.get(WORKOS).intercept({ path: /^\/user_management\/users\// }).reply(500, '').persist()
  fetchMock.get(WORKOS).intercept({ path: /^\/organizations\// }).reply(500, '').persist()
})

afterAll(() => {
  fetchMock.deactivate()
})

/**
 * Fake WorkOS for the addresses `match` accepts: every send succeeds; a code
 * check succeeds for GOOD_CODE and is refused otherwise. Returns the number
 * of code checks WorkOS was asked for.
 */
function fakeWorkOS(match: (email: string) => boolean): { checks: number; sends: number } {
  const seen = { checks: 0, sends: 0 }
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'POST', path: '/user_management/magic_auth', body: (b: string) => match(JSON.parse(b).email) })
    .reply(() => {
      seen.sends++
      return { statusCode: 201, data: JSON.stringify({ id: `ma_${seen.sends}` }), responseOptions: { headers: { 'content-type': 'application/json' } } }
    })
    .persist()
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'POST', path: '/user_management/authenticate', body: (b: string) => match(new URLSearchParams(b).get('email') ?? '') })
    .reply((opts) => {
      seen.checks++
      const body = new URLSearchParams(String(opts.body))
      if (body.get('code') === GOOD_CODE) {
        return {
          statusCode: 200,
          data: JSON.stringify({ user: { id: `user_${crypto.randomUUID()}`, email: body.get('email'), first_name: 'Ada' } }),
          responseOptions: { headers: { 'content-type': 'application/json' } },
        }
      }
      return { statusCode: 400, data: '{"code":"invalid_one_time_code"}' }
    })
    .persist()
  return seen
}

type Flow = { path: string; cookie: string }

/** Send a code over the binding and open its flow page in "this browser". */
async function send(email: string): Promise<Flow> {
  const r = await authService().sendMagicLink({ email })
  expect(r.ok).toBe(true)
  const path = new URL((r as { verify_url: string }).verify_url).pathname
  const page = await SELF.fetch(`${BASE}${path}`)
  expect(page.status).toBe(200)
  const cookie = page.headers.getSetCookie().find((c) => c.startsWith('__mlf='))!.split(';')[0]!
  return { path, cookie }
}

function verify(flow: Flow, code: string, cookie: string | null = flow.cookie, ip = '192.0.2.10'): Promise<Response> {
  return SELF.fetch(`${BASE}${flow.path}`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'cf-connecting-ip': ip, ...(cookie ? { cookie } : {}) },
    body: `code=${code}`,
  })
}

const wrong = (i: number) => String(100000 + i)
const signedIn = (res: Response) => res.headers.getSetCookie().some((c) => c.startsWith('auth='))

describe('S1: a guess is bound to its flow', () => {
  it('refuses a guess without the flow cookie, without asking WorkOS', async () => {
    const email = 'nocookie@example.com'
    const workos = fakeWorkOS((e) => e === email)
    const flow = await send(email)
    const res = await verify(flow, GOOD_CODE, null)
    expect(res.status).toBe(403)
    expect(workos.checks).toBe(0)
  })

  it("refuses another flow's cookie", async () => {
    const workos = fakeWorkOS((e) => e.endsWith('@swap.example'))
    const mine = await send('mine@swap.example')
    const victim = await send('victim@swap.example')
    const res = await verify(victim, GOOD_CODE, mine.cookie)
    expect(res.status).toBe(403)
    expect(workos.checks).toBe(0)
  })
})

describe('S1: guesses at one address are capped across flows', () => {
  it('five wrong guesses spread over two flows spend the address; the sixth is refused unasked until a new send', async () => {
    const email = 'serial@example.com'
    const workos = fakeWorkOS((e) => e === email)
    const a = await send(email)
    const b = await send(email)
    for (let i = 0; i < 3; i++) expect((await verify(a, wrong(i))).status).toBe(400)
    for (let i = 3; i < 5; i++) expect((await verify(b, wrong(i))).status).toBe(400)
    expect(workos.checks).toBe(5)

    // Flow `a` has guesses of its own left, but the address has none: the
    // sixth guess, even the right code, is refused without asking WorkOS.
    const sixth = await verify(a, GOOD_CODE)
    expect(sixth.status).toBe(429)
    expect(Number(sixth.headers.get('retry-after'))).toBeGreaterThan(0)
    expect(workos.checks).toBe(5)

    // A new send opens a new flow and a fresh budget; its code works, once.
    const c = await send(email)
    const ok = await verify(c, GOOD_CODE)
    expect(ok.status).toBe(302)
    expect(signedIn(ok)).toBe(true)
    expect((await verify(c, GOOD_CODE)).status).toBe(410)
  })

  it('20 parallel guesses on one flow reach WorkOS at most 5 times', async () => {
    const email = 'parallel@example.com'
    const workos = fakeWorkOS((e) => e === email)
    const flow = await send(email)
    const results = await Promise.all(Array.from({ length: 20 }, (_, i) => verify(flow, wrong(i))))
    expect(workos.checks).toBeLessThanOrEqual(5)
    expect(results.some((r) => signedIn(r))).toBe(false)
  })

  it('parallel guesses spread over several flows still reach WorkOS at most 5 times', async () => {
    const email = 'spread@example.com'
    const workos = fakeWorkOS((e) => e === email)
    // Four sends first (each would start the budget afresh), then the burst.
    const flows = [await send(email), await send(email), await send(email), await send(email)]
    const results = await Promise.all(flows.flatMap((f, t) => Array.from({ length: 5 }, (_, i) => verify(f, wrong(t * 10 + i)))))
    expect(workos.checks).toBeLessThanOrEqual(5)
    expect(results.filter((r) => r.status === 429).length).toBe(20 - workos.checks)
  })
})

describe('S1: guesses from one IP are capped across addresses', () => {
  it('50 guesses per IP per hour, then refused unasked; another IP is unaffected', async () => {
    const workos = fakeWorkOS((e) => e.endsWith('@spray.example'))
    const ip = '198.51.100.7'
    for (let i = 0; i < 50; i++) {
      const email = `u${i}@spray.example`
      expect((await verify(await send(email), wrong(i), undefined, ip)).status).toBe(400)
    }
    expect(workos.checks).toBe(50)

    const flow = await send('u50@spray.example')
    expect((await verify(flow, wrong(50), undefined, ip)).status).toBe(429)
    expect(workos.checks).toBe(50)
    expect((await verify(flow, wrong(51), undefined, '198.51.100.8')).status).toBe(400)
    expect(workos.checks).toBe(51)
  })
})
