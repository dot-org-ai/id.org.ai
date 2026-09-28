/**
 * Brute force of emailed sign-in codes (security review S1).
 *
 * Since 86c6afa, POST /federation/email/verify turns a correct WorkOS Magic
 * Auth code into an id.org.ai session, and production takes this path for
 * every viewer (MICROSOFT_CLIENT_ID is unset). It had no guess limit, no
 * browser binding and no link to a send, so anyone could try all 10^6 codes
 * against any address. Now:
 *
 *   - a verify must present the send transaction's cookie (same browser, same
 *     address, within 10 minutes), which allows 5 guesses;
 *   - every guess, on this route and on POST /magic-link/:flow, reserves one
 *     of 5 guesses per address per 15 minutes (a new send starts it afresh)
 *     and one of 50 per IP per hour, atomically, before WorkOS is asked.
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
          data: JSON.stringify({ user: { id: `user_${seen.checks}`, email: body.get('email'), first_name: 'Ada' } }),
          responseOptions: { headers: { 'content-type': 'application/json' } },
        }
      }
      return { statusCode: 400, data: '{"code":"invalid_one_time_code"}' }
    })
    .persist()
  return seen
}

/** POST /federation/email/send as the page does; returns the send cookie. */
async function send(email: string): Promise<string> {
  const res = await SELF.fetch(`${BASE}/federation/email/send`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email }),
  })
  expect(res.status).toBe(200)
  const cookie = res.headers.getSetCookie().find((c) => c.startsWith('__fec='))
  return cookie ? cookie.split(';')[0]! : ''
}

function verify(email: string, code: string, cookie = '', ip = '192.0.2.10'): Promise<Response> {
  return SELF.fetch(`${BASE}/federation/email/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'cf-connecting-ip': ip, ...(cookie ? { cookie } : {}) },
    body: JSON.stringify({ email, code, continue: '/' }),
  })
}

const wrong = (i: number) => String(100000 + i)

describe('S1: /federation/email/verify is bound to a send', () => {
  it('refuses a guess with no send transaction, without asking WorkOS', async () => {
    const email = 'nosend@example.com'
    const workos = fakeWorkOS((e) => e === email)
    const res = await verify(email, GOOD_CODE)
    expect(res.status).toBe(403)
    expect(workos.checks).toBe(0)
  })

  it("refuses another address's send transaction", async () => {
    const workos = fakeWorkOS((e) => e.endsWith('@swap.example'))
    const cookie = await send('mine@swap.example')
    const res = await verify('victim@swap.example', GOOD_CODE, cookie)
    expect(res.status).toBe(403)
    expect(workos.checks).toBe(0)
  })
})

describe('S1: guesses at one address are capped', () => {
  it('five wrong guesses in a row, then refused until a new send; the new code then works', async () => {
    const email = 'serial@example.com'
    const workos = fakeWorkOS((e) => e === email)
    const cookie = await send(email)
    for (let i = 0; i < 5; i++) expect((await verify(email, wrong(i), cookie)).status).toBe(401)
    expect(workos.checks).toBe(5)

    // The sixth guess, even the right code, is refused unasked.
    const sixth = await verify(email, GOOD_CODE, cookie)
    expect(sixth.status).toBe(429)
    expect(workos.checks).toBe(5)

    // A new send opens a new transaction and a fresh budget.
    const again = await send(email)
    const ok = await verify(email, GOOD_CODE, again)
    expect(ok.status).toBe(200)
    expect(ok.headers.getSetCookie().some((c) => c.startsWith('auth='))).toBe(true)
    // ...once: the transaction is spent.
    expect((await verify(email, GOOD_CODE, again)).status).toBe(403)
  })

  it('20 parallel guesses on one send reach WorkOS at most 5 times', async () => {
    const email = 'parallel@example.com'
    const workos = fakeWorkOS((e) => e === email)
    const cookie = await send(email)
    const results = await Promise.all(Array.from({ length: 20 }, (_, i) => verify(email, wrong(i), cookie)))
    const statuses = results.map((r) => r.status)
    expect(workos.checks).toBeLessThanOrEqual(5)
    expect(statuses.filter((s) => s === 401).length).toBe(workos.checks)
    expect(statuses.filter((s) => s === 429).length).toBe(20 - workos.checks)
  })

  it('parallel guesses spread over several sends still reach WorkOS at most 5 times', async () => {
    const email = 'spread@example.com'
    const workos = fakeWorkOS((e) => e === email)
    // Four sends first (each would start the budget afresh), then the burst.
    const cookies = [await send(email), await send(email), await send(email), await send(email)]
    const results = await Promise.all(
      cookies.flatMap((cookie, t) => Array.from({ length: 5 }, (_, i) => verify(email, wrong(t * 10 + i), cookie))),
    )
    expect(workos.checks).toBeLessThanOrEqual(5)
    expect(results.filter((r) => r.status === 429).length).toBe(20 - workos.checks)
  })

  it('the budget is shared with /magic-link/:flow', async () => {
    const email = 'shared@example.com'
    const workos = fakeWorkOS((e) => e === email)
    // A magic-link flow for the address (opened over a service binding)...
    const sent = await authService().sendMagicLink({ email })
    if (!sent.ok) throw new Error(`sendMagicLink: ${sent.status}`)
    const path = new URL(sent.verify_url).pathname
    const flowCookie = (await SELF.fetch(`${BASE}${path}`)).headers.getSetCookie().find((c) => c.startsWith('__mlf='))!.split(';')[0]!

    // ...then the federation path spends the address's five guesses...
    const cookie = await send(email)
    for (let i = 0; i < 5; i++) expect((await verify(email, wrong(i), cookie)).status).toBe(401)
    expect(workos.checks).toBe(5)

    // ...so the flow's first guess is refused without asking WorkOS.
    const res = await SELF.fetch(`${BASE}${path}`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: flowCookie, 'cf-connecting-ip': '192.0.2.10' },
      body: `code=${GOOD_CODE}`,
    })
    expect(res.status).toBe(429)
    expect(workos.checks).toBe(5)
  })
})

describe('S1: guesses from one IP are capped across addresses', () => {
  it('50 guesses per IP per hour, then refused unasked; another IP is unaffected', async () => {
    const workos = fakeWorkOS((e) => e.endsWith('@spray.example'))
    const ip = '198.51.100.7'
    for (let i = 0; i < 50; i++) {
      const email = `u${i}@spray.example`
      expect((await verify(email, wrong(i), await send(email), ip)).status).toBe(401)
    }
    expect(workos.checks).toBe(50)

    const email = 'u50@spray.example'
    const cookie = await send(email)
    expect((await verify(email, wrong(50), cookie, ip)).status).toBe(429)
    expect(workos.checks).toBe(50)
    expect((await verify(email, wrong(51), cookie, '198.51.100.8')).status).toBe(401)
    expect(workos.checks).toBe(51)
  })
})
