/**
 * Magic-link budgets under concurrency (security review S2).
 *
 * The 5-guess budget per sign-in flow was a read-modify-write across two
 * Durable Object calls, so N guesses fired at once all read `attempts: 0`
 * and all reached WorkOS. The budget is now incremented and checked in one
 * Durable Object call (IdentityDO.consumeBudget) before WorkOS is asked.
 *
 * Runs the real worker (SELF, real IdentityDO); only WorkOS is faked, and the
 * fake counts how often it is asked.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock } from 'cloudflare:test'

const BASE = 'https://id.org.ai'
const WORKOS = 'https://api.workos.com'
/** A host outside the public routes: the request arrives as a service binding. */
const BINDING = 'https://internal.example'
const PARALLEL = 20
const BUDGET = 5

beforeAll(() => {
  fetchMock.activate()
  fetchMock.disableNetConnect()
  fetchMock.get(WORKOS).intercept({ path: /^\/user_management\/users\// }).reply(500, '').persist()
  fetchMock.get(WORKOS).intercept({ path: /^\/organizations\// }).reply(500, '').persist()
})

afterAll(() => {
  fetchMock.deactivate()
})

/** Count WorkOS magic_auth sends for one address. */
function countSends(email: string): { n: number } {
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

/** Count WorkOS code checks for one address; every one is a wrong code. */
function countWrongCodeChecks(email: string): { n: number } {
  const calls = { n: 0 }
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'POST', path: '/user_management/authenticate', body: (b: string) => new URLSearchParams(b).get('email') === email })
    .reply(() => {
      calls.n++
      return { statusCode: 400, data: '{"code":"invalid_one_time_code"}' }
    })
    .persist()
  return calls
}

async function openFlow(email: string): Promise<{ path: string; cookie: string }> {
  const res = await SELF.fetch(`${BINDING}/api/magic-link`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email }),
  })
  expect(res.status).toBe(202)
  const { verify_url } = (await res.json()) as { verify_url: string }
  const path = new URL(verify_url).pathname
  const page = await SELF.fetch(`${BASE}${path}`)
  expect(page.status).toBe(200)
  const cookie = page.headers.getSetCookie().find((c) => c.startsWith('__mlf='))!.split(';')[0]!
  return { path, cookie }
}

function guess(path: string, cookie: string, code: string): Promise<Response> {
  return SELF.fetch(`${BASE}${path}`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
    body: `code=${code}`,
  })
}

describe('S2: the magic-link code budget holds under parallel guesses', () => {
  it(`${PARALLEL} parallel guesses on one flow reach WorkOS at most ${BUDGET} times, and end the flow`, async () => {
    const email = 'race@example.com'
    countSends(email)
    const { path, cookie } = await openFlow(email)
    const checks = countWrongCodeChecks(email)

    const results = await Promise.all(
      Array.from({ length: PARALLEL }, (_, i) => guess(path, cookie, String(100000 + i))),
    )
    const statuses = results.map((r) => r.status)

    expect(checks.n).toBeLessThanOrEqual(BUDGET)
    expect(checks.n).toBeGreaterThan(0)
    for (const s of statuses) expect([400, 410]).toContain(s)
    // At most BUDGET - 1 guesses are told to retry; the rest see the flow end.
    expect(statuses.filter((s) => s === 400).length).toBeLessThanOrEqual(BUDGET - 1)

    // The flow is spent: the page, and one more guess, are an expired link,
    // and WorkOS is not asked again.
    expect((await SELF.fetch(`${BASE}${path}`)).status).toBe(410)
    expect((await guess(path, cookie, '999999')).status).toBe(410)
    expect(checks.n).toBeLessThanOrEqual(BUDGET)
  })

  it(`${PARALLEL} parallel sends to one address reach WorkOS at most ${BUDGET} times`, async () => {
    const email = 'flood@example.com'
    const sends = countSends(email)
    const results = await Promise.all(
      Array.from({ length: PARALLEL }, () =>
        SELF.fetch(`${BINDING}/api/magic-link`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ email }),
        }),
      ),
    )
    const statuses = results.map((r) => r.status)
    expect(sends.n).toBeLessThanOrEqual(BUDGET)
    expect(statuses.filter((s) => s === 202).length).toBe(sends.n)
    expect(statuses.filter((s) => s === 429).length).toBe(PARALLEL - sends.n)
  })
})
