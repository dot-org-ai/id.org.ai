/**
 * The send and guess budgets are per path (round-3 security review, R4-1).
 *
 * 92e6a78 made /federation/email/send and magic-link spend ONE per-address
 * send counter (`code-send:<email>`, 5 per hour). /federation/email/send is
 * public, so anyone could spend a person's whole hourly budget with five
 * requests and lock them out of magic-link sign-in at every relying party.
 * Now each path has its own counters:
 *
 *   fed  code-send:fed:<email>, code-guess:email:fed:<email>
 *        (POST /federation/email/send, POST /federation/email/verify)
 *   ml   code-send:ml:<email>, code-guess:email:ml:<email>
 *        (POST /api/magic-link, AuthService.sendMagicLink, POST /magic-link/:flow)
 *
 * and a send restarts only its own path's guess budget. Every guess still
 * belongs to one send (a federation transaction or a magic-link flow, 5
 * guesses each), so per address: at most 5 sends x 5 guesses per path per
 * send window, 50 across both paths; 100 over any 60 minutes (a 60-minute
 * interval can straddle two fixed send windows).
 *
 * Runs the real worker (SELF, real IdentityDO); only WorkOS is faked.
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

let ipSeq = 0
const nextIp = () => `203.0.113.${(ipSeq++ % 250) + 1}`
const wrong = (i: number) => String(100000 + i)

// ── The federation path (public) ──────────────────────────────────────────

function fedSend(email: string): Promise<Response> {
  return SELF.fetch(`${BASE}/federation/email/send`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email }),
  })
}

const fecCookie = (res: Response) => res.headers.getSetCookie().find((c) => c.startsWith('__fec='))?.split(';')[0] ?? ''

function fedVerify(email: string, code: string, cookie: string, ip = nextIp()): Promise<Response> {
  return SELF.fetch(`${BASE}/federation/email/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'cf-connecting-ip': ip, cookie },
    body: JSON.stringify({ email, code, continue: '/' }),
  })
}

// ── The magic-link path (listed clients and service bindings) ─────────────

async function listedClient(): Promise<string> {
  const id = 'cid_magiclink_test_10'
  const secret = `cs_${crypto.randomUUID().replace(/-/g, '')}`
  await oauth().oauthStorageOp({
    op: 'put',
    key: `client:${id}`,
    value: { id, name: 'Listed', secret, redirectUris: [CB], grantTypes: ['authorization_code'], responseTypes: ['code'], scopes: ['openid'], trusted: false, tokenEndpointAuthMethod: 'client_secret_basic', createdAt: Date.now() },
  })
  return `Basic ${btoa(`${id}:${secret}`)}`
}

/** POST /api/magic-link as a listed client; the verify_url on success. */
async function mlSendHttp(email: string, basic: string): Promise<string | null> {
  const res = await SELF.fetch(`${BASE}/api/magic-link`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: basic },
    body: JSON.stringify({ email }),
  })
  if (res.status !== 202) return null
  return ((await res.json()) as { verify_url: string }).verify_url
}

/** AuthService.sendMagicLink over the binding; the verify_url on success. */
async function mlSendRpc(email: string): Promise<string | null> {
  const r = await authService().sendMagicLink({ email })
  return r.ok ? r.verify_url : null
}

/** Open a flow's page in "this browser": the flow cookie a guess must carry. */
async function openFlow(verifyUrl: string): Promise<{ path: string; cookie: string }> {
  const path = new URL(verifyUrl).pathname
  const page = await SELF.fetch(`${BASE}${path}`)
  expect(page.status).toBe(200)
  const cookie = page.headers.getSetCookie().find((c) => c.startsWith('__mlf='))!.split(';')[0]!
  return { path, cookie }
}

function mlGuess(path: string, cookie: string, code: string, ip = nextIp()): Promise<Response> {
  return SELF.fetch(`${BASE}${path}`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie, 'cf-connecting-ip': ip },
    body: `code=${code}`,
  })
}

describe('R4-1: a flood of the public federation path does not lock anyone out of magic-link', () => {
  it('fed sends and fed guesses exhausted for an address; magic-link still sends (HTTP and RPC) and its code is checked', async () => {
    const email = 'victim@fedflood.example'
    const workos = fakeWorkOS(email)

    // The attacker spends the public path's whole send budget...
    const sends = await Promise.all(Array.from({ length: 20 }, () => fedSend(email)))
    const fedOk = sends.filter((r) => r.status === 200)
    expect(fedOk.length).toBe(SEND_BUDGET)
    expect((await fedSend(email)).status).toBe(429)
    // ...and the public path's guess budget for the address (wrong codes,
    // from fresh IPs, on its own transactions).
    let n = 0
    const fedGuesses = await Promise.all(fedOk.flatMap((r) => Array.from({ length: 5 }, () => fedVerify(email, wrong(n++), fecCookie(r)))))
    expect(fedGuesses.some((r) => r.status === 429)).toBe(true)
    const checksAfterFlood = workos.checks
    expect(checksAfterFlood).toBeLessThanOrEqual(GUESSES_PER_SEND)

    // The person signs in through a relying party's magic link: both callers send.
    const basic = await listedClient()
    const viaHttp = await mlSendHttp(email, basic)
    expect(viaHttp).toBeTruthy()
    const viaRpc = await mlSendRpc(email)
    expect(viaRpc).toBeTruthy()
    expect(workos.sends).toBe(SEND_BUDGET + 2)

    // ...and their code reaches WorkOS (a 400 "not valid" from the fake), not
    // a 429 from a guess budget the attacker spent on the other path.
    const { path, cookie } = await openFlow(viaRpc!)
    const res = await mlGuess(path, cookie, '424242')
    expect(res.status).toBe(400)
    expect(workos.checks).toBe(checksAfterFlood + 1)
  })

  it('a code already sent by magic link stays guessable after the public path spends its guess budget', async () => {
    const email = 'midflight@fedflood.example'
    const workos = fakeWorkOS(email)
    const flow = await openFlow((await mlSendRpc(email))!)

    // While the person reads their mail, the attacker sends federation codes
    // (each used to restart the SHARED guess budget) and burns guesses on them.
    const sends = (await Promise.all(Array.from({ length: 10 }, () => fedSend(email)))).filter((r) => r.status === 200)
    expect(sends.length).toBeGreaterThan(0)
    let n = 0
    const fedGuesses = await Promise.all(sends.flatMap((r) => Array.from({ length: 5 }, () => fedVerify(email, wrong(n++), fecCookie(r)))))
    expect(fedGuesses.some((r) => r.status === 429)).toBe(true)
    const checksAfterFlood = workos.checks

    const res = await mlGuess(flow.path, flow.cookie, '424242')
    expect(res.status).toBe(400)
    expect(workos.checks).toBe(checksAfterFlood + 1)
  })
})

describe('R4-1: a flood of the magic-link path does not lock anyone out of the federation fallback', () => {
  it('ml sends and ml guesses exhausted for an address; /federation/email/send still sends and its code is checked', async () => {
    const email = 'victim@mlflood.example'
    const workos = fakeWorkOS(email)
    const basic = await listedClient()

    const urls = await Promise.all([
      ...Array.from({ length: 10 }, () => mlSendRpc(email)),
      ...Array.from({ length: 10 }, () => mlSendHttp(email, basic)),
    ])
    const flows = urls.filter((u): u is string => !!u)
    expect(flows.length).toBe(SEND_BUDGET)
    expect(await mlSendRpc(email)).toBeNull()
    let n = 0
    const opened = await Promise.all(flows.map(openFlow))
    const mlGuesses = await Promise.all(opened.flatMap((f) => Array.from({ length: 5 }, () => mlGuess(f.path, f.cookie, wrong(n++)))))
    expect(mlGuesses.some((r) => r.status === 429)).toBe(true)
    const checksAfterFlood = workos.checks
    expect(checksAfterFlood).toBeLessThanOrEqual(GUESSES_PER_SEND)

    const send = await fedSend(email)
    expect(send.status).toBe(200)
    const res = await fedVerify(email, '424242', fecCookie(send))
    expect(res.status).toBe(401)
    expect(workos.checks).toBe(checksAfterFlood + 1)
  })
})

describe('R4-1: guesses per address stay bounded with both paths flooded at once', () => {
  it(`sends <= ${SEND_BUDGET} per path, WorkOS code checks <= ${GUESSES_PER_SEND} x sends <= ${2 * SEND_BUDGET * GUESSES_PER_SEND}`, async () => {
    const email = 'both@flood.example'
    const workos = fakeWorkOS(email)
    const basic = await listedClient()
    let n = 0

    // Every send, the moment it succeeds, fires 10 wrong guesses (twice its
    // per-send budget) from fresh IPs, while the other sends race to restart
    // their path's guess budget.
    const fedBurst = () =>
      fedSend(email).then(async (res) => {
        if (res.status !== 200) return 0
        await Promise.all(Array.from({ length: 10 }, () => fedVerify(email, wrong(n++), fecCookie(res))))
        return 1
      })
    const mlBurst = (send: () => Promise<string | null>) =>
      send().then(async (url) => {
        if (!url) return 0
        const f = await openFlow(url)
        await Promise.all(Array.from({ length: 10 }, () => mlGuess(f.path, f.cookie, wrong(n++))))
        return 1
      })

    const [fed, ml] = await Promise.all([
      Promise.all(Array.from({ length: 15 }, fedBurst)),
      Promise.all([
        ...Array.from({ length: 8 }, () => mlBurst(() => mlSendRpc(email))),
        ...Array.from({ length: 7 }, () => mlBurst(() => mlSendHttp(email, basic))),
      ]),
    ])
    const fedSends = fed.reduce((a, b) => a + b, 0)
    const mlSends = ml.reduce((a, b) => a + b, 0)

    expect(fedSends).toBe(SEND_BUDGET)
    expect(mlSends).toBe(SEND_BUDGET)
    expect(workos.sends).toBe(fedSends + mlSends)
    expect(workos.checks).toBeGreaterThan(0)
    expect(workos.checks).toBeLessThanOrEqual(GUESSES_PER_SEND * (fedSends + mlSends))
    expect(workos.checks).toBeLessThanOrEqual(2 * SEND_BUDGET * GUESSES_PER_SEND)

    // Both send budgets spent: no further guess budget can be opened on either path.
    expect((await fedSend(email)).status).toBe(429)
    expect(await mlSendRpc(email)).toBeNull()
    expect(await mlSendHttp(email, basic)).toBeNull()
    expect(workos.sends).toBe(fedSends + mlSends)
  })
})
