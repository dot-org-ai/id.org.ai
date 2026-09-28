/**
 * Who may ask id.org.ai to email a sign-in code (security review S3 / P1).
 *
 * POST /api/magic-link accepted any registered confidential client, and
 * registration (RFC 7591) is open: anyone could register a client, then have
 * id.org.ai's WorkOS account mail codes to any address (spam relay, targeted
 * lockout of the address's send budget, and codes relayed into first-party
 * sessions). Now only service bindings and the clients MAGIC_LINK_CLIENTS
 * lists may call it, and all callers together share an hourly send cap.
 *
 * vitest.config.ts lists cid_magiclink_test_01..20; this file seeds 15..20.
 * Runs the real worker (SELF, real IdentityDO); only WorkOS is faked.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock, env } from 'cloudflare:test'

const BASE = 'https://id.org.ai'
const WORKOS = 'https://api.workos.com'
const BINDING = 'https://internal.example'
const CB = 'https://waitlist.example/auth/cb'
/** The hourly cap across every caller, and the counter it lives in (worker/routes/magic-link.ts). */
const GLOBAL_CAP = 300
const GLOBAL_KEY = 'magiclink-rl:global'

type OAuthStub = { oauthStorageOp(op: { op: 'put' | 'get'; key: string; value?: unknown }): Promise<Record<string, unknown>> }
const oauth = () => env.IDENTITY.get(env.IDENTITY.idFromName('oauth')) as unknown as OAuthStub

beforeAll(() => {
  fetchMock.activate()
  fetchMock.disableNetConnect()
})

afterAll(() => {
  fetchMock.deactivate()
})

/** Count WorkOS sends to addresses `match` accepts. */
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

function sendMagicLink(body: Record<string, unknown>, headers: Record<string, string> = {}, base = BASE): Promise<Response> {
  return SELF.fetch(`${base}/api/magic-link`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  })
}

async function registerConfidential(): Promise<{ id: string; secret: string }> {
  const res = await SELF.fetch(`${BASE}/oauth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: 'Anyone at all',
      redirect_uris: [CB],
      token_endpoint_auth_method: 'client_secret_basic',
      grant_types: ['authorization_code', 'refresh_token'],
    }),
  })
  expect(res.status).toBe(201)
  const j = (await res.json()) as { client_id: string; client_secret: string }
  return { id: j.client_id, secret: j.client_secret }
}

let seq = 14
/** A confidential client whose id MAGIC_LINK_CLIENTS lists (the record a registration would store). */
async function allowlistedClient(): Promise<{ id: string; secret: string }> {
  const id = `cid_magiclink_test_${String(++seq).padStart(2, '0')}`
  const secret = `cs_${crypto.randomUUID().replace(/-/g, '')}`
  await oauth().oauthStorageOp({
    op: 'put',
    key: `client:${id}`,
    value: { id, name: 'Listed', secret, redirectUris: [CB], grantTypes: ['authorization_code'], responseTypes: ['code'], scopes: ['openid'], trusted: false, tokenEndpointAuthMethod: 'client_secret_basic', createdAt: Date.now() },
  })
  return { id, secret }
}

const basic = (c: { id: string; secret: string }) => ({ authorization: `Basic ${btoa(`${c.id}:${c.secret}`)}` })

describe('S3: POST /api/magic-link callers', () => {
  it('a freshly registered confidential client is refused (403), with either auth method, and nothing is sent', async () => {
    const sends = countSends((e) => e.endsWith('@dcr.example'))
    const c = await registerConfidential()
    const viaBasic = await sendMagicLink({ email: 'victim@dcr.example', continue: '/dash/profile' }, basic(c))
    expect(viaBasic.status).toBe(403)
    expect(((await viaBasic.json()) as { error: string }).error).toBe('unauthorized_client')
    const viaPost = await sendMagicLink({ email: 'victim@dcr.example', client_id: c.id, client_secret: c.secret })
    expect(viaPost.status).toBe(403)
    expect(sends.n).toBe(0)
  })

  it('a listed client is served (202); a listed client with a wrong secret is still 401', async () => {
    const sends = countSends((e) => e.endsWith('@listed.example'))
    const c = await allowlistedClient()
    const ok = await sendMagicLink({ email: 'ada@listed.example', continue: 'https://waitlist.example/welcome' }, basic(c))
    expect(ok.status).toBe(202)
    expect(sends.n).toBe(1)
    const wrong = await sendMagicLink({ email: 'ada@listed.example' }, basic({ id: c.id, secret: 'cs_wrong' }))
    expect(wrong.status).toBe(401)
    expect(sends.n).toBe(1)
  })

  it('a service binding is served (202) without a client', async () => {
    const sends = countSends((e) => e.endsWith('@bound.example'))
    const res = await sendMagicLink({ email: 'grace@bound.example', continue: 'https://internal.example/after' }, {}, BINDING)
    expect(res.status).toBe(202)
    expect(sends.n).toBe(1)
  })
})

describe('S3: the hourly cap across every caller', () => {
  it(`holds at ${GLOBAL_CAP} sends an hour for bindings and listed clients alike`, async () => {
    const sends = countSends((e) => e.endsWith('@cap.example'))
    // Stand in for an hour's traffic from many callers: one send left.
    await oauth().oauthStorageOp({ op: 'put', key: GLOBAL_KEY, value: { count: GLOBAL_CAP - 1, windowStartedAt: Date.now() } })

    expect((await sendMagicLink({ email: 'last@cap.example' }, {}, BINDING)).status).toBe(202)
    expect(sends.n).toBe(1)

    const overBinding = await sendMagicLink({ email: 'over1@cap.example' }, {}, BINDING)
    expect(overBinding.status).toBe(429)
    expect(Number(overBinding.headers.get('retry-after'))).toBeGreaterThan(0)
    const c = await allowlistedClient()
    expect((await sendMagicLink({ email: 'over2@cap.example' }, basic(c))).status).toBe(429)
    expect(sends.n).toBe(1)
  })
})
