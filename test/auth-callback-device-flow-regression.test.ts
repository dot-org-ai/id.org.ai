/**
 * Regression test — production incident 2026-07-23:
 * GET /api/callback returned a bare 500 while completing the auto_dev_cli
 * OAuth device flow (user_code G9QTTYLC), after the founder authorized in the
 * browser. /.well-known/jwks.json was also 500ing live.
 *
 * Root cause (worker/middleware/tenant.ts): getSigningKeyManager cached the
 * SigningKeyManager at module level WITH a Durable Object stub captured in the
 * storageOp closure. DO stubs are request-scoped I/O objects in the Workers
 * runtime — any LATER request that made the manager touch storage (its lazy
 * key load, or rotation) blew up with:
 *
 *   "Cannot perform I/O on behalf of a different request ... (I/O type: OutgoingFactory)"
 *
 * Production sequence: the CLI's POST /oauth/device constructed the manager
 * (via getOAuthProvider) WITHOUT loading keys; the founder's browser callback
 * then called signingManager.sign() (worker/routes/auth.ts:369) in a DIFFERENT
 * request → ensureLoaded ran its first storage op through the stale stub →
 * uncaught throw → Hono's default 500. Once poisoned, every signing/JWKS
 * operation in the isolate failed the same way.
 *
 * This file replays that exact request sequence in-process via SELF
 * (real IDENTITY DO + KV; only the WorkOS upstream is mocked).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock } from 'cloudflare:test'

const BASE = 'https://id.org.ai'

beforeAll(() => {
  fetchMock.activate()
  fetchMock.disableNetConnect()

  // WorkOS code exchange — the one upstream call that must succeed for the
  // callback to proceed to JWT signing (where the regression lived).
  fetchMock
    .get('https://api.workos.com')
    .intercept({ method: 'POST', path: '/user_management/authenticate' })
    .reply(
      200,
      JSON.stringify({
        access_token: 'at_opaque_test_access_token',
        refresh_token: 'rt_test_refresh_token',
        user: { id: 'user_01TESTFOUNDER', email: 'founder@example.com', first_name: 'Test', last_name: 'Founder' },
        organization_id: 'org_01TESTORG',
      }),
      { headers: { 'content-type': 'application/json' } },
    )
    .persist()

  // Profile/org enrichment lookups: the handler null-fallbacks when these
  // fail, so reply 500 — we only care that they're intercepted (net is off).
  fetchMock
    .get('https://api.workos.com')
    .intercept({ path: /^\/user_management\/users\// })
    .reply(500, '')
    .persist()
  fetchMock
    .get('https://api.workos.com')
    .intercept({ path: /^\/organizations\// })
    .reply(500, '')
    .persist()
})

afterAll(() => {
  fetchMock.deactivate()
})

describe('device-flow login callback (2026-07-23 500 regression)', () => {
  it('completes /api/callback with a 302 to the /device continue URL even when an earlier request constructed the signing manager', async () => {
    // 1. CLI starts the device flow. Pre-fix, THIS request constructed the
    //    module-level SigningKeyManager (via getOAuthProvider) and captured
    //    this request's DO stub in the storageOp closure — without loading
    //    keys, leaving the I/O for a later, different request.
    const deviceRes = await SELF.fetch(`${BASE}/oauth/device`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'client_id=auto_dev_cli',
    })
    expect(deviceRes.status).toBe(200)
    const device = (await deviceRes.json()) as { user_code: string; device_code: string }
    expect(device.user_code).toBeTruthy()

    // 2. Browser: /login stores the login CSRF and bounces to WorkOS with the
    //    device page as the continue URL — capture the state param, exactly
    //    what WorkOS would echo back.
    const continueUrl = `${BASE}/device?user_code=${device.user_code}`
    const loginRes = await SELF.fetch(`${BASE}/login?provider=GitHubOAuth&continue=${encodeURIComponent(continueUrl)}`, {
      redirect: 'manual',
    })
    expect(loginRes.status).toBe(302)
    const authUrl = new URL(loginRes.headers.get('location')!)
    expect(authUrl.hostname).toBe('api.workos.com')
    const state = authUrl.searchParams.get('state')!
    expect(state).toBeTruthy()

    // 3. WorkOS redirects back — the EXACT failing request shape from the
    //    incident: /api/callback?code=…&state={csrf, continue: /device?user_code=…,
    //    origin: https://id.org.ai} (same-origin path → cookie + redirect).
    //    Pre-fix this returned a bare 500 from signingManager.sign().
    const cbRes = await SELF.fetch(`${BASE}/api/callback?code=01KY7SA4Z7VCEYK80BAEZ68STK&state=${encodeURIComponent(state)}`, {
      redirect: 'manual',
    })
    expect(cbRes.status).toBe(302)
    expect(cbRes.headers.get('location')).toBe(continueUrl)
    expect(cbRes.headers.get('set-cookie') || '').toContain('auth=')
  })

  it('serves /.well-known/jwks.json on every request, not only the first in an isolate', async () => {
    const first = await SELF.fetch(`${BASE}/.well-known/jwks.json`)
    expect(first.status).toBe(200)
    const second = await SELF.fetch(`${BASE}/.well-known/jwks.json`)
    expect(second.status).toBe(200)
    const jwks = (await second.json()) as { keys: Array<{ kid: string }> }
    expect(jwks.keys.length).toBeGreaterThan(0)
  })
})
