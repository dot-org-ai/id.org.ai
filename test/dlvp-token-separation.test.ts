/**
 * A DLVP token is never an id.org.ai sign-in credential (release review; main's
 * DLVP had never been deployed).
 *
 * POST /dlvp/session is anonymous and signs a request-object whose `sub` is the
 * caller's `identifier`. It used to sign with the id.org.ai issuer key under
 * `iss: https://id.org.ai`, so the session it returned was a sign-in session
 * as whatever user id the caller named: as the `auth` cookie /api/me answered
 * `{ authenticated: true, user: { id: <that id> } }`, /auth/verify answered
 * valid, and the `auth` worker (which verifies against the published JWKS with
 * no issuer check) accepted it as that user. Now:
 *
 *   - DLVP signs with its own key set (getDlvpSigningKeyManager), which is not
 *     published at /.well-known/jwks.json, under `iss: https://id.org.ai/dlvp`;
 *   - a DLVP token must say it is a session (`dlvp_typ`) and carry a nonce to
 *     settle, so a receipt VC cannot be replayed as one;
 *   - /dlvp/* is served only when DLVP_ENABLED is "true" (production: unset).
 *
 * Runs the real worker (SELF) with the production signer (no injected deps).
 */
import { describe, it, expect } from 'vitest'
import { SELF, env } from 'cloudflare:test'
import * as jose from 'jose'
import { getSigningKeyManager, getDlvpSigningKeyManager } from '../worker/middleware/tenant'
import { DLVP_TOKEN_ISSUER, signerFromKeyManager } from '../worker/dlvp/nonce'
import { createDlvpApp } from '../worker/routes/dlvp'
import type { Env } from '../worker/types'
// @ts-expect-error vite ?raw import
import wranglerConfig from '../worker/wrangler.jsonc?raw'

const BASE = 'https://id.org.ai'
const VICTIM = 'user_01VICTIMVICTIMVICTIMVICTIM'
const e = () => env as unknown as Env

function claimsOf(jwt: string): Record<string, unknown> {
  const b64 = jwt.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/')
  return JSON.parse(atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4)))
}

async function openSession(identifier: string): Promise<string> {
  const res = await SELF.fetch(`${BASE}/dlvp/session`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ identifier, consumerAsk: [] }),
  })
  expect(res.status).toBe(200)
  return ((await res.json()) as { session: string }).session
}

async function settleWith(session: string): Promise<{ status: number; code: string }> {
  const res = await SELF.fetch(`${BASE}/dlvp/settle`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ session, consumerPresentation: 'x~', brandPresentation: 'y~' }),
  })
  return { status: res.status, code: ((await res.json()) as { error: { code: string } }).error.code }
}

describe('DLVP tokens are not sign-in credentials', () => {
  it('the session is signed with a key the published JWKS does not carry, under the DLVP issuer', async () => {
    const session = await openSession(VICTIM)
    const claims = claimsOf(session)
    expect(claims.iss).toBe(DLVP_TOKEN_ISSUER)
    expect(claims.dlvp_typ).toBe('co-presentation-request')

    const published = (await (await SELF.fetch(`${BASE}/.well-known/jwks.json`)).json()) as jose.JSONWebKeySet
    const kid = jose.decodeProtectedHeader(session).kid
    expect(published.keys.some((k) => k.kid === kid)).toBe(false)
    // What the `auth` worker does: verify against the published JWKS, no issuer check.
    await expect(jose.jwtVerify(session, jose.createLocalJWKSet(published))).rejects.toThrow()
  })

  it('as the auth cookie it authenticates no one: /api/me, /api/session, an authenticated route', async () => {
    const cookie = `auth=${await openSession(VICTIM)}`
    const me = await SELF.fetch(`${BASE}/api/me`, { headers: { cookie } })
    expect(await me.json()).toEqual({ authenticated: false })
    const s = await SELF.fetch(`${BASE}/api/session`, { headers: { cookie } })
    expect(s.status).not.toBe(200)
    expect(await s.text()).not.toContain(VICTIM)
    expect((await SELF.fetch(`${BASE}/api/keys`, { headers: { cookie } })).status).toBe(401)
  })

  it('/auth/verify refuses it', async () => {
    const res = await SELF.fetch(`${BASE}/auth/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: await openSession(VICTIM) }),
    })
    expect(((await res.json()) as { valid: boolean }).valid).toBe(false)
  })

  it('a sign-in JWT (the id.org.ai key) is refused as a DLVP session', async () => {
    const signIn = await getSigningKeyManager(e()).sign({ sub: VICTIM, nonce: 'n', dlvp_typ: 'co-presentation-request' }, { issuer: BASE, expiresIn: 60 })
    expect(await settleWith(signIn)).toEqual({ status: 400, code: 'SESSION_INVALID' })
  })

  it('a DLVP token that is not a session (a receipt, or no nonce) does not settle', async () => {
    const signer = signerFromKeyManager(getDlvpSigningKeyManager(e()))
    const receipt = await signer.sign({ sub: 'grai', dlvp_typ: 'consent-receipt' }, { expiresIn: 60 })
    expect(await settleWith(receipt)).toEqual({ status: 400, code: 'SESSION_INVALID' })
    const noNonce = await signer.sign({ sub: 'x', dlvp_typ: 'co-presentation-request' }, { expiresIn: 60 })
    expect(await settleWith(noNonce)).toEqual({ status: 400, code: 'SESSION_INVALID' })
  })

  it('the production signer refuses to sign under the sign-in issuer', () => {
    const manager = getDlvpSigningKeyManager(e())
    expect(() => signerFromKeyManager(manager, BASE)).toThrow()
    expect(() => signerFromKeyManager(manager, `${BASE}/`)).toThrow()
  })

  it('/dlvp/session refuses an oversized body', async () => {
    const res = await SELF.fetch(`${BASE}/dlvp/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ identifier: 'x', consumerAsk: ['a'.repeat(20_000)] }),
    })
    expect(res.status).toBe(400)
  })
})

describe('DLVP is off unless DLVP_ENABLED is "true"', () => {
  const post = (app: ReturnType<typeof createDlvpApp>, envVars: Partial<Env>) =>
    app.request(
      '/dlvp/session',
      { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ identifier: VICTIM, consumerAsk: [] }) },
      { ...e(), ...envVars } as Env,
    )

  it('unset or anything but "true": every /dlvp/* route is a 404 and nothing is signed', async () => {
    const app = createDlvpApp()
    for (const flag of [undefined, '', 'false', '1', 'TRUE']) {
      const res = await post(app, { DLVP_ENABLED: flag })
      expect(res.status).toBe(404)
      expect(await res.text()).not.toContain('session')
    }
    expect((await app.request('/dlvp/receipt/x', {}, { ...e(), DLVP_ENABLED: undefined } as Env)).status).toBe(404)
  })

  it('"true" serves it', async () => {
    expect((await post(createDlvpApp(), { DLVP_ENABLED: 'true' })).status).toBe(200)
  })

  it('production config leaves it unset', () => {
    expect(wranglerConfig).toContain('"vars"')
    expect(wranglerConfig).not.toContain('DLVP_ENABLED')
  })
})
