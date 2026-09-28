/**
 * A DLVP token is never an id.org.ai sign-in session (release review, main
 * never deployed).
 *
 * POST /dlvp/session is anonymous and signs its request-object with the
 * id.org.ai key, putting the caller's `identifier` in `sub`. It used to sign
 * under `iss: https://id.org.ai`, the sign-in session issuer, so the session
 * it returned, set as the `auth` cookie (or posted to /auth/verify), was a
 * sign-in session as whatever user id the caller named: /api/me answered
 * `{ authenticated: true, user: { id: <that id> } }`. The production DLVP
 * signer now signs under DLVP_TOKEN_ISSUER (`https://id.org.ai/dlvp`), which
 * every session verifier refuses, and DLVP refuses a sign-in JWT in turn.
 *
 * Runs the real worker (SELF) with the production signer (no injected deps).
 */
import { describe, it, expect } from 'vitest'
import { SELF, env } from 'cloudflare:test'
import { getSigningKeyManager } from '../worker/middleware/tenant'
import { DLVP_TOKEN_ISSUER, signerFromKeyManager } from '../worker/dlvp/nonce'
import type { Env } from '../worker/types'

const BASE = 'https://id.org.ai'
const VICTIM = 'user_01VICTIMVICTIMVICTIMVICTIM'

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

describe('DLVP tokens are not sign-in sessions', () => {
  it('the anonymous /dlvp/session JWT is issued under the DLVP issuer, not the sign-in issuer', async () => {
    const session = await openSession(VICTIM)
    const claims = claimsOf(session)
    expect(claims.iss).toBe(DLVP_TOKEN_ISSUER)
    expect(claims.iss).not.toBe(BASE)
    expect(claims.sub).toBe(VICTIM)
  })

  it('as the auth cookie it authenticates no one: /api/me, /api/session, an authenticated route', async () => {
    const session = await openSession(VICTIM)
    const cookie = `auth=${session}`

    const me = await SELF.fetch(`${BASE}/api/me`, { headers: { cookie } })
    expect(await me.json()).toEqual({ authenticated: false })

    const s = await SELF.fetch(`${BASE}/api/session`, { headers: { cookie } })
    expect(s.status).not.toBe(200)
    expect(await s.text()).not.toContain(VICTIM)

    const keys = await SELF.fetch(`${BASE}/api/keys`, { headers: { cookie } })
    expect(keys.status).toBe(401)
  })

  it('/auth/verify refuses it', async () => {
    const session = await openSession(VICTIM)
    const res = await SELF.fetch(`${BASE}/auth/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: session }),
    })
    const body = (await res.json()) as { valid: boolean }
    expect(body.valid).toBe(false)
  })

  it('a sign-in JWT (iss https://id.org.ai, same key) is refused as a DLVP session', async () => {
    const manager = getSigningKeyManager(env as unknown as Env)
    const signIn = await manager.sign({ sub: VICTIM, nonce: 'n', epcisEventId: 'epcis:x' }, { issuer: BASE, expiresIn: 60 })
    expect(await signerFromKeyManager(manager).verify(signIn)).toBeNull()
    const res = await SELF.fetch(`${BASE}/dlvp/settle`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ session: signIn, consumerPresentation: 'x~', brandPresentation: 'y~' }),
    })
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('SESSION_INVALID')
  })

  it('the production signer refuses to sign under the sign-in issuer', () => {
    const manager = getSigningKeyManager(env as unknown as Env)
    expect(() => signerFromKeyManager(manager, BASE)).toThrow()
    expect(() => signerFromKeyManager(manager, `${BASE}/`)).toThrow()
  })
})
