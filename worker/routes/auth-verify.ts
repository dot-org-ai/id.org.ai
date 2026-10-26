/**
 * Token-verification wire surface for id.org.ai.
 *
 * Exposes `POST /auth/verify` — the cross-origin / non-binding counterpart to
 * the `AuthIdentity` RPC entrypoint (worker/index.ts). Both share one core:
 * `verifyIdentityTokenWithEnv`, a thin wrapper that loads the live JWKS from
 * the signing-key manager and delegates to the stable `verifyToken` primitive
 * (src/sdk/auth/verify-token.ts → src/sdk/oauth/jwt-verify.ts).
 *
 * The JWKS source (`JwksResolver`) and the session-record check
 * (`SessionChecker`) are injectable so the endpoint can be driven hermetically
 * in tests without a Durable Object, while production uses the signing-key
 * manager and the Person's IdentityDO.
 */
import { Hono } from 'hono'
import * as jose from 'jose'
import type { Env, Variables } from '../types'
import { getSigningKeyManager } from '../middleware/tenant'
import { checkSessionState } from '../utils/session'
import { verifyToken as verifyIdentityToken, CANONICAL_AUTH_ORIGIN } from '../../src/sdk/auth'
import type { VerifyTokenResult } from '../../src/sdk/auth'
import type { JWKS } from '../../src/sdk/jwt/signing'

export type JwksResolver = (env: Env) => Promise<JWKS>

/** Production resolver — reads the live JWKS from the signing-key manager. */
export const defaultJwksResolver: JwksResolver = (env) => getSigningKeyManager(env).getJWKS()

/**
 * Is a verified token's browser session still live (H4)? Production asks the
 * session record in the Person's IdentityDO; tests inject a stand-in.
 */
export type SessionChecker = (env: Env, payload: jose.JWTPayload, token: string) => Promise<boolean>

/**
 * Verify an id.org.ai-issued JWT against our live signing keys. Pins the
 * canonical issuer and never throws. Shared by the RPC entrypoint and the
 * HTTP endpoint.
 */
export async function verifyIdentityTokenWithEnv(
  token: string,
  env: Env,
  resolveJwks: JwksResolver = defaultJwksResolver,
  checkSession: SessionChecker = checkSessionState,
): Promise<VerifyTokenResult> {
  // Separate a SERVER-side failure (JWKS/signing-key manager unavailable) from a
  // TOKEN-side failure. A server failure must not be dressed up as "invalid
  // token" (a 401) nor leak the raw internal error — it returns the stable
  // `jwks_unavailable` code (logged server-side) which the HTTP layer maps to
  // 503. Token-validity errors flow through verifyToken unchanged.
  let jwks: JWKS
  try {
    jwks = await resolveJwks(env)
  } catch (err) {
    console.error('[auth/verify] JWKS resolution failed:', err instanceof Error ? err.message : err)
    return { valid: false, error: 'jwks_unavailable' }
  }
  const result = await verifyIdentityToken(token, { jwks, issuer: CANONICAL_AUTH_ORIGIN })
  if (!result.valid) return result
  // The signature is good; a browser session must also still be live: not
  // logged out, not frozen (security review H4). Other token kinds pass.
  if (!(await checkSession(env, jose.decodeJwt(token), token))) {
    return { valid: false, error: 'Session revoked' }
  }
  return result
}

/**
 * Build the `/auth/verify` Hono app. `resolveJwks` defaults to the
 * signing-key manager; tests inject a fixed JWKS.
 */
export function createAuthVerifyApp(resolveJwks: JwksResolver = defaultJwksResolver, checkSession: SessionChecker = checkSessionState) {
  const app = new Hono<{ Bindings: Env; Variables: Variables }>()

  app.post('/auth/verify', async (c) => {
    let body: { token?: unknown }
    try {
      body = (await c.req.json()) as { token?: unknown }
    } catch {
      return c.json({ valid: false, error: 'Invalid JSON body' } satisfies VerifyTokenResult, 400)
    }

    const token = body?.token
    if (typeof token !== 'string' || token.trim() === '') {
      return c.json({ valid: false, error: 'Missing or empty token' } satisfies VerifyTokenResult, 400)
    }

    const result = await verifyIdentityTokenWithEnv(token, c.env, resolveJwks, checkSession)
    if (!result.valid && result.error === 'jwks_unavailable') {
      // Server-side verification substrate is down — 503, not a token 401, and
      // a generic client message (the real cause is already logged).
      return c.json({ valid: false, error: 'Verification temporarily unavailable' } satisfies VerifyTokenResult, 503)
    }
    return c.json(result, result.valid ? 200 : 401)
  })

  return app
}

/** Production mount used by worker/index.ts. */
export const authVerifyRoutes = createAuthVerifyApp()
