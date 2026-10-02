/**
 * Tenant resolution middleware for id.org.ai worker
 *
 * Resolves the identity shard key from auth credentials (API key, session token,
 * JWT cookie) and injects the correct IdentityDO stub into Hono context.
 * Each identity gets its own Durable Object instance.
 */

import * as jose from 'jose'
import type { IdentityStub } from '../../src/server/do/Identity'
import { SigningKeyManager } from '../../src/sdk/jwt/signing'
import { parseCookieValue } from '../utils/cookies'
import { isApiKeyPrefix, extractApiKey, extractSessionToken } from '../utils/extract'
import type { Env } from '../types'
import { workosUrl } from '../../src/sdk/workos/base'

/**
 * Get a DO stub for a specific identity shard.
 * Returns a typed IdentityStub for direct RPC calls.
 */
export function getStubForIdentity(env: Env, identityId: string): IdentityStub {
  const id = env.IDENTITY.idFromName(identityId)
  return env.IDENTITY.get(id) as unknown as IdentityStub
}

/**
 * Module-level cache for the SigningKeyManager.
 *
 * The manager itself is safe to cache across requests — its state is plain
 * data + CryptoKeys. The Durable Object STUB is not: DO stubs are
 * request-scoped I/O objects in the Workers runtime, and a stub captured in
 * one request's context throws
 *   "Cannot perform I/O on behalf of a different request (I/O type: OutgoingFactory)"
 * when any later request calls through it. Caching the stub in the storageOp
 * closure broke every signing/JWKS operation after the first request in an
 * isolate (500 on /api/callback login completion, /.well-known/jwks.json,
 * /oauth/token issuance, …).
 *
 * So: cache the manager (preserving the in-memory key cache that avoids
 * re-hitting the DO on every sign/verify), but create a FRESH stub from the
 * current request's env for each storage op. `signingKeyManagerEnv` is
 * re-pointed at the caller's env on every call so the closure never uses a
 * stale request's bindings.
 */
let cachedSigningKeyManager: SigningKeyManager | null = null
let signingKeyManagerEnv: Env | null = null

export function getSigningKeyManager(env: Env): SigningKeyManager {
  signingKeyManagerEnv = env
  if (!cachedSigningKeyManager) {
    cachedSigningKeyManager = new SigningKeyManager((op) => getStubForIdentity(signingKeyManagerEnv!, 'oauth').oauthStorageOp(op))
  }
  return cachedSigningKeyManager
}

let cachedDlvpKeyManager: SigningKeyManager | null = null
let dlvpKeyManagerEnv: Env | null = null

/**
 * The DLVP signer's own key set (storage key `dlvp-signing-keys` in the
 * 'oauth' shard). It is NOT the id.org.ai issuer key: nothing publishes it at
 * /.well-known/jwks.json, so no sign-in verifier anywhere (this worker, the
 * `auth` worker, a relying party fetching our JWKS) can accept a DLVP token,
 * whatever its claims. POST /dlvp/session is anonymous and signs claims the
 * caller chooses; it must never sign with a published key.
 */
export function getDlvpSigningKeyManager(env: Env): SigningKeyManager {
  dlvpKeyManagerEnv = env
  if (!cachedDlvpKeyManager) {
    cachedDlvpKeyManager = new SigningKeyManager((op) => getStubForIdentity(dlvpKeyManagerEnv!, 'oauth').oauthStorageOp(op), 'dlvp-signing-keys')
  }
  return cachedDlvpKeyManager
}

/**
 * Resolve the identity ID (shard key) from the request's auth credentials.
 * Returns null for anonymous/L0 requests that don't need a DO.
 */
export async function resolveIdentityId(request: Request, env: Env): Promise<string | null> {
  // 1. API key → KV lookup
  const apiKey = extractApiKey(request)
  if (apiKey) {
    const identityId = await env.SESSIONS.get(`apikey:${apiKey}`)
    return identityId
  }

  // 2. Session token → KV lookup
  const sessionToken = extractSessionToken(request)
  if (sessionToken) {
    const identityId = await env.SESSIONS.get(`session:${sessionToken}`)
    return identityId
  }

  // 3. JWT auth cookie → verify and extract identity
  const cookie = request.headers.get('cookie')
  if (cookie) {
    const jwt = parseCookieValue(cookie, 'auth')
    if (jwt) {
      try {
        const manager = getSigningKeyManager(env)
        const jwks = await manager.getJWKS()
        const localJwks = jose.createLocalJWKSet(jwks)
        const { payload } = await jose.jwtVerify(jwt, localJwks, { issuer: 'https://id.org.ai' })
        if (payload.sub) {
          return `human:${payload.sub}`
        }
      } catch (err) {
        console.error('[resolveIdentityId] JWT verification failed:', err instanceof Error ? err.message : err)
      }
    }
  }

  // 4. No credentials → anonymous (no DO needed)
  return null
}

/**
 * How the browser session in the `auth` cookie was established: the `amr`,
 * `idp` and `auth_time` claims /api/callback (or the magic-link flow) signed
 * into it. Undefined when there is no verifiable cookie or it carries none
 * (sessions minted before these claims existed).
 */
export async function readSessionSignIn(
  request: Request,
  env: Env,
): Promise<{ amr?: string[]; idp?: string; authTime?: number } | undefined> {
  const cookie = request.headers.get('cookie')
  const jwt = cookie ? parseCookieValue(cookie, 'auth') : null
  if (!jwt) return undefined
  try {
    const manager = getSigningKeyManager(env)
    const jwks = await manager.getJWKS()
    const { payload } = await jose.jwtVerify(jwt, jose.createLocalJWKSet(jwks), { issuer: 'https://id.org.ai' })
    const amr = Array.isArray(payload.amr) ? payload.amr.filter((x): x is string => typeof x === 'string') : undefined
    const idp = typeof payload.idp === 'string' ? payload.idp : undefined
    const authTime = typeof payload.auth_time === 'number' ? payload.auth_time : undefined
    if (!amr?.length && !idp && !authTime) return undefined
    return { ...(amr?.length ? { amr } : {}), ...(idp ? { idp } : {}), ...(authTime ? { authTime } : {}) }
  } catch {
    return undefined
  }
}

/**
 * The organization the browser session is in (the `auth` cookie JWT's `org.id`),
 * verified like readSessionSignIn. Consent preselects it when the request names none.
 */
export async function readSessionOrgId(request: Request, env: Env): Promise<string | undefined> {
  const cookie = request.headers.get('cookie')
  const jwt = cookie ? parseCookieValue(cookie, 'auth') : null
  if (!jwt) return undefined
  try {
    const jwks = await getSigningKeyManager(env).getJWKS()
    const { payload } = await jose.jwtVerify(jwt, jose.createLocalJWKSet(jwks), { issuer: 'https://id.org.ai' })
    const org = payload.org as { id?: unknown } | undefined
    return typeof org?.id === 'string' ? org.id : undefined
  } catch {
    return undefined
  }
}

/**
 * Resolve the identity ID from a claim token via KV.
 */
export async function resolveIdentityFromClaim(claimToken: string, env: Env): Promise<string | null> {
  if (!claimToken?.startsWith('clm_')) return null
  return env.SESSIONS.get(`claim:${claimToken}`)
}

// ── WorkOS JWT verification ──────────────────────────────────────────────────
// Used by /api/orgs/* endpoints to accept browser JWTs forwarded via service binding.
// The standard authenticateRequest flow only handles ses_* and API keys.

let _localJwks: jose.JWTVerifyGetKey | null = null
let _jwksFetchedAt = 0
const JWKS_TTL_MS = 10 * 60 * 1000 // 10 minutes

/** Fetch and cache JWKS keys locally (same pattern as auth verifier worker). */
export async function getLocalJwks(clientId: string): Promise<jose.JWTVerifyGetKey> {
  if (_localJwks && Date.now() - _jwksFetchedAt < JWKS_TTL_MS) return _localJwks

  const keys = await fetch(workosUrl(`/sso/jwks/${clientId}`))
    .then((r) => r.json() as Promise<{ keys: jose.JWK[] }>)
    .then((j) => j.keys)
  _localJwks = jose.createLocalJWKSet({ keys })
  _jwksFetchedAt = Date.now()
  return _localJwks
}

/** Verify a WorkOS JWT from Authorization header. Returns sub (WorkOS user ID) or null. */
export async function extractWorkOSUserFromJWT(request: Request, env: Env): Promise<{ sub: string; orgId?: string; email?: string } | null> {
  const auth = request.headers.get('authorization')
  if (!auth?.startsWith('Bearer ')) return null
  const token = auth.slice(7)
  // Must be a JWT (contains dots), not a session token or API key
  if (!token.includes('.') || token.startsWith('ses_') || isApiKeyPrefix(token)) return null
  if (!env.WORKOS_CLIENT_ID) return null

  try {
    const jwks = await getLocalJwks(env.WORKOS_CLIENT_ID)
    const { payload } = await jose.jwtVerify(token, jwks)
    const org = payload.org as { id?: string } | undefined
    return {
      sub: payload.sub!,
      orgId: org?.id || (payload.org_id as string | undefined),
      email: payload.email as string | undefined,
    }
  } catch {
    _localJwks = null // Clear cache on failure (key rotation)
    return null
  }
}

/**
 * Identity stub middleware.
 * Resolves the shard key from auth credentials and injects the correct
 * IdentityDO stub into context. Each identity gets its own DO instance.
 */
export async function identityStubMiddleware(c: any, next: () => Promise<void>): Promise<void> {
  const identityId = await resolveIdentityId(c.req.raw, c.env)

  if (identityId) {
    // Authenticated request — route to identity-specific DO
    c.set('resolvedIdentityId', identityId)
    c.set('identityStub', getStubForIdentity(c.env, identityId))
  }
  // For anonymous/L0 requests, identityStub is NOT set.
  // Routes that require a stub will handle this explicitly
  // (e.g., provision creates a new identity, claim resolves via KV).

  await next()
}
