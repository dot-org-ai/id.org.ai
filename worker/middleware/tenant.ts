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
 * Workers run one env per isolate, so a single manager is safe to reuse across
 * requests. This avoids rebuilding the manager (and re-hitting the DO for keys)
 * on every JWT verify / JWKS read / token sign.
 */
let cachedSigningKeyManager: SigningKeyManager | null = null

export function getSigningKeyManager(env: Env): SigningKeyManager {
  if (!cachedSigningKeyManager) {
    const oauthStub = getStubForIdentity(env, 'oauth')
    cachedSigningKeyManager = new SigningKeyManager((op) => oauthStub.oauthStorageOp(op))
  }
  return cachedSigningKeyManager
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

  const keys = await fetch(`https://api.workos.com/sso/jwks/${clientId}`)
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
