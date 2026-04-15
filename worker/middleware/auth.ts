/**
 * MCP authentication middleware for id.org.ai worker
 *
 * Three-tier auth: L0 (anonymous), L1 (session), L2+ (API key).
 * Detects credentials, verifies via MCPAuth, falls back to JWT cookie identity
 * for human logins.
 */

import { MCPAuth } from '../../src/sdk/mcp/auth'
import { errorResponse, ErrorCode } from '../../src/sdk/errors'
import { parseCookieValue } from '../utils/cookies'
import { extractApiKey, extractSessionToken } from '../utils/extract'

export async function authenticateRequest(c: any, next: () => Promise<void>) {
  const stub = c.get('identityStub')

  // Detect explicit credentials in the request
  const hasExplicitApiKey = !!extractApiKey(c.req.raw)
  const hasExplicitSession = !!extractSessionToken(c.req.raw)

  if (stub) {
    const mcpAuth = new MCPAuth(stub)
    const auth = await mcpAuth.authenticate(c.req.raw)

    // Explicit credentials provided but auth failed → reject (don't silently downgrade to L0)
    if ((hasExplicitApiKey || hasExplicitSession) && !auth.authenticated) {
      return errorResponse(c, 401, ErrorCode.Unauthorized, auth.error || 'Invalid credentials')
    }

    // MCPAuth only knows about API keys and session tokens. If the identity
    // was resolved from a JWT cookie (human login), MCPAuth returns unauthenticated.
    // In that case, construct an auth result from the cookie identity.
    if (!auth.authenticated && !hasExplicitApiKey && !hasExplicitSession) {
      const cookieHeader = c.req.header('cookie') || ''
      const jwt = parseCookieValue(cookieHeader, 'auth')
      if (jwt) {
        // Identity was resolved from JWT in resolveIdentityId — trust it
        const resolvedId = c.get('resolvedIdentityId') as string
        const identity = await stub.getIdentity(resolvedId)
        c.set('auth', {
          authenticated: true,
          identityId: identity?.id || resolvedId,
          level: identity?.level ?? 2,
          scopes: ['openid', 'profile', 'email'],
          capabilities: { read: true, write: true, admin: false },
        })
        return next()
      }
    }

    c.set('auth', auth)
  } else if (hasExplicitApiKey || hasExplicitSession) {
    // Credentials provided but couldn't resolve identity from KV → invalid/expired
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Invalid or expired credentials')
  } else {
    // True anonymous L0 — no credentials provided
    c.set('auth', MCPAuth.anonymousResult())
  }
  await next()
}
