/**
 * Worker auth middleware — delegates credential extraction to the
 * AuthBroker, synthesises the legacy `MCPAuthResult` for back-compat.
 *
 * Both contexts are populated:
 *   - `c.set('identity', identity)`  — the canonical Identity (new code)
 *   - `c.set('auth', mcpAuthResult)` — legacy MCPAuthResult shape (17+ existing readers)
 *
 * The broker is the single source of truth for credential resolution; the
 * mcp/auth synthesis is a pure shape-conversion of its output.
 */

import { AuthBrokerImpl } from '../../src/sdk/auth/broker-impl'
import { MCPAuth } from '../../src/sdk/mcp/auth'
import { errorResponse, ErrorCode } from '../../src/sdk/errors'
import { extractApiKey, extractSessionToken } from '../utils/extract'

export async function authenticateRequest(c: any, next: () => Promise<void>) {
  const stub = c.get('identityStub')

  // No stub means tenant resolution didn't run — only L0 anonymous is possible.
  if (!stub) {
    const hasExplicit = !!extractApiKey(c.req.raw) || !!extractSessionToken(c.req.raw)
    if (hasExplicit) {
      return errorResponse(c, 401, ErrorCode.Unauthorized, 'Invalid or expired credentials')
    }
    c.set('auth', MCPAuth.anonymousResult())
    return next()
  }

  const broker = new AuthBrokerImpl({
    stubFor: () => stub,
    // JWT verification happens upstream in tenant resolution; trust the
    // already-resolved identityId. The broker calls this only when an
    // `auth` cookie is present.
    verifyJwt: async () => {
      const id = c.get('resolvedIdentityId') as string | undefined
      return id ? { identityId: id } : null
    },
  })

  const presentedExplicit = !!extractApiKey(c.req.raw) || !!extractSessionToken(c.req.raw)
  const identity = await broker.identify(c.req.raw)

  // Mirror prior behaviour: explicit creds that fail to resolve → 401, not L0.
  if (presentedExplicit && identity.id === 'anon') {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Invalid or expired credentials')
  }

  c.set('identity', identity)

  // Synthesise the legacy MCPAuthResult. Rate-limit lookup is best-effort —
  // if the stub fails, we still set the auth context (rate limits aren't
  // load-bearing for every route).
  let rateLimit: { allowed: boolean; remaining: number; resetAt: number } | undefined
  if (identity.id !== 'anon') {
    rateLimit = await stub.checkRateLimit(identity.id, identity.level).catch(() => undefined)
  }
  c.set('auth', MCPAuth.fromIdentity(identity, rateLimit))

  await next()
}
