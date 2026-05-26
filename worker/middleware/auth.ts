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
import { validateWorkOSApiKey } from '../../src/sdk/workos/apikey'
import type { IdentityStub } from '../../src/server/do/Identity'

/**
 * No-op stub for the broker when tenant resolution didn't produce an
 * id.org.ai-issued identity. The broker's only call path here is the WorkOS
 * `sk_*` fallback, which doesn't read from the DO. We satisfy the typed
 * `stubFor()` contract with a stub that reports "not found" for every lookup —
 * the broker's DO miss then triggers `validateWorkOSKey`.
 */
const NO_STUB: IdentityStub = {
  validateApiKey: async () => ({ valid: false }),
  getSession: async () => ({ valid: false }),
  getIdentity: async () => null,
  getAgent: async () => null,
  touchAgent: async () => {},
  checkRateLimit: async () => ({ allowed: true, remaining: 0, resetAt: 0 }),
} as unknown as IdentityStub

export async function authenticateRequest(c: any, next: () => Promise<void>) {
  const stub = c.get('identityStub')
  const workosApiKey = c.env?.WORKOS_API_KEY as string | undefined

  // No stub means tenant resolution didn't find an id.org.ai-issued identity
  // for the credential. For most credentials that's terminal (401). The one
  // exception is a WorkOS-issued `sk_*` API key: it never lives in our DO
  // storage, so tenant resolution always returns null, but the key may still
  // validate against WorkOS. Hand it to the broker below, which has the
  // WorkOS fallback wired. Other explicit creds still 401 here.
  if (!stub) {
    const explicitKey = extractApiKey(c.req.raw)
    const explicitSession = extractSessionToken(c.req.raw)
    const isWorkosSk = explicitKey?.startsWith('sk_') && workosApiKey
    if ((explicitKey && !isWorkosSk) || explicitSession) {
      return errorResponse(c, 401, ErrorCode.Unauthorized, 'Invalid or expired credentials')
    }
    if (!isWorkosSk) {
      c.set('auth', MCPAuth.anonymousResult())
      return next()
    }
    // Falls through to the broker — only the sk_ → WorkOS path remains.
  }

  const broker = new AuthBrokerImpl({
    // stubFor() never reaches the network path here when there's no real
    // stub (sk_ → WorkOS only); supply a minimal shim so the call signature
    // stays satisfied.
    stubFor: () => stub ?? NO_STUB,
    // JWT verification happens upstream in tenant resolution; trust the
    // already-resolved identityId. The broker calls this only when an
    // `auth` cookie is present.
    verifyJwt: async () => {
      const id = c.get('resolvedIdentityId') as string | undefined
      return id ? { identityId: id } : null
    },
    // WorkOS sk_* fallback: when the DO misses (i.e. the key was issued by
    // WorkOS, not id.org.ai), validate against WorkOS. Without this, the
    // dashboard's IDORGAI_ORG_TOKEN (a WorkOS sk_*) 401s at the middleware
    // and never reaches the org-membership routes. See PR #7.
    ...(workosApiKey
      ? {
          validateWorkOSKey: async (key: string) => {
            const r = await validateWorkOSApiKey(key, workosApiKey)
            // Adapt WorkOS' snake_case to the broker's camelCase contract.
            return {
              valid: r.valid,
              id: r.id,
              name: r.name,
              organizationId: r.organization_id,
              permissions: r.permissions,
            }
          },
        }
      : {}),
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
  // load-bearing for every route). No stub (sk_/WorkOS service path) → skip.
  let rateLimit: { allowed: boolean; remaining: number; resetAt: number } | undefined
  if (stub && identity.id !== 'anon') {
    rateLimit = await stub.checkRateLimit(identity.id, identity.level).catch(() => undefined)
  }
  c.set('auth', MCPAuth.fromIdentity(identity, rateLimit))

  await next()
}
