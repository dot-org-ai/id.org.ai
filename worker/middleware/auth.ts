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
import { getStubForIdentity } from './tenant'
import { mcpResourceUri, mcpWwwAuthenticate, isMcpPath, canonicalizeResourceUri } from '../utils/mcp-resource'
import type { IdentityStub } from '../../src/server/do/Identity'

/**
 * OAuth 2.1 resource-server validation for opaque `at_` access tokens
 * (RFC 8707 audience-binding). Runs before the broker because OAuth access
 * tokens live in the OAuth Durable Object's storage, not in the KV/session
 * paths the broker/tenant resolver understand.
 *
 * `at_` tokens are ONLY accepted at /mcp — the one route with a defined
 * resource URI + enforced audience check. On any other route we don't have
 * an aud check to enforce, so an at_ bearer token is not treated as a valid
 * credential there at all (falls through to the normal broker path, same as
 * any other unrecognized credential) — otherwise a token minted for /mcp
 * would silently authenticate at unrelated routes with no audience
 * enforcement.
 *
 * On /mcp the token MUST be audience-bound to this MCP resource URI: a token
 * minted for a DIFFERENT resource (or with no `resource` at all) is REJECTED,
 * so a token issued for another audience can never be replayed at /mcp. The
 * `resource` field is compared as a set (RFC 8707 permits multiple resource
 * indicators on one token) and canonicalized (scheme+host case, trailing
 * slash) before comparison.
 *
 * Returns:
 *   - a Response  → terminal (401): reject and emit the WWW-Authenticate chain
 *   - true        → token resolved & audience-valid; context populated, proceed
 *   - false       → not an `at_` token, or not at /mcp; fall through to the
 *                    normal broker path
 */
async function tryOAuthAccessToken(c: any): Promise<Response | boolean> {
  const authz = c.req.raw.headers.get('authorization') as string | null
  if (!authz?.startsWith('Bearer at_')) return false

  const url = new URL(c.req.url)
  const origin = url.origin
  const onMcp = isMcpPath(url.pathname)

  // at_ tokens carry a resource-bound audience that is only enforced on
  // /mcp. Don't authenticate them anywhere else — fall through instead of
  // granting access purely on a token scoped to a different resource.
  if (!onMcp) return false

  const token = authz.slice(7)

  const reject = (description: string): Response => {
    c.header('WWW-Authenticate', mcpWwwAuthenticate(origin, 'invalid_token', description))
    return errorResponse(c, 401, ErrorCode.Unauthorized, description)
  }

  const oauthStub = getStubForIdentity(c.env, 'oauth')
  const res = await oauthStub.oauthStorageOp({ op: 'get', key: `access:${token}` }).catch(() => ({}) as any)
  const rec = (res?.value ?? undefined) as
    | { identityId?: string; scopes?: string[]; expiresAt?: number; resource?: string | string[] | null }
    | undefined

  if (!rec) return reject('Invalid access token')

  // Fail closed: a record without a positive, finite numeric expiry is
  // treated as expired, never as non-expiring. Mirrors the canonical
  // provider.validateAccessToken contract (AccessToken.expiresAt is a
  // required number) rather than trusting whatever shape came back from
  // storage.
  if (!(typeof rec.expiresAt === 'number' && Number.isFinite(rec.expiresAt) && rec.expiresAt > 0)) {
    return reject('Access token has no valid expiry')
  }
  if (rec.expiresAt < Date.now()) return reject('Access token has expired')

  // RFC 8707 audience binding — enforced at the /mcp resource server. Require
  // the token to be bound to THIS resource; reject cross-resource and aud-less
  // tokens (strict OAuth 2.1 resource-server policy). `resource` may be a
  // single string or an array (multi-valued audience) — accept if ANY bound
  // audience canonically matches this resource.
  {
    const mcpUri = mcpResourceUri(origin)
    const canonicalMcpUri = canonicalizeResourceUri(mcpUri)
    const auds: string[] = Array.isArray(rec.resource) ? rec.resource : rec.resource == null ? [] : [rec.resource]
    const bound = auds.some((a) => typeof a === 'string' && canonicalizeResourceUri(a) === canonicalMcpUri)
    if (!bound) {
      return reject(
        auds.length
          ? `token audience ${auds.join(', ')} is not bound to ${mcpUri}`
          : `token is not audience-bound to ${mcpUri} (RFC 8707 resource indicator required)`,
      )
    }
  }

  if (!rec.identityId) return reject('Access token is not associated with an identity')

  const identityStub = getStubForIdentity(c.env, rec.identityId)
  const identity = await identityStub.getIdentity(rec.identityId).catch(() => null)
  if (!identity) return reject('Identity not found for access token')

  c.set('resolvedIdentityId', rec.identityId)
  c.set('identityStub', identityStub)
  c.set('identity', identity)
  const rateLimit = await identityStub.checkRateLimit(identity.id, identity.level).catch(() => undefined)
  c.set('auth', MCPAuth.fromIdentity(identity, rateLimit))
  return true
}

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

  // OAuth 2.1 access tokens (`at_`) are validated here as a resource server:
  // signature-equivalent lookup in the OAuth DO + RFC 8707 audience binding on
  // /mcp. Runs first because these tokens don't live in the KV/session paths.
  const oauthResult = await tryOAuthAccessToken(c)
  if (oauthResult instanceof Response) return oauthResult
  if (oauthResult === true) return next()

  const mcpUnauthorized = () => {
    if (isMcpPath(new URL(c.req.url).pathname)) {
      c.header('WWW-Authenticate', mcpWwwAuthenticate(new URL(c.req.url).origin))
    }
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Invalid or expired credentials')
  }

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
      return mcpUnauthorized()
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
    return mcpUnauthorized()
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
