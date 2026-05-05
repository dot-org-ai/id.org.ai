/**
 * AuthBroker implementation.
 *
 * Three call shapes:
 *   - `check(identity, need)`   — sync, no I/O. The hot path used by MCP
 *                                 dispatch and digital-tools' `wrap()` helper.
 *   - `identify(req)`           — extracts a credential, resolves the
 *                                 `Identity`. Returns the L0 anonymous
 *                                 identity when no credential is presented.
 *   - `gate(req, need)`         — `identify()` + `check()`, plus a pre-baked
 *                                 401/403 Response on failure.
 *
 * Three credential shapes are recognised, mirroring the existing extractors
 * in `worker/middleware/auth.ts` and `src/sdk/mcp/auth.ts`:
 *   1. API key  — `oai_*`, `hly_sk_*`, `sk_*` via `X-API-Key` header,
 *                 `Authorization: Bearer <key>`, or `?api_key=` query param.
 *   2. Session  — `ses_*` via `Authorization: Bearer ses_*`.
 *   3. JWT      — `auth` cookie (or chunked `auth.0` / `auth.1` / …) carrying
 *                 a WorkOS-issued JWT. Verification is delegated to an
 *                 injected `verifyJwt` so the broker stays portable
 *                 (no `cloudflare:workers` import).
 *
 * The broker never constructs DO stubs itself — the worker passes a
 * `stubFor(identityId?)` resolver. For credential validation prior to
 * knowing the identity (API key / session lookup), `stubFor()` may be
 * called with no argument; the worker decides whether to return a
 * pre-routed stub or a generic lookup stub.
 */
import { errorJson, ErrorCode } from '../errors'
import type { CapabilityLevel, Identity, IdentityStub } from '../types'
import type { AuthBroker, AuthDecision, AuthDenialReason, AuthRequirement } from './broker'

// ── Anonymous L0 identity ─────────────────────────────────────────────────

const ANONYMOUS_IDENTITY: Identity = {
  id: 'anon',
  type: 'agent',
  name: 'anonymous',
  verified: false,
  level: 0,
  claimStatus: 'unclaimed',
  scopes: [],
}

/** Default scopes attached to a JWT-cookie-resolved human identity. */
const HUMAN_DEFAULT_SCOPES = ['openid', 'profile', 'email']

// ── Credential extraction (mirrors worker/utils/extract.ts) ───────────────
// Inlined here so the SDK module stays free of worker-relative imports.

function isApiKeyPrefix(s: string): boolean {
  return s.startsWith('oai_') || s.startsWith('hly_sk_') || s.startsWith('sk_')
}

function extractApiKey(req: Request): string | null {
  const header = req.headers.get('x-api-key')
  if (header && isApiKeyPrefix(header)) return header

  const auth = req.headers.get('authorization')
  if (auth?.startsWith('Bearer ')) {
    const token = auth.slice(7)
    if (isApiKeyPrefix(token)) return token
  }

  try {
    const url = new URL(req.url)
    const param = url.searchParams.get('api_key')
    if (param && isApiKeyPrefix(param)) return param
  } catch {
    // Invalid URL — skip.
  }
  return null
}

function extractSessionToken(req: Request): string | null {
  const auth = req.headers.get('authorization')
  if (auth?.startsWith('Bearer ses_')) return auth.slice(7)
  return null
}

/**
 * Parse a cookie value, supporting chunked cookies (`auth.0`, `auth.1`, …).
 * Mirrors `worker/utils/cookies.ts#parseCookieValue` but inlined to keep the
 * SDK portable.
 */
function parseCookieValue(cookieHeader: string, name: string): string | null {
  // Single cookie first.
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${escaped}=([^;]*)`))
  if (match) return decodeURIComponent(match[1])

  // Chunked cookies.
  let result = ''
  for (let i = 0; ; i++) {
    const chunk = cookieHeader.match(new RegExp(`(?:^|;\\s*)${escaped}\\.${i}=([^;]*)`))
    if (!chunk) break
    result += decodeURIComponent(chunk[1])
  }
  return result || null
}

function extractAuthCookie(req: Request): string | null {
  const cookie = req.headers.get('cookie')
  if (!cookie) return null
  return parseCookieValue(cookie, 'auth')
}

// ── Dependencies ──────────────────────────────────────────────────────────

export interface AuthBrokerDeps {
  /**
   * Resolve a stub for credential validation. Called twice in the credential
   * flow: once with no argument (or a sentinel) for the initial lookup, and
   * once with the resolved `identityId` to fetch the full `Identity`.
   *
   * In production the worker pre-routes via KV and may return the same stub
   * for both calls. In tests this is typically a single mock stub.
   */
  stubFor(identityId?: string): IdentityStub

  /**
   * Optional WorkOS JWT verification for the human `auth` cookie. Returns
   * the identity id (`human:<sub>` in production) on success. When omitted,
   * cookie-based auth is skipped and the request resolves to anonymous.
   */
  verifyJwt?: (jwt: string) => Promise<{ identityId: string } | null>
}

// ── Failure-response shaping ──────────────────────────────────────────────

function statusForReason(reason: AuthDenialReason): number {
  switch (reason) {
    case 'unauthenticated':
      return 401
    case 'rate-limited':
      return 429
    case 'frozen':
    case 'insufficient-level':
    case 'missing-scope':
    case 'missing-role':
    case 'forbidden':
    default:
      return 403
  }
}

function errorCodeForReason(reason: AuthDenialReason): string {
  switch (reason) {
    case 'unauthenticated':
      return ErrorCode.Unauthorized
    case 'insufficient-level':
      return ErrorCode.InsufficientLevel
    case 'missing-scope':
    case 'missing-role':
      return ErrorCode.Forbidden
    case 'frozen':
      return ErrorCode.AccessDenied
    case 'rate-limited':
      return ErrorCode.RateLimitExceeded
    case 'forbidden':
    default:
      return ErrorCode.Forbidden
  }
}

function descriptionForReason(reason: AuthDenialReason): string {
  switch (reason) {
    case 'unauthenticated':
      return 'Authentication required'
    case 'insufficient-level':
      return 'Insufficient capability level'
    case 'missing-scope':
      return 'Missing required scope'
    case 'missing-role':
      return 'Missing required role'
    case 'frozen':
      return 'Identity is frozen'
    case 'rate-limited':
      return 'Rate limit exceeded'
    case 'forbidden':
    default:
      return 'Forbidden'
  }
}

// ── Implementation ────────────────────────────────────────────────────────

export class AuthBrokerImpl implements AuthBroker {
  /**
   * The deps are optional so callers that only need `check()` (the
   * sync, already-resolved-identity path) can construct the broker without
   * wiring up stub/JWT plumbing — matches phase-1 behaviour.
   */
  constructor(private deps?: AuthBrokerDeps) {}

  /**
   * Synchronous gate against an already-resolved Identity. Pure function
   * over `identity.{level, scopes, frozen, claimStatus}` — no I/O.
   */
  check(identity: Identity, need: AuthRequirement): AuthDecision {
    if (identity.frozen) {
      return { ok: false, identity, reason: 'frozen' }
    }

    // Bare-number shorthand: just a level gate.
    if (typeof need === 'number') {
      if (identity.level < need) {
        return { ok: false, identity, reason: 'insufficient-level' }
      }
      return { ok: true, identity }
    }

    if (need.minLevel != null && identity.level < need.minLevel) {
      return { ok: false, identity, reason: 'insufficient-level' }
    }

    const have = new Set(identity.scopes ?? [])

    if (need.scopes && need.scopes.length > 0) {
      for (const scope of need.scopes) {
        if (!have.has(scope)) {
          return { ok: false, identity, reason: 'missing-scope' }
        }
      }
    }

    if (need.anyScopes && need.anyScopes.length > 0) {
      const matched = need.anyScopes.some((s) => have.has(s))
      if (!matched) {
        return { ok: false, identity, reason: 'missing-scope' }
      }
    }

    // Roles: today id.org.ai does not store WorkOS roles on Identity. The
    // shape exists so digital-tools can declare role requirements; the
    // check is a no-op until WorkOS-role propagation lands.
    if (need.roles && need.roles.length > 0) {
      // Non-blocking — record-only for now. When roles[] lands on Identity,
      // flip to a hard check.
    }

    // FGA on `need.resource` is async; callers asking for it must use
    // gate(), not check(). We treat its presence here as a programming
    // error — fail closed.
    if (need.resource) {
      return { ok: false, identity, reason: 'forbidden' }
    }

    return { ok: true, identity }
  }

  /**
   * Resolve identity from a request. Returns the L0 anonymous identity when
   * no credential is presented or all credentials fail to resolve. Never
   * throws on a malformed credential — callers that need to reject invalid
   * credentials should use `gate()` instead.
   */
  async identify(req: Request): Promise<Identity> {
    if (!this.deps) return ANONYMOUS_IDENTITY

    // ── 1. API key (oai_*, hly_sk_*, sk_*) ──────────────────────────────
    const apiKey = extractApiKey(req)
    if (apiKey) {
      const stub = this.deps.stubFor()
      const data = await stub.validateApiKey(apiKey)
      if (data.valid && data.identityId) {
        return this.hydrateIdentity(data.identityId, {
          level: (data.level ?? 2) as CapabilityLevel,
          scopes: data.scopes,
          fallback: { type: 'agent', name: 'api-key' },
        })
      }
      // Invalid API key → anonymous (gate() turns this into a 401).
      return ANONYMOUS_IDENTITY
    }

    // ── 2. Session token (ses_*) ─────────────────────────────────────────
    const sessionToken = extractSessionToken(req)
    if (sessionToken) {
      const stub = this.deps.stubFor()
      const data = await stub.getSession(sessionToken)
      if (data.valid && data.identityId) {
        return this.hydrateIdentity(data.identityId, {
          level: (data.level ?? 1) as CapabilityLevel,
          fallback: { type: 'agent', name: 'session' },
        })
      }
      return ANONYMOUS_IDENTITY
    }

    // ── 3. JWT cookie (human via WorkOS) ────────────────────────────────
    const jwt = extractAuthCookie(req)
    if (jwt && this.deps.verifyJwt) {
      const verified = await this.deps.verifyJwt(jwt).catch(() => null)
      if (verified?.identityId) {
        return this.hydrateIdentity(verified.identityId, {
          level: 2,
          scopes: HUMAN_DEFAULT_SCOPES,
          fallback: { type: 'human', name: 'human' },
        })
      }
      return ANONYMOUS_IDENTITY
    }

    // ── 4. No credential — true L0 anonymous ────────────────────────────
    return ANONYMOUS_IDENTITY
  }

  /**
   * Extract a credential, resolve identity, and gate against `need`. On
   * rejection, the returned decision carries a pre-baked Response the
   * caller returns directly.
   *
   * Distinguishes "no credential presented" (anonymous, may still pass an
   * L0 requirement) from "credential presented but invalid" (always 401).
   */
  async gate(req: Request, need: AuthRequirement): Promise<AuthDecision> {
    const presentedCredential = !!(
      extractApiKey(req) ||
      extractSessionToken(req) ||
      (extractAuthCookie(req) && this.deps?.verifyJwt)
    )

    const identity = await this.identify(req)

    // Credential was presented but auth failed → reject as unauthenticated,
    // even if `need` would otherwise accept L0. Mirrors the existing
    // worker/middleware/auth.ts behaviour.
    if (presentedCredential && identity.id === ANONYMOUS_IDENTITY.id) {
      return this.deny(identity, 'unauthenticated', 'Invalid or expired credentials')
    }

    const decision = this.check(identity, need)
    if (decision.ok) return decision

    return this.deny(decision.identity ?? identity, decision.reason)
  }

  // ── Internal helpers ─────────────────────────────────────────────────────

  /**
   * Pull the canonical Identity from the DO and overlay credential-derived
   * fields (level, scopes). Falls back to a synthetic identity when the DO
   * has no record (e.g. the credential is valid but the row was reaped) so
   * `gate()` still has something to reason about.
   */
  private async hydrateIdentity(
    identityId: string,
    overlay: {
      level: CapabilityLevel
      scopes?: string[]
      fallback: { type: Identity['type']; name: string }
    },
  ): Promise<Identity> {
    if (!this.deps) {
      return {
        id: identityId,
        type: overlay.fallback.type,
        name: overlay.fallback.name,
        verified: false,
        level: overlay.level,
        claimStatus: 'unclaimed',
        scopes: overlay.scopes,
      }
    }

    const stub = this.deps.stubFor(identityId)
    const stored = await stub.getIdentity(identityId).catch(() => null)

    if (stored) {
      // Prefer the credential-derived level (an API key may scope-down a
      // higher-level identity); always carry credential scopes.
      return {
        ...stored,
        level: Math.max(stored.level, overlay.level) as CapabilityLevel,
        scopes: overlay.scopes ?? stored.scopes,
      }
    }

    return {
      id: identityId,
      type: overlay.fallback.type,
      name: overlay.fallback.name,
      verified: false,
      level: overlay.level,
      claimStatus: 'unclaimed',
      scopes: overlay.scopes,
    }
  }

  private deny(
    identity: Identity | null,
    reason: AuthDenialReason,
    descriptionOverride?: string,
  ): AuthDecision {
    const status = statusForReason(reason)
    const code = errorCodeForReason(reason)
    const description = descriptionOverride ?? descriptionForReason(reason)
    return {
      ok: false,
      identity,
      reason,
      response: errorJson(code, description, status),
    }
  }
}
