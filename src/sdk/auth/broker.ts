/**
 * AuthBroker — the unified seam between authenticated identity and
 * authorisation decisions.
 *
 * Today the codebase makes authorisation decisions in three+ places using
 * three different vocabularies (`auth.level < 1` in middleware, `if
 * (scopes.includes(...))` in OAuth, ad-hoc role checks in the WorkOS
 * layer). The AuthBroker collapses these into one interface: callers
 * declare what they need (a level, optionally scopes, optionally a
 * resource for FGA), the broker decides yes/no.
 *
 * Three methods, three call shapes:
 *   - `gate(req, need)`         — extract credential, resolve identity, check
 *   - `identify(req)`           — extract credential, resolve identity, no check
 *   - `check(identity, need)`   — already-resolved identity, synchronous check
 */
import type { CapabilityLevel, Identity } from '../types'
import type { ThingRef } from 'schema.org.ai'

/**
 * What a caller needs to be authorised. Two shapes:
 *
 * **Shallow (95% case)** — a bare `CapabilityLevel`. `auth.check(id, 1)`
 * gates against L1+; the most common call site collapses to one number.
 *
 * **Typed** — when scopes, a verb, or a resource matters. The broker is
 * additive: as new authz vocabularies (FGA, attribute predicates) land,
 * they extend this object; the bare-number case keeps working.
 */
export type AuthRequirement =
  | CapabilityLevel
  | {
      /** Verb being attempted (`tools.call`, `oauth.authorize`, …). */
      verb?: string
      /** Minimum capability level. Defaults to 0 (no level gate). */
      minLevel?: CapabilityLevel
      /** ALL-of: every scope must be present. */
      scopes?: string[]
      /** ANY-of: at least one scope must be present. */
      anyScopes?: string[]
      /** WorkOS / org roles. */
      roles?: string[]
      /** Optional resource — enables per-resource (FGA-shaped) checks. */
      resource?: ThingRef
      /** Adapter-specific request context (ip, mcp band, oauth claims). */
      context?: Record<string, unknown>
    }

/**
 * Why a check failed. Stable identifiers — callers may switch on these to
 * shape the wire response.
 */
export type AuthDenialReason =
  | 'unauthenticated'
  | 'insufficient-level'
  | 'missing-scope'
  | 'missing-role'
  | 'frozen'
  | 'rate-limited'
  | 'forbidden'

/**
 * What `check()` and `gate()` return. On success, the identity is always
 * populated so callers can pass it downstream without re-resolving.
 */
export type AuthDecision =
  | {
      ok: true
      identity: Identity
      /** Audit / header obligations the caller MUST honour. */
      obligations?: AuthObligation[]
    }
  | {
      ok: false
      identity: Identity | null
      reason: AuthDenialReason
      /**
       * Pre-baked 401/403 the route can return directly. Set by `gate()`;
       * `check()` returns this only if the caller asked for a Response.
       */
      response?: Response
      /** Hint for the upgrade flow — claim URL, login URL, scope grant URL. */
      upgrade?: { url: string; hint: string }
    }

/**
 * Side-effects the broker promises were applied iff the route honours them.
 * Today: emit an audit event, set a response header. The broker stays free
 * of HTTP coupling by emitting these as data.
 */
export interface AuthObligation {
  kind: 'audit' | 'header' | 'tag'
  payload: Record<string, unknown>
}

export interface AuthBroker {
  /**
   * Default. Extracts credential from the request, resolves identity, and
   * gates against `need`. On rejection, the returned decision carries a
   * pre-baked Response the caller returns directly.
   */
  gate(req: Request, need: AuthRequirement): Promise<AuthDecision>

  /**
   * Resolve identity from a request without any gating. For middleware
   * that wants to populate context but lets routes decide their own
   * requirements. Returns the L0 anonymous identity when no credential is
   * presented.
   */
  identify(req: Request): Promise<Identity>

  /**
   * Synchronous check against an already-resolved identity. The hot path
   * — MCP tool dispatch already has the identity in hand and a network
   * round-trip would be waste. Requirements that demand I/O (FGA against
   * a remote backend) MUST use `gate()` instead.
   */
  check(identity: Identity, need: AuthRequirement): AuthDecision
}
