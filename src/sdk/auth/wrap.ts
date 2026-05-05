/**
 * `wrap()` — canonical broker usage helper for digital-tools and any route
 * handler that already holds an Identity (e.g. MCP dispatch).
 *
 * The helper composes `AuthBroker.check()` (synchronous, no I/O) with a
 * handler. On success the handler runs; on failure the helper returns a
 * pre-baked JSON Response built via `denialResponse()` so callers never
 * hand-roll 401/403 plumbing.
 *
 * Symmetric to the broker's own `gate()` (which extracts a credential from
 * a Request first), but `wrap()` is the right shape when the caller has
 * already resolved the Identity upstream.
 */
import { errorJson, ErrorCode } from '../errors'
import type { Identity } from '../types'
import type { AuthBroker, AuthDecision, AuthDenialReason, AuthRequirement } from './broker'

/**
 * The JSON body shape `denialResponse()` produces. Stable contract — used by
 * digital-tools and primitives.org.ai for parsing failure responses.
 */
export interface WrapDenialBody {
  error: string
  error_description: string
  reason: AuthDenialReason
}

/**
 * Map an AuthDenialReason to its HTTP status. 401 for missing credentials,
 * 429 for rate-limited, 403 for everything else (forbidden by policy).
 */
export function statusForDenial(reason: AuthDenialReason): number {
  if (reason === 'unauthenticated') return 401
  if (reason === 'rate-limited') return 429
  return 403
}

function errorCodeForDenial(reason: AuthDenialReason): string {
  if (reason === 'unauthenticated') return ErrorCode.Unauthorized
  if (reason === 'insufficient-level') return ErrorCode.InsufficientLevel
  if (reason === 'frozen') return ErrorCode.AccessDenied
  if (reason === 'rate-limited') return ErrorCode.RateLimitExceeded
  return ErrorCode.Forbidden
}

function descriptionForDenial(reason: AuthDenialReason): string {
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

/**
 * Build a JSON Response from a failed AuthDecision. The decision's pre-baked
 * `response`, if present, wins — otherwise we synthesise one from the
 * standard error-code vocabulary.
 */
export function denialResponse(decision: Extract<AuthDecision, { ok: false }>): Response {
  if (decision.response) return decision.response
  return errorJson(
    errorCodeForDenial(decision.reason),
    descriptionForDenial(decision.reason),
    statusForDenial(decision.reason),
  )
}

/**
 * Wrap a handler with an auth check. The 95% case for digital-tools and any
 * route that operates on an already-resolved Identity:
 *
 * @example
 * ```ts
 * const summarise = wrap(broker, 1, async (identity, ctx) => {
 *   return summariseImpl(ctx.body, identity)
 * })
 * ```
 *
 * The wrapped function takes the resolved Identity and an opaque caller
 * context, runs `auth.check(identity, need)`, and either calls the handler
 * on success or returns a denial Response on failure.
 */
export function wrap<TCtx, TResponse extends Response>(
  auth: AuthBroker,
  need: AuthRequirement,
  handler: (identity: Identity, ctx: TCtx) => Promise<TResponse>,
): (identity: Identity, ctx: TCtx) => Promise<Response> {
  return async (identity, ctx) => {
    const decision = auth.check(identity, need)
    if (!decision.ok) return denialResponse(decision)
    return handler(decision.identity, ctx)
  }
}
