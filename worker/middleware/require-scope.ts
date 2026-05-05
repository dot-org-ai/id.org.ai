/**
 * `requireScope(...scopes)` — Hono middleware that gates a route on the
 * caller's API-key (or session) scopes.
 *
 * Uses the AuthBroker's synchronous `check()` against the `Identity` set by
 * `authenticateRequest`. ANY-of semantics: passing the request requires at
 * least one of the listed scopes. Use `requireAllScopes` for ALL-of.
 *
 * ## Standard scope vocabulary
 *
 * The codebase uses three flat scope vocabularies (per `src/sdk/mcp/auth.ts`
 * `LEVEL_SCOPES`):
 *   - **API-key scopes** (issued at key creation): `read`, `write`, `admin`.
 *   - **MCP capability scopes** (per-level, static): `search`, `fetch`,
 *     `explore`, `do`, `try`, `claim`, `export`, `webhook`, `invite`,
 *     `billing`.
 *   - **OIDC scopes** (issued at /oauth/authorize): `openid`, `profile`,
 *     `email`, `offline_access`.
 *
 * ## Adoption
 *
 * New routes that need scope-restricted access — e.g. issuing or revoking
 * API keys, mutating organization settings, exporting data — should mount
 * `requireScope` AFTER `authenticateRequest` so that `c.get('identity')` is
 * populated. Existing routes are not migrated automatically; per-route
 * adoption is the deliberate path so API-key consumers can be evaluated for
 * scope coverage individually.
 *
 * ## Example
 *
 * ```ts
 * app.post('/api/keys', requireScope('admin'), async (c) => {
 *   // only callers with `admin` in identity.scopes can reach here
 * })
 * ```
 */
import { AuthBrokerImpl } from '../../src/sdk/auth/broker-impl'
import { errorResponse, ErrorCode } from '../../src/sdk/errors'
import type { Identity } from '../../src/sdk/types'

const broker = new AuthBrokerImpl()

/** ANY-of: at least one of the listed scopes must be on the identity. */
export function requireScope(...scopes: string[]) {
  if (scopes.length === 0) {
    throw new Error('requireScope() needs at least one scope')
  }
  return async (c: any, next: () => Promise<void>) => {
    const identity = c.get('identity') as Identity | undefined
    if (!identity) {
      return errorResponse(
        c,
        500,
        ErrorCode.ServerError,
        'requireScope: identity context missing — authenticateRequest must run first',
      )
    }
    const decision = broker.check(identity, { anyScopes: scopes })
    if (!decision.ok) {
      const reason =
        decision.reason === 'frozen'
          ? 'Identity is frozen'
          : `Required scope(s): ${scopes.join(', ')}`
      return errorResponse(c, 403, ErrorCode.Forbidden, reason)
    }
    await next()
  }
}

/** ALL-of: every listed scope must be on the identity. */
export function requireAllScopes(...scopes: string[]) {
  if (scopes.length === 0) {
    throw new Error('requireAllScopes() needs at least one scope')
  }
  return async (c: any, next: () => Promise<void>) => {
    const identity = c.get('identity') as Identity | undefined
    if (!identity) {
      return errorResponse(
        c,
        500,
        ErrorCode.ServerError,
        'requireAllScopes: identity context missing — authenticateRequest must run first',
      )
    }
    const decision = broker.check(identity, { scopes })
    if (!decision.ok) {
      const reason =
        decision.reason === 'frozen'
          ? 'Identity is frozen'
          : `Required scopes (all): ${scopes.join(', ')}`
      return errorResponse(c, 403, ErrorCode.Forbidden, reason)
    }
    await next()
  }
}
