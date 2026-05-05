/**
 * AuthBroker implementation — phase 1.
 *
 * This pass ships the `check()` (sync, already-resolved-identity) path
 * since that's the call shape MCP dispatch and digital-tools' `wrap()`
 * helper need. `gate()` and `identify()` will absorb the credential
 * extraction currently in `worker/middleware/auth.ts` in a follow-up — at
 * that point the middleware collapses to ~6 lines.
 */
import type { Identity } from '../types'
import type { AuthBroker, AuthDecision, AuthRequirement } from './broker'

export class AuthBrokerImpl implements AuthBroker {
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
   * Phase 2: resolve identity from request via existing middleware logic.
   * Until then, this throws so callers don't silently succeed.
   */
  async gate(_req: Request, _need: AuthRequirement): Promise<AuthDecision> {
    throw new Error(
      'AuthBroker.gate() not yet implemented — use check() with an already-resolved Identity until phase 2',
    )
  }

  /** Phase 2 — same as gate(). */
  async identify(_req: Request): Promise<Identity> {
    throw new Error(
      'AuthBroker.identify() not yet implemented — use the existing worker auth middleware until phase 2',
    )
  }
}
