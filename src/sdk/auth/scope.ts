/**
 * Scope — a structured, constrained capability grant carried on an API key.
 *
 * The flat-string scope vocabulary (`scopes: string[]`, e.g. `['read',
 * 'write']`) answers "does the caller hold capability X?" but cannot express
 * a *constrained* may-do: "may call verb `read` on resource `listings/*`, up
 * to a ceiling of 100 requests". A `Scope` is that structured grant.
 *
 * The noun is imported unchanged from the agent-led-commerce rulings (see the
 * .ax repo CONTEXT.md): a may-do is a `verb` + `resource`, narrowable, with an
 * optional `ceiling: Measure`. A Scope is a *set* of such grants; a caller is
 * authorised for a request iff some grant covers it.
 *
 * Two core predicates:
 *   - `scopeSatisfies(granted, required)` — is a single may-do request inside
 *     the grant set? (evaluated synchronously by `AuthBroker.check`/`gate`)
 *   - `narrows(child, parent)` — is `child` a strict subset of `parent`?
 *     (a child Scope may only ever shrink: verbs/resources ⊆, ceiling ≤)
 *
 * This module is dependency-free so it can be imported from both the SDK
 * (`src/sdk/auth`) and the key service (`src/server/services/keys`) without
 * introducing a cycle.
 */

/**
 * A bounded quantity — a `value` in some `unit`. Grounds `ceiling: Measure`
 * from agent-led-commerce: a Scope grant may cap the amount a verb may consume
 * (e.g. `{ value: 100, unit: 'requests' }`, `{ value: 50, unit: 'usd' }`).
 */
export interface Measure {
  value: number
  unit: string
}

/**
 * A single may-do: permission to call `verb` on `resource`, optionally capped
 * by a `ceiling`. `verb` and `resource` may be the wildcard `*` or a trailing
 * glob (`listings/*`); an absent `ceiling` means unbounded.
 */
export interface ScopeGrant {
  /** Verb permitted (`read`, `write`, …) or `*` for any verb. */
  verb: string
  /** Resource permitted — exact (`listings/123`), prefix glob (`listings/*`), or `*`. */
  resource: string
  /** Optional upper bound on the amount this grant permits. */
  ceiling?: Measure
}

/**
 * A structured capability grant: the set of may-dos a key carries. A request
 * is authorised iff at least one grant covers it.
 */
export interface Scope {
  grants: ScopeGrant[]
}

/**
 * A single may-do request to test against a Scope: "may I call `verb` on
 * `resource` (consuming `amount`)?". `resource` must be concrete (no glob).
 */
export interface ScopeRequirement {
  verb: string
  resource: string
  /** The amount the request would consume; tested against a grant's ceiling. */
  amount?: Measure
}

// ── Glob / pattern helpers ────────────────────────────────────────────────

/**
 * Does `pattern` match the concrete `value`? Supports `*` (any) and a single
 * trailing prefix glob (`listings/*` matches `listings/123`, `listings/a/b`).
 * An exact pattern matches only itself.
 */
export function resourceMatches(pattern: string, value: string): boolean {
  if (pattern === '*') return true
  if (pattern === value) return true
  if (pattern.endsWith('/*')) {
    const prefix = pattern.slice(0, -1) // keep trailing slash: `listings/`
    return value.startsWith(prefix)
  }
  return false
}

/**
 * Is the pattern `child` a subset of the pattern `parent`? i.e. is everything
 * `child` matches also matched by `parent`? Used for narrowing — a widening
 * child (`*` under `listings/*`) returns false.
 */
function patternNarrows(child: string, parent: string): boolean {
  if (parent === '*') return true
  if (child === parent) return true
  if (parent.endsWith('/*')) {
    const prefix = parent.slice(0, -1) // `listings/`
    // `child` is a subset iff every value it matches starts with `prefix`.
    // A concrete child must start with it; a glob child `P*` is a subset iff
    // its own prefix starts with the parent prefix.
    if (child === '*') return false
    if (child.endsWith('/*')) return child.slice(0, -1).startsWith(prefix)
    return child.startsWith(prefix)
  }
  // Exact parent: only the identical child is a subset (handled above).
  return false
}

/** Is verb `child` a subset of verb `parent`? (`*` covers any verb.) */
function verbNarrows(child: string, parent: string): boolean {
  if (parent === '*') return true
  return child === parent
}

/**
 * Is `child`'s ceiling within `parent`'s ceiling? An absent parent ceiling is
 * unbounded (any child fits). An absent child ceiling under a bounded parent
 * is *wider* (unbounded ⊄ bounded) → false. Mismatched units are incomparable
 * → false (fail closed).
 */
function ceilingNarrows(child: Measure | undefined, parent: Measure | undefined): boolean {
  if (!parent) return true // parent unbounded — anything narrows it
  if (!child) return false // child unbounded but parent bounded — widening
  if (child.unit !== parent.unit) return false
  return child.value <= parent.value
}

// ── Core predicates ────────────────────────────────────────────────────────

/**
 * Does a grant cover a concrete request? verb must match (or grant verb `*`),
 * resource pattern must match the concrete resource, and — when the request
 * carries an `amount` — it must sit within the grant's ceiling.
 */
function grantCovers(grant: ScopeGrant, required: ScopeRequirement): boolean {
  if (!verbNarrows(required.verb, grant.verb)) return false
  if (!resourceMatches(grant.resource, required.resource)) return false
  if (required.amount) {
    // The request wants `amount`; the grant permits up to `grant.ceiling`.
    // An unbounded grant (no ceiling) permits any amount.
    if (grant.ceiling) {
      if (required.amount.unit !== grant.ceiling.unit) return false
      if (required.amount.value > grant.ceiling.value) return false
    }
  }
  return true
}

/**
 * Is the request `required` inside the granted Scope? True iff at least one
 * grant covers it. The synchronous, no-I/O predicate `AuthBroker.check`/`gate`
 * evaluates for structured needs.
 */
export function scopeSatisfies(granted: Scope, required: ScopeRequirement): boolean {
  if (!granted || !Array.isArray(granted.grants)) return false
  return granted.grants.some((g) => grantCovers(g, required))
}

/**
 * Is `child` a strict subset of `parent`? Every grant in `child` must be
 * narrowed by some grant in `parent`: verb ⊆, resource ⊆, ceiling ≤. Any grant
 * in `child` that widens (a verb/resource/ceiling not fully contained by a
 * single parent grant) makes the whole check false.
 *
 * An empty child (no grants) trivially narrows any parent. A child grant with
 * no covering parent grant → false.
 */
export function narrows(child: Scope, parent: Scope): boolean {
  if (!child || !Array.isArray(child.grants)) return false
  if (!parent || !Array.isArray(parent.grants)) return false
  return child.grants.every((cg) =>
    parent.grants.some(
      (pg) =>
        verbNarrows(cg.verb, pg.verb) &&
        patternNarrows(cg.resource, pg.resource) &&
        ceilingNarrows(cg.ceiling, pg.ceiling),
    ),
  )
}

/**
 * Delegation helper: derive a CHILD Scope narrowed strictly below `parent`.
 * The proposed `narrowed` Scope is returned iff it is a subset of `parent`;
 * any widening (a verb/resource/ceiling outside the parent) throws. This is
 * the "delegatable via a Mandate that narrows downward" property — a child key
 * can never hold more authority than its parent.
 */
export function deriveChildScope(parent: Scope, narrowed: Scope): Scope {
  if (!narrows(narrowed, parent)) {
    throw new Error('deriveChildScope: proposed scope widens the parent — delegation must narrow')
  }
  return { grants: narrowed.grants.map((g) => ({ ...g })) }
}

/** Type guard: is `v` a structurally-valid Scope? */
export function isScope(v: unknown): v is Scope {
  if (!v || typeof v !== 'object') return false
  const grants = (v as { grants?: unknown }).grants
  if (!Array.isArray(grants)) return false
  return grants.every(
    (g) =>
      g &&
      typeof g === 'object' &&
      typeof (g as ScopeGrant).verb === 'string' &&
      typeof (g as ScopeGrant).resource === 'string',
  )
}
