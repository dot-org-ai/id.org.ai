/**
 * The RFC 8693 `act` claim — and why this file exists at all.
 *
 * OAuth 2.0 Token Exchange (RFC 8693 §4.1) carries delegation as a **nested
 * `act` claim**. Its own worked example is the contract we implement:
 *
 * ```json
 * { "sub": "user@example.net",
 *   "act": { "sub": "https://service16.example.com",
 *            "act": { "sub": "https://service77.example.com" } } }
 * ```
 *
 * and the RFC's reading of it — *"service16 is the current actor and service77
 * was a prior actor"* — pins the direction that is otherwise very easy to get
 * backwards: the token's own `sub` is the **original subject** (our human
 * root), the **outermost `act` is the MOST RECENT actor**, and each nested
 * `act` is an earlier one. Our ledger chain runs the other way, actor-first, so
 * `envelopeFromChain` performs exactly that permutation and
 * `chainFromEnvelope` undoes it. Getting this backwards produces an envelope
 * that verifies against itself and inverts who is accountable, which is why the
 * RFC's own example is pinned as a test.
 *
 * ⚠ **The specification is explicit that `act` is INFORMATIONAL.** RFC 8693
 * defines the claim's syntax and places no obligation on a resource server to
 * check that the delegation it describes ever happened. A token can therefore
 * assert a chain no authority record supports while every other part of it —
 * signature, issuer, audience, expiry — is perfectly valid.
 *
 * **So our ledger enforces it.** `verifyActChain` holds a presented envelope
 * against the chain the grant records actually contain, elementwise, and
 * refuses an extra hop, a missing hop, a reordering, a substituted principal, a
 * fabricated root and a cycle. The check is exact rather than "close enough" on
 * purpose: a delegation chain that is nearly right is a delegation chain that
 * is wrong.
 *
 * Depth is capped. An unbounded nest is a cheap way to burn a verifier's stack
 * or its CPU budget, and a real delegation sixteen hops deep is a defect.
 */

import type { ActClaimShape, ActHop } from './types'

/**
 * The deepest delegation chain that may exist. Sixteen is far past any real
 * B2H2A → A2A path and small enough that a recursive walk cannot be used as a
 * denial-of-service primitive.
 */
export const MAX_CHAIN_DEPTH = 16

export type ActChainMismatch =
  | 'malformed'
  | 'depth-exceeded'
  | 'length-mismatch'
  | 'principal-mismatch'
  | 'cycle'
  | 'empty'

export type ActChainVerdict = { ok: true } | { ok: false; reason: ActChainMismatch; at: number }

export type FlattenResult =
  | { ok: true; principals: string[] }
  | { ok: false; reason: 'malformed' | 'depth-exceeded'; at: number }

/**
 * Build the RFC 8693 envelope from a ledger chain.
 *
 * `chain[0]` is the principal acting now; `chain[chain.length - 1]` is the root
 * it ultimately acts for. The envelope's `sub` is that root, its outermost
 * `act.sub` is `chain[0]`, and each nested `act` walks toward the root.
 *
 * A single-hop chain (a human acting for itself) yields `{ sub }` with no
 * `act` — there is no actor distinct from the subject to name.
 */
export function envelopeFromChain(chain: readonly ActHop[]): ActClaimShape | null {
  if (chain.length === 0) return null
  if (chain.length > MAX_CHAIN_DEPTH) {
    throw new RangeError(`act chain exceeds MAX_CHAIN_DEPTH (${MAX_CHAIN_DEPTH})`)
  }
  const root = chain[chain.length - 1].sub
  if (chain.length === 1) return { sub: root }
  // Actors, most-recent first: chain[0] … chain[n-2].
  let inner: ActClaimShape = { sub: chain[chain.length - 2].sub }
  for (let i = chain.length - 3; i >= 0; i--) {
    inner = { sub: chain[i].sub, act: inner }
  }
  return { sub: root, act: inner }
}

/**
 * Undo `envelopeFromChain` — the principal list in LEDGER order (actor first,
 * root last). Returns `null` on anything malformed or over-deep; it never
 * returns a truncated list, because a truncated chain that looks complete is
 * exactly the lie this module exists to refuse.
 */
export function chainFromEnvelope(envelope: unknown, maxDepth: number = MAX_CHAIN_DEPTH): string[] | null {
  const flat = flattenEnvelope(envelope, maxDepth)
  if (!flat.ok) return null
  const [root, ...actors] = flat.principals
  return [...actors, root]
}

/**
 * Walk the envelope outermost-in, returning `[sub, act.sub, act.act.sub, …]`.
 * This is the raw wire order, not the ledger order — `chainFromEnvelope`
 * converts.
 */
export function flattenEnvelope(envelope: unknown, maxDepth: number = MAX_CHAIN_DEPTH): FlattenResult {
  const principals: string[] = []
  let node: unknown = envelope
  while (node !== undefined) {
    if (node === null || typeof node !== 'object' || Array.isArray(node)) {
      return { ok: false, reason: 'malformed', at: principals.length }
    }
    const sub = (node as { sub?: unknown }).sub
    if (typeof sub !== 'string' || sub.length === 0) {
      return { ok: false, reason: 'malformed', at: principals.length }
    }
    principals.push(sub)
    if (principals.length > maxDepth) {
      return { ok: false, reason: 'depth-exceeded', at: maxDepth }
    }
    node = (node as { act?: unknown }).act
  }
  return { ok: true, principals }
}

/**
 * Hold a presented envelope against the ledger's chain.
 *
 * Exact and elementwise. Every refusal below is a real forgery shape, not a
 * hypothetical:
 *
 * - **extra hop** — a token inserts an intermediary that never received a
 *   grant, laundering an unauthorised agent into a legitimate chain.
 * - **missing hop** — a token elides the intermediary that ATTENUATED the
 *   scope, so a verifier reasons about the root's authority rather than the
 *   narrowed authority it should be bounded by.
 * - **reordering** — swapping two hops swaps who is accountable while keeping
 *   the same set of names, which passes any set-based check.
 * - **substituted principal** — one name changed, everything else identical.
 * - **cycle** — a repeated principal: either a bug, or a chain built to defeat
 *   a depth check.
 */
export function verifyActChain(presented: unknown, ledger: readonly ActHop[]): ActChainVerdict {
  if (ledger.length === 0) return { ok: false, reason: 'empty', at: 0 }
  const flat = flattenEnvelope(presented)
  if (!flat.ok) return { ok: false, reason: flat.reason, at: flat.at }

  const seen = new Set<string>()
  for (let i = 0; i < flat.principals.length; i++) {
    if (seen.has(flat.principals[i])) return { ok: false, reason: 'cycle', at: i }
    seen.add(flat.principals[i])
  }

  const presentedChain = chainFromEnvelope(presented)
  if (presentedChain === null) return { ok: false, reason: 'malformed', at: 0 }
  if (presentedChain.length !== ledger.length) {
    return { ok: false, reason: 'length-mismatch', at: Math.min(presentedChain.length, ledger.length) }
  }
  for (let i = 0; i < presentedChain.length; i++) {
    if (presentedChain[i] !== ledger[i].sub) return { ok: false, reason: 'principal-mismatch', at: i }
  }
  return { ok: true }
}

// ============================================================================
// Poison fixtures
// ============================================================================

/**
 * Exported so every consumer tests the same forgeries rather than each
 * inventing its own happy path. A gate that has only ever seen valid input is
 * a gate nobody has tested.
 *
 * `ledger` is the truth; `presented` is what a token claimed.
 */
export interface ActChainPoison {
  name: string
  why: string
  ledger: ActHop[]
  presented: unknown
  expect: ActChainMismatch
}

/** agent_7f3a acts under agent_supervisor_02, which acts for human:seat_kim. */
export const POISON_LEDGER_CHAIN: readonly ActHop[] = [
  { sub: 'agent_7f3a', grantId: 'grant_c' },
  { sub: 'agent_supervisor_02', grantId: 'grant_b' },
  { sub: 'human:seat_kim', grantId: null },
]

/** The honest envelope for `POISON_LEDGER_CHAIN`. */
export const POISON_HONEST_ENVELOPE: ActClaimShape = {
  sub: 'human:seat_kim',
  act: { sub: 'agent_7f3a', act: { sub: 'agent_supervisor_02' } },
}

export const ACT_CHAIN_POISON: readonly ActChainPoison[] = [
  {
    name: 'extra-hop',
    why: 'an intermediary that never received a grant is laundered into a legitimate chain',
    ledger: [...POISON_LEDGER_CHAIN],
    presented: {
      sub: 'human:seat_kim',
      act: { sub: 'agent_7f3a', act: { sub: 'agent_intruder', act: { sub: 'agent_supervisor_02' } } },
    },
    expect: 'length-mismatch',
  },
  {
    name: 'missing-hop',
    why: 'eliding the attenuating hop makes a verifier reason about the root scope, not the narrowed one',
    ledger: [...POISON_LEDGER_CHAIN],
    presented: { sub: 'human:seat_kim', act: { sub: 'agent_7f3a' } },
    expect: 'length-mismatch',
  },
  {
    name: 'reordered',
    why: 'the same principals in a different order swap who is accountable and pass any set-based check',
    ledger: [...POISON_LEDGER_CHAIN],
    presented: {
      sub: 'human:seat_kim',
      act: { sub: 'agent_supervisor_02', act: { sub: 'agent_7f3a' } },
    },
    expect: 'principal-mismatch',
  },
  {
    name: 'substituted-root',
    why: 'one name changed — a fabricated human root under an otherwise correct chain',
    ledger: [...POISON_LEDGER_CHAIN],
    presented: {
      sub: 'human:seat_dana',
      act: { sub: 'agent_7f3a', act: { sub: 'agent_supervisor_02' } },
    },
    expect: 'principal-mismatch',
  },
  {
    name: 'cycle',
    why: 'a repeated principal is either a bug or a chain built to defeat a depth check',
    ledger: [...POISON_LEDGER_CHAIN],
    presented: {
      sub: 'human:seat_kim',
      act: { sub: 'agent_7f3a', act: { sub: 'agent_7f3a' } },
    },
    expect: 'cycle',
  },
  {
    name: 'not-an-object',
    why: 'a bare string where an envelope belongs — the shape check must precede the content check',
    ledger: [...POISON_LEDGER_CHAIN],
    presented: 'agent_7f3a',
    expect: 'malformed',
  },
  {
    name: 'array-envelope',
    why: 'an array is an object in JS and would otherwise reach the property read',
    ledger: [...POISON_LEDGER_CHAIN],
    presented: ['human:seat_kim', 'agent_7f3a'],
    expect: 'malformed',
  },
  {
    name: 'sub-not-a-string',
    why: 'a numeric `sub` is not a principal and must not be coerced into one',
    ledger: [...POISON_LEDGER_CHAIN],
    presented: { sub: 7, act: { sub: 'agent_7f3a' } },
    expect: 'malformed',
  },
  {
    name: 'empty-sub',
    why: 'an empty principal matches nothing and must not be treated as a wildcard',
    ledger: [...POISON_LEDGER_CHAIN],
    presented: { sub: '', act: { sub: 'agent_7f3a' } },
    expect: 'malformed',
  },
  {
    name: 'null-act',
    why: 'an explicit null terminator is not the same as an absent one and must not read as a hop',
    ledger: [...POISON_LEDGER_CHAIN],
    presented: { sub: 'human:seat_kim', act: null },
    expect: 'malformed',
  },
  {
    name: 'over-deep',
    why: 'an unbounded nest is a cheap denial-of-service against any recursive verifier',
    ledger: [...POISON_LEDGER_CHAIN],
    presented: (() => {
      let c: ActClaimShape = { sub: 'p0' }
      for (let i = 1; i <= MAX_CHAIN_DEPTH + 4; i++) c = { sub: `p${i}`, act: c }
      return c
    })(),
    expect: 'depth-exceeded',
  },
]
