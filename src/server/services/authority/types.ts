/**
 * AuthorityService — Domain 11 (Authority)
 *
 * The four authority verbs canon claims and no code performed:
 *
 *   grant       principal + scope + expiry → a Scope record
 *   introspect  a grant (or a principal) → THE FULL CHAIN TO ITS HUMAN ROOT
 *   revoke      a grant → revoked, free, seatless, NON-RETROACTIVE
 *   refuse      an authority ask + a human → a settled, NON-granting decision
 *
 * ── WHY THIS EXISTS, AND WHY IN THIS ORDER ─────────────────────────────────
 *
 * `deputize` and `engage` are ratified ceremonies and neither is implemented.
 * **Shipping `deputize` before `revoke` ships an irrevocable authority grant**
 * — the migration would be a security incident, not a release. So `revoke`
 * lands first, with `introspect` beside it, because *you cannot revoke what
 * you cannot list*: an agent that cannot introspect discovers its authority by
 * PROBING, writing denial events into a customer's evidence ledger.
 *
 * ── THE FOUR PROPERTIES THAT ARE LOAD-BEARING ──────────────────────────────
 *
 * 1. **A grant is never authored from parameters.** Every grant has exactly one
 *    origin: a concrete ask a HUMAN read and settled (`fromAsk`), or an
 *    attenuation of a grant that already exists (`parentGrantId`). Neither →
 *    `authority-authoring-refused`. No surface in this family is permitted to
 *    be an authority-authoring UI, and this is that rule as code rather than
 *    as review.
 *
 * 2. **An attenuation may only ever shrink.** `narrows(child, parent)` from
 *    `src/sdk/auth/scope.ts` — already written, not re-invented here — plus a
 *    matching bound on expiry and an inherited warrantor.
 *
 * 3. **Revocation is non-retroactive and it says so.** Every revocation
 *    receipt, and every introspection, carries `NON_RETROACTIVE_DISCLOSURE`
 *    verbatim. A limit that is not stated is a false claim, and a limit
 *    disclosed only on hover is not disclosed.
 *
 * 4. **A refusal is a record.** On an append-only ledger a refusal that leaves
 *    no trace is indistinguishable from a request never seen. `settlement()`
 *    therefore returns four distinguishable states — `unasked` · `pending` ·
 *    `granted` · `refused` — the four-presence-state discipline applied to a
 *    decision.
 *
 * ── WHAT THIS MODULE IS NOT ────────────────────────────────────────────────
 *
 * - **Not a second write door.** Every Action this service records is handed to
 *   an injected `ActionSink`, which in production emits THROUGH the one public
 *   write door. When the sink cannot confirm, the receipt's artifact is
 *   `unconfirmed` — never a fabricated hash, never a silent success.
 * - **Not the OAuth token endpoints.** `/oauth/revoke` (RFC 7009) and
 *   `/oauth/introspect` (RFC 7662) act on TOKENS. These verbs act on AUTHORITY
 *   GRANTS. Two different acts sharing two names; this module never touches the
 *   OAuth ones and the HTTP surface mounts at `/authority/*` so a dispatcher
 *   never has to guess.
 *
 * Storage keys (all under the tenant's own Durable Object):
 *   authority:grant:{grantId}            → GrantRecord
 *   authority:children:{grantId}         → string[]  (attenuations of this grant)
 *   authority:held:{principalId}         → string[]  (grants this principal holds)
 *   authority:revoke-token:{hash}        → grantId   (the seatless revoke address)
 *   authority:claim-token:{hash}         → grantId   (REQ-9's pending subject)
 *   authority:ask:{askId}                → AskRecord
 *   authority:settlement:{askId}         → AskSettlement
 *   authority:refusal:{refusalId}        → RefusalRecord
 */

import type { Result } from '../../../sdk/foundation'
import type { Scope, Measure } from '../../../sdk/auth/scope'

export type { Scope, Measure } from '../../../sdk/auth/scope'

// ============================================================================
// Subjects and principals
// ============================================================================

/** The grains a resolved authority subject can be. */
export type PrincipalKind = 'human' | 'agent' | 'code' | 'service'

/** A subject that exists today. */
export interface ResolvedSubject {
  kind: PrincipalKind
  id: string
}

/**
 * REQ-9 — a subject that has **never resolved**. A warrantor may grant to a
 * person who has no record yet; the grant is minted `pending`, carries a claim
 * URL, authorises NOTHING until claimed, and is revocable before claim.
 *
 * The `hint` is whatever the warrantor addressed (an email, a badge number). It
 * is never treated as an identifier and never resolves anything.
 */
export interface PendingSubject {
  kind: 'pending'
  hint?: string
}

export type Subject = ResolvedSubject | PendingSubject

export function isPendingSubject(s: Subject): s is PendingSubject {
  return s.kind === 'pending'
}

/** The stable address of a resolved subject; `null` while pending. */
export function subjectId(s: Subject): string | null {
  return isPendingSubject(s) ? null : s.id
}

// ============================================================================
// The grant record
// ============================================================================

export type GrantStatus = 'pending' | 'active' | 'revoked' | 'expired'

/**
 * One hop of a delegation chain, in the shape RFC 8693's nested `act` claim
 * carries on the wire. `grantId` is `null` only for a human root, which holds
 * its authority natively rather than by grant.
 */
export interface ActHop {
  sub: string
  grantId: string | null
}

/**
 * The concrete ask a human read and settled. A grant that cites one may never
 * be wider than it: `narrows(minted, askedScope)` is checked at mint time and
 * is the identity for approve-and-stand.
 */
export interface SettledAskRef {
  askId: string
  /** The HUMAN who read it. An agent here is `not-the-warrantor`. */
  settledBy: string
  /** The Scope the human actually read, verbatim. */
  askedScope: Scope
}

/** REQ-9's claim seam. The token is stored hashed; the plaintext is returned once. */
export interface PendingClaim {
  tokenHash: string
  url: string
  claimedAt?: string
  claimedBy?: string
}

export const REVOCATION_CAUSES = [
  'warrantor-revoked',
  'holder-revoked',
  'cascade',
  'superseded',
  'policy',
] as const
export type RevocationCause = (typeof REVOCATION_CAUSES)[number]

export interface GrantRecord {
  id: string
  tenantId: string
  subject: Subject
  /** The human seat whose authority this spends. Inherited, never re-declared. */
  warrantor: string
  parentGrantId?: string
  scope: Scope
  /** REQ-20 — a standing envelope the tier cascade reads so a call never climbs. */
  standing: boolean
  /** Which rung of the cascade a standing envelope binds to. */
  bindsToTier?: string
  /** Whether a standing envelope also covers asks that `narrow` the one read. */
  narrowingAsksIncluded: boolean
  expiresAt: string
  status: GrantStatus
  createdAt: string
  fromAsk?: SettledAskRef
  claim?: PendingClaim
  revokedAt?: string
  revokedBy?: string
  revocationCause?: RevocationCause
  /** Set when this grant was revoked as a descendant of another. */
  cascadedFrom?: string
  /** SHA-256 of the seatless revoke secret. The secret is returned once, at mint. */
  revokeTokenHash: string
  /** The chain as recorded at mint: this hop first, the human root last. */
  actChain: ActHop[]
}

/** The read projection of a grant. Never carries a token hash. */
export interface GrantView {
  id: string
  tenantId: string
  subject: Subject
  warrantor: string
  parentGrantId: string | null
  scope: Scope
  standing: boolean
  bindsToTier: string | null
  narrowingAsksIncluded: boolean
  expiresAt: string
  status: GrantStatus
  createdAt: string
  askId: string | null
  /** The per-call ceiling this grant imposes, when it imposes exactly one. */
  ceiling: Measure | null
  revokedAt: string | null
  revokedBy: string | null
  revocationCause: RevocationCause | null
  cascadedFrom: string | null
  claimUrl: string | null
}

// ============================================================================
// Asks, settlements and refusals — #358
// ============================================================================

/**
 * The authority-class ask, indexed on the authority side. `worklists.dev` owns
 * the Action; this record is what makes `refused` distinguishable from
 * `unasked`. Without it, a decline leaves no trace and an agent retries a
 * refusal until the SLA kills it.
 */
export interface AskRecord {
  askId: string
  tenantId: string
  requestedBy: string
  /** The human seat the agent claims to act for. */
  onBehalfOf: string
  scope: Scope
  /** The requested expiry, echoed so the settlement can be bounded by it. */
  expiresAt: string
  createdAt: string
  /** The agent's justification, when it is disclosable. */
  reason?: string
}

/**
 * Fixed per deployment, never free text — the same discipline as
 * `worklists.dev`'s `block`. A free-text cause is a per-person note about a
 * human decision on an append-only ledger.
 */
export const REFUSAL_CAUSES = [
  'not-authorised',
  'scope-too-wide',
  'wrong-warrantor',
  'no-longer-needed',
  'unrecognised-request',
  'policy',
] as const
export type RefusalCause = (typeof REFUSAL_CAUSES)[number]

export function isRefusalCause(v: unknown): v is RefusalCause {
  return typeof v === 'string' && (REFUSAL_CAUSES as readonly string[]).includes(v)
}

export interface RefusalRecord {
  id: string
  tenantId: string
  askId: string
  /** The human who read it and said no. */
  refusedBy: string
  cause: RefusalCause
  at: string
  /** The artifact. Absent while the emit is unconfirmed — never fabricated. */
  eventHash?: string
}

/**
 * The four states a settlement can be in, and they are four different facts.
 * `unasked` is not `pending`, and `pending` is not `refused`.
 */
export type SettlementState = 'unasked' | 'pending' | 'granted' | 'refused'

export interface AskSettlement {
  askId: string
  state: SettlementState
  grantId: string | null
  refusalId: string | null
  settledBy: string | null
  settledAt: string | null
  cause: RefusalCause | null
}

// ============================================================================
// The chain — REQ-6
// ============================================================================

export type HopResolution = 'resolved' | 'unresolved'

/** Why a hop could not be resolved. A gap is REPORTED, never elided. */
export type HopGap =
  | 'grant-missing'
  | 'subject-unclaimed'
  | 'cycle-detected'
  | 'depth-exceeded'
  | 'tenant-mismatch'

export interface ChainHop {
  hop: number
  principal: string | null
  grantId: string | null
  grantedBy: string | null
  expiresAt: string | null
  scope: Scope | null
  status: GrantStatus | null
  resolution: HopResolution
  gap: HopGap | null
}

/**
 * What `revoke` costs and what it cannot do, carried on every introspection and
 * every revocation receipt. REQ-7: the limit is stated or the claim is false.
 */
export interface RevokeDisclosure {
  /** The seatless address. Reachable by the warrantor with no session. */
  address: string | null
  /** The verbatim string every face renders. Not a tooltip. Not a link. */
  disclosure: string
  free: true
  seatRequired: false
  nonRetroactive: true
}

export interface IntrospectResult {
  grant: GrantView | null
  /** From the grant up. Every hop present, gaps included. */
  chain: ChainHop[]
  /** False when any hop is unresolved. A shortened chain is never reported as whole. */
  chainComplete: boolean
  /** True only when the chain terminates at a human who settled a concrete ask. */
  rootsAtHuman: boolean
  warrantor: string | null
  /** The nested RFC 8693 `act` claim this chain would carry on the wire. */
  actClaim: ActClaimShape | null
  revoke: RevokeDisclosure
  asOf: string
}

/** A nested RFC 8693 `act` claim. Informational on the wire; enforced here. */
export interface ActClaimShape {
  sub: string
  act?: ActClaimShape
}

// ============================================================================
// Actions — every mint, attenuation, use and revocation
// ============================================================================

export type AuthorityActionName =
  | 'authority.mint'
  | 'authority.attenuate'
  | 'authority.claim'
  | 'authority.use'
  | 'authority.revoke'
  | 'authority.refuse'

export interface AuthorityAction {
  action: AuthorityActionName
  tenantId: string
  /** Who performed it. */
  actor: string
  subject?: string
  grantId?: string
  askId?: string
  at: string
  metadata?: Record<string, unknown>
}

/** What an emit produced. `confirmed: false` → the artifact is `unconfirmed`. */
export interface ActionReceipt {
  eventHash?: string
  confirmed: boolean
}

/**
 * The one write door, injected. This service never writes an event itself and
 * never fabricates a hash: an unconfirmed emit produces an `unconfirmed`
 * artifact, which is a presence state the contract already carries.
 */
export interface ActionSink {
  emit(action: AuthorityAction): Promise<ActionReceipt>
}

export interface Artifact {
  eventHash: string | null
  state: 'confirmed' | 'unconfirmed'
}

// ============================================================================
// Errors
// ============================================================================

/**
 * Slugs this service refuses under. Eight are already pinned in the estate's
 * cross-door error registry and are spelled here exactly as that registry
 * spells them — a second spelling of one error is the drift the registry
 * exists to prevent. The rest are PROPOSED and are reported as a filing
 * against the registry, not invented quietly.
 */
export const AUTHORITY_SLUGS = {
  // ── pinned in the cross-door registry, id.org.ai is a serving door ────────
  'ask-not-found': { registry: 'pinned', retryable: false, status: 404 },
  'ask-already-settled': { registry: 'pinned', retryable: false, status: 409 },
  'ask-expired': { registry: 'pinned', retryable: false, status: 410 },
  'not-the-warrantor': { registry: 'pinned', retryable: false, status: 403 },
  'chain-incomplete': { registry: 'pinned', retryable: true, status: 409 },
  'authz-expired': { registry: 'pinned', retryable: true, status: 401 },
  // ── proposed: filed against the registry, not invented quietly ────────────
  'grant-not-found': { registry: 'proposed', retryable: false, status: 404 },
  'grant-not-active': { registry: 'proposed', retryable: false, status: 409 },
  'scope-widens-parent': { registry: 'proposed', retryable: false, status: 422 },
  'expiry-widens-parent': { registry: 'proposed', retryable: false, status: 422 },
  'grant-widens-ask': { registry: 'proposed', retryable: false, status: 422 },
  'warrantor-mismatch': { registry: 'proposed', retryable: false, status: 422 },
  'authority-authoring-refused': { registry: 'proposed', retryable: false, status: 422 },
  'subject-unclaimed': { registry: 'proposed', retryable: false, status: 409 },
  'claim-token-invalid': { registry: 'proposed', retryable: false, status: 403 },
  'act-chain-mismatch': { registry: 'proposed', retryable: false, status: 403 },
  'refusal-cause-unknown': { registry: 'proposed', retryable: false, status: 422 },
  'revocation-incomplete': { registry: 'proposed', retryable: true, status: 409 },
  'chain-depth-exceeded': { registry: 'proposed', retryable: false, status: 422 },
  'invalid-expiry': { registry: 'proposed', retryable: false, status: 422 },
  'malformed-scope': { registry: 'proposed', retryable: false, status: 422 },
} as const

export type AuthoritySlug = keyof typeof AUTHORITY_SLUGS

/**
 * RFC 9457 `title` per slug — a short, stable, human-readable summary that does
 * not vary between occurrences. Kept beside the slugs so this repo has one
 * place, not one per route. The cross-door registry owns the canonical wording
 * for the six pinned rows; a divergence here is a filing, not a fork.
 */
export const AUTHORITY_SLUG_TITLES: Record<AuthoritySlug, string> = {
  'ask-not-found': 'Ask not found',
  'ask-already-settled': 'Ask already settled',
  'ask-expired': 'Ask expired',
  'not-the-warrantor': 'Not the warrantor',
  'chain-incomplete': 'Authority chain incomplete',
  'authz-expired': 'Authorization expired',
  'grant-not-found': 'Grant not found',
  'grant-not-active': 'Grant not active',
  'scope-widens-parent': 'Scope widens its parent',
  'expiry-widens-parent': 'Expiry outlives its parent',
  'grant-widens-ask': 'Grant widens the ask a human read',
  'warrantor-mismatch': 'Warrantor mismatch',
  'authority-authoring-refused': 'Authority authoring refused',
  'subject-unclaimed': 'Subject has not been claimed',
  'claim-token-invalid': 'Claim token invalid',
  'act-chain-mismatch': 'Act chain does not match the ledger',
  'refusal-cause-unknown': 'Refusal cause unknown',
  'revocation-incomplete': 'Revocation incomplete',
  'chain-depth-exceeded': 'Authority chain too deep',
  'invalid-expiry': 'Invalid expiry',
  'malformed-scope': 'Malformed scope',
}

export class AuthorityError {
  readonly _tag = 'AuthorityError' as const
  readonly message: string
  constructor(
    readonly slug: AuthoritySlug,
    message: string,
    readonly detail?: Record<string, unknown>,
  ) {
    this.message = message
  }
  get retryable(): boolean {
    return AUTHORITY_SLUGS[this.slug].retryable
  }
  get status(): number {
    return AUTHORITY_SLUGS[this.slug].status
  }
}

/**
 * The wire shape an authority verb crosses a Durable Object RPC boundary in.
 *
 * `AuthorityError` carries `status` and `retryable` as prototype getters, and
 * structured clone does not carry a getter. Returning the class across the
 * boundary silently strips exactly the two fields the HTTP error response is
 * built from — so every RPC flattens to this instead.
 */
export type AuthorityRpcResult<T> =
  | { ok: true; data: T }
  | {
      ok: false
      slug: AuthoritySlug
      message: string
      status: number
      retryable: boolean
      detail?: Record<string, unknown>
    }

// ============================================================================
// Verb inputs and receipts
// ============================================================================

export interface GrantInput {
  tenantId: string
  subject: Subject
  scope: Scope
  expiresAt: string
  /** Exactly one of these two. Neither → `authority-authoring-refused`. */
  fromAsk?: SettledAskRef
  parentGrantId?: string
  /** Only ever declared on a grant born from an ask. */
  warrantor?: string
  standing?: boolean
  bindsToTier?: string
  narrowingAsksIncluded?: boolean
  /** Who called. On an attenuation, must be the parent's holder or its warrantor. */
  actor: string
  /** Where a pending subject's claim URL is rooted. */
  claimUrlBase?: string
}

export interface GrantReceipt {
  grant: GrantView
  /** The seatless revoke secret. Returned ONCE, at mint. */
  revokeToken: string
  revoke: RevokeDisclosure
  /** REQ-9 — returned once, only for a pending subject. */
  claimToken: string | null
  artifact: Artifact
  actClaim: ActClaimShape
}

export interface ClaimInput {
  tenantId: string
  grantId: string
  claimToken: string
  subject: ResolvedSubject
  actor: string
}

export interface RevokeInput {
  tenantId: string
  grantId: string
  /**
   * Who is revoking. Authorised iff it is the warrantor, the holder, or a
   * caller presenting `revokeToken`. **No seat is required on any path.**
   */
  actor?: string
  revokeToken?: string
  cause?: RevocationCause
}

export interface RevokeReceipt {
  grantId: string
  revokedAt: string
  revokedBy: string
  cause: RevocationCause
  /** Descendants revoked with it. Cascade fails closed. */
  cascaded: string[]
  /** True when this call found the grant already revoked. Not an error. */
  alreadyRevoked: boolean
  revoke: RevokeDisclosure
  artifact: Artifact
}

export interface RefuseInput {
  tenantId: string
  askId: string
  /** The human who read it. An agent here is `not-the-warrantor`. */
  refusedBy: string
  cause: RefusalCause
}

export interface RefuseReceipt {
  refusal: RefusalRecord
  settlement: AskSettlement
  artifact: Artifact
}

export interface AuthorizeInput {
  tenantId: string
  grantId: string
  verb: string
  resource: string
  amount?: Measure
  /** Who is exercising it. */
  actor: string
  /** The `act` chain the caller's token presented, if any. Cross-checked. */
  presentedActClaim?: ActClaimShape
}

/**
 * The decision. A DENIAL RECORDS NOTHING on the ledger: REQ-6's whole argument
 * is that an agent which cannot introspect discovers its authority by probing,
 * and a service that writes a denial event per probe turns that into the
 * customer's evidence ledger. Introspection is the remedy; denial noise is not.
 */
export interface AuthorizeDecision {
  allowed: boolean
  grantId: string
  /** Present only on a denial. Never rendered as an authority. */
  reason: string | null
  slug: AuthoritySlug | null
  artifact: Artifact | null
}

export interface ListGrantsInput {
  tenantId: string
  /** Restrict to grants held by one principal. */
  principal?: string
  /** Restrict to standing envelopes — §2.5's list. */
  standingOnly?: boolean
  /** Include revoked/expired rows. Default false. */
  includeInactive?: boolean
  limit?: number
  cursor?: string
}

export interface ListGrantsResult {
  grants: GrantView[]
  /** Opaque forward cursor. No totals. */
  cursor: string | null
  revoke: RevokeDisclosure
  asOf: string
}

// ============================================================================
// The service
// ============================================================================

export interface AuthorityService {
  /** Index an authority-class ask so a refusal is distinguishable from silence. */
  recordAsk(input: AskRecord): Promise<Result<AskRecord, AuthorityError>>

  grant(input: GrantInput): Promise<Result<GrantReceipt, AuthorityError>>
  claim(input: ClaimInput): Promise<Result<GrantReceipt, AuthorityError>>
  introspect(input: { tenantId: string; grantId: string }): Promise<Result<IntrospectResult, AuthorityError>>
  revoke(input: RevokeInput): Promise<Result<RevokeReceipt, AuthorityError>>
  refuse(input: RefuseInput): Promise<Result<RefuseReceipt, AuthorityError>>

  settlement(input: { tenantId: string; askId: string }): Promise<Result<AskSettlement, AuthorityError>>
  listGrants(input: ListGrantsInput): Promise<Result<ListGrantsResult, AuthorityError>>
  authorize(input: AuthorizeInput): Promise<Result<AuthorizeDecision, AuthorityError>>
}
