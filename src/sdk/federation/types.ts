/**
 * Upstream federation — the types a federated principal carries.
 *
 * id.org.ai is the **broker**: an upstream IdP (today Microsoft Entra ID)
 * terminates AT id.org.ai, which then issues its OWN identity to downstream
 * clients. Downstream consumers (e.g. a deck gate) verify an id.org.ai token
 * and never talk to Microsoft. This file names what survives that hop.
 *
 * Vocabulary discipline — two `tenantId`s exist in this codebase and they are
 * NOT the same thing:
 *   - `Identity.tenantId`            — id.org.ai's own parent Tenant (the
 *                                      thing an Agent belongs to).
 *   - `FederationProvenance.tenantId` — the UPSTREAM directory's tenant, i.e.
 *                                      the Entra `tid` GUID. Provenance only.
 *                                      Never an authorisation subject on its own.
 * The upstream tenant lives on `federation`, never on `Identity.tenantId`.
 */

/**
 * How strongly the human behind this principal was proven, recorded honestly.
 *
 * Ordered — `assuranceRank` below turns this into a comparable number. A gate
 * that demands `federated-idp` must NOT silently accept `email-code`.
 *
 *   `federated-idp` — an upstream OIDC provider authenticated the human and we
 *                     verified its signed id_token (Microsoft Entra today).
 *                     The human's own directory (and any IdP it federates to,
 *                     e.g. Ping) applied its own MFA/conditional-access policy.
 *   `email-code`    — the human proved control of a mailbox by returning a
 *                     one-time code. Proves mailbox custody at one instant.
 *                     Does NOT prove the directory account is live, that MFA
 *                     ran, or that the employer still employs them.
 *   `unverified`    — nothing was proven. Never minted by these flows; exists
 *                     so a legacy or unknown-provenance row can be represented
 *                     without lying about it.
 */
export type AssuranceLevel = 'federated-idp' | 'email-code' | 'unverified'

const ASSURANCE_RANK: Record<AssuranceLevel, number> = {
  unverified: 0,
  'email-code': 1,
  'federated-idp': 2,
}

/** Comparable rank for an assurance level. Unknown values sort as 0. */
export function assuranceRank(level: AssuranceLevel | undefined): number {
  if (!level) return 0
  return ASSURANCE_RANK[level] ?? 0
}

/** True iff `have` is at least as strong as `need`. */
export function assuranceSatisfies(have: AssuranceLevel | undefined, need: AssuranceLevel): boolean {
  return assuranceRank(have) >= assuranceRank(need)
}

/**
 * Which upstream produced this principal. Kept open (`string & {}`) because a
 * closed union here would have to be amended for every new upstream; the two
 * we implement are named.
 */
export type FederationProvider = 'microsoft' | 'email-code' | (string & {})

/**
 * Where a federated principal came from — recorded on the identity row so any
 * later authorisation decision can see the provenance, not just the outcome.
 *
 * Immutable once written except `verifiedAt`/`assurance`, which are re-stamped
 * on each successful re-authentication.
 */
export interface FederationProvenance {
  provider: FederationProvider
  /**
   * The upstream issuer, verbatim from the verified id_token `iss` claim
   * (e.g. `https://login.microsoftonline.com/<tid>/v2.0`). For `email-code`
   * this is the broker's own origin — the code was ours, not an IdP's.
   */
  issuer: string
  /**
   * Upstream directory tenant. Entra `tid` GUID. NOT `Identity.tenantId`.
   * Absent for `email-code` (no directory was consulted).
   */
  tenantId?: string
  /**
   * Upstream immutable subject. Entra `oid` (the object id, which survives
   * email/UPN changes) — deliberately not `sub`, which is pairwise per-app and
   * would break if the app registration is ever re-created.
   */
  subject: string
  /** Assurance actually achieved on the most recent authentication. */
  assurance: AssuranceLevel
  /** Epoch ms of the most recent successful upstream authentication. */
  verifiedAt: number
  /**
   * Email domain the principal authenticated under, lowercased
   * (`zebra.com`). This is what a domain-scoped gate keys on — it is derived
   * from a VERIFIED email/UPN, never from user input.
   */
  emailDomain?: string
  /** Upstream display name at time of verification. Advisory only. */
  displayName?: string
}

/**
 * The broker's normalised view of an upstream authentication, before it is
 * written to an identity row. Deliberately provider-agnostic: the Microsoft
 * mapper and the email-code mapper both produce this shape, so the identity
 * write path has exactly one branch.
 */
export interface FederatedPrincipal {
  /**
   * The id.org.ai identity id (DO shard key). Stable across logins.
   *   Microsoft   → `human:ms:<tid>:<oid>`
   *   email-code  → `human:email:<lowercased email>`
   */
  identityId: string
  /** Verified email address, lowercased. */
  email: string
  /** Display name, best effort. Falls back to the email local-part. */
  name: string
  provenance: FederationProvenance
}

/**
 * Capability level a given assurance may reach. A stored row can claim any
 * level it likes; the broker clamps to this so a downgrade in assurance is
 * never silently ignored.
 *
 *   federated-idp → 2 (L2 Identified — same as a WorkOS-authenticated human)
 *   email-code    → 1 (L1 Sandboxed — enough to read a gated deck, not enough
 *                      to mint keys or act on a tenant)
 *   unverified    → 0
 */
export function levelCeilingForAssurance(level: AssuranceLevel | undefined): 0 | 1 | 2 {
  switch (level) {
    case 'federated-idp':
      return 2
    case 'email-code':
      return 1
    default:
      return 0
  }
}

/** Lowercased domain part of an email, or undefined when unparseable. */
export function emailDomainOf(email: string | undefined): string | undefined {
  if (!email) return undefined
  const at = email.lastIndexOf('@')
  if (at <= 0 || at === email.length - 1) return undefined
  return email.slice(at + 1).toLowerCase()
}

/**
 * Why an upstream federation attempt failed, in terms the UI can branch on.
 *
 * `consent-required` is the one that matters commercially: it is what a
 * restrictive corporate tenant returns when its admin-consent policy blocks an
 * unknown third-party app. It is NOT an error in our integration — it is the
 * exact condition the email-code fallback exists to survive, so the callback
 * routes it to the fallback rather than showing a failure.
 */
export type FederationErrorKind =
  | 'consent-required'
  | 'access-denied'
  | 'invalid-state'
  | 'invalid-token'
  | 'upstream-error'
  | 'not-configured'

export class FederationError extends Error {
  constructor(
    readonly kind: FederationErrorKind,
    message: string,
    /** Upstream error code verbatim (`AADSTS65001`, `consent_required`, …). */
    readonly upstreamCode?: string,
  ) {
    super(message)
    this.name = 'FederationError'
  }
}
