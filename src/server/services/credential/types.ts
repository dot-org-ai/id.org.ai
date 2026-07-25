/**
 * Held-credential facts (beads id-j0k, ADR 0016 C6) — per-principal
 * identity facts on IdentityDO storage, NEVER a concept-dimension node.
 *
 * A held fact records that a principal CLAIMS to hold a credential (plus
 * any holder-attested artifacts it has supplied). It is input to
 * verification, never a substitute for it: standing always comes from the
 * registry at check time (serve-never-home). Verification outcomes are
 * journaled as INSERT-ONLY events — a cached `live` flag on a revoked
 * credential is the suspended-attorney bug (ADR 0016 walk 5), so no
 * mutable verification status is ever stored.
 */

import type { Result } from '../../../sdk/foundation'
import type { NotFoundError, ValidationError } from '../../../sdk/foundation'
import type {
  EffectClass,
  HolderPortalExport,
  PresentedCredential,
  SourceClass,
  VerificationVerdict,
} from '../../../sdk/credential'

export interface HeldCredentialFact {
  readonly principalId: string
  readonly credentialType: string
  /** Registry-facing reference: registration/license/membership number. */
  readonly ref: string
  readonly jurisdiction?: string
  readonly presented: PresentedCredential
  /** Holder-supplied portal export (the AuctionACCESS interim tier). */
  readonly holderAttested?: HolderPortalExport
  readonly recordedAt: string
}

/** One verification outcome, journaled insert-only. */
export interface CredentialVerificationEvent {
  readonly principalId: string
  readonly credentialType: string
  readonly ref: string
  readonly registry: string
  readonly verdict: VerificationVerdict
  readonly sourceClass: SourceClass
  readonly effectClass: EffectClass
  readonly live: boolean
  readonly goodStanding: boolean
  readonly satisfiesActClass: boolean
  readonly checkedAt: string
}

export interface CredentialFactService {
  putFact(fact: Omit<HeldCredentialFact, 'recordedAt'> & { recordedAt?: string }): Promise<Result<HeldCredentialFact, ValidationError>>
  getFact(principalId: string, credentialType: string, ref: string): Promise<Result<HeldCredentialFact, NotFoundError>>
  listFacts(principalId: string, opts?: { credentialType?: string }): Promise<HeldCredentialFact[]>
  deleteFact(principalId: string, credentialType: string, ref: string): Promise<Result<{ deleted: boolean }, never>>
  /** Insert-only journal — there is deliberately no update or delete. */
  recordVerification(event: CredentialVerificationEvent): Promise<Result<CredentialVerificationEvent, ValidationError>>
  listVerifications(principalId: string, opts?: { limit?: number }): Promise<CredentialVerificationEvent[]>
}
