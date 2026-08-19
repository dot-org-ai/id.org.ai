/**
 * dlvp/bizsteps.ts — the PROVISIONAL digital bizStep verbs for the DLVP consent
 * handshake (SYNTHESIS C2, lens-B §3).
 *
 * These mirror `worker/resolve/capture.ts` BIZSTEP_RESOLVING EXACTLY: they are
 * OUR draft/provisional DIGITAL bizStep verbs — a superset extension projecting
 * down to ref.gs1.org/cbv where a physical analog exists. They are **NOT
 * ratified GS1 CBV vocabulary**.
 *
 * ┌─ HONEST-GRADE (do not remove) ────────────────────────────────────────────┐
 * │ The digital bizSteps `Consenting` / `Disclosing` / `Revoking` DO NOT EXIST │
 * │ in the gs1.org.ai CBV vocabulary yet. They ship here as clearly-marked     │
 * │ provisional constants under our draft-superset namespace. The vocab rows   │
 * │ themselves must be authored in the sibling standards repo.                 │
 * │ TICKET: standards.org.ai — author BizStep-consenting/disclosing/revoking.  │
 * │ Tracked as a bd model-gap on this repo. NEVER claim ratified GS1.          │
 * └────────────────────────────────────────────────────────────────────────────┘
 */

/** Provisional digital bizStep: a consent grant is minted (the DLVP receipt). */
export const BIZSTEP_CONSENTING = 'https://gs1.org.ai/cbv/BizStep-consenting'
/** Provisional digital bizStep: one party selectively discloses to the other. */
export const BIZSTEP_DISCLOSING = 'https://gs1.org.ai/cbv/BizStep-disclosing'
/** Provisional digital bizStep: a consent grant is revoked (status-list flip). */
export const BIZSTEP_REVOKING = 'https://gs1.org.ai/cbv/BizStep-revoking'

/** The full set of provisional DLVP bizSteps (for advertisement/discovery). */
export const DLVP_BIZSTEPS = Object.freeze([
  BIZSTEP_CONSENTING,
  BIZSTEP_DISCLOSING,
  BIZSTEP_REVOKING,
] as const)

/** True iff `uri` is one of our provisional DLVP bizStep verbs (never ratified GS1). */
export function isDlvpBizStep(uri: string): boolean {
  return (DLVP_BIZSTEPS as readonly string[]).includes(uri)
}
