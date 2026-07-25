/**
 * Credential verification vocabulary — org.ai ADR 0016 C5 / ADR 0018.
 *
 * id.org.ai is the VERIFIER (the AuctionAccess role): issuers home
 * credentials, this layer verifies them, the law-substrate kernel judges the
 * resulting facts. Serve, never home — nothing in this module ever mints or
 * revokes a credential (ADR 0013 R5).
 *
 * Naming (ADR 0016 M-d / beads id-bb3): "Credential" collides with OAuth's
 * client_credentials in this repo, and the rename decision is not yet
 * settled. The pinned acceptance spec (specs/axp-acceptance.spec.json,
 * digest eaae6c2b…) pins RESPONSE SHAPE, never type names — so this module
 * deliberately avoids exporting a bare `Credential` type. The thing a caller
 * hands to `verify()` is a `PresentedCredential` (a claim to hold, presented
 * for verification); the per-principal stored fact is a `HeldCredentialFact`
 * (server side, src/server/services/credential). When id-bb3 lands, these
 * names can migrate without touching the wire contract.
 */

// ── Effect classes (ADR 0016 C5 — the drivly triad) ────────────────────────

export type EffectClass = 'act' | 'record' | 'read'

export const EFFECT_CLASSES: readonly EffectClass[] = Object.freeze(['act', 'record', 'read'])

export function isEffectClass(v: unknown): v is EffectClass {
  return typeof v === 'string' && (EFFECT_CLASSES as readonly string[]).includes(v)
}

// ── Verdict tier (ADR 0018 R4 — evidentiary strength is typed, never implied)

/**
 * How strong the evidence is:
 *   - `registry-verified`   — the registry of record itself answered.
 *   - `holder-attested`     — the holder's own authenticated export of its
 *     registry artifacts (e.g. the dealer's AuctionACCESS portal session).
 *     Honest but self-reported. NEVER satisfies an act-class predicate
 *     (ADR 0018 open item (b): currently it may not).
 *   - `unverifiable-by-registry` — no sanctioned channel exists (or the
 *     source is not yet connected/ingested). Carries a typed cure — the
 *     access application itself. Never fabricated liveness.
 */
export type VerificationVerdict = 'registry-verified' | 'holder-attested' | 'unverifiable-by-registry'

// ── Source classification ──────────────────────────────────────────────────

/** The five adapter classes of the 2026-07-25 registry research (+ the interim partner tier). */
export type SourceClass =
  | 'public-lookup'
  | 'bulk-ingest'
  | 'sanctioned-aggregator'
  | 'subscription'
  | 'partner'
  | 'partner-interim'

/** ADR 0016 C5 verification modes as they appear on the wire (`source.mode`). */
export type SourceMode = 'registry' | 'psv' | 'partner' | 'federated'

/** Whether the adapter's lookup path is actually built, interim, or an honest stub. */
export type AdapterStatus = 'real' | 'real-interim' | 'stub'

/**
 * The registry's OWN publication cadence. Freshness is bounded by what the
 * registry itself publishes (ADR 0018 R5): a per-query source supports a
 * genuine at-the-act check; a file-published source supports only
 * fresh-against-latest-file, and the answer must carry `asOf` explicitly.
 */
export type RegistryCadence =
  | { readonly kind: 'per-query' }
  | { readonly kind: 'daily' }
  | { readonly kind: 'twice-weekly'; readonly publishDays: readonly string[] }
  | { readonly kind: 'unknown' }

// ── Request shapes ─────────────────────────────────────────────────────────

/**
 * A claim to hold a credential, presented for verification. Monadic —
 * {issuer, holder}, no represented principal (ADR 0016 C1); representation
 * edges are a different primitive and are never carried here.
 */
export interface PresentedCredential {
  /** Credential-type key, e.g. 'uspto-registered', 'mn-dealer-license'. */
  readonly type: string
  readonly registrationNumber?: string
  readonly licenseNumber?: string
  readonly membershipId?: string
  /** The acting jurisdiction, where the type is multi-state. */
  readonly jurisdiction?: string
  readonly holderName?: string
}

export interface VerifyPrincipal {
  readonly id: string
  readonly workerType: 'human' | 'agent' | 'organization' | 'service'
}

// ── Answer shapes ──────────────────────────────────────────────────────────

export interface HolderRecord {
  readonly name: string
  readonly kind: 'human' | 'organization'
  readonly id?: string
  readonly jurisdiction?: string
}

/** A registry-enumerated worker ID (rep card, salesperson license, MLO number). */
export interface RepRecord {
  readonly registry: string
  readonly workerId?: string
  readonly name?: string
  /** Verbatim registry standing for the worker ID — never collapsed. */
  readonly standing?: string
}

/**
 * The machine-readable cure attached to a typed failure (ADR 0018 R4). Where
 * no sanctioned channel exists, the cure IS the access application.
 */
export type RegistryCure =
  | { readonly action: 'connect-source'; readonly channel: string; readonly note: string }
  | { readonly action: 'subscribe'; readonly channel: 'nipr-pdb' | 'nmls-b2b-access'; readonly note: string }
  | { readonly action: 'apply-partner'; readonly channel: 'auctionaccess-autotec'; readonly note: string }
  | { readonly action: 'confirm-source'; readonly channel: string; readonly note: string }
  | { readonly action: 'refresh-bulk-file'; readonly channel: string; readonly note: string }
  | { readonly action: 'holder-pull'; readonly channel: 'auctionaccess-holder-pull'; readonly note: string }

/** What a registry (or the holder's export) actually said. */
export interface RegistryFinding {
  /** Is the credential currently in force? Never collapsed with goodStanding. */
  readonly live: boolean
  /** Is it unencumbered? Two fields, never one (TX 'APA Expired' survives). */
  readonly goodStanding: boolean
  /** The registry's status VERBATIM — 'Active', 'APA Expired', 'Suspended', … */
  readonly registryStatus: string
  readonly holder: HolderRecord | null
  readonly reps: readonly RepRecord[]
  /** When the registry's answer speaks as of (ISO). Mandatory — bulk sources especially. */
  readonly asOf: string
  /** Did this answer come from a cache rather than a fresh source round-trip? */
  readonly fromCache: boolean
}

/**
 * What an adapter returns. A stub NEVER fabricates a finding — where no
 * sanctioned channel exists the answer is `unverifiable-by-registry` with a
 * cure the caller must surface.
 */
export type RegistryAnswer =
  | ({ readonly verdict: 'registry-verified' } & RegistryFinding)
  | ({ readonly verdict: 'holder-attested'; readonly attestedBy: string } & RegistryFinding)
  | { readonly verdict: 'unverifiable-by-registry'; readonly reason: string; readonly cure: RegistryCure }

// ── The verify() result (pinned wire shape + verdict-tier extensions) ──────

export type FreshnessFailure = 'cached-for-act' | 'stale-beyond-cadence'

/**
 * The pinned spec fixes { live, goodStanding, holder, reps, source,
 * freshness, checkedAt }; the verdict tier, registryStatus, cadence,
 * satisfiesActClass and cure are additive (ADR 0018).
 */
export interface VerificationResult {
  readonly live: boolean
  readonly goodStanding: boolean
  readonly holder: HolderRecord | null
  readonly reps: readonly RepRecord[]
  readonly source: {
    readonly mode: SourceMode
    readonly registry: string
    readonly sourceClass: SourceClass
    readonly status: AdapterStatus
  }
  readonly freshness: {
    readonly cached: boolean
    readonly maxAgeSeconds?: number
    readonly asOf?: string
    readonly cadence: RegistryCadence
    readonly staleBeyondCadence: boolean
  }
  readonly checkedAt: string
  readonly verdict: VerificationVerdict
  readonly registryStatus?: string
  /**
   * May this evidence satisfy an act-class predicate? True ONLY for a fresh,
   * uncached `registry-verified` answer within the registry's own cadence.
   * `holder-attested` is NEVER true here; neither is any freshness failure.
   */
  readonly satisfiesActClass: boolean
  readonly freshnessFailure?: FreshnessFailure
  readonly cure?: RegistryCure
}

// ── Holder-attested input (AuctionACCESS interim pull) ─────────────────────

/**
 * The dealer entity's own authenticated AuctionACCESS portal export — its
 * standing plus rep-card roster. Typed `holder-attested`, never
 * `registry-verified` (ADR 0018 R4).
 */
export interface HolderPortalExport {
  /** Principal id of the holder whose portal session produced the export. */
  readonly exportedBy: string
  readonly exportedAt: string
  readonly membership: { readonly id: string; readonly status: string }
  readonly repCards: readonly { readonly repCardId: string; readonly name?: string; readonly status: string }[]
}

// ── Deep-freeze helper for ratified tables ─────────────────────────────────

export function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value)
    for (const key of Object.getOwnPropertyNames(value)) {
      deepFreeze((value as Record<string, unknown>)[key])
    }
  }
  return value
}
