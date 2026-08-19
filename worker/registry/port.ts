/**
 * registry/port.ts — the Phase-4 registry PORT: the ONE read seam between the
 * resolver door and the identifier registry (SYNTHESIS C1, lens-A §2).
 *
 * The registry is the spine: `identifier → owner → linkset → defaultLink →
 * policy` as four records with INDEPENDENT lifecycles (lens-A §2). A brand
 * proves ownership once (OwnerRef) and writes linksets thousands of times
 * (Linkset) without re-proving; an individual claims one instance without
 * touching the brand's record; policy inherits class → lot → instance unless
 * overridden. The resolve path needs only `lookup` — it joins the four records
 * into one `ResolvedManifest`. Owner/linkset/policy WRITES are a separate admin
 * seam (the record shapes are defined here; the write API is deferred + ticketed).
 *
 * This copies the shape of `src/sdk/credential/sources/port.ts` VERBATIM: a
 * single-seam interface plus an HONEST default (`emptyRegistryPort`) that
 * answers every lookup with a TYPED not-provisioned — never a fabricated
 * record. With no live binding wired (RAILS: no D1/R2/KV provisioned this
 * increment), the resolver falls back to the current existence-neutral,
 * self-derived identity document, so the shipped resolve.test.ts stays green.
 *
 * DEFERRED + TICKETED (bd model-gap):
 *   - LIVE BINDING PROVISIONING — no R2/parquet (or D1/KV) store this increment.
 *     `registry/schema.sql` is the schema-of-record the provisioning ticket
 *     implements against; the port default stays `emptyRegistryPort`.
 *   - REGISTRY WRITE / ADMIN API — the ownership-claim provision endpoint and
 *     the linkset-authoring API are a separate seam.
 */

/**
 * The declared grain of an identifier (lens-A §2 data model). Each leftmost AI
 * carries its own grain; the registry stores it, never guesses it.
 */
export type Grain = 'class' | 'lot' | 'instance' | 'place' | 'asset' | 'document'

/** How ownership was established (lens-A §2 ownership ladder). */
export type ProofMethod = 'gcp-vc' | 'dns' | 'vc' | 'anchor'

/**
 * The scope a single OwnershipClaim grants. The four proof methods reduce to
 * one claim; the scope says WHICH key-space the owner may write.
 *   - range    : all `01/{gcpPrefix}*` keys, claimed in one act (the GCP wedge).
 *   - instance : one `01/{gtin}/21/{serial}` key (the consumer-side unlock).
 *   - hostname : a brand-domain branded resolver, proven by DNS control.
 */
export type ClaimScope =
  | { kind: 'range'; gcpPrefix: string }
  | { kind: 'instance'; key: string }
  | { kind: 'hostname'; host: string }

/**
 * The unified ownership claim (lens-A §2). All four proof methods (GCP-VC, DNS,
 * non-GS1 VC, on-chain anchor) reduce internally to this ONE shape with a proof
 * digest. `strength` is the verdict tier the method mints.
 *
 * HONEST-GRADE (deferred + ticketed): `proofDigest` is trusted as-supplied in
 * v1. Full cryptographic verification of each method — GCP-VC signature verify
 * against the GS1/bridge issuer JWKS, DNS TXT (`_gs1-owner`) fetch, non-GS1 VC
 * verify against the ID-JAG trust list, on-chain anchor read — is a later
 * increment. See `registry/ownership.ts`.
 */
export interface OwnershipClaim {
  method: ProofMethod
  /** The owner id — reuses the org_/human_/agent_ id space (no new principal type). */
  subject: string
  scope: ClaimScope
  /** Hash over the proof artifact (VC jws | DNS token | anchor ref). */
  proofDigest: string
  provedAt: string
  strength: 'range' | 'hostname' | 'attested' | 'anchored'
}

// ── The four independent-lifecycle records (lens-A §2 data model) ───────────

/**
 * IdentifierRecord — the map from one canonical identifier to who owns it, what
 * it links to, and under what policy. The joining record; the other three are
 * referenced by id so they can be written on their own lifecycles.
 */
export interface IdentifierRecord {
  /** Canonical uncompressed DL path, grain-typed: "01/09506000134352", "01/…/21/SER1", "vin/1HG…". */
  key: string
  grain: Grain
  /** The {type}_{sqid} $id it dereferences to (entity-store id). */
  canonicalId: string
  /** FK → OwnerRef.ownerId (may be class-inherited). */
  ownerRef: string
  /** FK → Linkset.id. */
  linksetRef: string
  /** linkId | 'gs1:pip' — the 303 target. */
  defaultLink: string
  /** FK → PolicyRef.id. */
  policyRef: string
  provenance: { proofId: string; provedAt: string; method: ProofMethod }
  etag: string
  updatedAt: string
}

/** OwnerRef — the proven claimant (lens-A §2). Written once per proof, reused across keys. */
export interface OwnerRef {
  /** org_… | human_… | agent_… — reuses src/sdk types Identity id space. */
  ownerId: string
  claim: OwnershipClaim
  /** For GS1 keys: the licensed Company Prefix — ASSERTED by the GCP-VC, never derived. */
  gcpPrefix?: string
  scope: ClaimScope
}

/** One RFC 9264 link entry. `linkType` is a full relation URI (gs1:* or our id:* superset). */
export interface LinkEntry {
  linkType: string
  href: string
  title?: string
  hreflang?: string
  type?: string
  grain?: Grain
}

/** Linkset — the RFC 9264 set, per-lens (lens-A §2). Written thousands of times per owner. */
export interface Linkset {
  id: string
  links: LinkEntry[]
  /** linkId | 'gs1:pip' — the default 303 target for this linkset. */
  defaultLink: string
  /** → resolver capability advert (/.well-known/gs1resolver). */
  wellKnownRef?: string
}

/** PolicyRef — tier, cacheability, existence-neutrality, offer bindings (lens-A §2). Inherited class → lot → instance. */
export interface PolicyRef {
  id: string
  tier: number
  cacheable: boolean
  existenceNeutral: boolean
  offerBindings?: string[]
}

/**
 * ResolvedManifest — the JOINED view the resolve seam returns. Records are
 * stored separately (independent lifecycles) and joined at read.
 */
export interface ResolvedManifest {
  key: string
  grain: Grain
  canonicalId: string
  owner: OwnerRef
  linkset: Linkset
  defaultLink: string
  policy: PolicyRef
  provenance: IdentifierRecord['provenance']
  etag: string
  updatedAt: string
}

/**
 * The typed answer of a lookup. A miss is TYPED, never a fabricated record:
 *   - no-record       : the store is live but holds no record for this key
 *                       (existence-neutral — the resolver serves the self-doc).
 *   - not-provisioned : no live binding is wired (the emptyRegistryPort default).
 */
export type RegistryLookup =
  | { found: true; manifest: ResolvedManifest }
  | { found: false; reason: 'no-record' | 'not-provisioned'; detail: string }

/**
 * The registry PORT. The resolve path needs only `lookup`. In production this is
 * backed by the R2/parquet store (deferred); in tests it is `MemoryRegistryPort`.
 */
export interface RegistryPort {
  lookup(key: string, grain: Grain): Promise<RegistryLookup>
}

/**
 * The honest default (mirrors `unconnectedSourcePort`): no live binding wired,
 * so every lookup answers a TYPED `not-provisioned`. The resolver falls back to
 * the current existence-neutral self-derived document. NEVER fabricates a record.
 */
export function emptyRegistryPort(detail = 'registry binding not provisioned'): RegistryPort {
  return {
    async lookup(key: string): Promise<RegistryLookup> {
      return { found: false, reason: 'not-provisioned', detail: `${detail} (key: ${key})` }
    },
  }
}
