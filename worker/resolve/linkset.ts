/**
 * linkset.ts — RFC 9264 linkset builder + the extended id:* linkType taxonomy
 * (SYNTHESIS / lens-A §1,§3).
 *
 * `?linkType=linkset` or `Accept: application/linkset+json` returns a 200 RFC
 * 9264 document with NO redirect (the GS1-conformant contract). The document is
 * `{ "linkset": [ { "anchor": <canonical>, "<relURI>": [ { href, title, type,
 * hreflang } ] } ] }`. Relations are full URIs — GS1 vocabulary for `gs1:*`,
 * our OWN namespace for the `id:*` superset.
 *
 * The `id:*` entries (id:offer / id:consent / id:event / id:owner) are each
 * themselves a resolvable, typed address (`?linkType=id:offer` …) — a linkset
 * whose targets are themselves typed faces. In THIS increment they resolve to a
 * typed STUB envelope (shape only, `status:'placeholder'`) with a ticket to the
 * phase that fills them in. They are OUR OPENLY-DRAFT SUPERSET — no GS1
 * ratification is claimed.
 *
 * DEFERRED + TICKETED (bd model-gap):
 *   - Live linkset records come from the FIXTURE registry, not a live R2/parquet
 *     store (RAILS: no live binding this increment).
 *   - Real id:offer settlement (Phase-6), id:consent crypto (Phase-5), and the
 *     authenticated id:event EPCIS capture seam (id.org.ai-w9d) fill the stubs.
 *   - Language (Accept-Language) negotiation among per-hreflang links.
 */

import type { ResolvedManifest, LinkEntry } from '../registry/port'
import { buildBrandPaysConsumerOffer, type DualLegOffer, type PossessionTier } from '../dlvp/offer'

/** GS1 link-relation vocabulary base (the ratified gs1:* relations). */
export const GS1_VOC = 'https://ref.gs1.org/voc/'
/** OUR draft-superset link-relation vocabulary base (the id:* relations). */
export const ID_VOC = 'https://id.org.ai/voc/'

/** The four extended id:* relations this increment addresses as typed stubs. */
export const ID_LINKTYPES = Object.freeze(['id:offer', 'id:consent', 'id:event', 'id:owner'])

/** Expand a compact linkType (`gs1:pip`, `id:offer`) to its full relation URI. */
export function relationUri(linkType: string): string {
  if (linkType.startsWith('gs1:')) return GS1_VOC + linkType.slice(4)
  if (linkType.startsWith('id:')) return ID_VOC + linkType.slice(3)
  return linkType // already a full URI, or an unrecognised compact form
}

/** One RFC 9264 target object. */
interface LinksetTarget {
  href: string
  title?: string
  type?: string
  hreflang?: string
}

export interface LinksetDocument {
  linkset: Array<Record<string, string | LinksetTarget[]>>
}

/**
 * Build the RFC 9264 linkset for one anchor. The self/identity entry and the
 * four id:* typed entries are ALWAYS present (existence-neutral — an
 * unprovisioned key still advertises its addressable faces); any registry
 * `manifest.linkset.links` are merged in on top.
 */
export function buildLinkset(anchor: string, manifest?: ResolvedManifest): LinksetDocument {
  const entry: Record<string, string | LinksetTarget[]> = { anchor }

  // The self / identity face (JSON-LD identity document at the anchor).
  entry[relationUri('id:identity')] = [
    { href: anchor, title: 'identity document', type: 'application/ld+json' },
  ]

  // The four extended id:* faces — each a resolvable typed address.
  for (const lt of ID_LINKTYPES) {
    entry[relationUri(lt)] = [
      { href: `${anchor}?linkType=${lt}`, title: `${lt} face (draft superset)`, type: 'application/json' },
    ]
  }

  // Merge registry-provided links (gs1:* defaultLink target, PIP, etc.).
  if (manifest) {
    for (const link of manifest.linkset.links) {
      addLink(entry, link)
    }
    // Surface the defaultLink relation explicitly when it names a gs1 relation.
    if (manifest.defaultLink && manifest.defaultLink.startsWith('gs1:')) {
      const rel = relationUri(manifest.defaultLink)
      if (!entry[rel]) entry[rel] = [{ href: anchor, title: 'default link (303 target)' }]
    }
  }

  return { linkset: [entry] }
}

function addLink(entry: Record<string, string | LinksetTarget[]>, link: LinkEntry): void {
  const rel = relationUri(link.linkType)
  const target: LinksetTarget = { href: link.href }
  if (link.title) target.title = link.title
  if (link.type) target.type = link.type
  if (link.hreflang) target.hreflang = link.hreflang
  const existing = entry[rel]
  if (Array.isArray(existing)) existing.push(target)
  else entry[rel] = [target]
}

// ── The extended id:* typed stub envelopes ──────────────────────────────────

/**
 * A typed STUB envelope for one id:* linkType — SHAPE ONLY. Resolving
 * `?linkType=id:offer` (etc.) returns one of these (200 JSON), NOT the identity
 * doc. `status:'placeholder'` and the `ticket` make the deferral honest and
 * addressable. These are OUR draft superset; no GS1 ratification is claimed.
 */
export interface LinkTypeStub {
  $context: string
  $type: string
  linkType: string
  anchor: string
  status: 'placeholder'
  draftSuperset: true
  $comment: string
  ticket: string
  [extra: string]: unknown
}

/** The draft digital bizStep verb (reused from capture.ts; provisional, non-ratified). */
const BIZSTEP_RESOLVING = 'https://gs1.org.ai/cbv/BizStep-resolving'
/** The provisional DLVP consent bizStep (from dlvp/bizsteps.ts; non-ratified GS1). */
const BIZSTEP_CONSENTING = 'https://gs1.org.ai/cbv/BizStep-consenting'
/** The live Phase-5 DLVP co-presentation endpoint. */
const DLVP_SESSION_ENDPOINT = 'https://id.org.ai/dlvp/session'

const STUBS: Record<string, (anchor: string) => LinkTypeStub> = {
  'id:offer': (anchor) => ({
    $context: ID_VOC,
    $type: 'Offer',
    linkType: 'id:offer',
    anchor,
    // The ENVELOPE stays a draft-superset placeholder (no GS1 ratification, value
    // settlement is v1-mock), but it now carries a LIVE typed dual-leg OFFER book
    // (see `offers` below, attached in buildLinkTypeStub). Phase-6.
    status: 'placeholder',
    draftSuperset: true,
    direction: 'mutual',
    $comment:
      'The bidirectional dual-leg OFFER face. Phase-6: `offers` is a live typed ' +
      'DualLegOffer book (brand-pays-consumer by default); the value rail is a ' +
      'money-safe mock/no-op port until id.org.ai-67g wires the live rail.',
    ticket: 'id.org.ai-dfh',
    settleEndpoint: 'https://id.org.ai/dlvp/settle-offer',
  }),
  'id:consent': (anchor) => ({
    $context: ID_VOC,
    $type: 'ConsentRequest',
    linkType: 'id:consent',
    anchor,
    // status stays 'placeholder': the DLVP endpoint is LIVE (Phase-5), but the
    // record-backed requirements (per-OFFER minConfidence read from a live
    // policy) are still draft-superset — no GS1 ratification claimed.
    status: 'placeholder',
    draftSuperset: true,
    $comment:
      'The disclosure handshake face. Phase-5 DLVP endpoint is LIVE; the ' +
      'consentRequirements block below is our draft superset (SD-JWT-VC co-presentation).',
    ticket: 'id.org.ai-dfh',
  }),
  'id:event': (anchor) => ({
    $context: ID_VOC,
    $type: 'EpcisEventSeam',
    linkType: 'id:event',
    anchor,
    status: 'placeholder',
    draftSuperset: true,
    'why.bizStep': BIZSTEP_RESOLVING,
    $comment: 'The EPCIS 2.0 capture seam. Authenticated capture + G5 gating is id.org.ai-w9d.',
    ticket: 'id.org.ai-w9d',
  }),
  'id:owner': (anchor) => ({
    $context: ID_VOC,
    $type: 'OwnershipClaim',
    linkType: 'id:owner',
    anchor,
    status: 'placeholder',
    draftSuperset: true,
    $comment: 'The ownership-proof record face. The proof ladder is a later Phase-4 increment.',
    ticket: 'id.org.ai-dfh',
  }),
}

/** True iff `linkType` is one of the addressable id:* stubs. */
export function isIdLinkType(linkType: string): boolean {
  return linkType in STUBS
}

/**
 * Build the typed stub envelope for one id:* linkType. When a registry manifest
 * resolves and it is id:owner, the stub carries the proven owner id (shape still
 * a placeholder for the full proof-record face).
 */
export function buildLinkTypeStub(linkType: string, anchor: string, manifest?: ResolvedManifest): LinkTypeStub {
  const stub = STUBS[linkType](anchor)
  if (linkType === 'id:owner' && manifest) {
    stub.owner = manifest.owner.ownerId
    stub.proof = {
      method: manifest.owner.claim.method,
      strength: manifest.owner.claim.strength,
      provedAt: manifest.owner.claim.provedAt,
    }
  }
  if (linkType === 'id:consent') {
    stub.consentRequirements = buildConsentRequirements(anchor, manifest)
  }
  if (linkType === 'id:offer') {
    stub.offers = buildOfferFace(anchor, manifest)
  }
  return stub
}

/**
 * The live (draft-superset) dual-leg OFFER book advertised on the id:offer face
 * (Phase-6). Reads `manifest.policy.offerBindings` — each becomes the verified-
 * attribute the consumer discloses in exchange for a brand-paid coupon (value
 * flows TO the discloser; default minConfidence 1 = coupon tier). Existence-
 * neutral default when no record resolves: a single `owns`-for-coupon OFFER.
 *
 * Settlement is atomic disclosure↔value via POST /dlvp/settle-offer and clears on
 * a money-safe MOCK/no-op port in v1 (no live rail, no keys — id.org.ai-67g).
 */
export function buildOfferFace(anchor: string, manifest?: ResolvedManifest): DualLegOffer[] {
  const bindings = manifest?.policy.offerBindings ?? []
  const attributes = (bindings.length > 0 ? bindings : ['owns']).map((b) => ({ claim: b, op: 'present' as const }))
  const minConfidence: PossessionTier = 1
  return [
    buildBrandPaysConsumerOffer({
      anchor,
      consumerGives: { valueType: 'verified-attribute', attributes },
      brandGives: { valueType: 'micro-payment', amountMicros: 100_000, asset: 'USD' }, // $0.10 coupon (mock)
      minConfidence,
      // Deterministic id + expiry aligned with the face's 1h cache (illustrative
      // advert; real policy-driven offers with per-OFFER expiry are id.org.ai-67g).
      offerId: `offer_advert_${anchor}`,
      expiry: new Date(Date.now() + 3600_000).toISOString(),
    }),
  ]
}

/**
 * The real (draft-superset) ConsentRequirements block wired into the id:consent
 * face (Phase-5). Names the LIVE DLVP endpoint, the provisional consent bizStep,
 * the consumer_ask / brand_offer predicates (read from the record's policy
 * offerBindings when provisioned), and the per-OFFER minConfidence (SYNTHESIS C5
 * — the possession-confidence the value at stake demands). Existence-neutral
 * defaults when no record resolves. Still OUR draft superset — no GS1 ratified.
 */
export function buildConsentRequirements(anchor: string, manifest?: ResolvedManifest) {
  const bindings = manifest?.policy.offerBindings ?? []
  // offerBindings are opaque predicate keys in v1; each becomes a presence ask.
  const consumerAsk = bindings.length > 0 ? bindings.map((b) => ({ claim: b, op: 'present' as const })) : [{ claim: 'owns', op: 'present' as const }]
  return {
    protocol: 'DLVP/1',
    description: 'symmetric SD-JWT-VC co-presentation (one nonce, two presentations, one EPCIS event)',
    endpoint: DLVP_SESSION_ENDPOINT,
    method: 'POST',
    anchor,
    bizStep: BIZSTEP_CONSENTING,
    draftSuperset: true,
    consumerAsk,
    brandOffer: [
      { claim: 'genuine', op: 'present' as const },
      { claim: 'warranty_active', op: 'present' as const },
    ],
    // C5: the possession-confidence tier the value at stake demands (v1 advertises;
    // it does not settle value — Phase-6). 1 = coupon-tier default.
    minConfidence: 1,
  }
}
