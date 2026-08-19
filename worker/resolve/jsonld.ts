/**
 * jsonld.ts — the keyless-first-value JSON-LD identity-document builder for
 * the resolver door (ADR 0001 D1/D2).
 *
 * Anonymous, cacheable, existence-neutral: emits an identity document keyed by
 * the identifier the caller resolved, with the canonical GS1 Digital Link URI
 * carried as `sameAs`. No credential is required and none is written.
 *
 * $context is `https://schema.org.ai` (the estate JSON-LD vocabulary). $type:
 *   - Vehicle          for a VIN
 *   - Product          for a bare GTIN (class grain)
 *   - a Product with an `hasVariant`/instance node for GTIN + serial (instance grain)
 *
 * PHASE-4 (registry-backed, additive): when the resolver reads a
 * `ResolvedManifest` through the registry PORT, the builders switch the `$id`
 * from the self/derived URL to the manifest's `{type}_{sqid}` canonicalId, add
 * an `owner` assertion (id + proof method/strength), and advertise the
 * `gs1:linkset` face. When NO manifest is present (the emptyRegistryPort default,
 * or a registry miss), the builders emit the SAME existence-neutral self-derived
 * document as before — so the shipped resolve.test.ts is behaviour-preserved.
 *
 * STAGE-1 NARROWING (still true when the registry is unprovisioned, ADR 0001 D1):
 *   - Absent a manifest, no registry dereference: the doc carries a self/derived
 *     canonical `$id` (the resolver URL) and points `sameAs` at the canonical
 *     DL / VIN URI, with an existence-neutral `$comment`.
 */

import type { ResolvedManifest, Grain } from '../registry/port'

/** The canonical resolver origin — the self/derived `$id` base for stage 1. */
export const RESOLVER_ORIGIN = 'https://id.org.ai'

/** The estate JSON-LD vocabulary IRI. */
export const SCHEMA_CONTEXT = 'https://schema.org.ai'

export interface IdentityDoc {
  $context: string
  $type: string
  $id: string
  identifier: Array<{ $type: 'PropertyValue'; propertyID: string; value: string }>
  sameAs: string[]
  /** Provisional, existence-neutral note — stage 1 asserts identity form, not a registry record. */
  $comment: string
  /** Present only when a credential resolved (see Who wiring). Existence-neutral otherwise. */
  who?: WhoBlock
  /** Present only when a registry manifest resolved: the proven owner assertion. */
  owner?: OwnerBlock
  /** Present only when a registry manifest resolved: the RFC 9264 linkset face address. */
  'gs1:linkset'?: string
  /** Instance node for GTIN + serial (instance grain). */
  hasVariant?: {
    $type: 'Product'
    serialNumber: string
    identifier: Array<{ $type: 'PropertyValue'; propertyID: string; value: string }>
    sameAs: string[]
  }
}

export interface WhoBlock {
  $type: 'Person' | 'SoftwareAgent' | 'Organization'
  identifier: string
  level: number
}

/** The registry-backed owner assertion attached when a manifest resolves. */
export interface OwnerBlock {
  $type: 'Organization' | 'Person' | 'SoftwareAgent'
  identifier: string
  proof: { method: string; strength: string; provedAt: string }
}

/** Map an owner id + claim to the doc's owner block. */
function ownerBlock(manifest: ResolvedManifest): OwnerBlock {
  const id = manifest.owner.ownerId
  const $type: OwnerBlock['$type'] = id.startsWith('human_')
    ? 'Person'
    : id.startsWith('agent_')
      ? 'SoftwareAgent'
      : 'Organization'
  return {
    $type,
    identifier: id,
    proof: {
      method: manifest.owner.claim.method,
      strength: manifest.owner.claim.strength,
      provedAt: manifest.owner.claim.provedAt,
    },
  }
}

/**
 * Apply a resolved manifest to a self-derived doc IN PLACE: swap `$id` to the
 * registry canonicalId, attach the owner assertion + linkset face, and replace
 * the existence-neutral $comment with a registry-backed one. No-op when absent.
 */
function applyManifest(doc: IdentityDoc, canonical: string, manifest?: ResolvedManifest): void {
  if (!manifest) return
  doc.$id = manifest.canonicalId
  doc.owner = ownerBlock(manifest)
  doc['gs1:linkset'] = `${canonical}?linkType=linkset`
  doc.$comment =
    'Phase-4 registry-backed identity document. The $id dereferences the ' +
    'registry canonical record; `owner` is the proven claimant; `gs1:linkset` ' +
    'addresses the RFC 9264 linkset face.'
}

const CANONICAL_DL_DOMAIN = 'https://id.org.ai'

/** Canonical VIN URI form the resolver publishes as its self address. */
export function vinCanonicalUri(vin: string): string {
  return `${CANONICAL_DL_DOMAIN}/vin/${vin.toUpperCase()}`
}

/** Canonical GS1 Digital Link URI: /01/{gtin14}[/21/{serial}]. */
export function dlCanonicalUri(gtin: string, serial?: string): string {
  const base = `${CANONICAL_DL_DOMAIN}/01/${gtin}`
  return serial ? `${base}/21/${serial}` : base
}

/**
 * Build the JSON-LD identity document for a VIN (Vehicle, class-of-one grain).
 * When a registry `manifest` is present, the doc is registry-backed (see
 * `applyManifest`); absent, it is the existence-neutral self-derived form.
 */
export function buildVinDoc(vin: string, who?: WhoBlock, manifest?: ResolvedManifest): IdentityDoc {
  const v = vin.toUpperCase()
  const canonical = vinCanonicalUri(v)
  const doc: IdentityDoc = {
    $context: SCHEMA_CONTEXT,
    $type: 'Vehicle',
    $id: canonical,
    identifier: [{ $type: 'PropertyValue', propertyID: 'vin', value: v }],
    sameAs: [canonical],
    $comment:
      'Stage-1 resolver identity form (ADR 0001). Existence-neutral: this document ' +
      'asserts the well-formed VIN identity, not a registry record. No registry $id yet.',
  }
  if (who) doc.who = who
  applyManifest(doc, canonical, manifest)
  return doc
}

/**
 * Build the JSON-LD identity document for a GTIN.
 *   - bare GTIN → Product at class grain.
 *   - GTIN + serial → Product class node with an instance `hasVariant` node.
 * When a registry `manifest` is present the doc is registry-backed.
 */
export function buildGtinDoc(
  gtin: string,
  serial: string | undefined,
  who?: WhoBlock,
  manifest?: ResolvedManifest,
): IdentityDoc {
  const classCanonical = dlCanonicalUri(gtin)
  const doc: IdentityDoc = {
    $context: SCHEMA_CONTEXT,
    $type: 'Product',
    $id: classCanonical,
    identifier: [{ $type: 'PropertyValue', propertyID: 'gtin', value: gtin }],
    sameAs: [classCanonical],
    $comment:
      'Stage-1 resolver identity form (ADR 0001). Existence-neutral: this document ' +
      'asserts the well-formed GTIN identity, not a registry record. No registry $id yet.',
  }
  if (serial) {
    const instanceCanonical = dlCanonicalUri(gtin, serial)
    doc.hasVariant = {
      $type: 'Product',
      serialNumber: serial,
      identifier: [
        { $type: 'PropertyValue', propertyID: 'gtin', value: gtin },
        { $type: 'PropertyValue', propertyID: 'serialNumber', value: serial },
      ],
      sameAs: [instanceCanonical],
    }
  }
  if (who) doc.who = who
  applyManifest(doc, serial ? dlCanonicalUri(gtin, serial) : classCanonical, manifest)
  return doc
}

// ── Phase-4 generalised grain-typed keys (SSCC/GLN/GIAI/GRAI/GDTI) ──────────

/** Canonical DL URI for a generalised key: /{ai}/{value}. */
export function keyCanonicalUri(keyAi: string, primaryValue: string): string {
  return `${CANONICAL_DL_DOMAIN}/${keyAi}/${primaryValue}`
}

/** The schema.org.ai $type each grain maps to (the resolver's grain→type table). */
const GRAIN_TYPE: Record<Grain, string> = {
  class: 'Product',
  lot: 'Product',
  instance: 'Product',
  place: 'Place',
  asset: 'Product',
  document: 'CreativeWork',
}

/** The propertyID (the identifier's short name) each supported key advertises. */
const KEY_PROPERTY_ID: Record<string, string> = {
  '00': 'sscc',
  '414': 'gln',
  '8004': 'giai',
  '8003': 'grai',
  '253': 'gdti',
}

/**
 * Build the JSON-LD identity document for a Phase-4 generalised key. Grain-typed
 * via GRAIN_TYPE; keyless-first-value existence-neutral by default, registry
 * backed when a manifest resolves. `serial` (GRAI/GDTI instance) rides as an
 * extra PropertyValue on the identifier list.
 */
export function buildKeyDoc(
  keyAi: string,
  primaryValue: string,
  grain: Grain,
  serial: string | undefined,
  who?: WhoBlock,
  manifest?: ResolvedManifest,
): IdentityDoc {
  const canonical = keyCanonicalUri(keyAi, primaryValue)
  const propertyID = KEY_PROPERTY_ID[keyAi] ?? keyAi
  const identifier = [{ $type: 'PropertyValue' as const, propertyID, value: primaryValue }]
  if (serial) identifier.push({ $type: 'PropertyValue' as const, propertyID: 'serialNumber', value: serial })
  const doc: IdentityDoc = {
    $context: SCHEMA_CONTEXT,
    $type: GRAIN_TYPE[grain],
    $id: canonical,
    identifier,
    sameAs: [canonical],
    $comment:
      'Stage-1 resolver identity form (ADR 0001). Existence-neutral: this document ' +
      `asserts the well-formed ${propertyID.toUpperCase()} identity, not a registry record. No registry $id yet.`,
  }
  if (who) doc.who = who
  applyManifest(doc, canonical, manifest)
  return doc
}
