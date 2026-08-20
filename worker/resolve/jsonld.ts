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
 * STAGE-1 NARROWING (deferred + ticketed, ADR 0001 D1):
 *   - No registry dereference to a typed-sqid `{type}_{sqid}` `$id`. Stage 1
 *     emits a self/derived canonical `$id` (the resolver URL itself) and points
 *     `sameAs` at the canonical DL / VIN URI. The registry-backed `$id` is a
 *     later stage.
 */

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

/** Build the JSON-LD identity document for a VIN (Vehicle, class-of-one grain). */
export function buildVinDoc(vin: string, who?: WhoBlock): IdentityDoc {
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
  return doc
}

/**
 * Build the JSON-LD identity document for a GTIN.
 *   - bare GTIN → Product at class grain.
 *   - GTIN + serial → Product class node with an instance `hasVariant` node.
 */
export function buildGtinDoc(gtin: string, serial: string | undefined, who?: WhoBlock): IdentityDoc {
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
  return doc
}
