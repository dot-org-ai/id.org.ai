/**
 * wellknown.ts — the /.well-known/gs1resolver description document
 * (GS1-Conformant Resolver Standard §well-known; SYNTHESIS / lens-A §1).
 *
 * Advertises this resolver's surface: supported primary keys, supported
 * linkTypes (gs1:* plus our id:* superset), and the compression flag. Marked
 * honestly as OUR implementation's advertised surface; the id:* rows are flagged
 * as our OPENLY-DRAFT superset (no GS1 ratification is claimed).
 *
 * DEFERRED + TICKETED (bd model-gap): compressed DL support (flag stays false),
 * the remaining primary keys, and the GS1-Conformant Resolver Standard official
 * test-vector conformance suite (id.org.ai-ig1).
 */

import { SUPPORTED_PRIMARY_KEYS } from './identifiers'
import { ID_LINKTYPES } from './linkset'

/** The gs1:* linkTypes this resolver recognises today (ratified GS1 relations). */
const SUPPORTED_GS1_LINKTYPES = Object.freeze([
  'gs1:pip',
  'gs1:defaultLink',
  'gs1:instructions',
  'gs1:recallStatus',
  'gs1:traceability',
])

export interface Gs1ResolverDescription {
  name: string
  resolverRoot: string
  supportedPrimaryKeys: readonly string[]
  supportedLinkType: readonly string[]
  /** OUR draft-superset linkTypes, called out separately (no GS1 ratification claimed). */
  draftSupersetLinkType: readonly string[]
  supportsCompression: false
  generatedAt: string
}

/** Build the resolver description document. */
export function buildResolverDescription(resolverRoot = 'https://id.org.ai'): Gs1ResolverDescription {
  return {
    name: 'id.org.ai GS1 Digital Link resolver',
    resolverRoot,
    supportedPrimaryKeys: SUPPORTED_PRIMARY_KEYS,
    supportedLinkType: [...SUPPORTED_GS1_LINKTYPES, ...ID_LINKTYPES],
    draftSupersetLinkType: ID_LINKTYPES,
    supportsCompression: false,
    generatedAt: new Date().toISOString(),
  }
}
