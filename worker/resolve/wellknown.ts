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
import { DLVP_BIZSTEPS } from '../dlvp/bizsteps'

/**
 * The gs1:* linkTypes surfaced by this resolver (ratified GS1 relations). They appear
 * INSIDE the RFC 9264 linkset and as the 303 defaultLink target; per-linkType ?linkType
 * dispatch for gs1:* (beyond linkset/all + the id:* set) is tracked by id.org.ai-ch5.
 */
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
  /**
   * The Phase-5 DLVP symmetric-consent handshake surface, advertised in-band
   * (SYNTHESIS C6 — machine-discoverable). Draft superset; the provisional
   * bizSteps are NOT ratified GS1 CBV (standards.org.ai vocab ticketed).
   */
  dlvp: {
    profile: 'DLVP/1'
    sessionEndpoint: string
    settleEndpoint: string
    receiptEndpoint: string
    provisionalBizSteps: readonly string[]
    draftSuperset: true
  }
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
    dlvp: {
      profile: 'DLVP/1',
      sessionEndpoint: `${resolverRoot}/dlvp/session`,
      settleEndpoint: `${resolverRoot}/dlvp/settle`,
      receiptEndpoint: `${resolverRoot}/dlvp/receipt/{grai}`,
      provisionalBizSteps: DLVP_BIZSTEPS,
      draftSuperset: true,
    },
    generatedAt: new Date().toISOString(),
  }
}
