/**
 * The src.do-contract source port — the ONE seam between the registry
 * adapters and the outside world (beads id-vy7, id-sp0 scope correction).
 *
 * id.org.ai builds one consumer interface, not N integrations: roster
 * ingest, scraping, session walks, and cache/staleness plumbing are src.do's
 * scope. An adapter declares WHICH resource it needs and HOW to read the
 * answer; the port does the I/O. In production the port is backed by the
 * src.do source proxy; in tests it is an in-memory fake. A port with no
 * backing source answers with a TYPED unavailability — never a fabricated
 * payload — which `verify()` surfaces as `unverifiable-by-registry` with a
 * `connect-source` cure.
 */

export interface SourceRequest {
  /** Source id — matches the adapter id (e.g. 'mn-dvs-dealer'). */
  readonly source: string
  /** Resource within the source (e.g. 'dealership-lookup', 'roster-stats'). */
  readonly resource: string
  readonly params: Readonly<Record<string, string>>
  /**
   * Act-class checks demand 'bypass-cache' (ADR 0018 R5); read/record may
   * accept 'allow-cache' within the effect-class TTL.
   */
  readonly freshness: 'bypass-cache' | 'allow-cache'
}

export type SourceResult =
  | {
      readonly ok: true
      readonly data: unknown
      /** When the answer speaks as of (ISO). Mandatory — adapters must refuse without it. */
      readonly asOf: string
      readonly fromCache: boolean
      readonly provenance?: string
    }
  | {
      readonly ok: false
      readonly unavailable: 'not-connected' | 'unreachable' | 'not-ingested'
      readonly detail: string
    }

export interface SourcePort {
  fetch(req: SourceRequest): Promise<SourceResult>
}

/**
 * The honest default: no source is connected. Every lookup answers with a
 * typed `not-connected` so the adapter surfaces `unverifiable-by-registry`
 * plus the connect-source cure — never a fake pass.
 */
export function unconnectedSourcePort(detail = 'src.do source proxy is not bound'): SourcePort {
  return {
    async fetch(req: SourceRequest): Promise<SourceResult> {
      return { ok: false, unavailable: 'not-connected', detail: `${detail} (source: ${req.source})` }
    },
  }
}
