/**
 * capture.ts — the conservative resolve-time capture stamp (ADR 0001 D3/D4).
 *
 * A GET on the resolver is a READ. It NEVER writes a membrane G5 event and
 * NEVER requires a credential. What this module provides is only the *shape* of
 * the resolve capture stamp plus a no-op sink: the event is fully formed but
 * goes nowhere until an EPCIS-2.0-shaped sink is wired in a later stage.
 *
 * `why.bizStep` is our draft/provisional DIGITAL bizStep verb — OUR superset
 * extension, openly marked provisional, projecting down to ref.gs1.org/cbv
 * where a physical analog exists. It is NOT ratified GS1 vocabulary. The verb
 * rows are authored in a sibling repo; this constant only references the URI.
 *
 * DEFERRED + TICKETED (bd model-gap): the real capture path — authenticated
 * POST capture, EPCIS 2.0 capture/query seam, Who-staged EPCIS event, and
 * membrane G5 gating (ADR 0001 D3/D4/D5).
 */

/**
 * The draft digital bizStep verb for a resolve. Provisional superset extension,
 * NOT ratified GS1 CBV. Authored in a sibling vocab repo; referenced here.
 */
export const BIZSTEP_RESOLVING = 'https://gs1.org.ai/cbv/BizStep-resolving'

/** EPCIS-2.0-shaped-ish action for a read/observe. */
export type CaptureAction = 'OBSERVE'

export interface CaptureStamp {
  /** EPCIS event type (an observation of the resolved identity). */
  type: 'ObjectEvent'
  action: CaptureAction
  /** The resolved identity's canonical URI (VIN or DL). */
  epcList: string[]
  /** ISO-8601 event time (stamp construction time). */
  eventTime: string
  /** The draft digital bizStep verb — provisional, non-ratified. */
  'why.bizStep': typeof BIZSTEP_RESOLVING
  /** Who, when a credential resolved; 'anon' for L0. Existence-neutral. */
  'who.principal': string
  /** Marks this as a non-persisted, read-time stamp — never a G5 write. */
  provisional: true
}

/**
 * Build the resolve capture stamp. Pure — constructs the shape only.
 * `canonical` is the resolved identity's canonical URI; `principal` is the Who
 * (a `human_*`/`agent_*` id, or `'anon'` for L0).
 */
export function buildCaptureStamp(canonical: string, principal: string): CaptureStamp {
  return {
    type: 'ObjectEvent',
    action: 'OBSERVE',
    epcList: [canonical],
    eventTime: new Date().toISOString(),
    'why.bizStep': BIZSTEP_RESOLVING,
    'who.principal': principal,
    provisional: true,
  }
}

/** A sink swallows (or, later, persists) a capture stamp. */
export interface CaptureSink {
  emit(stamp: CaptureStamp): void | Promise<void>
}

/**
 * The default sink is a NO-OP: with no EPCIS/G5 sink wired, the stamp is built
 * and dropped. This keeps the read path a pure read (contract: GET never writes
 * G5) while proving the stamp shape end-to-end. A real sink is a later stage.
 */
export const noopCaptureSink: CaptureSink = {
  emit() {
    /* intentional no-op — no sink wired in stage 1 (deferred + ticketed) */
  },
}

/**
 * Stamp a resolve. Builds the shape and hands it to `sink` (default no-op).
 * Returns the stamp so callers/tests can assert its shape. Never throws.
 */
export function stampResolve(
  canonical: string,
  principal: string,
  sink: CaptureSink = noopCaptureSink,
): CaptureStamp {
  const stamp = buildCaptureStamp(canonical, principal)
  try {
    void sink.emit(stamp)
  } catch {
    /* a sink failure must never break a read */
  }
  return stamp
}
