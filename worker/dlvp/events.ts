/**
 * dlvp/events.ts — the DLVP EPCIS events with PROVISIONAL digital bizSteps
 * (SYNTHESIS C2, lens-B §3). Builds ON worker/resolve/capture.ts: it reuses the
 * `CaptureSink` / `noopCaptureSink` no-op-sink discipline VERBATIM and mirrors
 * the `stampResolve` shape — a fully-formed EPCIS-2.0-ish event that goes
 * NOWHERE until a real capture/G5 sink is wired (id.org.ai-w9d).
 *
 * The bizStep verbs are the provisional, NON-ratified DLVP constants from
 * bizsteps.ts. `dlvp.nonce` carries `r` INTO the event — the `r ⊆ e` property
 * (SYNTHESIS: the single-event binding that makes two presentations one event).
 *
 * DEFERRED + TICKETED (bd model-gap): the authenticated EPCIS 2.0 capture/query
 * sink + membrane G5 gating (id.org.ai-w9d) — v1 events flow to noopCaptureSink,
 * exactly like the resolve stamp. Never a G5 write.
 */

import { noopCaptureSink, type CaptureSink } from '../resolve/capture'
import { BIZSTEP_CONSENTING, BIZSTEP_DISCLOSING, BIZSTEP_REVOKING } from './bizsteps'

/** A DLVP EPCIS-shaped event (provisional; never persisted in v1). */
export interface DlvpEvent {
  type: 'ObjectEvent' | 'TransactionEvent'
  action: 'OBSERVE' | 'ADD'
  /** The identity / receipt canonical URI(s). */
  epcList: string[]
  eventTime: string
  /** The provisional digital bizStep verb (non-ratified GS1). */
  'why.bizStep': string
  /** Who — a principal id or a scoped pseudonym; 'anon' for L0. */
  'who.principal': string
  /** The DLVP binding — r ⊆ e (the single-event property). */
  dlvp: { nonce: string; epcisEventId: string; receiptDigest?: string; side?: 'consumer' | 'brand' }
  /** Marks this as a non-persisted, provisional stamp — never a G5 write. */
  provisional: true
}

/** move 1: the provisional consent event stamped at session open (bizStep consenting). */
export function buildConsentEvent(params: {
  identifier: string
  principal: string
  nonce: string
  epcisEventId: string
  receiptDigest?: string
}): DlvpEvent {
  return {
    type: 'ObjectEvent',
    action: 'OBSERVE',
    epcList: [params.identifier],
    eventTime: new Date().toISOString(),
    'why.bizStep': BIZSTEP_CONSENTING,
    'who.principal': params.principal,
    dlvp: { nonce: params.nonce, epcisEventId: params.epcisEventId, receiptDigest: params.receiptDigest },
    provisional: true,
  }
}

/** move 3–4: one disclosure event per side (bizStep disclosing). */
export function buildDisclosureEvent(params: {
  identifier: string
  principal: string
  nonce: string
  epcisEventId: string
  side: 'consumer' | 'brand'
  presentationDigest: string
}): DlvpEvent {
  return {
    type: 'ObjectEvent',
    action: 'OBSERVE',
    epcList: [params.identifier],
    eventTime: new Date().toISOString(),
    'why.bizStep': BIZSTEP_DISCLOSING,
    'who.principal': params.principal,
    dlvp: {
      nonce: params.nonce,
      epcisEventId: params.epcisEventId,
      side: params.side,
      receiptDigest: params.presentationDigest,
    },
    provisional: true,
  }
}

/** revocation: the status-list flip event (bizStep revoking). */
export function buildRevokeEvent(params: {
  receiptDigitalLink: string
  principal: string
  nonce: string
  epcisEventId: string
}): DlvpEvent {
  return {
    type: 'ObjectEvent',
    action: 'OBSERVE',
    epcList: [params.receiptDigitalLink],
    eventTime: new Date().toISOString(),
    'why.bizStep': BIZSTEP_REVOKING,
    'who.principal': params.principal,
    dlvp: { nonce: params.nonce, epcisEventId: params.epcisEventId },
    provisional: true,
  }
}

/** Stamp a DLVP event to a sink (default no-op). Never throws — a sink failure never breaks settle. */
export function stampDlvp(event: DlvpEvent, sink: CaptureSink = noopCaptureSink): DlvpEvent {
  try {
    // CaptureSink.emit is typed for the resolve stamp; the DLVP event is a
    // superset shape — cast at the seam only. A real EPCIS sink accepts both.
    void sink.emit(event as unknown as Parameters<CaptureSink['emit']>[0])
  } catch {
    /* provisional stamp: a sink failure must never break settle */
  }
  return event
}
