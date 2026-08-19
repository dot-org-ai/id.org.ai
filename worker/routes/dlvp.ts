/**
 * routes/dlvp.ts — the DLVP v1 HTTP surface (Phase-5; SYNTHESIS §3 Phase-5).
 *
 * Additive to the merged Phase-4 resolver + the shipped credential/auth layer;
 * mounted keyless-first-value (the /dlvp/* prefix matches no authenticated
 * prefix). Copies createResolveApp's deps-injected Hono-app factory VERBATIM so
 * tests inject a seeded MemoryRegistryPort + a session signer + an issuer trust
 * map, while production defaults to emptyRegistryPort + the DO-backed issuer key
 * (getSigningKeyManager) + an EMPTY trust map (honest: with no real issuer trust
 * list wired, settle fail-closes on every presentation — never a fabricated pass).
 *
 * Surface (lens-B five-move flow, bounded to v1):
 *   POST /dlvp/session               — open a co-presentation, mint r, sign the
 *                                      stateless request-object (moves 1–2).
 *   POST /dlvp/settle                — the synchronous ATOMIC co-settle: verify
 *                                      BOTH presentations over r, counter-verify
 *                                      the consumer against the registry, mint the
 *                                      ISO 27560 receipt, stamp EPCIS (moves 3–5).
 *   GET  /dlvp/receipt/:grai         — fetch the receipt VC + live status.
 *   POST /dlvp/receipt/:grai/revoke  — flip the status-list bit + stamp revoking.
 *
 * ┌─ DEFERRED + TICKETED (bd model-gap) ──────────────────────────────────────┐
 * │ • The async single-sided /dlvp/present with server-held half-session state │
 * │   — needs a binding; v1 ships the synchronous atomic /dlvp/settle instead.  │
 * │ • A real issuer trust list — production trust map is empty (session-        │
 * │   injected in tests). • Robust identifier→(key,grain) parsing reuses        │
 * │   parseDlPath/parseDlKey later; v1 uses a lightweight split.                │
 * └────────────────────────────────────────────────────────────────────────────┘
 */

import { Hono } from 'hono'
import type { Context } from 'hono'
import type { Env, Variables } from '../types'
import type { Grain, RegistryPort } from '../registry/port'
import { emptyRegistryPort } from '../registry/port'
import { getSigningKeyManager } from '../middleware/tenant'
import type { CaptureSink } from '../resolve/capture'
import { noopCaptureSink } from '../resolve/capture'
import {
  mintNonce,
  mintEventId,
  buildCoPresentationRequest,
  nonceBindingHolds,
  signerFromKeyManager,
  RESOLVER_ORIGIN,
  SESSION_TTL_SECONDS,
  type DlvpSigner,
} from '../dlvp/nonce'
import { verifySdJwtPresentation, type IssuerTrustMap } from '../dlvp/sd-jwt'
import { counterVerify } from '../dlvp/counter-verify'
import { mintReceipt } from '../dlvp/receipt'
import { DlvpStore, dlvpStore } from '../dlvp/store'
import { buildConsentEvent, buildDisclosureEvent, buildRevokeEvent, stampDlvp } from '../dlvp/events'
import type { DlvpSessionRequest, DlvpSettleRequest, DlvpError } from '../dlvp/protocol'
import { decodeJWT } from '../../src/sdk/oauth/jwt-verify'

type DlvpContext = Context<{ Bindings: Env; Variables: Variables }>

export interface DlvpDeps {
  registry?: RegistryPort
  /** Injected in tests; production builds one per-request from getSigningKeyManager(env). */
  signer?: DlvpSigner
  /** The session-injected issuer JWKS trust map (empty in production — deferred). */
  trust?: IssuerTrustMap
  store?: DlvpStore
  sink?: CaptureSink
  resolverOrigin?: string
}

function dlvpError(
  c: DlvpContext,
  code: DlvpError['error']['code'],
  message: string,
  hint: string,
  status: 400 | 404 = 400,
  side?: 'consumer' | 'brand',
) {
  const body: DlvpError = { error: { code, message, hint, ...(side ? { side } : {}) } }
  return c.json(body, status)
}

/** Lightweight identifier → (key, grain) mapping (robust parser deferred + ticketed). */
function keyGrain(identifier: string): { key: string; grain: Grain } {
  if (identifier.startsWith('vin/')) return { key: identifier, grain: 'instance' }
  const segs = identifier.split('/')
  if (segs[0] === '01') return { key: identifier, grain: segs.length >= 4 ? 'instance' : 'class' }
  if (segs[0] === '8003') return { key: identifier, grain: segs.length > 2 ? 'instance' : 'document' }
  if (segs[0] === '00') return { key: identifier, grain: 'instance' }
  if (segs[0] === '414') return { key: identifier, grain: 'place' }
  if (segs[0] === '8004') return { key: identifier, grain: 'asset' }
  if (segs[0] === '253') return { key: identifier, grain: 'document' }
  return { key: identifier, grain: 'class' }
}

export function createDlvpApp(deps: DlvpDeps = {}) {
  const registry = deps.registry ?? emptyRegistryPort()
  const store = deps.store ?? dlvpStore
  const sink = deps.sink ?? noopCaptureSink
  const trust: IssuerTrustMap = deps.trust ?? {}
  const origin = deps.resolverOrigin ?? RESOLVER_ORIGIN
  const app = new Hono<{ Bindings: Env; Variables: Variables }>()

  const signerFor = (c: DlvpContext): DlvpSigner =>
    deps.signer ?? signerFromKeyManager(getSigningKeyManager(c.env), origin)

  // ── POST /dlvp/session — moves 1–2 (open + sign the stateless request-object) ─
  app.post('/dlvp/session', async (c) => {
    const body = (await c.req.json().catch(() => null)) as DlvpSessionRequest | null
    if (!body || typeof body.identifier !== 'string' || !Array.isArray(body.consumerAsk)) {
      return dlvpError(
        c,
        'BAD_REQUEST',
        'body must be { identifier: string, consumerAsk: Predicate[], brandOffer?: Predicate[] }',
        'open a co-presentation over one identifier',
      )
    }
    const signer = signerFor(c)
    const nonce = mintNonce()
    const epcisEventId = mintEventId()
    const claims = buildCoPresentationRequest(
      body,
      nonce,
      epcisEventId,
      { consumer: 'dlvp:consumer', brand: 'dlvp:brand' },
      origin,
    )
    const session = await signer.sign(claims as unknown as Record<string, unknown>, {
      expiresIn: SESSION_TTL_SECONDS,
    })
    // move 1: the provisional consent event (r ⊆ e), no-op sink.
    const consentEvent = buildConsentEvent({
      identifier: body.identifier,
      principal: 'anon',
      nonce,
      epcisEventId,
    })
    stampDlvp(consentEvent, sink)
    return c.json(
      {
        session,
        nonce,
        epcisEventId,
        resolverAud: origin,
        consumerAsk: claims.consumerAsk,
        brandAsk: claims.brandAsk,
        expiresInSeconds: SESSION_TTL_SECONDS,
        epcis: [consentEvent],
      },
      200,
    )
  })

  // ── POST /dlvp/settle — moves 3–5 (the ATOMIC co-settle) ─────────────────────
  app.post('/dlvp/settle', async (c) => {
    const body = (await c.req.json().catch(() => null)) as DlvpSettleRequest | null
    if (!body || !body.session || !body.consumerPresentation || !body.brandPresentation) {
      return dlvpError(
        c,
        'BAD_REQUEST',
        'body must be { session, consumerPresentation, brandPresentation }',
        'settle a co-presentation returned from /dlvp/session',
      )
    }
    const signer = signerFor(c)

    // (a) verify the session request-object against our own key, unexpired.
    const sess = await signer.verify(body.session)
    if (!sess) {
      const decoded = decodeJWT(body.session)
      const now = Math.floor(Date.now() / 1000)
      if (decoded && typeof decoded.payload.exp === 'number' && decoded.payload.exp < now) {
        return dlvpError(c, 'SESSION_EXPIRED', 'the co-presentation-request has expired', 're-open /dlvp/session')
      }
      return dlvpError(c, 'SESSION_INVALID', 'the session request-object did not verify', 're-open /dlvp/session')
    }
    const r = String(sess.nonce)
    const epcisEventId = String(sess.epcisEventId)
    const identifier = String(sess.sub)
    const { key, grain } = keyGrain(identifier)

    // (b) verify BOTH presentations over the SAME r (the symmetry).
    const consumer = await verifySdJwtPresentation(body.consumerPresentation, {
      trust,
      expectedNonce: r,
      expectedAud: origin,
    })
    if (!consumer.ok) {
      return dlvpError(c, presentationCode(consumer.code), consumer.reason, 're-present a valid SD-JWT-VC bound to r', 400, 'consumer')
    }
    const brand = await verifySdJwtPresentation(body.brandPresentation, {
      trust,
      expectedNonce: r,
      expectedAud: origin,
    })
    if (!brand.ok) {
      return dlvpError(c, presentationCode(brand.code), brand.reason, 're-present a valid SD-JWT-VC bound to r', 400, 'brand')
    }

    // The four-place nonce binding — this is what makes two presentations ONE event.
    if (
      !consumer.kb ||
      !brand.kb ||
      !nonceBindingHolds({
        sessionNonce: r,
        eventNonce: r,
        consumerKbNonce: consumer.kb.nonce,
        brandKbNonce: brand.kb.nonce,
      })
    ) {
      return dlvpError(c, 'NONCE_MISMATCH', 'the four-place nonce binding does not hold', 'each KB-JWT nonce must equal r', 400)
    }

    // (c) COUNTER-VERIFY the consumer VC against the registry of record (C3).
    const cv = await counterVerify({ presentation: consumer, identifier: key, grain, registry })

    // (d) ATOMIC: everything above verified — only now do we mint + record.
    const brandController = String((brand.claims as Record<string, unknown>).controller ?? brand.iss)
    const receipt = await mintReceipt({
      signer,
      store,
      brandController,
      consumerCnfJwk: consumer.cnfJwk,
      consumerPseudonym: consumer.cnfThumbprint,
      consumerAsk: (sess.consumerAsk as never[]) ?? [],
      brandAsk: (sess.brandAsk as never[]) ?? [],
      nonce: r,
      epcisEventId,
      consumerPresentationDigest: consumer.presentationDigest,
      brandPresentationDigest: brand.presentationDigest,
      resolverOrigin: origin,
    })

    // (e) stamp the disclosure events (both sides) + the receipt consent event.
    const consumerDisclosure = buildDisclosureEvent({
      identifier,
      principal: consumer.cnfThumbprint,
      nonce: r,
      epcisEventId,
      side: 'consumer',
      presentationDigest: consumer.presentationDigest,
    })
    const brandDisclosure = buildDisclosureEvent({
      identifier,
      principal: brandController,
      nonce: r,
      epcisEventId,
      side: 'brand',
      presentationDigest: brand.presentationDigest,
    })
    const receiptConsent = buildConsentEvent({
      identifier: receipt.digitalLink,
      principal: consumer.cnfThumbprint,
      nonce: r,
      epcisEventId,
      receiptDigest: receipt.grai,
    })
    stampDlvp(consumerDisclosure, sink)
    stampDlvp(brandDisclosure, sink)
    stampDlvp(receiptConsent, sink)

    return c.json(
      {
        verdict: cv.verdict,
        counterVerify: { owner: cv.owner, registryStrength: cv.registryStrength, rung: cv.rung, note: cv.note },
        disclosedToConsumer: brand.claims,
        disclosedToBrand: consumer.claims,
        receipt: {
          grai: receipt.grai,
          digitalLink: receipt.digitalLink,
          vcJwt: receipt.vcJwt,
          statusListRef: receipt.status,
        },
        epcis: [consumerDisclosure, brandDisclosure, receiptConsent],
      },
      200,
    )
  })

  // ── GET /dlvp/receipt/:grai — fetch the receipt VC + live status ─────────────
  app.get('/dlvp/receipt/:grai', (c) => {
    const grai = c.req.param('grai')
    const receipt = store.get(grai)
    if (!receipt) {
      return dlvpError(c, 'RECEIPT_NOT_FOUND', `no consent receipt for GRAI ${grai}`, 'mint one via /dlvp/settle', 404)
    }
    return c.json(
      {
        grai: receipt.grai,
        digitalLink: receipt.digitalLink,
        vcJwt: receipt.vcJwt,
        iso27560: receipt.iso27560,
        dlvp: receipt.dlvp,
        status: receipt.status,
        statusState: store.statusOf(grai),
      },
      200,
    )
  })

  // ── POST /dlvp/receipt/:grai/revoke — flip the status bit + stamp revoking ───
  app.post('/dlvp/receipt/:grai/revoke', (c) => {
    const grai = c.req.param('grai')
    const receipt = store.get(grai)
    if (!receipt) {
      return dlvpError(c, 'RECEIPT_NOT_FOUND', `no consent receipt for GRAI ${grai}`, 'mint one via /dlvp/settle', 404)
    }
    store.revoke(grai)
    const revokeEvent = buildRevokeEvent({
      receiptDigitalLink: receipt.digitalLink,
      principal: receipt.iso27560.piiPrincipalId,
      nonce: receipt.dlvp.nonce,
      epcisEventId: receipt.dlvp.epcisEventId,
    })
    stampDlvp(revokeEvent, sink)
    return c.json(
      {
        revoked: true,
        grai,
        statusListRef: { ...receipt.status, status: 'revoked' as const },
        statusState: store.statusOf(grai),
        epcis: [revokeEvent],
      },
      200,
    )
  })

  return app
}

/** Map an sd-jwt failure code to the DLVP error code. */
function presentationCode(code: string): DlvpError['error']['code'] {
  switch (code) {
    case 'NONCE_MISMATCH':
      return 'NONCE_MISMATCH'
    case 'AUD_MISMATCH':
      return 'AUD_MISMATCH'
    case 'SD_HASH_MISMATCH':
      return 'SD_HASH_MISMATCH'
    default:
      return 'PRESENTATION_INVALID'
  }
}

/** Production mount used by worker/index.ts. Empty registry + empty trust (RAILS). */
export const dlvpRoutes = createDlvpApp()

// Re-export the settle-side helper for the id:consent linkset block (Phase-5 wiring).
export { keyGrain as dlvpKeyGrain }
