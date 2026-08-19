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
 * │   — needs a binding; v1 ships synchronous atomic /dlvp/settle. id.org.ai-2s1.│
 * │ • A real issuer trust list — production trust map is empty (session-        │
 * │   injected in tests). id.org.ai-e9a. • Atomic disclosure↔VALUE settlement +  │
 * │   the C5 rungs: id.org.ai-67g. • Robust identifier→(key,grain) parsing       │
 * │   reuses parseDlPath/parseDlKey later; v1 uses a lightweight split.          │
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
import { mintReceipt, buildReceipt, persistReceipt } from '../dlvp/receipt'
import { DlvpStore, dlvpStore } from '../dlvp/store'
import {
  buildConsentEvent,
  buildDisclosureEvent,
  buildRevokeEvent,
  buildSettlementEvent,
  stampDlvp,
} from '../dlvp/events'
import type { DlvpSessionRequest, DlvpSettleRequest, DlvpSettleOfferRequest, DlvpError } from '../dlvp/protocol'
import { BIZSTEP_CLEARING } from '../dlvp/bizsteps'
import {
  validateOffer,
  offerAccepts,
  V1_MAX_SETTLE_TIER,
  type DualLegOffer,
  type OfferLeg,
  type PossessionTier,
} from '../dlvp/offer'
import {
  noopSettlementPort,
  type SettlementPort,
  type SettlementLeg,
  type SettlementIntent,
} from '../dlvp/settlement'
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
  /**
   * Phase-6: the value-settlement port. Production default is the FAIL-CLOSED
   * noopSettlementPort (no rail wired → every settle-offer answers not-provisioned).
   * Tests inject mockSettlementPort. NO live money, NO keys (money-safety hard rule).
   */
  settlement?: SettlementPort
}

function dlvpError(
  c: DlvpContext,
  code: DlvpError['error']['code'],
  message: string,
  hint: string,
  status: 400 | 402 | 403 | 404 | 409 = 400,
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
  const settlement: SettlementPort = deps.settlement ?? noopSettlementPort()
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
    // An OFFER-bearing session is a PAID handshake — it MUST clear atomically with
    // value via /dlvp/settle-offer. Redeeming it here (the free path, no value leg)
    // would hand the discloser's claims over without payment and burn the nonce so
    // the paid path can never run. The OFFER lives inside the signed session, so it
    // cannot be stripped. Refuse. (Closes the disclosure-without-value bypass.)
    if ((sess as Record<string, unknown>).offer) {
      return dlvpError(c, 'OFFER_REQUIRES_SETTLE_OFFER', 'this session carries an OFFER and must be settled atomically with value', 'POST the co-presentation to /dlvp/settle-offer instead', 400)
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

    // (b2) REPLAY GUARD: a co-presentation nonce is single-use. Burn it BEFORE minting
    // so a captured settle body cannot be replayed within the ~120s session TTL.
    // (v1 in-memory/per-isolate; the durable cross-isolate guard is id.org.ai-56v.)
    if (store.isNonceSpent(r)) {
      return dlvpError(c, 'NONCE_REPLAY', 'this resolution nonce has already been settled', 'start a fresh /dlvp/session — each co-presentation is single-use', 409)
    }
    store.spendNonce(r)

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

    // (f) mint the revocation CAPABILITY — returned once, to the settling parties only.
    // Revoke requires it, so a bystander who learns the public GRAI cannot revoke.
    const revocationToken = mintNonce()
    store.setRevocationToken(receipt.grai, revocationToken)

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
          revocationToken,
        },
        epcis: [consumerDisclosure, brandDisclosure, receiptConsent],
      },
      200,
    )
  })

  // ── POST /dlvp/settle-offer — the Phase-6 ATOMIC disclosure↔VALUE co-settle ──
  // Additive to /dlvp/settle; the P5 path is byte-for-byte unchanged. The OFFER
  // rides the SIGNED session (sess.offer), so minConfidence + amounts are tamper-
  // proof. Ordering makes value-without-disclosure, disclosure-without-value,
  // settlement-fails-after-disclosure, partial, and minConfidence-too-low all
  // impossible: value only prepares after BOTH presentations verify + the C5 gate
  // passes; the disclosed claims are WITHHELD until the value commit succeeds.
  app.post('/dlvp/settle-offer', async (c) => {
    const body = (await c.req.json().catch(() => null)) as DlvpSettleOfferRequest | null
    if (!body || !body.session || !body.consumerPresentation || !body.brandPresentation) {
      return dlvpError(
        c,
        'BAD_REQUEST',
        'body must be { session, consumerPresentation, brandPresentation, valueProof? }',
        'settle a co-presentation OFFER returned from /dlvp/session',
      )
    }
    const signer = signerFor(c)

    // (a) verify the signed session request-object (our own key, unexpired).
    const sess = await signer.verify(body.session)
    if (!sess) {
      const decoded = decodeJWT(body.session)
      const now = Math.floor(Date.now() / 1000)
      if (decoded && typeof decoded.payload.exp === 'number' && decoded.payload.exp < now) {
        return dlvpError(c, 'SESSION_EXPIRED', 'the co-presentation-request has expired', 're-open /dlvp/session')
      }
      return dlvpError(c, 'SESSION_INVALID', 'the session request-object did not verify', 're-open /dlvp/session')
    }

    // (b) the OFFER travels in the SIGNED session — tamper-proof terms. Missing →
    // this is a consent-only session; the caller must use /dlvp/settle instead.
    const offer = sess.offer as DualLegOffer | undefined
    if (!offer || typeof offer !== 'object') {
      return dlvpError(c, 'OFFER_MISSING', 'this session carries no OFFER', 'open /dlvp/session with an offer, or use /dlvp/settle')
    }

    const r = String(sess.nonce)
    const epcisEventId = String(sess.epcisEventId)
    const identifier = String(sess.sub)
    const { key, grain } = keyGrain(identifier)

    // (c) verify BOTH presentations over the SAME r — value never even prepares
    // until disclosure verifies. [kills value-without-disclosure]
    const consumer = await verifySdJwtPresentation(body.consumerPresentation, { trust, expectedNonce: r, expectedAud: origin })
    if (!consumer.ok) {
      return dlvpError(c, presentationCode(consumer.code), consumer.reason, 're-present a valid SD-JWT-VC bound to r', 400, 'consumer')
    }
    const brand = await verifySdJwtPresentation(body.brandPresentation, { trust, expectedNonce: r, expectedAud: origin })
    if (!brand.ok) {
      return dlvpError(c, presentationCode(brand.code), brand.reason, 're-present a valid SD-JWT-VC bound to r', 400, 'brand')
    }

    // (d) the four-place nonce binding (r ⊆ e; two presentations = one event).
    if (
      !consumer.kb ||
      !brand.kb ||
      !nonceBindingHolds({ sessionNonce: r, eventNonce: r, consumerKbNonce: consumer.kb.nonce, brandKbNonce: brand.kb.nonce })
    ) {
      return dlvpError(c, 'NONCE_MISMATCH', 'the four-place nonce binding does not hold', 'each KB-JWT nonce must equal r', 400)
    }

    // (e) validate the OFFER shape + fence + expiry (tamper-proof, from the session).
    const valid = validateOffer(offer)
    if (!valid.ok) {
      const code = valid.code === 'EXPIRED' ? 'OFFER_EXPIRED' : 'OFFER_INVALID'
      return dlvpError(c, code, valid.reason, 'advertise a well-formed, in-date OFFER within the present-value fence', 400)
    }

    // (f) REPLAY + VALUE LOCK: atomic check-and-set. Guards both a P5-spent nonce
    // and a concurrent in-flight settle-offer on the same nonce. Released on any
    // settlement failure below; promoted to spent only on full success.
    if (!store.tryLockNonce(r)) {
      return dlvpError(c, 'NONCE_REPLAY', 'this resolution nonce has already been settled or is in-flight', 'start a fresh /dlvp/session — each co-presentation is single-use', 409)
    }

    try {
      // (g) counter-verify the consumer possession rung (C3/C5 input).
      const cv = await counterVerify({ presentation: consumer, identifier: key, grain, registry })
      const reachedRung = cv.rung as PossessionTier

      // (h) THE C5 GATE — the value only clears when the proven rung meets the
      // OFFER's minConfidence AND the rung is settleable in v1 (fail-closed above
      // rung 3). [kills minConfidence-too-low; kills settlement above proven confidence]
      if (offer.minConfidence > V1_MAX_SETTLE_TIER || !offerAccepts(offer, reachedRung)) {
        store.releaseNonce(r)
        const hint =
          offer.minConfidence > V1_MAX_SETTLE_TIER
            ? `this OFFER demands rung ${offer.minConfidence}; v1 settlement caps at rung ${V1_MAX_SETTLE_TIER} (id.org.ai-67g)`
            : `the proven possession rung ${reachedRung} is below the OFFER minConfidence ${offer.minConfidence}`
        return dlvpError(c, 'CONFIDENCE_TOO_LOW', 'the proven possession confidence does not meet the OFFER minConfidence', hint, 402)
      }

      // (h2) REGISTRY-BACKED CONFIDENCE ONLY — rung 3 is "registry / purchase binding".
      // counterVerify grants rung 3 to a holder-attested VC (scope present) even when
      // the registry is empty/absent (verdict 'holder-attested'), which in production
      // is EVERY presentation. Value must NOT move on a rung that was not actually
      // counter-verified against the registry of record. Fail-closed: any settleable
      // (rung ≥ 3) tier requires the counter-verified verdict.
      if (reachedRung >= 3 && cv.verdict !== 'holder-presented-vc-counterverified') {
        store.releaseNonce(r)
        return dlvpError(c, 'CONFIDENCE_NOT_COUNTERVERIFIED', 'settlement requires registry-counter-verified possession, not holder-attestation', `the possession claim is ${cv.verdict}; a registry counter-match is required to clear value at rung ${reachedRung}`, 402)
      }

      // (i) build the dual-leg settlement intent from the OFFER (amounts) + the
      // verified disclosure (attribute digests — never raw PII).
      const brandLeg = await toSettlementLeg(legFor(offer, 'brand'), consumer, brand)
      const consumerLeg = await toSettlementLeg(legFor(offer, 'consumer'), consumer, brand)
      const intent: SettlementIntent = {
        nonce: r,
        epcisEventId,
        offerId: offer.offerId,
        brandLeg,
        consumerLeg,
        reachedRung,
        ...(body.valueProof ? { valueProof: body.valueProof } : {}),
      }

      // (j) PREPARE the value hold. Rejected → nothing recorded, claims withheld,
      // nonce released. [kills disclosure-without-value: no claims revealed]
      const prepared = await settlement.prepare(intent)
      if (!('handle' in prepared)) {
        store.releaseNonce(r)
        return dlvpError(c, 'SETTLEMENT_FAILED', `value settlement could not be prepared: ${prepared.reason}`, prepared.detail, 402)
      }

      // (k) BUILD (sign) the receipt — the fallible local step — BEFORE capture, so
      // a signing failure voids the hold with nothing recorded.
      const brandController = String((brand.claims as Record<string, unknown>).controller ?? brand.iss)
      let receipt
      try {
        receipt = await buildReceipt({
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
          bizStep: BIZSTEP_CLEARING,
        })
      } catch (e) {
        await settlement.void(prepared)
        store.releaseNonce(r)
        return dlvpError(c, 'SETTLEMENT_FAILED', 'the receipt could not be minted; the value hold was voided', String(e), 402)
      }

      // (l) COMMIT the value capture — the point of no return on the rail. Rejected
      // → the receipt is NEVER persisted, claims withheld, hold voided, nonce
      // released. [kills settlement-fails-after-disclosure → nothing recorded]
      const settled = await settlement.commit(prepared)
      if (!('ok' in settled) || settled.ok !== true) {
        await settlement.void(prepared)
        store.releaseStatus(receipt.grai)
        store.releaseNonce(r)
        const reason = 'ok' in settled ? (settled as { reason: string }).reason : 'unknown'
        return dlvpError(c, 'SETTLEMENT_FAILED', `value capture failed: ${reason}`, 'the disclosure was NOT revealed and NOTHING was recorded', 402)
      }

      // (m) COMMIT the disclosure side (non-fallible, in-memory). Both legs cleared
      // → persist the receipt, burn the nonce, record the value in the receipt,
      // stamp the paired EPCIS events, mint the revocation capability.
      // NOTE: the receipt VC (receipt.vcJwt) was SIGNED at step (k), before the value
      // was captured, so this valueExchanged block is NOT covered by that signature —
      // it is ADVISORY. The AUTHORITATIVE record of the value transfer is the signed
      // settlement EPCIS event below (buildSettlementEvent: txRef + legDigests +
      // achievedConfidence). A signed-after-commit attestation is deferred (id.org.ai-kzj).
      receipt.dlvp.valueExchanged = {
        attestation: 'advisory',
        authoritativeRecord: 'epcis-settlement-event',
        txRef: settled.txRef,
        achievedConfidence: reachedRung,
        legs: settled.legs.map((l) => ({ valueType: l.valueType, from: l.from, to: l.to, ...(l.amountMicros !== undefined ? { amountMicros: l.amountMicros } : {}) })),
      }
      persistReceipt(store, receipt)
      store.spendNonce(r) // promote lock → spent (single-use, permanent)

      const consumerDisclosure = buildDisclosureEvent({ identifier, principal: consumer.cnfThumbprint, nonce: r, epcisEventId, side: 'consumer', presentationDigest: consumer.presentationDigest })
      const brandDisclosure = buildDisclosureEvent({ identifier, principal: brandController, nonce: r, epcisEventId, side: 'brand', presentationDigest: brand.presentationDigest })
      const settlementEvent = buildSettlementEvent({
        receiptDigitalLink: receipt.digitalLink,
        principal: consumer.cnfThumbprint,
        nonce: r,
        epcisEventId,
        txRef: settled.txRef,
        legDigests: [digestLabel(brandLeg), digestLabel(consumerLeg)],
        achievedConfidence: reachedRung,
      })
      stampDlvp(consumerDisclosure, sink)
      stampDlvp(brandDisclosure, sink)
      stampDlvp(settlementEvent, sink)

      const revocationToken = mintNonce()
      store.setRevocationToken(receipt.grai, revocationToken)

      // (n) REVEAL — only now are the disclosed claims returned to each party.
      return c.json(
        {
          verdict: cv.verdict,
          counterVerify: { owner: cv.owner, registryStrength: cv.registryStrength, rung: cv.rung, note: cv.note },
          disclosedToConsumer: brand.claims,
          disclosedToBrand: consumer.claims,
          settlement: {
            cleared: true,
            txRef: settled.txRef,
            offerId: offer.offerId,
            achievedConfidence: reachedRung,
            minConfidence: offer.minConfidence,
            legs: settled.legs,
          },
          receipt: {
            grai: receipt.grai,
            digitalLink: receipt.digitalLink,
            vcJwt: receipt.vcJwt,
            statusListRef: receipt.status,
            revocationToken,
          },
          epcis: [consumerDisclosure, brandDisclosure, settlementEvent],
        },
        200,
      )
    } catch (e) {
      // Any unexpected throw: fail-closed, release the lock, record nothing.
      store.releaseNonce(r)
      return dlvpError(c, 'SETTLEMENT_FAILED', 'settlement aborted', String(e), 402)
    }
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
  app.post('/dlvp/receipt/:grai/revoke', async (c) => {
    const grai = c.req.param('grai')
    const receipt = store.get(grai)
    if (!receipt) {
      return dlvpError(c, 'RECEIPT_NOT_FOUND', `no consent receipt for GRAI ${grai}`, 'mint one via /dlvp/settle', 404)
    }
    // AUTHORIZE: only a holder of the revocation capability (minted to the parties at
    // settle) may revoke — a public GRAI alone must not let a bystander grief the grant.
    const token = c.req.header('x-revocation-token') ?? (await c.req.json().catch(() => ({})))?.revocationToken
    if (!store.checkRevocationToken(grai, token)) {
      return dlvpError(c, 'REVOKE_UNAUTHORIZED', 'a valid revocationToken is required to revoke this receipt', 'present the revocationToken returned at /dlvp/settle', 403)
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

/** The OFFER leg for one party (validateOffer has already guaranteed one each). */
function legFor(offer: DualLegOffer, party: 'consumer' | 'brand'): OfferLeg {
  const leg = offer.legs.find((l) => l.party === party)
  if (!leg) throw new Error(`offer missing ${party} leg`)
  return leg
}

/** base64url SHA-256 over a string (for non-PII attribute digests). */
async function sha256b64u(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input))
  const bytes = new Uint8Array(buf)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Map an OFFER leg → a SettlementLeg. `from` is the giving party; `to` the
 * counterparty. A verified-attribute leg carries a DIGEST of the disclosed
 * predicate values (never raw PII) drawn from the giver's actual presentation.
 */
async function toSettlementLeg(
  leg: OfferLeg,
  consumer: { claims: Record<string, unknown> },
  brand: { claims: Record<string, unknown> },
): Promise<SettlementLeg> {
  const from = leg.party
  const to: 'consumer' | 'brand' = from === 'consumer' ? 'brand' : 'consumer'
  const give = leg.give
  if (give.valueType === 'micro-payment') {
    return { valueType: 'micro-payment', from, to, amountMicros: give.amountMicros, asset: give.asset ?? 'USD' }
  }
  if (give.valueType === 'credential-grant') {
    return { valueType: 'credential-grant', from, to, vct: give.vct }
  }
  // verified-attribute: digest the giver's disclosed values for the named claims.
  const source = from === 'consumer' ? consumer.claims : brand.claims
  const material = give.attributes.map((p) => `${p.claim}=${JSON.stringify(source[p.claim] ?? null)}`).join('|')
  const attributeDigest = await sha256b64u(material)
  return { valueType: 'verified-attribute', from, to, attributeDigest }
}

/** A short, non-PII label for a leg (for the settlement EPCIS event's legDigests). */
function digestLabel(leg: SettlementLeg): string {
  if (leg.valueType === 'micro-payment') return `micro-payment:${leg.amountMicros}${leg.asset ?? 'USD'}`
  if (leg.valueType === 'credential-grant') return `credential-grant:${leg.vct ?? ''}`
  return `verified-attribute:${leg.attributeDigest ?? ''}`
}

/** Production mount used by worker/index.ts. Empty registry + empty trust (RAILS). */
export const dlvpRoutes = createDlvpApp()

// Re-export the settle-side helper for the id:consent linkset block (Phase-5 wiring).
export { keyGrain as dlvpKeyGrain }
