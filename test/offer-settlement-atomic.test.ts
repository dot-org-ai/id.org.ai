/**
 * POST /dlvp/settle-offer — the Phase-6 ATOMIC disclosure<->value co-settle.
 *
 * The correctness core: disclosure (P5) and value settlement clear TOGETHER or
 * NEITHER. This suite drives the fatal failure modes and asserts, every time,
 * store.size() (receipts) and the settlement-port call log:
 *   - value-without-disclosure           (bad presentation -> value never prepares)
 *   - disclosure-without-value           (prepare/commit reject -> claims withheld)
 *   - settlement-fails-after-disclosure  (commit reject -> nothing recorded, hold voided)
 *   - minConfidence-too-low              (C5 gate -> reject before any value moves)
 *   - replay                             (nonce single-use across settle + settle-offer)
 * No live money, no keys: the mock/no-op settlement port stands in (money-safe).
 */
import { describe, it, expect, beforeAll } from 'vitest'
import { createDlvpApp } from '../worker/routes/dlvp'
import { createSessionSigner, type DlvpSigner } from '../worker/dlvp/nonce'
import { DlvpStore } from '../worker/dlvp/store'
import { mockSettlementPort, noopSettlementPort } from '../worker/dlvp/settlement'
import { buildBrandPaysConsumerOffer, type DualLegOffer, type PossessionTier } from '../worker/dlvp/offer'
import { MemoryRegistryPort } from '../worker/registry/memory'
import type { IdentifierRecord, OwnerRef, Linkset, PolicyRef } from '../worker/registry/port'
import { genKey, buildPresentation, type FixtureKey } from './helpers/dlvp-issue'
import type { JWK } from '../src/sdk/oauth/jwt-verify'

const ORIGIN = 'https://id.org.ai'
const GTIN = '09506000134352'
const INSTANCE_KEY = `01/${GTIN}/21/SER1`
const CONSUMER_ISS = 'https://issuer.example/loyalty'
const BRAND_ISS = 'https://issuer.example/brand'

function seededRegistry() {
  const policy: PolicyRef = { id: 'pol', tier: 0, cacheable: true, existenceNeutral: true, offerBindings: ['owns'] }
  const owner: OwnerRef = {
    ownerId: 'human_alice',
    claim: {
      method: 'vc', subject: 'human_alice',
      scope: { kind: 'instance', key: INSTANCE_KEY },
      proofDigest: 'sha256:x', provedAt: '2026-08-19T00:00:00.000Z', strength: 'attested',
    },
    scope: { kind: 'instance', key: INSTANCE_KEY },
  }
  const linkset: Linkset = { id: 'ls', defaultLink: 'gs1:pip', links: [] }
  const record: IdentifierRecord = {
    key: INSTANCE_KEY, grain: 'instance', canonicalId: 'inst_1',
    ownerRef: 'human_alice', linksetRef: 'ls', defaultLink: 'gs1:pip', policyRef: 'pol',
    provenance: { proofId: 'p', provedAt: '2026-08-19T00:00:00.000Z', method: 'vc' },
    etag: 'W/"1"', updatedAt: '2026-08-19T00:00:00.000Z',
  }
  return new MemoryRegistryPort({ identifier: [record], owner: [owner], linkset: [linkset], policy: [policy] })
}

let consumerIssuerKey: FixtureKey
let consumerHolderKey: FixtureKey
let brandIssuerKey: FixtureKey
let brandHolderKey: FixtureKey
let trust: Record<string, JWK>
let signer: DlvpSigner

beforeAll(async () => {
  consumerIssuerKey = await genKey('ES256')
  consumerHolderKey = await genKey('ES256')
  brandIssuerKey = await genKey('EdDSA')
  brandHolderKey = await genKey('EdDSA')
  trust = { [CONSUMER_ISS]: consumerIssuerKey.publicJwk, [BRAND_ISS]: brandIssuerKey.publicJwk }
  signer = await createSessionSigner()
})

/** An OFFER: consumer discloses `owns`, brand pays a $0.10 coupon; minConfidence gated. */
function offerFor(minConfidence: PossessionTier): DualLegOffer {
  return buildBrandPaysConsumerOffer({
    anchor: INSTANCE_KEY,
    consumerGives: { valueType: 'verified-attribute', attributes: [{ claim: 'owns', op: 'present' }] },
    brandGives: { valueType: 'micro-payment', amountMicros: 100_000, asset: 'USD' },
    minConfidence,
    offerId: 'offer_test_1',
  })
}

interface AppOpts { store?: DlvpStore; settlement?: ReturnType<typeof mockSettlementPort> | ReturnType<typeof noopSettlementPort> }

/** Open a session over INSTANCE_KEY, optionally carrying an OFFER in the signed request. */
async function openSession(offer: DualLegOffer | undefined, opts: AppOpts = {}) {
  const store = opts.store ?? new DlvpStore()
  const app = createDlvpApp({ registry: seededRegistry(), signer, trust, store, settlement: opts.settlement })
  const res = await app.request(`${ORIGIN}/dlvp/session`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ identifier: INSTANCE_KEY, consumerAsk: [{ claim: 'genuine' }], brandOffer: [{ claim: 'owns' }], ...(offer ? { offer } : {}) }),
  })
  expect(res.status).toBe(200)
  const body = (await res.json()) as { session: string; nonce: string }
  return { app, store, session: body.session, nonce: body.nonce }
}

async function bothPresentations(nonce: string, opts: { brandNonce?: string } = {}) {
  const consumer = await buildPresentation({
    issuerKey: consumerIssuerKey, holderKey: consumerHolderKey, iss: CONSUMER_ISS,
    vct: 'https://id.org.ai/vct/ownership',
    sdClaims: { owner_subject: 'human_alice', owns: INSTANCE_KEY, tier: 2 },
    nonce, aud: ORIGIN,
  })
  const brand = await buildPresentation({
    issuerKey: brandIssuerKey, holderKey: brandHolderKey, iss: BRAND_ISS,
    vct: 'https://id.org.ai/vct/provenance',
    sdClaims: { genuine: true, warranty_active: true },
    plainClaims: { controller: 'org_acme' },
    nonce: opts.brandNonce ?? nonce, aud: ORIGIN,
  })
  return { consumer: consumer.presentation, brand: brand.presentation }
}

function settleOffer(app: ReturnType<typeof createDlvpApp>, session: string, p: { consumer: string; brand: string }, valueProof?: Record<string, unknown>) {
  return app.request(`${ORIGIN}/dlvp/settle-offer`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ session, consumerPresentation: p.consumer, brandPresentation: p.brand, ...(valueProof ? { valueProof } : {}) }),
  })
}

describe('happy path: disclosure and value clear together', () => {
  it('rung 3 meets minConfidence 3 -> receipt minted, both legs cleared, paired event stamped', async () => {
    const port = mockSettlementPort()
    const { app, store, session, nonce } = await openSession(offerFor(3), { settlement: port })
    const p = await bothPresentations(nonce)
    const res = await settleOffer(app, session, p)
    expect(res.status).toBe(200)
    const body = (await res.json()) as {
      verdict: string
      disclosedToConsumer: Record<string, unknown>
      disclosedToBrand: Record<string, unknown>
      settlement: { cleared: boolean; txRef: string; achievedConfidence: number; minConfidence: number; legs: unknown[] }
      receipt: { grai: string; vcJwt: string }
      epcis: unknown[]
    }
    expect(body.verdict).toBe('holder-presented-vc-counterverified')
    // Disclosure revealed ONLY on the success path.
    expect(body.disclosedToConsumer.genuine).toBe(true)
    expect(body.disclosedToBrand.owns).toBe(INSTANCE_KEY)
    // Value cleared: both legs, a mock txRef, the confidence recorded.
    expect(body.settlement.cleared).toBe(true)
    expect(body.settlement.txRef).toContain('mocktx_')
    expect(body.settlement.achievedConfidence).toBe(3)
    expect(body.settlement.minConfidence).toBe(3)
    expect(body.settlement.legs).toHaveLength(2)
    // Receipt persisted; the paired settlement event is among the 3 EPCIS events.
    expect(store.size()).toBe(1)
    expect(body.epcis).toHaveLength(3)
    // The port saw exactly one prepare + one commit, no void.
    expect(port.committedCount).toBe(1)
    expect(port.calls.map((c) => c.phase)).toEqual(['prepare', 'commit'])
  })

  it('records a non-PII valueExchanged summary on the receipt (no amounts leaked as PII, type recorded)', async () => {
    const port = mockSettlementPort()
    const { app, store, session, nonce } = await openSession(offerFor(3), { settlement: port })
    const p = await bothPresentations(nonce)
    const res = await settleOffer(app, session, p)
    const grai = ((await res.json()) as { receipt: { grai: string } }).receipt.grai
    const get = await app.request(`${ORIGIN}/dlvp/receipt/${grai}`)
    const rec = (await get.json()) as { dlvp: { valueExchanged?: { txRef: string; legs: Array<{ valueType: string }> } } }
    expect(rec.dlvp.valueExchanged?.txRef).toContain('mocktx_')
    expect(rec.dlvp.valueExchanged?.legs.map((l) => l.valueType).sort()).toEqual(['micro-payment', 'verified-attribute'])
  })
})

describe('FATAL MODE: value-without-disclosure', () => {
  it('a tampered brand presentation -> 400, value never prepares, nothing recorded', async () => {
    const port = mockSettlementPort()
    const { app, store, session, nonce } = await openSession(offerFor(3), { settlement: port })
    const p = await bothPresentations(nonce)
    const tampered = { consumer: p.consumer, brand: p.brand.slice(0, -4) + 'AAAA' }
    const res = await settleOffer(app, session, tampered)
    expect(res.status).toBe(400)
    const err = (await res.json()) as { error: { side?: string }; disclosedToConsumer?: unknown }
    expect(err.error.side).toBe('brand')
    expect(err.disclosedToConsumer).toBeUndefined() // claims withheld
    expect(store.size()).toBe(0)
    expect(port.calls).toHaveLength(0) // value never even prepared
  })
})

describe('FATAL MODE: minConfidence too low (C5 gate)', () => {
  it('an OFFER demanding rung 4 can never clear in v1 -> 402, no value moves', async () => {
    const port = mockSettlementPort()
    const { app, store, session, nonce } = await openSession(offerFor(4), { settlement: port })
    const p = await bothPresentations(nonce)
    const res = await settleOffer(app, session, p)
    expect(res.status).toBe(402)
    const err = (await res.json()) as { error: { code: string }; disclosedToConsumer?: unknown }
    expect(err.error.code).toBe('CONFIDENCE_TOO_LOW')
    expect(err.disclosedToConsumer).toBeUndefined()
    expect(store.size()).toBe(0)
    expect(port.calls).toHaveLength(0) // gate fails BEFORE any prepare
  })

  it('a proven rung below the OFFER minConfidence -> 402 (no-scope consumer = attested rung 1, min 3)', async () => {
    const port = mockSettlementPort()
    const { app, store, session, nonce } = await openSession(offerFor(3), { settlement: port })
    // A consumer VC asserting NO ownership scope -> holder-attested at rung 1.
    const consumer = await buildPresentation({
      issuerKey: consumerIssuerKey, holderKey: consumerHolderKey, iss: CONSUMER_ISS,
      vct: 'https://id.org.ai/vct/ownership',
      sdClaims: { tier: 2 }, nonce, aud: ORIGIN,
    })
    const brand = await buildPresentation({
      issuerKey: brandIssuerKey, holderKey: brandHolderKey, iss: BRAND_ISS,
      vct: 'https://id.org.ai/vct/provenance', sdClaims: { genuine: true },
      plainClaims: { controller: 'org_acme' }, nonce, aud: ORIGIN,
    })
    const res = await settleOffer(app, session, { consumer: consumer.presentation, brand: brand.presentation })
    expect(res.status).toBe(402)
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('CONFIDENCE_TOO_LOW')
    expect(store.size()).toBe(0)
    expect(port.calls).toHaveLength(0)
  })
})

describe('FATAL MODE: disclosure-without-value (settlement prepare fails)', () => {
  it('prepare reject -> SETTLEMENT_FAILED, claims withheld, nothing recorded, nonce released', async () => {
    const port = mockSettlementPort({ failAt: 'prepare', failReason: 'declined' })
    const { app, store, session, nonce } = await openSession(offerFor(3), { settlement: port })
    const p = await bothPresentations(nonce)
    const res = await settleOffer(app, session, p)
    expect(res.status).toBe(402)
    const err = (await res.json()) as { error: { code: string }; disclosedToConsumer?: unknown }
    expect(err.error.code).toBe('SETTLEMENT_FAILED')
    expect(err.disclosedToConsumer).toBeUndefined()
    expect(store.size()).toBe(0)
    expect(port.committedCount).toBe(0)
    // Nonce was RELEASED (not spent) on a settlement failure: a legitimate retry
    // is possible (it will fail again the same way, but is not a 409 replay).
    const retry = await settleOffer(app, session, p)
    expect(retry.status).toBe(402)
    expect(((await retry.json()) as { error: { code: string } }).error.code).toBe('SETTLEMENT_FAILED')
  })
})

describe('FATAL MODE: settlement-fails-after-disclosure (commit fails)', () => {
  it('commit reject -> nothing recorded, hold voided, claims withheld', async () => {
    const port = mockSettlementPort({ failAt: 'commit', failReason: 'insufficient-funds' })
    const { app, store, session, nonce } = await openSession(offerFor(3), { settlement: port })
    const p = await bothPresentations(nonce)
    const res = await settleOffer(app, session, p)
    expect(res.status).toBe(402)
    const err = (await res.json()) as { error: { code: string }; disclosedToConsumer?: unknown }
    expect(err.error.code).toBe('SETTLEMENT_FAILED')
    expect(err.disclosedToConsumer).toBeUndefined()
    // Receipt NEVER persisted even though it was built + signed pre-commit.
    expect(store.size()).toBe(0)
    expect(port.committedCount).toBe(0)
    // prepare -> commit(reject) -> void (compensating release).
    expect(port.calls.map((c) => c.phase)).toEqual(['prepare', 'commit', 'void'])
  })
})

describe('replay + backward-compat', () => {
  it('the resolution nonce is single-use across settle-offer', async () => {
    const port = mockSettlementPort()
    const { app, store, session, nonce } = await openSession(offerFor(3), { settlement: port })
    const p = await bothPresentations(nonce)
    expect((await settleOffer(app, session, p)).status).toBe(200)
    expect(store.size()).toBe(1)
    const replay = await settleOffer(app, session, p)
    expect(replay.status).toBe(409)
    expect(((await replay.json()) as { error: { code: string } }).error.code).toBe('NONCE_REPLAY')
    expect(store.size()).toBe(1)
  })

  it('OFFER_MISSING when the session carries no offer', async () => {
    const port = mockSettlementPort()
    const { app, store, session, nonce } = await openSession(undefined, { settlement: port })
    const p = await bothPresentations(nonce)
    const res = await settleOffer(app, session, p)
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('OFFER_MISSING')
    expect(store.size()).toBe(0)
    expect(port.calls).toHaveLength(0)
  })

  it('an OFFER-bearing session CANNOT be redeemed on the free P5 /dlvp/settle path (no disclosure-without-value)', async () => {
    // Closes the bypass: the same co-presentation minted for a paid settle must not
    // hand over the disclosure on the value-free path (which would also burn the nonce).
    const store = new DlvpStore()
    const { app, session, nonce } = await openSession(offerFor(3), { store })
    const p = await bothPresentations(nonce)
    const res = await app.request(`${ORIGIN}/dlvp/settle`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ session, consumerPresentation: p.consumer, brandPresentation: p.brand }),
    })
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('OFFER_REQUIRES_SETTLE_OFFER')
    expect(store.size()).toBe(0) // nothing disclosed, nothing minted
  })

  it('a plain (offer-free) P5 session still settles normally on /dlvp/settle', async () => {
    const store = new DlvpStore()
    const { app, session, nonce } = await openSession(undefined, { store })
    const p = await bothPresentations(nonce)
    const res = await app.request(`${ORIGIN}/dlvp/settle`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ session, consumerPresentation: p.consumer, brandPresentation: p.brand }),
    })
    expect(res.status).toBe(200)
    expect(store.size()).toBe(1)
  })

  it('value does NOT clear on holder-attestation when the registry is empty (counter-verified required)', async () => {
    // The exact hole the C5 gate closes: counterVerify grants rung 3 to a scope-asserting
    // VC even with NO registry record (verdict holder-attested) — in production the
    // registry is empty, so EVERY presentation would otherwise reach rung 3. Value must
    // require the registry-counter-verified verdict, not mere holder-attestation.
    const store = new DlvpStore()
    const port = mockSettlementPort()
    const { session, nonce } = await openSession(offerFor(3), { store, settlement: port })
    const p = await bothPresentations(nonce)
    // Settle against an app whose registry has NO record for the key.
    const emptyApp = createDlvpApp({ registry: new MemoryRegistryPort(), signer, trust, store, settlement: port })
    const res = await settleOffer(emptyApp, session, p)
    expect(res.status).toBe(402)
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('CONFIDENCE_NOT_COUNTERVERIFIED')
    expect(store.size()).toBe(0) // nothing minted
    expect(port.committedCount).toBe(0) // no value captured
    expect(port.calls.some((x) => x.phase === 'prepare')).toBe(false) // blocked BEFORE any value hold
  })

  it('a signer failure at receipt-mint voids the hold and records NOTHING (atomic)', async () => {
    const store = new DlvpStore()
    const port = mockSettlementPort()
    const { session, nonce } = await openSession(offerFor(3), { store, settlement: port })
    const p = await bothPresentations(nonce)
    // A second app over the SAME store whose signer.sign() throws at receipt-mint;
    // verify still delegates, so the session + presentations verify and the value
    // hold prepares — then minting fails.
    const failSigner: DlvpSigner = {
      sign: async () => { throw new Error('signer unavailable') },
      verify: (t: string) => signer.verify(t),
    }
    const failApp = createDlvpApp({ registry: seededRegistry(), signer: failSigner, trust, store, settlement: port })
    const res = await settleOffer(failApp, session, p)
    expect(res.status).toBe(402)
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('SETTLEMENT_FAILED')
    expect(store.size()).toBe(0) // nothing minted, nothing disclosed
    expect(port.committedCount).toBe(0) // no value captured
    expect(port.calls.some((x) => x.phase === 'void')).toBe(true) // the hold was voided
    expect(port.calls.some((x) => x.phase === 'commit')).toBe(false) // never committed
  })

  it('production default settlement port is FAIL-CLOSED (no rail wired -> SETTLEMENT_FAILED, no money)', async () => {
    // No settlement injected -> createDlvpApp defaults to noopSettlementPort.
    const store = new DlvpStore()
    const app = createDlvpApp({ registry: seededRegistry(), signer, trust, store })
    const open = await app.request(`${ORIGIN}/dlvp/session`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ identifier: INSTANCE_KEY, consumerAsk: [{ claim: 'genuine' }], brandOffer: [{ claim: 'owns' }], offer: offerFor(3) }),
    })
    const { session, nonce } = (await open.json()) as { session: string; nonce: string }
    const p = await bothPresentations(nonce)
    const res = await settleOffer(app, session, p)
    expect(res.status).toBe(402)
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('SETTLEMENT_FAILED')
    expect(store.size()).toBe(0)
  })

  it('the OFFER terms come from the SIGNED session, not the body (body tamper is ignored)', async () => {
    const port = mockSettlementPort()
    const { app, session, nonce } = await openSession(offerFor(3), { settlement: port })
    const p = await bothPresentations(nonce)
    // Attach a malicious offer + minConfidence in the body; the handler must ignore it.
    const res = await app.request(`${ORIGIN}/dlvp/settle-offer`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        session, consumerPresentation: p.consumer, brandPresentation: p.brand,
        offer: { ...offerFor(1), offerId: 'attacker_offer' }, minConfidence: 1,
      }),
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as { settlement: { offerId: string; minConfidence: number } }
    expect(body.settlement.offerId).toBe('offer_test_1') // from the session, not the body
    expect(body.settlement.minConfidence).toBe(3)
  })
})
