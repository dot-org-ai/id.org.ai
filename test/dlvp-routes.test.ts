/**
 * DLVP HTTP surface — the full symmetric handshake end-to-end via
 * createDlvpApp().request() (a seeded MemoryRegistryPort + a session signer + an
 * injected issuer trust map; no live keys, no live binding — RAILS). Asserts:
 * session → settle mints the counter-verified receipt; the receipt is fetchable
 * + revocable through its own address; and settle is ATOMIC (any tamper → typed
 * 400, NOTHING recorded).
 */
import { describe, it, expect, beforeAll } from 'vitest'
import { createDlvpApp } from '../worker/routes/dlvp'
import { createSessionSigner, type DlvpSigner } from '../worker/dlvp/nonce'
import { DlvpStore } from '../worker/dlvp/store'
import { MemoryRegistryPort } from '../worker/registry/memory'
import type { IdentifierRecord, OwnerRef, Linkset, PolicyRef } from '../worker/registry/port'
import {
  genKey,
  buildPresentation,
  issueSdJwtVc,
  makeKbJwt,
  assemble,
  type FixtureKey,
} from './helpers/dlvp-issue'
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

// Shared fixture keys (session-generated once).
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

/** Open a session over INSTANCE_KEY and return { app, store, nonce }. */
async function openSession(overrides: { store?: DlvpStore } = {}) {
  const store = overrides.store ?? new DlvpStore()
  const app = createDlvpApp({ registry: seededRegistry(), signer, trust, store })
  const res = await app.request(`${ORIGIN}/dlvp/session`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      identifier: INSTANCE_KEY,
      consumerAsk: [{ claim: 'genuine' }],
      brandOffer: [{ claim: 'owns' }],
    }),
  })
  expect(res.status).toBe(200)
  const body = (await res.json()) as { session: string; nonce: string; epcis: unknown[] }
  return { app, store, session: body.session, nonce: body.nonce, sessionBody: body }
}

/** Build both presentations bound to `nonce` (consumer owns the instance; brand attests genuine). */
async function bothPresentations(nonce: string, opts: { consumerNonce?: string; brandNonce?: string } = {}) {
  const consumer = await buildPresentation({
    issuerKey: consumerIssuerKey, holderKey: consumerHolderKey, iss: CONSUMER_ISS,
    vct: 'https://id.org.ai/vct/ownership',
    sdClaims: { owner_subject: 'human_alice', owns: INSTANCE_KEY, tier: 2 },
    nonce: opts.consumerNonce ?? nonce, aud: ORIGIN,
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

describe('POST /dlvp/session', () => {
  it('mints a signed stateless request-object carrying nonce + epcis consent event', async () => {
    const { sessionBody } = await openSession()
    expect(typeof sessionBody.session).toBe('string')
    expect(sessionBody.nonce.length).toBeGreaterThan(0)
    expect(sessionBody.epcis.length).toBe(1)
    const verified = await signer.verify(sessionBody.session)
    expect(verified!.nonce).toBe(sessionBody.nonce)
  })

  it('400s a malformed body', async () => {
    const app = createDlvpApp({ registry: seededRegistry(), signer, trust })
    const res = await app.request(`${ORIGIN}/dlvp/session`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ nope: 1 }),
    })
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('BAD_REQUEST')
  })
})

describe('POST /dlvp/settle — the atomic symmetric co-settle', () => {
  it('verifies BOTH presentations over r, counter-verifies, and mints the receipt', async () => {
    const { app, store, session, nonce } = await openSession()
    const p = await bothPresentations(nonce)
    const res = await app.request(`${ORIGIN}/dlvp/settle`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ session, consumerPresentation: p.consumer, brandPresentation: p.brand }),
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as {
      verdict: string
      disclosedToConsumer: Record<string, unknown>
      disclosedToBrand: Record<string, unknown>
      receipt: { grai: string; digitalLink: string; vcJwt: string; statusListRef: { status: string } }
      epcis: unknown[]
    }
    // C3 dual-verifier tier.
    expect(body.verdict).toBe('holder-presented-vc-counterverified')
    // Symmetric disclosure: brand → consumer, consumer → brand.
    expect(body.disclosedToConsumer.genuine).toBe(true)
    expect(body.disclosedToBrand.owns).toBe(INSTANCE_KEY)
    // The minted receipt + its three EPCIS events (2 disclosing + 1 consenting).
    expect(body.receipt.grai.length).toBeGreaterThan(14)
    expect(body.receipt.digitalLink).toBe(`${ORIGIN}/8003/${body.receipt.grai}`)
    expect(body.receipt.statusListRef.status).toBe('valid')
    expect(body.epcis.length).toBe(3)
    expect(store.size()).toBe(1)
  })

  it('the receipt is fetchable and revocable through its own Digital Link address', async () => {
    const { app, session, nonce } = await openSession()
    const p = await bothPresentations(nonce)
    const settle = await app.request(`${ORIGIN}/dlvp/settle`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ session, consumerPresentation: p.consumer, brandPresentation: p.brand }),
    })
    const settled = (await settle.json()) as { receipt: { grai: string; revocationToken: string } }
    const grai = settled.receipt.grai
    const revocationToken = settled.receipt.revocationToken

    const get = await app.request(`${ORIGIN}/dlvp/receipt/${grai}`)
    expect(get.status).toBe(200)
    expect(((await get.json()) as { statusState: string }).statusState).toBe('valid')

    // Revoke without the capability is refused; with it, it succeeds.
    const unauth = await app.request(`${ORIGIN}/dlvp/receipt/${grai}/revoke`, { method: 'POST' })
    expect(unauth.status).toBe(403)
    const wrong = await app.request(`${ORIGIN}/dlvp/receipt/${grai}/revoke`, { method: 'POST', headers: { 'x-revocation-token': 'not-the-token' } })
    expect(wrong.status).toBe(403)

    const revoke = await app.request(`${ORIGIN}/dlvp/receipt/${grai}/revoke`, { method: 'POST', headers: { 'x-revocation-token': revocationToken } })
    expect(revoke.status).toBe(200)
    const rbody = (await revoke.json()) as { revoked: boolean; statusState: string; epcis: unknown[] }
    expect(rbody.revoked).toBe(true)
    expect(rbody.statusState).toBe('revoked')
    expect(rbody.epcis.length).toBe(1)

    const after = await app.request(`${ORIGIN}/dlvp/receipt/${grai}`)
    expect(((await after.json()) as { statusState: string }).statusState).toBe('revoked')
  })

  it('ATOMIC: a tampered brand presentation -> typed 400, NOTHING recorded', async () => {
    const { app, store, session, nonce } = await openSession()
    const p = await bothPresentations(nonce)
    const tamperedBrand = p.brand.slice(0, -4) + 'AAAA' // corrupt the KB signature
    const res = await app.request(`${ORIGIN}/dlvp/settle`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ session, consumerPresentation: p.consumer, brandPresentation: tamperedBrand }),
    })
    expect(res.status).toBe(400)
    const err = (await res.json()) as { error: { code: string; side?: string } }
    expect(err.error.side).toBe('brand')
    // atomic-or-nothing: no receipt minted.
    expect(store.size()).toBe(0)
  })

  it('rejects a consumer presentation bound to a DIFFERENT nonce (NONCE_MISMATCH), records nothing', async () => {
    const { app, store, session, nonce } = await openSession()
    const p = await bothPresentations(nonce, { consumerNonce: 'r-WRONG' })
    const res = await app.request(`${ORIGIN}/dlvp/settle`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ session, consumerPresentation: p.consumer, brandPresentation: p.brand }),
    })
    expect(res.status).toBe(400)
    const err = (await res.json()) as { error: { code: string; side?: string } }
    // The consumer side fails its own KB nonce check first.
    expect(err.error.code).toBe('NONCE_MISMATCH')
    expect(store.size()).toBe(0)
  })

  it('rejects an untrusted issuer (empty trust map) — honest fail-closed, records nothing', async () => {
    const store = new DlvpStore()
    const app = createDlvpApp({ registry: seededRegistry(), signer, trust: {}, store })
    const open = await app.request(`${ORIGIN}/dlvp/session`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ identifier: INSTANCE_KEY, consumerAsk: [{ claim: 'genuine' }] }),
    })
    const { session, nonce } = (await open.json()) as { session: string; nonce: string }
    const p = await bothPresentations(nonce)
    const res = await app.request(`${ORIGIN}/dlvp/settle`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ session, consumerPresentation: p.consumer, brandPresentation: p.brand }),
    })
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('PRESENTATION_INVALID')
    expect(store.size()).toBe(0)
  })

  it('400s an expired session', async () => {
    const store = new DlvpStore()
    const app = createDlvpApp({ registry: seededRegistry(), signer, trust, store })
    // Sign a session that is already expired.
    const expired = await signer.sign({ sub: INSTANCE_KEY, nonce: 'r', epcisEventId: 'e' }, { expiresIn: -300 })
    const p = await bothPresentations('r')
    const res = await app.request(`${ORIGIN}/dlvp/settle`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ session: expired, consumerPresentation: p.consumer, brandPresentation: p.brand }),
    })
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('SESSION_EXPIRED')
  })
})

describe('GET/POST /dlvp/receipt/:grai', () => {
  it('404s an unknown GRAI on fetch and revoke', async () => {
    const app = createDlvpApp({ registry: seededRegistry(), signer, trust, store: new DlvpStore() })
    expect((await app.request(`${ORIGIN}/dlvp/receipt/unknown`)).status).toBe(404)
    expect((await app.request(`${ORIGIN}/dlvp/receipt/unknown/revoke`, { method: 'POST' })).status).toBe(404)
  })
})
