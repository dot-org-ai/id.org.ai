/**
 * DLVP ISO/IEC 27560 consent receipt. Asserts the receipt shape (piiPrincipalId
 * is the scoped pseudonym, NEVER a raw identity), the GRAI is a well-formed AI
 * 8003 (resolves through the existing door), the signed VC carries the vct + cnf
 * + dlvp binding, and the Token-Status-List revoke flips the bit.
 */
import { describe, it, expect } from 'vitest'
import { mintGrai, buildIso27560, mintReceipt, CONSENT_RECEIPT_VCT } from '../worker/dlvp/receipt'
import { DlvpStore } from '../worker/dlvp/store'
import { createSessionSigner } from '../worker/dlvp/nonce'
import { mod10Verify } from '../worker/resolve/identifiers'
import { decodeJWT } from '../src/sdk/oauth/jwt-verify'

describe('mintGrai', () => {
  it('mints a well-formed AI 8003 GRAI: 14-digit core (valid mod-10) + serial', () => {
    const grai = mintGrai()
    const core = grai.slice(0, 14)
    expect(/^[0-9]{14}/.test(grai)).toBe(true)
    expect(mod10Verify(core).pass).toBe(true)
    expect(grai.length).toBeGreaterThan(14)
  })
})

describe('buildIso27560', () => {
  it('records disclosed predicates as piiCategories; pseudonym is NEVER a raw identity', () => {
    const iso = buildIso27560({
      consentReceiptID: 'grai-1',
      brandController: 'org_acme',
      consumerPseudonym: 'thumbprint-xyz',
      consumerAsk: [{ claim: 'genuine' }, { claim: 'warranty', op: 'gte', value: 12 }],
      brandAsk: [{ claim: 'owns' }, { claim: 'tier', op: 'gte', value: 2 }],
    })
    expect(iso.collectionMethod).toBe('dlvp-symmetric-presentation')
    expect(iso.piiPrincipalId).toBe('thumbprint-xyz')
    expect(iso.piiControllers).toEqual(['org_acme'])
    const cats = iso.services[0]!.purposes[0]!.piiCategories
    expect(cats).toContain('owns')
    expect(cats).toContain('tier>=2')
    expect(cats).toContain('warranty>=12')
  })
})

describe('mintReceipt + revoke', () => {
  it('mints a signed receipt VC (vct + cnf + dlvp binding), stores it, and revokes', async () => {
    const signer = await createSessionSigner()
    const store = new DlvpStore()
    const receipt = await mintReceipt({
      signer,
      store,
      brandController: 'org_acme',
      consumerCnfJwk: { kty: 'EC', crv: 'P-256', x: 'abc', y: 'def' },
      consumerPseudonym: 'tp-consumer',
      consumerAsk: [{ claim: 'genuine' }],
      brandAsk: [{ claim: 'owns' }],
      nonce: 'r-123',
      epcisEventId: 'epcis:evt-1',
      consumerPresentationDigest: 'cd',
      brandPresentationDigest: 'bd',
    })

    expect(receipt.grai.length).toBeGreaterThan(14)
    expect(receipt.digitalLink).toBe(`https://id.org.ai/8003/${receipt.grai}`)
    expect(receipt.status.status).toBe('valid')
    expect(receipt.dlvp.nonce).toBe('r-123')

    // The signed VC decodes to the receipt claims.
    const decoded = decodeJWT(receipt.vcJwt)
    expect(decoded).not.toBeNull()
    expect(decoded!.payload.vct).toBe(CONSENT_RECEIPT_VCT)
    expect((decoded!.payload.cnf as { jwk: { kty: string } }).jwk.kty).toBe('EC')
    expect((decoded!.payload.dlvp as { nonce: string }).nonce).toBe('r-123')

    // Stored + fetchable + revocable.
    expect(store.get(receipt.grai)!.grai).toBe(receipt.grai)
    expect(store.statusOf(receipt.grai)).toBe('valid')
    expect(store.revoke(receipt.grai)).toBe(true)
    expect(store.statusOf(receipt.grai)).toBe('revoked')
    expect(store.get(receipt.grai)!.status.status).toBe('revoked')
  })

  it('revoke on an unknown GRAI returns false', async () => {
    const store = new DlvpStore()
    expect(store.revoke('nope')).toBe(false)
  })
})
