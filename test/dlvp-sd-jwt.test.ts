/**
 * DLVP SD-JWT-VC verifier — WebCrypto-only, ES256 + EdDSA fixtures generated at
 * test time (session keys only). Asserts the three verification steps: issuer
 * signature, selective-disclosure digest match, and the KB-JWT nonce/aud/sd_hash
 * binding — and fail-closed on every tamper.
 */
import { describe, it, expect } from 'vitest'
import { verifySdJwtPresentation, parseSdJwt, jwkThumbprint, type IssuerTrustMap } from '../worker/dlvp/sd-jwt'
import { genKey, buildPresentation, issueSdJwtVc, makeKbJwt, assemble, type FixtureAlg } from './helpers/dlvp-issue'

const ISS = 'https://issuer.example/loyalty'
const AUD = 'https://id.org.ai'
const VCT = 'https://id.org.ai/vct/membership'
const NONCE = 'r-nonce-abc123'

for (const alg of ['ES256', 'EdDSA'] as FixtureAlg[]) {
  describe(`verifySdJwtPresentation - ${alg}`, () => {
    it('verifies a well-formed presentation and reconstructs only disclosed claims', async () => {
      const issuerKey = await genKey(alg)
      const holderKey = await genKey(alg)
      const { presentation, issuerJwk } = await buildPresentation({
        issuerKey,
        holderKey,
        iss: ISS,
        vct: VCT,
        sdClaims: { tier: 2, owns: '01/09506000134352/21/SER1', owner_subject: 'human_alice' },
        nonce: NONCE,
        aud: AUD,
      })
      const trust: IssuerTrustMap = { [ISS]: issuerJwk }
      const res = await verifySdJwtPresentation(presentation, { trust, expectedNonce: NONCE, expectedAud: AUD })
      expect(res.ok).toBe(true)
      if (!res.ok) return
      expect(res.iss).toBe(ISS)
      expect(res.vct).toBe(VCT)
      expect(res.claims.tier).toBe(2)
      expect(res.claims.owns).toBe('01/09506000134352/21/SER1')
      expect(res.kb).not.toBeNull()
      expect(res.kb!.nonce).toBe(NONCE)
      expect(res.cnfThumbprint.length).toBeGreaterThan(0)
    })

    it('rejects an UNTRUSTED issuer (no trust-map key)', async () => {
      const issuerKey = await genKey(alg)
      const holderKey = await genKey(alg)
      const { presentation } = await buildPresentation({
        issuerKey, holderKey, iss: ISS, vct: VCT, sdClaims: { tier: 2 }, nonce: NONCE, aud: AUD,
      })
      const res = await verifySdJwtPresentation(presentation, { trust: {}, expectedNonce: NONCE, expectedAud: AUD })
      expect(res.ok).toBe(false)
      if (res.ok) return
      expect(res.code).toBe('UNTRUSTED_ISSUER')
    })

    it('rejects a wrong-key issuer signature', async () => {
      const issuerKey = await genKey(alg)
      const wrongKey = await genKey(alg)
      const holderKey = await genKey(alg)
      const { presentation } = await buildPresentation({
        issuerKey, holderKey, iss: ISS, vct: VCT, sdClaims: { tier: 2 }, nonce: NONCE, aud: AUD,
      })
      // Trust map points at the WRONG public key → signature must fail.
      const res = await verifySdJwtPresentation(presentation, {
        trust: { [ISS]: wrongKey.publicJwk }, expectedNonce: NONCE, expectedAud: AUD,
      })
      expect(res.ok).toBe(false)
      if (res.ok) return
      expect(res.code).toBe('ISSUER_SIG_INVALID')
    })

    it('rejects a tampered disclosure (digest not in _sd)', async () => {
      const issuerKey = await genKey(alg)
      const holderKey = await genKey(alg)
      const { issuerJwt, disclosures, issuerJwk } = await buildPresentation({
        issuerKey, holderKey, iss: ISS, vct: VCT, sdClaims: { tier: 2 }, nonce: NONCE, aud: AUD,
      })
      // Inject a foreign disclosure whose digest is NOT in _sd.
      const forged = await issueSdJwtVc({ issuerKey, iss: ISS, vct: VCT, sdClaims: { tier: 99 } })
      const kb = await makeKbJwt({ holderKey, nonce: NONCE, aud: AUD, issuerJwt, disclosures: [...disclosures, forged.disclosures[0]!] })
      const tampered = assemble(issuerJwt, [...disclosures, forged.disclosures[0]!], kb)
      const res = await verifySdJwtPresentation(tampered, { trust: { [ISS]: issuerJwk }, expectedNonce: NONCE, expectedAud: AUD })
      expect(res.ok).toBe(false)
      if (res.ok) return
      expect(res.code).toBe('DISCLOSURE_UNMATCHED')
    })

    it('rejects a nonce mismatch (KB bound to a different r)', async () => {
      const issuerKey = await genKey(alg)
      const holderKey = await genKey(alg)
      const { presentation, issuerJwk } = await buildPresentation({
        issuerKey, holderKey, iss: ISS, vct: VCT, sdClaims: { tier: 2 }, nonce: 'r-OTHER', aud: AUD,
      })
      const res = await verifySdJwtPresentation(presentation, { trust: { [ISS]: issuerJwk }, expectedNonce: NONCE, expectedAud: AUD })
      expect(res.ok).toBe(false)
      if (res.ok) return
      expect(res.code).toBe('NONCE_MISMATCH')
    })

    it('rejects an aud mismatch (KB aud != resolver origin)', async () => {
      const issuerKey = await genKey(alg)
      const holderKey = await genKey(alg)
      const { presentation, issuerJwk } = await buildPresentation({
        issuerKey, holderKey, iss: ISS, vct: VCT, sdClaims: { tier: 2 }, nonce: NONCE, aud: 'https://evil.example',
      })
      const res = await verifySdJwtPresentation(presentation, { trust: { [ISS]: issuerJwk }, expectedNonce: NONCE, expectedAud: AUD })
      expect(res.ok).toBe(false)
      if (res.ok) return
      expect(res.code).toBe('AUD_MISMATCH')
    })

    it('rejects an sd_hash mismatch (KB bound to a different disclosure set)', async () => {
      const issuerKey = await genKey(alg)
      const holderKey = await genKey(alg)
      const { issuerJwt, disclosures, issuerJwk } = await buildPresentation({
        issuerKey, holderKey, iss: ISS, vct: VCT, sdClaims: { tier: 2, secret: 'hidden' }, nonce: NONCE, aud: AUD,
      })
      // KB computed over BOTH disclosures, but present only ONE → sd_hash differs.
      const kbOverAll = await makeKbJwt({ holderKey, nonce: NONCE, aud: AUD, issuerJwt, disclosures })
      const oneOnly = assemble(issuerJwt, [disclosures[0]!], kbOverAll)
      const res = await verifySdJwtPresentation(oneOnly, { trust: { [ISS]: issuerJwk }, expectedNonce: NONCE, expectedAud: AUD })
      expect(res.ok).toBe(false)
      if (res.ok) return
      expect(res.code).toBe('SD_HASH_MISMATCH')
    })

    it('rejects a missing key-binding JWT when one is required', async () => {
      const issuerKey = await genKey(alg)
      const holderKey = await genKey(alg)
      const issued = await issueSdJwtVc({ issuerKey, iss: ISS, vct: VCT, cnfJwk: holderKey.publicJwk, sdClaims: { tier: 2 } })
      const noKb = assemble(issued.issuerJwt, issued.disclosures, null)
      const res = await verifySdJwtPresentation(noKb, { trust: { [ISS]: issuerKey.publicJwk }, expectedNonce: NONCE, expectedAud: AUD })
      expect(res.ok).toBe(false)
      if (res.ok) return
      expect(res.code).toBe('KB_MISSING')
    })
  })
}

describe('parseSdJwt + jwkThumbprint', () => {
  it('parses issuer~disclosures~kb into its parts', async () => {
    const k = await genKey('ES256')
    const h = await genKey('ES256')
    const { presentation, issuerJwt, disclosures } = await buildPresentation({
      issuerKey: k, holderKey: h, iss: ISS, vct: VCT, sdClaims: { a: 1, b: 2 }, nonce: NONCE, aud: AUD,
    })
    const parsed = parseSdJwt(presentation)
    expect(parsed).not.toBeNull()
    expect(parsed!.issuerJwt).toBe(issuerJwt)
    expect(parsed!.disclosures.length).toBe(disclosures.length)
    expect(parsed!.kbJwt).not.toBeNull()
  })

  it('returns null for a non-SD-JWT string', () => {
    expect(parseSdJwt('not-a-jwt')).toBeNull()
    expect(parseSdJwt('')).toBeNull()
  })

  it('thumbprint is stable + differs per key (the scoped-pseudonym seed)', async () => {
    const a = await genKey('ES256')
    const b = await genKey('ES256')
    const ta1 = await jwkThumbprint(a.publicJwk)
    const ta2 = await jwkThumbprint(a.publicJwk)
    const tb = await jwkThumbprint(b.publicJwk)
    expect(ta1).toBe(ta2)
    expect(ta1).not.toBe(tb)
  })
})
