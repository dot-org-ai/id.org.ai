/**
 * DLVP nonce + stateless session request-object. Asserts r is 256-bit + unique,
 * the session signer round-trips (sign → verify) and rejects tamper/foreign
 * signatures, and the four-place nonce binding holds only when all four agree.
 */
import { describe, it, expect } from 'vitest'
import {
  mintNonce,
  mintEventId,
  createSessionSigner,
  buildCoPresentationRequest,
  nonceBindingHolds,
} from '../worker/dlvp/nonce'
import { base64UrlDecode } from '../src/sdk/oauth/pkce'

describe('mintNonce / mintEventId', () => {
  it('mints a 256-bit (32-byte) base64url nonce, unique per call', () => {
    const a = mintNonce()
    const b = mintNonce()
    expect(a).not.toBe(b)
    expect(new Uint8Array(base64UrlDecode(a)).length).toBe(32)
  })
  it('mints a unique event id', () => {
    expect(mintEventId()).not.toBe(mintEventId())
  })
})

describe('stateless session request-object', () => {
  it('signs and verifies the co-presentation-request; nonce survives the round-trip', async () => {
    const signer = await createSessionSigner()
    const nonce = mintNonce()
    const eventId = mintEventId()
    const claims = buildCoPresentationRequest(
      { identifier: '01/09506000134352/21/SER1', consumerAsk: [{ claim: 'genuine' }], brandOffer: [{ claim: 'owns' }] },
      nonce,
      eventId,
      { consumer: 'dlvp:consumer', brand: 'dlvp:brand' },
    )
    const jwt = await signer.sign(claims as unknown as Record<string, unknown>, { expiresIn: 120 })
    const verified = await signer.verify(jwt)
    expect(verified).not.toBeNull()
    expect(verified!.nonce).toBe(nonce)
    expect(verified!.sub).toBe('01/09506000134352/21/SER1')
    expect(verified!.epcisEventId).toBe(eventId)
  })

  it('rejects a foreign-signed session (different key)', async () => {
    const a = await createSessionSigner()
    const b = await createSessionSigner()
    const jwt = await a.sign({ sub: 'x', nonce: 'n' }, { expiresIn: 120 })
    expect(await b.verify(jwt)).toBeNull()
  })

  it('rejects an expired session', async () => {
    const signer = await createSessionSigner()
    // Past the verifier's 60s clock tolerance.
    const jwt = await signer.sign({ sub: 'x', nonce: 'n' }, { expiresIn: -300 })
    expect(await signer.verify(jwt)).toBeNull()
  })
})

describe('four-place nonce binding', () => {
  it('holds only when session === event === consumerKB === brandKB', () => {
    expect(nonceBindingHolds({ sessionNonce: 'r', eventNonce: 'r', consumerKbNonce: 'r', brandKbNonce: 'r' })).toBe(true)
    expect(nonceBindingHolds({ sessionNonce: 'r', eventNonce: 'r', consumerKbNonce: 'r', brandKbNonce: 'x' })).toBe(false)
    expect(nonceBindingHolds({ sessionNonce: 'r', eventNonce: 'x', consumerKbNonce: 'r', brandKbNonce: 'r' })).toBe(false)
    expect(nonceBindingHolds({ sessionNonce: '', eventNonce: '', consumerKbNonce: '', brandKbNonce: '' })).toBe(false)
  })
})
