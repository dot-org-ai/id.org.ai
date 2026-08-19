/**
 * Integration tests for the resolver door (worker/routes/resolve.ts), mounted
 * in the real worker and exercised in-process via `SELF` (workers pool).
 *
 * Covers ADR 0001 stage-1 contract: valid VIN → 200 JSON-LD; bad grammar →
 * typed CONFORMANCE 400; bad check digit → typed CHECKSUM_FAIL 400; /01/{gtin}
 * class grain + /01/{gtin}/21/{serial} instance grain; conneg (ld+json vs
 * default vs browser→html fallback); anonymous 200 with no Who; Vary + Link
 * alternate headers; and an OAuth regression check that the shipped metadata
 * endpoint still answers unchanged.
 */
import { describe, it, expect } from 'vitest'
import { SELF } from 'cloudflare:test'

const BASE = 'https://id.org.ai'

// Fixtures (check digits computed from the ported algorithms):
const VALID_VIN = '1HGCM82633A004352' // ISO 3779 valid, pos9=3
const BAD_CHECK_VIN = '1HGCM82653A004352' // grammar OK, wrong check digit
const BAD_GRAMMAR_VIN = '1HGCM8263IA004352' // contains 'I' - not VIN alphabet
const VALID_GTIN = '09506000134352' // GS1 mod-10 valid GTIN-14
const BAD_CHECK_GTIN = '09506000134353' // wrong check digit

describe('GET /vin/{vin}', () => {
  it('valid VIN → 200 JSON-LD Vehicle identity doc (anonymous)', async () => {
    const res = await SELF.fetch(`${BASE}/vin/${VALID_VIN}`, { headers: { accept: 'application/ld+json' } })
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('application/ld+json')
    const doc = (await res.json()) as Record<string, unknown>
    expect(doc.$context).toBe('https://schema.org.ai')
    expect(doc.$type).toBe('Vehicle')
    expect(doc.sameAs).toContain(`https://id.org.ai/vin/${VALID_VIN}`)
    // anonymous: no Who attached
    expect(doc.who).toBeUndefined()
    expect((doc.identifier as Array<{ value: string }>)[0].value).toBe(VALID_VIN)
  })

  it('carries Vary + Link rel=alternate headers, never 406', async () => {
    const res = await SELF.fetch(`${BASE}/vin/${VALID_VIN}`, { headers: { accept: 'application/json' } })
    expect(res.status).toBe(200)
    expect(res.headers.get('vary')).toContain('Accept')
    expect(res.headers.get('vary')).toContain('Sec-Fetch-Mode')
    const link = res.headers.get('link') ?? ''
    expect(link).toContain('rel="alternate"')
    expect(link).toContain('application/ld+json')
  })

  it('anonymous response is publicly cacheable but Vary keys on credential headers (no cross-user leak)', async () => {
    const res = await SELF.fetch(`${BASE}/vin/${VALID_VIN}`, { headers: { accept: 'application/ld+json' } })
    expect(res.status).toBe(200)
    // Anonymous (keyless-first-value) doc carries no Who and is safe to share-cache.
    expect((await res.json() as Record<string, unknown>).who).toBeUndefined()
    expect(res.headers.get('cache-control')).toContain('public')
    // A shared cache MUST key on the credential headers so an authenticated request
    // can never be served this anonymous entry (and vice-versa). Guards the leak the
    // personalized branch closes with private,no-store.
    const vary = res.headers.get('vary') ?? ''
    expect(vary).toContain('Authorization')
    expect(vary).toContain('Cookie')
  })

  it('bad VIN check digit → 400 typed CHECKSUM_FAIL', async () => {
    const res = await SELF.fetch(`${BASE}/vin/${BAD_CHECK_VIN}`)
    expect(res.status).toBe(400)
    const body = (await res.json()) as { error: { code: string; message: string; hint: string } }
    expect(body.error.code).toBe('CHECKSUM_FAIL')
    expect(body.error.hint).toContain('ISO 3779')
  })

  it('bad VIN grammar (I/O/Q) → 400 typed CONFORMANCE', async () => {
    const res = await SELF.fetch(`${BASE}/vin/${BAD_GRAMMAR_VIN}`)
    expect(res.status).toBe(400)
    const body = (await res.json()) as { error: { code: string } }
    expect(body.error.code).toBe('CONFORMANCE')
  })

  it('browser (Sec-Fetch navigate) falls back to 200 JSON-LD (defaultLink 303 store deferred)', async () => {
    const res = await SELF.fetch(`${BASE}/vin/${VALID_VIN}`, {
      headers: { 'sec-fetch-mode': 'navigate', accept: 'text/html' },
      redirect: 'manual',
    })
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('application/ld+json')
    expect(res.headers.get('x-resolver-fallback')).toContain('html->jsonld')
  })

  it('default client (bare, no Accept) → 200 JSON-LD', async () => {
    const res = await SELF.fetch(`${BASE}/vin/${VALID_VIN}`)
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('application/ld+json')
  })
})

describe('GET /01/{gtin} and /01/{gtin}/21/{serial}', () => {
  it('valid GTIN → 200 JSON-LD Product (class grain)', async () => {
    const res = await SELF.fetch(`${BASE}/01/${VALID_GTIN}`, { headers: { accept: 'application/ld+json' } })
    expect(res.status).toBe(200)
    const doc = (await res.json()) as Record<string, unknown>
    expect(doc.$type).toBe('Product')
    expect(doc.sameAs).toContain(`https://id.org.ai/01/${VALID_GTIN}`)
    expect(doc.hasVariant).toBeUndefined()
  })

  it('valid GTIN + serial → 200 JSON-LD with instance node (instance grain)', async () => {
    const res = await SELF.fetch(`${BASE}/01/${VALID_GTIN}/21/SN-42`, { headers: { accept: 'application/ld+json' } })
    expect(res.status).toBe(200)
    const doc = (await res.json()) as Record<string, unknown>
    expect(doc.$type).toBe('Product')
    const variant = doc.hasVariant as { serialNumber: string; sameAs: string[] }
    expect(variant.serialNumber).toBe('SN-42')
    expect(variant.sameAs).toContain(`https://id.org.ai/01/${VALID_GTIN}/21/SN-42`)
  })

  it('bad GTIN check digit → 400 typed CHECKSUM_FAIL', async () => {
    const res = await SELF.fetch(`${BASE}/01/${BAD_CHECK_GTIN}`)
    expect(res.status).toBe(400)
    const body = (await res.json()) as { error: { code: string } }
    expect(body.error.code).toBe('CHECKSUM_FAIL')
  })

  it('bad GTIN shape → 400 typed CONFORMANCE', async () => {
    const res = await SELF.fetch(`${BASE}/01/123`)
    expect(res.status).toBe(400)
    const body = (await res.json()) as { error: { code: string } }
    expect(body.error.code).toBe('CONFORMANCE')
  })
})

describe('regression - OAuth surface untouched by the additive mount', () => {
  it('the shipped OAuth authorization-server metadata still answers 200', async () => {
    const res = await SELF.fetch(`${BASE}/.well-known/oauth-authorization-server`)
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>
    // A well-known OAuth metadata field is present - the door did not shadow it.
    expect(body.issuer ?? body.authorization_endpoint).toBeDefined()
  })
})
