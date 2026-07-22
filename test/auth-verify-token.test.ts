/**
 * verifyToken seam tests — the acceptance for ax-e6b.17.3.
 *
 * Asserts the SECURITY behaviour of the stable token-verification primitive
 * (src/sdk/auth/verify-token.ts) and its HTTP wire surface
 * (worker/routes/auth-verify.ts → POST /auth/verify), which builder.domains
 * consumes as `env.AUTH.verifyToken(token)` to project a claimed, owned page
 * onto a custom domain.
 *
 * Tokens are minted hermetically with id.org.ai's OWN signing path
 * (src/sdk/jwt/signing.ts) so no network / real keys are required.
 */

import { describe, it, expect, beforeAll } from 'vitest'
import { generateSigningKey, exportKeysToJWKS, signJWT } from '../src/sdk/jwt/signing'
import type { SigningKey, JWKS, AccessTokenClaims } from '../src/sdk/jwt/signing'
import { verifyToken } from '../src/sdk/auth/verify-token'
import { createAuthVerifyApp } from '../worker/routes/auth-verify'
import type { Env } from '../worker/types'

const ISSUER = 'https://id.org.ai'

let key: SigningKey
let jwks: JWKS

beforeAll(async () => {
  key = await generateSigningKey()
  jwks = await exportKeysToJWKS([key])
})

/** Decode a base64url string (no padding) into raw bytes. */
function base64UrlToBytes(b64url: string): Uint8Array {
  const padded = b64url.replace(/-/g, '+').replace(/_/g, '/').padEnd(b64url.length + ((4 - (b64url.length % 4)) % 4), '=')
  const bin = atob(padded)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes
}

/** Encode raw bytes as base64url (no padding). */
function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

/** Mint an id.org.ai-issued JWT with the test signing key. */
async function mint(
  claims: AccessTokenClaims,
  opts: { issuer?: string; audience?: string; expiresIn?: number } = {},
): Promise<string> {
  return signJWT(key, claims, {
    issuer: opts.issuer ?? ISSUER,
    ...(opts.audience !== undefined && { audience: opts.audience }),
    ...(opts.expiresIn !== undefined && { expiresIn: opts.expiresIn }),
  })
}

// ═══════════════════════════════════════════════════════════════════════════
// Core primitive
// ═══════════════════════════════════════════════════════════════════════════

describe('verifyToken (core primitive)', () => {
  it('accepts a valid id.org.ai-issued token and returns the identity', async () => {
    const token = await mint({
      sub: 'user_42',
      email: 'sally@do.industries',
      name: 'Sally',
      scope: 'read write claim',
      org_id: 'org_acme',
      roles: ['owner'],
    })

    const result = await verifyToken(token, { jwks, issuer: ISSUER })

    expect(result.valid).toBe(true)
    if (!result.valid) throw new Error(result.error)
    expect(result.identity.sub).toBe('user_42')
    expect(result.identity.email).toBe('sally@do.industries')
    expect(result.identity.scope).toBe('read write claim')
    expect(result.identity.scopes).toEqual(['read', 'write', 'claim'])
    expect(result.identity.tenant).toBe('org_acme')
    expect(result.identity.org).toBe('org_acme')
    expect(result.identity.roles).toEqual(['owner'])
    expect(result.identity.issuer).toBe(ISSUER)
    expect(result.identity.claims.sub).toBe('user_42')
  })

  it('surfaces an agent id when the token was minted for an agent', async () => {
    const token = await mint({ sub: 'agent_1', agent_id: 'agent_1', tenant: 'tenant_xyz', scopes: ['do'] } as AccessTokenClaims)
    const result = await verifyToken(token, { jwks, issuer: ISSUER })
    expect(result.valid).toBe(true)
    if (!result.valid) throw new Error(result.error)
    expect(result.identity.agent).toBe('agent_1')
    expect(result.identity.tenant).toBe('tenant_xyz')
    expect(result.identity.scopes).toEqual(['do'])
  })

  it('rejects an EXPIRED token', async () => {
    const token = await mint({ sub: 'user_42' }, { expiresIn: -3600 })
    const result = await verifyToken(token, { jwks, issuer: ISSUER })
    expect(result.valid).toBe(false)
    if (result.valid) throw new Error('expected invalid')
    expect(result.error).toMatch(/expired/i)
  })

  it('rejects a token with a TAMPERED signature', async () => {
    const token = await mint({ sub: 'user_42' })
    const parts = token.split('.')
    // Flip a bit in a MIDDLE byte of the (decoded) signature, then
    // re-encode. Flipping only the LAST base64url character is flaky: an
    // RSA signature's final byte-group carries trailing padding bits that
    // some base64url decoders ignore, so a same-decoded-value flip (e.g.
    // 'A' <-> 'B' when the meaningful bits are already 0) is sometimes a
    // no-op and the "tampered" signature verifies anyway. Decoding, XORing a
    // full byte in the middle of the buffer, and re-encoding always changes
    // the bytes verifySignature() actually sees.
    const sig = parts[2]!
    const sigBytes = base64UrlToBytes(sig)
    const mid = Math.floor(sigBytes.length / 2)
    sigBytes[mid] = sigBytes[mid]! ^ 0xff
    const flipped = bytesToBase64Url(sigBytes)
    const tampered = `${parts[0]}.${parts[1]}.${flipped}`

    const result = await verifyToken(tampered, { jwks, issuer: ISSUER })
    expect(result.valid).toBe(false)
    if (result.valid) throw new Error('expected invalid')
    expect(result.error).toMatch(/signature/i)
  })

  it('rejects a token whose payload was tampered (signature no longer matches)', async () => {
    const token = await mint({ sub: 'user_42' })
    const parts = token.split('.')
    const forgedPayload = btoa(JSON.stringify({ sub: 'attacker', iss: ISSUER, exp: 9999999999 }))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '')
    const forged = `${parts[0]}.${forgedPayload}.${parts[2]}`

    const result = await verifyToken(forged, { jwks, issuer: ISSUER })
    expect(result.valid).toBe(false)
  })

  it('rejects a token from the WRONG issuer', async () => {
    const token = await mint({ sub: 'user_42' }, { issuer: 'https://evil.example' })
    const result = await verifyToken(token, { jwks, issuer: ISSUER })
    expect(result.valid).toBe(false)
    if (result.valid) throw new Error('expected invalid')
    expect(result.error).toMatch(/issuer/i)
  })

  it('rejects a token signed by a DIFFERENT key (foreign signature)', async () => {
    const foreignKey = await generateSigningKey()
    const token = await signJWT(foreignKey, { sub: 'user_42' }, { issuer: ISSUER })
    const result = await verifyToken(token, { jwks, issuer: ISSUER })
    expect(result.valid).toBe(false)
    if (result.valid) throw new Error('expected invalid')
    expect(result.error).toMatch(/signature/i)
  })

  it('enforces audience when the token carries one and an expected audience is supplied', async () => {
    const token = await mint({ sub: 'user_42' }, { audience: 'builder.domains' })

    const ok = await verifyToken(token, { jwks, issuer: ISSUER, audience: 'builder.domains' })
    expect(ok.valid).toBe(true)
    if (ok.valid) expect(ok.identity.audience).toBe('builder.domains')

    const wrong = await verifyToken(token, { jwks, issuer: ISSUER, audience: 'someone.else' })
    expect(wrong.valid).toBe(false)
    if (wrong.valid) throw new Error('expected invalid')
    expect(wrong.error).toMatch(/audience/i)
  })

  it.each([
    ['empty string', ''],
    ['whitespace', '   '],
    ['not-a-jwt', 'not-a-jwt'],
    ['two segments', 'aaa.bbb'],
    ['garbage segments', 'aaa.bbb.ccc'],
  ])('rejects a malformed token (%s) without throwing', async (_label, bad) => {
    const result = await verifyToken(bad, { jwks, issuer: ISSUER })
    expect(result.valid).toBe(false)
    if (result.valid) throw new Error('expected invalid')
    expect(typeof result.error).toBe('string')
  })

  it('rejects a signed token that has no subject (sub) claim', async () => {
    const token = await signJWT(key, {} as AccessTokenClaims, { issuer: ISSUER })
    const result = await verifyToken(token, { jwks, issuer: ISSUER })
    expect(result.valid).toBe(false)
    if (result.valid) throw new Error('expected invalid')
    expect(result.error).toMatch(/sub/i)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// HTTP POST /auth/verify
// ═══════════════════════════════════════════════════════════════════════════

describe('POST /auth/verify (HTTP wire surface)', () => {
  // Inject the test JWKS so the endpoint runs without a Durable Object.
  const app = createAuthVerifyApp(async () => jwks)
  const env = {} as Env

  async function post(body: unknown): Promise<Response> {
    return app.fetch(
      new Request('https://id.org.ai/auth/verify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      }),
      env,
    )
  }

  it('returns 200 + identity for a VALID token', async () => {
    const token = await mint({ sub: 'user_42', scope: 'read claim' })
    const res = await post({ token })
    expect(res.status).toBe(200)
    const json = (await res.json()) as { valid: boolean; identity?: { sub: string; scopes?: string[] } }
    expect(json.valid).toBe(true)
    expect(json.identity?.sub).toBe('user_42')
    expect(json.identity?.scopes).toEqual(['read', 'claim'])
  })

  it('returns 401 for an EXPIRED token', async () => {
    const token = await mint({ sub: 'user_42' }, { expiresIn: -3600 })
    const res = await post({ token })
    expect(res.status).toBe(401)
    const json = (await res.json()) as { valid: boolean; error?: string }
    expect(json.valid).toBe(false)
    expect(json.error).toMatch(/expired/i)
  })

  it('returns 401 for a TAMPERED signature', async () => {
    const token = await mint({ sub: 'user_42' })
    const parts = token.split('.')
    // Same deterministic-tamper fix as the core-primitive test above: flip a
    // full MIDDLE byte after decoding, not the last base64url character
    // (whose trailing padding bits some flips don't actually change).
    const sig = parts[2]!
    const sigBytes = base64UrlToBytes(sig)
    const mid = Math.floor(sigBytes.length / 2)
    sigBytes[mid] = sigBytes[mid]! ^ 0xff
    const tampered = `${parts[0]}.${parts[1]}.${bytesToBase64Url(sigBytes)}`
    const res = await post({ token: tampered })
    expect(res.status).toBe(401)
    const json = (await res.json()) as { valid: boolean }
    expect(json.valid).toBe(false)
  })

  it('returns 401 for a WRONG-issuer token', async () => {
    const token = await mint({ sub: 'user_42' }, { issuer: 'https://evil.example' })
    const res = await post({ token })
    expect(res.status).toBe(401)
    const json = (await res.json()) as { valid: boolean; error?: string }
    expect(json.valid).toBe(false)
    expect(json.error).toMatch(/issuer/i)
  })

  it('returns 400 for a missing/empty token (no throw)', async () => {
    const res = await post({})
    expect(res.status).toBe(400)
    const json = (await res.json()) as { valid: boolean }
    expect(json.valid).toBe(false)
  })

  it('returns 401 for a malformed token', async () => {
    const res = await post({ token: 'not-a-jwt' })
    expect(res.status).toBe(401)
    const json = (await res.json()) as { valid: boolean }
    expect(json.valid).toBe(false)
  })
})
