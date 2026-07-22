/**
 * DOGFOOD: id.org.ai passes api.qa's aap-discovery + authmd-agent-identity
 * conformance checks (ax-e6b.21.1) against its OWN shipped metadata + endpoints.
 *
 * The whole worker is exercised in-process via `SELF` (real IDENTITY DO + KV +
 * signing keys). The api.qa judges (src/checks.ts:judgeAapDiscovery,
 * judgeAuthmdAgentIdentity, advertisesIdJag) are not importable cross-repo, so
 * this file ports their SHAPE assertions FAITHFULLY and runs them against the
 * live documents, then behaviourally proves:
 *   - AAP host+jwt (EdDSA/Ed25519) is accepted + fail-closed (bad sig / exp /
 *     wrong-aud / wrong-key → 401),
 *   - /agent/identity verifies an ID-JAG and rejects a bad one,
 *   - /agent/events verifies a SET (RFC 8417) and rejects a bad one,
 *   - the caller-advertised jwks_uri fetch is SSRF-safe (private/http refused).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock } from 'cloudflare:test'

const BASE = 'https://id.org.ai'
const ORIGIN = 'https://id.org.ai'
const IDJAG_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id-jag'
const IDJAG_TYP = 'oauth-id-jag+jwt'
const SET_TYP = 'secevent+jwt'

// External mock issuer whose JWKS the worker fetches (SSRF-gated). Public host.
const ISSUER = 'https://issuer.example'
const JWKS_PATH = '/.well-known/jwks.json'
const JWKS_URL = `${ISSUER}${JWKS_PATH}`

// ── tiny JOSE mint helpers (test-only) ───────────────────────────────────────
function b64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}
function b64urlJson(obj: unknown): string {
  return b64url(new TextEncoder().encode(JSON.stringify(obj)))
}

async function signJwt(opts: {
  privateKey: CryptoKey
  alg: 'EdDSA' | 'RS256'
  typ?: string
  kid?: string
  payload: Record<string, unknown>
  tamper?: boolean
}): Promise<string> {
  const header: Record<string, unknown> = { alg: opts.alg }
  if (opts.typ) header.typ = opts.typ
  if (opts.kid) header.kid = opts.kid
  const data = `${b64urlJson(header)}.${b64urlJson(opts.payload)}`
  const algParams = opts.alg === 'EdDSA' ? { name: 'Ed25519' } : { name: 'RSASSA-PKCS1-v1_5' }
  const sig = new Uint8Array(await crypto.subtle.sign(algParams, opts.privateKey, new TextEncoder().encode(data)))
  if (opts.tamper) sig[sig.length - 1] ^= 0xff
  return `${data}.${b64url(sig)}`
}

const now = () => Math.floor(Date.now() / 1000)

let hostKey: CryptoKeyPair
let hostJwkPub: JsonWebKey
let rsaKey: CryptoKeyPair
let rsaJwkPub: JsonWebKey

beforeAll(async () => {
  hostKey = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
  hostJwkPub = await crypto.subtle.exportKey('jwk', hostKey.publicKey)
  hostJwkPub.kid = 'host-ed25519-1'

  rsaKey = (await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair
  rsaJwkPub = await crypto.subtle.exportKey('jwk', rsaKey.publicKey)
  rsaJwkPub.kid = 'rsa-1'

  const jwks = {
    keys: [
      { kty: 'OKP', crv: 'Ed25519', x: hostJwkPub.x, kid: hostJwkPub.kid, use: 'sig' },
      { kty: 'RSA', n: rsaJwkPub.n, e: rsaJwkPub.e, kid: rsaJwkPub.kid, alg: 'RS256', use: 'sig' },
    ],
  }

  fetchMock.activate()
  fetchMock.disableNetConnect()
  fetchMock
    .get(ISSUER)
    .intercept({ path: JWKS_PATH })
    .reply(200, JSON.stringify(jwks), { headers: { 'content-type': 'application/json' } })
    .persist()
})

afterAll(() => {
  fetchMock.deactivate()
})

// ── faithful ports of the api.qa judges (advertisement/shape-grade) ─────────
function originOf(u: string): string | undefined {
  try {
    return new URL(u).origin
  } catch {
    return undefined
  }
}
function isAbsoluteHttpsUrl(v: unknown): boolean {
  if (typeof v !== 'string' || v.trim().length === 0) return false
  try {
    return new URL(v).protocol === 'https:'
  } catch {
    return false
  }
}
function resolveHttpsUrl(v: unknown, base?: string): URL | undefined {
  if (typeof v !== 'string' || v.trim().length === 0) return undefined
  try {
    const u = new URL(v, base)
    return u.protocol === 'https:' ? u : undefined
  } catch {
    return undefined
  }
}
function judgeAapDiscovery(doc: any): string[] {
  const problems: string[] = []
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return ['not a JSON object']
  for (const key of ['version', 'issuer', 'provider_name']) {
    if (typeof doc[key] !== 'string' || !doc[key].trim()) problems.push(`${key} missing`)
  }
  const algs = Array.isArray(doc.algorithms) ? doc.algorithms : []
  if (!algs.includes('Ed25519')) problems.push('algorithms lacks Ed25519')
  const approvals = Array.isArray(doc.approval_methods) ? doc.approval_methods : []
  if (approvals.filter((a: unknown) => typeof a === 'string' && a.trim()).length === 0) {
    problems.push('approval_methods has no usable string')
  }
  const issuer = typeof doc.issuer === 'string' ? doc.issuer.trim() : undefined
  const issuerOrigin = issuer ? originOf(issuer) : undefined
  const endpoints = doc.endpoints && typeof doc.endpoints === 'object' && !Array.isArray(doc.endpoints) ? doc.endpoints : undefined
  if (!endpoints) problems.push('endpoints missing')
  else {
    for (const key of ['register', 'status', 'revoke']) {
      const resolved = resolveHttpsUrl(endpoints[key], issuer)
      if (!resolved) problems.push(`endpoints.${key} not https`)
      else if (!issuerOrigin || resolved.origin !== issuerOrigin) problems.push(`endpoints.${key} off-origin`)
    }
  }
  if (!resolveHttpsUrl(doc.jwks_uri, issuer)) problems.push('jwks_uri not https')
  return problems
}
function advertisesIdJag(asMeta: any, agentAuth: any): boolean {
  const pool: unknown[] = []
  const collect = (o: any, keys: string[]) => {
    if (!o || typeof o !== 'object') return
    for (const k of keys) {
      const v = o[k]
      if (typeof v === 'string') pool.push(v)
      else if (Array.isArray(v)) for (const e of v) if (typeof e === 'string') pool.push(e)
    }
  }
  collect(asMeta, ['subject_token_types_supported'])
  collect(agentAuth, ['subject_token_types', 'subject_token_types_supported', 'accepted_assertion_types', 'assertion_types'])
  return pool.some((v) => v === IDJAG_TOKEN_TYPE || v === IDJAG_TYP)
}
function judgeAuthmd(agentAuth: any, asMeta: any): string[] {
  const problems: string[] = []
  if (!agentAuth || typeof agentAuth !== 'object' || Array.isArray(agentAuth)) return ['agent_auth defective']
  for (const key of ['identity_endpoint', 'claim_endpoint']) {
    if (!isAbsoluteHttpsUrl(agentAuth[key])) problems.push(`agent_auth.${key} not https`)
  }
  if (!isAbsoluteHttpsUrl(agentAuth.events_endpoint)) problems.push('agent_auth.events_endpoint not https')
  if (!advertisesIdJag(asMeta, agentAuth)) problems.push('ID-JAG not advertised')
  return problems
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. AAP discovery (aap-discovery check)
// ─────────────────────────────────────────────────────────────────────────────
describe('dogfood: AAP discovery passes api.qa aap-discovery', () => {
  it('advertises Ed25519 + honest approval_methods + register/status/revoke + jwks_uri', async () => {
    const res = await SELF.fetch(`${BASE}/.well-known/agent-configuration`)
    expect(res.status).toBe(200)
    const doc = (await res.json()) as any
    expect(judgeAapDiscovery(doc)).toEqual([])
    // Honest approval_methods: NOT device_authorization (a ceremony we don't run).
    expect(doc.approval_methods).not.toContain('device_authorization')
    expect(doc.approval_methods).toContain('claim_by_commit')
    // identity/events/claim endpoints advertised (not null stubs).
    expect(doc.endpoints.identity).toBe('/agent/identity')
    expect(doc.endpoints.events).toBe('/agent/events')
    expect(doc.endpoints.claim).toBe('/api/claim')
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// 2. auth.md agent-identity (authmd-agent-identity check)
// ─────────────────────────────────────────────────────────────────────────────
describe('dogfood: RFC 8414 metadata passes api.qa authmd-agent-identity', () => {
  it('carries a well-formed agent_auth block + ID-JAG advertisement, and identity_endpoint RESOLVES', async () => {
    const res = await SELF.fetch(`${BASE}/.well-known/oauth-authorization-server`)
    expect(res.status).toBe(200)
    const asMeta = (await res.json()) as any
    const agentAuth = asMeta.agent_auth
    expect(agentAuth).toBeTruthy()
    expect(judgeAuthmd(agentAuth, asMeta)).toEqual([])
    expect(agentAuth.identity_endpoint).toBe(`${ORIGIN}/agent/identity`)
    expect(agentAuth.claim_endpoint).toBe(`${ORIGIN}/api/claim`)
    expect(agentAuth.events_endpoint).toBe(`${ORIGIN}/agent/events`)
    expect(advertisesIdJag(asMeta, agentAuth)).toBe(true)

    // The declared identity_endpoint must RESOLVE (probe: not 404/5xx).
    const probe = await SELF.fetch(agentAuth.identity_endpoint)
    expect(probe.status).toBe(200)
    const desc = (await probe.json()) as any
    expect(desc.accepted_token_type).toBe(IDJAG_TOKEN_TYPE)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// 3. AAP host+jwt (EdDSA/Ed25519) — accepted + fail-closed
// ─────────────────────────────────────────────────────────────────────────────
describe('dogfood: AAP host+jwt (Ed25519) verification', () => {
  const hdrs = (jwt: string) => ({ 'X-AAP-Host-JWT': jwt, 'X-AAP-Host-JWKS-URI': JWKS_URL })

  async function mintHost(overrides: Partial<Record<string, unknown>> = {}, tamper = false): Promise<string> {
    return signJwt({
      privateKey: hostKey.privateKey,
      alg: 'EdDSA',
      kid: 'host-ed25519-1',
      tamper,
      payload: { iss: ISSUER, sub: 'host_tenant_1', aud: ORIGIN, iat: now(), exp: now() + 300, ...overrides },
    })
  }

  it('ACCEPTS a valid Ed25519 host+jwt (auth passes → 404 for a missing agent, not 401)', async () => {
    const jwt = await mintHost()
    const res = await SELF.fetch(`${BASE}/agent/status?agent_id=does_not_exist`, { headers: hdrs(jwt) })
    expect(res.status).not.toBe(401)
    expect(res.status).toBe(404)
  })

  it('REJECTS a tampered signature (fail-closed 401)', async () => {
    const jwt = await mintHost({}, true)
    const res = await SELF.fetch(`${BASE}/agent/status?agent_id=x`, { headers: hdrs(jwt) })
    expect(res.status).toBe(401)
  })

  it('REJECTS an expired host+jwt', async () => {
    const jwt = await mintHost({ exp: now() - 600, iat: now() - 1200 })
    const res = await SELF.fetch(`${BASE}/agent/status?agent_id=x`, { headers: hdrs(jwt) })
    expect(res.status).toBe(401)
  })

  it('REJECTS a wrong-audience host+jwt', async () => {
    const jwt = await mintHost({ aud: 'https://evil.example' })
    const res = await SELF.fetch(`${BASE}/agent/status?agent_id=x`, { headers: hdrs(jwt) })
    expect(res.status).toBe(401)
  })

  it('REJECTS a host+jwt signed by a key absent from the JWKS', async () => {
    const rogue = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
    const jwt = await signJwt({
      privateKey: rogue.privateKey,
      alg: 'EdDSA',
      kid: 'host-ed25519-1', // claims a listed kid, but signature won't match
      payload: { iss: ISSUER, sub: 'host_tenant_1', aud: ORIGIN, iat: now(), exp: now() + 300 },
    })
    const res = await SELF.fetch(`${BASE}/agent/status?agent_id=x`, { headers: hdrs(jwt) })
    expect(res.status).toBe(401)
  })

  it('REJECTS an unsigned (alg=none) host+jwt', async () => {
    const data = `${b64urlJson({ alg: 'none', typ: 'JWT' })}.${b64urlJson({ iss: ISSUER, sub: 's', aud: ORIGIN })}.`
    const res = await SELF.fetch(`${BASE}/agent/status?agent_id=x`, { headers: hdrs(data) })
    expect(res.status).toBe(401)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// 4. /agent/identity — ID-JAG resolution (verify + reject)
// ─────────────────────────────────────────────────────────────────────────────
describe('dogfood: /agent/identity resolves an ID-JAG', () => {
  async function mintIdJag(overrides: Partial<Record<string, unknown>> = {}, opts: { typ?: string; tamper?: boolean } = {}) {
    return signJwt({
      privateKey: rsaKey.privateKey,
      alg: 'RS256',
      kid: 'rsa-1',
      typ: opts.typ ?? IDJAG_TYP,
      tamper: opts.tamper,
      payload: { iss: ISSUER, sub: 'agent:crm-1', aud: ORIGIN, iat: now(), exp: now() + 300, agent_id: 'agent:crm-1', ...overrides },
    })
  }
  const post = (assertion: string, jwks_uri: string = JWKS_URL) =>
    SELF.fetch(`${BASE}/agent/identity`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ assertion, jwks_uri }),
    })

  it('resolves a valid ID-JAG', async () => {
    const res = await post(await mintIdJag())
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.resolved).toBe(true)
    expect(body.sub).toBe('agent:crm-1')
    expect(body.token_type).toBe(IDJAG_TOKEN_TYPE)
  })

  it('rejects an assertion with the wrong typ (400)', async () => {
    const res = await post(await mintIdJag({}, { typ: 'JWT' }))
    expect(res.status).toBe(400)
  })

  it('rejects a tampered ID-JAG (401)', async () => {
    const res = await post(await mintIdJag({}, { tamper: true }))
    expect(res.status).toBe(401)
  })

  it('rejects an expired ID-JAG (401)', async () => {
    const res = await post(await mintIdJag({ exp: now() - 600, iat: now() - 1200 }))
    expect(res.status).toBe(401)
  })

  it('rejects a wrong-audience ID-JAG (401)', async () => {
    const res = await post(await mintIdJag({ aud: 'https://evil.example' }))
    expect(res.status).toBe(401)
  })

  it('SSRF: refuses a private/http jwks_uri without fetching (400)', async () => {
    const res = await post(await mintIdJag(), 'http://169.254.169.254/.well-known/jwks.json')
    expect(res.status).toBe(400)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// 5. /agent/events — SET (RFC 8417) revocation (verify + reject)
// ─────────────────────────────────────────────────────────────────────────────
describe('dogfood: /agent/events accepts a SET for revocation', () => {
  async function mintSet(overrides: Partial<Record<string, unknown>> = {}, opts: { typ?: string; tamper?: boolean } = {}) {
    return signJwt({
      privateKey: rsaKey.privateKey,
      alg: 'RS256',
      kid: 'rsa-1',
      typ: opts.typ ?? SET_TYP,
      tamper: opts.tamper,
      payload: {
        iss: ISSUER,
        aud: ORIGIN,
        iat: now(),
        jti: `set-${Math.random().toString(36).slice(2)}`,
        events: { 'https://id.org.ai/secevent/session-revoked': { reason: 'test' } },
        ...overrides,
      },
    })
  }
  const post = (set: string) =>
    SELF.fetch(`${BASE}/agent/events`, {
      method: 'POST',
      headers: { 'content-type': 'application/secevent+jwt', 'X-SET-JWKS-URI': JWKS_URL },
      body: set,
    })

  it('accepts a valid SET (202)', async () => {
    const res = await post(await mintSet())
    expect(res.status).toBe(202)
  })

  it('rejects a SET with no events claim (400)', async () => {
    const res = await post(await mintSet({ events: undefined }))
    expect(res.status).toBe(400)
  })

  it('rejects a wrong-typ SET (400)', async () => {
    const res = await post(await mintSet({}, { typ: 'JWT' }))
    expect(res.status).toBe(400)
  })

  it('rejects a tampered SET (400)', async () => {
    const res = await post(await mintSet({}, { tamper: true }))
    expect(res.status).toBe(400)
  })
})
