/**
 * DOGFOOD: id.org.ai passes api.qa's aap-discovery + authmd-agent-identity
 * conformance checks (ax-e6b.21.1) against its OWN shipped metadata + endpoints.
 *
 * The whole worker is exercised in-process via `SELF` (real IDENTITY DO + KV +
 * signing keys). The api.qa judges (src/checks.ts:judgeAapDiscovery,
 * judgeAuthmdAgentIdentity, advertisesIdJag) are not importable cross-repo, so
 * this file ports their SHAPE assertions FAITHFULLY and runs them against the
 * live documents, then behaviourally proves the SECURE trust-anchor model
 * (ax-e6b.21.3 SECURITY FIX):
 *   - a THIRD-PARTY host+jwt / ID-JAG / SET verifies ONLY when its issuer has
 *     a prior AUTHENTICATED registration (POST /agent/host/register) binding
 *     host_id -> {iss, jwks_uri, tenantId} — the verification key is ALWAYS
 *     re-fetched from the REGISTERED jwks_uri, and the tenant bound to a
 *     verified host+jwt is ALWAYS the registered tenant, NEVER a token claim,
 *   - an UNREGISTERED host_id, an ATTACKER-KEY host+jwt/SET (even one that
 *     claims a REAL registered host_id, or that supplies its own
 *     X-AAP-Host-JWKS-URI / X-SET-JWKS-URI header — both now IGNORED), a
 *     forged SET, and a cross-tenant SET subject are ALL rejected
 *     (401/403) — never a silent 202/200,
 *   - the advertisement shape still matches what api.qa's aap-discovery +
 *     authmd checks require.
 *
 * This file previously (pre-ax-e6b.21.3) DEMONSTRATED the bypass: a freshly
 * generated key at an arbitrary caller-advertised JWKS authenticated as
 * `host_tenant_1` with no registration at all. That is exactly what the
 * "REJECTS an unregistered host_id" / "REJECTS an attacker-key host+jwt
 * claiming a registered host_id" tests below now prove is CLOSED.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock } from 'cloudflare:test'

const BASE = 'https://id.org.ai'
const ORIGIN = 'https://id.org.ai'
const IDJAG_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id-jag'
const IDJAG_TYP = 'oauth-id-jag+jwt'
const SET_TYP = 'secevent+jwt'

// The REAL (to-be-registered) host's issuer + JWKS. Public host, SSRF-gated
// fetch is mocked.
const ISSUER = 'https://issuer.example'
const JWKS_PATH = '/.well-known/jwks.json'
const JWKS_URL = `${ISSUER}${JWKS_PATH}`

// An ATTACKER'S OWN issuer + JWKS — never registered. Used to prove that a
// signature valid over the attacker's OWN key (at the attacker's OWN
// advertised JWKS) is NOT sufficient to authenticate as anyone.
const ATTACKER_ISSUER = 'https://attacker.example'
const ATTACKER_JWKS_URL = `${ATTACKER_ISSUER}${JWKS_PATH}`

const REGISTERED_HOST_ID = 'host_tenant_1'

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

/** Standard base64 of a raw byte array (matches src/sdk/crypto/keys#base64Encode). */
function base64Encode(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}

const now = () => Math.floor(Date.now() / 1000)

/** POST /api/provision (no auth) → a fresh ses_ session + tenant identity. */
async function provision(): Promise<{ identityId: string; sessionToken: string }> {
  const res = await SELF.fetch(`${BASE}/api/provision`, { method: 'POST' })
  expect(res.status).toBe(201)
  const body = (await res.json()) as { identityId: string; sessionToken: string }
  return body
}

/** POST /agent/host/register with a ses_ bearer — the ONLY way to onboard a trust anchor. */
async function registerHost(
  sessionToken: string,
  input: { host_id: string; iss: string; jwks_uri: string },
): Promise<Response> {
  return SELF.fetch(`${BASE}/agent/host/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${sessionToken}` },
    body: JSON.stringify(input),
  })
}

let hostKey: CryptoKeyPair
let hostJwkPub: JsonWebKey
let rsaKey: CryptoKeyPair
let rsaJwkPub: JsonWebKey
let attackerHostKey: CryptoKeyPair
let attackerRsaKey: CryptoKeyPair

// The tenant that owns the REGISTERED host_id/iss (set up in beforeAll).
let registeredTenantId: string
let registeredSessionToken: string

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

  attackerHostKey = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
  attackerRsaKey = (await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair
  const attackerRsaJwkPub = await crypto.subtle.exportKey('jwk', attackerRsaKey.publicKey)
  attackerRsaJwkPub.kid = 'attacker-rsa-1'
  const attackerHostJwkPub = await crypto.subtle.exportKey('jwk', attackerHostKey.publicKey)
  attackerHostJwkPub.kid = 'host-ed25519-1' // deliberately claims the SAME kid as the real host

  const jwks = {
    keys: [
      { kty: 'OKP', crv: 'Ed25519', x: hostJwkPub.x, kid: hostJwkPub.kid, use: 'sig' },
      { kty: 'RSA', n: rsaJwkPub.n, e: rsaJwkPub.e, kid: rsaJwkPub.kid, alg: 'RS256', use: 'sig' },
    ],
  }
  const attackerJwks = {
    keys: [
      { kty: 'OKP', crv: 'Ed25519', x: attackerHostJwkPub.x, kid: attackerHostJwkPub.kid, use: 'sig' },
      { kty: 'RSA', n: attackerRsaJwkPub.n, e: attackerRsaJwkPub.e, kid: attackerRsaJwkPub.kid, alg: 'RS256', use: 'sig' },
    ],
  }

  fetchMock.activate()
  fetchMock.disableNetConnect()
  fetchMock
    .get(ISSUER)
    .intercept({ path: JWKS_PATH })
    .reply(200, JSON.stringify(jwks), { headers: { 'content-type': 'application/json' } })
    .persist()
  fetchMock
    .get(ATTACKER_ISSUER)
    .intercept({ path: JWKS_PATH })
    .reply(200, JSON.stringify(attackerJwks), { headers: { 'content-type': 'application/json' } })
    .persist()

  // ── Onboard the trust anchor: an AUTHENTICATED (ses_) call binds
  // REGISTERED_HOST_ID -> {iss: ISSUER, jwks_uri: JWKS_URL} under a real
  // provisioned tenant. Every "secure" test below relies on this having
  // happened FIRST via the real, authenticated endpoint — never a
  // caller-supplied header at verification time.
  const prov = await provision()
  registeredTenantId = prov.identityId
  registeredSessionToken = prov.sessionToken
  const reg = await registerHost(registeredSessionToken, { host_id: REGISTERED_HOST_ID, iss: ISSUER, jwks_uri: JWKS_URL })
  expect(reg.status).toBe(201)
  const regBody = (await reg.json()) as { host_id: string; tenant_id: string }
  expect(regBody.host_id).toBe(REGISTERED_HOST_ID)
  expect(regBody.tenant_id).toBe(registeredTenantId)
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
    // The trust-anchor onboarding endpoint is a real, resolvable endpoint too.
    expect(doc.endpoints.register_host).toBe('/agent/host/register')
    // Honesty: the trust model actually enforced (registered/self-issued),
    // NOT an unqualified claim that any caller-advertised key is trusted.
    const notes = doc.conformance_notes.join(' ')
    expect(notes).toMatch(/registered/i)
    expect(notes).toMatch(/self-issued/i)
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
    // The descriptor no longer offers a caller-suppliable jwks_uri request
    // field — a verification key is never taken from the caller.
    expect(desc.request).not.toHaveProperty('jwks_uri')
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// 3. POST /agent/host/register — the trust-anchor onboarding endpoint
// ─────────────────────────────────────────────────────────────────────────────
describe('dogfood: POST /agent/host/register onboards a trust anchor', () => {
  it('requires ses_/API-key authentication (401 with no credential)', async () => {
    const res = await SELF.fetch(`${BASE}/agent/host/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ host_id: 'nope', iss: ISSUER, jwks_uri: JWKS_URL }),
    })
    expect(res.status).toBe(401)
  })

  it('rejects a private/loopback jwks_uri at REGISTRATION time (SSRF-gated, 400)', async () => {
    const prov = await provision()
    const res = await registerHost(prov.sessionToken, {
      host_id: 'ssrf-host',
      iss: 'https://another-issuer.example',
      jwks_uri: 'http://169.254.169.254/.well-known/jwks.json',
    })
    expect(res.status).toBe(400)
  })

  it('rejects a non-https iss (400)', async () => {
    const prov = await provision()
    const res = await registerHost(prov.sessionToken, {
      host_id: 'bad-iss-host',
      iss: 'http://issuer.example',
      jwks_uri: JWKS_URL,
    })
    expect(res.status).toBe(400)
  })

  it('refuses to let a DIFFERENT tenant hijack an already-registered host_id (409)', async () => {
    const otherProv = await provision()
    const res = await registerHost(otherProv.sessionToken, {
      host_id: REGISTERED_HOST_ID, // already registered to `registeredTenantId` in beforeAll
      iss: 'https://someone-elses-issuer.example',
      jwks_uri: JWKS_URL,
    })
    expect(res.status).toBe(409)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// 4. AAP host+jwt (Ed25519) — trust-anchored verification
// ─────────────────────────────────────────────────────────────────────────────
describe('dogfood: AAP host+jwt (Ed25519) verification is trust-anchored', () => {
  async function mintHost(overrides: Partial<Record<string, unknown>> = {}, tamper = false): Promise<string> {
    return signJwt({
      privateKey: hostKey.privateKey,
      alg: 'EdDSA',
      kid: 'host-ed25519-1',
      tamper,
      payload: { iss: ISSUER, host_id: REGISTERED_HOST_ID, sub: 'agent-runner-1', aud: ORIGIN, iat: now(), exp: now() + 300, ...overrides },
    })
  }
  const hdrs = (jwt: string, extra: Record<string, string> = {}) => ({ 'X-AAP-Host-JWT': jwt, ...extra })

  it('ACCEPTS a valid Ed25519 host+jwt from a REGISTERED host (auth passes → 404 for a missing agent, not 401)', async () => {
    const jwt = await mintHost()
    const res = await SELF.fetch(`${BASE}/agent/status?agent_id=does_not_exist`, { headers: hdrs(jwt) })
    expect(res.status).not.toBe(401)
    expect(res.status).toBe(404)
  })

  it('binds the VERIFIED host+jwt to the REGISTERED tenant (never a token claim)', async () => {
    // Register an agent under the registered tenant via the ses_ path, then
    // resolve it via host+jwt — proving the host+jwt principal lands in the
    // SAME tenant DO as the registered owner.
    const { publicKeyRawB64 } = await (async () => {
      const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
      const raw = new Uint8Array((await crypto.subtle.exportKey('raw', kp.publicKey)) as ArrayBuffer)
      return { publicKeyRawB64: base64Encode(raw) }
    })()
    const regRes = await SELF.fetch(`${BASE}/agent/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${registeredSessionToken}` },
      body: JSON.stringify({ name: 'bound-agent', mode: 'autonomous', public_key: publicKeyRawB64 }),
    })
    expect(regRes.status).toBe(201)
    const reg = (await regRes.json()) as { agent_id: string; host_id: string }
    expect(reg.host_id).toBe(registeredTenantId)

    const jwt = await mintHost()
    const statusRes = await SELF.fetch(`${BASE}/agent/status?agent_id=${reg.agent_id}`, { headers: hdrs(jwt) })
    expect(statusRes.status).toBe(200)
    const status = (await statusRes.json()) as { agent_id: string; host_id: string }
    expect(status.host_id).toBe(registeredTenantId)
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

  it('REJECTS an unsigned (alg=none) host+jwt', async () => {
    const data = `${b64urlJson({ alg: 'none', typ: 'JWT' })}.${b64urlJson({ iss: ISSUER, sub: 's', aud: ORIGIN })}.`
    const res = await SELF.fetch(`${BASE}/agent/status?agent_id=x`, { headers: hdrs(data) })
    expect(res.status).toBe(401)
  })

  // ── bypass-rejection tests (the ax-e6b.21.3 fix) ───────────────────────────

  it('BYPASS CLOSED: REJECTS an UNREGISTERED host_id (401, fail-closed)', async () => {
    const jwt = await signJwt({
      privateKey: hostKey.privateKey,
      alg: 'EdDSA',
      kid: 'host-ed25519-1',
      payload: { iss: ISSUER, host_id: 'never_registered_host', sub: 'x', aud: ORIGIN, iat: now(), exp: now() + 300 },
    })
    const res = await SELF.fetch(`${BASE}/agent/status?agent_id=x`, { headers: hdrs(jwt) })
    expect(res.status).toBe(401)
  })

  it('BYPASS CLOSED: an ATTACKER-KEY host+jwt claiming the REGISTERED host_id is REJECTED (401) — this is the fixed cross-tenant bypass', async () => {
    // The attacker signs with their OWN key (never the real host's key), but
    // claims the REAL registered host_id — the exact shape of the original
    // bug. The registered jwks_uri belongs to the REAL host, so the
    // attacker's signature never matches a key found there.
    const jwt = await signJwt({
      privateKey: attackerHostKey.privateKey,
      alg: 'EdDSA',
      kid: 'host-ed25519-1', // claims the real host's kid — signature still won't verify
      payload: { iss: ISSUER, host_id: REGISTERED_HOST_ID, sub: 'attacker', aud: ORIGIN, iat: now(), exp: now() + 300 },
    })
    const res = await SELF.fetch(`${BASE}/agent/status?agent_id=x`, { headers: hdrs(jwt) })
    expect(res.status).toBe(401)
  })

  it('BYPASS CLOSED: a caller-advertised X-AAP-Host-JWKS-URI is IGNORED — attacker cannot self-vouch its own key (401)', async () => {
    // Attacker signs with their OWN key, claims their OWN issuer (so `iss`
    // does not match the registered host's iss — this alone is fatal), and
    // supplies X-AAP-Host-JWKS-URI pointing at their OWN JWKS (which WOULD
    // validate the signature under the pre-fix code path). The header must
    // now be completely inert.
    const jwt = await signJwt({
      privateKey: attackerHostKey.privateKey,
      alg: 'EdDSA',
      kid: 'host-ed25519-1',
      payload: { iss: ATTACKER_ISSUER, host_id: REGISTERED_HOST_ID, sub: 'attacker', aud: ORIGIN, iat: now(), exp: now() + 300 },
    })
    const res = await SELF.fetch(`${BASE}/agent/status?agent_id=x`, {
      headers: hdrs(jwt, { 'X-AAP-Host-JWKS-URI': ATTACKER_JWKS_URL }),
    })
    expect(res.status).toBe(401)
  })

  it('BYPASS CLOSED: a fresh unregistered keypair + arbitrary caller-chosen host_id/tenant claim is REJECTED (401) — the ORIGINAL bug reproduction', async () => {
    // This is exactly the original bypass: a caller mints a brand-new
    // keypair, hosts (or points to) its own JWKS, and signs a token naming
    // ANY tenant it likes. It must be rejected because that host_id has no
    // registration binding it to this key.
    const rogue = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
    const jwt = await signJwt({
      privateKey: rogue.privateKey,
      alg: 'EdDSA',
      kid: 'rogue-1',
      payload: { iss: ATTACKER_ISSUER, host_id: 'some_victim_tenant', sub: 'attacker', aud: ORIGIN, iat: now(), exp: now() + 300 },
    })
    const res = await SELF.fetch(`${BASE}/agent/status?agent_id=x`, {
      headers: hdrs(jwt, { 'X-AAP-Host-JWKS-URI': ATTACKER_JWKS_URL }),
    })
    expect(res.status).toBe(401)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// 5. /agent/identity — ID-JAG resolution, trust-anchored
// ─────────────────────────────────────────────────────────────────────────────
describe('dogfood: /agent/identity resolves an ID-JAG against a trust anchor only', () => {
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
  const post = (assertion: string) =>
    SELF.fetch(`${BASE}/agent/identity`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ assertion }),
    })

  it('resolves a valid ID-JAG from a REGISTERED issuer', async () => {
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

  it('BYPASS CLOSED: a caller-supplied jwks_uri field is IGNORED — an UNREGISTERED issuer is rejected (401)', async () => {
    const jwt = await signJwt({
      privateKey: attackerRsaKey.privateKey,
      alg: 'RS256',
      kid: 'attacker-rsa-1',
      typ: IDJAG_TYP,
      payload: { iss: ATTACKER_ISSUER, sub: 'attacker', agent_id: 'attacker', aud: ORIGIN, iat: now(), exp: now() + 300 },
    })
    // Even if the request tries to smuggle a jwks_uri, the field is not read.
    const res = await SELF.fetch(`${BASE}/agent/identity`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ assertion: jwt, jwks_uri: ATTACKER_JWKS_URL }),
    })
    expect(res.status).toBe(401)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// 6. /agent/events — SET (RFC 8417) revocation, trust-anchored + tenant-scoped
// ─────────────────────────────────────────────────────────────────────────────
describe('dogfood: /agent/events accepts a SET only from a trust anchor, tenant-scoped', () => {
  async function mintSet(overrides: Partial<Record<string, unknown>> = {}, opts: { typ?: string; tamper?: boolean; key?: CryptoKey; kid?: string } = {}) {
    return signJwt({
      privateKey: opts.key ?? rsaKey.privateKey,
      alg: 'RS256',
      kid: opts.kid ?? 'rsa-1',
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
  const post = (set: string, headers: Record<string, string> = {}) =>
    SELF.fetch(`${BASE}/agent/events`, {
      method: 'POST',
      headers: { 'content-type': 'application/secevent+jwt', ...headers },
      body: set,
    })

  it('accepts a valid SET from a REGISTERED issuer (202)', async () => {
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

  it('rejects a tampered SET (401 — a signature failure, like host+jwt/ID-JAG)', async () => {
    const res = await post(await mintSet({}, { tamper: true }))
    expect(res.status).toBe(401)
  })

  it('BYPASS CLOSED: a forged SET from an UNREGISTERED issuer is rejected (401), never a silent 202', async () => {
    const forged = await signJwt({
      privateKey: attackerRsaKey.privateKey,
      alg: 'RS256',
      kid: 'attacker-rsa-1',
      typ: SET_TYP,
      payload: {
        iss: ATTACKER_ISSUER,
        aud: ORIGIN,
        iat: now(),
        jti: 'forged-1',
        events: { 'https://id.org.ai/secevent/session-revoked': { reason: 'forged' } },
      },
    })
    const res = await post(forged)
    expect(res.status).toBe(401)
  })

  it('BYPASS CLOSED: a caller-supplied X-SET-JWKS-URI is IGNORED — an attacker-signed SET claiming the registered iss is rejected (401)', async () => {
    // Claims the REAL registered iss, but is signed by the ATTACKER's key —
    // the pre-fix code would have honored X-SET-JWKS-URI and accepted this.
    const forged = await mintSet({}, { key: attackerRsaKey.privateKey, kid: 'rsa-1' })
    const res = await post(forged, { 'X-SET-JWKS-URI': ATTACKER_JWKS_URL })
    expect(res.status).toBe(401)
  })

  it('BYPASS CLOSED: a cross-tenant SET subject is REJECTED (403), never silently revoked', async () => {
    // A SECOND, independent tenant with its own agent.
    const otherProv = await provision()
    const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
    const raw = new Uint8Array((await crypto.subtle.exportKey('raw', kp.publicKey)) as ArrayBuffer)
    const regRes = await SELF.fetch(`${BASE}/agent/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${otherProv.sessionToken}` },
      body: JSON.stringify({ name: 'other-tenant-agent', mode: 'autonomous', public_key: base64Encode(raw) }),
    })
    expect(regRes.status).toBe(201)
    const otherAgent = (await regRes.json()) as { agent_id: string; host_id: string }
    expect(otherAgent.host_id).toBe(otherProv.identityId)
    expect(otherProv.identityId).not.toBe(registeredTenantId)

    // A SET, correctly signed by the REGISTERED (tenant-A) issuer, targets
    // the OTHER tenant's agent as its subject.
    const set = await mintSet({ sub_id: { format: 'complex', agent_id: otherAgent.agent_id } })
    const res = await post(set)
    expect(res.status).toBe(403)

    // The subject agent must be UNCHANGED (never revoked cross-tenant).
    const statusRes = await SELF.fetch(`${BASE}/agent/status?agent_id=${otherAgent.agent_id}`, {
      headers: { authorization: `Bearer ${otherProv.sessionToken}` },
    })
    const status = (await statusRes.json()) as { status: string }
    expect(status.status).toBe('active')
  })

  it('a REGISTERED issuer CAN revoke an agent that genuinely belongs to its OWN tenant (202)', async () => {
    const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
    const raw = new Uint8Array((await crypto.subtle.exportKey('raw', kp.publicKey)) as ArrayBuffer)
    const regRes = await SELF.fetch(`${BASE}/agent/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${registeredSessionToken}` },
      body: JSON.stringify({ name: 'own-tenant-agent', mode: 'autonomous', public_key: base64Encode(raw) }),
    })
    expect(regRes.status).toBe(201)
    const ownAgent = (await regRes.json()) as { agent_id: string; host_id: string }
    expect(ownAgent.host_id).toBe(registeredTenantId)

    const set = await mintSet({ sub_id: { format: 'complex', agent_id: ownAgent.agent_id } })
    const res = await post(set)
    expect(res.status).toBe(202)

    const statusRes = await SELF.fetch(`${BASE}/agent/status?agent_id=${ownAgent.agent_id}`, {
      headers: { authorization: `Bearer ${registeredSessionToken}` },
    })
    const status = (await statusRes.json()) as { status: string }
    expect(status.status).toBe('revoked')
  })
})
