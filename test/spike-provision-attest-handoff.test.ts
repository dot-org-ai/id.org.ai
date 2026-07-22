/**
 * DE-RISK SPIKE (bd ax-e6b.17.5) — anon-provision → agent-attest → durable handoff.
 *
 * This is a SPIKE, not a production auth change. It drives the REAL worker
 * routes in-process (via `SELF` from `cloudflare:test`, so IDENTITY DO + KV
 * are wired exactly as production wires them) from a COLD ANONYMOUS start and
 * records every HTTP-seam-observable hop of the handoff:
 *
 *   1. POST /api/provision           (no auth)   → ses_ + clm_ + identityId
 *   2. Ed25519 keypair               (Web Crypto — the primitive id.org.ai uses)
 *   3. POST /agent/register          (ses_ auth) → durable attested agent
 *   4. GET  /agent/status            (ses_ auth) → resolve the attested identity
 *
 * The central question this de-risks: does the ses_ token minted by an
 * anonymous provision satisfy `requireTenant` on /agent/register, or does a
 * durable attested agent require the clm_ claim to be redeemed first (a WorkOS
 * tenant / GitHub claim-by-commit)? The empirical answer is asserted below and
 * written up in docs/spikes/2026-07-22-provision-attest-handoff.md.
 *
 * NOTE: this test drives real auth (nothing is mocked away). It does NOT touch
 * WorkOS/GitHub secrets — the provision→register→status path never needs them.
 */

import { describe, it, expect } from 'vitest'
import { SELF } from 'cloudflare:test'

const BASE = 'https://id.org.ai'

/** Standard base64 of a raw byte array (matches src/sdk/crypto/keys#base64Encode). */
function base64Encode(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}

/** Generate an Ed25519 keypair via Web Crypto — same primitive as
 *  src/sdk/crypto/keys#generateKeypair. Returns the raw 32-byte public key. */
async function generateEd25519(): Promise<{ publicKeyRawB64: string; publicKeyBytes: Uint8Array }> {
  const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
  const raw = new Uint8Array((await crypto.subtle.exportKey('raw', kp.publicKey)) as ArrayBuffer)
  return { publicKeyRawB64: base64Encode(raw), publicKeyBytes: raw }
}

describe('SPIKE: anon-provision -> agent-attest -> durable handoff (real routes)', () => {
  it('drives the full cold-anon handoff and records every hop', async () => {
    const hops: Record<string, unknown> = {}

    // ── HOP 1 — POST /api/provision (NO auth) ────────────────────────────
    const provRes = await SELF.fetch(`${BASE}/api/provision`, { method: 'POST' })
    const prov = (await provRes.json()) as {
      identityId: string
      tenantId: string
      sessionToken: string
      claimToken: string
      level: number
      limits: { maxEntities: number; ttlHours: number; maxRequestsPerMinute: number }
      upgrade: { nextLevel: number; action: string; url: string }
    }
    hops.provision = {
      status: provRes.status,
      identityId: prov.identityId,
      sessionTokenPrefix: prov.sessionToken.slice(0, 4),
      claimTokenPrefix: prov.claimToken.slice(0, 4),
      level: prov.level,
      ttlHours: prov.limits?.ttlHours,
      upgrade: prov.upgrade,
    }

    expect(provRes.status).toBe(201)
    expect(prov.sessionToken.startsWith('ses_')).toBe(true)
    expect(prov.claimToken.startsWith('clm_')).toBe(true)
    expect(prov.identityId).toBeTruthy()
    expect(prov.level).toBe(1)
    expect(prov.limits.ttlHours).toBe(24) // ses_ session lifetime (86_400_000 ms in DO)
    expect(prov.upgrade.action).toBe('claim') // clm_ is the L2 durability gate (30-day KV TTL)

    // ── HOP 2 — Ed25519 keypair (Web Crypto) ─────────────────────────────
    const { publicKeyRawB64, publicKeyBytes } = await generateEd25519()
    hops.keygen = { alg: 'Ed25519', rawPublicKeyBytes: publicKeyBytes.length, publicKeyB64Len: publicKeyRawB64.length }
    expect(publicKeyBytes.length).toBe(32)

    // ── NEGATIVE CONTROL — /agent/register with NO credential → 401 ──────
    const anonReg = await SELF.fetch(`${BASE}/agent/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'anon-agent', mode: 'autonomous', public_key: publicKeyRawB64 }),
    })
    hops.registerNoAuth = { status: anonReg.status, body: await anonReg.json().catch(() => null) }
    expect(anonReg.status).toBe(401) // requireTenant rejects true-anonymous callers

    // ── NEGATIVE CONTROL — clm_ token as bearer is NOT a session cred ────
    // clm_ doesn't match the ses_/api-key extractors, so it reads as "no
    // credential presented" → anonymous → 401. It is the *claim* redemption
    // gate, not a request credential.
    const clmReg = await SELF.fetch(`${BASE}/agent/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${prov.claimToken}` },
      body: JSON.stringify({ name: 'clm-agent', mode: 'autonomous', public_key: publicKeyRawB64 }),
    })
    hops.registerWithClaimToken = { status: clmReg.status }
    expect(clmReg.status).toBe(401)

    // ── HOP 3 — POST /agent/register WITH the ses_ token ─────────────────
    // THE KEY QUESTION: does a provisioned-but-unclaimed ses_ principal
    // satisfy requireTenant? If this is 201, the ses_ token alone yields a
    // durable attested agent (no clm_ redemption required for registration).
    const regRes = await SELF.fetch(`${BASE}/agent/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${prov.sessionToken}` },
      body: JSON.stringify({
        name: 'spike-attested-agent',
        mode: 'autonomous',
        public_key: publicKeyRawB64,
        capabilities: ['read', 'write'],
      }),
    })
    const reg = (await regRes.json()) as {
      agent_id?: string
      host_id?: string
      name?: string
      mode?: string
      status?: string
      agent_capability_grants?: Array<{ capability: string; status: string }>
      error?: string
    }
    hops.registerWithSession = {
      status: regRes.status,
      agent_id: reg.agent_id,
      host_id: reg.host_id,
      agentStatus: reg.status,
      mode: reg.mode,
      grants: reg.agent_capability_grants,
      error: reg.error,
    }

    // THE FINDING: ses_ from anonymous provision DOES satisfy requireTenant.
    expect(regRes.status).toBe(201)
    expect(reg.agent_id).toMatch(/^agent_/)
    expect(reg.host_id).toBe(prov.identityId) // agent is bound to the provisioned tenant
    expect(reg.status).toBe('active') // autonomous → active immediately (attested)
    expect(reg.mode).toBe('autonomous')

    // ── HOP 4 — GET /agent/status (durable attested identity resolves) ───
    const statRes = await SELF.fetch(`${BASE}/agent/status?agent_id=${reg.agent_id}`, {
      headers: { authorization: `Bearer ${prov.sessionToken}` },
    })
    const stat = (await statRes.json()) as {
      agent_id?: string
      host_id?: string
      status?: string
      mode?: string
      created_at?: string
      activated_at?: string
    }
    hops.agentStatus = {
      status: statRes.status,
      agent_id: stat.agent_id,
      host_id: stat.host_id,
      agentStatus: stat.status,
      mode: stat.mode,
      created_at: stat.created_at,
      activated_at: stat.activated_at,
    }
    expect(statRes.status).toBe(200)
    expect(stat.agent_id).toBe(reg.agent_id)
    expect(stat.host_id).toBe(prov.identityId)
    expect(stat.status).toBe('active')

    // Emit the full hop record so `npm test` output is the spike's raw log.
    // eslint-disable-next-line no-console
    console.log('\n[SPIKE ax-e6b.17.5 hop record]\n' + JSON.stringify(hops, null, 2) + '\n')
  })
})
