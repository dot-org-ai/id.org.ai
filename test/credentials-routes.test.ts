/**
 * /credentials/* wire surface — drives the Hono sub-app directly (the
 * aap-routes pattern) and checks the pinned-spec shapes: verify response,
 * structured 402, gate objects, ordered enforcement denials, registry
 * descriptors, and typed 400s.
 */

import { describe, it, expect, vi } from 'vitest'
import { Hono } from 'hono'
import { credentialRoutes } from '../worker/routes/credentials'
import type { Env, Variables } from '../worker/types'
import type { HeldCredentialFact } from '../src/server/services/credential'

function makeApp() {
  const app = new Hono<{ Bindings: Env; Variables: Variables }>()
  app.route('', credentialRoutes)
  return app
}

/** A minimal env whose IDENTITY namespace answers with a fake stub. */
function makeEnv(stub: Record<string, unknown>): Env {
  return {
    IDENTITY: {
      idFromName: vi.fn(() => ({})),
      get: vi.fn(() => stub),
    },
  } as unknown as Env
}

function post(app: ReturnType<typeof makeApp>, path: string, body: unknown, env?: Env) {
  return app.fetch(
    new Request(`https://id.org.ai${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
    env,
  )
}

const SPEC_VERIFY_BODY = {
  credential: { type: 'uspto-registered', registrationNumber: '999999' },
  principal: { id: 'conformance-unknown-principal', workerType: 'human' },
  effectClass: 'act',
}

describe('POST /credentials/verify', () => {
  it('rejects an empty request with 400', async () => {
    const res = await post(makeApp(), '/credentials/verify', {})
    expect(res.status).toBe(400)
  })

  it('rejects an unknown effect class with 400', async () => {
    const res = await post(makeApp(), '/credentials/verify', { ...SPEC_VERIFY_BODY, effectClass: 'teleport' })
    expect(res.status).toBe(400)
  })

  it('answers the pinned verify shape for the uspto-oed registry lookup', async () => {
    const res = await post(makeApp(), '/credentials/verify', SPEC_VERIFY_BODY)
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>
    // Pinned: { live, goodStanding, holder, reps, source, freshness, checkedAt }
    expect(body.live).toBe(false)
    expect(body.goodStanding).toBe(false)
    expect(body.holder).toBeNull()
    expect(Array.isArray(body.reps)).toBe(true)
    expect((body.source as Record<string, unknown>).mode).toBe('registry')
    expect((body.source as Record<string, unknown>).registry).toBe('uspto-oed')
    expect((body.freshness as Record<string, unknown>).cached).toBe(false)
    expect(typeof body.checkedAt).toBe('string')
    // ADR 0018 additions: the verdict tier and cure are surfaced, not hidden.
    expect(body.verdict).toBe('unverifiable-by-registry')
    expect((body.cure as Record<string, unknown>).action).toBe('connect-source')
    expect(body.satisfiesActClass).toBe(false)
  })

  it('discloses the read-class TTL', async () => {
    const res = await post(makeApp(), '/credentials/verify', { ...SPEC_VERIFY_BODY, effectClass: 'read' })
    expect(res.status).toBe(200)
    const body = (await res.json()) as { freshness: { cached: boolean; maxAgeSeconds: number } }
    expect(body.freshness.maxAgeSeconds).toBeGreaterThanOrEqual(0)
  })

  it('answers PSV mode with a structured 402 whose first alternative is the free registry mode', async () => {
    const res = await post(makeApp(), '/credentials/verify', { ...SPEC_VERIFY_BODY, mode: 'psv' })
    expect(res.status).toBe(402)
    const body = (await res.json()) as Record<string, unknown>
    expect(typeof body.id).toBe('string')
    expect(typeof body.title).toBe('string')
    expect(body.price).toBeDefined()
    expect((body.alternatives as Array<{ mode: string }>)[0].mode).toBe('registry')
  })

  it('journals the verification on the principal DO when the binding exists', async () => {
    const recordCredentialVerification = vi.fn(async () => {})
    const env = makeEnv({ recordCredentialVerification })
    const res = await post(makeApp(), '/credentials/verify', SPEC_VERIFY_BODY, env)
    expect(res.status).toBe(200)
    expect(recordCredentialVerification).toHaveBeenCalledTimes(1)
    expect(recordCredentialVerification.mock.calls[0][0]).toMatchObject({
      principalId: 'conformance-unknown-principal',
      registry: 'uspto-oed',
      verdict: 'unverifiable-by-registry',
      effectClass: 'act',
    })
  })
})

describe('GET /credentials/gates/*', () => {
  it('serves the supply gate as an object carrying a jurisdiction', async () => {
    const res = await makeApp().fetch(new Request('https://id.org.ai/credentials/gates/act/file.patent'))
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.act).toBe('file.patent')
    expect((body.requiresSigner as Record<string, unknown>).jurisdiction).toBe('US')
  })

  it('serves the demand gate as an object carrying a jurisdiction', async () => {
    const res = await makeApp().fetch(new Request('https://id.org.ai/credentials/gates/upstream/cm-ecf'))
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.upstream).toBe('cm-ecf')
    expect((body.requiresAccess as Record<string, unknown>).jurisdiction).toBe('US')
  })

  it('404s on unratified acts and upstreams', async () => {
    expect((await makeApp().fetch(new Request('https://id.org.ai/credentials/gates/act/file.wizardry'))).status).toBe(404)
    expect((await makeApp().fetch(new Request('https://id.org.ai/credentials/gates/upstream/narnia'))).status).toBe(404)
  })
})

describe('GET /credentials/registries', () => {
  it('lists the adapter roster with real/stub status', async () => {
    const res = await makeApp().fetch(new Request('https://id.org.ai/credentials/registries'))
    expect(res.status).toBe(200)
    const body = (await res.json()) as { registries: Array<{ id: string; status: string }> }
    expect(body.registries.length).toBe(11)
    const byId = Object.fromEntries(body.registries.map((r) => [r.id, r]))
    expect(byId['mn-dvs-dealer'].status).toBe('real')
    expect(byId['nipr-pdb'].status).toBe('stub')
  })

  it('reports uspto-oed honestly as not ingested until the roster lands', async () => {
    const res = await makeApp().fetch(new Request('https://id.org.ai/credentials/registries/uspto-oed'))
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.id).toBe('uspto-oed')
    expect(body.mode).toBe('registry')
    expect(body.ingested).toBe(false)
    expect(body.practitionerCount).toBe(0)
  })

  it('404s on an unknown registry', async () => {
    expect((await makeApp().fetch(new Request('https://id.org.ai/credentials/registries/hogwarts'))).status).toBe(404)
  })
})

describe('POST /credentials/enforce — ordered gates', () => {
  it('rejects a request naming neither act nor upstream', async () => {
    const res = await post(makeApp(), '/credentials/enforce', {})
    expect(res.status).toBe(400)
  })

  it('denies an agent signer at humanSigner FIRST', async () => {
    const res = await post(makeApp(), '/credentials/enforce', {
      act: 'file.patent',
      signer: { id: 'conformance-agent', workerType: 'agent' },
    })
    expect(res.status).toBe(403)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.denied).toBe(true)
    expect(body.gate).toBe('humanSigner')
  })

  it('denies an uncredentialed human at requiresSigner with the required jurisdiction object', async () => {
    const res = await post(makeApp(), '/credentials/enforce', {
      act: 'file.patent',
      signer: { id: 'conformance-uncredentialed-human', workerType: 'human' },
    })
    expect(res.status).toBe(403)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.denied).toBe(true)
    expect(body.gate).toBe('requiresSigner')
    expect((body.required as Record<string, unknown>).jurisdiction).toBe('US')
  })

  it('denies an unentitled principal at requiresAccess with the required jurisdiction object', async () => {
    const res = await post(makeApp(), '/credentials/enforce', {
      upstream: 'cm-ecf',
      principal: { id: 'conformance-unentitled-human', workerType: 'human' },
    })
    expect(res.status).toBe(403)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.denied).toBe(true)
    expect(body.gate).toBe('requiresAccess')
    expect((body.required as Record<string, unknown>).jurisdiction).toBe('US')
  })

  it('surfaces the stub cure when a held credential cannot be registry-verified', async () => {
    // The signer HOLDS a fact, but the source is unconnected — verification
    // answers unverifiable-by-registry, which must deny AND carry the cure.
    const fact: HeldCredentialFact = {
      principalId: 'user_pat',
      credentialType: 'uspto-registered',
      ref: '99999',
      presented: { type: 'uspto-registered', registrationNumber: '99999' },
      recordedAt: '2026-07-25T00:00:00.000Z',
    }
    const env = makeEnv({ listHeldCredentials: vi.fn(async () => [fact]) })
    const res = await post(makeApp(), '/credentials/enforce', {
      act: 'file.patent',
      signer: { id: 'user_pat', workerType: 'human' },
    }, env)
    expect(res.status).toBe(403)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.gate).toBe('requiresSigner')
    expect((body.cure as Record<string, unknown>).action).toBe('connect-source')
  })

  it('never lets a holder-attested fact clear the supply gate', async () => {
    const fact: HeldCredentialFact = {
      principalId: 'org_dealer1',
      credentialType: 'uspto-registered',
      ref: '100-123',
      presented: { type: 'auction-access-holder-attested', membershipId: '100-123' },
      holderAttested: {
        exportedBy: 'org_dealer1',
        exportedAt: new Date().toISOString(),
        membership: { id: '100-123', status: 'Active' },
        repCards: [],
      },
      recordedAt: '2026-07-25T00:00:00.000Z',
    }
    const env = makeEnv({ listHeldCredentials: vi.fn(async () => [fact]) })
    const res = await post(makeApp(), '/credentials/enforce', {
      act: 'file.patent',
      signer: { id: 'org_dealer1', workerType: 'human' },
    }, env)
    expect(res.status).toBe(403)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.gate).toBe('requiresSigner')
    expect(body.reason).toContain('holder-attested')
  })
})
