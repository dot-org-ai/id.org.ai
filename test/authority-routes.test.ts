/**
 * The `/authority/*` HTTP surface.
 *
 * These tests run the real router against a real service over in-memory
 * storage, with only the tenant/principal resolution faked -- so what is
 * asserted here is the HTTP contract: the RFC 9457 shape, the status codes,
 * and the two routes that deliberately require no session.
 *
 * The poison cases are the ones that matter: a body that tries to name its own
 * tenant, its own actor, or its own settling human. Each of those is a way one
 * caller writes an authority record in another's name, and each is refused by
 * construction rather than by validation -- the route never reads those fields
 * off the body at all.
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { MemoryStorageAdapter } from '../src/sdk/storage'
import { AuthorityServiceImpl, MemoryActionSink } from '../src/server/services/authority/service'
import { createAuthorityRoutes, ERRORS_BASE } from '../worker/routes/authority'
import type { AuthorityResolver } from '../worker/routes/authority'
import type { Scope } from '../src/server/services/authority/types'

const TENANT = 'tenant_acme'
const KIM = 'human:seat_kim'
const AGENT = 'agent_7f3a'
const NOW = new Date('2026-08-05T12:00:00.000Z')
const IN_AN_HOUR = '2026-08-05T13:00:00.000Z'
const IN_A_DAY = '2026-08-06T12:00:00.000Z'

const SCOPE: Scope = { grants: [{ verb: 'epcis.capture', resource: 'gtin/09506000134376' }] }

let storage: MemoryStorageAdapter
let sink: MemoryActionSink
let svc: AuthorityServiceImpl
let app: ReturnType<typeof createAuthorityRoutes>

/**
 * The fake only decides WHO is calling. Everything below it is the real
 * service, so a route that quietly trusted the body would fail these tests.
 */
function resolver(): AuthorityResolver {
  return {
    async forCaller(c) {
      const principal = c.req.header('x-test-principal')
      if (!principal) return null
      return { service: svc, tenantId: TENANT, principal }
    },
    async forTenant(_c, tenantId) {
      // A tenant this deployment does not serve resolves to nothing.
      return tenantId === TENANT ? { service: svc } : null
    },
  }
}

beforeEach(() => {
  storage = new MemoryStorageAdapter()
  sink = new MemoryActionSink()
  svc = new AuthorityServiceImpl({ storage, actions: sink, now: () => NOW, origin: 'https://id.org.ai' })
  app = createAuthorityRoutes(resolver())
})

async function post(path: string, body: unknown, principal?: string) {
  return app.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(principal ? { 'x-test-principal': principal } : {}) },
    body: JSON.stringify(body),
  })
}

async function get(path: string, principal?: string) {
  return app.request(path, { headers: principal ? { 'x-test-principal': principal } : {} })
}

async function seedAsk(askId = 'ask_1') {
  const res = await post(
    '/authority/ask',
    { askId, requestedBy: AGENT, onBehalfOf: KIM, scope: SCOPE, expiresAt: IN_AN_HOUR, createdAt: NOW.toISOString() },
    KIM,
  )
  expect(res.status).toBe(201)
}

async function seedGrant(askId = 'ask_1') {
  await seedAsk(askId)
  const res = await post(
    '/authority/grant',
    {
      subject: { kind: 'agent', id: AGENT },
      scope: SCOPE,
      expiresAt: IN_A_DAY,
      fromAsk: { askId, settledBy: KIM, askedScope: SCOPE },
    },
    KIM,
  )
  expect(res.status).toBe(201)
  return (await res.json()) as { grant: { id: string }; revokeToken: string; claimToken: string | null }
}

// ============================================================================

describe('the RFC 9457 error face', () => {
  it('serves application/problem+json with a dereferenceable type', async () => {
    const res = await get('/authority/introspect?grant=grant_ghost', KIM)
    expect(res.status).toBe(404)
    expect(res.headers.get('content-type')).toContain('application/problem+json')
    const body = (await res.json()) as Record<string, unknown>
    expect(body.type).toBe(`${ERRORS_BASE}/grant-not-found`)
    expect(body.status).toBe(404)
    expect(body.door).toBe('id.org.ai')
    expect(body.verb).toBe('introspect')
    expect(body.retryable).toBe(false)
    expect(body.costed).toBe(false)
    expect(typeof body.title).toBe('string')
    expect(typeof body.detail).toBe('string')
  })

  it('marks a retryable condition as retryable', async () => {
    const res = await get('/authority/introspect?grant=x')
    expect(res.status).toBe(401)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.type).toBe(`${ERRORS_BASE}/authz-expired`)
    expect(body.retryable).toBe(true)
  })

  it('never costs a caller for a refusal', async () => {
    await seedAsk()
    const res = await post('/authority/refuse', { askId: 'ask_1', cause: 'made up' }, KIM)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.type).toBe(`${ERRORS_BASE}/refusal-cause-unknown`)
    expect(body.costed).toBe(false)
  })
})

describe('the tenant and the actor come from the session, never from the body', () => {
  it('ignores a body-supplied tenantId', async () => {
    await seedAsk()
    const res = await post(
      '/authority/grant',
      {
        tenantId: 'tenant_somebody_else',
        subject: { kind: 'agent', id: AGENT },
        scope: SCOPE,
        expiresAt: IN_A_DAY,
        fromAsk: { askId: 'ask_1', settledBy: KIM, askedScope: SCOPE },
      },
      KIM,
    )
    expect(res.status).toBe(201)
    const body = (await res.json()) as { grant: { tenantId: string } }
    expect(body.grant.tenantId).toBe(TENANT)
  })

  it('ignores a body-supplied actor', async () => {
    await seedAsk()
    const res = await post(
      '/authority/grant',
      {
        actor: 'human:seat_impostor',
        subject: { kind: 'agent', id: AGENT },
        scope: SCOPE,
        expiresAt: IN_A_DAY,
        fromAsk: { askId: 'ask_1', settledBy: KIM, askedScope: SCOPE },
      },
      KIM,
    )
    expect(res.status).toBe(201)
    expect(sink.byName('authority.mint')[0].actor).toBe(KIM)
  })

  it('records a refusal against the SESSION, so nobody declines in another name', async () => {
    await seedAsk()
    const res = await post(
      '/authority/refuse',
      { askId: 'ask_1', refusedBy: 'human:seat_somebody_else', cause: 'policy' },
      KIM,
    )
    expect(res.status).toBe(200)
    const body = (await res.json()) as { refusal: { refusedBy: string } }
    expect(body.refusal.refusedBy).toBe(KIM)
  })

  it('refuses an agent principal as a settling human', async () => {
    await seedAsk()
    const res = await post('/authority/refuse', { askId: 'ask_1', cause: 'policy' }, AGENT)
    expect(res.status).toBe(403)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.type).toBe(`${ERRORS_BASE}/not-the-warrantor`)
  })
})

describe('the seatless revoke address (REQ-7)', () => {
  it('revokes with NO session, NO key and NO seat', async () => {
    const minted = await seedGrant()
    // No `x-test-principal` header at all: nothing here authenticates a caller.
    const res = await post(
      `/authority/revoke/${TENANT}/${minted.grant.id}`,
      { revokeToken: minted.revokeToken },
      undefined,
    )
    expect(res.status).toBe(200)
    const body = (await res.json()) as { alreadyRevoked: boolean; revoke: { disclosure: string } }
    expect(body.alreadyRevoked).toBe(false)
    expect(body.revoke.disclosure).toContain('cannot retract what has already been read')
  })

  it('accepts the secret as a query parameter, for a one-click link', async () => {
    const minted = await seedGrant()
    const res = await post(`/authority/revoke/${TENANT}/${minted.grant.id}?t=${minted.revokeToken}`, {}, undefined)
    expect(res.status).toBe(200)
  })

  it('refuses with no secret at all -- the address is not the credential', async () => {
    const minted = await seedGrant()
    const res = await post(`/authority/revoke/${TENANT}/${minted.grant.id}`, {}, undefined)
    expect(res.status).toBe(403)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.type).toBe(`${ERRORS_BASE}/not-the-warrantor`)
  })

  it('refuses a wrong secret', async () => {
    const minted = await seedGrant()
    const res = await post(
      `/authority/revoke/${TENANT}/${minted.grant.id}`,
      { revokeToken: 'rvk_' + '0'.repeat(48) },
      undefined,
    )
    expect(res.status).toBe(403)
  })

  it('reports an unserved tenant as MISSING rather than confirming the grant', async () => {
    const minted = await seedGrant()
    const res = await post(
      `/authority/revoke/tenant_globex/${minted.grant.id}`,
      { revokeToken: minted.revokeToken },
      undefined,
    )
    expect(res.status).toBe(404)
  })

  // The property under test is that no handler except the seatless revoke ever
  // consults a revoke secret. Black-box: presenting it as a query parameter, as
  // a bearer header and in a body opens nothing.
  it('presenting the revoke secret anywhere else grants nothing', async () => {
    const minted = await seedGrant()
    // Presented everywhere a bearer credential might be honoured.
    const asQuery = await get(`/authority/introspect?grant=${minted.grant.id}&t=${minted.revokeToken}`)
    expect(asQuery.status).toBe(401)
    const asHeader = await app.request(`/authority/grants`, {
      headers: { authorization: `Bearer ${minted.revokeToken}` },
    })
    expect(asHeader.status).toBe(401)
    const asBody = await post('/authority/grant', { revokeToken: minted.revokeToken }, undefined)
    expect(asBody.status).toBe(401)
  })
})

describe('the keyless claim address (REQ-9)', () => {
  it('claims a pending grant with no session', async () => {
    await seedAsk('ask_pending')
    const mintRes = await post(
      '/authority/grant',
      {
        subject: { kind: 'pending', hint: 'kim@acme.example' },
        scope: SCOPE,
        expiresAt: IN_A_DAY,
        fromAsk: { askId: 'ask_pending', settledBy: KIM, askedScope: SCOPE },
      },
      KIM,
    )
    const minted = (await mintRes.json()) as { grant: { id: string; status: string }; claimToken: string }
    expect(minted.grant.status).toBe('pending')

    const res = await post(
      '/authority/claim',
      {
        tenantId: TENANT,
        grantId: minted.grant.id,
        claimToken: minted.claimToken,
        subject: { kind: 'human', id: 'human:seat_new' },
      },
      undefined,
    )
    expect(res.status).toBe(200)
    const claimed = (await res.json()) as { grant: { status: string; claimUrl: string | null } }
    expect(claimed.grant.status).toBe('active')
    expect(claimed.grant.claimUrl).toBeNull()
  })

  it('refuses an incomplete claim without touching the store', async () => {
    const res = await post('/authority/claim', { tenantId: TENANT }, undefined)
    expect(res.status).toBe(403)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.type).toBe(`${ERRORS_BASE}/claim-token-invalid`)
  })
})

describe('reads', () => {
  it('requires a ?grant= on introspect and says so', async () => {
    const res = await get('/authority/introspect', KIM)
    expect(res.status).toBe(404)
    expect((await res.json()).detail).toContain('?grant=')
  })

  it('introspects a chain to its human root', async () => {
    const minted = await seedGrant()
    const res = await get(`/authority/introspect?grant=${minted.grant.id}`, KIM)
    expect(res.status).toBe(200)
    const body = (await res.json()) as {
      chain: { principal: string | null }[]
      chainComplete: boolean
      rootsAtHuman: boolean
      revoke: { address: string; seatRequired: boolean }
    }
    expect(body.chain.map((h) => h.principal)).toEqual([AGENT, KIM])
    expect(body.chainComplete).toBe(true)
    expect(body.rootsAtHuman).toBe(true)
    expect(body.revoke.seatRequired).toBe(false)
    expect(body.revoke.address).toContain(`/authority/revoke/${TENANT}/${minted.grant.id}`)
  })

  it('lists standing authority and paginates without a total', async () => {
    await seedGrant()
    const res = await get('/authority/grants', KIM)
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>
    expect(Object.keys(body)).toEqual(['grants', 'cursor', 'revoke', 'asOf'])
  })

  it('reports an unasked settlement as 200 unasked, not as a 404', async () => {
    const res = await get('/authority/settlement/ask_never', KIM)
    expect(res.status).toBe(200)
    const body = (await res.json()) as { state: string }
    // `unasked` and `refused` are different facts and both are answers.
    expect(body.state).toBe('unasked')
  })

  it('reports a refusal as a settled decision an agent can read', async () => {
    await seedAsk('ask_r')
    await post('/authority/refuse', { askId: 'ask_r', cause: 'scope-too-wide' }, KIM)
    const res = await get('/authority/settlement/ask_r', KIM)
    const body = (await res.json()) as { state: string; cause: string; settledBy: string }
    expect(body.state).toBe('refused')
    expect(body.cause).toBe('scope-too-wide')
    expect(body.settledBy).toBe(KIM)
  })
})

describe('every authenticated route refuses an unauthenticated caller', () => {
  const routes: [string, 'GET' | 'POST'][] = [
    ['/authority/ask', 'POST'],
    ['/authority/grant', 'POST'],
    ['/authority/refuse', 'POST'],
    ['/authority/authorize', 'POST'],
    ['/authority/introspect?grant=x', 'GET'],
    ['/authority/grants', 'GET'],
    ['/authority/settlement/ask_1', 'GET'],
    ['/authority/revoke', 'POST'],
  ]

  for (const [path, method] of routes) {
    it(`${method} ${path}`, async () => {
      const res = method === 'GET' ? await get(path) : await post(path, {})
      expect(res.status).toBe(401)
      expect(res.headers.get('content-type')).toContain('application/problem+json')
    })
  }
})
