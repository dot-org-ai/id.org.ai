/**
 * The authority surface — `/authority/*`.
 *
 * ── WHY NOT `/oauth/revoke` AND `/oauth/introspect` ────────────────────────
 *
 * This worker already serves `/oauth/revoke` (RFC 7009) and `/oauth/introspect`
 * (RFC 7662). Those act on **tokens**. The verbs here act on **authority
 * grants**. They are different acts that happen to share two names, and a
 * dispatcher cannot be asked to guess which one a caller meant. So the estate
 * verbs mount in their own namespace and neither route is touched. The name
 * collision itself is still an open ruling; this layout means the ruling can go
 * either way without a migration.
 *
 * ── ERRORS ────────────────────────────────────────────────────────────────
 *
 * RFC 9457 `application/problem+json`, `type` dereferenceable at
 * `https://id.org.ai/errors/{slug}`, carrying the estate extensions `door`,
 * `verb`, `retryable` and `costed`. Six of the slugs are already pinned in the
 * cross-door registry and are spelled here exactly as that registry spells
 * them; the rest are marked `proposed` in `AUTHORITY_SLUGS` and are a filing
 * against it, not a private catalogue.
 *
 * ── AUTH, AND THE TWO ROUTES THAT DELIBERATELY HAVE NONE ──────────────────
 *
 * `POST /authority/revoke/:tenantId/:grantId` is **seatless** — REQ-7: you pay
 * to govern at scale, never to stop an agent, and a revocation behind a login
 * is a paywall on stopping one. Its credential is the grant's own revoke
 * secret, which authorises exactly one act on exactly one grant and nothing
 * else.
 *
 * `POST /authority/claim` is **keyless** — REQ-9: the subject has never
 * resolved, so there is by construction no session to authenticate it with. The
 * claim token is single-use and is the credential.
 *
 * Every other route requires the caller's authenticated identity, applied in
 * `worker/index.ts` by naming the paths rather than by a wildcard, so that the
 * two exemptions above are visible at the mount point instead of buried here.
 */

import { Hono } from 'hono'
import type { Context } from 'hono'
import type { Env, Variables } from '../types'
import {
  AUTHORITY_SLUGS,
  AUTHORITY_SLUG_TITLES,
  AuthorityError as AuthorityErrorClass,
} from '../../src/server/services/authority/types'
import type {
  AuthorityError,
  AuthorityRpcResult,
  AuthorityService,
  AuthoritySlug,
} from '../../src/server/services/authority/types'
import type { Result } from '../../src/sdk/foundation'

export const AUTHORITY_DOOR = 'id.org.ai'
export const ERRORS_BASE = 'https://id.org.ai/errors'

type Ctx = Context<{ Bindings: Env; Variables: Variables }>

/**
 * How a request finds its tenant and its service. Injected so the HTTP contract
 * is testable without a Durable Object, and so the seatless routes can resolve
 * a tenant from the path while every other route resolves it from the session.
 */
export interface AuthorityResolver {
  /** For authenticated routes. Returns null when the caller has no identity. */
  forCaller(c: Ctx): Promise<{ service: AuthorityService; tenantId: string; principal: string } | null>
  /** For the seatless routes. The tenant comes from the path, never from a token. */
  forTenant(c: Ctx, tenantId: string): Promise<{ service: AuthorityService } | null>
}

// ── RFC 9457 ────────────────────────────────────────────────────────────────

export interface Problem {
  type: string
  title: string
  status: number
  detail: string
  door: string
  verb: string
  retryable: boolean
  costed: boolean
  [k: string]: unknown
}

export function problemFor(slug: AuthoritySlug, verb: string, detail: string, extra?: Record<string, unknown>): Problem {
  const meta = AUTHORITY_SLUGS[slug]
  return {
    type: `${ERRORS_BASE}/${slug}`,
    title: AUTHORITY_SLUG_TITLES[slug],
    status: meta.status,
    detail,
    door: AUTHORITY_DOOR,
    verb,
    retryable: meta.retryable,
    // No authority verb is metered. `revoke` and `refuse` are free by ruling;
    // the rest are not billed for refusing.
    costed: false,
    ...(extra ? { ...extra } : {}),
  }
}

function sendProblem(c: Ctx, p: Problem) {
  return c.json(p, p.status as never, { 'content-type': 'application/problem+json' })
}

function fromError(c: Ctx, verb: string, err: AuthorityError) {
  return sendProblem(
    c,
    problemFor(err.slug, verb, err.message, err.detail ? { detail_context: err.detail } : undefined),
  )
}

/**
 * A caller with no resolvable identity on an authenticated route. `authz-
 * expired` is the registry's spelling and it is retryable — the remedy is to
 * renew, which is a thing the caller can do.
 */
function unauthenticated(c: Ctx, verb: string) {
  return sendProblem(c, problemFor('authz-expired', verb, 'This verb requires an authenticated caller'))
}

function send<T>(c: Ctx, verb: string, r: Result<T, AuthorityError>, status = 200) {
  if (!r.success) return fromError(c, verb, r.error)
  return c.json(r.data as never, status as never)
}

// ── Routes ──────────────────────────────────────────────────────────────────

export function createAuthorityRoutes(resolver: AuthorityResolver) {
  const app = new Hono<{ Bindings: Env; Variables: Variables }>()

  /** Index the authority-class ask, so a refusal is distinguishable from silence. */
  app.post('/authority/ask', async (c) => {
    const ctx = await resolver.forCaller(c)
    if (!ctx) return unauthenticated(c, 'ask')
    const body = (await c.req.json().catch(() => ({}))) as Record<string, never>
    return send(c, 'ask', await ctx.service.recordAsk({ ...(body as object), tenantId: ctx.tenantId } as never), 201)
  })

  app.post('/authority/grant', async (c) => {
    const ctx = await resolver.forCaller(c)
    if (!ctx) return unauthenticated(c, 'grant')
    const body = (await c.req.json().catch(() => ({}))) as Record<string, never>
    // The tenant and the actor are taken from the session, NEVER from the body.
    // A body-supplied tenant is how one caller settles another tenant's ask.
    return send(
      c,
      'grant',
      await ctx.service.grant({ ...(body as object), tenantId: ctx.tenantId, actor: ctx.principal } as never),
      201,
    )
  })

  /**
   * REQ-9 — keyless by construction. The subject has never resolved, so there
   * is no session to present. The claim token is the credential and is
   * single-use.
   */
  app.post('/authority/claim', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      tenantId?: string
      grantId?: string
      claimToken?: string
      subject?: { kind?: string; id?: string }
    }
    if (!body.tenantId || !body.grantId || !body.claimToken || !body.subject?.id) {
      return sendProblem(
        c,
        problemFor('claim-token-invalid', 'claim', 'tenantId, grantId, claimToken and subject.id are all required'),
      )
    }
    const ctx = await resolver.forTenant(c, body.tenantId)
    if (!ctx) return sendProblem(c, problemFor('grant-not-found', 'claim', 'No such grant'))
    return send(
      c,
      'claim',
      await ctx.service.claim({
        tenantId: body.tenantId,
        grantId: body.grantId,
        claimToken: body.claimToken,
        subject: body.subject as never,
        actor: body.subject.id,
      }),
    )
  })

  app.get('/authority/introspect', async (c) => {
    const ctx = await resolver.forCaller(c)
    if (!ctx) return unauthenticated(c, 'introspect')
    const grantId = c.req.query('grant')
    if (!grantId) {
      return sendProblem(c, problemFor('grant-not-found', 'introspect', 'A ?grant= parameter is required'))
    }
    return send(c, 'introspect', await ctx.service.introspect({ tenantId: ctx.tenantId, grantId }))
  })

  app.get('/authority/grants', async (c) => {
    const ctx = await resolver.forCaller(c)
    if (!ctx) return unauthenticated(c, 'introspect')
    const q = c.req.query()
    return send(
      c,
      'introspect',
      await ctx.service.listGrants({
        tenantId: ctx.tenantId,
        principal: q.principal,
        standingOnly: q.standing === 'true',
        includeInactive: q.includeInactive === 'true',
        limit: q.limit ? Number(q.limit) : undefined,
        cursor: q.cursor,
      }),
    )
  })

  app.get('/authority/settlement/:askId', async (c) => {
    const ctx = await resolver.forCaller(c)
    if (!ctx) return unauthenticated(c, 'introspect')
    return send(c, 'introspect', await ctx.service.settlement({ tenantId: ctx.tenantId, askId: c.req.param('askId') }))
  })

  app.post('/authority/refuse', async (c) => {
    const ctx = await resolver.forCaller(c)
    if (!ctx) return unauthenticated(c, 'refuse')
    const body = (await c.req.json().catch(() => ({}))) as { askId?: string; cause?: string }
    return send(
      c,
      'refuse',
      await ctx.service.refuse({
        tenantId: ctx.tenantId,
        askId: body.askId ?? '',
        // The settling human is the SESSION's principal, never a body field.
        // A body-supplied `refusedBy` lets one party record a refusal in
        // another's name on an append-only ledger.
        refusedBy: ctx.principal,
        cause: body.cause as never,
      }),
    )
  })

  app.post('/authority/authorize', async (c) => {
    const ctx = await resolver.forCaller(c)
    if (!ctx) return unauthenticated(c, 'authorize')
    const body = (await c.req.json().catch(() => ({}))) as Record<string, never>
    return send(
      c,
      'authorize',
      await ctx.service.authorize({ ...(body as object), tenantId: ctx.tenantId, actor: ctx.principal } as never),
    )
  })

  /**
   * REQ-7 — **the seatless revoke address.** No session, no key, no seat. Its
   * credential is the grant's revoke secret, presented in the body or as `?t=`.
   *
   * The secret authorises one act on one grant. It cannot read the grant, list
   * anything, widen anything or reach any other route: the only handler that
   * consults it is this one.
   */
  app.post('/authority/revoke/:tenantId/:grantId', async (c) => {
    const tenantId = c.req.param('tenantId')
    const grantId = c.req.param('grantId')
    const body = (await c.req.json().catch(() => ({}))) as { revokeToken?: string; cause?: string }
    const revokeToken = body.revokeToken ?? c.req.query('t')
    const ctx = await resolver.forTenant(c, tenantId)
    if (!ctx) return sendProblem(c, problemFor('grant-not-found', 'revoke', 'No such grant'))
    if (!revokeToken) {
      return sendProblem(
        c,
        problemFor('not-the-warrantor', 'revoke', 'This address revokes on presentation of the grant’s revoke secret'),
      )
    }
    return send(c, 'revoke', await ctx.service.revoke({ tenantId, grantId, revokeToken, cause: body.cause as never }))
  })

  /** The seated path: the warrantor or the holder, revoking from a session. */
  app.post('/authority/revoke', async (c) => {
    const ctx = await resolver.forCaller(c)
    if (!ctx) return unauthenticated(c, 'revoke')
    const body = (await c.req.json().catch(() => ({}))) as { grantId?: string; cause?: string }
    return send(
      c,
      'revoke',
      await ctx.service.revoke({
        tenantId: ctx.tenantId,
        grantId: body.grantId ?? '',
        actor: ctx.principal,
        cause: body.cause as never,
      }),
    )
  })

  return app
}

// ============================================================================
// The production resolver — one Durable Object per tenant
// ============================================================================

/**
 * Re-inflate a flattened RPC envelope into the `Result<T, AuthorityError>` the
 * route layer expects. The DO flattens because structured clone drops prototype
 * getters; this is the other half of that trip. See `IdentityDO.flatten`.
 */
function inflate<T>(env: AuthorityRpcResult<T>): Result<T, AuthorityError> {
  if (env.ok) return { success: true, data: env.data }
  return { success: false, error: new AuthorityErrorClass(env.slug, env.message, env.detail) }
}

/**
 * An `AuthorityService` backed by a tenant's Durable Object. Every method is a
 * single RPC; none of them holds state on this side, because a worker isolate
 * is not where an authority record may live.
 */
export function stubAuthorityService(stub: AuthorityStub): AuthorityService {
  return {
    recordAsk: async (i) => inflate(await stub.authorityRecordAsk(i)),
    grant: async (i) => inflate(await stub.authorityGrant(i)),
    claim: async (i) => inflate(await stub.authorityClaim(i)),
    introspect: async (i) => inflate(await stub.authorityIntrospect(i)),
    revoke: async (i) => inflate(await stub.authorityRevoke(i)),
    refuse: async (i) => inflate(await stub.authorityRefuse(i)),
    settlement: async (i) => inflate(await stub.authoritySettlement(i)),
    listGrants: async (i) => inflate(await stub.authorityListGrants(i)),
    authorize: async (i) => inflate(await stub.authorityAuthorize(i)),
  }
}

/** The subset of `IdentityStub` this surface calls. */
export interface AuthorityStub {
  authorityRecordAsk(i: unknown): Promise<AuthorityRpcResult<never>>
  authorityGrant(i: unknown): Promise<AuthorityRpcResult<never>>
  authorityClaim(i: unknown): Promise<AuthorityRpcResult<never>>
  authorityIntrospect(i: unknown): Promise<AuthorityRpcResult<never>>
  authorityRevoke(i: unknown): Promise<AuthorityRpcResult<never>>
  authorityRefuse(i: unknown): Promise<AuthorityRpcResult<never>>
  authoritySettlement(i: unknown): Promise<AuthorityRpcResult<never>>
  authorityListGrants(i: unknown): Promise<AuthorityRpcResult<never>>
  authorityAuthorize(i: unknown): Promise<AuthorityRpcResult<never>>
}

/**
 * How a caller's session becomes a tenant and a principal.
 *
 * **The tenant is the tenant, never the agent.** An agent's `MCPAuthResult`
 * carries its parent `tenantId`; authority records live in the TENANT's Durable
 * Object, so an agent minting an attenuation and the human who warranted it
 * read and write the same store. Resolving to the agent's own DO would give
 * every agent a private authority store, and two authority stores make
 * "revocation kills access instantly" false.
 *
 * **The principal's grain is carried in its name.** `human:` is the prefix the
 * service tests for when it insists a settlement was made by a person — the one
 * check standing between the tier and an agent approving its own ask.
 */
export function durableObjectResolver(
  getStub: (env: Env, identityId: string) => AuthorityStub,
): AuthorityResolver {
  return {
    async forCaller(c) {
      const auth = c.get('auth')
      if (!auth?.authenticated || !auth.identityId) return null
      const tenantId = auth.tenantId ?? auth.identityId
      const isAgent = !!auth.tenantId && auth.tenantId !== auth.identityId
      const principal = isAgent ? `agent_${auth.identityId}` : `human:${auth.identityId}`
      return { service: stubAuthorityService(getStub(c.env, tenantId)), tenantId, principal }
    },
    async forTenant(c, tenantId) {
      if (!tenantId) return null
      return { service: stubAuthorityService(getStub(c.env, tenantId)) }
    },
  }
}
