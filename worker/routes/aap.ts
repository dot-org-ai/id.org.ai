/**
 * Agent Auth Protocol (AAP) v1.0-draft wire surface — id-9s0.
 *
 * Implements the subset of agent-auth-protocol.com endpoints that the
 * AgentService (id-ax7) makes well-defined:
 *
 *   GET  /.well-known/agent-configuration   discovery (no auth)
 *   POST /agent/register                    register a new agent under a tenant
 *   GET  /agent/status?agent_id=...         agent record
 *   POST /agent/revoke                      permanent revocation
 *   POST /agent/reactivate                  expired → active
 *
 * AAP terminology translation (per project_positioning.md): AAP "host" =
 * id.org.ai Tenant. Wire-format `host_*` parameters are mapped to
 * `tenant_*` internally by this module — the rest of the codebase only
 * sees the Tenant vocabulary.
 *
 * Authentication for phase 1: existing session token (`ses_*`) or API key
 * (`oai_*`/`hly_sk_*`). Strict AAP `host+jwt` verification is phase 2 and
 * pairs with the JWT issuance work — out of scope here. Per the
 * conformance footnote in our positioning, we accept the AAP shape but
 * authenticate via id.org.ai's existing mechanisms.
 *
 * Capability execution (`/capability/list,describe,execute`) is NOT
 * implemented here — that pairs with FGA migration (id-lkj) which gives
 * capabilities structured grants instead of flat strings.
 */

import { Hono } from 'hono'
import type { Env, Variables } from '../types'
import { errorResponse, ErrorCode, errorMessage } from '../../src/sdk/errors'
import type { AgentMode } from '../../src/sdk/types'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

// ── Discovery (RFC-style well-known doc) ──────────────────────────────────
// No authentication required. Cached for 1 hour upstream.

app.get('/.well-known/agent-configuration', (c) => {
  const origin = new URL(c.req.url).origin
  return c.json(
    {
      version: '1.0-draft',
      provider_name: 'id.org.ai',
      description: 'Agent-First Identity — humans, agents, organizations',
      issuer: origin,
      algorithms: ['Ed25519'],
      modes: ['delegated', 'autonomous'],
      // AAP discovery declares approval methods. id.org.ai's claim-by-commit
      // does not slot into AAP's `device_authorization` / `ciba` enum
      // cleanly — phase 2 will add a custom value `claim_by_commit` once
      // an AAP-vocabulary alignment lands.
      approval_methods: ['device_authorization'],
      // Conformance note: id.org.ai supports BOTH continuity (default —
      // claimed agents stay active) and AAP-strict (autonomous → claimed
      // terminal). Strict mode is requested via `strict: true` at register.
      conformance_notes: [
        'Default mode is claim-continuity: when a tenant gets claimed, agents stay active and become delegated. AAP-strict (autonomous → terminal claimed) requires `strict: true` on /agent/register.',
        'Phase 1 authenticates via id.org.ai session/API key; host+jwt verification is phase 2.',
      ],
      endpoints: {
        register: '/agent/register',
        status: '/agent/status',
        revoke: '/agent/revoke',
        reactivate: '/agent/reactivate',
        // Endpoints below are NOT yet implemented — declared as `null` so
        // AAP clients see them missing rather than 404 their way through.
        request_capability: null,
        rotate_key: null,
        introspect: null,
        revoke_host: null,
        rotate_host_key: null,
        capabilities: null,
        describe_capability: null,
        execute: null,
      },
      jwks_uri: `${origin}/.well-known/jwks.json`,
    },
    200,
    { 'Cache-Control': 'public, max-age=3600' },
  )
})

// ── Auth helper ───────────────────────────────────────────────────────────

function requireTenant(c: Parameters<Parameters<typeof app.post>[1]>[0]) {
  const auth = c.get('auth')
  if (!auth?.authenticated || !auth.identityId) {
    return null
  }
  // Tenants are identified by the auth principal: a session for the tenant
  // OR an API key issued to an agent under that tenant. For agent
  // principals, prefer auth.tenantId (set by AuthBroker.hydrateAgent).
  const tenantId = auth.tenantId ?? auth.identityId
  return { tenantId, principal: auth.identityId }
}

// ── /agent/register ───────────────────────────────────────────────────────
//
// Body shape mirrors AAP v1.0-draft §registration:
//   {
//     name: string,                 // human label
//     host_name?: string,           // ignored — tenant is derived from auth
//     mode: 'delegated' | 'autonomous',
//     capabilities?: string[],
//     public_key?: string,          // base64 raw 32-byte Ed25519
//     jwks_url?: string,            // alternative: JWKS URL
//     strict?: boolean,             // AAP-strict claim semantics (D7)
//     reason?: string               // ignored at L1
//   }

app.post('/agent/register', async (c) => {
  const tenant = requireTenant(c)
  if (!tenant) return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required to register an agent')

  const stub = c.get('identityStub')
  if (!stub) return errorResponse(c, 500, ErrorCode.ServerError, 'Identity stub not resolved')

  const body = (await c.req.json().catch(() => ({}))) as {
    name?: string
    mode?: AgentMode
    capabilities?: string[]
    public_key?: string
    jwks_url?: string
    strict?: boolean
    sessionTtlMs?: number
    maxLifetimeMs?: number
    absoluteLifetimeMs?: number
  }

  if (!body.name?.trim()) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'name is required')
  }
  if (body.mode !== 'delegated' && body.mode !== 'autonomous') {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'mode must be "delegated" or "autonomous"')
  }
  if (!body.public_key && !body.jwks_url) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'public_key or jwks_url is required')
  }

  try {
    const result = await stub.registerAgent({
      tenantId: tenant.tenantId,
      name: body.name,
      publicKey: body.public_key,
      jwksUrl: body.jwks_url,
      mode: body.mode,
      capabilities: body.capabilities,
      strict: body.strict,
      sessionTtlMs: body.sessionTtlMs,
      maxLifetimeMs: body.maxLifetimeMs,
      absoluteLifetimeMs: body.absoluteLifetimeMs,
    })
    if (!result.success || !result.agent) {
      return errorResponse(c, 400, ErrorCode.InvalidRequest, result.error ?? 'Agent registration failed')
    }
    return c.json(
      {
        agent_id: result.agent.id,
        host_id: result.agent.tenantId,
        name: result.agent.name,
        mode: result.agent.mode,
        status: result.agent.status,
        agent_capability_grants: result.agent.capabilities.map((capability) => ({
          capability,
          status: 'active',
        })),
      },
      201,
    )
  } catch (err: unknown) {
    return errorResponse(c, 500, ErrorCode.ServerError, errorMessage(err))
  }
})

// ── /agent/status ─────────────────────────────────────────────────────────

app.get('/agent/status', async (c) => {
  const tenant = requireTenant(c)
  if (!tenant) return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required')

  const stub = c.get('identityStub')
  if (!stub) return errorResponse(c, 500, ErrorCode.ServerError, 'Identity stub not resolved')

  const agentId = c.req.query('agent_id')
  if (!agentId) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'agent_id query parameter required')
  }

  const agent = await stub.getAgent(agentId)
  if (!agent) {
    return errorResponse(c, 404, ErrorCode.NotFound, 'Agent not found')
  }

  // Cross-tenant lookup is forbidden.
  if (agent.tenantId !== tenant.tenantId) {
    return errorResponse(c, 403, ErrorCode.Forbidden, 'Agent is in a different tenant')
  }

  return c.json({
    agent_id: agent.id,
    host_id: agent.tenantId,
    name: agent.name,
    status: agent.status,
    mode: agent.mode,
    agent_capability_grants: agent.capabilities.map((capability) => ({ capability, status: 'active' })),
    activated_at: agent.activatedAt ? new Date(agent.activatedAt).toISOString() : undefined,
    created_at: new Date(agent.createdAt).toISOString(),
    last_used_at: agent.lastUsedAt ? new Date(agent.lastUsedAt).toISOString() : undefined,
    expires_at: agent.expiresAt ? new Date(agent.expiresAt).toISOString() : undefined,
  })
})

// ── /agent/revoke ─────────────────────────────────────────────────────────

app.post('/agent/revoke', async (c) => {
  const tenant = requireTenant(c)
  if (!tenant) return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required')

  const stub = c.get('identityStub')
  if (!stub) return errorResponse(c, 500, ErrorCode.ServerError, 'Identity stub not resolved')

  const body = (await c.req.json().catch(() => ({}))) as { agent_id?: string; reason?: string }
  if (!body.agent_id) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'agent_id required')
  }

  const agent = await stub.getAgent(body.agent_id)
  if (!agent) {
    return errorResponse(c, 404, ErrorCode.NotFound, 'Agent not found')
  }
  if (agent.tenantId !== tenant.tenantId) {
    return errorResponse(c, 403, ErrorCode.Forbidden, 'Agent is in a different tenant')
  }

  const result = await stub.revokeAgent(body.agent_id, body.reason)
  if (!result.success || !result.agent) {
    return errorResponse(c, 409, ErrorCode.Forbidden, result.error ?? 'Revoke failed')
  }
  return c.json({
    agent_id: result.agent.id,
    status: result.agent.status,
    revoked_at: result.agent.revokedAt ? new Date(result.agent.revokedAt).toISOString() : undefined,
  })
})

// ── /agent/reactivate ─────────────────────────────────────────────────────

app.post('/agent/reactivate', async (c) => {
  const tenant = requireTenant(c)
  if (!tenant) return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required')

  const stub = c.get('identityStub')
  if (!stub) return errorResponse(c, 500, ErrorCode.ServerError, 'Identity stub not resolved')

  const body = (await c.req.json().catch(() => ({}))) as { agent_id?: string }
  if (!body.agent_id) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'agent_id required')
  }

  const agent = await stub.getAgent(body.agent_id)
  if (!agent) {
    return errorResponse(c, 404, ErrorCode.NotFound, 'Agent not found')
  }
  if (agent.tenantId !== tenant.tenantId) {
    return errorResponse(c, 403, ErrorCode.Forbidden, 'Agent is in a different tenant')
  }

  const result = await stub.reactivateAgent(body.agent_id)
  if (!result.success || !result.agent) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, result.error ?? 'Reactivation failed')
  }
  return c.json({
    agent_id: result.agent.id,
    status: result.agent.status,
    activated_at: result.agent.activatedAt ? new Date(result.agent.activatedAt).toISOString() : undefined,
  })
})

export { app as aapRoutes }
