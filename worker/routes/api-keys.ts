/**
 * API Key Management route module — CRUD for API keys
 * Extracted from worker/index.ts (Phase 9).
 * Requires L1+ authentication (mounted after authenticateRequest middleware).
 */
import { Hono } from 'hono'
import type { Env, Variables } from '../types'
import type { IdentityStub } from '../../src/server/do/Identity'
import type { Identity } from '../../src/sdk/types'
import { errorResponse, ErrorCode, errorMessage } from '../../src/sdk/errors'
import { ensurePersonalOrg } from '../../src/sdk/workos/upstream'
import { createWorkOSApiKey, listWorkOSApiKeys, revokeWorkOSApiKey } from '../../src/sdk/workos/keys'
import { requireScope } from '../middleware/require-scope'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

// ── Helper ──────────────────────────────────────────────────────────────────

/**
 * Resolve the user's WorkOS org ID, creating a personal org if needed.
 * Returns the org ID or null if WorkOS is not configured or resolution fails.
 */
async function resolveOrgForApiKeys(env: Env, identityId: string, stub: IdentityStub): Promise<string | null> {
  if (!env.WORKOS_API_KEY) return null

  // Extract WorkOS user ID from identity record
  const stored = await stub.oauthStorageOp({ op: 'get', key: `identity:${identityId}` })
  const record = stored.value as { workosUserId?: string; email?: string; name?: string; organizationId?: string } | null
  if (!record?.workosUserId) return null

  // If identity already has an org, use it
  if (record.organizationId) return record.organizationId

  // No org — ensure a personal org exists
  const result = await ensurePersonalOrg(env.WORKOS_API_KEY, record.workosUserId, record.name, record.email || '')
  if (!result) return null

  // Persist org ID back to identity record so we don't re-check next time
  await stub.oauthStorageOp({
    op: 'put',
    key: `identity:${identityId}`,
    value: { ...record, organizationId: result.orgId },
  })

  return result.orgId
}

// ── Routes ──────────────────────────────────────────────────────────────────

// Minting a key is an ISSUANCE operation: the caller must carry explicit
// issuance authority (`keys:issue`) or be an `admin`. Bare authentication is
// NOT enough — otherwise any key could mint a broader child (privilege
// escalation). The narrowing check in ApiKeyServiceImpl.create() then bounds
// what an authorised issuer may mint to no more than its own authority.
app.post('/api/keys', requireScope('keys:issue', 'admin'), async (c) => {
  const auth = c.get('auth')
  if (!auth.authenticated || !auth.identityId) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required to create API keys')
  }

  // The minting caller's OWN resolved authority — the ceiling a delegated mint
  // may not exceed. Fail closed if the identity context is missing/unresolvable
  // (should be impossible after requireScope, but deny rather than mint blind).
  const identity = c.get('identity') as Identity | undefined
  if (!identity) {
    return errorResponse(c, 403, ErrorCode.Forbidden, 'Caller authority unresolvable — refusing to mint')
  }

  const stub = c.get('identityStub')
  if (!stub) {
    return errorResponse(c, 500, ErrorCode.ServerError, 'Identity stub not resolved')
  }

  const body = (await c.req.json().catch(() => ({}))) as {
    name?: string
    scopes?: string[]
    scope?: import('../../src/sdk/auth/scope').Scope
    expiresAt?: string
  }

  if (!body.name) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'name is required')
  }

  // Use WorkOS API keys when configured — WorkOS handles generation, rotation, validation
  if (c.env.WORKOS_API_KEY) {
    // Scope-shaped (structured) keys are a NATIVE-key primitive: their Scope is
    // stored + enforced on the id.org.ai key record, which WorkOS-backed keys
    // don't have. Minting a WorkOS key here would silently drop `body.scope`,
    // yielding a scope-less key that then fail-closed-403s every scoped request.
    // Reject up front rather than issue a subtly-broken key.
    if (body.scope !== undefined) {
      return errorResponse(
        c,
        400,
        ErrorCode.InvalidRequest,
        'scope-shaped keys are a native-key primitive; not supported on WorkOS-backed keys',
      )
    }
    try {
      const orgId = await resolveOrgForApiKeys(c.env, auth.identityId, stub)
      const result = await createWorkOSApiKey(c.env.WORKOS_API_KEY, {
        name: body.name,
        organizationId: orgId || undefined,
        permissions: body.scopes,
        expiresAt: body.expiresAt,
      })
      return c.json({ id: result.id, key: result.key, name: result.name }, 201)
    } catch (err: unknown) {
      return errorResponse(c, 500, ErrorCode.ServerError, errorMessage(err))
    }
  }

  // Fallback to custom hly_sk_* keys for tenants without WorkOS
  try {
    const result = await stub.createApiKey({
      name: body.name,
      identityId: auth.identityId,
      scopes: body.scopes,
      scope: body.scope,
      expiresAt: body.expiresAt,
      // Delegated-mint ceiling: the child may never exceed the caller's own
      // flat scopes / structured Scope. create() enforces narrowing (and fails
      // closed on a structured mint without a caller Scope).
      caller: { flatScopes: identity.scopes, scope: identity.scope },
    })

    // Write KV mapping so future requests with this key route to the correct DO shard
    await c.env.SESSIONS.put(`apikey:${result.key}`, auth.identityId)

    return c.json(result, 201)
  } catch (err: unknown) {
    const msg = errorMessage(err) || 'Failed to create API key'
    if (msg.includes('Invalid scope') || msg.includes('in the future') || msg.includes('required')) {
      return errorResponse(c, 400, ErrorCode.InvalidRequest, msg)
    }
    return errorResponse(c, 500, ErrorCode.ServerError, msg)
  }
})

app.get('/api/keys', async (c) => {
  const auth = c.get('auth')
  if (!auth.authenticated || !auth.identityId) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required to list API keys')
  }

  const stub = c.get('identityStub')
  if (!stub) {
    return errorResponse(c, 500, ErrorCode.ServerError, 'Identity stub not resolved')
  }

  // Use WorkOS API keys when configured — scoped to user's org
  if (c.env.WORKOS_API_KEY) {
    try {
      const orgId = await resolveOrgForApiKeys(c.env, auth.identityId, stub)
      const workosKeys = await listWorkOSApiKeys(c.env.WORKOS_API_KEY, orgId || undefined)
      const keys = workosKeys.map((k) => ({
        id: k.id,
        name: k.name,
        createdAt: k.created_at,
        lastUsedAt: k.last_used_at,
      }))
      return c.json({ keys })
    } catch (err: unknown) {
      return errorResponse(c, 500, ErrorCode.ServerError, errorMessage(err))
    }
  }

  // Fallback to custom hly_sk_* keys
  try {
    const keys = await stub.listApiKeys(auth.identityId)
    return c.json({ keys })
  } catch (err: unknown) {
    return errorResponse(c, 500, ErrorCode.ServerError, errorMessage(err))
  }
})

app.delete('/api/keys/:id', async (c) => {
  const auth = c.get('auth')
  if (!auth.authenticated || !auth.identityId) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required to revoke API keys')
  }

  const stub = c.get('identityStub')
  if (!stub) {
    return errorResponse(c, 500, ErrorCode.ServerError, 'Identity stub not resolved')
  }

  const keyId = c.req.param('id')

  // Use WorkOS API keys when configured
  if (c.env.WORKOS_API_KEY) {
    try {
      const revoked = await revokeWorkOSApiKey(c.env.WORKOS_API_KEY, keyId)
      if (!revoked) {
        return errorResponse(c, 500, ErrorCode.ServerError, 'Failed to revoke WorkOS API key')
      }
      return c.json({ id: keyId, status: 'revoked', revokedAt: new Date().toISOString() })
    } catch (err: unknown) {
      return errorResponse(c, 500, ErrorCode.ServerError, errorMessage(err))
    }
  }

  // Fallback to custom hly_sk_* keys
  try {
    const result = await stub.revokeApiKey(keyId, auth.identityId)
    if (!result) {
      return errorResponse(c, 404, ErrorCode.NotFound, 'API key not found')
    }

    // Clean up KV entry so the revoked key can't route to a DO anymore
    if (result.key) {
      await c.env.SESSIONS.delete(`apikey:${result.key}`)
    }

    // Don't expose the key string in the response
    return c.json({ id: result.id, status: result.status, revokedAt: result.revokedAt })
  } catch (err: unknown) {
    return errorResponse(c, 500, ErrorCode.ServerError, errorMessage(err))
  }
})

export { app as apiKeyRoutes }
