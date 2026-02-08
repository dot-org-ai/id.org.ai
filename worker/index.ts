/**
 * id.org.ai — Agent-First Identity
 *
 * Cloudflare Worker entry point.
 * Routes: id.org.ai, auth.org.ai
 *
 * Every request is authenticated via MCPAuth (three-tier):
 *   L0: No auth — anonymous, read scopes, 30 req/min
 *   L1: ses_* token — session, read+write, 100 req/min
 *   L2+: oai_* key — API key, full scopes, 1000+ req/min
 *
 * Sharding: Each identity gets its own Durable Object instance.
 * The shard key is derived from the request:
 *   - API key (oai_*) → KV lookup: apikey:{key} → identityId
 *   - Session token (ses_*) → KV lookup: session:{token} → identityId
 *   - Claim token (clm_*) → KV lookup: claim:{token} → identityId
 *   - Provision (POST /api/provision) → new UUID (creates new DO)
 *   - Anonymous L0 → no DO needed (schema-only responses)
 */

import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { IdentityDO } from '../src/do/Identity'
import { MCPAuth } from '../src/mcp/auth'
import type { MCPAuthResult } from '../src/mcp/auth'
import { dispatchTool } from '../src/mcp/tools'
import { ClaimService } from '../src/claim/provision'
import { verifyClaim } from '../src/claim/verify'
import { GitHubApp } from '../src/github/app'
import type { PushEvent } from '../src/github/app'
import { OAuthProvider } from '../src/oauth/provider'

export { IdentityDO }

interface Env {
  IDENTITY: DurableObjectNamespace
  SESSIONS: KVNamespace
  AUTH_SECRET: string
  JWKS_SECRET: string
  GITHUB_APP_ID?: string
  GITHUB_APP_PRIVATE_KEY?: string
  GITHUB_WEBHOOK_SECRET?: string
}

type Variables = {
  auth: MCPAuthResult
  identityStub: { fetch(input: RequestInfo): Promise<Response> }
}

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

// ── Shard Resolution ─────────────────────────────────────────────────────
// Resolves the identity ID (shard key) from a request's auth credentials.
// Uses KV for token → identityId lookups so each identity gets its own DO.

/**
 * Get a DO stub for a specific identity shard.
 */
function getStubForIdentity(env: Env, identityId: string): { fetch(input: RequestInfo): Promise<Response> } {
  const id = env.IDENTITY.idFromName(identityId)
  return env.IDENTITY.get(id)
}

/**
 * Extract the API key from a request (oai_* prefix).
 */
function extractApiKey(request: Request): string | null {
  const header = request.headers.get('x-api-key')
  if (header?.startsWith('oai_')) return header
  const auth = request.headers.get('authorization')
  if (auth?.startsWith('Bearer oai_')) return auth.slice(7)
  try {
    const url = new URL(request.url)
    const keyParam = url.searchParams.get('api_key')
    if (keyParam?.startsWith('oai_')) return keyParam
  } catch { /* ignore */ }
  return null
}

/**
 * Extract the session token from a request (ses_* prefix).
 */
function extractSessionToken(request: Request): string | null {
  const auth = request.headers.get('authorization')
  if (auth?.startsWith('Bearer ses_')) return auth.slice(7)
  return null
}

/**
 * Resolve the identity ID (shard key) from the request's auth credentials.
 * Returns null for anonymous/L0 requests that don't need a DO.
 */
async function resolveIdentityId(request: Request, env: Env): Promise<string | null> {
  // 1. API key → KV lookup
  const apiKey = extractApiKey(request)
  if (apiKey) {
    const identityId = await env.SESSIONS.get(`apikey:${apiKey}`)
    return identityId
  }

  // 2. Session token → KV lookup
  const sessionToken = extractSessionToken(request)
  if (sessionToken) {
    const identityId = await env.SESSIONS.get(`session:${sessionToken}`)
    return identityId
  }

  // 3. No credentials → anonymous (no DO needed)
  return null
}

/**
 * Resolve the identity ID from a claim token via KV.
 */
async function resolveIdentityFromClaim(claimToken: string, env: Env): Promise<string | null> {
  if (!claimToken?.startsWith('clm_')) return null
  return env.SESSIONS.get(`claim:${claimToken}`)
}

// ── CORS ──────────────────────────────────────────────────────────────────

app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  credentials: true,
}))

// ── Identity Stub Middleware ──────────────────────────────────────────────
// Resolves the shard key from auth credentials and injects the correct
// IdentityDO stub into context. Each identity gets its own DO instance.

app.use('*', async (c, next) => {
  const identityId = await resolveIdentityId(c.req.raw, c.env)

  if (identityId) {
    // Authenticated request — route to identity-specific DO
    c.set('identityStub', getStubForIdentity(c.env, identityId))
  }
  // For anonymous/L0 requests, identityStub is NOT set.
  // Routes that require a stub will handle this explicitly
  // (e.g., provision creates a new identity, claim resolves via KV).

  await next()
})

// ── Health (no auth required) ─────────────────────────────────────────────

app.get('/health', (c) => c.json({
  status: 'ok',
  service: 'id.org.ai',
  tagline: 'Humans. Agents. Identity.',
}))

// ── OIDC Discovery (no auth required) ─────────────────────────────────────

app.get('/.well-known/openid-configuration', (c) => {
  const provider = getOAuthProvider(c)
  return provider.getOpenIDConfiguration()
})

// ── MCP Auth Middleware ───────────────────────────────────────────────────
// Authenticates every request below this point. The auth result is always
// set in context — L0 (anonymous) is a valid result, not an error.
// If no identityStub was resolved (anonymous), MCPAuth returns L0 result.

async function authenticateRequest(c: any, next: () => Promise<void>) {
  const stub = c.get('identityStub')
  if (stub) {
    const mcpAuth = new MCPAuth(stub)
    const auth = await mcpAuth.authenticate(c.req.raw)
    c.set('auth', auth)
  } else {
    // Anonymous L0 — no DO stub needed for read-only schema access
    c.set('auth', MCPAuth.anonymousResult())
  }
  await next()
}

app.use('/api/*', authenticateRequest)
app.use('/mcp', authenticateRequest)
app.use('/mcp/*', authenticateRequest)
app.use('/oauth/authorize', authenticateRequest)
app.use('/device', authenticateRequest)

// ── MCP Endpoint ──────────────────────────────────────────────────────────
// Returns capabilities based on auth level. This is the entry point for
// agents connecting via MCP protocol.

app.get('/mcp', async (c) => {
  const auth = c.get('auth')
  const meta = MCPAuth.buildMetaStatic(auth)

  return c.json({
    jsonrpc: '2.0',
    result: {
      protocolVersion: '2024-11-05',
      serverInfo: {
        name: 'id.org.ai',
        version: '1.0.0',
      },
      capabilities: {
        tools: buildToolList(auth),
        resources: buildResourceList(auth),
      },
      _meta: meta,
    },
  })
})

app.post('/mcp', async (c) => {
  const auth = c.get('auth')
  const stub = c.get('identityStub')
  const meta = MCPAuth.buildMetaStatic(auth)

  // Rate limit check
  if (auth.rateLimit && !auth.rateLimit.allowed) {
    return c.json({
      jsonrpc: '2.0',
      error: {
        code: -32000,
        message: 'Rate limit exceeded',
        data: meta,
      },
    }, 429)
  }

  const body = await c.req.json() as { method?: string; params?: any; id?: string | number }

  // Handle MCP initialize
  if (body.method === 'initialize') {
    return c.json({
      jsonrpc: '2.0',
      id: body.id,
      result: {
        protocolVersion: '2024-11-05',
        serverInfo: { name: 'id.org.ai', version: '1.0.0' },
        capabilities: {
          tools: buildToolList(auth),
          resources: buildResourceList(auth),
        },
        _meta: meta,
      },
    })
  }

  // Handle tools/list
  if (body.method === 'tools/list') {
    return c.json({
      jsonrpc: '2.0',
      id: body.id,
      result: {
        tools: buildToolList(auth),
        _meta: meta,
      },
    })
  }

  // Handle tools/call — dispatch to tool handlers
  if (body.method === 'tools/call') {
    const toolName = body.params?.name as string

    // Check capability level — explore is always available, try requires L1+
    const toolLevelMap: Record<string, number> = { explore: 0, search: 0, fetch: 0, try: 1, do: 1 }
    const requiredLevel = toolLevelMap[toolName] ?? 0

    if (requiredLevel > auth.level) {
      return c.json({
        jsonrpc: '2.0',
        id: body.id,
        error: {
          code: -32601,
          message: `Tool "${toolName}" requires Level ${requiredLevel}+ authentication`,
          data: { ...meta, requiredLevel, currentLevel: auth.level },
        },
      }, 403)
    }

    // L1+ tools require a DO stub (authenticated identity)
    if (requiredLevel >= 1 && !stub) {
      return c.json({
        jsonrpc: '2.0',
        id: body.id,
        error: {
          code: -32601,
          message: `Tool "${toolName}" requires authentication`,
          data: meta,
        },
      }, 401)
    }

    // For L0 tools without a stub, pass a null-safe stub that won't be called
    // (explore, search schema-only, and fetch schema-only don't need the DO)
    const effectiveStub = stub ?? { fetch: async () => new Response('{}', { status: 404 }) }

    // Dispatch to the tool handler
    const toolResult = await dispatchTool(toolName, body.params?.arguments ?? {}, effectiveStub, auth)

    return c.json({
      jsonrpc: '2.0',
      id: body.id,
      result: { ...toolResult, _meta: meta },
    })
  }

  return c.json({
    jsonrpc: '2.0',
    id: body.id,
    error: { code: -32601, message: 'Method not found', data: meta },
  }, 404)
})

// ── Provision Endpoint ────────────────────────────────────────────────────
// Auto-provisions an anonymous tenant. No auth required.
// Creates a NEW identity with its own Durable Object instance (shard).
// Writes token → identityId mappings to KV for future request routing.

app.post('/api/provision', async (c) => {
  // Generate a new identity ID to use as the shard key.
  // We pass this to the DO so the identity ID matches the shard key.
  const shardKey = crypto.randomUUID()
  const stub = getStubForIdentity(c.env, shardKey)

  try {
    // Call the DO's provision endpoint with the pre-generated identity ID
    const res = await stub.fetch(new Request('https://id.org.ai/api/provision', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Worker-Auth': c.env.AUTH_SECRET },
      body: JSON.stringify({ identityId: shardKey }),
    }))

    if (!res.ok) {
      const body = await res.text()
      throw new Error(`Provision failed (${res.status}): ${body}`)
    }

    const data = await res.json() as {
      identity: { id: string; name: string; level: number }
      sessionToken: string
      claimToken: string
    }

    // Build the provision result
    const result = {
      tenantId: data.identity.name,
      identityId: data.identity.id,
      sessionToken: data.sessionToken,
      claimToken: data.claimToken,
      level: 1 as const,
      limits: {
        maxEntities: 1000,
        ttlHours: 24,
        maxRequestsPerMinute: 100,
      },
      upgrade: {
        nextLevel: 2 as const,
        action: 'claim' as const,
        description: 'Commit a GitHub Action workflow to claim this tenant',
        url: `https://id.org.ai/claim/${data.claimToken}`,
      },
    }

    // Write KV mappings so future requests can route to this shard.
    // Session token → identityId (24h TTL matches session TTL)
    await c.env.SESSIONS.put(
      `session:${data.sessionToken}`,
      data.identity.id,
      { expirationTtl: 86400 },
    )
    // Claim token → identityId (30 days — claim window)
    await c.env.SESSIONS.put(
      `claim:${data.claimToken}`,
      data.identity.id,
      { expirationTtl: 2592000 },
    )

    return c.json(result, 201)
  } catch (err: any) {
    return c.json({ error: 'provision_failed', message: err.message }, 500)
  }
})

// ── Claim Status Endpoint ─────────────────────────────────────────────────

app.get('/api/claim/:token', async (c) => {
  const token = c.req.param('token')

  // Resolve shard from claim token via KV
  const identityId = await resolveIdentityFromClaim(token, c.env)
  if (!identityId) {
    return c.json({ valid: false, error: 'Unknown claim token' }, 404)
  }
  const stub = getStubForIdentity(c.env, identityId)

  try {
    const status = await verifyClaim(token, stub)
    return c.json(status, status.valid ? 200 : 404)
  } catch (err: any) {
    return c.json({ error: 'verification_failed', message: err.message }, 500)
  }
})

// ── Freeze Endpoint ───────────────────────────────────────────────────────
// Requires L1+ auth. Freezes the caller's own tenant.

app.post('/api/freeze', async (c) => {
  const auth = c.get('auth')
  if (!auth.authenticated || !auth.identityId) {
    return c.json({
      error: 'unauthorized',
      message: 'Session token required to freeze a tenant',
      upgrade: auth.upgrade,
    }, 401)
  }

  // Stub is already set by middleware for authenticated requests
  const stub = c.get('identityStub')
  if (!stub) {
    return c.json({ error: 'internal_error', message: 'Identity stub not resolved' }, 500)
  }
  const claimService = new ClaimService(stub)

  try {
    const result = await claimService.freeze(auth.identityId)
    return c.json(result)
  } catch (err: any) {
    return c.json({ error: 'freeze_failed', message: err.message }, 500)
  }
})

// ── Forward identity operations to IdentityDO ─────────────────────────────
// Sensitive endpoints require authentication. The catch-all proxies to the
// DO but injects an X-Worker-Auth header so the DO knows the request came
// through the authenticated worker layer (not directly to the DO).

app.all('/api/*', async (c) => {
  const auth = c.get('auth')
  const stub = c.get('identityStub')

  if (!stub) {
    return c.json({
      error: 'unauthorized',
      message: 'Authentication required for this endpoint',
      upgrade: auth?.upgrade ?? {
        nextLevel: 1,
        action: 'provision',
        description: 'POST to provision endpoint to get a session token',
        url: 'https://id.org.ai/api/provision',
      },
    }, 401)
  }

  // Clone the request and add internal auth headers so the DO can verify
  // the request was routed through the worker's auth middleware.
  const headers = new Headers(c.req.raw.headers)
  headers.set('X-Worker-Auth', c.env.AUTH_SECRET)
  if (auth?.authenticated && auth.identityId) {
    headers.set('X-Identity-Id', auth.identityId)
    headers.set('X-Auth-Level', String(auth.level))
  }

  const proxiedRequest = new Request(c.req.raw.url, {
    method: c.req.raw.method,
    headers,
    body: c.req.raw.body,
  })
  return stub.fetch(proxiedRequest)
})

// ── OAuth 2.1 Provider Endpoints ──────────────────────────────────────────
// Wires the OAuthProvider class into the Hono router. The provider uses the
// IdentityDO's storage (via stub.fetch) for client, token, and consent state.

function getOAuthProvider(c: any): OAuthProvider {
  // OAuth state (clients, tokens, consent) lives in a dedicated 'oauth' shard.
  // This is separate from identity sharding — OAuth is a system-level concern.
  const stub = getStubForIdentity(c.env, 'oauth')
  const authSecret = c.env.AUTH_SECRET
  const base = 'https://id.org.ai'
  return new OAuthProvider({
    storage: {
      async get<T = unknown>(key: string): Promise<T | undefined> {
        const res = await stub.fetch(new Request(`https://id.org.ai/api/oauth-storage`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Worker-Auth': authSecret },
          body: JSON.stringify({ op: 'get', key }),
        }))
        if (!res.ok) return undefined
        const data = await res.json() as { value?: T }
        return data.value
      },
      async put(key: string, value: unknown, options?: { expirationTtl?: number }): Promise<void> {
        await stub.fetch(new Request(`https://id.org.ai/api/oauth-storage`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Worker-Auth': authSecret },
          body: JSON.stringify({ op: 'put', key, value, options }),
        }))
      },
      async delete(key: string): Promise<boolean> {
        const res = await stub.fetch(new Request(`https://id.org.ai/api/oauth-storage`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Worker-Auth': authSecret },
          body: JSON.stringify({ op: 'delete', key }),
        }))
        return res.ok
      },
      async list<T = unknown>(options?: { prefix?: string; limit?: number }): Promise<Map<string, T>> {
        const res = await stub.fetch(new Request(`https://id.org.ai/api/oauth-storage`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Worker-Auth': authSecret },
          body: JSON.stringify({ op: 'list', options }),
        }))
        if (!res.ok) return new Map()
        const data = await res.json() as { entries: Array<[string, T]> }
        return new Map(data.entries)
      },
    },
    config: {
      issuer: base,
      authorizationEndpoint: `${base}/oauth/authorize`,
      tokenEndpoint: `${base}/oauth/token`,
      userinfoEndpoint: `${base}/oauth/userinfo`,
      registrationEndpoint: `${base}/oauth/register`,
      deviceAuthorizationEndpoint: `${base}/oauth/device`,
      revocationEndpoint: `${base}/oauth/revoke`,
      introspectionEndpoint: `${base}/oauth/introspect`,
      jwksUri: `${base}/.well-known/jwks.json`,
    },
    getIdentity: async (id: string) => {
      // Identity data lives in the identity's own shard, not in the oauth shard
      const identityStub = getStubForIdentity(c.env, id)
      const res = await identityStub.fetch(
        new Request(`https://id.org.ai/api/identity/${id}`, {
          method: 'GET',
          headers: { 'X-Worker-Auth': authSecret },
        })
      )
      if (!res.ok) return null
      return await res.json() as { id: string; name?: string; handle?: string; email?: string; emailVerified?: boolean; image?: string }
    },
  })
}

// Dynamic Client Registration (RFC 7591)
app.post('/oauth/register', async (c) => {
  const provider = getOAuthProvider(c)
  return provider.handleRegister(c.req.raw)
})

// Authorization Endpoint
app.get('/oauth/authorize', async (c) => {
  const auth = c.get('auth')
  const identityId = auth?.authenticated ? auth.identityId ?? null : null
  const provider = getOAuthProvider(c)
  return provider.handleAuthorize(c.req.raw, identityId)
})

// Authorization Consent Submission
app.post('/oauth/authorize', async (c) => {
  const auth = c.get('auth')
  if (!auth?.authenticated || !auth.identityId) {
    return c.json({ error: 'authentication_required' }, 401)
  }
  const provider = getOAuthProvider(c)
  return provider.handleAuthorizeConsent(c.req.raw, auth.identityId)
})

// Token Endpoint
app.post('/oauth/token', async (c) => {
  const provider = getOAuthProvider(c)
  return provider.handleToken(c.req.raw)
})

// Device Authorization (RFC 8628)
app.post('/oauth/device', async (c) => {
  const provider = getOAuthProvider(c)
  return provider.handleDeviceAuthorization(c.req.raw)
})

// Device Verification (browser-side)
app.all('/device', async (c) => {
  const auth = c.get('auth')
  const identityId = auth?.authenticated ? auth.identityId ?? null : null
  const provider = getOAuthProvider(c)
  return provider.handleDeviceVerification(c.req.raw, identityId)
})

// UserInfo Endpoint (OIDC Core)
app.get('/oauth/userinfo', async (c) => {
  const provider = getOAuthProvider(c)
  return provider.handleUserinfo(c.req.raw)
})

// Token Introspection (RFC 7662)
app.post('/oauth/introspect', async (c) => {
  const provider = getOAuthProvider(c)
  return provider.handleIntrospect(c.req.raw)
})

// Token Revocation (RFC 7009)
app.post('/oauth/revoke', async (c) => {
  const provider = getOAuthProvider(c)
  return provider.handleRevoke(c.req.raw)
})

// Fallback for unhandled /oauth/* routes
app.all('/oauth/*', async (c) => {
  const stub = c.get('identityStub')
  if (!stub) {
    return c.json({ error: 'authentication_required', message: 'OAuth endpoints require authentication' }, 401)
  }
  return stub.fetch(c.req.raw)
})

// ── Claim page (human-facing) ─────────────────────────────────────────────

app.get('/claim/:token', async (c) => {
  const token = c.req.param('token')

  // Resolve shard from claim token via KV
  const identityId = await resolveIdentityFromClaim(token, c.env)
  if (!identityId) {
    return c.json({
      error: 'invalid_claim_token',
      message: 'This claim token is invalid or has expired.',
    }, 404)
  }
  const stub = getStubForIdentity(c.env, identityId)
  const status = await verifyClaim(token, stub)

  if (!status.valid) {
    return c.json({
      error: 'invalid_claim_token',
      message: 'This claim token is invalid or has expired.',
    }, 404)
  }

  // Return claim info for the human-facing claim page
  return c.json({
    claimToken: token,
    status: status.status,
    stats: status.stats,
    instructions: {
      step1: 'Add this GitHub Action workflow to your repository:',
      file: '.github/workflows/headlessly.yml',
      content: buildClaimWorkflow(token),
      step2: 'Push to your main branch',
      step3: 'The push event will link your GitHub identity to this tenant',
    },
  })
})

// ── GitHub webhook endpoint ───────────────────────────────────────────────

app.post('/webhook/github', async (c) => {
  const signature = c.req.header('x-hub-signature-256')
  const event = c.req.header('x-github-event')
  const deliveryId = c.req.header('x-github-delivery')
  const body = await c.req.text()

  // Validate required environment variables
  if (!c.env.GITHUB_WEBHOOK_SECRET || !c.env.GITHUB_APP_ID || !c.env.GITHUB_APP_PRIVATE_KEY) {
    return c.json({ error: 'github_app_not_configured' }, 503)
  }

  const githubApp = new GitHubApp({
    webhookSecret: c.env.GITHUB_WEBHOOK_SECRET,
    appId: c.env.GITHUB_APP_ID,
    privateKey: c.env.GITHUB_APP_PRIVATE_KEY,
  })

  // Verify webhook signature
  if (!await githubApp.verifySignature(body, signature ?? '')) {
    return c.json({ error: 'invalid_signature' }, 401)
  }

  // Handle push events — the core claim-by-commit flow
  if (event === 'push') {
    const push = JSON.parse(body) as PushEvent

    // The GitHubApp.handlePush needs to fetch the workflow file from GitHub,
    // parse the claim token, then route to the correct DO shard.
    // We use a sharded stub resolver that wraps handlePush.
    const result = await handlePushWithSharding(githubApp, push, c.env)

    return c.json({
      event: 'push',
      delivery: deliveryId,
      ...result,
    })
  }

  // Handle installation events for logging/telemetry
  if (event === 'installation') {
    const payload = JSON.parse(body) as { action: string; installation: { id: number; account: { login: string } } }
    return c.json({
      received: true,
      event: 'installation',
      action: payload.action,
      account: payload.installation?.account?.login,
      delivery: deliveryId,
    })
  }

  // Handle installation_repositories events
  if (event === 'installation_repositories') {
    return c.json({
      received: true,
      event: 'installation_repositories',
      delivery: deliveryId,
    })
  }

  // Acknowledge all other events
  return c.json({
    received: true,
    event,
    delivery: deliveryId,
  })
})

// ── Fallback ──────────────────────────────────────────────────────────────

app.all('*', (c) => c.json({
  error: 'not_found',
  service: 'id.org.ai',
  tagline: 'Humans. Agents. Identity.',
}, 404))

export default app

// ============================================================================
// GitHub Push Sharding
// ============================================================================

/**
 * Handle a GitHub push webhook with identity sharding.
 *
 * The GitHubApp.handlePush method needs a DO stub, but the webhook doesn't
 * carry auth credentials — it carries a claim token embedded in the workflow
 * YAML. We resolve the claim token to an identity via KV, then pass the
 * correct shard's stub to handlePush.
 *
 * Flow:
 *   1. Check if any commit touches the headlessly workflow file
 *   2. If not, return early (no claim)
 *   3. Fetch the workflow file from GitHub
 *   4. Parse the claim token from the YAML
 *   5. Resolve identity ID from claim token via KV
 *   6. Get the correct DO stub for that identity
 *   7. Call the claim endpoint on that specific DO
 */
async function handlePushWithSharding(
  githubApp: GitHubApp,
  push: PushEvent,
  env: Env,
): Promise<{
  claimed: boolean
  claimToken?: string
  tenantId?: string
  level?: number
  branch?: string
  error?: string
}> {
  // Check if any commit touches the headlessly workflow
  const WORKFLOW_PATH = '.github/workflows/headlessly.yml'
  const touchedWorkflow = push.commits.some(
    (c) => c.added.includes(WORKFLOW_PATH) || c.modified.includes(WORKFLOW_PATH),
  )

  if (!touchedWorkflow) {
    return { claimed: false }
  }

  const branch = push.ref.replace('refs/heads/', '')

  if (!push.installation?.id) {
    return { claimed: false, branch, error: 'missing_installation_id' }
  }

  // Fetch the workflow file to extract the claim token
  let yamlContent: string | null = null
  try {
    yamlContent = await githubApp.fetchWorkflowContent(
      push.repository.full_name,
      push.ref,
      push.installation.id,
    )
  } catch (err: any) {
    return { claimed: false, branch, error: `fetch_workflow_failed: ${err.message}` }
  }

  if (!yamlContent) {
    return { claimed: false, branch, error: 'workflow_file_not_found' }
  }

  const claimToken = githubApp.parseClaimToken(yamlContent)
  if (!claimToken) {
    return { claimed: false, branch, error: 'no_claim_token_in_workflow' }
  }

  // Resolve the identity shard from the claim token
  const identityId = await resolveIdentityFromClaim(claimToken, env)
  if (!identityId) {
    return { claimed: false, claimToken, branch, error: 'unknown_claim_token' }
  }

  // Get the DO stub for this specific identity and execute the claim
  const stub = getStubForIdentity(env, identityId)

  try {
    const res = await stub.fetch(
      new Request('https://id.org.ai/api/claim', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Worker-Auth': env.AUTH_SECRET,
        },
        body: JSON.stringify({
          claimToken,
          githubUserId: String(push.sender.id),
          githubUsername: push.sender.login,
          githubEmail: push.sender.email,
          repo: push.repository.full_name,
          branch,
        }),
      }),
    )

    const result = await res.json() as {
      success: boolean
      identity?: { id: string; level: number }
      error?: string
    }

    if (!result.success) {
      return { claimed: false, claimToken, branch, error: result.error ?? 'claim_failed' }
    }

    return {
      claimed: true,
      claimToken,
      tenantId: result.identity?.id,
      level: result.identity?.level,
      branch,
    }
  } catch (err: any) {
    return { claimed: false, claimToken, branch, error: `claim_request_failed: ${err.message}` }
  }
}

// ============================================================================
// Helpers
// ============================================================================

/**
 * Build the list of MCP tools available at the given auth level.
 *
 * Tools by level:
 *   L0+: explore, search, fetch
 *   L1+: try, do
 */
function buildToolList(auth: MCPAuthResult): Array<{ name: string; description: string; inputSchema: Record<string, unknown> }> {
  const tools: Array<{ name: string; description: string; inputSchema: Record<string, unknown> }> = []

  // explore — available at all levels (L0+)
  tools.push({
    name: 'explore',
    description: 'Discover all 32 entity schemas with verbs, fields, and relationships. Start here to understand the system.',
    inputSchema: {
      type: 'object',
      properties: {
        type: { type: 'string', description: 'Specific entity type to explore (e.g. Contact, Deal, Subscription). Omit for full system overview.' },
        depth: { type: 'string', enum: ['summary', 'full'], description: 'Detail level: summary (names + verbs) or full (complete schemas with field types). Default: summary' },
      },
    },
  })

  // search — available at all levels (L0+)
  tools.push({
    name: 'search',
    description: 'Search entities across the graph — schemas, identities, organizations, and data',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search query' },
        type: { type: 'string', description: 'Entity type to search (e.g. Contact, schema, identity)' },
        limit: { type: 'number', description: 'Max results (default 10, max 100)' },
      },
      required: ['query'],
    },
  })

  // fetch — available at all levels (L0+)
  tools.push({
    name: 'fetch',
    description: 'Fetch a specific entity, schema, or session. Use type=schema to get entity definitions.',
    inputSchema: {
      type: 'object',
      properties: {
        type: { type: 'string', description: 'Resource type: schema, identity, session, or any entity name (Contact, Deal, etc.)' },
        id: { type: 'string', description: 'Resource ID. For schema type, this is the entity name.' },
        fields: { type: 'array', items: { type: 'string' }, description: 'Optional: specific fields to return' },
      },
      required: ['type'],
    },
  })

  // try — available at L1+ (requires session)
  if (auth.level >= 1) {
    tools.push({
      name: 'try',
      description: 'Execute-with-rollback. Run a sequence of operations and see the results WITHOUT persisting anything. Shows what would happen: entities created, events emitted, side effects triggered.',
      inputSchema: {
        type: 'object',
        properties: {
          operations: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                entity: { type: 'string', description: 'Entity type (e.g. Contact, Deal, Subscription)' },
                verb: { type: 'string', description: 'Verb to execute (e.g. create, close, qualify)' },
                data: { type: 'object', description: 'Operation data' },
              },
              required: ['entity', 'verb', 'data'],
            },
            description: 'Sequence of operations to simulate (max 50)',
          },
        },
        required: ['operations'],
      },
    })
  }

  // do — available at L1+ (requires session)
  if (auth.level >= 1) {
    tools.push({
      name: 'do',
      description: 'Execute any action on an entity for real. Creates/updates entities, emits events, triggers workflows.',
      inputSchema: {
        type: 'object',
        properties: {
          entity: { type: 'string', description: 'Entity type (e.g. Contact, Deal, Subscription)' },
          verb: { type: 'string', description: 'Verb to execute (e.g. create, update, close, qualify)' },
          data: { type: 'object', description: 'Operation data (fields, values, relationships)' },
        },
        required: ['entity', 'verb', 'data'],
      },
    })
  }

  return tools
}

/**
 * Build the list of MCP resources available at the given auth level.
 */
function buildResourceList(auth: MCPAuthResult): Array<{ name: string; description: string; uri: string }> {
  const resources: Array<{ name: string; description: string; uri: string }> = []

  resources.push({
    name: 'schema',
    description: 'Identity schema and type definitions',
    uri: 'id://schema',
  })

  if (auth.authenticated && auth.identityId) {
    resources.push({
      name: 'identity',
      description: 'Current authenticated identity',
      uri: `id://identity/${auth.identityId}`,
    })
  }

  return resources
}

/**
 * Build the GitHub Action workflow YAML for claim-by-commit.
 */
function buildClaimWorkflow(claimToken: string): string {
  return `name: Claim headless.ly tenant
on:
  push:
    branches: [main, master]
permissions:
  id-token: write
  contents: read
jobs:
  claim:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dot-org-ai/id@v1
        with:
          tenant: '${claimToken}'
`
}
