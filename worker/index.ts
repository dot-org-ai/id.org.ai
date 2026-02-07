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

export { IdentityDO }

interface Env {
  IDENTITY: DurableObjectNamespace
  DB: D1Database
  SESSIONS: KVNamespace
  WORKOS_API_KEY: string
  WORKOS_CLIENT_ID: string
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

// ── CORS ──────────────────────────────────────────────────────────────────

app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  credentials: true,
}))

// ── Identity Stub Middleware ──────────────────────────────────────────────
// Injects the IdentityDO stub into context for all downstream handlers.

app.use('*', async (c, next) => {
  const id = c.env.IDENTITY.idFromName('global')
  const stub = c.env.IDENTITY.get(id)
  c.set('identityStub', stub)
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
  const base = 'https://id.org.ai'
  return c.json({
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    userinfo_endpoint: `${base}/oauth/userinfo`,
    jwks_uri: `${base}/.well-known/jwks.json`,
    registration_endpoint: `${base}/oauth/register`,
    device_authorization_endpoint: `${base}/oauth/device`,
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256', 'ES256'],
  })
})

// ── MCP Auth Middleware ───────────────────────────────────────────────────
// Authenticates every request below this point. The auth result is always
// set in context — L0 (anonymous) is a valid result, not an error.

app.use('/api/*', async (c, next) => {
  const stub = c.get('identityStub')
  const mcpAuth = new MCPAuth(stub)
  const auth = await mcpAuth.authenticate(c.req.raw)
  c.set('auth', auth)
  await next()
})

app.use('/mcp', async (c, next) => {
  const stub = c.get('identityStub')
  const mcpAuth = new MCPAuth(stub)
  const auth = await mcpAuth.authenticate(c.req.raw)
  c.set('auth', auth)
  await next()
})

app.use('/mcp/*', async (c, next) => {
  const stub = c.get('identityStub')
  const mcpAuth = new MCPAuth(stub)
  const auth = await mcpAuth.authenticate(c.req.raw)
  c.set('auth', auth)
  await next()
})

// ── MCP Endpoint ──────────────────────────────────────────────────────────
// Returns capabilities based on auth level. This is the entry point for
// agents connecting via MCP protocol.

app.get('/mcp', async (c) => {
  const auth = c.get('auth')
  const stub = c.get('identityStub')
  const mcpAuth = new MCPAuth(stub)
  const meta = mcpAuth.buildMeta(auth)

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
  const mcpAuth = new MCPAuth(stub)
  const meta = mcpAuth.buildMeta(auth)

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

    // Dispatch to the tool handler
    const toolResult = await dispatchTool(toolName, body.params?.arguments ?? {}, stub, auth)

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

app.post('/api/provision', async (c) => {
  const stub = c.get('identityStub')
  const claimService = new ClaimService(stub)

  try {
    const result = await claimService.provision()
    return c.json(result, 201)
  } catch (err: any) {
    return c.json({ error: 'provision_failed', message: err.message }, 500)
  }
})

// ── Claim Status Endpoint ─────────────────────────────────────────────────

app.get('/api/claim/:token', async (c) => {
  const token = c.req.param('token')
  const stub = c.get('identityStub')

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

  const stub = c.get('identityStub')
  const claimService = new ClaimService(stub)

  try {
    const result = await claimService.freeze(auth.identityId)
    return c.json(result)
  } catch (err: any) {
    return c.json({ error: 'freeze_failed', message: err.message }, 500)
  }
})

// ── Forward identity operations to IdentityDO ─────────────────────────────

app.all('/api/*', async (c) => {
  const stub = c.get('identityStub')
  return stub.fetch(c.req.raw)
})

// ── OAuth endpoints → IdentityDO ──────────────────────────────────────────

app.all('/oauth/*', async (c) => {
  const stub = c.get('identityStub')
  return stub.fetch(c.req.raw)
})

// ── Claim page (human-facing) ─────────────────────────────────────────────

app.get('/claim/:token', async (c) => {
  const token = c.req.param('token')
  const stub = c.get('identityStub')
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
    const stub = c.get('identityStub')
    const result = await githubApp.handlePush(push, stub)

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
