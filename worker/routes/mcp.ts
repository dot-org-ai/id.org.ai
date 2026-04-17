/**
 * MCP (Model Context Protocol) route module — GET/POST /mcp
 * Extracted from worker/index.ts (Phase 9).
 * Requires authentication (mounted after authenticateRequest middleware).
 */
import { Hono } from 'hono'
import type { Env, Variables } from '../types'
import type { IdentityStub } from '../../src/server/do/Identity'
import { MCPAuth } from '../../src/sdk/mcp/auth'
import type { MCPAuthResult } from '../../src/sdk/mcp/auth'
import { dispatchTool } from '../../src/sdk/mcp/tools'
import { AUDIT_EVENTS } from '../../src/sdk/audit'
import { logAuditEvent } from '../utils/audit'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

// ── Null Stub ───────────────────────────────────────────────────────────────
// A safe no-op stub for L0 (anonymous) requests that don't resolve a DO.

export const nullStub: IdentityStub = {
  async getIdentity() {
    return null
  },
  async provisionAnonymous() {
    throw new Error('Not available at L0')
  },
  async claim() {
    return { success: false, error: 'Not available at L0' }
  },
  async getSession() {
    return { valid: false }
  },
  async validateApiKey() {
    return { valid: false }
  },
  async createApiKey() {
    throw new Error('Not available at L0')
  },
  async listApiKeys() {
    return []
  },
  async revokeApiKey() {
    return null
  },
  async checkRateLimit() {
    return { allowed: true, remaining: 30, resetAt: Date.now() + 60_000 }
  },
  async verifyClaimToken() {
    return { valid: false }
  },
  async freezeIdentity() {
    throw new Error('Not available at L0')
  },
  async mcpSearch() {
    return { results: [], total: 0, limit: 20, offset: 0 }
  },
  async mcpFetch() {
    return { type: '', data: null }
  },
  async mcpDo() {
    return { success: false, entity: '', verb: '', error: 'Not available at L0' }
  },
  async ensureCliClient() {},
  async ensureOAuthDoClient() {},
  async ensureWebClients() {},
  async oauthStorageOp() {
    return {}
  },
  async writeAuditEvent() {},
  async queryAuditLog() {
    return { events: [], hasMore: false }
  },
  async storeWorkOSRefreshToken() {},
  async refreshWorkOSToken() {
    throw new Error('Not available at L0')
  },
  async clearWorkOSRefreshToken() {},
}

// ── Helpers ─────────────────────────────────────────────────────────────────

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
        depth: {
          type: 'string',
          enum: ['summary', 'full'],
          description: 'Detail level: summary (names + verbs) or full (complete schemas with field types). Default: summary',
        },
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
      description:
        'Execute-with-rollback. Run a sequence of operations and see the results WITHOUT persisting anything. Shows what would happen: entities created, events emitted, side effects triggered.',
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

// ── Routes ──────────────────────────────────────────────────────────────────

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
    // Audit: rate limit exceeded
    if (stub && auth.identityId) {
      await logAuditEvent(stub, {
        event: AUDIT_EVENTS.RATE_LIMIT_EXCEEDED,
        actor: auth.identityId,
        ip: c.req.raw.headers.get('cf-connecting-ip') ?? undefined,
        userAgent: c.req.raw.headers.get('user-agent') ?? undefined,
        metadata: { level: auth.level, remaining: auth.rateLimit.remaining },
      })
    }

    return c.json(
      {
        jsonrpc: '2.0',
        error: {
          code: -32000,
          message: 'Rate limit exceeded',
          data: meta,
        },
      },
      429,
    )
  }

  const body = (await c.req.json()) as { method?: string; params?: any; id?: string | number }

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
      return c.json(
        {
          jsonrpc: '2.0',
          id: body.id,
          error: {
            code: -32601,
            message: `Tool "${toolName}" requires Level ${requiredLevel}+ authentication`,
            data: { ...meta, requiredLevel, currentLevel: auth.level },
          },
        },
        403,
      )
    }

    // L1+ tools require a DO stub (authenticated identity)
    if (requiredLevel >= 1 && !stub) {
      return c.json(
        {
          jsonrpc: '2.0',
          id: body.id,
          error: {
            code: -32601,
            message: `Tool "${toolName}" requires authentication`,
            data: meta,
          },
        },
        401,
      )
    }

    // For L0 tools without a stub, pass a null-safe stub
    // (explore, search schema-only, and fetch schema-only don't need the DO)
    const effectiveStub = stub ?? nullStub

    // Dispatch to the tool handler
    const toolResult = await dispatchTool(toolName, body.params?.arguments ?? {}, effectiveStub, auth)

    return c.json({
      jsonrpc: '2.0',
      id: body.id,
      result: { ...toolResult, _meta: meta },
    })
  }

  return c.json(
    {
      jsonrpc: '2.0',
      id: body.id,
      error: { code: -32601, message: 'Method not found', data: meta },
    },
    404,
  )
})

export { app as mcpRoutes }
