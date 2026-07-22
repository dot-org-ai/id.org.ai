/**
 * MCP OAuth 2.1 resource-server conformance (ax-e6b.20.3).
 *
 * Dogfoods the api.qa MCP-auth conformance check (ax-e6b.20.1): id.org.ai's
 * /mcp endpoint must behave as a conformant OAuth 2.1 protected resource.
 *
 * Covers the three gaps:
 *   GAP 1 - unauthenticated /mcp -> 401 with WWW-Authenticate: Bearer
 *           resource_metadata pointing at the RFC 9728 protected-resource
 *           metadata (the discovery chain MCP clients read).
 *   GAP 2 - RFC 8707 audience binding: a token minted WITH resource=/mcp is
 *           accepted; a token bound to a DIFFERENT resource (or none) is
 *           REJECTED at /mcp - no cross-resource token replay.
 *   GAP 3 - the protected-resource `resource` is the canonical /mcp URI.
 */

import { describe, it, expect, vi } from 'vitest'
import { Hono } from 'hono'
import { mcpRoutes } from '../worker/routes/mcp'
import { authenticateRequest } from '../worker/middleware/auth'
import {
  mcpResourceUri,
  protectedResourceMetadataUrl,
  mcpWwwAuthenticate,
  canonicalizeResourceUri,
} from '../worker/utils/mcp-resource'
import { MCPAuth } from '../src/sdk/mcp/auth'
import type { MCPAuthResult } from '../src/sdk/mcp/auth'
import type { Env, Variables } from '../worker/types'

const ORIGIN = 'https://id.org.ai'
const MCP_URL = `${ORIGIN}/mcp`

// -- GAP 3 + helpers: canonical identifiers ----------------------------------

describe('MCP resource-server identifiers (RFC 9728 / RFC 8707)', () => {
  it('resource URI is the canonical <origin>/mcp audience', () => {
    expect(mcpResourceUri(ORIGIN)).toBe('https://id.org.ai/mcp')
    expect(mcpResourceUri('http://localhost:8787')).toBe('http://localhost:8787/mcp')
  })

  it('protected-resource metadata URL is the RFC 9728 root well-known', () => {
    expect(protectedResourceMetadataUrl(ORIGIN)).toBe('https://id.org.ai/.well-known/oauth-protected-resource')
  })

  it('WWW-Authenticate references the protected-resource metadata (RFC 9728 sec 5.1)', () => {
    const wa = mcpWwwAuthenticate(ORIGIN)
    expect(wa).toContain('Bearer')
    expect(wa).toContain('resource_metadata=')
    // api.qa asserts wa.includes(wellKnownAt(mcpUrl,'oauth-protected-resource'))
    expect(wa).toContain(protectedResourceMetadataUrl(ORIGIN))
  })
})

// -- GAP 1: unauthenticated /mcp is challenged -------------------------------

function makeMcpApp(auth: MCPAuthResult) {
  const app = new Hono<{ Bindings: Env; Variables: Variables }>()
  app.use('*', async (c, next) => {
    c.set('auth', auth as never)
    await next()
  })
  app.route('', mcpRoutes)
  return app
}

describe('GAP 1 - unauthenticated /mcp returns 401 + WWW-Authenticate', () => {
  it('GET /mcp anonymous -> 401 with Bearer resource_metadata challenge', async () => {
    const app = makeMcpApp(MCPAuth.anonymousResult())
    const res = await app.request(MCP_URL, { method: 'GET' })
    expect(res.status).toBe(401)
    const wa = res.headers.get('www-authenticate')
    expect(wa).toBeTruthy()
    expect(/bearer/i.test(wa!)).toBe(true)
    expect(wa).toContain('resource_metadata=')
    expect(wa).toContain(protectedResourceMetadataUrl(ORIGIN))
  })

  it('POST /mcp anonymous -> 401 with challenge', async () => {
    const app = makeMcpApp(MCPAuth.anonymousResult())
    const res = await app.request(MCP_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }),
    })
    expect(res.status).toBe(401)
    expect(res.headers.get('www-authenticate')).toContain(protectedResourceMetadataUrl(ORIGIN))
  })

  it('authenticated GET /mcp -> 200 (challenge only when unauthenticated)', async () => {
    const authed: MCPAuthResult = { authenticated: true, identityId: 'human:u1', level: 2, scopes: ['read'], capabilities: [] }
    const app = makeMcpApp(authed)
    const res = await app.request(MCP_URL, { method: 'GET' })
    expect(res.status).toBe(200)
    expect(res.headers.get('www-authenticate')).toBeNull()
  })
})

// -- GAP 2: RFC 8707 audience binding enforced at the resource server ---------

function makeCtx(opts: { url: string; authorization?: string; env: any }) {
  const headers = new Headers()
  if (opts.authorization) headers.set('authorization', opts.authorization)
  const store = new Map<string, unknown>()
  const resHeaders = new Headers()
  const c: any = {
    env: opts.env,
    req: { raw: { headers }, url: opts.url },
    get: (k: string) => store.get(k),
    set: (k: string, v: unknown) => store.set(k, v),
    header: (k: string, v: string) => resHeaders.set(k, v),
    json: (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: resHeaders }),
  }
  return { c, store, resHeaders }
}

function makeEnv(tokenRecord: unknown, identity: unknown) {
  const oauthStub = {
    oauthStorageOp: vi.fn(async (op: any) =>
      op.op === 'get' && typeof op.key === 'string' && op.key.startsWith('access:') && tokenRecord
        ? { value: tokenRecord }
        : {},
    ),
  }
  const identityStub = {
    getIdentity: vi.fn(async () => identity),
    checkRateLimit: vi.fn(async () => ({ allowed: true, remaining: 5, resetAt: Date.now() + 60000 })),
  }
  const env = {
    IDENTITY: {
      idFromName: (n: string) => n,
      get: (n: string) => (n === 'oauth' ? oauthStub : identityStub),
    },
  }
  return { env, oauthStub, identityStub }
}

const IDENTITY = { id: 'human:u1', type: 'human', name: 'U', verified: true, level: 2, claimStatus: 'claimed' }
const TOKEN = 'at_abc123'

describe('GAP 2 - audience binding (RFC 8707) at /mcp', () => {
  it('ACCEPTS a token bound to the /mcp resource', async () => {
    const rec = { identityId: 'human:u1', scopes: ['openid'], expiresAt: Date.now() + 60_000, resource: MCP_URL }
    const { env } = makeEnv(rec, IDENTITY)
    const { c, store } = makeCtx({ url: MCP_URL, authorization: `Bearer ${TOKEN}`, env })
    let nexted = false
    const ret = await authenticateRequest(c, async () => {
      nexted = true
    })
    expect(ret).toBeUndefined() // next() path, no early Response
    expect(nexted).toBe(true)
    const auth = store.get('auth') as MCPAuthResult
    expect(auth.authenticated).toBe(true)
    expect(auth.identityId).toBe('human:u1')
    expect(store.get('identity')).toBeTruthy()
  })

  it('REJECTS a token bound to a DIFFERENT resource (no cross-resource replay)', async () => {
    const rec = { identityId: 'human:u1', scopes: ['openid'], expiresAt: Date.now() + 60_000, resource: 'https://id.org.ai/other' }
    const { env } = makeEnv(rec, IDENTITY)
    const { c } = makeCtx({ url: MCP_URL, authorization: `Bearer ${TOKEN}`, env })
    const ret = (await authenticateRequest(c, async () => {})) as Response
    expect(ret).toBeInstanceOf(Response)
    expect(ret.status).toBe(401)
    expect(ret.headers.get('www-authenticate')).toContain(protectedResourceMetadataUrl(ORIGIN))
  })

  it('REJECTS a token with NO resource/aud (strict: aud required for /mcp)', async () => {
    const rec = { identityId: 'human:u1', scopes: ['openid'], expiresAt: Date.now() + 60_000 }
    const { env } = makeEnv(rec, IDENTITY)
    const { c } = makeCtx({ url: MCP_URL, authorization: `Bearer ${TOKEN}`, env })
    const ret = (await authenticateRequest(c, async () => {})) as Response
    expect(ret.status).toBe(401)
    expect(ret.headers.get('www-authenticate')).toContain('resource_metadata=')
  })

  it('REJECTS an expired token', async () => {
    const rec = { identityId: 'human:u1', scopes: ['openid'], expiresAt: Date.now() - 1_000, resource: MCP_URL }
    const { env } = makeEnv(rec, IDENTITY)
    const { c } = makeCtx({ url: MCP_URL, authorization: `Bearer ${TOKEN}`, env })
    const ret = (await authenticateRequest(c, async () => {})) as Response
    expect(ret.status).toBe(401)
  })

  it('REJECTS an unknown token', async () => {
    const { env } = makeEnv(undefined, IDENTITY)
    const { c } = makeCtx({ url: MCP_URL, authorization: `Bearer ${TOKEN}`, env })
    const ret = (await authenticateRequest(c, async () => {})) as Response
    expect(ret.status).toBe(401)
  })
})

// -- LOW gap fixes ------------------------------------------------------------

describe('LOW gap - multi-valued (array) RFC 8707 audience', () => {
  it('ACCEPTS an array-valued resource that INCLUDES the /mcp audience', async () => {
    const rec = {
      identityId: 'human:u1',
      scopes: ['openid'],
      expiresAt: Date.now() + 60_000,
      resource: ['https://id.org.ai/mcp', 'https://other'],
    }
    const { env } = makeEnv(rec, IDENTITY)
    const { c, store } = makeCtx({ url: MCP_URL, authorization: `Bearer ${TOKEN}`, env })
    let nexted = false
    const ret = await authenticateRequest(c, async () => {
      nexted = true
    })
    expect(ret).toBeUndefined()
    expect(nexted).toBe(true)
    expect((store.get('auth') as MCPAuthResult).authenticated).toBe(true)
  })

  it('REJECTS an array-valued resource that does NOT include the /mcp audience', async () => {
    const rec = {
      identityId: 'human:u1',
      scopes: ['openid'],
      expiresAt: Date.now() + 60_000,
      resource: ['https://other'],
    }
    const { env } = makeEnv(rec, IDENTITY)
    const { c } = makeCtx({ url: MCP_URL, authorization: `Bearer ${TOKEN}`, env })
    const ret = (await authenticateRequest(c, async () => {})) as Response
    expect(ret).toBeInstanceOf(Response)
    expect(ret.status).toBe(401)
  })

  it('ACCEPTS a resource with a trailing slash (canonicalized before compare)', async () => {
    const rec = {
      identityId: 'human:u1',
      scopes: ['openid'],
      expiresAt: Date.now() + 60_000,
      resource: 'https://id.org.ai/mcp/',
    }
    const { env } = makeEnv(rec, IDENTITY)
    const { c, store } = makeCtx({ url: MCP_URL, authorization: `Bearer ${TOKEN}`, env })
    let nexted = false
    const ret = await authenticateRequest(c, async () => {
      nexted = true
    })
    expect(ret).toBeUndefined()
    expect(nexted).toBe(true)
    expect((store.get('auth') as MCPAuthResult).authenticated).toBe(true)
  })

  it('canonicalizeResourceUri lowercases scheme+host, trims trailing slash, preserves path case', () => {
    expect(canonicalizeResourceUri('https://ID.org.ai/mcp/')).toBe('https://id.org.ai/mcp')
    expect(canonicalizeResourceUri('HTTPS://id.org.ai/Mcp')).toBe('https://id.org.ai/Mcp')
    expect(canonicalizeResourceUri(mcpResourceUri(ORIGIN))).toBe(canonicalizeResourceUri('https://id.org.ai/mcp/'))
  })
})

describe('LOW gap - expiry fails closed when expiresAt is missing/non-numeric', () => {
  it('REJECTS a token record with a missing expiresAt (not treated as non-expiring)', async () => {
    const rec = { identityId: 'human:u1', scopes: ['openid'], resource: MCP_URL } as any
    const { env } = makeEnv(rec, IDENTITY)
    const { c } = makeCtx({ url: MCP_URL, authorization: `Bearer ${TOKEN}`, env })
    const ret = (await authenticateRequest(c, async () => {})) as Response
    expect(ret).toBeInstanceOf(Response)
    expect(ret.status).toBe(401)
  })

  it('REJECTS a token record with a non-numeric (NaN) expiresAt', async () => {
    const rec = { identityId: 'human:u1', scopes: ['openid'], expiresAt: NaN, resource: MCP_URL } as any
    const { env } = makeEnv(rec, IDENTITY)
    const { c } = makeCtx({ url: MCP_URL, authorization: `Bearer ${TOKEN}`, env })
    const ret = (await authenticateRequest(c, async () => {})) as Response
    expect(ret).toBeInstanceOf(Response)
    expect(ret.status).toBe(401)
  })
})

describe('LOW gap - at_ tokens are not honored outside /mcp', () => {
  it('a /mcp-bound at_ token presented at a NON-/mcp route does not authenticate via the at_ path', async () => {
    const rec = { identityId: 'human:u1', scopes: ['openid'], expiresAt: Date.now() + 60_000, resource: MCP_URL }
    const { env } = makeEnv(rec, IDENTITY)
    const otherUrl = `${ORIGIN}/api/whoami`
    const { c, store } = makeCtx({ url: otherUrl, authorization: `Bearer ${TOKEN}`, env })
    let nexted = false
    const ret = await authenticateRequest(c, async () => {
      nexted = true
    })
    // Falls through to the broker path (no stub/creds it understands here) —
    // it must NOT resolve to the identity behind the at_ token.
    expect(ret).toBeUndefined()
    expect(nexted).toBe(true)
    const auth = store.get('auth') as MCPAuthResult | undefined
    if (auth) {
      expect(auth.authenticated).not.toBe(true)
      expect(auth.identityId).not.toBe('human:u1')
    }
    expect(store.get('identity')).toBeFalsy()
  })
})
