/**
 * MCP Tools Unit Tests
 *
 * Tests for explore, try, search, fetch, and do tool handlers.
 * Includes tests for the queryable entity storage via mcp-search and mcp-fetch.
 */

import { describe, it, expect, vi } from 'vitest'
import { handleExplore, handleTry, handleSearch, handleFetch, handleDo, dispatchTool } from '../src/mcp/tools'
import type { MCPAuthResult } from '../src/mcp/auth'

// ── Auth Fixtures ───────────────────────────────────────────────────────

const L0_AUTH: MCPAuthResult = {
  authenticated: false,
  level: 0,
  scopes: ['read', 'search', 'fetch', 'explore'],
  capabilities: ['explore', 'search', 'fetch'],
  upgrade: { nextLevel: 1, action: 'provision', description: 'Provision', url: 'https://id.org.ai/api/provision' },
}

const L1_AUTH: MCPAuthResult = {
  authenticated: true,
  identityId: 'id-123',
  level: 1,
  scopes: ['read', 'write', 'search', 'fetch', 'explore', 'do', 'try', 'claim'],
  capabilities: ['explore', 'search', 'fetch', 'try', 'do'],
}

// ── Mock Identity Stub Helpers ──────────────────────────────────────────

/**
 * Creates a mock identity stub that simulates the IdentityDO endpoints.
 * Stores entities in an in-memory map to mirror the DO's storage layout.
 */
function createEntityStub() {
  const storage = new Map<string, Record<string, unknown>>()

  return {
    storage,
    stub: {
      fetch: vi.fn(async (input: string | Request): Promise<Response> => {
        const request = typeof input === 'string' ? new Request(input) : input
        const url = new URL(request.url)
        const path = url.pathname

        // ── mcp-do: create/update/delete entities ──
        if (path === '/api/mcp-do' && request.method === 'POST') {
          const body = await request.json() as {
            entity: string
            verb: string
            data: Record<string, unknown>
            identityId?: string
            timestamp: number
          }
          const entityId = (body.data.id as string) ?? crypto.randomUUID()
          const owner = body.identityId ?? 'global'
          const storageKey = `entity:${owner}:${body.entity}:${entityId}`

          if (body.verb === 'create') {
            const record = {
              ...body.data,
              id: entityId,
              $type: body.entity,
              createdAt: body.timestamp,
              updatedAt: body.timestamp,
            }
            storage.set(storageKey, record)
            return Response.json({
              success: true,
              entity: body.entity,
              verb: body.verb,
              result: record,
              events: [
                { type: `${body.verb}ing`, entity: body.entity, verb: body.verb, timestamp: new Date(body.timestamp).toISOString() },
                { type: `${body.verb}ed`, entity: body.entity, verb: body.verb, timestamp: new Date(body.timestamp).toISOString() },
              ],
            })
          }

          if (body.verb === 'delete') {
            storage.delete(storageKey)
            return Response.json({
              success: true,
              entity: body.entity,
              verb: body.verb,
              result: { id: entityId, deleted: true },
              events: [],
            })
          }

          // update / custom verbs
          const existing = storage.get(storageKey)
          const record = { ...(existing ?? {}), ...body.data, id: entityId, $type: body.entity, updatedAt: body.timestamp }
          storage.set(storageKey, record)
          return Response.json({
            success: true,
            entity: body.entity,
            verb: body.verb,
            result: record,
            events: [],
          })
        }

        // ── mcp-search: search entities ──
        if (path === '/api/mcp-search' && request.method === 'POST') {
          const body = await request.json() as {
            identityId: string
            query?: string
            type?: string
            filters?: Record<string, unknown>
            limit?: number
            offset?: number
          }

          const owner = body.identityId ?? 'global'
          const limit = Math.min(body.limit ?? 20, 100)
          const offset = body.offset ?? 0
          const queryLower = body.query?.toLowerCase().trim() ?? ''
          const prefix = body.type ? `entity:${owner}:${body.type}:` : `entity:${owner}:`

          let results: Array<{ type: string; id: string; data: Record<string, unknown>; score: number }> = []

          for (const [key, value] of storage) {
            if (!key.startsWith(prefix)) continue
            const parts = key.split(':')
            const entityType = parts[2]

            // Apply field filters
            if (body.filters) {
              let matches = true
              for (const [field, expected] of Object.entries(body.filters)) {
                const actual = value[field]
                if (actual === undefined || actual === null) { matches = false; break }
                if (typeof actual === 'string' && typeof expected === 'string') {
                  if (actual.toLowerCase() !== expected.toLowerCase()) { matches = false; break }
                } else if (actual !== expected) {
                  matches = false; break
                }
              }
              if (!matches) continue
            }

            // Text search
            let score = 1
            if (queryLower) {
              score = 0
              for (const [field, val] of Object.entries(value)) {
                if (val === null || val === undefined || typeof val === 'object') continue
                const strVal = String(val).toLowerCase()
                if (strVal.includes(queryLower)) {
                  if (field === 'name' || field === 'title') score += strVal === queryLower ? 20 : 10
                  else if (field === 'email') score += strVal === queryLower ? 15 : 8
                  else score += 2
                }
              }
              if (score === 0) continue
            }

            results.push({
              type: entityType,
              id: String(value.id ?? ''),
              data: value,
              score,
            })
          }

          results.sort((a, b) => b.score - a.score)
          const total = results.length
          results = results.slice(offset, offset + limit)
          return Response.json({ results, total, limit, offset })
        }

        // ── mcp-fetch: fetch entities by type/id ──
        if (path === '/api/mcp-fetch' && request.method === 'POST') {
          const body = await request.json() as {
            identityId: string
            type: string
            id?: string
            filters?: Record<string, unknown>
            limit?: number
            offset?: number
          }

          const owner = body.identityId ?? 'global'

          if (body.id) {
            const storageKey = `entity:${owner}:${body.type}:${body.id}`
            const data = storage.get(storageKey)
            if (!data) {
              return new Response(JSON.stringify({ type: body.type, id: body.id, data: null }), { status: 404 })
            }
            return Response.json({ type: body.type, id: body.id, data })
          }

          // List all entities of this type
          const prefix = `entity:${owner}:${body.type}:`
          const limit = Math.min(body.limit ?? 20, 100)
          const offset = body.offset ?? 0
          let items: Record<string, unknown>[] = []

          for (const [key, value] of storage) {
            if (!key.startsWith(prefix)) continue
            if (body.filters) {
              let matches = true
              for (const [field, expected] of Object.entries(body.filters)) {
                const actual = value[field]
                if (actual === undefined || actual === null) { matches = false; break }
                if (typeof actual === 'string' && typeof expected === 'string') {
                  if (actual.toLowerCase() !== expected.toLowerCase()) { matches = false; break }
                } else if (actual !== expected) {
                  matches = false; break
                }
              }
              if (!matches) continue
            }
            items.push(value)
          }

          const total = items.length
          items = items.slice(offset, offset + limit)
          return Response.json({ type: body.type, items, total, limit, offset })
        }

        return new Response(JSON.stringify({ error: 'not_found' }), { status: 404 })
      }),
    },
  }
}

// ── Explore Tests ───────────────────────────────────────────────────────

describe('handleExplore', () => {
  it('returns all 32 entities in summary mode', () => {
    const result = handleExplore({})
    expect(result.isError).toBeUndefined()

    const data = JSON.parse(result.content[0].text)
    expect(data.totalEntities).toBe(32)
    expect(data.totalVerbs).toBeGreaterThan(0)
    expect(Object.keys(data.domains)).toContain('CRM')
    expect(Object.keys(data.domains)).toContain('Projects')
    expect(Object.keys(data.domains)).toContain('Billing')
    expect(Object.keys(data.domains)).toContain('Support')
    expect(Object.keys(data.domains)).toContain('Analytics')
    expect(Object.keys(data.domains)).toContain('Marketing')
    expect(Object.keys(data.domains)).toContain('Experimentation')
    expect(Object.keys(data.domains)).toContain('Platform')
  })

  it('returns a specific entity by name', () => {
    const result = handleExplore({ type: 'Contact' })
    expect(result.isError).toBeUndefined()

    const data = JSON.parse(result.content[0].text)
    expect(data.name).toBe('Contact')
    expect(data.domain).toBe('CRM')
    expect(data.verbs).toBeDefined()
    expect(data.verbs.some((v: any) => v.name === 'qualify')).toBe(true)
  })

  it('returns full schema when depth is full', () => {
    const result = handleExplore({ type: 'Contact', depth: 'full' })
    expect(result.isError).toBeUndefined()

    const data = JSON.parse(result.content[0].text)
    expect(data.fields).toBeDefined()
    expect(data.fields.email).toBeDefined()
    expect(data.relationships).toBeDefined()
  })

  it('returns error for unknown entity', () => {
    const result = handleExplore({ type: 'NonExistent' })
    expect(result.isError).toBe(true)

    const data = JSON.parse(result.content[0].text)
    expect(data.error).toContain('Unknown entity type')
    expect(data.availableTypes).toBeDefined()
  })

  it('is case-insensitive for entity lookup', () => {
    const result = handleExplore({ type: 'contact' })
    expect(result.isError).toBeUndefined()

    const data = JSON.parse(result.content[0].text)
    expect(data.name).toBe('Contact')
  })
})

// ── Try Tests ───────────────────────────────────────────────────────────

describe('handleTry', () => {
  it('simulates a single create operation', () => {
    const result = handleTry({
      operations: [
        { entity: 'Contact', verb: 'create', data: { name: 'Alice', email: 'alice@test.com', stage: 'Lead' } },
      ],
    }, L1_AUTH)

    expect(result.isError).toBeUndefined()
    const data = JSON.parse(result.content[0].text)
    expect(data.rollback).toBe(true)
    expect(data.operations).toHaveLength(1)
    expect(data.operations[0].entity).toBe('Contact')
    expect(data.operations[0].verb).toBe('create')
    expect(data.operations[0].result.name).toBe('Alice')
    expect(data.operations[0].result.id).toMatch(/^try_contact_/)
  })

  it('generates correct lifecycle events', () => {
    const result = handleTry({
      operations: [
        { entity: 'Deal', verb: 'close', data: { stage: 'Closed Won' } },
      ],
    }, L1_AUTH)

    const data = JSON.parse(result.content[0].text)
    expect(data.operations[0].events).toHaveLength(2)
    expect(data.operations[0].events[0].type).toBe('closing')
    expect(data.operations[0].events[1].type).toBe('closed')
  })

  it('generates side effects for Deal.close', () => {
    const result = handleTry({
      operations: [
        { entity: 'Deal', verb: 'close', data: { stage: 'Closed Won' } },
      ],
    }, L1_AUTH)

    const data = JSON.parse(result.content[0].text)
    const sideEffects = data.operations[0].sideEffects
    expect(sideEffects.length).toBeGreaterThan(0)
    expect(sideEffects.some((s: string) => s.includes('deal.closed'))).toBe(true)
  })

  it('rejects operations at L0', () => {
    const result = handleTry({
      operations: [
        { entity: 'Contact', verb: 'create', data: { name: 'Blocked' } },
      ],
    }, L0_AUTH)

    expect(result.isError).toBe(true)
    const data = JSON.parse(result.content[0].text)
    expect(data.error).toContain('Level 1+')
  })

  it('rejects empty operations array', () => {
    const result = handleTry({ operations: [] }, L1_AUTH)
    expect(result.isError).toBe(true)
  })

  it('rejects more than 50 operations', () => {
    const ops = Array.from({ length: 51 }, (_, i) => ({
      entity: 'Contact',
      verb: 'create',
      data: { name: `Contact ${i}` },
    }))
    const result = handleTry({ operations: ops }, L1_AUTH)
    expect(result.isError).toBe(true)
    const data = JSON.parse(result.content[0].text)
    expect(data.count).toBe(51)
  })

  it('reports errors for unknown entity types', () => {
    const result = handleTry({
      operations: [
        { entity: 'Bogus', verb: 'create', data: {} },
      ],
    }, L1_AUTH)

    const data = JSON.parse(result.content[0].text)
    expect(data.operations[0].result.error).toContain('Unknown entity type')
  })

  it('reports errors for unknown verbs', () => {
    const result = handleTry({
      operations: [
        { entity: 'Contact', verb: 'teleport', data: {} },
      ],
    }, L1_AUTH)

    const data = JSON.parse(result.content[0].text)
    expect(data.operations[0].result.error).toContain('Unknown verb')
  })

  it('generates a human-readable summary', () => {
    const result = handleTry({
      operations: [
        { entity: 'Contact', verb: 'create', data: { name: 'Alice', email: 'a@test.com' } },
        { entity: 'Deal', verb: 'create', data: { title: 'Big Deal' } },
        { entity: 'Deal', verb: 'close', data: {} },
      ],
    }, L1_AUTH)

    const data = JSON.parse(result.content[0].text)
    expect(data.summary).toContain('create')
    expect(data.summary).toContain('Contact')
    expect(data.summary).toContain('Deal')
    expect(data.note).toContain('simulated')
  })
})

// ── Search Tests ────────────────────────────────────────────────────────

describe('handleSearch', () => {
  it('returns schema results for unauthenticated text search', async () => {
    const { stub } = createEntityStub()
    const result = await handleSearch({ query: 'contact' }, stub, L0_AUTH)
    expect(result.isError).toBeUndefined()

    const data = JSON.parse(result.content[0].text)
    expect(data.results.length).toBeGreaterThan(0)
    expect(data.results.some((r: any) => r.type === 'schema' && r.id === 'Contact')).toBe(true)
  })

  it('requires at least one of query, type, or filters', async () => {
    const { stub } = createEntityStub()
    const result = await handleSearch({ query: '' }, stub, L0_AUTH)
    expect(result.isError).toBe(true)

    const data = JSON.parse(result.content[0].text)
    expect(data.error).toContain('At least one of')
  })

  it('searches entity data when authenticated', async () => {
    const { stub, storage } = createEntityStub()

    // Pre-populate storage with test entities
    storage.set('entity:id-123:Contact:c1', {
      id: 'c1', $type: 'Contact', name: 'Alice Smith', email: 'alice@acme.co', stage: 'Lead',
    })
    storage.set('entity:id-123:Contact:c2', {
      id: 'c2', $type: 'Contact', name: 'Bob Jones', email: 'bob@acme.co', stage: 'Customer',
    })

    const result = await handleSearch({ query: 'alice' }, stub, L1_AUTH)
    const data = JSON.parse(result.content[0].text)

    // Should find Alice in entity data
    const aliceResult = data.results.find((r: any) => r.type === 'Contact' && r.id === 'c1')
    expect(aliceResult).toBeDefined()
    expect(aliceResult.snippet.name).toBe('Alice Smith')
  })

  it('filters by entity type', async () => {
    const { stub, storage } = createEntityStub()

    storage.set('entity:id-123:Contact:c1', {
      id: 'c1', $type: 'Contact', name: 'Alice', stage: 'Lead',
    })
    storage.set('entity:id-123:Deal:d1', {
      id: 'd1', $type: 'Deal', title: 'Alice Deal', stage: 'Discovery',
    })

    const result = await handleSearch({ query: 'alice', type: 'Contact' }, stub, L1_AUTH)
    const data = JSON.parse(result.content[0].text)

    // Only Contact results (data + schema), no Deal data
    const dealDataResults = data.results.filter((r: any) => r.type === 'Deal')
    expect(dealDataResults.length).toBe(0)

    const contactDataResult = data.results.find((r: any) => r.type === 'Contact')
    expect(contactDataResult).toBeDefined()
  })

  it('filters by field values', async () => {
    const { stub, storage } = createEntityStub()

    storage.set('entity:id-123:Contact:c1', {
      id: 'c1', $type: 'Contact', name: 'Alice', stage: 'Lead',
    })
    storage.set('entity:id-123:Contact:c2', {
      id: 'c2', $type: 'Contact', name: 'Bob', stage: 'Customer',
    })
    storage.set('entity:id-123:Contact:c3', {
      id: 'c3', $type: 'Contact', name: 'Charlie', stage: 'Lead',
    })

    const result = await handleSearch(
      { query: '', type: 'Contact', filters: { stage: 'Lead' } },
      stub,
      L1_AUTH,
    )
    const data = JSON.parse(result.content[0].text)

    // Should only find Leads — no schema results since query is empty
    const entityResults = data.results.filter((r: any) => r.type === 'Contact')
    expect(entityResults.length).toBe(2)
    expect(entityResults.every((r: any) => r.snippet.stage === 'Lead')).toBe(true)
  })

  it('combines text query with field filters', async () => {
    const { stub, storage } = createEntityStub()

    storage.set('entity:id-123:Contact:c1', {
      id: 'c1', $type: 'Contact', name: 'Alice Lead', stage: 'Lead',
    })
    storage.set('entity:id-123:Contact:c2', {
      id: 'c2', $type: 'Contact', name: 'Alice Customer', stage: 'Customer',
    })

    const result = await handleSearch(
      { query: 'alice', type: 'Contact', filters: { stage: 'Lead' } },
      stub,
      L1_AUTH,
    )
    const data = JSON.parse(result.content[0].text)

    const entityResults = data.results.filter((r: any) => r.type === 'Contact')
    expect(entityResults.length).toBe(1)
    expect(entityResults[0].snippet.name).toBe('Alice Lead')
  })

  it('respects pagination limit', async () => {
    const { stub, storage } = createEntityStub()

    for (let i = 0; i < 5; i++) {
      storage.set(`entity:id-123:Contact:c${i}`, {
        id: `c${i}`, $type: 'Contact', name: `Contact ${i}`, stage: 'Lead',
      })
    }

    const result = await handleSearch(
      { query: '', type: 'Contact', limit: 2 },
      stub,
      L1_AUTH,
    )
    const data = JSON.parse(result.content[0].text)
    expect(data.results.length).toBeLessThanOrEqual(2)
  })

  it('does not return entity data for unauthenticated requests', async () => {
    const { stub, storage } = createEntityStub()

    storage.set('entity:id-123:Contact:c1', {
      id: 'c1', $type: 'Contact', name: 'Secret Contact', stage: 'Lead',
    })

    const result = await handleSearch({ query: 'secret' }, stub, L0_AUTH)
    const data = JSON.parse(result.content[0].text)

    // Should only have schema results, no entity data
    const entityDataResults = data.results.filter((r: any) => r.type !== 'schema')
    expect(entityDataResults.length).toBe(0)
  })
})

// ── Fetch Tests ─────────────────────────────────────────────────────────

describe('handleFetch', () => {
  it('fetches schema by type name (unauthenticated)', async () => {
    const { stub } = createEntityStub()
    const result = await handleFetch({ type: 'schema', id: 'Contact' }, stub, L0_AUTH)
    expect(result.isError).toBeUndefined()

    const data = JSON.parse(result.content[0].text)
    expect(data.type).toBe('schema')
    expect(data.id).toBe('Contact')
    expect(data.data.name).toBe('Contact')
    expect(data.data.domain).toBe('CRM')
  })

  it('fetches all schemas when no id provided', async () => {
    const { stub } = createEntityStub()
    const result = await handleFetch({ type: 'schema' }, stub, L0_AUTH)
    expect(result.isError).toBeUndefined()

    const data = JSON.parse(result.content[0].text)
    expect(data.data.totalEntities).toBe(32)
  })

  it('fetches a single entity by type and id', async () => {
    const { stub, storage } = createEntityStub()

    storage.set('entity:id-123:Contact:c1', {
      id: 'c1', $type: 'Contact', name: 'Alice', email: 'alice@test.com', stage: 'Lead',
    })

    const result = await handleFetch({ type: 'Contact', id: 'c1' }, stub, L1_AUTH)
    expect(result.isError).toBeUndefined()

    const data = JSON.parse(result.content[0].text)
    expect(data.type).toBe('Contact')
    expect(data.id).toBe('c1')
    expect(data.data.name).toBe('Alice')
    expect(data.data.email).toBe('alice@test.com')
  })

  it('returns error when entity not found', async () => {
    const { stub } = createEntityStub()

    const result = await handleFetch({ type: 'Contact', id: 'nonexistent' }, stub, L1_AUTH)
    expect(result.isError).toBe(true)

    const data = JSON.parse(result.content[0].text)
    expect(data.data).toBeNull()
  })

  it('lists all entities of a type', async () => {
    const { stub, storage } = createEntityStub()

    storage.set('entity:id-123:Contact:c1', {
      id: 'c1', $type: 'Contact', name: 'Alice', stage: 'Lead',
    })
    storage.set('entity:id-123:Contact:c2', {
      id: 'c2', $type: 'Contact', name: 'Bob', stage: 'Customer',
    })
    storage.set('entity:id-123:Deal:d1', {
      id: 'd1', $type: 'Deal', title: 'Big Deal', stage: 'Discovery',
    })

    const result = await handleFetch({ type: 'Contact' }, stub, L1_AUTH)
    expect(result.isError).toBeUndefined()

    const data = JSON.parse(result.content[0].text)
    expect(data.type).toBe('Contact')
    expect(data.items).toHaveLength(2)
    expect(data.total).toBe(2)
  })

  it('lists entities with field filters', async () => {
    const { stub, storage } = createEntityStub()

    storage.set('entity:id-123:Contact:c1', {
      id: 'c1', $type: 'Contact', name: 'Alice', stage: 'Lead',
    })
    storage.set('entity:id-123:Contact:c2', {
      id: 'c2', $type: 'Contact', name: 'Bob', stage: 'Customer',
    })
    storage.set('entity:id-123:Contact:c3', {
      id: 'c3', $type: 'Contact', name: 'Charlie', stage: 'Lead',
    })

    const result = await handleFetch(
      { type: 'Contact', filters: { stage: 'Lead' } },
      stub,
      L1_AUTH,
    )
    expect(result.isError).toBeUndefined()

    const data = JSON.parse(result.content[0].text)
    expect(data.items).toHaveLength(2)
    expect(data.total).toBe(2)
    expect(data.items.every((item: any) => item.stage === 'Lead')).toBe(true)
  })

  it('applies field projection', async () => {
    const { stub, storage } = createEntityStub()

    storage.set('entity:id-123:Contact:c1', {
      id: 'c1', $type: 'Contact', name: 'Alice', email: 'alice@test.com', stage: 'Lead', phone: '555-1234',
    })

    const result = await handleFetch(
      { type: 'Contact', id: 'c1', fields: ['name', 'email'] },
      stub,
      L1_AUTH,
    )
    expect(result.isError).toBeUndefined()

    const data = JSON.parse(result.content[0].text)
    expect(data.data.name).toBe('Alice')
    expect(data.data.email).toBe('alice@test.com')
    expect(data.data.phone).toBeUndefined()
    expect(data.data.stage).toBeUndefined()
  })

  it('applies field projection to list results', async () => {
    const { stub, storage } = createEntityStub()

    storage.set('entity:id-123:Contact:c1', {
      id: 'c1', $type: 'Contact', name: 'Alice', email: 'alice@test.com', stage: 'Lead',
    })
    storage.set('entity:id-123:Contact:c2', {
      id: 'c2', $type: 'Contact', name: 'Bob', email: 'bob@test.com', stage: 'Customer',
    })

    const result = await handleFetch(
      { type: 'Contact', fields: ['name', 'stage'] },
      stub,
      L1_AUTH,
    )
    expect(result.isError).toBeUndefined()

    const data = JSON.parse(result.content[0].text)
    expect(data.items).toHaveLength(2)
    for (const item of data.items) {
      expect(item.name).toBeDefined()
      expect(item.stage).toBeDefined()
      expect(item.email).toBeUndefined()
    }
  })

  it('returns schema when entity type is known but not authenticated', async () => {
    const { stub } = createEntityStub()

    const result = await handleFetch({ type: 'Contact' }, stub, L0_AUTH)
    expect(result.isError).toBeUndefined()

    const data = JSON.parse(result.content[0].text)
    expect(data.type).toBe('schema')
    expect(data.data.name).toBe('Contact')
  })

  it('returns auth error for entity by id when not authenticated', async () => {
    const { stub } = createEntityStub()

    const result = await handleFetch({ type: 'Contact', id: 'c1' }, stub, L0_AUTH)
    expect(result.isError).toBe(true)

    const data = JSON.parse(result.content[0].text)
    expect(data.error).toContain('Authentication required')
    expect(data.schema).toBeDefined()
  })

  it('respects pagination parameters', async () => {
    const { stub, storage } = createEntityStub()

    for (let i = 0; i < 10; i++) {
      storage.set(`entity:id-123:Contact:c${i}`, {
        id: `c${i}`, $type: 'Contact', name: `Contact ${i}`, stage: 'Lead',
      })
    }

    const result = await handleFetch(
      { type: 'Contact', limit: 3, offset: 2 },
      stub,
      L1_AUTH,
    )
    expect(result.isError).toBeUndefined()

    const data = JSON.parse(result.content[0].text)
    expect(data.items.length).toBeLessThanOrEqual(3)
    expect(data.total).toBe(10)
  })

  it('returns error for unknown type', async () => {
    const { stub } = createEntityStub()
    const result = await handleFetch({ type: 'Nonexistent' }, stub, L0_AUTH)
    expect(result.isError).toBe(true)

    const data = JSON.parse(result.content[0].text)
    expect(data.error).toContain('Unknown type')
  })

  it('fetches session info', async () => {
    const { stub } = createEntityStub()
    const result = await handleFetch({ type: 'session' }, stub, L1_AUTH)
    expect(result.isError).toBeUndefined()

    const data = JSON.parse(result.content[0].text)
    expect(data.type).toBe('session')
    expect(data.data.identityId).toBe('id-123')
    expect(data.data.level).toBe(1)
  })
})

// ── Do + Search + Fetch Integration Tests ───────────────────────────────

describe('do + search + fetch integration', () => {
  it('creates entity via do, then finds it via search', async () => {
    const { stub } = createEntityStub()

    // Create a contact
    const doResult = await handleDo(
      { entity: 'Contact', verb: 'create', data: { name: 'Alice', email: 'alice@test.com', stage: 'Lead' } },
      stub,
      L1_AUTH,
    )
    expect(doResult.isError).toBeUndefined()
    const doData = JSON.parse(doResult.content[0].text)
    expect(doData.success).toBe(true)

    // Search for alice
    const searchResult = await handleSearch({ query: 'alice' }, stub, L1_AUTH)
    const searchData = JSON.parse(searchResult.content[0].text)

    const aliceResult = searchData.results.find((r: any) => r.type === 'Contact' && r.snippet?.name === 'Alice')
    expect(aliceResult).toBeDefined()
  })

  it('creates entity via do, then fetches it by id', async () => {
    const { stub } = createEntityStub()

    // Create a deal
    const doResult = await handleDo(
      { entity: 'Deal', verb: 'create', data: { id: 'deal-1', title: 'Big Deal', stage: 'Discovery', value: 50000 } },
      stub,
      L1_AUTH,
    )
    const doData = JSON.parse(doResult.content[0].text)
    expect(doData.success).toBe(true)

    // Fetch it back
    const fetchResult = await handleFetch({ type: 'Deal', id: 'deal-1' }, stub, L1_AUTH)
    const fetchData = JSON.parse(fetchResult.content[0].text)

    expect(fetchData.type).toBe('Deal')
    expect(fetchData.id).toBe('deal-1')
    expect(fetchData.data.title).toBe('Big Deal')
    expect(fetchData.data.value).toBe(50000)
  })

  it('creates multiple entities, lists them by type', async () => {
    const { stub } = createEntityStub()

    await handleDo({ entity: 'Contact', verb: 'create', data: { id: 'c1', name: 'Alice', stage: 'Lead' } }, stub, L1_AUTH)
    await handleDo({ entity: 'Contact', verb: 'create', data: { id: 'c2', name: 'Bob', stage: 'Customer' } }, stub, L1_AUTH)
    await handleDo({ entity: 'Deal', verb: 'create', data: { id: 'd1', title: 'Deal 1', stage: 'Discovery' } }, stub, L1_AUTH)

    // Fetch all contacts
    const fetchResult = await handleFetch({ type: 'Contact' }, stub, L1_AUTH)
    const fetchData = JSON.parse(fetchResult.content[0].text)

    expect(fetchData.items).toHaveLength(2)
    expect(fetchData.total).toBe(2)
  })

  it('creates entities, filters them by field value', async () => {
    const { stub } = createEntityStub()

    await handleDo({ entity: 'Contact', verb: 'create', data: { id: 'c1', name: 'Alice', stage: 'Lead' } }, stub, L1_AUTH)
    await handleDo({ entity: 'Contact', verb: 'create', data: { id: 'c2', name: 'Bob', stage: 'Customer' } }, stub, L1_AUTH)
    await handleDo({ entity: 'Contact', verb: 'create', data: { id: 'c3', name: 'Charlie', stage: 'Lead' } }, stub, L1_AUTH)

    // Search for Leads only
    const searchResult = await handleSearch(
      { query: '', type: 'Contact', filters: { stage: 'Lead' } },
      stub,
      L1_AUTH,
    )
    const searchData = JSON.parse(searchResult.content[0].text)

    const contactResults = searchData.results.filter((r: any) => r.type === 'Contact')
    expect(contactResults).toHaveLength(2)
    expect(contactResults.every((r: any) => r.snippet.stage === 'Lead')).toBe(true)
  })

  it('updates entity via do, then fetch reflects changes', async () => {
    const { stub } = createEntityStub()

    await handleDo({ entity: 'Contact', verb: 'create', data: { id: 'c1', name: 'Alice', stage: 'Lead' } }, stub, L1_AUTH)

    // Update the stage via qualify verb
    await handleDo({ entity: 'Contact', verb: 'qualify', data: { id: 'c1', stage: 'Qualified' } }, stub, L1_AUTH)

    const fetchResult = await handleFetch({ type: 'Contact', id: 'c1' }, stub, L1_AUTH)
    const fetchData = JSON.parse(fetchResult.content[0].text)

    expect(fetchData.data.stage).toBe('Qualified')
    expect(fetchData.data.name).toBe('Alice')
  })

  it('deletes entity via do, then fetch returns not found', async () => {
    const { stub } = createEntityStub()

    await handleDo({ entity: 'Contact', verb: 'create', data: { id: 'c1', name: 'Alice', stage: 'Lead' } }, stub, L1_AUTH)

    // Delete it
    await handleDo({ entity: 'Contact', verb: 'delete', data: { id: 'c1' } }, stub, L1_AUTH)

    const fetchResult = await handleFetch({ type: 'Contact', id: 'c1' }, stub, L1_AUTH)
    expect(fetchResult.isError).toBe(true)

    const fetchData = JSON.parse(fetchResult.content[0].text)
    expect(fetchData.data).toBeNull()
  })
})

// ── dispatchTool Tests ──────────────────────────────────────────────────

describe('dispatchTool', () => {
  const mockStub = {
    fetch: async () => new Response(JSON.stringify({})),
  }

  it('dispatches explore tool', async () => {
    const result = await dispatchTool('explore', {}, mockStub, L0_AUTH)
    const data = JSON.parse(result.content[0].text)
    expect(data.totalEntities).toBe(32)
  })

  it('dispatches try tool', async () => {
    const result = await dispatchTool('try', {
      operations: [{ entity: 'Contact', verb: 'create', data: { name: 'Test' } }],
    }, mockStub, L1_AUTH)

    const data = JSON.parse(result.content[0].text)
    expect(data.rollback).toBe(true)
  })

  it('dispatches search tool', async () => {
    const { stub, storage } = createEntityStub()
    storage.set('entity:id-123:Contact:c1', {
      id: 'c1', $type: 'Contact', name: 'Alice', stage: 'Lead',
    })

    const result = await dispatchTool('search', { query: 'alice' }, stub, L1_AUTH)
    const data = JSON.parse(result.content[0].text)
    expect(data.results).toBeDefined()
    expect(data.results.some((r: any) => r.type === 'Contact')).toBe(true)
  })

  it('dispatches fetch tool', async () => {
    const { stub, storage } = createEntityStub()
    storage.set('entity:id-123:Contact:c1', {
      id: 'c1', $type: 'Contact', name: 'Alice', stage: 'Lead',
    })

    const result = await dispatchTool('fetch', { type: 'Contact', id: 'c1' }, stub, L1_AUTH)
    const data = JSON.parse(result.content[0].text)
    expect(data.data.name).toBe('Alice')
  })

  it('dispatches fetch tool with filters', async () => {
    const { stub, storage } = createEntityStub()
    storage.set('entity:id-123:Contact:c1', {
      id: 'c1', $type: 'Contact', name: 'Alice', stage: 'Lead',
    })
    storage.set('entity:id-123:Contact:c2', {
      id: 'c2', $type: 'Contact', name: 'Bob', stage: 'Customer',
    })

    const result = await dispatchTool('fetch', { type: 'Contact', filters: { stage: 'Lead' } }, stub, L1_AUTH)
    const data = JSON.parse(result.content[0].text)
    expect(data.items).toHaveLength(1)
    expect(data.items[0].name).toBe('Alice')
  })

  it('returns error for unknown tool', async () => {
    const result = await dispatchTool('nonexistent', {}, mockStub, L0_AUTH)
    expect(result.isError).toBe(true)
    const data = JSON.parse(result.content[0].text)
    expect(data.error).toContain('Unknown tool')
  })
})
