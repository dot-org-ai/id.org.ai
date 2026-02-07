/**
 * MCP Tools Unit Tests
 *
 * Tests for explore, try, search, fetch, and do tool handlers.
 */

import { describe, it, expect } from 'vitest'
import { handleExplore, handleTry, dispatchTool } from '../src/mcp/tools'
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

  it('returns error for unknown tool', async () => {
    const result = await dispatchTool('nonexistent', {}, mockStub, L0_AUTH)
    expect(result.isError).toBe(true)
    const data = JSON.parse(result.content[0].text)
    expect(data.error).toContain('Unknown tool')
  })
})
