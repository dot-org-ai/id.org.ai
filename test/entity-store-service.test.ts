/**
 * EntityStoreService Unit Tests
 *
 * Tests generic indexed entity storage: CRUD, secondary indexes, query, and search.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { EntityStoreServiceImpl } from '../src/services/entity-store/service'
import { isOk, isErr } from '../src/foundation/result'

// ── Mock DurableObjectStorage ─────────────────────────────────────────────

function createMockStorage(): DurableObjectStorage {
  const store = new Map<string, unknown>()

  return {
    get: vi.fn(async (key: string) => store.get(key)),
    put: vi.fn(async (key: string | Record<string, unknown>, value?: unknown) => {
      if (typeof key === 'string') {
        store.set(key, value)
      } else {
        for (const [k, v] of Object.entries(key)) {
          store.set(k, v)
        }
      }
    }),
    delete: vi.fn(async (key: string | string[]) => {
      if (Array.isArray(key)) {
        let count = 0
        for (const k of key) {
          if (store.has(k)) {
            store.delete(k)
            count++
          }
        }
        return count
      }
      const had = store.has(key)
      store.delete(key)
      return had
    }),
    list: vi.fn(async (options?: { prefix?: string; limit?: number; reverse?: boolean; start?: string }) => {
      const entries = new Map<string, unknown>()
      const prefix = options?.prefix ?? ''
      const limit = options?.limit ?? Infinity

      const matchingEntries: Array<[string, unknown]> = []
      for (const [key, value] of store) {
        if (key.startsWith(prefix)) {
          if (options?.start && key <= options.start) continue
          matchingEntries.push([key, value])
        }
      }

      matchingEntries.sort((a, b) => a[0].localeCompare(b[0]))

      for (const [key, value] of matchingEntries.slice(0, limit)) {
        entries.set(key, value)
      }
      return entries
    }),
    // Stubs for unused methods
    getAlarm: vi.fn(async () => null),
    setAlarm: vi.fn(async () => {}),
    deleteAlarm: vi.fn(async () => {}),
    deleteAll: vi.fn(async () => {}),
    transaction: vi.fn(async (fn: any) => fn({ get: vi.fn(), put: vi.fn(), delete: vi.fn() })),
    sync: vi.fn(async () => {}),
    getReader: vi.fn(),
    getCurrentBookmark: vi.fn(async () => ''),
    getBookmarkForTime: vi.fn(async () => ''),
    onNextSessionRestoreBookmark: vi.fn(async () => {}),
    sql: {} as any,
    transactionSync: vi.fn((fn: any) => fn()),
  } as unknown as DurableObjectStorage
}

/** Helper to inspect raw storage keys */
function getStoreKeys(storage: DurableObjectStorage): string[] {
  const store = (storage.list as any).mock as any
  // Call list with empty prefix to get all keys
  return []
}

// We need a way to inspect the raw store. Let's wrap it.
function createTestStorage() {
  const store = new Map<string, unknown>()
  const storage = createMockStorageWithStore(store)
  return { storage, store }
}

function createMockStorageWithStore(store: Map<string, unknown>): DurableObjectStorage {
  return {
    get: vi.fn(async (key: string) => store.get(key)),
    put: vi.fn(async (key: string | Record<string, unknown>, value?: unknown) => {
      if (typeof key === 'string') {
        store.set(key, value)
      } else {
        for (const [k, v] of Object.entries(key)) {
          store.set(k, v)
        }
      }
    }),
    delete: vi.fn(async (key: string | string[]) => {
      if (Array.isArray(key)) {
        let count = 0
        for (const k of key) {
          if (store.has(k)) {
            store.delete(k)
            count++
          }
        }
        return count
      }
      const had = store.has(key)
      store.delete(key)
      return had
    }),
    list: vi.fn(async (options?: { prefix?: string; limit?: number }) => {
      const entries = new Map<string, unknown>()
      const prefix = options?.prefix ?? ''
      const limit = options?.limit ?? Infinity

      const matchingEntries: Array<[string, unknown]> = []
      for (const [key, value] of store) {
        if (key.startsWith(prefix)) {
          matchingEntries.push([key, value])
        }
      }
      matchingEntries.sort((a, b) => a[0].localeCompare(b[0]))
      for (const [key, value] of matchingEntries.slice(0, limit)) {
        entries.set(key, value)
      }
      return entries
    }),
    getAlarm: vi.fn(async () => null),
    setAlarm: vi.fn(async () => {}),
    deleteAlarm: vi.fn(async () => {}),
    deleteAll: vi.fn(async () => {}),
    transaction: vi.fn(async (fn: any) => fn({ get: vi.fn(), put: vi.fn(), delete: vi.fn() })),
    sync: vi.fn(async () => {}),
    getReader: vi.fn(),
    getCurrentBookmark: vi.fn(async () => ''),
    getBookmarkForTime: vi.fn(async () => ''),
    onNextSessionRestoreBookmark: vi.fn(async () => {}),
    sql: {} as any,
    transactionSync: vi.fn((fn: any) => fn()),
  } as unknown as DurableObjectStorage
}

// ── Tests ─────────────────────────────────────────────────────────────────

describe('EntityStoreService', () => {
  let store: Map<string, unknown>
  let storage: DurableObjectStorage
  let svc: EntityStoreServiceImpl

  beforeEach(() => {
    const t = createTestStorage()
    store = t.store
    storage = t.storage
    svc = new EntityStoreServiceImpl({ storage })
  })

  // ── CRUD ──────────────────────────────────────────────────────────────

  describe('put()', () => {
    it('stores entity and returns Ok with record', async () => {
      const record = { id: 'c1', name: 'Acme', stage: 'Lead' }
      const result = await svc.put('owner1', 'Contact', 'c1', record)
      expect(isOk(result)).toBe(true)
      if (isOk(result)) {
        expect(result.data).toEqual(record)
      }
      // Verify storage key
      expect(store.has('entity:owner1:Contact:c1')).toBe(true)
      expect(store.get('entity:owner1:Contact:c1')).toEqual(record)
    })

    it('returns Err(ValidationError) for empty entityType', async () => {
      const result = await svc.put('owner1', '', 'c1', { id: 'c1' })
      expect(isErr(result)).toBe(true)
      if (isErr(result)) {
        expect(result.error._tag).toBe('ValidationError')
        expect(result.error.field).toBe('entityType')
      }
    })

    it('returns Err(ValidationError) for empty entityId', async () => {
      const result = await svc.put('owner1', 'Contact', '', { id: 'c1' })
      expect(isErr(result)).toBe(true)
      if (isErr(result)) {
        expect(result.error._tag).toBe('ValidationError')
        expect(result.error.field).toBe('entityId')
      }
    })

    it('creates secondary index keys for string fields', async () => {
      const record = { id: 'c1', name: 'Acme', stage: 'Lead' }
      await svc.put('owner1', 'Contact', 'c1', record)

      // Should have indexes for name and stage (not id — it is in NON_INDEXED_FIELDS... wait, actually 'name' and 'stage' are not excluded)
      expect(store.has('idx:owner1:Contact:name:acme:c1')).toBe(true)
      expect(store.has('idx:owner1:Contact:stage:lead:c1')).toBe(true)
    })

    it('does NOT index NON_INDEXED_FIELDS', async () => {
      const record = {
        id: 'c1',
        name: 'Acme',
        metadata: 'should-not-index',
        properties: 'should-not-index',
        config: 'should-not-index',
        targeting: 'should-not-index',
        variants: 'should-not-index',
        steps: 'should-not-index',
        trigger: 'should-not-index',
        filters: 'should-not-index',
        fields: 'should-not-index',
        $type: 'Contact',
      }
      await svc.put('owner1', 'Contact', 'c1', record)

      // id is in NON_INDEXED_FIELDS
      expect(store.has('idx:owner1:Contact:id:c1:c1')).toBe(false)
      expect(store.has('idx:owner1:Contact:metadata:should-not-index:c1')).toBe(false)
      expect(store.has('idx:owner1:Contact:properties:should-not-index:c1')).toBe(false)
      expect(store.has('idx:owner1:Contact:config:should-not-index:c1')).toBe(false)
      expect(store.has('idx:owner1:Contact:targeting:should-not-index:c1')).toBe(false)
      expect(store.has('idx:owner1:Contact:variants:should-not-index:c1')).toBe(false)
      expect(store.has('idx:owner1:Contact:steps:should-not-index:c1')).toBe(false)
      expect(store.has('idx:owner1:Contact:trigger:should-not-index:c1')).toBe(false)
      expect(store.has('idx:owner1:Contact:filters:should-not-index:c1')).toBe(false)
      expect(store.has('idx:owner1:Contact:fields:should-not-index:c1')).toBe(false)
      expect(store.has('idx:owner1:Contact:$type:contact:c1')).toBe(false)

      // name SHOULD be indexed
      expect(store.has('idx:owner1:Contact:name:acme:c1')).toBe(true)
    })

    it('does NOT index object/array/null values', async () => {
      const record = {
        id: 'c1',
        name: 'Acme',
        tags: ['a', 'b'],
        nested: { foo: 'bar' },
        empty: null,
      }
      await svc.put('owner1', 'Contact', 'c1', record)

      // Only name should be indexed
      expect(store.has('idx:owner1:Contact:name:acme:c1')).toBe(true)

      // Collect all idx keys
      const idxKeys = [...store.keys()].filter((k) => k.startsWith('idx:'))
      expect(idxKeys).toHaveLength(1) // only name
    })

    it('normalizes indexes to lowercase, max 128 chars', async () => {
      const longValue = 'A'.repeat(200)
      const record = { id: 'c1', name: 'UPPERCASE', longField: longValue }
      await svc.put('owner1', 'Contact', 'c1', record)

      // Lowercase
      expect(store.has('idx:owner1:Contact:name:uppercase:c1')).toBe(true)
      // Truncated to 128
      const expectedTruncated = 'a'.repeat(128)
      expect(store.has(`idx:owner1:Contact:longField:${expectedTruncated}:c1`)).toBe(true)
    })

    it('indexes number and boolean values as strings', async () => {
      const record = { id: 'c1', age: 30, active: true }
      await svc.put('owner1', 'Contact', 'c1', record)
      expect(store.has('idx:owner1:Contact:age:30:c1')).toBe(true)
      expect(store.has('idx:owner1:Contact:active:true:c1')).toBe(true)
    })
  })

  describe('get()', () => {
    it('returns Ok with entity', async () => {
      const record = { id: 'c1', name: 'Acme' }
      await svc.put('owner1', 'Contact', 'c1', record)

      const result = await svc.get('owner1', 'Contact', 'c1')
      expect(isOk(result)).toBe(true)
      if (isOk(result)) {
        expect(result.data).toEqual(record)
      }
    })

    it('returns Err(NotFoundError) for missing entity', async () => {
      const result = await svc.get('owner1', 'Contact', 'missing')
      expect(isErr(result)).toBe(true)
      if (isErr(result)) {
        expect(result.error._tag).toBe('NotFoundError')
      }
    })
  })

  describe('delete()', () => {
    it('removes entity + indexes, returns Ok({ deleted: true })', async () => {
      const record = { id: 'c1', name: 'Acme', stage: 'Lead' }
      await svc.put('owner1', 'Contact', 'c1', record)

      const result = await svc.delete('owner1', 'Contact', 'c1')
      expect(isOk(result)).toBe(true)
      if (isOk(result)) {
        expect(result.data).toEqual({ deleted: true })
      }

      // Entity gone
      expect(store.has('entity:owner1:Contact:c1')).toBe(false)
      // Indexes gone
      expect(store.has('idx:owner1:Contact:name:acme:c1')).toBe(false)
      expect(store.has('idx:owner1:Contact:stage:lead:c1')).toBe(false)
    })

    it('returns Ok({ deleted: false }) for missing entity — idempotent', async () => {
      const result = await svc.delete('owner1', 'Contact', 'missing')
      expect(isOk(result)).toBe(true)
      if (isOk(result)) {
        expect(result.data).toEqual({ deleted: false })
      }
    })
  })

  describe('deleteIndexes() + put() update pattern', () => {
    it('cleans old indexes and creates new ones', async () => {
      const record = { id: 'c1', name: 'Acme', stage: 'Lead' }
      await svc.put('owner1', 'Contact', 'c1', record)

      // Old indexes exist
      expect(store.has('idx:owner1:Contact:stage:lead:c1')).toBe(true)

      // Update: delete old indexes, then put new record
      await svc.deleteIndexes('owner1', 'Contact', 'c1', record)
      const updated = { id: 'c1', name: 'Acme', stage: 'Qualified' }
      await svc.put('owner1', 'Contact', 'c1', updated)

      // Old index gone
      expect(store.has('idx:owner1:Contact:stage:lead:c1')).toBe(false)
      // New index present
      expect(store.has('idx:owner1:Contact:stage:qualified:c1')).toBe(true)
      // Name index still present
      expect(store.has('idx:owner1:Contact:name:acme:c1')).toBe(true)
    })
  })

  // ── Query ─────────────────────────────────────────────────────────────

  describe('query()', () => {
    beforeEach(async () => {
      await svc.put('owner1', 'Contact', 'c1', { id: 'c1', name: 'Alice', stage: 'Lead' })
      await svc.put('owner1', 'Contact', 'c2', { id: 'c2', name: 'Bob', stage: 'Qualified' })
      await svc.put('owner1', 'Contact', 'c3', { id: 'c3', name: 'Charlie', stage: 'Lead' })
      await svc.put('owner1', 'Deal', 'd1', { id: 'd1', name: 'Big Deal', amount: 5000 })
    })

    it('returns all entities for owner+type', async () => {
      const result = await svc.query('owner1', 'Contact', {})
      expect(result.items).toHaveLength(3)
      expect(result.total).toBe(3)
    })

    it('does not return entities of different type', async () => {
      const result = await svc.query('owner1', 'Contact', {})
      const ids = result.items.map((i) => i.id)
      expect(ids).not.toContain('d1')
    })

    it('filters by field value', async () => {
      const result = await svc.query('owner1', 'Contact', { filters: { stage: 'Lead' } })
      expect(result.items).toHaveLength(2)
      const names = result.items.map((i) => i.name)
      expect(names).toContain('Alice')
      expect(names).toContain('Charlie')
    })

    it('paginates with limit and offset, returns total', async () => {
      const page1 = await svc.query('owner1', 'Contact', { limit: 2, offset: 0 })
      expect(page1.items).toHaveLength(2)
      expect(page1.total).toBe(3)

      const page2 = await svc.query('owner1', 'Contact', { limit: 2, offset: 2 })
      expect(page2.items).toHaveLength(1)
      expect(page2.total).toBe(3)
    })
  })

  // ── Search ────────────────────────────────────────────────────────────

  describe('search()', () => {
    beforeEach(async () => {
      await svc.put('owner1', 'Contact', 'c1', { id: 'c1', name: 'Alice Smith', description: 'A key contact' })
      await svc.put('owner1', 'Contact', 'c2', { id: 'c2', name: 'Bob Jones', description: 'Alice referral' })
      await svc.put('owner1', 'Deal', 'd1', { id: 'd1', name: 'Alice Deal', amount: 5000 })
    })

    it('returns scored results across all types', async () => {
      const result = await svc.search('owner1', 'alice', {})
      expect(result.results.length).toBeGreaterThan(0)
      expect(result.total).toBeGreaterThan(0)
      // Should find across Contact and Deal
      const types = new Set(result.results.map((r) => r.type))
      expect(types.has('Contact')).toBe(true)
      expect(types.has('Deal')).toBe(true)
    })

    it('name/title matches score higher than description', async () => {
      const result = await svc.search('owner1', 'alice', {})
      // c1 has 'Alice' in name (score 10) + description has 'alice' (would match? no, description says "A key contact")
      // Actually: c1 name='Alice Smith' has alice → 10, c2 description='Alice referral' has alice → 3, d1 name='Alice Deal' has alice → 10
      const c1 = result.results.find((r) => r.id === 'c1')
      const c2 = result.results.find((r) => r.id === 'c2')
      expect(c1).toBeDefined()
      expect(c2).toBeDefined()
      expect(c1!.score).toBeGreaterThan(c2!.score)
    })

    it('filters by type', async () => {
      const result = await svc.search('owner1', 'alice', { type: 'Contact' })
      expect(result.results.every((r) => r.type === 'Contact')).toBe(true)
      expect(result.results.length).toBe(2) // c1 name match, c2 description match
    })

    it('filters by field value', async () => {
      const result = await svc.search('owner1', 'alice', { filters: { name: 'Alice Smith' } })
      // Only c1 matches the filter name='Alice Smith'
      expect(result.results).toHaveLength(1)
      expect(result.results[0].id).toBe('c1')
    })

    it('returns empty results for non-matching query', async () => {
      const result = await svc.search('owner1', 'zzzznotfound', {})
      expect(result.results).toHaveLength(0)
      expect(result.total).toBe(0)
    })
  })
})
