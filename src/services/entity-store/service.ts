/**
 * EntityStoreService — Generic indexed entity storage
 *
 * Extracted from IdentityDO's entity index management.
 * Provides CRUD, secondary indexing, query, and text search.
 *
 * Storage layout:
 *   entity:{owner}:{type}:{id}  → full JSON record
 *   idx:{owner}:{type}:{field}:{value}:{id} → true
 */

import { Ok, Err } from '../../foundation'
import type { Result } from '../../foundation'
import { NotFoundError, ValidationError } from '../../foundation'

// ── Interface ─────────────────────────────────────────────────────────────

export interface EntityStoreService {
  put(owner: string, entityType: string, entityId: string, record: Record<string, unknown>): Promise<Result<Record<string, unknown>, ValidationError>>
  get(owner: string, entityType: string, entityId: string): Promise<Result<Record<string, unknown>, NotFoundError>>
  delete(owner: string, entityType: string, entityId: string): Promise<Result<{ deleted: boolean }, never>>
  deleteIndexes(owner: string, entityType: string, entityId: string, record: Record<string, unknown>): Promise<void>
  query(
    owner: string,
    entityType: string,
    params: {
      filters?: Record<string, unknown>
      limit?: number
      offset?: number
    },
  ): Promise<{ items: Record<string, unknown>[]; total: number }>
  search(
    owner: string,
    query: string,
    params: {
      type?: string
      filters?: Record<string, unknown>
      limit?: number
      offset?: number
    },
  ): Promise<{ results: Array<{ type: string; id: string; data: Record<string, unknown>; score: number }>; total: number }>
}

// ── Implementation ────────────────────────────────────────────────────────

/** Fields that should not be indexed (JSON blobs, binary, internal) */
const NON_INDEXED_FIELDS = new Set(['id', 'metadata', 'properties', 'config', 'targeting', 'variants', 'steps', 'trigger', 'filters', 'fields', '$type'])

export class EntityStoreServiceImpl implements EntityStoreService {
  private readonly storage: DurableObjectStorage

  constructor(deps: { storage: DurableObjectStorage }) {
    this.storage = deps.storage
  }

  // ── CRUD ────────────────────────────────────────────────────────────

  async put(
    owner: string,
    entityType: string,
    entityId: string,
    record: Record<string, unknown>,
  ): Promise<Result<Record<string, unknown>, ValidationError>> {
    if (!entityType) return Err(new ValidationError('entityType', 'entityType must not be empty'))
    if (!entityId) return Err(new ValidationError('entityId', 'entityId must not be empty'))

    const storageKey = `entity:${owner}:${entityType}:${entityId}`
    const indexes = this.indexKeysForEntity(owner, entityType, entityId, record)

    const batch: Record<string, unknown> = {}
    batch[storageKey] = record
    for (const [key, val] of indexes) {
      batch[key] = val
    }
    await this.storage.put(batch)

    return Ok(record)
  }

  async get(owner: string, entityType: string, entityId: string): Promise<Result<Record<string, unknown>, NotFoundError>> {
    const storageKey = `entity:${owner}:${entityType}:${entityId}`
    const data = await this.storage.get<Record<string, unknown>>(storageKey)
    if (data === undefined || data === null) {
      return Err(new NotFoundError(entityType, entityId))
    }
    return Ok(data)
  }

  async delete(owner: string, entityType: string, entityId: string): Promise<Result<{ deleted: boolean }, never>> {
    const storageKey = `entity:${owner}:${entityType}:${entityId}`
    const existing = await this.storage.get<Record<string, unknown>>(storageKey)

    if (!existing) {
      return Ok({ deleted: false })
    }

    const indexes = this.indexKeysForEntity(owner, entityType, entityId, existing)
    const keysToDelete = [storageKey, ...indexes.keys()]
    await this.storage.delete(keysToDelete)

    return Ok({ deleted: true })
  }

  async deleteIndexes(owner: string, entityType: string, entityId: string, record: Record<string, unknown>): Promise<void> {
    const indexes = this.indexKeysForEntity(owner, entityType, entityId, record)
    if (indexes.size > 0) {
      await this.storage.delete([...indexes.keys()])
    }
  }

  // ── Query ───────────────────────────────────────────────────────────

  async query(
    owner: string,
    entityType: string,
    params: {
      filters?: Record<string, unknown>
      limit?: number
      offset?: number
    },
  ): Promise<{ items: Record<string, unknown>[]; total: number }> {
    const prefix = `entity:${owner}:${entityType}:`
    const entries = await this.storage.list<Record<string, unknown>>({ prefix })
    const limit = Math.min(params.limit ?? 20, 100)
    const offset = params.offset ?? 0

    let items: Record<string, unknown>[] = []
    for (const [, value] of entries) {
      if (!value || typeof value !== 'object') continue
      if (params.filters && !this.matchesFilters(value, params.filters)) continue
      items.push(value)
    }

    const total = items.length
    items = items.slice(offset, offset + limit)
    return { items, total }
  }

  // ── Search ──────────────────────────────────────────────────────────

  async search(
    owner: string,
    query: string,
    params: {
      type?: string
      filters?: Record<string, unknown>
      limit?: number
      offset?: number
    },
  ): Promise<{ results: Array<{ type: string; id: string; data: Record<string, unknown>; score: number }>; total: number }> {
    const limit = Math.min(params.limit ?? 20, 100)
    const offset = params.offset ?? 0
    const queryLower = query.toLowerCase().trim()

    let results: Array<{ type: string; id: string; data: Record<string, unknown>; score: number }> = []

    if (params.type) {
      // Search within a specific type
      const prefix = `entity:${owner}:${params.type}:`
      const entries = await this.storage.list<Record<string, unknown>>({ prefix })

      for (const [, value] of entries) {
        if (!value || typeof value !== 'object') continue
        if (params.filters && !this.matchesFilters(value, params.filters)) continue
        let score = 1
        if (queryLower) {
          score = this.calculateTextScore(value, queryLower)
          if (score === 0) continue
        }
        results.push({ type: params.type, id: String(value.id ?? ''), data: value, score })
      }
    } else if (params.filters && Object.keys(params.filters).length > 0) {
      // Search across all types with filters
      const prefix = `entity:${owner}:`
      const entries = await this.storage.list<Record<string, unknown>>({ prefix })

      for (const [key, value] of entries) {
        if (!value || typeof value !== 'object') continue
        const parts = key.split(':')
        const entityType = parts[2]
        if (!this.matchesFilters(value, params.filters!)) continue
        let score = 1
        if (queryLower) {
          score = this.calculateTextScore(value, queryLower)
          if (score === 0) continue
        }
        results.push({ type: entityType, id: String(value.id ?? ''), data: value, score })
      }
    } else if (queryLower) {
      // Text search across all types
      const prefix = `entity:${owner}:`
      const entries = await this.storage.list<Record<string, unknown>>({ prefix })

      for (const [key, value] of entries) {
        if (!value || typeof value !== 'object') continue
        const parts = key.split(':')
        const entityType = parts[2]
        const score = this.calculateTextScore(value, queryLower)
        if (score === 0) continue
        results.push({ type: entityType, id: String(value.id ?? ''), data: value, score })
      }
    }

    results.sort((a, b) => b.score - a.score)
    const total = results.length
    results = results.slice(offset, offset + limit)

    return { results, total }
  }

  // ── Private Helpers ─────────────────────────────────────────────────

  /** Returns the index keys for a given entity record */
  private indexKeysForEntity(owner: string, entityType: string, entityId: string, record: Record<string, unknown>): Map<string, true> {
    const keys = new Map<string, true>()
    for (const [field, value] of Object.entries(record)) {
      if (NON_INDEXED_FIELDS.has(field)) continue
      if (value === null || value === undefined) continue
      if (typeof value === 'object') continue
      const normalized = String(value).toLowerCase().slice(0, 128)
      keys.set(`idx:${owner}:${entityType}:${field}:${normalized}:${entityId}`, true)
    }
    return keys
  }

  /** Check if an entity record matches a set of field filters */
  private matchesFilters(record: Record<string, unknown>, filters: Record<string, unknown>): boolean {
    for (const [field, expected] of Object.entries(filters)) {
      const actual = record[field]
      if (actual === undefined || actual === null) return false
      if (typeof actual === 'string' && typeof expected === 'string') {
        if (actual.toLowerCase() !== expected.toLowerCase()) return false
      } else if (actual !== expected) {
        return false
      }
    }
    return true
  }

  /** Calculate a text relevance score for an entity against a query */
  private calculateTextScore(record: Record<string, unknown>, queryLower: string): number {
    let score = 0
    for (const [field, value] of Object.entries(record)) {
      if (value === null || value === undefined || typeof value === 'object') continue
      const strValue = String(value).toLowerCase()
      if (!strValue.includes(queryLower)) continue

      if (field === 'name' || field === 'title' || field === 'subject') {
        score += strValue === queryLower ? 20 : 10
      } else if (field === 'email' || field === 'slug' || field === 'key') {
        score += strValue === queryLower ? 15 : 8
      } else if (field === 'description' || field === 'body') {
        score += 3
      } else if (field === '$type') {
        score += 5
      } else {
        score += 2
      }
    }
    return score
  }
}
