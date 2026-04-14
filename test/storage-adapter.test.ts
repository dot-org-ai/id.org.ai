import { describe, it, expect, beforeEach } from 'vitest'
import { MemoryStorageAdapter } from '../src/storage'

describe('MemoryStorageAdapter', () => {
  let storage: MemoryStorageAdapter

  beforeEach(() => {
    storage = new MemoryStorageAdapter()
  })

  it('get returns undefined for missing key', async () => {
    expect(await storage.get('nope')).toBeUndefined()
  })

  it('put then get returns value', async () => {
    await storage.put('k', { name: 'test' })
    expect(await storage.get('k')).toEqual({ name: 'test' })
  })

  it('delete returns true for existing key', async () => {
    await storage.put('k', 'v')
    expect(await storage.delete('k')).toBe(true)
    expect(await storage.get('k')).toBeUndefined()
  })

  it('delete returns false for missing key', async () => {
    expect(await storage.delete('nope')).toBe(false)
  })

  it('list with prefix filters keys', async () => {
    await storage.put('user:1', { id: '1' })
    await storage.put('user:2', { id: '2' })
    await storage.put('session:1', { id: 's1' })

    const result = await storage.list({ prefix: 'user:' })
    expect(result.size).toBe(2)
    expect(result.has('user:1')).toBe(true)
    expect(result.has('session:1')).toBe(false)
  })

  it('list with limit caps results', async () => {
    await storage.put('a:1', 1)
    await storage.put('a:2', 2)
    await storage.put('a:3', 3)

    const result = await storage.list({ prefix: 'a:', limit: 2 })
    expect(result.size).toBe(2)
  })

  it('list with reverse returns keys in reverse order', async () => {
    await storage.put('a:1', 1)
    await storage.put('a:2', 2)
    await storage.put('a:3', 3)

    const result = await storage.list({ prefix: 'a:', reverse: true })
    const keys = [...result.keys()]
    expect(keys).toEqual(['a:3', 'a:2', 'a:1'])
  })

  it('list with start skips keys before start', async () => {
    await storage.put('a:1', 1)
    await storage.put('a:2', 2)
    await storage.put('a:3', 3)

    const result = await storage.list({ prefix: 'a:', start: 'a:2' })
    expect(result.has('a:1')).toBe(false)
    expect(result.has('a:2')).toBe(false)
    expect(result.has('a:3')).toBe(true)
  })
})
