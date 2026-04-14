/**
 * Portable key-value storage interface.
 *
 * Mirrors the subset of DurableObjectStorage that id.org.ai services use.
 * This is the same shape that OAuthProvider already accepts (see worker/routes/oauth.ts).
 *
 * Implementations:
 *   - MemoryStorageAdapter (tests, in this file)
 *   - DurableObjectStorageAdapter (production, in do/storage-adapter.ts)
 */
export interface StorageAdapter {
  get<T = unknown>(key: string): Promise<T | undefined>
  put(key: string, value: unknown, options?: { expirationTtl?: number }): Promise<void>
  delete(key: string): Promise<boolean>
  list<T = unknown>(options?: {
    prefix?: string
    limit?: number
    start?: string
    reverse?: boolean
  }): Promise<Map<string, T>>
}

/**
 * In-memory StorageAdapter for tests.
 * Replaces the createMockStorage() pattern used across test files.
 */
export class MemoryStorageAdapter implements StorageAdapter {
  private data = new Map<string, unknown>()

  async get<T = unknown>(key: string): Promise<T | undefined> {
    return this.data.get(key) as T | undefined
  }

  async put(key: string, value: unknown): Promise<void> {
    this.data.set(key, value)
  }

  async delete(key: string): Promise<boolean> {
    return this.data.delete(key)
  }

  async list<T = unknown>(options?: {
    prefix?: string
    limit?: number
    start?: string
    reverse?: boolean
  }): Promise<Map<string, T>> {
    const prefix = options?.prefix ?? ''
    let entries: [string, unknown][] = []

    for (const [k, v] of this.data) {
      if (k.startsWith(prefix)) {
        if (options?.start && k <= options.start) continue
        entries.push([k, v])
      }
    }

    entries.sort((a, b) => a[0].localeCompare(b[0]))
    if (options?.reverse) entries.reverse()
    if (options?.limit) entries = entries.slice(0, options.limit)

    return new Map(entries) as Map<string, T>
  }
}
