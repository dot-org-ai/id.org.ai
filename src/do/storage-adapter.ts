import type { StorageAdapter } from '../storage'

/**
 * Adapts DurableObjectStorage to the StorageAdapter interface.
 * Used by Identity.ts to bridge ctx.storage to all services.
 */
export class DurableObjectStorageAdapter implements StorageAdapter {
  constructor(private storage: DurableObjectStorage) {}

  get<T = unknown>(key: string): Promise<T | undefined> {
    return this.storage.get(key) as Promise<T | undefined>
  }

  put(key: string, value: unknown, _options?: { expirationTtl?: number }): Promise<void> {
    // Note: DurableObjectStorage does not support expirationTtl natively.
    // TTL-based expiry is handled at the service layer where needed.
    return this.storage.put(key, value)
  }

  async delete(key: string): Promise<boolean> {
    return !!(await this.storage.delete(key))
  }

  list<T = unknown>(options?: {
    prefix?: string
    limit?: number
    start?: string
    reverse?: boolean
  }): Promise<Map<string, T>> {
    return this.storage.list(options) as Promise<Map<string, T>>
  }
}
