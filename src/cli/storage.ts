/**
 * CLI Token Storage for id.org.ai
 *
 * Stores token data in ~/.id.org.ai/token with restricted permissions (0600).
 * Compatible with oauth.do storage patterns.
 */

export interface StoredTokenData {
  accessToken: string
  refreshToken?: string
  expiresAt?: number
}

export interface TokenStorage {
  getToken(): Promise<string | null>
  setToken(token: string): Promise<void>
  removeToken(): Promise<void>
  getTokenData(): Promise<StoredTokenData | null>
  setTokenData(data: StoredTokenData): Promise<void>
}

export class SecureFileTokenStorage implements TokenStorage {
  private tokenPath: string | null = null
  private configDir: string | null = null
  private initialized = false
  private customPath?: string

  constructor(customPath?: string) {
    this.customPath = customPath
  }

  private async init(): Promise<boolean> {
    if (this.initialized) return this.tokenPath !== null
    this.initialized = true

    try {
      const os = await import('os')
      const path = await import('path')

      if (this.customPath) {
        const expandedPath = this.customPath.startsWith('~/')
          ? path.join(os.homedir(), this.customPath.slice(2))
          : this.customPath
        this.tokenPath = expandedPath
        this.configDir = path.dirname(expandedPath)
      } else {
        this.configDir = path.join(os.homedir(), '.id.org.ai')
        this.tokenPath = path.join(this.configDir, 'token')
      }
      return true
    } catch {
      return false
    }
  }

  async getToken(): Promise<string | null> {
    const data = await this.getTokenData()
    return data?.accessToken ?? null
  }

  async setToken(token: string): Promise<void> {
    await this.setTokenData({ accessToken: token.trim() })
  }

  async getTokenData(): Promise<StoredTokenData | null> {
    if (!(await this.init()) || !this.tokenPath) return null

    try {
      const fs = await import('fs/promises')
      const content = await fs.readFile(this.tokenPath, 'utf-8')
      const trimmed = content.trim()

      if (trimmed.startsWith('{')) {
        return JSON.parse(trimmed) as StoredTokenData
      }
      return { accessToken: trimmed }
    } catch {
      return null
    }
  }

  async setTokenData(data: StoredTokenData): Promise<void> {
    if (!(await this.init()) || !this.tokenPath || !this.configDir) {
      throw new Error('File storage not available')
    }

    const fs = await import('fs/promises')
    await fs.mkdir(this.configDir, { recursive: true, mode: 0o700 })
    await fs.writeFile(this.tokenPath, JSON.stringify(data), { encoding: 'utf-8', mode: 0o600 })
    await fs.chmod(this.tokenPath, 0o600)
  }

  async removeToken(): Promise<void> {
    if (!(await this.init()) || !this.tokenPath) return

    try {
      const fs = await import('fs/promises')
      await fs.unlink(this.tokenPath)
    } catch {
      // Ignore if file doesn't exist
    }
  }

  async getStoragePath(): Promise<string | null> {
    await this.init()
    return this.tokenPath
  }
}

export function createStorage(storagePath?: string): TokenStorage {
  return new SecureFileTokenStorage(storagePath)
}
