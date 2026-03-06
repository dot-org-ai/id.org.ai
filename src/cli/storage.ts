/**
 * CLI Token Storage for id.org.ai
 *
 * Stores token data in ~/.id.org.ai/token and mirrors the legacy oauth.do path
 * for migration compatibility.
 */

import { COMPATIBLE_TOKEN_DIRNAMES, TOKEN_FILE_NAME } from '../auth/index.js'

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
  private tokenPaths: string[] = []
  private initialized = false
  private customPath?: string

  constructor(customPath?: string) {
    this.customPath = customPath
  }

  private async init(): Promise<boolean> {
    if (this.initialized) return this.tokenPaths.length > 0
    this.initialized = true

    try {
      const os = await import('os')
      const path = await import('path')
      const homeDir = os.homedir()

      if (this.customPath) {
        const expandedPath = this.customPath.startsWith('~/') ? path.join(homeDir, this.customPath.slice(2)) : this.customPath
        this.tokenPaths = [expandedPath]
      } else {
        this.tokenPaths = [...COMPATIBLE_TOKEN_DIRNAMES].map((dirname) => path.join(homeDir, dirname, TOKEN_FILE_NAME))
      }
      return this.tokenPaths.length > 0
    } catch {
      return false
    }
  }

  private getPrimaryTokenPath(): string | null {
    return this.tokenPaths[0] ?? null
  }

  private async readTokenData(pathname: string): Promise<StoredTokenData | null> {
    try {
      const fs = await import('fs/promises')
      const content = await fs.readFile(pathname, 'utf-8')
      const trimmed = content.trim()

      if (trimmed.startsWith('{')) {
        return JSON.parse(trimmed) as StoredTokenData
      }
      return trimmed ? { accessToken: trimmed } : null
    } catch {
      return null
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
    if (!(await this.init()) || this.tokenPaths.length === 0) return null

    for (const tokenPath of this.tokenPaths) {
      const data = await this.readTokenData(tokenPath)
      if (data) return data
    }

    return null
  }

  async setTokenData(data: StoredTokenData): Promise<void> {
    if (!(await this.init()) || this.tokenPaths.length === 0) {
      throw new Error('File storage not available')
    }

    const fs = await import('fs/promises')
    const path = await import('path')
    for (const tokenPath of this.tokenPaths) {
      const configDir = path.dirname(tokenPath)
      await fs.mkdir(configDir, { recursive: true, mode: 0o700 })
      await fs.writeFile(tokenPath, JSON.stringify(data), { encoding: 'utf-8', mode: 0o600 })
      await fs.chmod(tokenPath, 0o600)
    }
  }

  async removeToken(): Promise<void> {
    if (!(await this.init()) || this.tokenPaths.length === 0) return

    const fs = await import('fs/promises')
    for (const tokenPath of this.tokenPaths) {
      try {
        await fs.unlink(tokenPath)
      } catch {
        // Ignore if file doesn't exist
      }
    }
  }

  async getStoragePath(): Promise<string | null> {
    await this.init()
    return this.getPrimaryTokenPath()
  }
}

export function createStorage(storagePath?: string): TokenStorage {
  return new SecureFileTokenStorage(storagePath)
}
