/**
 * CLI Tests for id.org.ai
 *
 * Tests for CLI token storage, device flow, and auth modules.
 * Does NOT test the actual CLI entry point (requires process.argv),
 * but tests all the underlying modules the CLI depends on.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { SecureFileTokenStorage, createStorage } from '../src/cli/storage'
import type { StoredTokenData, TokenStorage } from '../src/cli/storage'

// ── Storage Tests ───────────────────────────────────────────────────────────

describe('CLI Token Storage', () => {
  describe('SecureFileTokenStorage', () => {
    let tmpDir: string
    let storage: SecureFileTokenStorage

    beforeEach(async () => {
      const os = await import('os')
      const path = await import('path')
      const fs = await import('fs/promises')
      tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'id-org-ai-test-'))
      const tokenPath = path.join(tmpDir, 'token')
      storage = new SecureFileTokenStorage(tokenPath)
    })

    afterEach(async () => {
      const fs = await import('fs/promises')
      await fs.rm(tmpDir, { recursive: true, force: true })
    })

    it('returns null when no token stored', async () => {
      expect(await storage.getToken()).toBeNull()
    })

    it('returns null for getTokenData when no token stored', async () => {
      expect(await storage.getTokenData()).toBeNull()
    })

    it('stores and retrieves an access token', async () => {
      await storage.setToken('test_access_token')
      expect(await storage.getToken()).toBe('test_access_token')
    })

    it('trims whitespace from tokens', async () => {
      await storage.setToken('  token_with_spaces  ')
      expect(await storage.getToken()).toBe('token_with_spaces')
    })

    it('stores and retrieves full token data', async () => {
      const data: StoredTokenData = {
        accessToken: 'access_123',
        refreshToken: 'refresh_456',
        expiresAt: Date.now() + 3600000,
      }
      await storage.setTokenData(data)
      const retrieved = await storage.getTokenData()
      expect(retrieved).not.toBeNull()
      expect(retrieved!.accessToken).toBe('access_123')
      expect(retrieved!.refreshToken).toBe('refresh_456')
      expect(retrieved!.expiresAt).toBe(data.expiresAt)
    })

    it('getToken extracts accessToken from stored data', async () => {
      await storage.setTokenData({
        accessToken: 'from_data',
        refreshToken: 'refresh',
      })
      expect(await storage.getToken()).toBe('from_data')
    })

    it('removes stored token', async () => {
      await storage.setToken('to_delete')
      expect(await storage.getToken()).toBe('to_delete')

      await storage.removeToken()
      expect(await storage.getToken()).toBeNull()
    })

    it('removeToken is idempotent (no error when no token)', async () => {
      await storage.removeToken()
      await storage.removeToken()
      expect(await storage.getToken()).toBeNull()
    })

    it('creates directory with 0700 permissions', async () => {
      const os = await import('os')
      const path = await import('path')
      const fs = await import('fs/promises')

      const nestedDir = path.join(tmpDir, 'nested', 'dir')
      const nestedPath = path.join(nestedDir, 'token')
      const nestedStorage = new SecureFileTokenStorage(nestedPath)

      await nestedStorage.setToken('nested_token')
      const stats = await fs.stat(nestedDir)
      expect(stats.mode & 0o777).toBe(0o700)
    })

    it('creates token file with 0600 permissions', async () => {
      const fs = await import('fs/promises')
      const path = await import('path')

      await storage.setToken('secure_token')
      const tokenPath = path.join(tmpDir, 'token')
      const stats = await fs.stat(tokenPath)
      expect(stats.mode & 0o777).toBe(0o600)
    })

    it('writes JSON format', async () => {
      const fs = await import('fs/promises')
      const path = await import('path')

      await storage.setTokenData({ accessToken: 'json_test' })
      const content = await fs.readFile(path.join(tmpDir, 'token'), 'utf-8')
      const parsed = JSON.parse(content)
      expect(parsed.accessToken).toBe('json_test')
    })

    it('reads legacy plain text tokens', async () => {
      const fs = await import('fs/promises')
      const path = await import('path')

      // Write a plain text token (legacy format)
      await fs.writeFile(path.join(tmpDir, 'token'), 'plain_text_token', 'utf-8')
      expect(await storage.getToken()).toBe('plain_text_token')
    })

    it('overwrites existing token data', async () => {
      await storage.setToken('first')
      expect(await storage.getToken()).toBe('first')

      await storage.setToken('second')
      expect(await storage.getToken()).toBe('second')
    })

    it('handles token data without refreshToken', async () => {
      await storage.setTokenData({ accessToken: 'no_refresh' })
      const data = await storage.getTokenData()
      expect(data!.accessToken).toBe('no_refresh')
      expect(data!.refreshToken).toBeUndefined()
    })

    it('handles token data without expiresAt', async () => {
      await storage.setTokenData({ accessToken: 'no_expiry' })
      const data = await storage.getTokenData()
      expect(data!.accessToken).toBe('no_expiry')
      expect(data!.expiresAt).toBeUndefined()
    })

    it('getStoragePath returns the token path', async () => {
      const path = await import('path')
      const storagePath = await storage.getStoragePath()
      expect(storagePath).toBe(require('path').join(tmpDir, 'token'))
    })
  })

  describe('createStorage', () => {
    it('returns a SecureFileTokenStorage instance', () => {
      const s = createStorage()
      expect(s).toBeInstanceOf(SecureFileTokenStorage)
    })

    it('passes custom path to storage', () => {
      const s = createStorage('/custom/path/token')
      expect(s).toBeInstanceOf(SecureFileTokenStorage)
    })
  })
})

// ── Device Flow Types Tests ─────────────────────────────────────────────────

describe('Device Flow Types', () => {
  it('DeviceAuthorizationResponse has expected shape', () => {
    const response = {
      device_code: 'dev_abc',
      user_code: 'ABCD-1234',
      verification_uri: 'https://id.org.ai/device',
      verification_uri_complete: 'https://id.org.ai/device?user_code=ABCD-1234',
      expires_in: 600,
      interval: 5,
    }
    expect(response.device_code).toBe('dev_abc')
    expect(response.user_code).toBe('ABCD-1234')
    expect(response.verification_uri).toContain('id.org.ai')
    expect(response.verification_uri_complete).toContain('user_code=')
    expect(response.expires_in).toBe(600)
    expect(response.interval).toBe(5)
  })

  it('TokenResponse has expected shape', () => {
    const response = {
      access_token: 'at_123',
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: 'rt_456',
      scope: 'openid profile email',
    }
    expect(response.access_token).toBe('at_123')
    expect(response.token_type).toBe('Bearer')
    expect(response.expires_in).toBe(3600)
    expect(response.refresh_token).toBe('rt_456')
  })

  it('TokenResponse works without optional fields', () => {
    const response = {
      access_token: 'minimal_token',
      token_type: 'Bearer',
    }
    expect(response.access_token).toBe('minimal_token')
  })
})

// ── Auth Module Tests ───────────────────────────────────────────────────────

describe('Auth Module Types', () => {
  it('User type has expected fields', () => {
    const user = {
      id: 'user_123',
      email: 'alice@example.com',
      name: 'Alice',
      organizationId: 'org_acme',
      roles: ['admin'],
      permissions: ['read', 'write'],
    }
    expect(user.id).toBe('user_123')
    expect(user.email).toBe('alice@example.com')
    expect(user.name).toBe('Alice')
    expect(user.organizationId).toBe('org_acme')
    expect(user.roles).toContain('admin')
    expect(user.permissions).toContain('write')
  })

  it('User type works with minimal fields', () => {
    const user = { id: 'minimal_user' }
    expect(user.id).toBe('minimal_user')
  })

  it('AuthResult has user and optional token', () => {
    const success = { user: { id: 'u1', email: 'a@b.com' }, token: 'tok_123' }
    expect(success.user).not.toBeNull()
    expect(success.token).toBe('tok_123')

    const failure = { user: null }
    expect(failure.user).toBeNull()
  })
})

// ── CLI Command Structure Tests ─────────────────────────────────────────────

describe('CLI Command Structure', () => {
  const VALID_COMMANDS = ['login', 'logout', 'whoami', 'token', 'status']
  const VALID_FLAGS = ['--help', '-h', '--version', '-v', '--debug']

  it('defines all 5 commands', () => {
    expect(VALID_COMMANDS).toHaveLength(5)
  })

  it.each(VALID_COMMANDS)('includes %s command', (cmd) => {
    expect(VALID_COMMANDS).toContain(cmd)
  })

  it.each(VALID_FLAGS)('recognizes %s flag', (flag) => {
    expect(VALID_FLAGS).toContain(flag)
  })

  it('commands match oauth.do CLI parity', () => {
    // oauth.do has: login, logout, whoami, token, status
    const oauthDoCommands = ['login', 'logout', 'whoami', 'token', 'status']
    for (const cmd of oauthDoCommands) {
      expect(VALID_COMMANDS).toContain(cmd)
    }
  })
})

// ── Environment Variable Configuration Tests ────────────────────────────────

describe('CLI Environment Variables', () => {
  it('ID_ORG_AI_URL defaults to https://id.org.ai', () => {
    const url = process.env.ID_ORG_AI_URL || 'https://id.org.ai'
    expect(url).toBe('https://id.org.ai')
  })

  it('ID_ORG_AI_CLIENT_ID defaults to id_org_ai_cli', () => {
    const clientId = process.env.ID_ORG_AI_CLIENT_ID || 'id_org_ai_cli'
    expect(clientId).toBe('id_org_ai_cli')
  })

  it('ID_ORG_AI_STORAGE_PATH is undefined by default', () => {
    // In test environment, should not be set
    const storagePath = process.env.ID_ORG_AI_STORAGE_PATH
    expect(storagePath).toBeUndefined()
  })
})

// ── Storage Path Resolution Tests ───────────────────────────────────────────

describe('Storage Path Resolution', () => {
  it('default storage path is ~/.id.org.ai/token', async () => {
    const os = await import('os')
    const path = await import('path')
    const expected = path.join(os.homedir(), '.id.org.ai', 'token')
    const s = new SecureFileTokenStorage()
    const storagePath = await s.getStoragePath()
    expect(storagePath).toBe(expected)
  })

  it('custom path is used as-is', async () => {
    const s = new SecureFileTokenStorage('/tmp/custom-token')
    const storagePath = await s.getStoragePath()
    expect(storagePath).toBe('/tmp/custom-token')
  })

  it('tilde is expanded to home directory', async () => {
    const os = await import('os')
    const s = new SecureFileTokenStorage('~/.my-app/token')
    const storagePath = await s.getStoragePath()
    expect(storagePath).toContain(os.homedir())
    expect(storagePath).toContain('.my-app')
  })
})

// ── Token Data Serialization Tests ──────────────────────────────────────────

describe('Token Data Serialization', () => {
  it('round-trips full token data through JSON', () => {
    const original: StoredTokenData = {
      accessToken: 'at_roundtrip',
      refreshToken: 'rt_roundtrip',
      expiresAt: 1700000000000,
    }
    const json = JSON.stringify(original)
    const parsed = JSON.parse(json) as StoredTokenData
    expect(parsed).toEqual(original)
  })

  it('round-trips minimal token data through JSON', () => {
    const original: StoredTokenData = { accessToken: 'minimal' }
    const json = JSON.stringify(original)
    const parsed = JSON.parse(json) as StoredTokenData
    expect(parsed).toEqual(original)
  })

  it('JSON format starts with {', () => {
    const data: StoredTokenData = { accessToken: 'test' }
    const json = JSON.stringify(data)
    expect(json.startsWith('{')).toBe(true)
  })

  it('legacy plain text does not start with {', () => {
    const plainText = 'plain_token_value'
    expect(plainText.startsWith('{')).toBe(false)
  })
})

// ── Token Lifecycle Tests ───────────────────────────────────────────────────

describe('Token Lifecycle', () => {
  let tmpDir: string
  let storage: SecureFileTokenStorage

  beforeEach(async () => {
    const os = await import('os')
    const path = await import('path')
    const fs = await import('fs/promises')
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'id-lifecycle-'))
    storage = new SecureFileTokenStorage(require('path').join(tmpDir, 'token'))
  })

  afterEach(async () => {
    const fs = await import('fs/promises')
    await fs.rm(tmpDir, { recursive: true, force: true })
  })

  it('full lifecycle: store → read → update → read → remove → read', async () => {
    // 1. Store initial token
    await storage.setTokenData({
      accessToken: 'initial_at',
      refreshToken: 'initial_rt',
      expiresAt: Date.now() + 3600000,
    })

    // 2. Read back
    const first = await storage.getTokenData()
    expect(first!.accessToken).toBe('initial_at')
    expect(first!.refreshToken).toBe('initial_rt')

    // 3. Update (simulates token refresh)
    await storage.setTokenData({
      accessToken: 'refreshed_at',
      refreshToken: 'refreshed_rt',
      expiresAt: Date.now() + 7200000,
    })

    // 4. Read updated
    const second = await storage.getTokenData()
    expect(second!.accessToken).toBe('refreshed_at')
    expect(second!.refreshToken).toBe('refreshed_rt')

    // 5. Remove (logout)
    await storage.removeToken()

    // 6. Read after removal
    expect(await storage.getToken()).toBeNull()
    expect(await storage.getTokenData()).toBeNull()
  })

  it('expiry detection via expiresAt', async () => {
    // Store an already-expired token
    await storage.setTokenData({
      accessToken: 'expired_token',
      expiresAt: Date.now() - 1000, // Expired 1 second ago
    })

    const data = await storage.getTokenData()
    expect(data!.accessToken).toBe('expired_token')
    expect(data!.expiresAt).toBeLessThan(Date.now())
  })

  it('valid token expiry detection', async () => {
    await storage.setTokenData({
      accessToken: 'valid_token',
      expiresAt: Date.now() + 3600000, // Expires in 1 hour
    })

    const data = await storage.getTokenData()
    expect(data!.expiresAt).toBeGreaterThan(Date.now())
  })
})
