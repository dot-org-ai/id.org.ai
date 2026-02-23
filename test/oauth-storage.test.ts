import { describe, it, expect, beforeEach } from 'vitest'
import { MemoryOAuthStorage } from '../src/oauth/storage'
import type {
  OAuthUser,
  OAuthClient,
  OAuthAuthorizationCode,
  OAuthAccessToken,
  OAuthRefreshToken,
  OAuthGrant,
  OAuthConsent,
  OAuthDeviceCode,
} from '../src/oauth/types'

describe('MemoryOAuthStorage', () => {
  let storage: MemoryOAuthStorage

  beforeEach(() => {
    storage = new MemoryOAuthStorage()
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // User CRUD
  // ═══════════════════════════════════════════════════════════════════════════

  describe('User CRUD', () => {
    const user: OAuthUser = {
      id: 'user_1',
      email: 'alice@example.com',
      name: 'Alice',
      provider: 'github',
      providerId: 'gh_123',
      organizationId: 'org_1',
      createdAt: Date.now(),
      updatedAt: Date.now(),
    }

    it('should save and get a user by ID', async () => {
      await storage.saveUser(user)
      const result = await storage.getUser('user_1')
      expect(result).toEqual(user)
    })

    it('should return null for non-existent user', async () => {
      const result = await storage.getUser('nonexistent')
      expect(result).toBeNull()
    })

    it('should get a user by email (case-insensitive)', async () => {
      await storage.saveUser(user)
      const result = await storage.getUserByEmail('Alice@Example.COM')
      expect(result).toEqual(user)
    })

    it('should return null for non-existent email', async () => {
      const result = await storage.getUserByEmail('nobody@example.com')
      expect(result).toBeNull()
    })

    it('should get a user by provider identity', async () => {
      await storage.saveUser(user)
      const result = await storage.getUserByProvider('github', 'gh_123')
      expect(result).toEqual(user)
    })

    it('should return null for non-existent provider identity', async () => {
      const result = await storage.getUserByProvider('github', 'unknown')
      expect(result).toBeNull()
    })

    it('should delete a user and clean up indexes', async () => {
      await storage.saveUser(user)
      await storage.deleteUser('user_1')

      expect(await storage.getUser('user_1')).toBeNull()
      expect(await storage.getUserByEmail('alice@example.com')).toBeNull()
      expect(await storage.getUserByProvider('github', 'gh_123')).toBeNull()
    })

    it('should list users', async () => {
      const user2: OAuthUser = { ...user, id: 'user_2', email: 'bob@example.com', organizationId: 'org_2' }
      await storage.saveUser(user)
      await storage.saveUser(user2)

      const all = await storage.listUsers()
      expect(all).toHaveLength(2)
    })

    it('should list users with limit', async () => {
      const user2: OAuthUser = { ...user, id: 'user_2', email: 'bob@example.com' }
      await storage.saveUser(user)
      await storage.saveUser(user2)

      const limited = await storage.listUsers({ limit: 1 })
      expect(limited).toHaveLength(1)
    })

    it('should list users filtered by organizationId', async () => {
      const user2: OAuthUser = { ...user, id: 'user_2', email: 'bob@example.com', organizationId: 'org_2' }
      await storage.saveUser(user)
      await storage.saveUser(user2)

      const filtered = await storage.listUsers({ organizationId: 'org_1' })
      expect(filtered).toHaveLength(1)
      expect(filtered[0].id).toBe('user_1')
    })

    it('should update a user by saving with the same ID', async () => {
      await storage.saveUser(user)
      const updated = { ...user, name: 'Alice Updated' }
      await storage.saveUser(updated)

      const result = await storage.getUser('user_1')
      expect(result?.name).toBe('Alice Updated')
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Client CRUD
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Client CRUD', () => {
    const client: OAuthClient = {
      clientId: 'client_1',
      clientName: 'Test App',
      redirectUris: ['https://app.example.com/callback'],
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      tokenEndpointAuthMethod: 'client_secret_basic',
      scope: 'openid profile',
      createdAt: Date.now(),
    }

    it('should save and get a client', async () => {
      await storage.saveClient(client)
      const result = await storage.getClient('client_1')
      expect(result).toEqual(client)
    })

    it('should return null for non-existent client', async () => {
      const result = await storage.getClient('nonexistent')
      expect(result).toBeNull()
    })

    it('should delete a client', async () => {
      await storage.saveClient(client)
      await storage.deleteClient('client_1')
      expect(await storage.getClient('client_1')).toBeNull()
    })

    it('should list clients', async () => {
      const client2: OAuthClient = { ...client, clientId: 'client_2', clientName: 'App 2' }
      await storage.saveClient(client)
      await storage.saveClient(client2)

      const all = await storage.listClients()
      expect(all).toHaveLength(2)
    })

    it('should list clients with limit', async () => {
      const client2: OAuthClient = { ...client, clientId: 'client_2', clientName: 'App 2' }
      await storage.saveClient(client)
      await storage.saveClient(client2)

      const limited = await storage.listClients({ limit: 1 })
      expect(limited).toHaveLength(1)
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Authorization Code
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Authorization Code', () => {
    const authCode: OAuthAuthorizationCode = {
      code: 'ac_abc123',
      clientId: 'client_1',
      userId: 'user_1',
      redirectUri: 'https://app.example.com/callback',
      scope: 'openid profile',
      codeChallenge: 'challenge_value',
      codeChallengeMethod: 'S256',
      issuedAt: Date.now(),
      expiresAt: Date.now() + 600_000,
    }

    it('should save and consume an authorization code (one-time use)', async () => {
      await storage.saveAuthorizationCode(authCode)

      const first = await storage.consumeAuthorizationCode('ac_abc123')
      expect(first).toEqual(authCode)

      const second = await storage.consumeAuthorizationCode('ac_abc123')
      expect(second).toBeNull()
    })

    it('should return null for non-existent code', async () => {
      const result = await storage.consumeAuthorizationCode('nonexistent')
      expect(result).toBeNull()
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Access Token
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Access Token', () => {
    const accessToken: OAuthAccessToken = {
      token: 'at_xyz789',
      tokenType: 'Bearer',
      clientId: 'client_1',
      userId: 'user_1',
      scope: 'openid profile',
      issuedAt: Date.now(),
      expiresAt: Date.now() + 3600_000,
    }

    it('should save and get an access token', async () => {
      await storage.saveAccessToken(accessToken)
      const result = await storage.getAccessToken('at_xyz789')
      expect(result).toEqual(accessToken)
    })

    it('should return null for non-existent access token', async () => {
      const result = await storage.getAccessToken('nonexistent')
      expect(result).toBeNull()
    })

    it('should revoke an access token (delete)', async () => {
      await storage.saveAccessToken(accessToken)
      await storage.revokeAccessToken('at_xyz789')
      expect(await storage.getAccessToken('at_xyz789')).toBeNull()
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Refresh Token
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Refresh Token', () => {
    const refreshToken: OAuthRefreshToken = {
      token: 'rt_abc456',
      clientId: 'client_1',
      userId: 'user_1',
      scope: 'openid profile',
      issuedAt: Date.now(),
    }

    it('should save and get a refresh token', async () => {
      await storage.saveRefreshToken(refreshToken)
      const result = await storage.getRefreshToken('rt_abc456')
      expect(result).toEqual(refreshToken)
    })

    it('should return null for non-existent refresh token', async () => {
      const result = await storage.getRefreshToken('nonexistent')
      expect(result).toBeNull()
    })

    it('should revoke a refresh token (set revoked flag)', async () => {
      await storage.saveRefreshToken(refreshToken)
      await storage.revokeRefreshToken('rt_abc456')

      const result = await storage.getRefreshToken('rt_abc456')
      expect(result).not.toBeNull()
      expect(result?.revoked).toBe(true)
    })

    it('should revoke all tokens for a user', async () => {
      const accessToken: OAuthAccessToken = {
        token: 'at_user1',
        tokenType: 'Bearer',
        clientId: 'client_1',
        userId: 'user_1',
        issuedAt: Date.now(),
        expiresAt: Date.now() + 3600_000,
      }
      const accessToken2: OAuthAccessToken = {
        token: 'at_user2',
        tokenType: 'Bearer',
        clientId: 'client_1',
        userId: 'user_2',
        issuedAt: Date.now(),
        expiresAt: Date.now() + 3600_000,
      }

      await storage.saveAccessToken(accessToken)
      await storage.saveAccessToken(accessToken2)
      await storage.saveRefreshToken(refreshToken)

      await storage.revokeAllUserTokens('user_1')

      expect(await storage.getAccessToken('at_user1')).toBeNull()
      expect(await storage.getAccessToken('at_user2')).not.toBeNull()

      const rt = await storage.getRefreshToken('rt_abc456')
      expect(rt?.revoked).toBe(true)
    })

    it('should revoke all tokens for a client', async () => {
      const at1: OAuthAccessToken = {
        token: 'at_c1',
        tokenType: 'Bearer',
        clientId: 'client_1',
        userId: 'user_1',
        issuedAt: Date.now(),
        expiresAt: Date.now() + 3600_000,
      }
      const at2: OAuthAccessToken = {
        token: 'at_c2',
        tokenType: 'Bearer',
        clientId: 'client_2',
        userId: 'user_1',
        issuedAt: Date.now(),
        expiresAt: Date.now() + 3600_000,
      }

      await storage.saveAccessToken(at1)
      await storage.saveAccessToken(at2)
      await storage.saveRefreshToken(refreshToken)

      await storage.revokeAllClientTokens('client_1')

      expect(await storage.getAccessToken('at_c1')).toBeNull()
      expect(await storage.getAccessToken('at_c2')).not.toBeNull()

      const rt = await storage.getRefreshToken('rt_abc456')
      expect(rt?.revoked).toBe(true)
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Grant Operations
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Grant Operations', () => {
    const grant: OAuthGrant = {
      id: 'grant_1',
      userId: 'user_1',
      clientId: 'client_1',
      scope: 'openid profile',
      createdAt: Date.now(),
    }

    it('should save and get a grant', async () => {
      await storage.saveGrant(grant)
      const result = await storage.getGrant('user_1', 'client_1')
      expect(result).toEqual(grant)
    })

    it('should return null for non-existent grant', async () => {
      const result = await storage.getGrant('user_1', 'client_1')
      expect(result).toBeNull()
    })

    it('should list active grants for a user', async () => {
      const grant2: OAuthGrant = { ...grant, id: 'grant_2', clientId: 'client_2' }
      await storage.saveGrant(grant)
      await storage.saveGrant(grant2)

      const grants = await storage.listUserGrants('user_1')
      expect(grants).toHaveLength(2)
    })

    it('should revoke a grant (set revoked flag)', async () => {
      await storage.saveGrant(grant)
      await storage.revokeGrant('user_1', 'client_1')

      const result = await storage.getGrant('user_1', 'client_1')
      expect(result?.revoked).toBe(true)
    })

    it('should not list revoked grants', async () => {
      await storage.saveGrant(grant)
      await storage.revokeGrant('user_1', 'client_1')

      const grants = await storage.listUserGrants('user_1')
      expect(grants).toHaveLength(0)
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Consent Operations
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Consent Operations', () => {
    const consent: OAuthConsent = {
      userId: 'user_1',
      clientId: 'client_1',
      scopes: ['openid', 'profile'],
      createdAt: Date.now(),
      updatedAt: Date.now(),
    }

    it('should save and get consent', async () => {
      await storage.saveConsent(consent)
      const result = await storage.getConsent('user_1', 'client_1')
      expect(result).toEqual(consent)
    })

    it('should return null for non-existent consent', async () => {
      const result = await storage.getConsent('user_1', 'client_1')
      expect(result).toBeNull()
    })

    it('should list consents for a user', async () => {
      const consent2: OAuthConsent = { ...consent, clientId: 'client_2' }
      await storage.saveConsent(consent)
      await storage.saveConsent(consent2)

      const consents = await storage.listUserConsents('user_1')
      expect(consents).toHaveLength(2)
    })

    it('should revoke consent (delete)', async () => {
      await storage.saveConsent(consent)
      await storage.revokeConsent('user_1', 'client_1')
      expect(await storage.getConsent('user_1', 'client_1')).toBeNull()
    })

    it('should not list revoked consent', async () => {
      await storage.saveConsent(consent)
      await storage.revokeConsent('user_1', 'client_1')

      const consents = await storage.listUserConsents('user_1')
      expect(consents).toHaveLength(0)
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Device Code Operations (RFC 8628)
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Device Code Operations', () => {
    const deviceCode: OAuthDeviceCode = {
      deviceCode: 'dc_long_random_string',
      userCode: 'WDJB-MJHT',
      clientId: 'client_1',
      scope: 'openid profile',
      issuedAt: Date.now(),
      expiresAt: Date.now() + 900_000,
      interval: 5,
    }

    it('should save and get a device code', async () => {
      await storage.saveDeviceCode(deviceCode)
      const result = await storage.getDeviceCode('dc_long_random_string')
      expect(result).toEqual(deviceCode)
    })

    it('should return null for non-existent device code', async () => {
      const result = await storage.getDeviceCode('nonexistent')
      expect(result).toBeNull()
    })

    it('should get a device code by user code (case-insensitive)', async () => {
      await storage.saveDeviceCode(deviceCode)
      const result = await storage.getDeviceCodeByUserCode('wdjb-mjht')
      expect(result).toEqual(deviceCode)
    })

    it('should return null for non-existent user code', async () => {
      const result = await storage.getDeviceCodeByUserCode('XXXX-XXXX')
      expect(result).toBeNull()
    })

    it('should update a device code (e.g., when user authorizes)', async () => {
      await storage.saveDeviceCode(deviceCode)

      const updated: OAuthDeviceCode = {
        ...deviceCode,
        userId: 'user_1',
        authorized: true,
      }
      await storage.updateDeviceCode(updated)

      const result = await storage.getDeviceCode('dc_long_random_string')
      expect(result?.userId).toBe('user_1')
      expect(result?.authorized).toBe(true)
    })

    it('should delete a device code and clean up user code index', async () => {
      await storage.saveDeviceCode(deviceCode)
      await storage.deleteDeviceCode('dc_long_random_string')

      expect(await storage.getDeviceCode('dc_long_random_string')).toBeNull()
      expect(await storage.getDeviceCodeByUserCode('WDJB-MJHT')).toBeNull()
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // clear()
  // ═══════════════════════════════════════════════════════════════════════════

  describe('clear()', () => {
    it('should clear all data', async () => {
      const user: OAuthUser = { id: 'u1', email: 'a@b.com', createdAt: Date.now(), updatedAt: Date.now() }
      const client: OAuthClient = {
        clientId: 'c1',
        clientName: 'App',
        redirectUris: [],
        grantTypes: ['authorization_code'],
        responseTypes: ['code'],
        tokenEndpointAuthMethod: 'none',
        createdAt: Date.now(),
      }

      await storage.saveUser(user)
      await storage.saveClient(client)

      storage.clear()

      expect(await storage.getUser('u1')).toBeNull()
      expect(await storage.getUserByEmail('a@b.com')).toBeNull()
      expect(await storage.getClient('c1')).toBeNull()
    })
  })
})
