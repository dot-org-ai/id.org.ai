/**
 * OAuth 2.1 Storage Interface
 *
 * Defines the abstract storage interface that must be implemented
 * by concrete storage backends (e.g., DO SQLite, KV, D1, etc.)
 *
 * Canonical location: id.org.ai (moved from @dotdo/oauth)
 */

import type {
  OAuthUser,
  OAuthOrganization,
  OAuthClient,
  OAuthAuthorizationCode,
  OAuthAccessToken,
  OAuthRefreshToken,
  OAuthGrant,
  OAuthDeviceCode,
  OAuthConsent,
} from './types'

/**
 * Storage interface for OAuth 2.1 server
 *
 * Implementations of this interface provide persistence for:
 * - Users and organizations
 * - OAuth clients (registered applications)
 * - Authorization codes, tokens, and grants
 *
 * @example Implementing with DO SQLite
 * ```typescript
 * import type { OAuthStorage } from 'id.org.ai'
 * import { DigitalObject } from '@dotdo/do'
 *
 * export class DOAuthStorage implements OAuthStorage {
 *   constructor(private do: DigitalObject) {}
 *
 *   async getUser(id: string) {
 *     return this.do.state.get(`user:${id}`)
 *   }
 *   // ... implement other methods
 * }
 * ```
 */
export interface OAuthStorage {
  // ═══════════════════════════════════════════════════════════════════════════
  // User Operations
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get a user by ID
   */
  getUser(id: string): Promise<OAuthUser | null>

  /**
   * Get a user by email
   */
  getUserByEmail(email: string): Promise<OAuthUser | null>

  /**
   * Get a user by upstream provider identity
   */
  getUserByProvider(provider: string, providerId: string): Promise<OAuthUser | null>

  /**
   * Save a user (create or update)
   */
  saveUser(user: OAuthUser): Promise<void>

  /**
   * Delete a user
   */
  deleteUser(id: string): Promise<void>

  /**
   * List users (with optional pagination)
   */
  listUsers(options?: ListOptions): Promise<OAuthUser[]>

  // ═══════════════════════════════════════════════════════════════════════════
  // Organization Operations
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get an organization by ID
   */
  getOrganization(id: string): Promise<OAuthOrganization | null>

  /**
   * Get an organization by slug
   */
  getOrganizationBySlug(slug: string): Promise<OAuthOrganization | null>

  /**
   * Get an organization by verified domain
   */
  getOrganizationByDomain(domain: string): Promise<OAuthOrganization | null>

  /**
   * Save an organization (create or update)
   */
  saveOrganization(org: OAuthOrganization): Promise<void>

  /**
   * Delete an organization
   */
  deleteOrganization(id: string): Promise<void>

  /**
   * List organizations (with optional pagination)
   */
  listOrganizations(options?: ListOptions): Promise<OAuthOrganization[]>

  // ═══════════════════════════════════════════════════════════════════════════
  // Client Operations
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get a client by client ID
   */
  getClient(clientId: string): Promise<OAuthClient | null>

  /**
   * Save a client (create or update)
   */
  saveClient(client: OAuthClient): Promise<void>

  /**
   * Delete a client
   */
  deleteClient(clientId: string): Promise<void>

  /**
   * List clients (with optional pagination)
   */
  listClients(options?: ListOptions): Promise<OAuthClient[]>

  // ═══════════════════════════════════════════════════════════════════════════
  // Authorization Code Operations
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Save an authorization code
   */
  saveAuthorizationCode(code: OAuthAuthorizationCode): Promise<void>

  /**
   * Get and consume an authorization code (one-time use)
   * Returns null if code doesn't exist or has already been used
   */
  consumeAuthorizationCode(code: string): Promise<OAuthAuthorizationCode | null>

  // ═══════════════════════════════════════════════════════════════════════════
  // Token Operations
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Save an access token
   */
  saveAccessToken(token: OAuthAccessToken): Promise<void>

  /**
   * Get an access token
   */
  getAccessToken(token: string): Promise<OAuthAccessToken | null>

  /**
   * Revoke an access token
   */
  revokeAccessToken(token: string): Promise<void>

  /**
   * Save a refresh token
   */
  saveRefreshToken(token: OAuthRefreshToken): Promise<void>

  /**
   * Get a refresh token
   */
  getRefreshToken(token: string): Promise<OAuthRefreshToken | null>

  /**
   * Revoke a refresh token
   */
  revokeRefreshToken(token: string): Promise<void>

  /**
   * Revoke all tokens for a user
   */
  revokeAllUserTokens(userId: string): Promise<void>

  /**
   * Revoke all tokens for a client
   */
  revokeAllClientTokens(clientId: string): Promise<void>

  // ═══════════════════════════════════════════════════════════════════════════
  // Grant Operations
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get a grant by user and client
   */
  getGrant(userId: string, clientId: string): Promise<OAuthGrant | null>

  /**
   * Save a grant (create or update)
   */
  saveGrant(grant: OAuthGrant): Promise<void>

  /**
   * Revoke a grant
   */
  revokeGrant(userId: string, clientId: string): Promise<void>

  /**
   * List grants for a user
   */
  listUserGrants(userId: string): Promise<OAuthGrant[]>

  // ═══════════════════════════════════════════════════════════════════════════
  // Consent Operations
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get consent for a user+client pair
   */
  getConsent(userId: string, clientId: string): Promise<OAuthConsent | null>

  /**
   * Save consent (create or update)
   */
  saveConsent(consent: OAuthConsent): Promise<void>

  /**
   * Revoke consent for a user+client pair
   */
  revokeConsent(userId: string, clientId: string): Promise<void>

  /**
   * List all consents for a user
   */
  listUserConsents(userId: string): Promise<OAuthConsent[]>

  // ═══════════════════════════════════════════════════════════════════════════
  // Device Code Operations (RFC 8628)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Save a device code
   */
  saveDeviceCode(deviceCode: OAuthDeviceCode): Promise<void>

  /**
   * Get a device code by device code (long code used for polling)
   */
  getDeviceCode(deviceCode: string): Promise<OAuthDeviceCode | null>

  /**
   * Get a device code by user code (short code entered by user)
   */
  getDeviceCodeByUserCode(userCode: string): Promise<OAuthDeviceCode | null>

  /**
   * Update a device code (e.g., when user authorizes)
   */
  updateDeviceCode(deviceCode: OAuthDeviceCode): Promise<void>

  /**
   * Delete a device code (after successful token exchange or expiration)
   */
  deleteDeviceCode(deviceCode: string): Promise<void>
}

/**
 * Options for list operations
 */
export interface ListOptions {
  /** Maximum number of results to return */
  limit?: number
  /** Cursor for pagination */
  cursor?: string
  /** Filter by organization */
  organizationId?: string
}

/**
 * In-memory storage implementation for testing
 */
export class MemoryOAuthStorage implements OAuthStorage {
  private users = new Map<string, OAuthUser>()
  private usersByEmail = new Map<string, string>()
  private usersByProvider = new Map<string, string>()
  private organizations = new Map<string, OAuthOrganization>()
  private organizationsBySlug = new Map<string, string>()
  private organizationsByDomain = new Map<string, string>()
  private clients = new Map<string, OAuthClient>()
  private authCodes = new Map<string, OAuthAuthorizationCode>()
  private accessTokens = new Map<string, OAuthAccessToken>()
  private refreshTokens = new Map<string, OAuthRefreshToken>()
  private grants = new Map<string, OAuthGrant>()
  private consents = new Map<string, OAuthConsent>()
  private deviceCodes = new Map<string, OAuthDeviceCode>()
  private deviceCodesByUserCode = new Map<string, string>()

  // User operations
  async getUser(id: string): Promise<OAuthUser | null> {
    return this.users.get(id) ?? null
  }

  async getUserByEmail(email: string): Promise<OAuthUser | null> {
    const id = this.usersByEmail.get(email.toLowerCase())
    return id ? this.users.get(id) ?? null : null
  }

  async getUserByProvider(provider: string, providerId: string): Promise<OAuthUser | null> {
    const id = this.usersByProvider.get(`${provider}:${providerId}`)
    return id ? this.users.get(id) ?? null : null
  }

  async saveUser(user: OAuthUser): Promise<void> {
    this.users.set(user.id, user)
    if (user.email) {
      this.usersByEmail.set(user.email.toLowerCase(), user.id)
    }
    if (user.provider && user.providerId) {
      this.usersByProvider.set(`${user.provider}:${user.providerId}`, user.id)
    }
  }

  async deleteUser(id: string): Promise<void> {
    const user = this.users.get(id)
    if (user?.email) {
      this.usersByEmail.delete(user.email.toLowerCase())
    }
    if (user?.provider && user?.providerId) {
      this.usersByProvider.delete(`${user.provider}:${user.providerId}`)
    }
    this.users.delete(id)
  }

  async listUsers(options?: ListOptions): Promise<OAuthUser[]> {
    let users = Array.from(this.users.values())
    if (options?.organizationId) {
      users = users.filter((u) => u.organizationId === options.organizationId)
    }
    if (options?.limit) {
      users = users.slice(0, options.limit)
    }
    return users
  }

  // Organization operations
  async getOrganization(id: string): Promise<OAuthOrganization | null> {
    return this.organizations.get(id) ?? null
  }

  async getOrganizationBySlug(slug: string): Promise<OAuthOrganization | null> {
    const id = this.organizationsBySlug.get(slug.toLowerCase())
    return id ? this.organizations.get(id) ?? null : null
  }

  async getOrganizationByDomain(domain: string): Promise<OAuthOrganization | null> {
    const id = this.organizationsByDomain.get(domain.toLowerCase())
    return id ? this.organizations.get(id) ?? null : null
  }

  async saveOrganization(org: OAuthOrganization): Promise<void> {
    this.organizations.set(org.id, org)
    if (org.slug) {
      this.organizationsBySlug.set(org.slug.toLowerCase(), org.id)
    }
    if (org.domains) {
      for (const domain of org.domains) {
        this.organizationsByDomain.set(domain.toLowerCase(), org.id)
      }
    }
  }

  async deleteOrganization(id: string): Promise<void> {
    const org = this.organizations.get(id)
    if (org?.slug) {
      this.organizationsBySlug.delete(org.slug.toLowerCase())
    }
    if (org?.domains) {
      for (const domain of org.domains) {
        this.organizationsByDomain.delete(domain.toLowerCase())
      }
    }
    this.organizations.delete(id)
  }

  async listOrganizations(options?: ListOptions): Promise<OAuthOrganization[]> {
    let orgs = Array.from(this.organizations.values())
    if (options?.limit) {
      orgs = orgs.slice(0, options.limit)
    }
    return orgs
  }

  // Client operations
  async getClient(clientId: string): Promise<OAuthClient | null> {
    return this.clients.get(clientId) ?? null
  }

  async saveClient(client: OAuthClient): Promise<void> {
    this.clients.set(client.clientId, client)
  }

  async deleteClient(clientId: string): Promise<void> {
    this.clients.delete(clientId)
  }

  async listClients(options?: ListOptions): Promise<OAuthClient[]> {
    let clients = Array.from(this.clients.values())
    if (options?.limit) {
      clients = clients.slice(0, options.limit)
    }
    return clients
  }

  // Authorization code operations
  async saveAuthorizationCode(code: OAuthAuthorizationCode): Promise<void> {
    this.authCodes.set(code.code, code)
  }

  async consumeAuthorizationCode(code: string): Promise<OAuthAuthorizationCode | null> {
    const authCode = this.authCodes.get(code)
    if (!authCode) return null
    this.authCodes.delete(code)
    return authCode
  }

  // Token operations
  async saveAccessToken(token: OAuthAccessToken): Promise<void> {
    this.accessTokens.set(token.token, token)
  }

  async getAccessToken(token: string): Promise<OAuthAccessToken | null> {
    return this.accessTokens.get(token) ?? null
  }

  async revokeAccessToken(token: string): Promise<void> {
    this.accessTokens.delete(token)
  }

  async saveRefreshToken(token: OAuthRefreshToken): Promise<void> {
    this.refreshTokens.set(token.token, token)
  }

  async getRefreshToken(token: string): Promise<OAuthRefreshToken | null> {
    return this.refreshTokens.get(token) ?? null
  }

  async revokeRefreshToken(token: string): Promise<void> {
    const rt = this.refreshTokens.get(token)
    if (rt) {
      rt.revoked = true
      this.refreshTokens.set(token, rt)
    }
  }

  async revokeAllUserTokens(userId: string): Promise<void> {
    for (const [key, token] of this.accessTokens) {
      if (token.userId === userId) {
        this.accessTokens.delete(key)
      }
    }
    for (const [key, token] of this.refreshTokens) {
      if (token.userId === userId) {
        token.revoked = true
        this.refreshTokens.set(key, token)
      }
    }
  }

  async revokeAllClientTokens(clientId: string): Promise<void> {
    for (const [key, token] of this.accessTokens) {
      if (token.clientId === clientId) {
        this.accessTokens.delete(key)
      }
    }
    for (const [key, token] of this.refreshTokens) {
      if (token.clientId === clientId) {
        token.revoked = true
        this.refreshTokens.set(key, token)
      }
    }
  }

  // Grant operations
  private grantKey(userId: string, clientId: string): string {
    return `${userId}:${clientId}`
  }

  async getGrant(userId: string, clientId: string): Promise<OAuthGrant | null> {
    return this.grants.get(this.grantKey(userId, clientId)) ?? null
  }

  async saveGrant(grant: OAuthGrant): Promise<void> {
    this.grants.set(this.grantKey(grant.userId, grant.clientId), grant)
  }

  async revokeGrant(userId: string, clientId: string): Promise<void> {
    const grant = this.grants.get(this.grantKey(userId, clientId))
    if (grant) {
      grant.revoked = true
      this.grants.set(this.grantKey(userId, clientId), grant)
    }
  }

  async listUserGrants(userId: string): Promise<OAuthGrant[]> {
    return Array.from(this.grants.values()).filter((g) => g.userId === userId && !g.revoked)
  }

  // Consent operations
  private consentKey(userId: string, clientId: string): string {
    return `${userId}:${clientId}`
  }

  async getConsent(userId: string, clientId: string): Promise<OAuthConsent | null> {
    return this.consents.get(this.consentKey(userId, clientId)) ?? null
  }

  async saveConsent(consent: OAuthConsent): Promise<void> {
    this.consents.set(this.consentKey(consent.userId, consent.clientId), consent)
  }

  async revokeConsent(userId: string, clientId: string): Promise<void> {
    this.consents.delete(this.consentKey(userId, clientId))
  }

  async listUserConsents(userId: string): Promise<OAuthConsent[]> {
    return Array.from(this.consents.values()).filter((c) => c.userId === userId)
  }

  // Device code operations (RFC 8628)
  async saveDeviceCode(deviceCode: OAuthDeviceCode): Promise<void> {
    this.deviceCodes.set(deviceCode.deviceCode, deviceCode)
    this.deviceCodesByUserCode.set(deviceCode.userCode.toUpperCase(), deviceCode.deviceCode)
  }

  async getDeviceCode(deviceCode: string): Promise<OAuthDeviceCode | null> {
    return this.deviceCodes.get(deviceCode) ?? null
  }

  async getDeviceCodeByUserCode(userCode: string): Promise<OAuthDeviceCode | null> {
    const deviceCode = this.deviceCodesByUserCode.get(userCode.toUpperCase())
    return deviceCode ? this.deviceCodes.get(deviceCode) ?? null : null
  }

  async updateDeviceCode(deviceCode: OAuthDeviceCode): Promise<void> {
    this.deviceCodes.set(deviceCode.deviceCode, deviceCode)
  }

  async deleteDeviceCode(deviceCode: string): Promise<void> {
    const dc = this.deviceCodes.get(deviceCode)
    if (dc) {
      this.deviceCodesByUserCode.delete(dc.userCode.toUpperCase())
    }
    this.deviceCodes.delete(deviceCode)
  }

  /**
   * Clear all data (for testing)
   */
  clear(): void {
    this.users.clear()
    this.usersByEmail.clear()
    this.organizations.clear()
    this.organizationsBySlug.clear()
    this.clients.clear()
    this.authCodes.clear()
    this.accessTokens.clear()
    this.refreshTokens.clear()
    this.grants.clear()
    this.consents.clear()
    this.deviceCodes.clear()
    this.deviceCodesByUserCode.clear()
  }
}
