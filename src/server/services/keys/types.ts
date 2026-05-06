/**
 * KeyService — Domain 5 (Keys & Credentials)
 *
 * Owns: API keys, agent Ed25519 keys, rate limiting
 * Depends on: Foundation (0), Audit (10), Identity (3)
 * Depended on by: AuthService (1), MCPService (6)
 *
 * Storage keys:
 *   apikey:{id}           → ApiKeyRecord
 *   apikey-lookup:{key}   → key ID (reverse index for validation)
 *   agentkey:{id}         → AgentKeyRecord
 *   agentkey-did:{did}    → key ID (reverse index for DID lookup)
 *   agentkeys:{identityId} → string[] (key IDs per identity)
 *   rateLimit:{identityId} → RateLimitEntry
 */

import type { Result } from '../../../sdk/foundation'
import type { NotFoundError, ValidationError, KeyError } from '../../../sdk/foundation'
import type { CapabilityLevel } from '../identity/types'

export type { CapabilityLevel } from '../identity/types'

// ============================================================================
// Domain Types
// ============================================================================

export type ApiKeyStatus = 'active' | 'revoked'

export interface ApiKeyRecord {
  id: string
  key: string
  name: string
  prefix: string
  identityId: string
  scopes: string[]
  status: ApiKeyStatus
  createdAt: string
  expiresAt?: string
  revokedAt?: string
  lastUsedAt?: string
  requestCount: number
}

export interface ApiKeyInfo {
  id: string
  name: string
  prefix: string
  scopes: string[]
  status: ApiKeyStatus
  createdAt: string
  expiresAt?: string
  lastUsedAt?: string
}

export interface CreateApiKeyInput {
  name: string
  identityId: string
  scopes?: string[]
  expiresAt?: string
}

export interface CreateApiKeyResult {
  id: string
  key: string
  name: string
  prefix: string
  scopes: string[]
  createdAt: string
  expiresAt?: string
}

export interface ValidateApiKeyResult {
  valid: boolean
  identityId?: string
  scopes?: string[]
  level?: CapabilityLevel
}

export interface RateLimitEntry {
  identityId: string
  windowStart: number
  requestCount: number
}

export interface RateLimitResult {
  allowed: boolean
  remaining: number
  resetAt: number
}

export interface RateLimitConfig {
  maxRequests: number
  windowMs: number
}

// ============================================================================
// Service Interfaces
// ============================================================================

export interface ApiKeyReader {
  /** Validate an API key and return identity context. */
  validate(key: string): Promise<Result<ValidateApiKeyResult, NotFoundError>>

  /** List all API keys for an identity (metadata only, no key values). */
  list(identityId: string): Promise<ApiKeyInfo[]>
}

export interface ApiKeyWriter extends ApiKeyReader {
  /** Create a new API key. Returns the full key value (only time it's visible). */
  create(input: CreateApiKeyInput): Promise<Result<CreateApiKeyResult, ValidationError>>

  /** Revoke an API key by ID. */
  revoke(keyId: string, identityId: string): Promise<Result<{ id: string; status: 'revoked'; revokedAt: string; key?: string }, NotFoundError | KeyError>>
}

export interface RateLimitService {
  /** Check rate limit for an identity at a given capability level. */
  check(identityId: string, level: CapabilityLevel): Promise<RateLimitResult>
}

/** Unified KeyService — composes API keys and rate limiting. */
export interface KeyService {
  apiKeys: ApiKeyWriter
  rateLimit: RateLimitService
}
