/**
 * Keys & Credentials — Domain 5
 *
 * Owns: API keys, rate limiting
 * Depends on: Foundation (0), Audit (10), Identity (3)
 * Depended on by: AuthService (1), MCPService (6)
 *
 * As of id-ax7, agent Ed25519 keys moved to services/agents/ as a
 * first-class Agent entity (storage prefix agent:*). The legacy
 * AgentKeyService (storage prefix agentkey:*) is removed.
 */

export { KeyServiceImpl } from './service'
export { ApiKeyServiceImpl } from './api-keys'
export { RateLimitServiceImpl, RATE_LIMITS } from './rate-limit'
export type {
  KeyService,
  ApiKeyReader,
  ApiKeyWriter,
  RateLimitService,
  ApiKeyRecord,
  ApiKeyInfo,
  CreateApiKeyInput,
  CreateApiKeyResult,
  ValidateApiKeyResult,
  RateLimitEntry,
  RateLimitResult,
  RateLimitConfig,
  CapabilityLevel,
} from './types'
