/**
 * Keys & Credentials — Domain 5
 *
 * Owns: API keys, agent Ed25519 keys, rate limiting
 * Depends on: Foundation (0), Audit (10), Identity (3)
 * Depended on by: AuthService (1), MCPService (6)
 */

export { KeyServiceImpl } from './service'
export { ApiKeyServiceImpl } from './api-keys'
export { AgentKeyServiceImpl } from './agent-keys'
export { RateLimitServiceImpl, RATE_LIMITS } from './rate-limit'
export type {
  KeyService,
  ApiKeyReader,
  ApiKeyWriter,
  AgentKeyReader,
  AgentKeyWriter,
  RateLimitService,
  ApiKeyRecord,
  ApiKeyInfo,
  CreateApiKeyInput,
  CreateApiKeyResult,
  ValidateApiKeyResult,
  AgentKeyRecord,
  AgentKeyInfo,
  RegisterAgentKeyInput,
  RegisterAgentKeyResult,
  VerifyAgentSignatureInput,
  VerifyAgentSignatureResult,
  RateLimitEntry,
  RateLimitResult,
  RateLimitConfig,
  CapabilityLevel,
} from './types'
