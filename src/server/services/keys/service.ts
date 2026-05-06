import { ApiKeyServiceImpl } from './api-keys'
import { RateLimitServiceImpl } from './rate-limit'
import type { StorageAdapter } from '../../../sdk/storage'
import type { AuditService } from '../audit/service'
import type { IdentityReader } from '../identity/types'
import type { KeyService } from './types'
import { isOk } from '../../../sdk/foundation/result'

// ============================================================================
// Composite KeyService
// ============================================================================
//
// As of id-ax7, the legacy AgentKeyService (DID-based registration / Ed25519
// signature verification, storage prefix `agentkey:*`) is removed. The new
// AgentService (services/agents/, storage prefix `agent:*`) owns first-class
// Agent entities. Crypto primitives in src/sdk/crypto/keys.ts are unchanged
// and are reused by the future AAP wire surface (id-9s0) for `agent+jwt`
// signature verification.

export class KeyServiceImpl implements KeyService {
  readonly apiKeys: ApiKeyServiceImpl
  readonly rateLimit: RateLimitServiceImpl

  constructor({
    storage,
    audit,
    identity,
  }: {
    storage: StorageAdapter
    audit: AuditService
    identity?: IdentityReader
  }) {
    this.apiKeys = new ApiKeyServiceImpl({
      storage,
      audit,
      getIdentityLevel: identity
        ? async (id) => {
            const result = await identity.get(id)
            return isOk(result) ? result.data.level : null
          }
        : undefined,
    })

    this.rateLimit = new RateLimitServiceImpl({ storage })
  }
}
