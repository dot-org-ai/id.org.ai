import { ApiKeyServiceImpl } from './api-keys'
import { AgentKeyServiceImpl } from './agent-keys'
import { RateLimitServiceImpl } from './rate-limit'
import type { AuditService } from '../audit/service'
import type { IdentityReader } from '../identity/types'
import type { KeyService } from './types'
import { isOk } from '../../foundation/result'

// ============================================================================
// Composite KeyService
// ============================================================================

export class KeyServiceImpl implements KeyService {
  readonly apiKeys: ApiKeyServiceImpl
  readonly agentKeys: AgentKeyServiceImpl
  readonly rateLimit: RateLimitServiceImpl

  constructor({
    storage,
    audit,
    identity,
  }: {
    storage: DurableObjectStorage
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

    this.agentKeys = new AgentKeyServiceImpl({
      storage,
      audit,
      identityExists: identity ? (id) => identity.exists(id) : undefined,
      isIdentityFrozen: identity
        ? async (id) => {
            const result = await identity.get(id)
            return isOk(result) ? !!result.data.frozen : false
          }
        : undefined,
    })

    this.rateLimit = new RateLimitServiceImpl({ storage })
  }
}
