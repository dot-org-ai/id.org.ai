import { Ok, Err } from '../../foundation/result'
import type { Result } from '../../foundation/result'
import { ValidationError, NotFoundError, KeyError } from '../../foundation/errors'
import type { AuditService } from '../audit/service'
import type {
  ApiKeyWriter,
  ApiKeyRecord,
  ApiKeyInfo,
  CreateApiKeyInput,
  CreateApiKeyResult,
  ValidateApiKeyResult,
  CapabilityLevel,
} from './types'

// ============================================================================
// Constants
// ============================================================================

const VALID_SCOPES = new Set(['read', 'write', 'admin'])

// ============================================================================
// Implementation
// ============================================================================

export class ApiKeyServiceImpl implements ApiKeyWriter {
  private storage: DurableObjectStorage
  private audit: AuditService
  private getIdentityLevel: (id: string) => Promise<CapabilityLevel | null>

  constructor({
    storage,
    audit,
    getIdentityLevel,
  }: {
    storage: DurableObjectStorage
    audit: AuditService
    getIdentityLevel?: (id: string) => Promise<CapabilityLevel | null>
  }) {
    this.storage = storage
    this.audit = audit
    this.getIdentityLevel = getIdentityLevel ?? (async () => null)
  }

  async create(input: CreateApiKeyInput): Promise<Result<CreateApiKeyResult, ValidationError>> {
    if (!input.name?.trim()) {
      return Err(new ValidationError('name', 'name is required'))
    }

    const scopes = input.scopes ?? ['read', 'write']
    for (const s of scopes) {
      if (!VALID_SCOPES.has(s)) {
        return Err(new ValidationError('scopes', `Invalid scope: ${s}`))
      }
    }

    if (input.expiresAt) {
      const expiry = new Date(input.expiresAt).getTime()
      if (expiry <= Date.now()) {
        return Err(new ValidationError('expiresAt', 'expiresAt must be in the future'))
      }
    }

    const id = crypto.randomUUID()
    const key = `hly_sk_${crypto.randomUUID().replace(/-/g, '')}${crypto.randomUUID().replace(/-/g, '')}`
    const prefix = key.slice(0, 15)
    const now = new Date().toISOString()

    const record: ApiKeyRecord = {
      id,
      key,
      name: input.name,
      prefix,
      identityId: input.identityId,
      scopes,
      status: 'active',
      createdAt: now,
      expiresAt: input.expiresAt,
      requestCount: 0,
    }

    await this.storage.put(`apikey:${id}`, record)
    await this.storage.put(`apikey-lookup:${key}`, id)

    await this.audit.logFireAndForget({
      event: 'apikey.created',
      actor: input.identityId,
      target: id,
      metadata: { name: input.name, scopes },
    })

    const result: CreateApiKeyResult = { id, key, name: input.name, prefix, scopes, createdAt: now }
    if (input.expiresAt) result.expiresAt = input.expiresAt
    return Ok(result)
  }

  async list(identityId: string): Promise<ApiKeyInfo[]> {
    const entries = await this.storage.list<ApiKeyRecord>({ prefix: 'apikey:' })
    const keys: ApiKeyInfo[] = []

    for (const [storageKey, value] of entries) {
      if (storageKey.startsWith('apikey-lookup:')) continue
      if (value.identityId !== identityId) continue
      keys.push({
        id: value.id,
        name: value.name,
        prefix: value.prefix ?? (value.key ? value.key.slice(0, 15) : ''),
        scopes: value.scopes ?? ['read', 'write'],
        status: value.status ?? 'active',
        createdAt: value.createdAt ?? new Date(0).toISOString(),
        expiresAt: value.expiresAt,
        lastUsedAt: value.lastUsedAt,
      })
    }

    return keys
  }

  async revoke(
    keyId: string,
    identityId: string,
  ): Promise<Result<{ id: string; status: 'revoked'; revokedAt: string }, NotFoundError | KeyError>> {
    const apiKey = await this.storage.get<ApiKeyRecord>(`apikey:${keyId}`)
    if (!apiKey || apiKey.identityId !== identityId) {
      return Err(new NotFoundError('ApiKey', keyId))
    }

    if (apiKey.status === 'revoked') {
      return Err(new KeyError('already_revoked', `API key ${keyId} is already revoked`))
    }

    const revokedAt = new Date().toISOString()
    await this.storage.put(`apikey:${keyId}`, {
      ...apiKey,
      status: 'revoked' as const,
      revokedAt,
    })

    if (apiKey.key) {
      await this.storage.delete(`apikey-lookup:${apiKey.key}`)
    }

    await this.audit.logFireAndForget({
      event: 'apikey.revoked',
      actor: identityId,
      target: keyId,
    })

    return Ok({ id: keyId, status: 'revoked' as const, revokedAt })
  }

  async validate(key: string): Promise<Result<ValidateApiKeyResult, NotFoundError>> {
    const id = await this.storage.get<string>(`apikey-lookup:${key}`)
    if (!id) return Ok({ valid: false })

    const apiKey = await this.storage.get<ApiKeyRecord>(`apikey:${id}`)
    if (!apiKey || apiKey.status === 'revoked') return Ok({ valid: false })

    if (apiKey.expiresAt) {
      const expiry = new Date(apiKey.expiresAt).getTime()
      if (Date.now() > expiry) return Ok({ valid: false })
    }

    const level = await this.getIdentityLevel(apiKey.identityId)
    if (level === null) return Ok({ valid: false })

    const now = new Date().toISOString()
    await this.storage.put(`apikey:${id}`, {
      ...apiKey,
      lastUsedAt: now,
      requestCount: (apiKey.requestCount ?? 0) + 1,
    })

    return Ok({
      valid: true,
      identityId: apiKey.identityId,
      scopes: apiKey.scopes,
      level: level as CapabilityLevel,
    })
  }
}
