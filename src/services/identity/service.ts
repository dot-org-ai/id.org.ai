import { Ok, Err } from '../../foundation/result'
import type { Result } from '../../foundation/result'
import { NotFoundError, ValidationError, ConflictError } from '../../foundation/errors'
import type { AuthError } from '../../foundation/errors'
import type { AuditService } from '../audit/service'
import type {
  IdentityWriter,
  Identity,
  IdentityType,
  CapabilityLevel,
  ClaimStatus,
  LinkedAccount,
  LinkedAccountProvider,
  CreateHumanInput,
  CreateServiceInput,
  ProvisionAgentInput,
  ProvisionAgentResult,
  UpdateIdentityInput,
  LinkAccountInput,
} from './types'

// ============================================================================
// IdentityServiceImpl
// ============================================================================

export class IdentityServiceImpl implements IdentityWriter {
  private storage: DurableObjectStorage
  private audit: AuditService

  constructor({ storage, audit }: { storage: DurableObjectStorage; audit: AuditService }) {
    this.storage = storage
    this.audit = audit
  }

  // --------------------------------------------------------------------------
  // IdentityReader — get / exists
  // --------------------------------------------------------------------------

  async get(id: string): Promise<Result<Identity, NotFoundError>> {
    const raw = await this.storage.get<Record<string, unknown>>(`identity:${id}`)
    if (raw === undefined || raw === null) {
      return Err(new NotFoundError('Identity', id))
    }
    return Ok(this.toIdentity(raw))
  }

  async exists(id: string): Promise<boolean> {
    const raw = await this.storage.get(`identity:${id}`)
    return raw !== undefined && raw !== null
  }

  async getByHandle(_handle: string): Promise<Result<Identity, NotFoundError>> {
    return Err(new NotFoundError('Identity', _handle))
  }

  async getByEmail(_email: string): Promise<Result<Identity, NotFoundError>> {
    return Err(new NotFoundError('Identity', _email))
  }

  async getByGitHubUserId(_githubUserId: string): Promise<Result<Identity, NotFoundError>> {
    return Err(new NotFoundError('Identity', _githubUserId))
  }

  async getLinkedAccounts(_identityId: string): Promise<Result<LinkedAccount[], NotFoundError>> {
    return Err(new NotFoundError('Identity', _identityId))
  }

  async getLinkedAccount(_identityId: string, _provider: LinkedAccountProvider): Promise<Result<LinkedAccount, NotFoundError>> {
    return Err(new NotFoundError('LinkedAccount', `${_identityId}:${_provider}`))
  }

  // --------------------------------------------------------------------------
  // IdentityWriter — stubs
  // --------------------------------------------------------------------------

  async createHuman(input: CreateHumanInput): Promise<Result<Identity, ValidationError | ConflictError>> {
    if (!input.name || input.name.trim() === '') {
      return Err(new ValidationError('name', 'Name must not be empty'))
    }
    if (!input.email || input.email.trim() === '') {
      return Err(new ValidationError('email', 'Email must not be empty'))
    }

    const emailKey = `idx:email:${input.email.toLowerCase()}`
    const existing = await this.getIdByIndex(emailKey)
    if (existing !== null) {
      return Err(new ConflictError('Identity', `Email already in use: ${input.email}`))
    }

    if (input.handle) {
      const handleKey = `idx:handle:${input.handle.toLowerCase()}`
      const existingHandle = await this.getIdByIndex(handleKey)
      if (existingHandle !== null) {
        return Err(new ConflictError('Identity', `Handle already in use: ${input.handle}`))
      }
    }

    const id = this.generateId()
    const now = Date.now()
    const record: Record<string, unknown> = {
      id,
      type: 'human',
      name: input.name,
      email: input.email,
      handle: input.handle,
      image: input.image,
      verified: true,
      level: 2,
      claimStatus: 'claimed',
      frozen: false,
      createdAt: now,
      updatedAt: now,
    }

    await this.storage.put(`identity:${id}`, record)
    await this.putIndex(emailKey, id)
    if (input.handle) {
      await this.putIndex(`idx:handle:${input.handle.toLowerCase()}`, id)
    }

    await this.audit.log({ event: 'identity.created', target: id, metadata: { type: 'human' } })

    return Ok(this.toIdentity(record))
  }

  async provisionAgent(input: ProvisionAgentInput): Promise<Result<ProvisionAgentResult, ValidationError>> {
    const id = this.generateId()
    const claimToken = this.generateClaimToken()
    const name = input.name ?? `anon_${id.slice(0, 8)}`
    const now = Date.now()

    const record: Record<string, unknown> = {
      id,
      type: 'agent',
      name,
      verified: false,
      level: 0,
      claimStatus: 'unclaimed',
      claimToken,
      frozen: false,
      createdAt: now,
      updatedAt: now,
    }

    await this.storage.put(`identity:${id}`, record)

    return Ok({ identity: this.toIdentity(record), claimToken })
  }

  async createService(input: CreateServiceInput): Promise<Result<Identity, ValidationError | ConflictError>> {
    if (!input.name || input.name.trim() === '') {
      return Err(new ValidationError('name', 'Name must not be empty'))
    }
    if (!input.handle || input.handle.trim() === '') {
      return Err(new ValidationError('handle', 'Handle must not be empty'))
    }

    const handleKey = `idx:handle:${input.handle.toLowerCase()}`
    const existing = await this.getIdByIndex(handleKey)
    if (existing !== null) {
      return Err(new ConflictError('Identity', `Handle already in use: ${input.handle}`))
    }

    const id = this.generateId()
    const now = Date.now()
    const record: Record<string, unknown> = {
      id,
      type: 'service',
      name: input.name,
      handle: input.handle,
      verified: true,
      level: 3,
      claimStatus: 'claimed',
      frozen: false,
      createdAt: now,
      updatedAt: now,
    }

    await this.storage.put(`identity:${id}`, record)
    await this.putIndex(handleKey, id)

    return Ok(this.toIdentity(record))
  }

  async update(_id: string, _input: UpdateIdentityInput): Promise<Result<Identity, NotFoundError | ValidationError | ConflictError>> {
    throw new Error('Not implemented')
  }

  async freeze(_id: string, _reason: string): Promise<Result<Identity, NotFoundError | AuthError>> {
    throw new Error('Not implemented')
  }

  async unfreeze(_id: string): Promise<Result<Identity, NotFoundError | AuthError>> {
    throw new Error('Not implemented')
  }

  async linkAccount(_identityId: string, _input: LinkAccountInput): Promise<Result<LinkedAccount, NotFoundError | ValidationError | ConflictError>> {
    throw new Error('Not implemented')
  }

  async unlinkAccount(_identityId: string, _provider: LinkedAccountProvider): Promise<Result<LinkedAccount, NotFoundError>> {
    throw new Error('Not implemented')
  }

  // --------------------------------------------------------------------------
  // Private helpers
  // --------------------------------------------------------------------------

  private generateId(): string {
    return crypto.randomUUID().replace(/-/g, '')
  }

  private generateClaimToken(): string {
    return `clm_${crypto.randomUUID().replace(/-/g, '')}`
  }

  private async putIndex(indexKey: string, identityId: string): Promise<void> {
    await this.storage.put(indexKey, identityId)
  }

  private async getIdByIndex(indexKey: string): Promise<string | null> {
    const val = await this.storage.get<string>(indexKey)
    return val ?? null
  }

  private toIdentity(raw: Record<string, unknown>): Identity {
    const now = Date.now()
    return {
      id: raw['id'] as string,
      type: raw['type'] as IdentityType,
      name: raw['name'] as string,
      handle: raw['handle'] as string | undefined,
      email: raw['email'] as string | undefined,
      image: raw['image'] as string | undefined,
      verified: (raw['verified'] as boolean | undefined) ?? false,
      level: (raw['level'] as CapabilityLevel | undefined) ?? 0,
      claimStatus: (raw['claimStatus'] as ClaimStatus | undefined) ?? 'unclaimed',
      frozen: (raw['frozen'] as boolean | undefined) ?? false,
      frozenAt: raw['frozenAt'] as number | undefined,
      githubUserId: raw['githubUserId'] as string | undefined,
      githubUsername: raw['githubUsername'] as string | undefined,
      createdAt: (raw['createdAt'] as number | undefined) ?? now,
      updatedAt: (raw['updatedAt'] as number | undefined) ?? now,
    }
  }
}
