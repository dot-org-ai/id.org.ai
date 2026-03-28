import { Ok, Err } from '../../foundation/result'
import type { Result } from '../../foundation/result'
import { NotFoundError, ValidationError, ConflictError, AuthError } from '../../foundation/errors'
import type { AuditService } from '../audit/service'
import type {
  IdentityWriter,
  Identity,
  IdentityType,
  CapabilityLevel,
  ClaimStatus,
  LinkedAccount,
  LinkedAccountProvider,
  CreateIdentityInput,
  CreateIdentityResult,
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

  async getByHandle(handle: string): Promise<Result<Identity, NotFoundError>> {
    const id = await this.getIdByIndex(`idx:handle:${handle.toLowerCase()}`)
    if (id === null) return Err(new NotFoundError('Identity', handle))
    return this.get(id)
  }

  async getByEmail(email: string): Promise<Result<Identity, NotFoundError>> {
    const id = await this.getIdByIndex(`idx:email:${email.toLowerCase()}`)
    if (id === null) return Err(new NotFoundError('Identity', email))
    return this.get(id)
  }

  async getByGitHubUserId(githubUserId: string): Promise<Result<Identity, NotFoundError>> {
    const id = await this.getIdByIndex(`idx:github:${githubUserId}`)
    if (id === null) return Err(new NotFoundError('Identity', githubUserId))
    return this.get(id)
  }

  async getByClaimToken(claimToken: string): Promise<Result<Identity, NotFoundError>> {
    const id = await this.getIdByIndex(`idx:claimtoken:${claimToken}`)
    if (id === null) return Err(new NotFoundError('Identity', claimToken))
    return this.get(id)
  }

  async getLinkedAccounts(identityId: string): Promise<Result<LinkedAccount[], NotFoundError>> {
    const exists = await this.exists(identityId)
    if (!exists) return Err(new NotFoundError('Identity', identityId))
    const entries = await this.storage.list<LinkedAccount>({ prefix: `linked:${identityId}:` })
    return Ok(Array.from(entries.values()))
  }

  async getLinkedAccount(identityId: string, provider: LinkedAccountProvider): Promise<Result<LinkedAccount, NotFoundError>> {
    const raw = await this.storage.get<LinkedAccount>(`linked:${identityId}:${provider}`)
    if (raw === undefined || raw === null) {
      return Err(new NotFoundError('LinkedAccount', `${identityId}:${provider}`))
    }
    return Ok(raw)
  }

  // --------------------------------------------------------------------------
  // IdentityWriter — creation
  // --------------------------------------------------------------------------

  async create(input: CreateIdentityInput): Promise<Result<CreateIdentityResult, ValidationError | ConflictError>> {
    const id = input.id ?? this.generateId()
    const claimToken = this.generateClaimToken()
    const level = input.level ?? 0
    const now = Date.now()

    // Check email uniqueness if provided
    if (input.email) {
      const existing = await this.getIdByIndex(`idx:email:${input.email.toLowerCase()}`)
      if (existing !== null) {
        return Err(new ConflictError('Identity', `Email already in use: ${input.email}`))
      }
    }

    // Check handle uniqueness if provided
    if (input.handle) {
      const existing = await this.getIdByIndex(`idx:handle:${input.handle.toLowerCase()}`)
      if (existing !== null) {
        return Err(new ConflictError('Identity', `Handle already in use: ${input.handle}`))
      }
    }

    const record: Record<string, unknown> = {
      id,
      type: input.type,
      name: input.name,
      email: input.email,
      handle: input.handle,
      capabilities: input.capabilities,
      ownerId: input.ownerId,
      verified: false,
      level,
      claimStatus: 'unclaimed',
      claimToken,
      frozen: false,
      createdAt: now,
      updatedAt: now,
    }

    await this.storage.put(`identity:${id}`, record)

    // Create secondary indexes
    if (input.email) await this.putIndex(`idx:email:${input.email.toLowerCase()}`, id)
    if (input.handle) await this.putIndex(`idx:handle:${input.handle.toLowerCase()}`, id)
    await this.putIndex(`idx:claimtoken:${claimToken}`, id)

    await this.audit.log({ event: 'identity.created', target: id, metadata: { type: input.type } })

    return Ok({ identity: this.toIdentity(record), claimToken })
  }

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
    await this.putIndex(`idx:claimtoken:${claimToken}`, id)

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

  async update(id: string, input: UpdateIdentityInput): Promise<Result<Identity, NotFoundError | ValidationError | ConflictError>> {
    const raw = await this.storage.get<Record<string, unknown>>(`identity:${id}`)
    if (raw === undefined || raw === null) {
      return Err(new NotFoundError('Identity', id))
    }

    if (raw['frozen'] === true) {
      return Err(new ValidationError('frozen', 'Cannot update a frozen identity'))
    }

    // Level monotonicity
    if (input.level !== undefined && input.level < (raw['level'] as number)) {
      return Err(new ValidationError('level', 'Level cannot be decreased'))
    }

    // Handle uniqueness + index swap
    if (input.handle !== undefined && input.handle !== raw['handle']) {
      const newHandleKey = `idx:handle:${input.handle.toLowerCase()}`
      const existingId = await this.getIdByIndex(newHandleKey)
      if (existingId !== null && existingId !== id) {
        return Err(new ConflictError('Identity', `Handle already in use: ${input.handle}`))
      }
      if (raw['handle']) {
        await this.storage.delete(`idx:handle:${(raw['handle'] as string).toLowerCase()}`)
      }
      await this.putIndex(newHandleKey, id)
    }

    // Email uniqueness + index swap
    if (input.email !== undefined && input.email !== raw['email']) {
      const newEmailKey = `idx:email:${input.email.toLowerCase()}`
      const existingId = await this.getIdByIndex(newEmailKey)
      if (existingId !== null && existingId !== id) {
        return Err(new ConflictError('Identity', `Email already in use: ${input.email}`))
      }
      if (raw['email']) {
        await this.storage.delete(`idx:email:${(raw['email'] as string).toLowerCase()}`)
      }
      await this.putIndex(newEmailKey, id)
    }

    // GitHub index swap
    if (input.githubUserId !== undefined && input.githubUserId !== raw['githubUserId']) {
      if (raw['githubUserId']) {
        await this.storage.delete(`idx:github:${raw['githubUserId'] as string}`)
      }
      await this.putIndex(`idx:github:${input.githubUserId}`, id)
    }

    const now = Date.now()
    const updated: Record<string, unknown> = {
      ...raw,
      ...(input.name !== undefined ? { name: input.name } : {}),
      ...(input.handle !== undefined ? { handle: input.handle } : {}),
      ...(input.email !== undefined ? { email: input.email } : {}),
      ...(input.image !== undefined ? { image: input.image } : {}),
      ...(input.verified !== undefined ? { verified: input.verified } : {}),
      ...(input.level !== undefined ? { level: input.level } : {}),
      ...(input.claimStatus !== undefined ? { claimStatus: input.claimStatus } : {}),
      ...(input.githubUserId !== undefined ? { githubUserId: input.githubUserId } : {}),
      ...(input.githubUsername !== undefined ? { githubUsername: input.githubUsername } : {}),
      updatedAt: now,
    }

    await this.storage.put(`identity:${id}`, updated)
    await this.audit.log({ event: 'identity.updated', target: id, metadata: { fields: Object.keys(input) } })

    return Ok(this.toIdentity(updated))
  }

  async freeze(id: string, reason: string): Promise<Result<Identity, NotFoundError | AuthError>> {
    const raw = await this.storage.get<Record<string, unknown>>(`identity:${id}`)
    if (raw === undefined || raw === null) {
      return Err(new NotFoundError('Identity', id))
    }
    if (raw['frozen'] === true) {
      return Err(new AuthError('forbidden', 'Identity is already frozen'))
    }

    const now = Date.now()
    const updated: Record<string, unknown> = {
      ...raw,
      frozen: true,
      frozenAt: now,
      frozenReason: reason,
      previousClaimStatus: raw['claimStatus'],
      claimStatus: 'frozen',
      updatedAt: now,
    }

    await this.storage.put(`identity:${id}`, updated)
    await this.audit.log({ event: 'identity.frozen', target: id, metadata: { reason } })

    return Ok(this.toIdentity(updated))
  }

  async unfreeze(id: string): Promise<Result<Identity, NotFoundError | AuthError>> {
    const raw = await this.storage.get<Record<string, unknown>>(`identity:${id}`)
    if (raw === undefined || raw === null) {
      return Err(new NotFoundError('Identity', id))
    }
    if (raw['frozen'] !== true) {
      return Err(new AuthError('forbidden', 'Identity is not frozen'))
    }

    const now = Date.now()
    const restoredStatus = (raw['previousClaimStatus'] as string | undefined) ?? 'unclaimed'
    const updated: Record<string, unknown> = {
      ...raw,
      frozen: false,
      frozenAt: undefined,
      frozenReason: undefined,
      claimStatus: restoredStatus,
      previousClaimStatus: undefined,
      updatedAt: now,
    }

    await this.storage.put(`identity:${id}`, updated)
    await this.audit.log({ event: 'identity.unfrozen', target: id, metadata: {} })

    return Ok(this.toIdentity(updated))
  }

  async linkAccount(identityId: string, input: LinkAccountInput): Promise<Result<LinkedAccount, NotFoundError | ValidationError | ConflictError>> {
    const exists = await this.exists(identityId)
    if (!exists) return Err(new NotFoundError('Identity', identityId))

    const key = `linked:${identityId}:${input.provider}`
    const existing = await this.storage.get<LinkedAccount>(key)
    if (existing !== undefined && existing !== null) {
      return Err(new ConflictError('LinkedAccount', `Provider already linked: ${input.provider}`))
    }

    const account: LinkedAccount = {
      id: this.generateId(),
      identityId,
      provider: input.provider,
      providerAccountId: input.providerAccountId,
      type: input.type,
      displayName: input.displayName,
      email: input.email,
      status: 'active',
      linkedAt: Date.now(),
      metadata: input.metadata,
    }

    await this.storage.put(key, account)
    await this.audit.log({ event: 'identity.account.linked', target: identityId, metadata: { provider: input.provider } })

    return Ok(account)
  }

  async unlinkAccount(identityId: string, provider: LinkedAccountProvider): Promise<Result<LinkedAccount, NotFoundError>> {
    const key = `linked:${identityId}:${provider}`
    const existing = await this.storage.get<LinkedAccount>(key)
    if (existing === undefined || existing === null) {
      return Err(new NotFoundError('LinkedAccount', `${identityId}:${provider}`))
    }

    const revoked: LinkedAccount = { ...existing, status: 'revoked' }
    await this.storage.put(key, revoked)

    return Ok(revoked)
  }

  // --------------------------------------------------------------------------
  // Infrastructure — backfill
  // --------------------------------------------------------------------------

  async backfillIndexes(): Promise<void> {
    const entries = await this.storage.list({ prefix: 'identity:' })
    for (const [, value] of entries) {
      const data = value as Record<string, unknown>
      const id = data.id as string
      if (!id) continue
      if (data.email) await this.storage.put(`idx:email:${(data.email as string).toLowerCase()}`, id)
      if (data.handle) await this.storage.put(`idx:handle:${(data.handle as string).toLowerCase()}`, id)
      if (data.githubUserId) await this.storage.put(`idx:github:${data.githubUserId}`, id)
      if (data.claimToken) await this.storage.put(`idx:claimtoken:${data.claimToken}`, id)
    }
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
