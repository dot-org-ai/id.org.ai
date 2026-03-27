import { Ok, Err } from '../../foundation/result'
import type { Result } from '../../foundation/result'
import { NotFoundError } from '../../foundation/errors'
import type { AuthError, ValidationError, ConflictError } from '../../foundation/errors'
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

  async createHuman(_input: CreateHumanInput): Promise<Result<Identity, ValidationError | ConflictError>> {
    throw new Error('Not implemented')
  }

  async provisionAgent(_input: ProvisionAgentInput): Promise<Result<ProvisionAgentResult, ValidationError>> {
    throw new Error('Not implemented')
  }

  async createService(_input: CreateServiceInput): Promise<Result<Identity, ValidationError | ConflictError>> {
    throw new Error('Not implemented')
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
