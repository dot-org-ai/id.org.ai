/**
 * CredentialFactServiceImpl — held-credential facts over the DO storage
 * adapter (beads id-j0k).
 *
 * Storage layout (per-principal, mirrors the entity-store discipline):
 *   heldcred:{principalId}:{credentialType}:{ref}          → HeldCredentialFact
 *   heldcredverif:{principalId}:{checkedAt}:{seq}          → CredentialVerificationEvent
 *
 * Verification events are INSERT-ONLY: the service exposes no update or
 * delete for them — derived liveness is always recomputed from the registry,
 * never read back from a stored flag.
 */

import { Ok, Err } from '../../../sdk/foundation'
import type { Result } from '../../../sdk/foundation'
import { NotFoundError, ValidationError } from '../../../sdk/foundation'
import type { StorageAdapter } from '../../../sdk/storage'
import type { CredentialFactService, CredentialVerificationEvent, HeldCredentialFact } from './types'

export class CredentialFactServiceImpl implements CredentialFactService {
  private readonly storage: StorageAdapter
  private verifSeq = 0

  constructor(deps: { storage: StorageAdapter }) {
    this.storage = deps.storage
  }

  private factKey(principalId: string, credentialType: string, ref: string): string {
    return `heldcred:${principalId}:${credentialType}:${ref}`
  }

  async putFact(fact: Omit<HeldCredentialFact, 'recordedAt'> & { recordedAt?: string }): Promise<Result<HeldCredentialFact, ValidationError>> {
    if (!fact.principalId?.trim()) return Err(new ValidationError('principalId', 'principalId must not be empty'))
    if (!fact.credentialType?.trim()) return Err(new ValidationError('credentialType', 'credentialType must not be empty'))
    if (!fact.ref?.trim()) return Err(new ValidationError('ref', 'ref must not be empty'))
    if (!fact.presented || typeof fact.presented.type !== 'string') {
      return Err(new ValidationError('presented', 'presented credential is required'))
    }

    const stored: HeldCredentialFact = { ...fact, recordedAt: fact.recordedAt ?? new Date().toISOString() }
    await this.storage.put(this.factKey(fact.principalId, fact.credentialType, fact.ref), stored)
    return Ok(stored)
  }

  async getFact(principalId: string, credentialType: string, ref: string): Promise<Result<HeldCredentialFact, NotFoundError>> {
    const data = await this.storage.get<HeldCredentialFact>(this.factKey(principalId, credentialType, ref))
    if (data === undefined || data === null) {
      return Err(new NotFoundError('held-credential', `${principalId}/${credentialType}/${ref}`))
    }
    return Ok(data)
  }

  async listFacts(principalId: string, opts: { credentialType?: string } = {}): Promise<HeldCredentialFact[]> {
    const prefix = opts.credentialType
      ? `heldcred:${principalId}:${opts.credentialType}:`
      : `heldcred:${principalId}:`
    const entries = await this.storage.list<HeldCredentialFact>({ prefix })
    const facts: HeldCredentialFact[] = []
    for (const [, value] of entries) {
      if (value && typeof value === 'object') facts.push(value)
    }
    return facts
  }

  async deleteFact(principalId: string, credentialType: string, ref: string): Promise<Result<{ deleted: boolean }, never>> {
    const key = this.factKey(principalId, credentialType, ref)
    const existing = await this.storage.get<HeldCredentialFact>(key)
    if (!existing) return Ok({ deleted: false })
    await this.storage.delete(key)
    return Ok({ deleted: true })
  }

  async recordVerification(event: CredentialVerificationEvent): Promise<Result<CredentialVerificationEvent, ValidationError>> {
    if (!event.principalId?.trim()) return Err(new ValidationError('principalId', 'principalId must not be empty'))
    if (!event.registry?.trim()) return Err(new ValidationError('registry', 'registry must not be empty'))
    if (!event.checkedAt?.trim()) return Err(new ValidationError('checkedAt', 'checkedAt must not be empty'))

    const seq = (this.verifSeq++).toString(36).padStart(4, '0')
    await this.storage.put(`heldcredverif:${event.principalId}:${event.checkedAt}:${seq}`, event)
    return Ok(event)
  }

  async listVerifications(principalId: string, opts: { limit?: number } = {}): Promise<CredentialVerificationEvent[]> {
    const limit = Math.min(opts.limit ?? 50, 200)
    const entries = await this.storage.list<CredentialVerificationEvent>({ prefix: `heldcredverif:${principalId}:` })
    const events: CredentialVerificationEvent[] = []
    for (const [, value] of entries) {
      if (value && typeof value === 'object') events.push(value)
    }
    // Newest first, keyed by checkedAt.
    events.sort((a, b) => (a.checkedAt < b.checkedAt ? 1 : a.checkedAt > b.checkedAt ? -1 : 0))
    return events.slice(0, limit)
  }
}
