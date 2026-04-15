import { Ok, Err } from '../../foundation/result'
import type { Result } from '../../foundation/result'
import { ValidationError, NotFoundError, ConflictError, KeyError } from '../../foundation/errors'
import type { StorageAdapter } from '../../storage'
import {
  publicKeyToDID,
  didToPublicKey,
  pemToPublicKey,
  verify as ed25519Verify,
  base64Decode,
  base64Encode,
  isValidDID,
} from '../../crypto/keys'
import type { AuditService } from '../audit/service'
import type {
  AgentKeyWriter,
  AgentKeyRecord,
  AgentKeyInfo,
  RegisterAgentKeyInput,
  RegisterAgentKeyResult,
  VerifyAgentSignatureInput,
  VerifyAgentSignatureResult,
} from './types'

// ============================================================================
// Implementation
// ============================================================================

export class AgentKeyServiceImpl implements AgentKeyWriter {
  private storage: StorageAdapter
  private audit: AuditService
  private identityExists: (id: string) => Promise<boolean>
  private isIdentityFrozen: (id: string) => Promise<boolean>

  constructor({
    storage,
    audit,
    identityExists,
    isIdentityFrozen,
  }: {
    storage: StorageAdapter
    audit: AuditService
    identityExists?: (id: string) => Promise<boolean>
    isIdentityFrozen?: (id: string) => Promise<boolean>
  }) {
    this.storage = storage
    this.audit = audit
    this.identityExists = identityExists ?? (async () => true)
    this.isIdentityFrozen = isIdentityFrozen ?? (async () => false)
  }

  async register(input: RegisterAgentKeyInput): Promise<Result<RegisterAgentKeyResult, ValidationError | ConflictError | NotFoundError>> {
    const exists = await this.identityExists(input.identityId)
    if (!exists) {
      return Err(new NotFoundError('Identity', input.identityId))
    }

    let rawPublicKey: Uint8Array
    try {
      if (input.publicKey.includes('-----BEGIN PUBLIC KEY-----')) {
        rawPublicKey = pemToPublicKey(input.publicKey)
      } else {
        rawPublicKey = base64Decode(input.publicKey)
      }
    } catch (err: any) {
      return Err(new ValidationError('publicKey', `Invalid public key format: ${err.message}`))
    }

    if (rawPublicKey.length !== 32) {
      return Err(new ValidationError('publicKey', `Expected 32-byte Ed25519 public key, got ${rawPublicKey.length} bytes`))
    }

    const did = publicKeyToDID(rawPublicKey)

    const existingKey = await this.storage.get<string>(`agentkey-did:${did}`)
    if (existingKey) {
      return Err(new ConflictError('AgentKey', `An agent key with DID ${did} is already registered`))
    }

    const id = crypto.randomUUID()
    const keyRecord: AgentKeyRecord = {
      id,
      identityId: input.identityId,
      publicKey: base64Encode(rawPublicKey),
      algorithm: 'Ed25519',
      did,
      label: input.label,
      createdAt: Date.now(),
      revokedAt: null,
    }

    await this.storage.put(`agentkey:${id}`, keyRecord)
    await this.storage.put(`agentkey-did:${did}`, id)

    const identityKeysKey = `agentkeys:${input.identityId}`
    const existingIds = (await this.storage.get<string[]>(identityKeysKey)) ?? []
    existingIds.push(id)
    await this.storage.put(identityKeysKey, existingIds)

    await this.audit.logFireAndForget({
      event: 'agentkey.registered',
      actor: input.identityId,
      target: id,
      metadata: { did, label: input.label },
    })

    return Ok({ id, did })
  }

  async list(identityId: string): Promise<AgentKeyInfo[]> {
    const keyIds = (await this.storage.get<string[]>(`agentkeys:${identityId}`)) ?? []
    const keys: AgentKeyInfo[] = []

    const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000

    for (const keyId of keyIds) {
      const keyRecord = await this.storage.get<AgentKeyRecord>(`agentkey:${keyId}`)
      if (!keyRecord) continue
      if (keyRecord.revokedAt && keyRecord.revokedAt < thirtyDaysAgo) continue

      keys.push({
        id: keyRecord.id,
        did: keyRecord.did,
        label: keyRecord.label,
        createdAt: keyRecord.createdAt,
        revokedAt: keyRecord.revokedAt ?? undefined,
      })
    }

    return keys
  }

  async revoke(keyId: string): Promise<Result<boolean, NotFoundError | KeyError>> {
    const keyRecord = await this.storage.get<AgentKeyRecord>(`agentkey:${keyId}`)
    if (!keyRecord) {
      return Err(new NotFoundError('AgentKey', keyId))
    }

    if (keyRecord.revokedAt) {
      return Err(new KeyError('already_revoked', `Agent key ${keyId} is already revoked`))
    }

    keyRecord.revokedAt = Date.now()
    await this.storage.put(`agentkey:${keyId}`, keyRecord)
    await this.storage.delete(`agentkey-did:${keyRecord.did}`)

    await this.audit.logFireAndForget({
      event: 'agentkey.revoked',
      actor: keyRecord.identityId,
      target: keyId,
    })

    return Ok(true)
  }

  async verify(input: VerifyAgentSignatureInput): Promise<Result<VerifyAgentSignatureResult, NotFoundError>> {
    if (!isValidDID(input.did)) {
      return Ok({ valid: false })
    }

    const keyId = await this.storage.get<string>(`agentkey-did:${input.did}`)
    if (!keyId) {
      return Ok({ valid: false })
    }

    const keyRecord = await this.storage.get<AgentKeyRecord>(`agentkey:${keyId}`)
    if (!keyRecord || keyRecord.revokedAt) {
      return Ok({ valid: false })
    }

    const frozen = await this.isIdentityFrozen(keyRecord.identityId)
    if (frozen) {
      return Ok({ valid: false })
    }

    try {
      const publicKey = didToPublicKey(input.did)
      const messageBytes = new TextEncoder().encode(input.message)
      const signatureBytes = base64Decode(input.signature)

      const valid = await ed25519Verify(messageBytes, signatureBytes, publicKey)
      if (!valid) return Ok({ valid: false })

      return Ok({ valid: true, identityId: keyRecord.identityId })
    } catch {
      return Ok({ valid: false })
    }
  }
}
