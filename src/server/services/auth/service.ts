// src/services/auth/service.ts
import { Ok } from '../../../sdk/foundation/result'
import type { Result } from '../../../sdk/foundation/result'
import type { AuthError } from '../../../sdk/foundation/errors'
import type { StorageAdapter } from '../../../sdk/storage'
import type { IdentityReader } from '../identity/types'
import type {
  SessionService,
  SessionData,
  SessionValidation,
  SessionInfo,
  CapabilityLevel,
} from './types'

const DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1000 // 24 hours

export class SessionServiceImpl implements SessionService {
  private storage: StorageAdapter
  private identityReader: IdentityReader

  constructor(deps: { storage: StorageAdapter; identityReader: IdentityReader }) {
    this.storage = deps.storage
    this.identityReader = deps.identityReader
  }

  async get(token: string): Promise<SessionValidation> {
    if (!token.startsWith('ses_')) {
      return { valid: false }
    }

    const session = await this.storage.get<SessionData>(`session:${token}`)
    if (!session) {
      return { valid: false }
    }

    if (Date.now() > session.expiresAt) {
      await this.storage.delete(`session:${token}`)
      return { valid: false }
    }

    // Verify the identity still exists and is not frozen
    const result = await this.identityReader.get(session.identityId)
    if (!result.success || result.data.frozen) {
      return { valid: false }
    }

    return {
      valid: true,
      identityId: session.identityId,
      level: session.level,
      expiresAt: session.expiresAt,
    }
  }

  async list(identityId: string): Promise<SessionInfo[]> {
    const entries = await this.storage.list<SessionData>({ prefix: 'session:' })
    const sessions: SessionInfo[] = []
    const now = Date.now()

    for (const [key, value] of entries) {
      if (value.identityId === identityId && value.expiresAt > now) {
        sessions.push({
          token: key.slice('session:'.length),
          identityId: value.identityId,
          level: value.level,
          createdAt: value.createdAt,
          expiresAt: value.expiresAt,
        })
      }
    }

    return sessions
  }

  async findForIdentity(identityId: string): Promise<SessionData | null> {
    const entries = await this.storage.list<SessionData>({ prefix: 'session:' })
    const now = Date.now()
    for (const [, value] of entries) {
      if (value.identityId === identityId && value.expiresAt > now) {
        return value
      }
    }
    return null
  }

  async create(identityId: string, level: CapabilityLevel, ttlMs?: number): Promise<Result<SessionInfo, AuthError>> {
    const token = `ses_${crypto.randomUUID().replace(/-/g, '')}`
    const now = Date.now()
    const expiresAt = now + (ttlMs ?? DEFAULT_SESSION_TTL_MS)

    const data: SessionData = { identityId, level, createdAt: now, expiresAt }
    await this.storage.put(`session:${token}`, data)

    return Ok({ token, identityId, level, createdAt: now, expiresAt })
  }

  async delete(token: string): Promise<Result<{ deleted: boolean }, never>> {
    const existed = await this.storage.delete(`session:${token}`)
    return Ok({ deleted: !!existed })
  }

  async deleteAllForIdentity(identityId: string): Promise<number> {
    const entries = await this.storage.list<SessionData>({ prefix: 'session:' })
    const keysToDelete: string[] = []

    for (const [key, value] of entries) {
      if (value.identityId === identityId) {
        keysToDelete.push(key)
      }
    }

    for (const key of keysToDelete) {
      await this.storage.delete(key)
    }

    return keysToDelete.length
  }
}
