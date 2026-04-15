// src/services/auth/types.ts
import type { Result } from '../../../sdk/foundation/result'
import type { AuthError } from '../../../sdk/foundation/errors'
import type { CapabilityLevel } from '../identity/types'

export type { CapabilityLevel }

// ── Storage Types ──────────────────────────────────────────────────────

export interface SessionData {
  identityId: string
  level: CapabilityLevel
  createdAt: number
  expiresAt: number
}

export interface SessionInfo {
  token: string
  identityId: string
  level: CapabilityLevel
  createdAt: number
  expiresAt: number
}

export interface SessionValidation {
  valid: boolean
  identityId?: string
  level?: CapabilityLevel
  expiresAt?: number
}

// ── Service Interfaces ─────────────────────────────────────────────────

export interface SessionReader {
  /** Validate a session token — returns { valid: true, ... } or { valid: false } */
  get(token: string): Promise<SessionValidation>

  /** List active (non-expired) sessions for an identity */
  list(identityId: string): Promise<SessionInfo[]>

  /** Find the first active non-expired session for an identity (or null) */
  findForIdentity(identityId: string): Promise<SessionData | null>
}

export interface SessionWriter extends SessionReader {
  /** Create a new session token for an identity */
  create(identityId: string, level: CapabilityLevel, ttlMs?: number): Promise<Result<SessionInfo, AuthError>>

  /** Delete a session by token — returns { deleted: true/false } */
  delete(token: string): Promise<Result<{ deleted: boolean }, never>>

  /** Delete all sessions for an identity — returns count deleted */
  deleteAllForIdentity(identityId: string): Promise<number>
}

export type SessionService = SessionWriter
