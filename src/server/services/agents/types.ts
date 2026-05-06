/**
 * AgentService — first-class Agent entity under a Tenant.
 *
 * Agents are runtime actors with their own Ed25519 keypair and lifecycle.
 * Multiple agents can run under one Tenant; revoking one does not affect
 * the Tenant or sibling agents. Aligns with AAP v1.0's host/agent split,
 * with id.org.ai's Tenant playing AAP's "Host" role.
 *
 * Owns: Agent CRUD, lifecycle transitions, public-key reverse lookup
 * Depends on: Foundation (0), Audit (10), Identity (3 — for tenant existence)
 *
 * Storage keys:
 *   agent:{id}                       → Agent
 *   agent-by-tenant:{tenantId}       → string[]   // agent IDs under a tenant
 *   agent-by-pubkey:{base64-pubkey}  → agent ID   // reverse index for JWT verify
 */

import type { Result } from '../../../sdk/foundation'
import type { NotFoundError, ValidationError, ConflictError, AuthError } from '../../../sdk/foundation'
import type { Agent, AgentInfo, AgentMode, AgentStatus, AgentRegistrationInput } from '../../../sdk/types'

// Re-export for service consumers — sdk/types.ts is the canonical home
export type { Agent, AgentInfo, AgentMode, AgentStatus } from '../../../sdk/types'

/** Service-side input alias matching the SDK's portable AgentRegistrationInput. */
export type RegisterAgentInput = AgentRegistrationInput

export interface RegisterAgentResult {
  agent: Agent
}

export interface UpdateAgentStatusInput {
  status: AgentStatus
  reason?: string
}

// ============================================================================
// Service Interfaces
// ============================================================================

export interface AgentReader {
  /** Get an agent by ID. */
  get(id: string): Promise<Result<Agent, NotFoundError>>

  /** List all (non-pruned-revoked) agents for a tenant. */
  list(tenantId: string): Promise<AgentInfo[]>

  /** Look up an agent by its public key (base64 raw bytes). */
  getByPublicKey(publicKey: string): Promise<Result<Agent, NotFoundError>>
}

export interface AgentWriter extends AgentReader {
  /** Register a new Agent under a Tenant. */
  register(input: RegisterAgentInput): Promise<Result<RegisterAgentResult, ValidationError | ConflictError | NotFoundError>>

  /** Update an agent's status (with state transition validation). */
  updateStatus(id: string, input: UpdateAgentStatusInput): Promise<Result<Agent, NotFoundError | ValidationError | AuthError>>

  /** Revoke an agent permanently. */
  revoke(id: string, reason?: string): Promise<Result<Agent, NotFoundError | AuthError>>

  /** Reactivate an expired agent (resets sessionTtl + maxLifetime; absoluteLifetime unchanged). */
  reactivate(id: string): Promise<Result<Agent, NotFoundError | ValidationError>>

  /** Touch lastUsedAt — called by AuthBroker on each request from this agent. */
  touch(id: string): Promise<void>
}

export type AgentService = AgentWriter

// ============================================================================
// Defaults
// ============================================================================

export const DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1000 // 24h
export const DEFAULT_MAX_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000 // 30d
export const DEFAULT_ABSOLUTE_LIFETIME_MS = 365 * 24 * 60 * 60 * 1000 // 365d
