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

// ============================================================================
// Domain Types
// ============================================================================

/**
 * Agent lifecycle states (AAP v1.0 §3.2).
 *   pending  — awaiting user approval (delegated mode); cannot authenticate
 *   active   — operational; each request extends sessionTtl
 *   expired  — sessionTtl/maxLifetime elapsed; reactivable via reactivate()
 *   revoked  — permanent; cannot reactivate
 *   rejected — user denied registration
 *   claimed  — autonomous-mode terminal state; agent's history attributed to user
 *              when the parent Tenant gets claimed (only set in AAP-strict mode)
 */
export type AgentStatus = 'pending' | 'active' | 'expired' | 'revoked' | 'rejected' | 'claimed'

/**
 * Agent operating mode (AAP v1.0 §3).
 *   delegated  — agent acts on behalf of a user; capability changes need approval
 *   autonomous — no user in loop; auto-approval by tenant policy only
 */
export type AgentMode = 'delegated' | 'autonomous'

export interface Agent {
  /** 'agent_*' prefix; globally unique within the tenant's DO. */
  id: string

  /** Foreign key to the parent Tenant (Identity{type:'tenant'}). */
  tenantId: string

  /** Human-readable label; not unique. */
  name: string

  /**
   * Public key in raw base64 form (32-byte Ed25519). Stored alongside the
   * agent record for offline JWK construction. Either this or jwksUrl must
   * be set; both may be set.
   */
  publicKey?: string

  /**
   * URL to a JWKS document. AAP allows agents to publish their key via JWKS
   * for rotation without re-registration. Either this or publicKey must be set.
   */
  jwksUrl?: string

  status: AgentStatus
  mode: AgentMode

  /**
   * Capability grants. These are the names that will project into FGA tuples
   * once id-lkj lands (e.g., ['transfer_money', 'read_contacts']). Today they
   * are flat strings used for documentation; FGA will give them structure.
   */
  capabilities: string[]

  createdAt: number
  activatedAt?: number
  expiresAt?: number
  lastUsedAt?: number
  revokedAt?: number

  /**
   * AAP lifecycle clocks (§5.4).
   *   sessionTtlMs       — measured from lastUsedAt; → 'expired' if idle
   *   maxLifetimeMs      — measured from activatedAt; → 'expired' if exceeded
   *   absoluteLifetimeMs — measured from createdAt; → 'revoked' if exceeded
   */
  sessionTtlMs: number
  maxLifetimeMs: number
  absoluteLifetimeMs: number
}

/** Public-facing summary for list responses. */
export interface AgentInfo {
  id: string
  tenantId: string
  name: string
  status: AgentStatus
  mode: AgentMode
  capabilities: string[]
  createdAt: number
  activatedAt?: number
  expiresAt?: number
  lastUsedAt?: number
  revokedAt?: number
}

// ============================================================================
// Input Types
// ============================================================================

export interface RegisterAgentInput {
  tenantId: string
  name: string
  /** Base64-encoded 32-byte Ed25519 public key. Mutually exclusive with jwksUrl. */
  publicKey?: string
  /** JWKS document URL. Mutually exclusive with publicKey. */
  jwksUrl?: string
  mode: AgentMode
  capabilities?: string[]
  /**
   * AAP-strict mode (D7): when true, the agent transitions to 'claimed'
   * (terminal) when the parent tenant gets claimed. Default false →
   * id.org.ai claim-continuity (agent stays active under the claimed tenant).
   */
  strict?: boolean
  /** Override default sessionTtlMs (default 24h). */
  sessionTtlMs?: number
  /** Override default maxLifetimeMs (default 30d). */
  maxLifetimeMs?: number
  /** Override default absoluteLifetimeMs (default 365d). */
  absoluteLifetimeMs?: number
}

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
