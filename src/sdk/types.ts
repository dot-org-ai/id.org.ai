/**
 * Portable identity types used by SDK modules.
 *
 * These types are the RPC contract for IdentityDO. They contain no
 * Cloudflare-specific dependencies and are safe to import from sdk/.
 *
 * The concrete IdentityDO class (in server/do/Identity.ts) re-exports
 * these types for backward compatibility.
 */

import type { AuditEvent, StoredAuditEvent, AuditQueryOptions } from './audit'

// ============================================================================
// Core types
// ============================================================================

export type IdentityType = 'human' | 'tenant' | 'service' | 'agent'
// 'agent' is kept transitionally for the runtime-synthesised Identity that
// AuthBroker emits when the underlying actor is an Agent row. No 'agent'
// rows are written to identity:* storage — Agents live in agent:* storage.

export type ClaimStatus = 'unclaimed' | 'pending' | 'claimed' | 'frozen' | 'expired'

export type CapabilityLevel = 0 | 1 | 2 | 3

export interface Identity {
  id: string
  type: IdentityType
  name: string
  handle?: string
  email?: string
  image?: string
  verified: boolean
  level: CapabilityLevel
  claimStatus: ClaimStatus
  organizationId?: string
  frozen?: boolean
  frozenAt?: number
  githubUserId?: string
  githubUsername?: string

  // ─── SVO co-design additive fields ─────────────────────────────────────
  // Extend Identity for the AuthBroker / PaymentBroker contracts in
  // src/sdk/auth and src/sdk/payment. All optional — back-compat for the
  // wildcard re-export through primitives.org.ai/packages/org.ai.

  /** W3C DID (`did:web:…`, `did:key:…`). Optional for non-DID flows. */
  did?: string

  /**
   * Parent Tenant ID. Set when type='agent' — the tenant under which this
   * agent operates. Synthesised at runtime by AuthBroker from the Agent
   * row's tenantId foreign key. Used by mcpDo for entity ownership and
   * by audit for tenantId scoping.
   */
  tenantId?: string

  /** Authorisation scopes — AuthBroker.check() consumes these. */
  scopes?: string[]

  /** Bound payment instruments. Consumed by PaymentBroker for rail selection. */
  paymentInstruments?: import('./payment/types').PaymentInstrument[]

  /** Reachable channels (email, slack, webhook). Used by digital-tasks. */
  contacts?: import('./payment/types').ContactChannel[]
}

export interface LinkedAccount {
  id: string
  provider: string
  type: 'auth' | 'payment' | 'ai' | 'platform' | 'service'
  displayName?: string
  status: 'active' | 'pending' | 'expired' | 'revoked'
}

export interface SessionData {
  identityId: string
  level: CapabilityLevel
  createdAt: number
  expiresAt: number
}

// ============================================================================
// Agent — first-class runtime actor under a Tenant (AAP-aligned)
// ============================================================================

/**
 * Agent lifecycle states (AAP v1.0 §3.2).
 *   pending  — awaiting user approval (delegated mode); cannot authenticate
 *   active   — operational; each request extends sessionTtl
 *   expired  — sessionTtl/maxLifetime elapsed; reactivable via reactivateAgent()
 *   revoked  — permanent; cannot reactivate
 *   rejected — user denied registration
 *   claimed  — autonomous-mode terminal state when parent Tenant gets claimed
 *              (only set in AAP-strict mode per D7)
 */
export type AgentStatus = 'pending' | 'active' | 'expired' | 'revoked' | 'rejected' | 'claimed'

/**
 * Agent operating mode (AAP v1.0 §3).
 *   delegated  — agent acts on behalf of a user; capability changes need approval
 *   autonomous — no user in loop; auto-approval by tenant policy only
 */
export type AgentMode = 'delegated' | 'autonomous'

export interface Agent {
  id: string
  tenantId: string
  name: string
  publicKey?: string
  jwksUrl?: string
  status: AgentStatus
  mode: AgentMode
  capabilities: string[]
  createdAt: number
  activatedAt?: number
  expiresAt?: number
  lastUsedAt?: number
  revokedAt?: number
  sessionTtlMs: number
  maxLifetimeMs: number
  absoluteLifetimeMs: number
}

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

export interface AgentRegistrationInput {
  tenantId: string
  name: string
  publicKey?: string
  jwksUrl?: string
  mode: AgentMode
  capabilities?: string[]
  strict?: boolean
  sessionTtlMs?: number
  maxLifetimeMs?: number
  absoluteLifetimeMs?: number
}

// ============================================================================
// IdentityStub — RPC interface for IdentityDO
// ============================================================================

/**
 * IdentityStub — the RPC interface for IdentityDO.
 *
 * All consumers use this type instead of the concrete class or `{ fetch() }`.
 * Workers RPC calls these methods directly on the DO stub — no HTTP overhead,
 * no X-Worker-Auth headers, no JSON serialization/deserialization.
 */
export interface IdentityStub {
  // Identity
  getIdentity(id: string): Promise<Identity | null>
  provisionAnonymous(presetIdentityId?: string): Promise<{ identity: Identity; sessionToken: string; claimToken: string }>
  claim(data: { claimToken: string; githubUserId: string; githubUsername: string; githubEmail?: string; repo?: string; branch?: string; defaultBranch?: string }): Promise<{ success: boolean; identity?: Identity; error?: string }>

  // Auth
  getSession(token: string): Promise<{ valid: boolean; identityId?: string; level?: CapabilityLevel; expiresAt?: number }>
  validateApiKey(key: string): Promise<{ valid: boolean; identityId?: string; scopes?: string[]; level?: CapabilityLevel }>
  createApiKey(data: { name: string; identityId: string; scopes?: string[]; expiresAt?: string }): Promise<{ id: string; key: string; name: string; prefix: string; scopes: string[]; createdAt: string; expiresAt?: string }>
  listApiKeys(identityId: string): Promise<Array<{ id: string; name: string; prefix: string; scopes: string[]; status: string; createdAt: string; expiresAt?: string; lastUsedAt?: string }>>
  revokeApiKey(keyId: string, identityId: string): Promise<{ id: string; status: string; revokedAt: string; key?: string } | null>
  checkRateLimit(identityId: string, level: CapabilityLevel): Promise<{ allowed: boolean; remaining: number; resetAt: number }>
  verifyClaimToken(token: string): Promise<{ valid: boolean; identityId?: string; status?: ClaimStatus; level?: CapabilityLevel; stats?: { entities: number; events: number; createdAt: number; expiresAt?: number } }>
  freezeIdentity(id: string): Promise<{ frozen: boolean; stats: { entities: number; events: number; sessions: number }; expiresAt: number }>

  // MCP
  mcpSearch(params: { identityId: string; query?: string; type?: string; filters?: Record<string, unknown>; limit?: number; offset?: number }): Promise<{ results: Array<{ type: string; id: string; data: Record<string, unknown>; score: number }>; total: number; limit: number; offset: number }>
  mcpFetch(params: { identityId: string; type: string; id?: string; filters?: Record<string, unknown>; limit?: number; offset?: number }): Promise<Record<string, unknown>>
  mcpDo(params: { entity: string; verb: string; data: Record<string, unknown>; identityId?: string; tenantId?: string; authLevel: number; timestamp: number }): Promise<{ success: boolean; entity: string; verb: string; result?: Record<string, unknown>; events?: unknown[]; error?: string }>

  // OAuth
  ensureCliClient(): Promise<void>
  ensureOAuthDoClient(): Promise<void>
  ensureWebClients(): Promise<void>
  oauthStorageOp(op: { op: 'get' | 'put' | 'delete' | 'list'; key?: string; value?: unknown; options?: { expirationTtl?: number; prefix?: string; limit?: number } }): Promise<Record<string, unknown>>

  // Agents (AAP-aligned, runtime actors under a Tenant)
  registerAgent(input: AgentRegistrationInput): Promise<{ success: boolean; agent?: Agent; error?: string }>
  getAgent(id: string): Promise<Agent | null>
  listAgents(tenantId: string): Promise<AgentInfo[]>
  getAgentByPublicKey(publicKey: string): Promise<Agent | null>
  updateAgentStatus(id: string, status: AgentStatus, reason?: string): Promise<{ success: boolean; agent?: Agent; error?: string }>
  revokeAgent(id: string, reason?: string): Promise<{ success: boolean; agent?: Agent; error?: string }>
  reactivateAgent(id: string): Promise<{ success: boolean; agent?: Agent; error?: string }>
  touchAgent(id: string): Promise<void>

  // Audit
  auditEvent(event: Omit<AuditEvent, 'timestamp'> & { timestamp?: string }): Promise<void>
  queryAuditLog(options: AuditQueryOptions): Promise<{ events: StoredAuditEvent[]; cursor?: string; hasMore: boolean }>

  // WorkOS widget token support
  storeWorkOSRefreshToken(token: string): Promise<void>
  refreshWorkOSToken(credentials: { clientId: string; apiKey: string }, organizationId?: string): Promise<string>
  clearWorkOSRefreshToken(): Promise<void>
}
