/**
 * IdentityService — Domain 3 (Identity Core)
 *
 * Owns: Identity CRUD, provisioning, freeze/unfreeze, linked accounts
 * Depends on: Foundation (0), Audit (10), EntityStore (9)
 * Depended on by: ClaimService (4), KeysService (5), AuthService (1),
 *                 MCPService (6), OAuthService (2), OrgService (7)
 *
 * Design: CQRS-inspired Reader/Writer split with typed creation methods.
 * Most services depend only on IdentityReader (thin, read-only).
 * State transition safety is enforced at runtime inside the implementation.
 */

import type { Result } from '../../foundation'
import type { NotFoundError, ValidationError, AuthError, ConflictError } from '../../foundation'

// ============================================================================
// Domain Types
// ============================================================================

export type IdentityType = 'human' | 'agent' | 'service'
export type CapabilityLevel = 0 | 1 | 2 | 3
export type ClaimStatus = 'unclaimed' | 'pending' | 'claimed' | 'frozen' | 'expired'
export type LinkedAccountProvider = 'github' | 'stripe' | 'anthropic'
export type LinkedAccountType = 'auth' | 'payment' | 'ai' | 'platform' | 'service'
export type LinkedAccountStatus = 'active' | 'pending' | 'expired' | 'revoked'

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
  frozen?: boolean
  frozenAt?: number
  githubUserId?: string
  githubUsername?: string
  createdAt: number
  updatedAt: number
}

export interface LinkedAccount {
  id: string
  identityId: string
  provider: LinkedAccountProvider
  providerAccountId: string
  type: LinkedAccountType
  displayName: string
  email?: string
  status: LinkedAccountStatus
  linkedAt: number
  metadata?: Record<string, unknown>
}

// ============================================================================
// Input Types
// ============================================================================

export interface CreateIdentityInput {
  type: IdentityType
  name: string
  email?: string
  handle?: string
  capabilities?: string[]
  ownerId?: string
  level?: CapabilityLevel
  id?: string
}

export interface CreateIdentityResult {
  identity: Identity
  claimToken: string
}

export interface CreateHumanInput {
  name: string
  email: string
  handle?: string
  image?: string
}

export interface CreateServiceInput {
  name: string
  handle: string
}

export interface ProvisionAgentInput {
  name?: string
  model?: string
  capabilities?: string[]
}

export interface ProvisionAgentResult {
  identity: Identity
  claimToken: string
}

export interface UpdateIdentityInput {
  name?: string
  handle?: string
  email?: string
  image?: string
  verified?: boolean
  level?: CapabilityLevel
  claimStatus?: ClaimStatus
  githubUserId?: string
  githubUsername?: string
}

export interface LinkAccountInput {
  provider: LinkedAccountProvider
  providerAccountId: string
  type: LinkedAccountType
  displayName: string
  email?: string
  metadata?: Record<string, unknown>
}

// ============================================================================
// IdentityReader — Thin read-only interface
// ============================================================================
//
// The most-consumed interface in the system. Every service that needs to
// validate an identity exists, check frozen status, or resolve by handle/email
// depends on this — and ONLY this.
//
// Callers: AuthService, KeysService, MCPService, OAuthService, ClaimService

export interface IdentityReader {
  /** Get identity by ID. Most common operation. */
  get(id: string): Promise<Result<Identity, NotFoundError>>

  /** Fast existence check — avoids full deserialization. */
  exists(id: string): Promise<boolean>

  /** Resolve identity by unique handle. */
  getByHandle(handle: string): Promise<Result<Identity, NotFoundError>>

  /** Resolve identity by email (humans only, unique constraint). */
  getByEmail(email: string): Promise<Result<Identity, NotFoundError>>

  /** Resolve identity by GitHub user ID (claim flow, webhook dedup). */
  getByGitHubUserId(githubUserId: string): Promise<Result<Identity, NotFoundError>>

  /** List linked accounts for an identity. */
  getLinkedAccounts(identityId: string): Promise<Result<LinkedAccount[], NotFoundError>>

  /** Get a specific linked account by provider. */
  getLinkedAccount(identityId: string, provider: LinkedAccountProvider): Promise<Result<LinkedAccount, NotFoundError>>
}

// ============================================================================
// IdentityWriter — Typed creation + mutations + linked accounts
// ============================================================================
//
// Consumed by services that create or modify identities:
//   - Worker provisioning routes (provisionAgent, createHuman)
//   - ClaimService (update claimStatus, link GitHub account)
//   - Admin routes (freeze/unfreeze)
//
// Extends IdentityReader so writers don't need two injections.
//
// Design notes:
//   - Typed creation methods (createHuman, provisionAgent, createService)
//     instead of generic create() — different preconditions and guarantees
//   - update() for mutable field patches — state transition validation at runtime
//   - freeze/unfreeze as explicit methods — cascading side effects
//   - linkAccount/unlinkAccount for external provider lifecycle
//   - No delete — nothing is ever deleted

export interface IdentityWriter extends IdentityReader {
  /**
   * Generic identity creation — matches the legacy DO createIdentity() contract.
   * Accepts any type/level/id combo, stores exactly what you give it.
   * Defaults: verified=false, claimStatus='unclaimed', generates claimToken.
   * Creates secondary indexes (email, handle) automatically.
   * Used by the DO bridge; new code should prefer the typed methods below.
   */
  create(input: CreateIdentityInput): Promise<Result<CreateIdentityResult, ValidationError | ConflictError>>

  /**
   * Create a human identity (arrives pre-claimed via WorkOS AuthKit).
   * Starts at claimStatus='claimed', level >= 2.
   */
  createHuman(input: CreateHumanInput): Promise<Result<Identity, ValidationError | ConflictError>>

  /**
   * Provision an anonymous agent identity with a claim token.
   * Starts at claimStatus='unclaimed', level=0.
   * Atomic: identity + claim token generated together.
   */
  provisionAgent(input: ProvisionAgentInput): Promise<Result<ProvisionAgentResult, ValidationError>>

  /**
   * Create a service identity (platform-internal).
   * Starts at claimStatus='claimed', level=3.
   */
  createService(input: CreateServiceInput): Promise<Result<Identity, ValidationError | ConflictError>>

  /**
   * Partial update of mutable fields.
   * Validates: type immutable, level monotonic, frozen rejects all patches.
   * ClaimService uses this to set claimStatus + level on claim completion.
   */
  update(id: string, input: UpdateIdentityInput): Promise<Result<Identity, NotFoundError | ValidationError | ConflictError>>

  /**
   * Freeze an identity — suspends all sessions and keys.
   * Side effects: session invalidation, key suspension, audit event.
   */
  freeze(id: string, reason: string): Promise<Result<Identity, NotFoundError | AuthError>>

  /**
   * Unfreeze a previously frozen identity.
   * Restores previous claimStatus.
   */
  unfreeze(id: string): Promise<Result<Identity, NotFoundError | AuthError>>

  /**
   * Link an external account (GitHub, Stripe, Anthropic).
   * Fails on duplicate provider+accountId.
   */
  linkAccount(identityId: string, input: LinkAccountInput): Promise<Result<LinkedAccount, NotFoundError | ValidationError | ConflictError>>

  /**
   * Revoke a linked account (soft — sets status to 'revoked').
   */
  unlinkAccount(identityId: string, provider: LinkedAccountProvider): Promise<Result<LinkedAccount, NotFoundError>>
}
