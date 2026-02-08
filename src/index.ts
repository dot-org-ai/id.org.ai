/**
 * id.org.ai — Agent-First Identity
 *
 * "Humans. Agents. Identity."
 *
 * Open identity standard for the agent era:
 *   - Humans: WorkOS AuthKit (SSO, social login, MFA)
 *   - Agents: Ed25519 keypairs, GitHub identity, MCP auth
 *   - Organizations: Groups of humans and agents
 *
 * The core innovation: Connect → Operate → Claim
 *   1. Agent connects to MCP with no auth
 *   2. Server provisions a real sandbox tenant
 *   3. Agent operates freely (creates contacts, deals, workflows)
 *   4. Agent commits a GitHub Action workflow file to claim the tenant
 *   5. The commit IS the identity — GitHub authenticates who pushed
 *
 * @example
 * ```typescript
 * import { IdentityDO } from 'id.org.ai'
 * import { schema } from 'id.org.ai/db'
 * import { MCPAuth } from 'id.org.ai/mcp'
 * import { ClaimService } from 'id.org.ai/claim'
 * ```
 */

// Core DO
export { IdentityDO } from './do/Identity'
export type { Identity, IdentityType, IdentityEnv } from './do/Identity'

// Database schema
export * from './db'

// OAuth provider
export * from './oauth'

// MCP authentication
export * from './mcp'

// Auth utilities
export * from './auth'

// Claim-by-commit
export * from './claim'

// GitHub integration
export * from './github'

// Ed25519 cryptographic identity
export * from './crypto'

// CSRF protection
export * from './csrf'

// Audit logging
export * from './audit'

// Standardized error responses
export * from './errors'
