/**
 * Shared types for the id.org.ai worker.
 * Extracted from worker/index.ts to allow reuse across route modules.
 */

import type { MCPAuthResult } from '../src/sdk/mcp/auth'
import type { IdentityStub } from '../src/server/do/Identity'
import type { AuthUser, VerifyResult, AuthResult } from '../src/sdk/auth/index.js'

export type { MCPAuthResult, IdentityStub, AuthUser, VerifyResult, AuthResult }

export interface Env {
  IDENTITY: DurableObjectNamespace
  SESSIONS: KVNamespace
  DB?: D1Database
  ASSETS?: Fetcher
  AUTH_SECRET: string
  JWKS_SECRET: string
  WORKOS_CLIENT_ID?: string
  WORKOS_API_KEY?: string
  WORKOS_COOKIE_PASSWORD?: string
  WORKOS_WEBHOOK_SECRET?: string
  GITHUB_APP_ID?: string
  GITHUB_APP_PRIVATE_KEY?: string
  GITHUB_WEBHOOK_SECRET?: string
  // WorkOS Actions
  WORKOS_ACTIONS_SECRET?: string
  // Platform org — users in this org get platformRole: 'superadmin'
  PLATFORM_ORG_ID?: string
  // Branding for @mdxui/auth SPA
  APP_NAME?: string
  APP_TAGLINE?: string
  REDIRECT_URI?: string
}

export type Variables = {
  auth: MCPAuthResult
  identityStub: IdentityStub
  // Added for middleware extraction: typed accessor for the resolved identity ID
  // set via c.set('resolvedIdentityId', ...) in auth middleware (previously untyped)
  resolvedIdentityId?: string
}

// ── Auth Service (RPC via Service Binding) ──────────────────────────────
// Exposes verifyToken() as an RPC method for other Cloudflare Workers.
// Other workers bind to this as `env.AUTH` and call `env.AUTH.verifyToken(token)`.
export type AuthRPCResult = AuthResult
