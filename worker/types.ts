/**
 * Shared types for the id.org.ai worker.
 * Extracted from worker/index.ts to allow reuse across route modules.
 */

import type { MCPAuthResult } from '../src/sdk/mcp/auth'
import type { IdentityStub } from '../src/server/do/Identity'
import type { AuthUser, VerifyResult, AuthResult } from '../src/sdk/auth/index.js'
import type { Identity } from '../src/sdk/types'

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
  // Trusted-account OAuth (ADR-0007). Comma-separated list of bare hostnames
  // (e.g. "startup.games,foo.example") whose redirect_uri is accepted under
  // the canonical shared client_id `cid_trusted_account_v1` without per-app DCR.
  TRUSTED_ACCOUNT_DOMAINS?: string
  /**
   * Extra hosts a sign-in (`/login?continue=`) or sign-out
   * (`/logout?return_url=`) may send the browser to, beyond the built-in
   * policy in worker/utils/relying-parties.ts. Comma-separated bare hostnames;
   * a leading `*.` matches any subdomain (`*.dotdo.workers.dev`). Config, not
   * code, so adding an estate site is a reviewable one-line change.
   */
  LOGIN_CONTINUE_HOSTS?: string
  /**
   * `enforce` (the default when unset): a `/login` continue or `/logout`
   * return_url outside the policy falls back to the default landing.
   * `report`: it is still followed (the pre-policy behaviour), and logged as
   * `login.continue.unlisted` / `logout.return.unlisted` so the estate's
   * callers can be found and listed before switching to `enforce`.
   * POST /api/magic-link always enforces.
   */
  LOGIN_CONTINUE_POLICY?: string
  /**
   * `true` serves the DLVP handshake (/dlvp/*, worker/routes/dlvp.ts).
   * Unset in production: nothing in DLVP can complete there yet (empty issuer
   * trust map, no-op settlement), so its anonymous surface stays off.
   */
  DLVP_ENABLED?: string
  /**
   * OAuth client ids allowed to call POST /api/magic-link, comma-separated.
   * Registration (RFC 7591) is open, so a registered client is not by itself
   * trusted to have id.org.ai email sign-in codes. Unset = no client may call
   * it. Workers in the account call AuthService.sendMagicLink (RPC) instead;
   * HTTP never infers a service binding from the request's host.
   */
  MAGIC_LINK_CLIENTS?: string
  /**
   * Test seam: the WorkOS API base. Unset in production (https://api.workos.com).
   * worker/.dev.vars points it at the local stub (test-visual/workos-stub.mjs).
   * Only loopback URLs are honoured (src/sdk/workos/base.ts).
   */
  WORKOS_API_BASE?: string
  /**
   * Escape hatch (B13.2): `1` restores the old unauthenticated /admin-portal,
   * /fga/* and /pipes/* if an unknown estate caller breaks. `0` (secure) by default.
   */
  LEGACY_OPEN_WORKOS_ROUTES?: string
  /** CIMD client hosts shown as verified on consent (D3), comma-separated. Empty: only first-party clients are. */
  VERIFIED_CLIENT_HOSTS?: string
  /** `1` serves the design gallery at /__design (worker/.dev.vars only; never in wrangler.jsonc). */
  DESIGN_GALLERY?: string
}

export type Variables = {
  auth: MCPAuthResult
  identityStub: IdentityStub
  // Added for middleware extraction: typed accessor for the resolved identity ID
  // set via c.set('resolvedIdentityId', ...) in auth middleware (previously untyped)
  resolvedIdentityId?: string
  // The canonical Identity, set by authenticateRequest (worker/middleware/auth.ts)
  identity?: Identity
  // X-Request-Id for this request (worker/middleware/request-id.ts)
  requestId: string
}

// ── Auth Service (RPC via Service Binding) ──────────────────────────────
// Exposes verifyToken() as an RPC method for other Cloudflare Workers.
// Other workers bind to this as `env.AUTH` and call `env.AUTH.verifyToken(token)`.
export type AuthRPCResult = AuthResult
