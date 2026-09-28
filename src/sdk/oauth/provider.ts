/**
 * OAuth 2.1 Provider for id.org.ai
 *
 * A complete OAuth 2.1 authorization server backed by Durable Object storage.
 *
 * Implements:
 *   - Authorization Code + PKCE (mandatory per OAuth 2.1, S256 only)
 *   - Refresh Token with Rotation (old token revoked on use)
 *   - Client Credentials (service-to-service)
 *   - Device Flow (RFC 8628) — critical for agents without browsers
 *   - Dynamic Client Registration (RFC 7591)
 *   - OIDC Discovery
 *   - Token Introspection (RFC 7662)
 *   - Token Revocation (RFC 7009)
 *   - UserInfo Endpoint (OIDC Core)
 *
 * Storage key schema:
 *   client:{cid_xxx}         → OAuthProviderClient
 *   code:{ac_xxx}            → AuthorizationCode
 *   access:{at_xxx}          → AccessToken
 *   refresh:{rt_xxx}         → RefreshToken
 *   device:{dc_xxx}          → DeviceCode
 *   device-user:{USERCODE}   → device code id (index for user code lookup)
 *   consent:{identityId}:{clientId} → ConsentRecord
 */


// ============================================================================
// Types
// ============================================================================
//
// NOTE: These types are INTERNAL to the OAuthProvider class, used with its
// StorageLike (Durable Object KV) storage backend. They differ from the
// canonical types in ./types.ts which define the public API contract:
//
// Provider (internal)         | types.ts (canonical API)         | Key Differences
// ─────────────────────────── | ──────────────────────────────── | ─────────────────────────────────
// AuthorizationCode           | OAuthAuthorizationCode           | identityId vs userId, scopes[] vs scope string, mandatory codeChallenge, nonce
// AccessToken                 | OAuthAccessToken                 | identityId vs userId, scopes[] vs scope string, no tokenType
// RefreshToken                | OAuthRefreshToken                | scopes[] vs scope string, family for rotation tracking, non-optional revoked
// DeviceCode                  | OAuthDeviceCode                  | status enum vs authorized/denied booleans, scopes[] vs scope string
// ConsentRecord               | OAuthConsent                     | minimal (scopes+createdAt) vs full (userId, clientId, updatedAt)
// IdentityInfo                | OAuthUser                        | minimal display info vs full user record with roles/permissions/metadata
// StorageLike                 | OAuthStorage                     | raw KV (get/put/delete/list) vs typed methods (getUser, saveClient, etc.)
//
// The provider types are intentionally simpler — they map directly to
// Durable Object KV entries. The canonical types provide a richer,
// more ergonomic API surface for external consumers.
// ============================================================================

import { SigningKeyManager, signJWT, verifyJWTWithKeyManager, type AccessTokenClaims } from '../jwt/signing'
import {
  ACCESS_TOKEN_JWT_TTL,
  ACCESS_TOKEN_TYP,
  AUD_BOUND_HEADER,
  peekJwtHeader,
  signAccessTokenJwt,
  type ActorClaim,
} from './access-token-jwt'
import {
  CIMD_NEGATIVE_TTL_S,
  cimdClientIdProblem,
  cimdRedirectMatches,
  cimdTtlSeconds,
  isLoopbackUri,
  looksLikeCimdClientId,
  parseClientMetadataDocument,
} from './cimd'
import { canonicalHostname } from '../csrf'
import {
  OIDC_SCOPES,
  SB_RESOURCES,
  SB_SCOPE_DO,
  SCOPES_SUPPORTED,
  SCOPE_DESCRIPTIONS,
  DEFAULT_SB_RESOURCE,
  SB_SCOPE_READ,
  bindSbScopes,
  isSbResource,
  isSbScope,
  parseResourceIndicators,
  sameResource,
  scopeProblem,
  splitScopes,
} from './delegation'

export interface OAuthConfig {
  issuer: string
  authorizationEndpoint: string
  tokenEndpoint: string
  userinfoEndpoint: string
  registrationEndpoint: string
  deviceAuthorizationEndpoint: string
  revocationEndpoint: string
  introspectionEndpoint: string
  jwksUri?: string
}

/**
 * Trusted-account OAuth configuration (ADR-0007).
 *
 * When a request arrives with `client_id === clientId` and the request's
 * `redirect_uri` host is in `allowedDomains`, the OAuth flow bypasses the
 * usual DCR `client:{cid_*}` storage lookup and treats the request as
 * coming from a public client whose redirect_uri list is implicit-via-
 * allowlist. PKCE remains mandatory; scope/state validation are unchanged.
 *
 * This implements option (b) from ADR-0007: bypass DCR lookup entirely for
 * the canonical client rather than provisioning a real DCR record. Chosen
 * to keep the diff small and avoid a one-time bootstrap step — the trusted-
 * account "client" is fully synthesized from env config at request time.
 */
export interface TrustedAccountConfig {
  /** Canonical shared client_id for in-Cloudflare-account consumers. */
  clientId: string
  /** Bare hostnames (no scheme/path) accepted as redirect_uri hosts. */
  allowedDomains: Set<string>
}

export interface OAuthProviderClient {
  id: string                   // cid_xxx
  name: string
  secret?: string              // hashed for confidential clients; absent for public
  redirectUris: string[]
  grantTypes: string[]
  responseTypes: string[]
  scopes: string[]
  trusted: boolean             // skip consent for first-party apps
  tokenEndpointAuthMethod: 'client_secret_basic' | 'client_secret_post' | 'none'
  logo?: string
  website?: string
  createdAt: number
}

// Internal storage type — see OAuthAuthorizationCode in ./types.ts for canonical API type
interface AuthorizationCode {
  id: string                   // ac_xxx
  clientId: string
  identityId: string
  scopes: string[]
  redirectUri: string
  codeChallenge: string        // mandatory for public clients
  codeChallengeMethod: 'S256'
  state?: string
  nonce?: string
  resource?: string
  effectiveIssuer?: string     // multi-tenant: issuer override from X-Issuer header
  signIn?: SignInContext       // how the person signed in (amr / idp / auth_time)
  expiresAt: number
  createdAt: number
}

// Internal storage type — see OAuthAccessToken in ./types.ts for canonical API type
interface AccessToken {
  id: string                   // at_xxx
  clientId: string
  identityId?: string          // absent for client_credentials
  scopes: string[]
  expiresAt: number
  createdAt: number
  resource?: string            // RFC 8707 resource indicator → the token's bound
                               // audience. Enforced by the resource server (e.g.
                               // /mcp) so a token minted for one resource cannot
                               // be replayed against another.
  signIn?: SignInContext       // how the person signed in, for userinfo amr / idp
  family?: string              // the grant's refresh-token family: revoking it deletes this token
  grantedAt?: number           // when the Person's grant was made (see isTokenRevoked)
}

/**
 * The server-side record of an RFC 9068 JWT access token (`access-jwt:{jti}`).
 * The JWT itself is self-contained; this record lets introspection answer for
 * it and lets revoking the grant mark it inactive there. A resource server
 * that verifies the JWT locally sees a revocation only when the token expires
 * (ACCESS_TOKEN_JWT_TTL, 15 minutes).
 */
interface AccessTokenJwtRecord {
  jti: string
  clientId: string
  identityId: string
  scopes: string[]
  resource: string
  family?: string
  act?: ActorClaim
  issuer: string
  expiresAt: number
  createdAt: number
  grantedAt?: number
  revoked?: boolean
}

// Internal storage type — see OAuthRefreshToken in ./types.ts for canonical API type
interface RefreshToken {
  id: string                   // rt_xxx
  clientId: string
  identityId: string
  scopes: string[]
  family: string               // rotation family — if a revoked token is reused, revoke entire family
  revoked: boolean
  expiresAt: number
  createdAt: number
  resource?: string            // RFC 8707 resource indicator
  effectiveIssuer?: string     // multi-tenant: issuer override from X-Issuer header
  /**
   * ADR-0007: the consumer's redirect_uri host at issuance time, captured for
   * trusted-account flows so `handleRefreshTokenGrant` can re-validate the
   * host against the current allowlist. Removing a domain from
   * TRUSTED_ACCOUNT_DOMAINS must invalidate live refresh tokens for that
   * domain, otherwise per-app revocation (ADR-0007 §"per-app revocation")
   * doesn't actually hold for the refresh grant. Unset for non-trusted-
   * account flows.
   */
  consumerHost?: string
  signIn?: SignInContext       // carried through rotation so refreshed id_tokens keep amr / idp
  /**
   * When the Person's grant (the authorization code or device approval) was
   * made; carried through every rotation. A grant revoked at or after this
   * time is dead, whatever rotation raced the revocation.
   */
  grantedAt?: number
}

// Internal storage type — see OAuthDeviceCode in ./types.ts for canonical API type
interface DeviceCode {
  id: string                   // dc_xxx
  clientId: string
  userCode: string             // 8-char alphanumeric
  scopes: string[]
  status: 'pending' | 'approved' | 'denied' | 'expired'
  identityId?: string          // set when user approves
  interval: number             // polling interval in seconds
  expiresAt: number
  createdAt: number
}

// Internal storage type — see OAuthConsent in ./types.ts for canonical API type
interface ConsentRecord {
  scopes: string[]
  createdAt: number
}

// Internal display type — see OAuthUser in ./types.ts for canonical API type
interface IdentityInfo {
  id: string
  name?: string
  handle?: string
  email?: string
  emailVerified?: boolean
  image?: string
  level?: number
}

/**
 * How the person signed in, carried from the id.org.ai session into the tokens
 * a relying party receives: OIDC `amr` (RFC 8176 style method references, e.g.
 * `["oauth"]`, `["email_otp"]`, `["magic_link"]`), `idp` (the upstream that
 * verified them: `github`, `google`, `microsoft`, `apple`, `authkit`,
 * `magic_link`) and `auth_time` (epoch seconds). All optional: a session that
 * predates this field, or a non-browser credential, simply carries none.
 */
export interface SignInContext {
  amr?: string[]
  idp?: string
  authTime?: number
}

/** Add amr / idp / auth_time from a sign-in context onto a claims object. */
export function applySignInClaims(claims: Record<string, unknown>, signIn: SignInContext | undefined): void {
  if (!signIn) return
  if (signIn.amr?.length) claims.amr = signIn.amr
  if (signIn.idp) claims.idp = signIn.idp
  if (signIn.authTime) claims.auth_time = signIn.authTime
}

function tierFromLevel(level: number | undefined): string | undefined {
  if (level === undefined || !Number.isInteger(level) || level < 0) return undefined
  return `L${level}`
}

/** Build the OIDC discovery document. Shared between OAuthProvider and server-side facade. */
export function buildOpenIDConfiguration(config: OAuthConfig, features: { cimd?: boolean } = {}): Record<string, unknown> {
  return {
    issuer: config.issuer,
    authorization_endpoint: config.authorizationEndpoint,
    token_endpoint: config.tokenEndpoint,
    userinfo_endpoint: config.userinfoEndpoint,
    registration_endpoint: config.registrationEndpoint,
    device_authorization_endpoint: config.deviceAuthorizationEndpoint,
    revocation_endpoint: config.revocationEndpoint,
    introspection_endpoint: config.introspectionEndpoint,
    jwks_uri: config.jwksUri,
    response_types_supported: ['code'],
    grant_types_supported: [
      'authorization_code',
      'refresh_token',
      'client_credentials',
      'urn:ietf:params:oauth:grant-type:device_code',
    ],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256', 'ES256'],
    scopes_supported: SCOPES_SUPPORTED,
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    code_challenge_methods_supported: ['S256'],
    // RFC 9207: every authorization response carries `iss`.
    authorization_response_iss_parameter_supported: true,
    // Client ID Metadata Documents: an https client_id is fetched and validated.
    ...(features.cimd && { client_id_metadata_document_supported: true }),
    claims_supported: ['sub', 'name', 'preferred_username', 'picture', 'email', 'email_verified', 'tier', 'amr', 'idp', 'auth_time'],
  }
}

/** `grant:{identity}:{client}:` — the families (grants) a Person gave one client. Components are URI-encoded (both may contain ':'). */
function grantIndexPrefix(identityId: string, clientId: string): string {
  return `grant:${encodeURIComponent(identityId)}:${encodeURIComponent(clientId)}:`
}
function grantIndexKey(identityId: string, clientId: string, family: string): string {
  return `${grantIndexPrefix(identityId, clientId)}${family}`
}
/**
 * The revocation check over any storage getter (the provider's, or the
 * worker's direct DO reads at /mcp and userinfo). See OAuthProvider.isTokenRevoked.
 */
export async function isTokenRevokedIn(
  get: (key: string) => Promise<unknown>,
  rec: { identityId?: string; clientId: string; createdAt: number; grantedAt?: number; family?: string },
): Promise<boolean> {
  if (rec.family && (await get(familyRevokedKey(rec.family)))) return true
  if (rec.identityId) {
    const tomb = (await get(grantRevokedKey(rec.identityId, rec.clientId))) as { at?: number } | undefined
    if (tomb && typeof tomb.at === 'number' && (rec.grantedAt ?? rec.createdAt) <= tomb.at) return true
  }
  return false
}

/** `grant-revoked:{identity}:{client}` → { at }: every grant made at or before `at` is dead. */
function grantRevokedKey(identityId: string, clientId: string): string {
  return `grant-revoked:${encodeURIComponent(identityId)}:${encodeURIComponent(clientId)}`
}
/** `fam-revoked:{family}` → { at }: the whole family is dead. */
function familyRevokedKey(family: string): string {
  return `fam-revoked:${family}`
}

// Internal storage abstraction — see OAuthStorage in ./storage.ts for canonical API type
type StorageLike = {
  get<T = unknown>(key: string): Promise<T | undefined>
  put(key: string, value: unknown, options?: { expirationTtl?: number }): Promise<void>
  delete(key: string): Promise<boolean>
  list<T = unknown>(options?: { prefix?: string; limit?: number }): Promise<Map<string, T>>
  /**
   * Read a key and delete it in one step, answering the value to exactly one
   * caller (the IdentityDO's `takeOnce`). Used to redeem an authorization code
   * so two parallel redemptions cannot both succeed. Optional: without it the
   * provider falls back to get-then-delete.
   */
  take?<T = unknown>(key: string): Promise<T | undefined>
  /**
   * True for exactly one caller per key (an atomic first-claim in the
   * IdentityDO). Used so a refresh token rotates once: of N parallel
   * refreshes with one token, one wins. Optional: without it, rotation is
   * get-then-put as before.
   */
  claimOnce?(key: string, ttlMs: number): Promise<boolean>
}

// ============================================================================
// Utilities
// ============================================================================

function generateId(prefix: string): string {
  const bytes = new Uint8Array(24)
  crypto.getRandomValues(bytes)
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
  return `${prefix}${hex}`
}

function generateUserCode(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789' // no I/O/0/1 to avoid confusion
  const bytes = new Uint8Array(8)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => chars[b % chars.length]).join('')
}

async function computeS256Challenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

function parseBasicAuth(header: string): { clientId: string; clientSecret: string } | null {
  if (!header.startsWith('Basic ')) return null
  try {
    const decoded = atob(header.slice(6))
    const colonIdx = decoded.indexOf(':')
    if (colonIdx < 0) return null
    const clientId = decodeURIComponent(decoded.slice(0, colonIdx))
    const clientSecret = decodeURIComponent(decoded.slice(colonIdx + 1))
    return clientId && clientSecret ? { clientId, clientSecret } : null
  } catch {
    return null
  }
}

async function parseBody(request: Request): Promise<Record<string, string>> {
  return (await parseBodyWithRepeats(request)).fields
}

/**
 * The request's parameters (string values only: a JSON array or object is
 * dropped, never passed on as a "string"), and the names of any form
 * parameter sent more than once (RFC 6749 §3.1: MUST NOT be).
 */
async function parseBodyWithRepeats(request: Request): Promise<{ fields: Record<string, string>; repeated: string[] }> {
  const contentType = request.headers.get('content-type') || ''
  const fields: Record<string, string> = {}
  if (contentType.includes('application/json')) {
    const json = (await request.json().catch(() => ({}))) as unknown
    if (json && typeof json === 'object' && !Array.isArray(json)) {
      for (const [key, value] of Object.entries(json as Record<string, unknown>)) {
        if (typeof value === 'string') fields[key] = value
      }
    }
    return { fields, repeated: [] }
  }
  const form = await request.formData()
  const seen = new Set<string>()
  const repeated = new Set<string>()
  for (const [key, value] of form.entries()) {
    if (seen.has(key)) repeated.add(key)
    seen.add(key)
    if (typeof value === 'string') fields[key] = value
  }
  return { fields, repeated: [...repeated] }
}

/**
 * How a consent POST reached the provider, as the route established it. The
 * sb scopes are granted only when `interactive`: the identity came from the
 * Person's id.org.ai browser session (the `auth` cookie, not an API key or
 * session token) and the consent form's CSRF binding was verified. The check
 * runs on the scopes the provider is about to grant, so no difference in how
 * the route and the provider read the form can get around it.
 */
export interface ConsentContext {
  interactive: boolean
}

function jsonResponse(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      Pragma: 'no-cache',
      ...headers,
    },
  })
}

function oauthError(error: string, description: string, status = 400): Response {
  return jsonResponse({ error, error_description: description }, status)
}

// ============================================================================
// Token Lifetimes (seconds)
// ============================================================================

const ACCESS_TOKEN_TTL = 3600               // 1 hour (OAuth 2.1 best practice)
const REFRESH_TOKEN_TTL = 30 * 24 * 3600   // 30 days
const AUTH_CODE_TTL = 600                   // 10 minutes
const DEVICE_CODE_TTL = 1800               // 30 minutes
const DEVICE_POLL_INTERVAL = 5             // 5 seconds

// ============================================================================
// OAuthProvider
// ============================================================================

/**
 * Audit event emitter callback used by the OAuthProvider to record
 * trusted-account flow events (ADR-0007 BLOCKER 2). Fire-and-forget —
 * implementations must not throw, and the provider treats failures as
 * non-fatal. When unset, the provider emits nothing.
 *
 * In production, the worker passes `oauthStub.auditEvent` here; the stub
 * forwards to AuditService which writes immutable `audit:*` rows in the
 * shared OAuth DO shard. In tests, callers may pass a vi.fn() to capture
 * emissions.
 */
export type OAuthAuditEmit = (event: {
  event: string
  actor?: string
  target?: string
  metadata?: Record<string, unknown>
  ip?: string
  userAgent?: string
}) => Promise<void> | void

/**
 * Fetch a Client ID Metadata Document (worker/utils/client-metadata.ts owns
 * the SSRF guards, the size and time limits and the no-redirect rule). The
 * provider validates and caches what comes back.
 */
export type ClientMetadataFetcher = (
  url: string,
) => Promise<
  | { ok: true; doc: unknown; cacheControl: string | null }
  /** `transient`: nothing was learned about this URL (e.g. the caller was rate-limited); do not cache. */
  | { ok: false; error: string; transient?: boolean }
>

/** A cached CIMD fetch: the document, or the error, until `expiresAt`. */
interface CimdCacheEntry {
  doc?: unknown
  error?: string
  expiresAt: number
}

export class OAuthProvider {
  private storage: StorageLike
  private config: OAuthConfig
  private getIdentity: (id: string) => Promise<IdentityInfo | null>
  private signingKeyManager?: SigningKeyManager
  private trustedAccount?: TrustedAccountConfig
  private auditEmit?: OAuthAuditEmit
  private fetchClientMetadata?: ClientMetadataFetcher

  get issuer(): string {
    return this.config.issuer
  }

  /** Resolve effective issuer — respects X-Issuer header for multi-tenant MCP servers */
  getEffectiveIssuer(request?: Request): string {
    if (request) {
      const xIssuer = request.headers.get('X-Issuer')
      if (xIssuer) {
        try {
          new URL(xIssuer)
          return xIssuer.replace(/\/$/, '')
        } catch { /* invalid URL, fall through */ }
      }
    }
    return this.config.issuer
  }

  constructor(options: {
    storage: StorageLike
    config: OAuthConfig
    getIdentity: (id: string) => Promise<IdentityInfo | null>
    signingKeyManager?: SigningKeyManager
    /** ADR-0007: trusted-account OAuth mode for in-CF-account consumers. */
    trustedAccount?: TrustedAccountConfig
    /**
     * ADR-0007 (BLOCKER 2): callback to record audit events for trusted-
     * account flow. Currently the provider emits `oauth.code.issued` and
     * `oauth.token.issued` only on the trusted-account code paths, since
     * those use one shared canonical client_id and would otherwise have
     * no per-request traceability. DCR'd clients are intentionally untouched.
     */
    auditEmit?: OAuthAuditEmit
    /**
     * Enables Client ID Metadata Documents: a client_id that is an https URL
     * is fetched with this and validated (src/sdk/oauth/cimd.ts). Without it,
     * such a client_id is simply unknown.
     */
    fetchClientMetadata?: ClientMetadataFetcher
  }) {
    this.storage = options.storage
    this.config = options.config
    this.getIdentity = options.getIdentity
    this.signingKeyManager = options.signingKeyManager
    this.trustedAccount = options.trustedAccount
    this.auditEmit = options.auditEmit
    this.fetchClientMetadata = options.fetchClientMetadata
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE: Trusted-Account Helpers (ADR-0007)
  // ═══════════════════════════════════════════════════════════════════════════

  /** True iff `clientId` is the canonical trusted-account client id. */
  private isTrustedAccountClient(clientId: string): boolean {
    return !!this.trustedAccount && clientId === this.trustedAccount.clientId
  }

  /**
   * Returns true if `redirectUri` parses cleanly, uses https (or localhost
   * for dev), and its host is in the trusted-account allowlist.
   */
  private isTrustedAccountRedirect(redirectUri: string): boolean {
    if (!this.trustedAccount) return false
    let parsed: URL
    try {
      parsed = new URL(redirectUri)
    } catch {
      return false
    }
    if (parsed.protocol !== 'https:' && parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
      return false
    }
    if (parsed.hash) return false
    return this.trustedAccount.allowedDomains.has(canonicalHostname(parsed.hostname))
  }

  /**
   * Synthesize a virtual `OAuthProviderClient` for the canonical trusted-
   * account client. Used in place of a DCR storage lookup. `redirectUris`
   * is intentionally empty — host validation is performed separately
   * against the allowlist via {@link isTrustedAccountRedirect}.
   */
  private buildTrustedAccountClient(): OAuthProviderClient {
    return {
      id: this.trustedAccount!.clientId,
      name: 'Trusted Account Consumer',
      // No secret — this is a public client; PKCE is enforced as usual.
      redirectUris: [], // implicit-via-allowlist; do not validate via this array
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      // Standard OIDC scopes; per-app scope narrowing is not needed under
      // the trusted-account model — account membership is the trust boundary.
      scopes: ['openid', 'profile', 'email', 'offline_access'],
      // First-party: skip consent screen. Account membership = consent.
      trusted: true,
      tokenEndpointAuthMethod: 'none',
      createdAt: 0,
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // OIDC Discovery
  // ═══════════════════════════════════════════════════════════════════════════

  getOpenIDConfiguration(): Response {
    return jsonResponse(buildOpenIDConfiguration(this.config, { cimd: !!this.fetchClientMetadata }))
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Dynamic Client Registration (RFC 7591)
  // ═══════════════════════════════════════════════════════════════════════════

  async handleRegister(request: Request): Promise<Response> {
    if (request.method !== 'POST') {
      return oauthError('invalid_request', 'Method not allowed', 405)
    }

    let body: Record<string, unknown>
    try {
      body = await request.json() as Record<string, unknown>
    } catch {
      return oauthError('invalid_request', 'Invalid JSON body')
    }

    const clientName = body.client_name as string | undefined
    if (!clientName) {
      return oauthError('invalid_client_metadata', 'client_name is required')
    }

    const redirectUris = (body.redirect_uris as string[]) || []
    const grantTypes = (body.grant_types as string[]) || ['authorization_code', 'refresh_token']
    const responseTypes = (body.response_types as string[]) || ['code']
    const scope = (body.scope as string) || 'openid profile email'
    const tokenEndpointAuthMethod = (body.token_endpoint_auth_method as string) || 'none'

    // Scope tokens must fit RFC 6749 §3.3, and the sb names are reserved.
    if (typeof scope !== 'string') {
      return oauthError('invalid_client_metadata', 'scope must be a string')
    }
    const scopeIssue = scopeProblem(splitScopes(scope))
    if (scopeIssue) {
      return oauthError('invalid_client_metadata', scopeIssue)
    }

    // Validate grant types
    const validGrantTypes = [
      'authorization_code',
      'refresh_token',
      'client_credentials',
      'urn:ietf:params:oauth:grant-type:device_code',
    ]
    for (const gt of grantTypes) {
      if (!validGrantTypes.includes(gt)) {
        return oauthError('invalid_client_metadata', `Unsupported grant_type: ${gt}`)
      }
    }

    // authorization_code requires at least one redirect_uri
    if (grantTypes.includes('authorization_code') && redirectUris.length === 0) {
      return oauthError('invalid_client_metadata', 'redirect_uris required for authorization_code grant')
    }

    // Validate redirect URIs (must be HTTPS or localhost for dev)
    for (const uri of redirectUris) {
      try {
        const parsed = new URL(uri)
        if (parsed.protocol !== 'https:' && parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
          return oauthError('invalid_redirect_uri', `redirect_uri must use HTTPS: ${uri}`)
        }
        if (parsed.hash) {
          return oauthError('invalid_redirect_uri', 'redirect_uri must not contain a fragment')
        }
      } catch {
        return oauthError('invalid_redirect_uri', `Invalid redirect_uri: ${uri}`)
      }
    }

    const clientId = generateId('cid_')
    const isConfidential = tokenEndpointAuthMethod !== 'none'
    const clientSecret = isConfidential ? generateId('cs_') : undefined

    const client: OAuthProviderClient = {
      id: clientId,
      name: clientName,
      secret: clientSecret,
      redirectUris,
      grantTypes,
      responseTypes,
      scopes: scope.split(' '),
      trusted: false,
      tokenEndpointAuthMethod: tokenEndpointAuthMethod as OAuthProviderClient['tokenEndpointAuthMethod'],
      logo: body.logo_uri as string | undefined,
      website: body.client_uri as string | undefined,
      createdAt: Date.now(),
    }

    await this.storage.put(`client:${clientId}`, client)

    const response: Record<string, unknown> = {
      client_id: clientId,
      client_name: clientName,
      redirect_uris: redirectUris,
      grant_types: grantTypes,
      response_types: responseTypes,
      scope,
      token_endpoint_auth_method: tokenEndpointAuthMethod,
      client_id_issued_at: Math.floor(client.createdAt / 1000),
    }

    if (clientSecret) {
      response.client_secret = clientSecret
      response.client_secret_expires_at = 0 // never expires
    }

    if (client.logo) response.logo_uri = client.logo
    if (client.website) response.client_uri = client.website

    return jsonResponse(response, 201)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Authorization Endpoint
  // ═══════════════════════════════════════════════════════════════════════════

  async handleAuthorize(request: Request, identityId: string | null, signIn?: SignInContext): Promise<Response> {
    const url = new URL(request.url)
    const params = url.searchParams
    const iss = this.getEffectiveIssuer(request)

    const scope = params.get('scope') || 'openid profile email'
    const state = params.get('state') || undefined
    const codeChallenge = params.get('code_challenge') || undefined
    const nonce = params.get('nonce') || undefined
    const loginHint = params.get('login_hint') || undefined

    const checked = await this.validateAuthorizationRequest({
      clientId: params.get('client_id') || '',
      redirectUri: params.get('redirect_uri') || '',
      responseType: params.get('response_type') || '',
      scope,
      state,
      codeChallenge,
      codeChallengeMethod: params.get('code_challenge_method') || undefined,
      resources: params.getAll('resource'),
      iss,
    })
    if (!checked.ok) return checked.response
    const { client, redirectUri, scopes: requestedScopes, resource } = checked
    const clientId = client.id

    // ── User must be authenticated ──────────────────────────────────────
    if (!identityId) {
      const loginUrl = new URL('/login', iss)
      loginUrl.searchParams.set('continue', request.url)
      // OIDC login_hint: prefill the sign-in email at the upstream page.
      if (loginHint) loginUrl.searchParams.set('login_hint', loginHint)
      return Response.redirect(loginUrl.toString(), 302)
    }

    // ── Check existing consent ──────────────────────────────────────────
    // A first-party (trusted) client skips the consent screen, except for
    // the sb scopes: delegating api.sb authority is always shown to the
    // Person once per client (and again on a step-up to more scopes).
    const consentKey = `consent:${identityId}:${clientId}`
    const existingConsent = await this.storage.get<ConsentRecord>(consentKey)
    const hasFullConsent = !!existingConsent && requestedScopes.every((s) => existingConsent.scopes.includes(s))
    const consentRequired = !client.trusted || requestedScopes.some(isSbScope)
    // A CIMD client with a loopback redirect is a public native client whose
    // client_id is public and whose port is free: anyone can start its flow
    // and catch the code on the Person's localhost. RFC 8252 §8.6: never
    // approve it silently, even when consent is on record.
    const alwaysAsk = looksLikeCimdClientId(clientId) && isLoopbackUri(redirectUri)

    if ((consentRequired && !hasFullConsent) || alwaysAsk) {
      return this.renderConsentPage(client, {
        clientId,
        redirectUri,
        scope: requestedScopes.join(' '),
        state,
        codeChallenge,
        codeChallengeMethod: codeChallenge ? 'S256' : undefined,
        nonce,
        resource,
      })
    }

    // ── Generate authorization code ─────────────────────────────────────
    return this.issueAuthorizationCode(client, identityId, {
      redirectUri,
      scopes: requestedScopes,
      codeChallenge: codeChallenge || '',
      codeChallengeMethod: 'S256',
      state,
      nonce,
      resource,
      effectiveIssuer: iss,
      signIn,
    })
  }

  /**
   * The client and a redirect_uri it may receive a response at. Until both
   * are known nothing may redirect, so failures answer 400 directly.
   */
  private async resolveClientRedirect(
    clientId: string,
    redirectUri: string,
  ): Promise<{ ok: true; client: OAuthProviderClient } | { ok: false; response: Response }> {
    // ADR-0007: trusted-account clients bypass the DCR lookup entirely.
    // Their redirect_uri allowlist is host-based and supplied by env config.
    if (this.isTrustedAccountClient(clientId)) {
      if (!this.isTrustedAccountRedirect(redirectUri)) {
        return { ok: false, response: oauthError('invalid_request', 'redirect_uri host is not in the trusted-account allowlist') }
      }
      return { ok: true, client: this.buildTrustedAccountClient() }
    }
    // Client ID Metadata Document: the client is what its URL publishes.
    if (looksLikeCimdClientId(clientId)) {
      const resolved = await this.resolveCimdClient(clientId)
      if (!resolved.ok) return { ok: false, response: oauthError('invalid_client', resolved.description) }
      if (!redirectUri || !cimdRedirectMatches(resolved.client.redirectUris, redirectUri)) {
        return { ok: false, response: oauthError('invalid_request', 'Invalid redirect_uri') }
      }
      return { ok: true, client: resolved.client }
    }
    const client = await this.getClient(clientId)
    if (!client) {
      return { ok: false, response: oauthError('invalid_client', 'Unknown client_id') }
    }
    // Validate redirect URI against the DCR-registered list
    if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
      return { ok: false, response: oauthError('invalid_request', 'Invalid redirect_uri') }
    }
    return { ok: true, client }
  }

  /**
   * Resolve a CIMD client: validate the client_id URL, then the cached or
   * freshly fetched metadata document. A failed fetch is remembered for
   * CIMD_NEGATIVE_TTL_S; a document for its Cache-Control max-age, clamped to
   * 5 minutes .. 24 hours. Fails closed: no stale document is used.
   */
  private async resolveCimdClient(clientId: string): Promise<{ ok: true; client: OAuthProviderClient } | { ok: false; description: string }> {
    if (!this.fetchClientMetadata) return { ok: false, description: 'Unknown client_id' }
    const problem = cimdClientIdProblem(clientId)
    if (problem) return { ok: false, description: problem }

    const cacheKey = `cimd:${clientId}`
    const now = Date.now()
    const cached = await this.storage.get<CimdCacheEntry>(cacheKey)
    if (cached && cached.expiresAt > now) {
      if (cached.error !== undefined) return { ok: false, description: cached.error }
      return parseClientMetadataDocument(clientId, cached.doc)
    }

    let entry: CimdCacheEntry
    try {
      const fetched = await this.fetchClientMetadata(clientId)
      if (!fetched.ok && fetched.transient) {
        return { ok: false, description: `client metadata could not be fetched: ${fetched.error}` }
      }
      if (!fetched.ok) {
        entry = { error: `client metadata could not be fetched: ${fetched.error}`, expiresAt: now + CIMD_NEGATIVE_TTL_S * 1000 }
      } else {
        const parsed = parseClientMetadataDocument(clientId, fetched.doc)
        entry = parsed.ok
          ? { doc: fetched.doc, expiresAt: now + cimdTtlSeconds(fetched.cacheControl) * 1000 }
          : { error: parsed.description, expiresAt: now + CIMD_NEGATIVE_TTL_S * 1000 }
      }
    } catch (err) {
      entry = { error: `client metadata could not be fetched: ${err instanceof Error ? err.message : 'error'}`, expiresAt: now + CIMD_NEGATIVE_TTL_S * 1000 }
    }
    await this.storage.put(cacheKey, entry)
    if (entry.error !== undefined) return { ok: false, description: entry.error }
    return parseClientMetadataDocument(clientId, entry.doc)
  }

  /**
   * Validate an authorization request: the one at GET /oauth/authorize and,
   * again, the one the consent form posts back (whose fields came through the
   * browser and are re-checked, not trusted). Errors before the client and
   * its redirect_uri are known answer 400 here; after, they redirect to the
   * client with `error`, `state` and `iss` (RFC 6749 §4.1.2.1, RFC 9207).
   */
  private async validateAuthorizationRequest(input: {
    clientId: string
    redirectUri: string
    responseType: string
    scope: string
    state?: string
    codeChallenge?: string
    codeChallengeMethod?: string
    resources: Array<string | null | undefined>
    iss: string
  }): Promise<
    | { ok: true; client: OAuthProviderClient; redirectUri: string; scopes: string[]; resource?: string }
    | { ok: false; response: Response }
  > {
    const { clientId, redirectUri, responseType, scope, state, codeChallenge, codeChallengeMethod, resources, iss } = input
    const fail = (response: Response) => ({ ok: false as const, response })
    const redirectFail = (error: string, description: string) => fail(this.redirectError(redirectUri, error, description, state, iss))

    // ── Validate client and redirect_uri ────────────────────────────────
    const resolved = await this.resolveClientRedirect(clientId, redirectUri)
    if (!resolved.ok) return resolved
    const { client } = resolved
    const trustedAccount = this.isTrustedAccountClient(clientId)

    // ── Validate response_type ──────────────────────────────────────────
    if (responseType !== 'code') {
      return redirectFail('unsupported_response_type', 'Only "code" response type is supported')
    }

    // ── Validate grant type includes authorization_code ─────────────────
    if (!client.grantTypes.includes('authorization_code')) {
      return redirectFail('unauthorized_client', 'Client is not authorized for authorization_code grant')
    }

    // ── PKCE is mandatory for public clients (OAuth 2.1) ────────────────
    if (client.tokenEndpointAuthMethod === 'none' && !codeChallenge) {
      return redirectFail('invalid_request', 'code_challenge is required for public clients (OAuth 2.1)')
    }

    // ── Only S256 is supported ──────────────────────────────────────────
    if (codeChallenge && codeChallengeMethod && codeChallengeMethod !== 'S256') {
      return redirectFail('invalid_request', 'Only S256 code_challenge_method is supported')
    }

    // ── Validate requested scopes ───────────────────────────────────────
    // The OIDC scopes and (for any client but the shared trusted-account
    // one) the sb scopes are grantable by the Person's consent; anything
    // else must be in the client's registered scopes.
    const requestedScopes = splitScopes(scope)
    const scopeIssue = scopeProblem(requestedScopes)
    if (scopeIssue) return redirectFail('invalid_scope', scopeIssue)
    const grantable = (s: string) =>
      client.scopes.includes(s) || (OIDC_SCOPES as readonly string[]).includes(s) || (!trustedAccount && isSbScope(s))
    const invalidScopes = requestedScopes.filter((s) => !grantable(s) || (trustedAccount && isSbScope(s)))
    if (invalidScopes.length > 0) {
      return redirectFail('invalid_scope', `Invalid scopes: ${invalidScopes.join(', ')}`)
    }

    // ── RFC 8707 resource indicator → the token's audience ──────────────
    const parsed = parseResourceIndicators(resources)
    if (!parsed.ok) return redirectFail('invalid_target', parsed.description)
    const bound = bindSbScopes(requestedScopes, parsed.resource)
    if (!bound.ok) return redirectFail(bound.error, bound.description)

    return { ok: true, client, redirectUri, scopes: bound.scopes, ...(bound.resource !== undefined && { resource: bound.resource }) }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Authorization Consent Submission
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * The consent form's POST. Every field came back through the browser, so the
   * request is validated again exactly as at GET /oauth/authorize (client,
   * redirect_uri, PKCE, scopes, resource) before anything is stored or a code
   * is issued. `approved`:
   *   - `true`  — grant the requested scopes;
   *   - `read`  — grant them without `sb:do` (the Person keeps api.sb
   *               read-only; the client can step up later);
   *   - else    — denied.
   */
  async handleAuthorizeConsent(request: Request, identityId: string, signIn?: SignInContext, context: ConsentContext = { interactive: false }): Promise<Response> {
    const { fields: body, repeated } = await parseBodyWithRepeats(request)
    const iss = this.getEffectiveIssuer(request)

    // RFC 6749 §3.1: a parameter sent twice is refused, so no reader of this
    // form can see a different value from the one granted.
    if (repeated.length > 0) {
      return oauthError('invalid_request', `repeated parameter: ${repeated.join(', ')}`)
    }

    const state = body.state || undefined
    const codeChallenge = body.code_challenge || undefined
    const nonce = body.nonce || undefined

    const approved = body.approved === 'true' || body.approved === 'read'
    if (!approved) {
      // A denial needs only a client and a redirect_uri it may receive.
      const resolved = await this.resolveClientRedirect(body.client_id || '', body.redirect_uri || '')
      if (!resolved.ok) return resolved.response
      return this.redirectError(body.redirect_uri || '', 'access_denied', 'User denied the authorization request', state, iss)
    }

    const checked = await this.validateAuthorizationRequest({
      clientId: body.client_id || '',
      redirectUri: body.redirect_uri || '',
      // The consent form is only ever rendered for a response_type=code request.
      responseType: 'code',
      scope: body.scope || 'openid profile email',
      state,
      codeChallenge,
      codeChallengeMethod: body.code_challenge_method || undefined,
      resources: [body.resource],
      iss,
    })
    if (!checked.ok) return checked.response
    const { client, redirectUri, resource } = checked

    // The sb scopes are delegated only by the Person in their browser.
    if (checked.scopes.some(isSbScope) && !context.interactive) {
      return jsonResponse(
        { error: 'access_denied', error_description: 'api.sb access can only be granted from a signed-in browser session' },
        403,
      )
    }

    // "Allow read only": sb:do becomes sb:read (never an empty grant).
    let scopes = checked.scopes
    if (body.approved === 'read' && scopes.includes(SB_SCOPE_DO)) {
      scopes = scopes.filter((s) => s !== SB_SCOPE_DO)
      if (!scopes.includes(SB_SCOPE_READ)) scopes.push(SB_SCOPE_READ)
    }

    // Store consent
    const consentKey = `consent:${identityId}:${client.id}`
    await this.storage.put(consentKey, {
      scopes,
      createdAt: Date.now(),
    } satisfies ConsentRecord)

    // Issue authorization code
    return this.issueAuthorizationCode(client, identityId, {
      redirectUri,
      scopes,
      codeChallenge: codeChallenge || '',
      codeChallengeMethod: 'S256',
      state,
      nonce,
      resource,
      effectiveIssuer: iss,
      signIn,
    })
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Token Endpoint
  // ═══════════════════════════════════════════════════════════════════════════

  async handleToken(request: Request): Promise<Response> {
    if (request.method !== 'POST') {
      return oauthError('invalid_request', 'Method not allowed', 405)
    }

    const body = await parseBody(request)
    const grantType = body.grant_type

    // Resolve client authentication from Authorization header or body
    let clientId = body.client_id || ''
    let clientSecret = body.client_secret || ''

    const authHeader = request.headers.get('authorization') || ''
    if (authHeader) {
      const basicAuth = parseBasicAuth(authHeader)
      if (basicAuth) {
        clientId = basicAuth.clientId
        clientSecret = basicAuth.clientSecret
      }
    }

    switch (grantType) {
      case 'authorization_code':
        return this.handleAuthorizationCodeGrant(clientId, clientSecret, body)
      case 'refresh_token':
        return this.handleRefreshTokenGrant(clientId, clientSecret, body)
      case 'client_credentials':
        return this.handleClientCredentialsGrant(clientId, clientSecret, body)
      case 'urn:ietf:params:oauth:grant-type:device_code':
        return this.handleDeviceCodeGrant(clientId, body)
      default:
        return oauthError('unsupported_grant_type', `Unsupported grant_type: ${grantType}`)
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Device Authorization Endpoint (RFC 8628)
  // ═══════════════════════════════════════════════════════════════════════════

  async handleDeviceAuthorization(request: Request): Promise<Response> {
    if (request.method !== 'POST') {
      return oauthError('invalid_request', 'Method not allowed', 405)
    }

    const body = await parseBody(request)
    const clientId = body.client_id

    if (!clientId) {
      return oauthError('invalid_request', 'client_id is required')
    }
    // CIMD clients use the authorization code flow only (and this endpoint is
    // unauthenticated: it must not make id.org.ai fetch arbitrary URLs).
    if (looksLikeCimdClientId(clientId)) {
      return oauthError('unauthorized_client', 'Client ID Metadata Document clients cannot use the device flow')
    }

    const client = await this.getClient(clientId)
    if (!client) {
      return oauthError('invalid_client', 'Unknown client_id')
    }

    if (!client.grantTypes.includes('urn:ietf:params:oauth:grant-type:device_code')) {
      return oauthError('unauthorized_client', 'Client is not authorized for device_code grant')
    }

    const scope = body.scope || client.scopes.join(' ')
    const scopes = scope.split(' ')

    // Scope tokens must fit RFC 6749 §3.3 (no tab- or case-smuggled sb names).
    const deviceScopeIssue = scopeProblem(scopes.filter(Boolean))
    if (deviceScopeIssue) return oauthError('invalid_scope', deviceScopeIssue)

    // The device approval page names no scopes, so it cannot be where a Person
    // delegates api.sb authority: the sb scopes go through /oauth/authorize,
    // whose consent screen shows them.
    const sbScopes = scopes.filter(isSbScope)
    if (sbScopes.length > 0) {
      return oauthError('invalid_scope', `${sbScopes.join(', ')} cannot be granted through the device flow; use the authorization code flow`)
    }

    const deviceCodeId = generateId('dc_')
    const userCode = generateUserCode()
    const now = Date.now()
    const expiresAt = now + DEVICE_CODE_TTL * 1000

    const deviceCode: DeviceCode = {
      id: deviceCodeId,
      clientId,
      userCode,
      scopes,
      status: 'pending',
      interval: DEVICE_POLL_INTERVAL,
      expiresAt,
      createdAt: now,
    }

    await this.storage.put(`device:${deviceCodeId}`, deviceCode, {
      expirationTtl: DEVICE_CODE_TTL + 60, // slight buffer
    })

    // Index by user code for quick lookup during approval
    await this.storage.put(`device-user:${userCode}`, deviceCodeId, {
      expirationTtl: DEVICE_CODE_TTL + 60,
    })

    return jsonResponse({
      device_code: deviceCodeId,
      user_code: userCode,
      verification_uri: `${this.config.issuer}/device`,
      verification_uri_complete: `${this.config.issuer}/device?user_code=${userCode}`,
      expires_in: DEVICE_CODE_TTL,
      interval: DEVICE_POLL_INTERVAL,
    })
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Device User Approval (browser-side)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Called when the user visits /device and enters the user code.
   * Returns an HTML page or handles the POST approval.
   */
  async handleDeviceVerification(request: Request, identityId: string | null): Promise<Response> {
    if (!identityId) {
      const loginUrl = new URL('/login', this.config.issuer)
      loginUrl.searchParams.set('continue', request.url)
      return Response.redirect(loginUrl.toString(), 302)
    }

    if (request.method === 'GET') {
      const url = new URL(request.url)
      const userCode = url.searchParams.get('user_code') || ''
      return this.renderDeviceVerificationPage(userCode)
    }

    if (request.method === 'POST') {
      const body = await parseBody(request)
      const userCode = (body.user_code || '').toUpperCase().replace(/[\s-]/g, '')
      const approved = body.approved === 'true'

      if (!userCode || userCode.length !== 8) {
        return this.renderDeviceVerificationPage('', 'Please enter a valid 8-character code')
      }

      const deviceCodeId = await this.storage.get<string>(`device-user:${userCode}`)
      if (!deviceCodeId) {
        return this.renderDeviceVerificationPage(userCode, 'Invalid or expired code. Please try again.')
      }

      const deviceCode = await this.storage.get<DeviceCode>(`device:${deviceCodeId}`)
      if (!deviceCode || deviceCode.expiresAt < Date.now()) {
        return this.renderDeviceVerificationPage(userCode, 'This code has expired. Please request a new one.')
      }

      if (deviceCode.status !== 'pending') {
        return this.renderDeviceVerificationPage(userCode, 'This code has already been used.')
      }

      // Update device code status
      await this.storage.put(`device:${deviceCodeId}`, {
        ...deviceCode,
        status: approved ? 'approved' : 'denied',
        identityId: approved ? identityId : undefined,
      } satisfies DeviceCode)

      if (approved) {
        return new Response(this.deviceApprovedHtml(), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        })
      }

      return this.renderDeviceVerificationPage('', 'Authorization denied.')
    }

    return oauthError('invalid_request', 'Method not allowed', 405)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // UserInfo Endpoint (OIDC Core)
  // ═══════════════════════════════════════════════════════════════════════════

  async handleUserinfo(request: Request): Promise<Response> {
    const authHeader = request.headers.get('authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return jsonResponse({ error: 'invalid_token' }, 401, {
        'WWW-Authenticate': 'Bearer',
      })
    }

    const tokenId = authHeader.slice(7)
    const tokenData = await this.storage.get<AccessToken>(`access:${tokenId}`)

    if (!tokenData) {
      return jsonResponse({ error: 'invalid_token' }, 401, {
        'WWW-Authenticate': 'Bearer error="invalid_token"',
      })
    }

    if (tokenData.expiresAt < Date.now()) {
      return jsonResponse({ error: 'invalid_token', error_description: 'Token has expired' }, 401, {
        'WWW-Authenticate': 'Bearer error="invalid_token"',
      })
    }

    if (!tokenData.identityId) {
      return oauthError('invalid_token', 'Token has no associated identity', 401)
    }

    const identity = await this.getIdentity(tokenData.identityId)
    if (!identity) {
      return jsonResponse({ error: 'invalid_token' }, 401)
    }

    const claims: Record<string, unknown> = {
      sub: identity.id,
    }

    if (tokenData.scopes.includes('profile')) {
      claims.name = identity.name
      claims.preferred_username = identity.handle
      claims.picture = identity.image
    }

    if (tokenData.scopes.includes('email') && identity.email) {
      claims.email = identity.email
      claims.email_verified = identity.emailVerified ?? false
    }

    applySignInClaims(claims, tokenData.signIn)

    return jsonResponse(claims)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Token Introspection (RFC 7662)
  // ═══════════════════════════════════════════════════════════════════════════

  async handleIntrospect(request: Request): Promise<Response> {
    if (request.method !== 'POST') {
      return oauthError('invalid_request', 'Method not allowed', 405)
    }

    const body = await parseBody(request)
    const token = body.token

    if (!token) {
      return jsonResponse({ active: false })
    }

    // Try as access token
    if (token.startsWith('at_')) {
      const tokenData = await this.storage.get<AccessToken>(`access:${token}`)
      if (tokenData && tokenData.expiresAt > Date.now() && !(await this.isTokenRevoked(tokenData))) {
        const identity = tokenData.identityId ? await this.getIdentity(tokenData.identityId) : null
        const tier = tierFromLevel(identity?.level)
        return jsonResponse({
          active: true,
          client_id: tokenData.clientId,
          sub: tokenData.identityId,
          scope: tokenData.scopes.join(' '),
          token_type: 'Bearer',
          exp: Math.floor(tokenData.expiresAt / 1000),
          iat: Math.floor(tokenData.createdAt / 1000),
          // RFC 7662 §2.2 `aud`: the resource the token is bound to (RFC 8707).
          // A resource server MUST check it is itself before honouring the token.
          ...(tokenData.resource !== undefined && { aud: tokenData.resource }),
          ...(tier && { tier }),
        })
      }
    }

    // Try as an RFC 9068 JWT access token
    if (token.split('.').length === 3) {
      const rec = await this.verifyAccessTokenJwt(token)
      if (rec) {
        const identity = await this.getIdentity(rec.identityId)
        const tier = tierFromLevel(identity?.level)
        return jsonResponse({
          active: true,
          client_id: rec.clientId,
          sub: rec.identityId,
          scope: rec.scopes.join(' '),
          token_type: 'Bearer',
          exp: Math.floor(rec.expiresAt / 1000),
          iat: Math.floor(rec.createdAt / 1000),
          aud: rec.resource,
          iss: rec.issuer,
          jti: rec.jti,
          ...(rec.act && { act: rec.act }),
          ...(tier && { tier }),
        })
      }
    }

    // Try as refresh token
    if (token.startsWith('rt_')) {
      const tokenData = await this.storage.get<RefreshToken>(`refresh:${token}`)
      if (tokenData && !tokenData.revoked && tokenData.expiresAt > Date.now() && !(await this.isTokenRevoked(tokenData))) {
        const identity = tokenData.identityId ? await this.getIdentity(tokenData.identityId) : null
        const tier = tierFromLevel(identity?.level)
        return jsonResponse({
          active: true,
          client_id: tokenData.clientId,
          sub: tokenData.identityId,
          scope: tokenData.scopes.join(' '),
          token_type: 'refresh_token',
          exp: Math.floor(tokenData.expiresAt / 1000),
          iat: Math.floor(tokenData.createdAt / 1000),
          ...(tokenData.resource !== undefined && { aud: tokenData.resource }),
          ...(tier && { tier }),
        })
      }
    }

    return jsonResponse({ active: false })
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Token Revocation (RFC 7009)
  // ═══════════════════════════════════════════════════════════════════════════

  async handleRevoke(request: Request): Promise<Response> {
    if (request.method !== 'POST') {
      return oauthError('invalid_request', 'Method not allowed', 405)
    }

    const body = await parseBody(request)
    const token = body.token

    if (!token) {
      // Per RFC 7009, respond 200 even if token is missing
      return new Response(null, { status: 200 })
    }

    // Revoke access token
    if (token.startsWith('at_')) {
      await this.storage.delete(`access:${token}`)
    }

    // Revoke a JWT access token: introspection answers inactive from now on
    // (a resource server verifying it locally sees that at its expiry).
    if (token.split('.').length === 3) {
      const rec = await this.verifyAccessTokenJwt(token)
      if (rec) {
        const { claims: _claims, ...stored } = rec
        await this.storage.put(`access-jwt:${rec.jti}`, { ...stored, revoked: true } satisfies AccessTokenJwtRecord)
      }
    }

    // Revoke refresh token (mark as revoked, don't delete — for family detection)
    if (token.startsWith('rt_')) {
      const tokenData = await this.storage.get<RefreshToken>(`refresh:${token}`)
      if (tokenData) {
        await this.storage.put(`refresh:${token}`, {
          ...tokenData,
          revoked: true,
        } satisfies RefreshToken)

        // Revoke the entire rotation family
        await this.revokeRefreshTokenFamily(tokenData.family)
      }
    }

    return new Response(null, { status: 200 })
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Validate Access Token (utility for downstream middleware)
  // ═══════════════════════════════════════════════════════════════════════════

  async validateAccessToken(token: string): Promise<AccessToken | null> {
    if (!token.startsWith('at_')) return null

    const tokenData = await this.storage.get<AccessToken>(`access:${token}`)
    if (!tokenData) return null
    if (tokenData.expiresAt < Date.now()) return null
    if (await this.isTokenRevoked(tokenData)) return null

    return tokenData
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE: Grant Handlers
  // ═══════════════════════════════════════════════════════════════════════════

  private async handleAuthorizationCodeGrant(
    clientId: string,
    clientSecret: string,
    body: Record<string, string>,
  ): Promise<Response> {
    const code = body.code
    const redirectUri = body.redirect_uri
    const codeVerifier = body.code_verifier

    if (!code) {
      return oauthError('invalid_request', 'code is required')
    }

    // ── Look up (and consume) the authorization code ────────────────────
    // With `take`, the code is read and deleted in one step, so of N parallel
    // redemptions exactly one sees it (RFC 6749 §4.1.2: a code is single-use).
    // Any failed check below has then spent the code too.
    const codeData = this.storage.take
      ? await this.storage.take<AuthorizationCode>(`code:${code}`)
      : await this.storage.get<AuthorizationCode>(`code:${code}`)
    if (!codeData) {
      return oauthError('invalid_grant', 'Invalid or expired authorization code')
    }

    // ── Verify client ───────────────────────────────────────────────────
    if (codeData.clientId !== clientId) {
      return oauthError('invalid_grant', 'Authorization code was not issued to this client')
    }

    // ── Verify expiration ───────────────────────────────────────────────
    if (codeData.expiresAt < Date.now()) {
      await this.storage.delete(`code:${code}`)
      return oauthError('invalid_grant', 'Authorization code has expired')
    }

    // ── Verify redirect URI ─────────────────────────────────────────────
    if (codeData.redirectUri !== redirectUri) {
      return oauthError('invalid_grant', 'redirect_uri mismatch')
    }

    // ── ADR-0007: re-verify host against trusted-account allowlist ──────
    // Defense in depth: even though the redirect_uri matches the one stored
    // on the code (which was validated at /authorize time), re-check that
    // its host is still in the allowlist. This catches an allowlist that
    // shrank between authorize and token exchange.
    if (this.isTrustedAccountClient(clientId)) {
      if (!this.isTrustedAccountRedirect(redirectUri)) {
        return oauthError(
          'invalid_grant',
          'redirect_uri host is not in the trusted-account allowlist',
        )
      }
      // Trusted-account is a public client — no client_secret required.
      // Fall through to PKCE verification below.
    }

    // ── Verify PKCE (mandatory per OAuth 2.1) ───────────────────────────
    if (codeData.codeChallenge) {
      if (!codeVerifier) {
        return oauthError('invalid_grant', 'code_verifier is required')
      }

      const computedChallenge = await computeS256Challenge(codeVerifier)
      if (computedChallenge !== codeData.codeChallenge) {
        return oauthError('invalid_grant', 'Invalid code_verifier')
      }
    } else if (!this.isTrustedAccountClient(clientId)) {
      // No PKCE — confidential client must present valid secret.
      // (Trusted-account clients always have PKCE per /authorize enforcement.)
      const client = await this.getClient(clientId)
      if (client?.secret && client.secret !== clientSecret) {
        return oauthError('invalid_client', 'Invalid client credentials', 401)
      }
      // A code without PKCE is only ever issued to a confidential client;
      // a public one (no secret, or a CIMD client) must never redeem one.
      if (!client?.secret) {
        return oauthError('invalid_grant', 'code_verifier is required')
      }
    }

    // ── RFC 8707 at the token endpoint: the resource, if sent, must be the
    //    one the code was granted for (a client cannot re-target it) ─────
    const target = this.tokenRequestResource(body, codeData.resource)
    if (!target.ok) return target.response

    // ── The Person may have revoked this client since the code was issued ─
    if (await this.isTokenRevoked({ identityId: codeData.identityId, clientId, createdAt: codeData.createdAt })) {
      await this.storage.delete(`code:${code}`)
      return oauthError('invalid_grant', 'The grant for this code has been revoked')
    }

    // ── Delete authorization code (one-time use) ────────────────────────
    await this.storage.delete(`code:${code}`)

    // ── Issue tokens ────────────────────────────────────────────────────
    // ADR-0007: stamp the consumer host on the refresh token so the
    // refresh-grant path can re-check it against the current allowlist
    // (per-app revocation by domain removal). Also feeds the
    // `oauth.token.issued` audit event's `redirectUriHost` field.
    const consumerHost = this.isTrustedAccountClient(clientId)
      ? this.extractRedirectUriHost(codeData.redirectUri)
      : undefined

    return this.issueTokenPair({
      clientId,
      identityId: codeData.identityId,
      scopes: codeData.scopes,
      nonce: codeData.nonce,
      resource: codeData.resource,
      accessResource: target.resource,
      effectiveIssuer: codeData.effectiveIssuer,
      consumerHost,
      signIn: codeData.signIn,
      grantedAt: codeData.createdAt,
    })
  }

  private async handleRefreshTokenGrant(
    clientId: string,
    clientSecret: string,
    body: Record<string, string>,
  ): Promise<Response> {
    const refreshTokenId = body.refresh_token

    if (!refreshTokenId) {
      return oauthError('invalid_request', 'refresh_token is required')
    }

    const tokenData = await this.storage.get<RefreshToken>(`refresh:${refreshTokenId}`)
    if (!tokenData) {
      return oauthError('invalid_grant', 'Invalid refresh token')
    }

    // ── Verify client ───────────────────────────────────────────────────
    if (tokenData.clientId !== clientId) {
      return oauthError('invalid_grant', 'Refresh token was not issued to this client')
    }

    // ── Verify client secret for confidential clients ───────────────────
    // Trusted-account is a public client (no secret); skip the lookup so we
    // don't materialise a DCR row for it.
    // CIMD clients are public (no secret), so there is nothing to look up.
    if (!this.isTrustedAccountClient(clientId) && !looksLikeCimdClientId(clientId)) {
      const client = await this.getClient(clientId)
      if (client?.secret && client.secret !== clientSecret) {
        return oauthError('invalid_client', 'Invalid client credentials', 401)
      }
    }

    // ── ADR-0007 (QUESTION resolved): re-validate consumer host against ──
    //     the current trusted-account allowlist. The authorize-code grant
    //     does the same check at code → token exchange; refresh must fail
    //     closed when a domain is removed from TRUSTED_ACCOUNT_DOMAINS,
    //     otherwise "per-app revocation" (ADR-0007 §"Negative / mitigations")
    //     doesn't actually hold for the refresh grant.
    if (this.isTrustedAccountClient(clientId)) {
      const host = tokenData.consumerHost
      if (!host || !this.trustedAccount!.allowedDomains.has(canonicalHostname(host))) {
        return oauthError(
          'invalid_grant',
          'redirect_uri host is not in the trusted-account allowlist',
        )
      }
    }

    // ── Check if revoked (replay detection) ─────────────────────────────
    if (tokenData.revoked) {
      // A revoked token was reused — possible token theft!
      // Revoke the entire rotation family
      await this.revokeRefreshTokenFamily(tokenData.family)
      return oauthError('invalid_grant', 'Refresh token has been revoked')
    }

    // ── Check expiration ────────────────────────────────────────────────
    if (tokenData.expiresAt < Date.now()) {
      return oauthError('invalid_grant', 'Refresh token has expired')
    }

    // ── RFC 8707: a resource sent with the refresh must be the grant's ───
    const target = this.tokenRequestResource(body, tokenData.resource)
    if (!target.ok) return target.response

    // ── Rotate once: of parallel refreshes with this token, one wins ─────
    if (this.storage.claimOnce && !(await this.storage.claimOnce(`rt-rotation:${refreshTokenId}`, REFRESH_TOKEN_TTL * 1000 + 60_000))) {
      return oauthError('invalid_grant', 'Refresh token has already been used')
    }

    // ── The grant (or this family) may have been revoked: refuse, whatever
    //    this token's own record says (a racing rotation may have written it) ─
    const grantedAt = tokenData.grantedAt ?? tokenData.createdAt
    if (await this.isTokenRevoked({ identityId: tokenData.identityId, clientId, createdAt: tokenData.createdAt, grantedAt, family: tokenData.family })) {
      await this.storage.put(`refresh:${refreshTokenId}`, { ...tokenData, revoked: true } satisfies RefreshToken)
      return oauthError('invalid_grant', 'Refresh token has been revoked')
    }

    // ── Rotate: revoke old refresh token ────────────────────────────────
    await this.storage.put(`refresh:${refreshTokenId}`, {
      ...tokenData,
      revoked: true,
    } satisfies RefreshToken)

    // ── Issue new token pair (same family for rotation tracking) ─────────
    return this.issueTokenPair({
      clientId,
      identityId: tokenData.identityId,
      scopes: tokenData.scopes,
      family: tokenData.family,
      resource: tokenData.resource,
      accessResource: target.resource,
      effectiveIssuer: tokenData.effectiveIssuer,
      // Propagate the consumer host through rotation so subsequent refreshes
      // can keep enforcing the allowlist (ADR-0007).
      consumerHost: tokenData.consumerHost,
      signIn: tokenData.signIn,
      grantedAt,
    })
  }

  /**
   * RFC 8707 §2.2 at the token endpoint. Only the authorization request, which
   * the Person sees, sets an audience:
   *   - a grant made with no resource ignores a `resource` here (as before this
   *     change): a sign-in grant's refresh token can never be turned into a
   *     token some resource server accepts;
   *   - a grant made for a resource accepts that same resource, and refuses any
   *     other with invalid_target;
   *   - the one narrowing: a grant for https://api.sb (the default for an
   *     sb-scoped request that named no resource) may ask for
   *     https://api.sb/mcp.
   */
  private tokenRequestResource(
    body: Record<string, string>,
    granted: string | undefined,
  ): { ok: true; resource?: string } | { ok: false; response: Response } {
    if (granted === undefined) return { ok: true }
    const parsed = parseResourceIndicators([body.resource])
    if (!parsed.ok) return { ok: false, response: oauthError('invalid_target', parsed.description) }
    if (parsed.resource === undefined) return { ok: true }
    if (sameResource(granted, DEFAULT_SB_RESOURCE) && parsed.resource === 'https://api.sb/mcp') return { ok: true, resource: parsed.resource }
    if (!sameResource(parsed.resource, granted)) {
      return { ok: false, response: oauthError('invalid_target', `this grant is for ${granted}, not ${parsed.resource}`) }
    }
    return { ok: true }
  }

  private async handleClientCredentialsGrant(
    clientId: string,
    clientSecret: string,
    body: Record<string, string>,
  ): Promise<Response> {
    if (!clientId || !clientSecret) {
      return oauthError('invalid_client', 'client_id and client_secret are required', 401)
    }
    // A CIMD client has no secret; never fetch its document from here.
    if (looksLikeCimdClientId(clientId)) {
      return oauthError('invalid_client', 'Unknown client', 401)
    }

    const client = await this.getClient(clientId)
    if (!client) {
      return oauthError('invalid_client', 'Unknown client', 401)
    }

    if (!client.grantTypes.includes('client_credentials')) {
      return oauthError('unauthorized_client', 'Client is not authorized for client_credentials grant')
    }

    if (!client.secret || client.secret !== clientSecret) {
      return oauthError('invalid_client', 'Invalid client credentials', 401)
    }

    const scope = body.scope || client.scopes.join(' ')
    const scopes = scope.split(' ')

    // Scope tokens must fit RFC 6749 §3.3 (no tab- or case-smuggled sb names).
    const ccScopeIssue = scopeProblem(scopes.filter(Boolean))
    if (ccScopeIssue) return oauthError('invalid_scope', ccScopeIssue)

    // The sb scopes delegate a Person's authority; client_credentials has no
    // Person, so it can never carry them.
    const sbScopes = scopes.filter(isSbScope)
    if (sbScopes.length > 0) {
      return oauthError('invalid_scope', `${sbScopes.join(', ')} need a Person's consent; not available with client_credentials`)
    }
    const target = parseResourceIndicators([body.resource])
    if (!target.ok) return oauthError('invalid_target', target.description)

    // Client credentials flow — no user, just the client
    const accessTokenId = generateId('at_')
    const now = Date.now()

    const accessToken: AccessToken = {
      id: accessTokenId,
      clientId,
      scopes,
      expiresAt: now + ACCESS_TOKEN_TTL * 1000,
      createdAt: now,
      // RFC 8707: audience-bind to the requested resource, if any.
      ...(target.resource !== undefined && { resource: target.resource }),
    }

    await this.storage.put(`access:${accessTokenId}`, accessToken, {
      expirationTtl: ACCESS_TOKEN_TTL + 60,
    })

    return jsonResponse({
      access_token: accessTokenId,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_TTL,
      scope: scopes.join(' '),
    })
  }

  private async handleDeviceCodeGrant(
    clientId: string,
    body: Record<string, string>,
  ): Promise<Response> {
    const deviceCodeId = body.device_code

    if (!deviceCodeId) {
      return oauthError('invalid_request', 'device_code is required')
    }
    if (looksLikeCimdClientId(clientId)) {
      return oauthError('invalid_client', 'Unknown client')
    }

    const client = await this.getClient(clientId)
    if (!client) {
      return oauthError('invalid_client', 'Unknown client')
    }

    const deviceCode = await this.storage.get<DeviceCode>(`device:${deviceCodeId}`)
    if (!deviceCode) {
      return oauthError('invalid_grant', 'Invalid or expired device code')
    }

    if (deviceCode.clientId !== clientId) {
      return oauthError('invalid_grant', 'Device code was not issued to this client')
    }

    if (deviceCode.expiresAt < Date.now()) {
      return oauthError('expired_token', 'The device code has expired')
    }

    switch (deviceCode.status) {
      case 'pending':
        return oauthError('authorization_pending', 'The user has not yet authorized this device')

      case 'denied':
        // Clean up
        await this.storage.delete(`device:${deviceCodeId}`)
        await this.storage.delete(`device-user:${deviceCode.userCode}`)
        return oauthError('access_denied', 'The user denied the authorization request')

      case 'approved': {
        if (!deviceCode.identityId) {
          return oauthError('server_error', 'Device code approved but missing identity')
        }

        // Clean up device code (one-time use)
        await this.storage.delete(`device:${deviceCodeId}`)
        await this.storage.delete(`device-user:${deviceCode.userCode}`)

        // Issue tokens
        return this.issueTokenPair({
          clientId,
          identityId: deviceCode.identityId,
          scopes: deviceCode.scopes,
          grantedAt: Date.now(),
        })
      }

      default:
        return oauthError('server_error', 'Unknown device code status')
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE: Token Issuance
  // ═══════════════════════════════════════════════════════════════════════════

  private async issueAuthorizationCode(
    client: OAuthProviderClient,
    identityId: string,
    params: {
      redirectUri: string
      scopes: string[]
      codeChallenge: string
      codeChallengeMethod: 'S256'
      state?: string
      nonce?: string
      resource?: string
      effectiveIssuer?: string
      signIn?: SignInContext
    },
  ): Promise<Response> {
    const codeId = generateId('ac_')
    const now = Date.now()

    const code: AuthorizationCode = {
      id: codeId,
      clientId: client.id,
      identityId,
      scopes: params.scopes,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      codeChallengeMethod: params.codeChallengeMethod,
      state: params.state,
      nonce: params.nonce,
      resource: params.resource,
      effectiveIssuer: params.effectiveIssuer,
      ...(params.signIn && { signIn: params.signIn }),
      expiresAt: now + AUTH_CODE_TTL * 1000,
      createdAt: now,
    }

    await this.storage.put(`code:${codeId}`, code, {
      expirationTtl: AUTH_CODE_TTL + 60,
    })

    // ADR-0007 (BLOCKER 2): trace which consumer host produced this code.
    // DCR'd clients are intentionally untouched — traceability for them is
    // still via the `client:{cid_*}` row. Trusted-account is the only case
    // where one canonical client_id is reused across an unbounded host set.
    if (this.isTrustedAccountClient(client.id)) {
      await this.safeEmitAudit({
        event: 'oauth.code.issued',
        actor: identityId,
        target: codeId,
        metadata: {
          clientId: client.id,
          identityId,
          redirectUriHost: this.extractRedirectUriHost(params.redirectUri),
          scopes: params.scopes,
        },
      })
    }

    const redirectUrl = new URL(params.redirectUri)
    redirectUrl.searchParams.set('code', codeId)
    if (params.state) {
      redirectUrl.searchParams.set('state', params.state)
    }
    // RFC 9207: name the issuer, so a client talking to several authorization
    // servers can tell which one answered (mix-up defence). The same value the
    // metadata's `issuer` carries for this request.
    redirectUrl.searchParams.set('iss', params.effectiveIssuer || this.config.issuer)

    return Response.redirect(redirectUrl.toString(), 302)
  }

  /**
   * Extract the bare hostname from a redirect_uri, or undefined if the URI
   * doesn't parse. Used for audit-event `redirectUriHost` (ADR-0007 BLOCKER 2)
   * and for the consumerHost stamped on trusted-account refresh tokens (the
   * QUESTION resolution in PR #8 review).
   */
  private extractRedirectUriHost(redirectUri: string): string | undefined {
    try {
      return canonicalHostname(new URL(redirectUri).hostname)
    } catch {
      return undefined
    }
  }

  /**
   * Fire-and-forget audit emission. Wraps the optional auditEmit callback
   * in a try/catch so a downstream sink failure can never break the OAuth
   * flow. Mirrors `worker/utils/audit.ts#logAuditEvent` semantics.
   */
  private async safeEmitAudit(event: {
    event: string
    actor?: string
    target?: string
    metadata?: Record<string, unknown>
    ip?: string
    userAgent?: string
  }): Promise<void> {
    if (!this.auditEmit) return
    try {
      await this.auditEmit(event)
    } catch {
      // never break the request flow for an audit failure
    }
  }

  private async issueTokenPair(options: {
    clientId: string
    identityId: string
    scopes: string[]
    family?: string
    nonce?: string
    resource?: string
    effectiveIssuer?: string
    /**
     * ADR-0007: consumer's redirect_uri host. Stored on the refresh-token
     * record so `handleRefreshTokenGrant` can re-validate against the
     * current allowlist (QUESTION resolution from PR #8 review). Also used
     * as the `redirectUriHost` audit metadata field. Trusted-account flows
     * only; ignored for everything else.
     */
    consumerHost?: string
    /** How the person signed in; stamped on the id_token and the stored tokens. */
    signIn?: SignInContext
    /**
     * The access token's audience when it differs from the grant's: a grant
     * with no resource whose token request named one (RFC 8707 §2.2). The
     * refresh token keeps the grant's `resource`.
     */
    accessResource?: string
    /** When the Person's grant was made (the code, or the device approval); carried through rotation. */
    grantedAt?: number
  }): Promise<Response> {
    const { clientId, identityId, scopes, family, nonce, effectiveIssuer, consumerHost, signIn } = options
    const grantedAt = options.grantedAt ?? Date.now()
    const resource = options.resource
    const tokenAudience = options.accessResource ?? resource
    const now = Date.now()
    const accessTokenId = generateId('at_')
    const refreshTokenId = generateId('rt_')
    const tokenFamily = family || crypto.randomUUID()
    const issuer = effectiveIssuer || this.config.issuer

    // An access token for api.sb is an RFC 9068 JWT, which api.sb verifies
    // against the JWKS with no call back here. Every other access token stays
    // opaque (at_…), as existing clients and resource servers expect. If
    // signing fails the token is opaque too (introspection still answers).
    let accessTokenValue = accessTokenId
    let accessExpiresIn = ACCESS_TOKEN_TTL
    const jwt =
      tokenAudience !== undefined && isSbResource(tokenAudience) && this.signingKeyManager
        ? await this.mintAccessTokenJwt({ clientId, identityId, scopes, resource: tokenAudience, family: tokenFamily, issuer, grantedAt }).catch(() => null)
        : null
    if (jwt) {
      accessTokenValue = jwt.token
      accessExpiresIn = jwt.expiresIn
    }

    const accessToken: AccessToken = {
      id: accessTokenId,
      clientId,
      identityId,
      scopes,
      expiresAt: now + ACCESS_TOKEN_TTL * 1000,
      createdAt: now,
      // RFC 8707: bind the token's audience to the requested resource so the
      // resource server can reject cross-resource replay (carried
      // authorize → code → token, and re-carried through refresh rotation).
      ...(tokenAudience !== undefined && { resource: tokenAudience }),
      ...(signIn && { signIn }),
      family: tokenFamily,
      grantedAt,
    }

    const refreshToken: RefreshToken = {
      id: refreshTokenId,
      clientId,
      identityId,
      scopes,
      family: tokenFamily,
      revoked: false,
      expiresAt: now + REFRESH_TOKEN_TTL * 1000,
      createdAt: now,
      ...(resource !== undefined && { resource }),
      ...(effectiveIssuer !== undefined && { effectiveIssuer }),
      ...(consumerHost !== undefined && { consumerHost }),
      ...(signIn && { signIn }),
      grantedAt,
    }

    if (!jwt) {
      await this.storage.put(`access:${accessTokenId}`, accessToken, {
        expirationTtl: ACCESS_TOKEN_TTL + 60,
      })
      await this.storage.put(`fam:${tokenFamily}:at:${accessTokenId}`, 1)
    }

    await this.storage.put(`refresh:${refreshTokenId}`, refreshToken, {
      expirationTtl: REFRESH_TOKEN_TTL + 60,
    })
    // Indexes for revocation: the family's tokens, and the grant's families.
    await this.storage.put(`fam:${tokenFamily}:rt:${refreshTokenId}`, 1)
    await this.storage.put(grantIndexKey(identityId, clientId, tokenFamily), { createdAt: now })

    // ADR-0007 (BLOCKER 2): emit token-issuance audit for trusted-account
    // flows. Trace points: access token id, refresh token id, consumer host.
    if (this.isTrustedAccountClient(clientId)) {
      await this.safeEmitAudit({
        event: 'oauth.token.issued',
        actor: identityId,
        target: accessTokenId,
        metadata: {
          clientId,
          identityId,
          redirectUriHost: consumerHost,
          refreshTokenId,
          scopes,
        },
      })
    }

    // Mint OIDC id_token when openid scope is granted and signing is available
    let idToken: string | undefined
    if (this.signingKeyManager && scopes.includes('openid')) {
      try {
        const key = await this.signingKeyManager.getCurrentKey()
        const identity = await this.getIdentity(identityId)

        const claims: Record<string, unknown> = {
          sub: identityId,
        }
        if (nonce) claims.nonce = nonce
        if (scopes.includes('email') && identity?.email) {
          claims.email = identity.email
          claims.email_verified = identity.emailVerified ?? false
        }
        if (scopes.includes('profile') && identity?.name) {
          claims.name = identity.name
        }
        const tier = tierFromLevel(identity?.level)
        if (tier) claims.tier = tier
        applySignInClaims(claims, signIn)

        // Compute at_hash (OIDC Core Section 3.1.3.6) over the access token issued
        const tokenHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessTokenValue))
        const halfHash = new Uint8Array(tokenHash).slice(0, 16)
        let atHashBinary = ''
        for (const byte of halfHash) atHashBinary += String.fromCharCode(byte)
        claims.at_hash = btoa(atHashBinary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')

        idToken = await signJWT(key, claims as AccessTokenClaims, {
          issuer: effectiveIssuer || this.config.issuer,
          audience: clientId,
          expiresIn: 3600,
        })
      } catch {
        // Signing failure — degrade gracefully, return tokens without id_token
      }
    }

    return jsonResponse({
      access_token: accessTokenValue,
      token_type: 'Bearer',
      expires_in: accessExpiresIn,
      refresh_token: refreshTokenId,
      scope: scopes.join(' '),
      ...(idToken && { id_token: idToken }),
    })
  }

  /**
   * Sign an RFC 9068 access token and keep its record (`access-jwt:{jti}`)
   * for introspection and revocation. Its lifetime is ACCESS_TOKEN_JWT_TTL,
   * never past `notAfter` (an exchanged token does not outlive its subject).
   */
  private async mintAccessTokenJwt(params: {
    clientId: string
    identityId: string
    scopes: string[]
    resource: string
    family?: string
    issuer: string
    act?: ActorClaim
    notAfter?: number
    grantedAt?: number
  }): Promise<{ token: string; expiresIn: number; jti: string }> {
    if (!this.signingKeyManager) throw new Error('no signing key')
    const key = await this.signingKeyManager.getCurrentKey()
    const nowMs = Date.now()
    const iat = Math.floor(nowMs / 1000)
    let exp = iat + ACCESS_TOKEN_JWT_TTL
    if (params.notAfter !== undefined) exp = Math.min(exp, Math.floor(params.notAfter / 1000))
    if (exp <= iat) throw new Error('subject token is about to expire')
    const jti = crypto.randomUUID()
    const token = await signAccessTokenJwt(key, {
      iss: params.issuer,
      sub: params.identityId,
      aud: params.resource,
      client_id: params.clientId,
      scope: params.scopes.join(' '),
      iat,
      exp,
      jti,
      ...(params.act && { act: params.act }),
    })
    const record: AccessTokenJwtRecord = {
      jti,
      clientId: params.clientId,
      identityId: params.identityId,
      scopes: params.scopes,
      resource: params.resource,
      ...(params.family !== undefined && { family: params.family }),
      ...(params.act && { act: params.act }),
      issuer: params.issuer,
      expiresAt: exp * 1000,
      createdAt: nowMs,
      grantedAt: params.grantedAt ?? nowMs,
    }
    await this.storage.put(`access-jwt:${jti}`, record)
    if (params.family !== undefined) await this.storage.put(`fam:${params.family}:jwt:${jti}`, 1)
    return { token, expiresIn: exp - iat, jti }
  }

  /**
   * Verify an id.org.ai JWT access token and return its live record: the
   * signature (id.org.ai's keys), `typ: at+jwt`, the `aud_bound` extension,
   * expiry, and that the grant it came from has not been revoked. Null when
   * any check fails.
   */
  private async verifyAccessTokenJwt(token: string): Promise<(AccessTokenJwtRecord & { claims: Record<string, unknown> }) | null> {
    if (!this.signingKeyManager) return null
    const header = peekJwtHeader(token)
    if (!header || header.typ !== ACCESS_TOKEN_TYP) return null
    await this.signingKeyManager.getJWKS() // loads the keys
    const claims = await verifyJWTWithKeyManager(token, this.signingKeyManager, { crit: [AUD_BOUND_HEADER], clockTolerance: 0 })
    if (!claims || typeof claims.jti !== 'string' || typeof claims.exp !== 'number') return null
    if (claims.exp * 1000 <= Date.now()) return null
    const record = await this.storage.get<AccessTokenJwtRecord>(`access-jwt:${claims.jti}`)
    if (!record || record.revoked || record.expiresAt <= Date.now()) return null
    if (await this.isTokenRevoked(record)) return null
    // The record is the authority; the claims must agree with it.
    if (claims.sub !== record.identityId || claims.client_id !== record.clientId || claims.aud !== record.resource || claims.iss !== record.issuer) return null
    return { ...record, claims }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE: Client Lookup
  // ═══════════════════════════════════════════════════════════════════════════

  private async getClient(clientId: string): Promise<OAuthProviderClient | null> {
    if (!clientId) return null
    // An https client_id is a CIMD client: never looked up in `client:` storage.
    if (looksLikeCimdClientId(clientId)) {
      const resolved = await this.resolveCimdClient(clientId)
      return resolved.ok ? resolved.client : null
    }
    const client = await this.storage.get<OAuthProviderClient>(`client:${clientId}`)
    return client ?? null
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE: Refresh Token Family Revocation
  // ═══════════════════════════════════════════════════════════════════════════

  private async revokeRefreshTokenFamily(family: string): Promise<void> {
    // Tombstone first: a rotation racing this revocation is refused at use.
    await this.storage.put(familyRevokedKey(family), { at: Date.now() })
    const tokens = await this.storage.list<RefreshToken>({ prefix: 'refresh:rt_' })
    const updates: Promise<void>[] = []

    for (const [key, token] of tokens) {
      if (token.family === family && !token.revoked) {
        updates.push(
          this.storage.put(key, {
            ...token,
            revoked: true,
          } satisfies RefreshToken),
        )
      }
    }

    await Promise.all(updates)
    await this.revokeIndexedFamilyTokens(family)
  }

  /**
   * RFC 7009 §2.1: revoking a grant's refresh token also invalidates the
   * access tokens issued from it. Opaque access tokens are deleted; JWT access
   * tokens are marked revoked (introspection says inactive at once; a
   * resource server verifying locally sees it at expiry, ≤ 15 minutes).
   */
  private async revokeIndexedFamilyTokens(family: string): Promise<void> {
    const index = await this.storage.list<unknown>({ prefix: `fam:${family}:` })
    for (const key of index.keys()) {
      const rest = key.slice(`fam:${family}:`.length)
      const sep = rest.indexOf(':')
      const kind = rest.slice(0, sep)
      const id = rest.slice(sep + 1)
      if (kind === 'at') {
        await this.storage.delete(`access:${id}`)
      } else if (kind === 'jwt') {
        const rec = await this.storage.get<AccessTokenJwtRecord>(`access-jwt:${id}`)
        if (rec && !rec.revoked) await this.storage.put(`access-jwt:${id}`, { ...rec, revoked: true } satisfies AccessTokenJwtRecord)
      } else if (kind === 'rt') {
        const rec = await this.storage.get<RefreshToken>(`refresh:${id}`)
        if (rec && !rec.revoked) await this.storage.put(`refresh:${id}`, { ...rec, revoked: true } satisfies RefreshToken)
      }
    }
  }

  /**
   * Is the grant a token (or code) belongs to revoked? Revocation writes its
   * tombstone before anything else, and every point of use asks this, so a
   * rotation, redemption or exchange racing a revocation cannot outlive it:
   *   - the Person revoked the client's grant at or after the grant was made
   *     (`grant-revoked:`), or
   *   - the token's refresh family was revoked (`fam-revoked:`; RFC 7009).
   * `grantedAt` falls back to `createdAt` for records made before it existed.
   */
  async isTokenRevoked(rec: { identityId?: string; clientId: string; createdAt: number; grantedAt?: number; family?: string }): Promise<boolean> {
    return isTokenRevokedIn((key) => this.storage.get(key), rec)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Grants: what a Person has delegated to each client
  // ═══════════════════════════════════════════════════════════════════════════

  /** The clients a Person has consented to, with the scopes they hold. */
  async listGrants(identityId: string): Promise<Array<{ client_id: string; scopes: string[]; created_at: number }>> {
    const prefix = `consent:${identityId}:`
    const consents = await this.storage.list<ConsentRecord>({ prefix })
    const out: Array<{ client_id: string; scopes: string[]; created_at: number }> = []
    for (const [key, rec] of consents) out.push({ client_id: key.slice(prefix.length), scopes: rec.scopes, created_at: rec.createdAt })
    return out
  }

  /**
   * Revoke everything a Person delegated to one client: the consent record
   * (the next authorization asks again), every refresh token of every grant
   * (so the client cannot mint new access tokens), opaque access tokens
   * (deleted) and JWT access tokens (inactive at introspection; at a resource
   * server verifying locally, expired within ACCESS_TOKEN_JWT_TTL).
   */
  async revokeGrant(identityId: string, clientId: string): Promise<{ revoked_families: number }> {
    // The tombstone first: from here on every code, refresh token, access
    // token and exchange from a grant made up to now is refused at use
    // (isTokenRevoked), including tokens made before the family index existed
    // and tokens a racing rotation is writing right now.
    await this.storage.put(grantRevokedKey(identityId, clientId), { at: Date.now() })
    await this.storage.delete(`consent:${identityId}:${clientId}`)
    // Then tidy what the index knows about (opaque access tokens deleted, JWT
    // records and refresh tokens marked), so the records say so too.
    const families = new Set<string>()
    const prefix = grantIndexPrefix(identityId, clientId)
    for (const key of (await this.storage.list<unknown>({ prefix })).keys()) families.add(key.slice(prefix.length))
    for (const family of families) await this.revokeIndexedFamilyTokens(family)
    return { revoked_families: families.size }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Token Exchange (RFC 8693) — for api.sb's agents, via the AuthService binding
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Exchange a Person's access token for api.sb plus an agent identity for a
   * narrower access token that names the agent: `sub` stays the Person,
   * `act.sub` is the agent (RFC 8693 §4.1; an `act` already on the subject
   * token is nested under it), `client_id` stays the client the Person
   * delegated to, `aud` is an api.sb resource.
   *
   * Reachable only through the AuthService RPC binding (no HTTP route): the
   * calling Worker is authenticated by the binding and asserts the actor.
   * The result can only narrow the subject token (same Person, same client,
   * api.sb audience, a subset of its scopes, never past its expiry), carries
   * no refresh token, and dies with the Person's grant.
   */
  async exchangeToken(input: {
    subject_token?: unknown
    subject_token_type?: unknown
    requested_token_type?: unknown
    actor?: unknown
    resource?: unknown
    scope?: unknown
  }): Promise<
    | { ok: true; access_token: string; issued_token_type: string; token_type: 'Bearer'; expires_in: number; scope: string }
    | { ok: false; error: string; error_description: string }
  > {
    const fail = (error: string, error_description: string) => ({ ok: false as const, error, error_description })
    const ACCESS = 'urn:ietf:params:oauth:token-type:access_token'
    if (!this.signingKeyManager) return fail('server_error', 'token exchange needs a signing key')
    if (input.subject_token_type !== ACCESS) return fail('invalid_request', `subject_token_type must be ${ACCESS}`)
    if (input.requested_token_type !== undefined && input.requested_token_type !== ACCESS) {
      return fail('invalid_request', `requested_token_type must be ${ACCESS}`)
    }
    const actorSub = input.actor && typeof input.actor === 'object' ? (input.actor as { sub?: unknown }).sub : undefined
    if (typeof actorSub !== 'string' || !/^[\x21-\x7e]{1,256}$/.test(actorSub)) {
      return fail('invalid_request', 'actor.sub must be 1-256 visible ASCII characters')
    }
    if (typeof input.subject_token !== 'string' || input.subject_token === '') return fail('invalid_request', 'subject_token is required')
    const subjectToken = input.subject_token

    // ── The subject: a live access token of a Person, for api.sb ─────────
    let subject: { identityId: string; clientId: string; scopes: string[]; resource?: string; family?: string; act?: ActorClaim; issuer: string; expiresAt: number; grantedAt: number } | null = null
    if (subjectToken.startsWith('at_')) {
      const rec = await this.storage.get<AccessToken>(`access:${subjectToken}`)
      if (rec && rec.identityId && rec.expiresAt > Date.now() && !(await this.isTokenRevoked(rec))) {
        subject = { identityId: rec.identityId, clientId: rec.clientId, scopes: rec.scopes, resource: rec.resource, family: rec.family, issuer: this.config.issuer, expiresAt: rec.expiresAt, grantedAt: rec.grantedAt ?? rec.createdAt }
      }
    } else {
      const rec = await this.verifyAccessTokenJwt(subjectToken)
      if (rec) subject = { identityId: rec.identityId, clientId: rec.clientId, scopes: rec.scopes, resource: rec.resource, family: rec.family, act: rec.act, issuer: rec.issuer, expiresAt: rec.expiresAt, grantedAt: rec.grantedAt ?? rec.createdAt }
    }
    if (!subject) return fail('invalid_grant', 'subject_token is not an active id.org.ai access token')
    if (subject.resource === undefined || !isSbResource(subject.resource)) {
      return fail('invalid_target', `only an access token for api.sb (${SB_RESOURCES.join(' or ')}) can be exchanged`)
    }

    // ── What the new token may say ─────────────────────────────────────────
    const target = parseResourceIndicators([typeof input.resource === 'string' ? input.resource : undefined])
    if (!target.ok) return fail('invalid_target', target.description)
    // The subject's own audience, or the one narrowing the token endpoint
    // allows (https://api.sb → https://api.sb/mcp); never sideways or wider.
    const resource = target.resource ?? subject.resource
    const narrows = sameResource(subject.resource, DEFAULT_SB_RESOURCE) && resource === 'https://api.sb/mcp'
    if (!sameResource(resource, subject.resource) && !narrows) {
      return fail('invalid_target', `the subject token is for ${subject.resource}; an exchange may keep it or narrow https://api.sb to https://api.sb/mcp`)
    }
    const scopes = typeof input.scope === 'string' ? splitScopes(input.scope) : subject.scopes
    if (scopes.length === 0) return fail('invalid_scope', 'no scope requested')
    const extra = scopes.filter((sc) => !subject!.scopes.includes(sc))
    if (extra.length > 0) return fail('invalid_scope', `the subject token does not hold: ${extra.join(', ')}`)

    let depth = 0
    for (let a: ActorClaim | undefined = subject.act; a; a = a.act) depth++
    if (depth >= 4) return fail('invalid_request', 'delegation chain too long')
    const act: ActorClaim = { sub: actorSub, ...(subject.act && { act: subject.act }) }

    let minted: { token: string; expiresIn: number }
    try {
      minted = await this.mintAccessTokenJwt({
        clientId: subject.clientId,
        identityId: subject.identityId,
        scopes,
        resource,
        family: subject.family,
        issuer: subject.issuer,
        act,
        notAfter: subject.expiresAt,
        grantedAt: subject.grantedAt,
      })
    } catch (err) {
      return fail('invalid_grant', err instanceof Error ? err.message : 'could not issue the token')
    }
    return { ok: true, access_token: minted.token, issued_token_type: ACCESS, token_type: 'Bearer', expires_in: minted.expiresIn, scope: scopes.join(' ') }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE: Error Redirect
  // ═══════════════════════════════════════════════════════════════════════════

  private redirectError(
    redirectUri: string,
    error: string,
    description: string,
    state: string | undefined,
    iss: string,
  ): Response {
    const url = new URL(redirectUri)
    url.searchParams.set('error', error)
    url.searchParams.set('error_description', description)
    if (state) {
      url.searchParams.set('state', state)
    }
    // RFC 9207 §2: error responses carry `iss` too.
    url.searchParams.set('iss', iss)
    return Response.redirect(url.toString(), 302)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE: Consent Page
  // ═══════════════════════════════════════════════════════════════════════════

  private renderConsentPage(
    client: OAuthProviderClient,
    params: {
      clientId: string
      redirectUri: string
      scope: string
      state?: string
      codeChallenge?: string
      codeChallengeMethod?: string
      nonce?: string
      resource?: string
    },
  ): Response {
    const esc = (v: string) => this.escapeHtml(v)
    const scopes = splitScopes(params.scope)
    const delegatesDo = scopes.includes(SB_SCOPE_DO)
    // Every scope string is escaped: a registered client chooses its own
    // scope names, and this page is served from id.org.ai's origin.
    const scopeItems = scopes
      .map((s) => {
        const text = esc(SCOPE_DESCRIPTIONS[s] ?? s)
        if (s === SB_SCOPE_DO) return `<div class="scope write">${text}<div class="note">Changes are made in your name. Choose “Allow read only” to keep api.sb read-only.</div></div>`
        return `<div class="scope">${text}</div>`
      })
      .join('\n        ')

    // Name where the answer goes and which resource the access is for, from
    // values id.org.ai checked (the registered redirect_uri, the RFC 8707
    // resource), not from the client's self-chosen name.
    const hostOf = (u: string) => {
      try {
        return new URL(u).host
      } catch {
        return u
      }
    }
    const returnsTo = hostOf(params.redirectUri)
    const audience = params.resource ? hostOf(params.resource) : undefined
    // A CIMD client is named by the host of its client_id URL (which id.org.ai
    // fetched it from); the document's client_name is only what it calls itself.
    const cimd = looksLikeCimdClientId(client.id)
    const appName = cimd ? hostOf(client.id) : client.name

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Authorize ${esc(appName)} - id.org.ai</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 420px; margin: 60px auto; padding: 24px; color: #111; }
    h1 { font-size: 1.25rem; font-weight: 600; margin-bottom: 8px; }
    .subtitle { color: #666; margin-bottom: 24px; }
    .app { display: flex; align-items: center; gap: 12px; padding: 16px; background: #f9f9f9; border-radius: 12px; margin-bottom: 24px; }
    .app img { width: 40px; height: 40px; border-radius: 8px; }
    .app-name { font-weight: 600; }
    .app-url { font-size: 0.875rem; color: #666; }
    .scopes { margin-bottom: 24px; }
    .scope { padding: 10px 0; border-bottom: 1px solid #eee; font-size: 0.9375rem; }
    .scope:last-child { border-bottom: none; }
    .scope.write { font-weight: 600; }
    .note { font-weight: 400; font-size: 0.8125rem; color: #8a4b00; margin-top: 4px; }
    .buttons { display: flex; gap: 12px; flex-wrap: wrap; }
    button { flex: 1; padding: 12px 16px; border: none; border-radius: 10px; font-size: 1rem; font-weight: 500; cursor: pointer; transition: opacity 0.15s; }
    button:hover { opacity: 0.85; }
    .allow { background: #111; color: #fff; }
    .deny { background: #f0f0f0; color: #333; }
    .read { background: #e8eefc; color: #123; }
  </style>
</head>
<body>
  <h1>Authorize application</h1>
  <p class="subtitle">Grant access to your id.org.ai account</p>
  <div class="app">
    ${client.logo ? `<img src="${esc(client.logo)}" alt="">` : ''}
    <div>
      <div class="app-name">${esc(appName)}</div>
      ${cimd ? `<div class="app-url">Calls itself “${esc(client.name)}” · ${esc(client.id)}</div>` : ''}
      ${client.website && !cimd ? `<div class="app-url">${esc(client.website)}</div>` : ''}
      <div class="app-url">Returns to ${esc(returnsTo)}</div>
      ${audience ? `<div class="app-url">Access for ${esc(audience)}</div>` : ''}
    </div>
  </div>
  <div class="scopes">
    ${scopeItems}
  </div>
  <form method="POST" action="/oauth/authorize">
    <input type="hidden" name="client_id" value="${esc(params.clientId)}">
    <input type="hidden" name="redirect_uri" value="${esc(params.redirectUri)}">
    <input type="hidden" name="scope" value="${esc(params.scope)}">
    ${params.state ? `<input type="hidden" name="state" value="${esc(params.state)}">` : ''}
    ${params.codeChallenge ? `<input type="hidden" name="code_challenge" value="${esc(params.codeChallenge)}">` : ''}
    ${params.codeChallengeMethod ? `<input type="hidden" name="code_challenge_method" value="${esc(params.codeChallengeMethod)}">` : ''}
    ${params.nonce ? `<input type="hidden" name="nonce" value="${esc(params.nonce)}">` : ''}
    ${params.resource ? `<input type="hidden" name="resource" value="${esc(params.resource)}">` : ''}
    <div class="buttons">
      <button type="submit" name="approved" value="false" class="deny">Deny</button>
      ${delegatesDo ? '<button type="submit" name="approved" value="read" class="read">Allow read only</button>' : ''}
      <button type="submit" name="approved" value="true" class="allow">Allow</button>
    </div>
  </form>
</body>
</html>`

    return new Response(html, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        // The consent screen must not be framed: a framed "Allow" button can be
        // clicked by a Person who never saw what it grants (clickjacking).
        'X-Frame-Options': 'DENY',
        'Content-Security-Policy': "frame-ancestors 'none'",
        'Cache-Control': 'no-store',
      },
    })
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE: Device Verification Page
  // ═══════════════════════════════════════════════════════════════════════════

  private renderDeviceVerificationPage(userCode: string, error?: string): Response {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Device Authorization - id.org.ai</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 420px; margin: 60px auto; padding: 24px; color: #111; }
    h1 { font-size: 1.25rem; font-weight: 600; margin-bottom: 8px; }
    .subtitle { color: #666; margin-bottom: 24px; }
    .error { background: #fee; color: #c00; padding: 12px; border-radius: 8px; margin-bottom: 16px; font-size: 0.875rem; }
    label { display: block; font-weight: 500; margin-bottom: 8px; }
    input[type="text"] {
      width: 100%; padding: 14px 16px; font-size: 1.5rem; font-family: monospace;
      text-align: center; letter-spacing: 0.25em; text-transform: uppercase;
      border: 2px solid #ddd; border-radius: 10px; outline: none; transition: border-color 0.15s;
    }
    input[type="text"]:focus { border-color: #111; }
    .buttons { display: flex; gap: 12px; margin-top: 20px; }
    button { flex: 1; padding: 12px 16px; border: none; border-radius: 10px; font-size: 1rem; font-weight: 500; cursor: pointer; transition: opacity 0.15s; }
    button:hover { opacity: 0.85; }
    .allow { background: #111; color: #fff; }
    .deny { background: #f0f0f0; color: #333; }
  </style>
</head>
<body>
  <h1>Authorize Device</h1>
  <p class="subtitle">Enter the code shown on your device or agent</p>
  ${error ? `<div class="error">${this.escapeHtml(error)}</div>` : ''}
  <form method="POST" action="/device">
    <label for="user_code">Device Code</label>
    <input type="text" id="user_code" name="user_code" maxlength="8" autocomplete="off" autofocus
      value="${this.escapeHtml(userCode)}" placeholder="ABCD1234">
    <div class="buttons">
      <button type="submit" name="approved" value="false" class="deny">Deny</button>
      <button type="submit" name="approved" value="true" class="allow">Authorize</button>
    </div>
  </form>
</body>
</html>`

    return new Response(html, {
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    })
  }

  private deviceApprovedHtml(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Device Authorized - id.org.ai</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 420px; margin: 60px auto; padding: 24px; color: #111; text-align: center; }
    h1 { font-size: 1.25rem; font-weight: 600; margin-bottom: 8px; }
    .check { font-size: 3rem; margin-bottom: 16px; }
    .subtitle { color: #666; }
  </style>
</head>
<body>
  <div class="check">&#10003;</div>
  <h1>Device Authorized</h1>
  <p class="subtitle">You can close this window and return to your device or agent.</p>
</body>
</html>`
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE: HTML Escaping
  // ═══════════════════════════════════════════════════════════════════════════

  private escapeHtml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
  }
}
