/**
 * Auth API calls for id.org.ai CLI
 */

import {
  CANONICAL_API_ORIGIN,
  ID_ORG_AI_CLI_CLIENT_ID,
  OAUTH_DO_CLI_CLIENT_ID,
  AUTO_DEV_CLI_CLIENT_ID,
  RPC_DO_CLI_CLIENT_ID,
} from '../auth/index.js'
import type { TokenStorage, StoredTokenData } from './storage.js'

const API_BASE = process.env.ID_ORG_AI_URL || CANONICAL_API_ORIGIN
const CLIENT_ID = process.env.ID_ORG_AI_CLIENT_ID || ID_ORG_AI_CLI_CLIENT_ID

/**
 * First-party CLI client ids that share a token file (~/.id.org.ai/token is
 * mirrored to ~/.oauth.do/token). A refresh token is bound to the client that
 * issued it, so when a token file predates `clientId` being recorded we have
 * to probe: the configured id first, then the other known CLIs.
 */
export const KNOWN_CLI_CLIENT_IDS = [ID_ORG_AI_CLI_CLIENT_ID, OAUTH_DO_CLI_CLIENT_ID, AUTO_DEV_CLI_CLIENT_ID, RPC_DO_CLI_CLIENT_ID] as const

/** Buffer before expiry to trigger refresh (30 seconds) */
const REFRESH_BUFFER_MS = 30_000

export interface User {
  id: string
  email?: string
  name?: string
  organizationId?: string
  roles?: string[]
  permissions?: string[]
}

export interface AuthResult {
  user: User | null
  token?: string
}

/**
 * Why a refresh was rejected. `code` is the OAuth error code from the server
 * (`invalid_grant`, `invalid_client`, ...) or `network_error` / `server_error`
 * when no OAuth error body was available.
 */
export interface RefreshFailure {
  code: string
  description?: string
  status?: number
  /** The client_id of the last attempt */
  clientId: string
  /** Every client_id tried, in order */
  triedClientIds: string[]
}

export type RefreshOutcome = { ok: true; data: StoredTokenData } | { ok: false; error: RefreshFailure }

export interface RefreshOptions {
  /** Client the refresh token was issued to. Tried first when set. */
  clientId?: string
  /**
   * Fallback client ids to probe when `clientId` is absent or the server says
   * the token was issued to a different client. Defaults to the configured
   * CLIENT_ID followed by the other known first-party CLI ids.
   */
  fallbackClientIds?: readonly string[]
  headers?: Record<string, string>
  /**
   * When given, the rotated token pair is persisted here as part of the
   * refresh itself — before the result is returned — so a rotation can never
   * be lost to a crash between refresh and save.
   */
  storage?: TokenStorage
}

export type TokenResolutionReason = 'no_token' | 'expired_no_refresh' | 'refresh_failed'

export interface TokenResolution {
  /** A usable access token, or null. Never an expired token. */
  token: string | null
  /** Set when `token` is null */
  reason?: TokenResolutionReason
  /** Set when `reason === 'refresh_failed'` */
  error?: RefreshFailure
  /** Whether the token was obtained by refreshing */
  refreshed?: boolean
}

/**
 * Get the current authenticated user by verifying the token.
 */
export async function getUser(token: string, headers?: Record<string, string>): Promise<AuthResult> {
  try {
    const response = await fetch(`${API_BASE}/oauth/userinfo`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        ...headers,
      },
    })

    if (!response.ok) {
      if (response.status === 401) return { user: null }
      throw new Error(`Authentication failed: ${response.statusText}`)
    }

    const data = (await response.json()) as Record<string, unknown>
    const user: User = {
      id: (data.sub as string) || (data.id as string) || '',
      email: data.email as string | undefined,
      name: data.name as string | undefined,
      organizationId: data.org_id as string | undefined,
    }
    return { user, token }
  } catch {
    return { user: null }
  }
}

/** The server rejected the refresh because a different client issued the token. */
function isWrongClientError(error: RefreshFailure): boolean {
  return error.code === 'invalid_grant' && /not issued to this client/i.test(error.description ?? '')
}

/** Ordered, de-duplicated list of client ids to try for a refresh. */
export function refreshClientIdOrder(options?: Pick<RefreshOptions, 'clientId' | 'fallbackClientIds'>): string[] {
  const fallbacks = options?.fallbackClientIds ?? [CLIENT_ID, ...KNOWN_CLI_CLIENT_IDS]
  const ordered = options?.clientId ? [options.clientId, ...fallbacks] : [...fallbacks]
  return ordered.filter((id, i) => id && ordered.indexOf(id) === i)
}

async function refreshOnce(
  refreshToken: string,
  clientId: string,
  headers?: Record<string, string>,
): Promise<{ ok: true; data: StoredTokenData } | { ok: false; code: string; description?: string; status?: number }> {
  let response: Response
  try {
    response = await fetch(`${API_BASE}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: clientId,
      }).toString(),
    })
  } catch (err) {
    return { ok: false, code: 'network_error', description: err instanceof Error ? err.message : String(err) }
  }

  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as { error?: string; error_description?: string }
    return {
      ok: false,
      code: body.error || (response.status >= 500 ? 'server_error' : 'unknown'),
      description: body.error_description,
      status: response.status,
    }
  }

  const data = (await response.json()) as {
    access_token: string
    refresh_token?: string
    expires_in?: number
  }

  return {
    ok: true,
    data: {
      accessToken: data.access_token,
      // Refresh tokens rotate on use; the old one is revoked server-side.
      refreshToken: data.refresh_token || refreshToken,
      expiresAt: data.expires_in ? Date.now() + data.expires_in * 1000 : undefined,
      clientId,
    },
  }
}

/**
 * Refresh an access token, trying client ids in order until one is accepted.
 *
 * The server binds refresh tokens to their issuing client, so a token written
 * by `auto_dev_cli` cannot be refreshed as `id_org_ai_cli`. Probing stops at
 * the first success, or at the first failure that is NOT a wrong-client
 * rejection (a revoked/expired token is not going to work under another id,
 * and retrying a revoked token would trip replay detection on the family).
 *
 * On success the rotated pair — including the client id that worked — is
 * written to `options.storage` (when given) before returning.
 */
export async function refreshTokens(refreshToken: string, options?: RefreshOptions): Promise<RefreshOutcome> {
  const order = refreshClientIdOrder(options)
  const tried: string[] = []
  let last: RefreshFailure | null = null

  for (const clientId of order) {
    tried.push(clientId)
    const result = await refreshOnce(refreshToken, clientId, options?.headers)

    if (result.ok) {
      if (options?.storage) await options.storage.setTokenData(result.data)
      return { ok: true, data: result.data }
    }

    last = { code: result.code, description: result.description, status: result.status, clientId, triedClientIds: [...tried] }
    if (!isWrongClientError(last)) break
  }

  return { ok: false, error: last ?? { code: 'no_client_id', clientId: '', triedClientIds: tried } }
}

/**
 * Refresh an access token using a refresh token.
 * Calls POST /oauth/token with grant_type=refresh_token.
 * Returns new token data or null if refresh failed.
 *
 * Thin wrapper over {@link refreshTokens}; prefer that when you need the reason.
 */
export async function refreshAccessToken(refreshToken: string, options?: RefreshOptions): Promise<StoredTokenData | null> {
  const outcome = await refreshTokens(refreshToken, options)
  return outcome.ok ? outcome.data : null
}

/**
 * Resolve a usable access token from storage, refreshing when the stored one
 * is expired or within REFRESH_BUFFER_MS (30s) of expiry.
 *
 * Never returns an expired token: when refresh fails the result carries
 * `token: null` plus the reason, so callers can tell the user why.
 */
export async function resolveAccessToken(storage: TokenStorage, headers?: Record<string, string>): Promise<TokenResolution> {
  const tokenData = await storage.getTokenData()
  if (!tokenData?.accessToken) return { token: null, reason: 'no_token' }

  const needsRefresh = !!tokenData.expiresAt && tokenData.expiresAt - Date.now() < REFRESH_BUFFER_MS
  if (!needsRefresh) return { token: tokenData.accessToken }

  if (!tokenData.refreshToken) return { token: null, reason: 'expired_no_refresh' }

  const outcome = await refreshTokens(tokenData.refreshToken, { clientId: tokenData.clientId, headers, storage })
  if (outcome.ok) return { token: outcome.data.accessToken, refreshed: true }

  return { token: null, reason: 'refresh_failed', error: outcome.error }
}

/**
 * Ensure we have a valid access token, refreshing if needed.
 * Returns the access token or null if no valid token is available.
 * See {@link resolveAccessToken} for the failure reason.
 */
export async function ensureValidToken(storage: TokenStorage): Promise<string | null> {
  return (await resolveAccessToken(storage)).token
}

/**
 * One-line, user-facing explanation of why no token could be resolved.
 */
export function describeTokenFailure(resolution: TokenResolution): string {
  switch (resolution.reason) {
    case 'no_token':
      return 'no stored token'
    case 'expired_no_refresh':
      return 'access token expired and no refresh token is stored'
    case 'refresh_failed': {
      const e = resolution.error
      if (!e) return 'refresh rejected'
      const detail = e.description ? `${e.description}` : `${e.code}${e.status ? ` (HTTP ${e.status})` : ''}`
      const clients = e.triedClientIds.length > 1 ? ` [tried client_id ${e.triedClientIds.join(', ')}]` : ` [client_id ${e.clientId}]`
      if (e.code === 'network_error') return `refresh failed: could not reach ${API_BASE} (${e.description ?? 'network error'})`
      return `refresh rejected: ${detail}${clients}`
    }
    default:
      return 'no valid token'
  }
}

/**
 * Revoke a token server-side via the OAuth revocation endpoint (RFC 7009).
 */
async function revokeToken(
  token: string,
  tokenTypeHint?: 'access_token' | 'refresh_token',
  headers?: Record<string, string>,
  clientId: string = CLIENT_ID,
): Promise<void> {
  try {
    await fetch(`${API_BASE}/oauth/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams({
        token,
        client_id: clientId,
        ...(tokenTypeHint ? { token_type_hint: tokenTypeHint } : {}),
      }).toString(),
    })
  } catch {
    // Best-effort — don't fail logout if revocation fails
  }
}

/**
 * Logout: revoke tokens server-side, then clear local storage.
 * Revokes both access and refresh tokens for proper cleanup.
 */
export async function logout(
  accessToken: string,
  refreshToken?: string,
  headers?: Record<string, string>,
  clientId?: string,
): Promise<void> {
  await Promise.all([
    revokeToken(accessToken, 'access_token', headers, clientId),
    refreshToken ? revokeToken(refreshToken, 'refresh_token', headers, clientId) : Promise.resolve(),
  ])
}
