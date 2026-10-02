/**
 * Auth API calls for id.org.ai CLI
 */

import { CANONICAL_API_ORIGIN } from '../auth/index.js'
import type { TokenStorage, StoredTokenData } from './storage.js'
import { cleanText, parseToken } from './untrusted.js'

const API_BASE = process.env.ID_ORG_AI_URL || CANONICAL_API_ORIGIN
const CLIENT_ID = process.env.ID_ORG_AI_CLIENT_ID || 'id_org_ai_cli'

/** Buffer before expiry to trigger refresh (30 seconds) */
const REFRESH_BUFFER_MS = 30_000

export interface User {
  id: string
  email?: string
  name?: string
  organizationId?: string
  /** The workspace's name, when userinfo carries `org_name`. */
  organizationName?: string
  roles?: string[]
  permissions?: string[]
}

export interface AuthResult {
  user: User | null
  token?: string
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

    // Every field is printed (login, whoami, status), and the server's text is
    // not trusted: a workspace name is whatever its owner typed. Cleaned here,
    // where it comes in (see untrusted.ts); a field that isn't a string is dropped.
    const data = (await response.json()) as Record<string, unknown>
    const user: User = {
      id: cleanText(data.sub) || cleanText(data.id),
      email: cleanText(data.email) || undefined,
      name: cleanText(data.name) || undefined,
      organizationId: cleanText(data.org_id) || undefined,
      organizationName: cleanText(data.org_name) || undefined,
    }
    return { user, token }
  } catch {
    return { user: null }
  }
}

/** What the person reads when a token reply carries a token the CLI won't store. The token is never quoted. */
export const UNUSABLE_TOKEN = "the server sent a token the CLI can't use"

/** A token reply whose access or refresh token isn't made of token characters (see parseToken). */
export class TokenReplyError extends Error {
  constructor() {
    super(UNUSABLE_TOKEN)
    this.name = 'TokenReplyError'
  }
}

/**
 * A token reply (RFC 6749 §5.1) as the CLI stores it, or null when it is a
 * protocol error: the access token and effective refresh token (including a
 * retained legacy value) must be made of token characters only (parseToken). `id.org.ai token`
 * prints the stored access token as is, so nothing else is ever stored.
 * With no refresh token in the reply, `previousRefreshToken` is kept.
 */
export function storedTokenData(reply: unknown, previousRefreshToken?: string): StoredTokenData | null {
  const body = (reply && typeof reply === 'object' ? reply : {}) as Record<string, unknown>
  const accessToken = parseToken(body.access_token)
  if (!accessToken) return null
  let refreshToken = previousRefreshToken
  if (body.refresh_token !== undefined && body.refresh_token !== null && body.refresh_token !== '') {
    const sent = parseToken(body.refresh_token)
    if (!sent) return null
    refreshToken = sent
  }
  if (refreshToken !== undefined && !parseToken(refreshToken)) return null
  const expiresIn = body.expires_in
  return {
    accessToken,
    refreshToken,
    expiresAt: typeof expiresIn === 'number' && Number.isFinite(expiresIn) && expiresIn > 0 ? Date.now() + expiresIn * 1000 : undefined,
  }
}

/**
 * Refresh an access token using a refresh token.
 * Calls POST /oauth/token with grant_type=refresh_token.
 * Returns new token data, or null if the refresh failed (no reply, an error
 * reply, or one that isn't JSON). Throws TokenReplyError when the server
 * answers with a token that isn't one (see storedTokenData): a protocol
 * error, and the value must not be stored.
 */
export async function refreshAccessToken(
  refreshToken: string,
  options?: { clientId?: string; headers?: Record<string, string> },
): Promise<StoredTokenData | null> {
  let data: unknown
  try {
    const response = await fetch(`${API_BASE}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...options?.headers },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: options?.clientId ?? CLIENT_ID,
      }).toString(),
    })

    if (!response.ok) return null
    data = await response.json()
  } catch {
    return null
  }

  const stored = storedTokenData(data, refreshToken)
  if (!stored) throw new TokenReplyError()
  return stored
}

/**
 * Ensure we have a valid access token, refreshing if needed.
 * Returns the access token or null if no valid token is available. A stored
 * token that isn't made of token characters (an older CLI stored whatever the
 * server sent) counts as none: `id.org.ai token` prints what this returns.
 * Throws TokenReplyError when a refresh answers with a token that isn't one.
 *
 * Auto-refreshes when:
 * - Token is expired
 * - Token expires within REFRESH_BUFFER_MS (30 seconds)
 */
export async function ensureValidToken(storage: TokenStorage): Promise<string | null> {
  const tokenData = await storage.getTokenData()
  if (!tokenData?.accessToken || !parseToken(tokenData.accessToken)) return null

  // Check if token is still valid (with 30s buffer)
  const needsRefresh = tokenData.expiresAt && (tokenData.expiresAt - Date.now() < REFRESH_BUFFER_MS)

  if (!needsRefresh) return tokenData.accessToken

  // Try to refresh
  if (tokenData.refreshToken) {
    const refreshed = await refreshAccessToken(tokenData.refreshToken)
    if (refreshed) {
      await storage.setTokenData(refreshed)
      return refreshed.accessToken
    }
  }

  // Refresh failed — return existing token (might still work, let the server decide)
  return tokenData.accessToken
}

/**
 * Revoke a token server-side via the OAuth revocation endpoint (RFC 7009).
 */
async function revokeToken(
  token: string,
  tokenTypeHint?: 'access_token' | 'refresh_token',
  headers?: Record<string, string>,
): Promise<void> {
  try {
    await fetch(`${API_BASE}/oauth/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams({
        token,
        client_id: CLIENT_ID,
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
): Promise<void> {
  await Promise.all([
    revokeToken(accessToken, 'access_token', headers),
    refreshToken ? revokeToken(refreshToken, 'refresh_token', headers) : Promise.resolve(),
  ])
}
