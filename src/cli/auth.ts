/**
 * Auth API calls for id.org.ai CLI
 */

import { CANONICAL_API_ORIGIN } from '../auth/index.js'
import type { TokenStorage, StoredTokenData } from './storage.js'

const API_BASE = process.env.ID_ORG_AI_URL || CANONICAL_API_ORIGIN
const CLIENT_ID = process.env.ID_ORG_AI_CLIENT_ID || 'id_org_ai_cli'

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
 * Get the current authenticated user by verifying the token.
 */
export async function getUser(token: string): Promise<AuthResult> {
  try {
    const response = await fetch(`${API_BASE}/oauth/userinfo`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
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

/**
 * Refresh an access token using a refresh token.
 * Calls POST /oauth/token with grant_type=refresh_token.
 * Returns new token data or null if refresh failed.
 */
export async function refreshAccessToken(refreshToken: string): Promise<StoredTokenData | null> {
  try {
    const response = await fetch(`${API_BASE}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: CLIENT_ID,
      }).toString(),
    })

    if (!response.ok) return null

    const data = (await response.json()) as {
      access_token: string
      refresh_token?: string
      expires_in?: number
    }

    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token || refreshToken,
      expiresAt: data.expires_in ? Date.now() + data.expires_in * 1000 : undefined,
    }
  } catch {
    return null
  }
}

/**
 * Ensure we have a valid access token, refreshing if needed.
 * Returns the access token or null if no valid token is available.
 *
 * Auto-refreshes when:
 * - Token is expired
 * - Token expires within REFRESH_BUFFER_MS (30 seconds)
 */
export async function ensureValidToken(storage: TokenStorage): Promise<string | null> {
  const tokenData = await storage.getTokenData()
  if (!tokenData?.accessToken) return null

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
async function revokeToken(token: string, tokenTypeHint?: 'access_token' | 'refresh_token'): Promise<void> {
  try {
    await fetch(`${API_BASE}/oauth/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
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
export async function logout(accessToken: string, refreshToken?: string): Promise<void> {
  await Promise.all([
    revokeToken(accessToken, 'access_token'),
    refreshToken ? revokeToken(refreshToken, 'refresh_token') : Promise.resolve(),
  ])
}
