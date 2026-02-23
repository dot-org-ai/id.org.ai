/**
 * WorkOS Upstream Authentication
 *
 * Handles the login redirect → WorkOS AuthKit → callback flow.
 * This is the human authentication path — SSO, social login, MFA.
 *
 * Flow:
 *   1. GET /login → redirect to WorkOS AuthKit
 *   2. User authenticates at WorkOS
 *   3. GET /callback?code=...&state=... → exchange code → set cookie → redirect
 */

// ============================================================================
// Types
// ============================================================================

export interface WorkOSUser {
  id: string
  email: string
  first_name?: string
  last_name?: string
  organization_id?: string
  role?: string
  roles?: string[]
  permissions?: string[]
}

export interface WorkOSAuthResult {
  access_token: string
  refresh_token?: string
  expires_in?: number
  user: WorkOSUser
  organization_id?: string
}

// ============================================================================
// Auth URL Builder
// ============================================================================

/**
 * Build the WorkOS AuthKit authorization URL.
 *
 * @param clientId - WorkOS client ID
 * @param redirectUri - Where WorkOS should redirect after auth (e.g. https://id.org.ai/callback)
 * @param state - Opaque state parameter (CSRF + continue URL)
 * @param provider - WorkOS provider (e.g. 'GitHubOAuth', 'GoogleOAuth'). Defaults to 'authkit' (all methods)
 */
export function buildWorkOSAuthUrl(clientId: string, redirectUri: string, state: string, provider?: string): string {
  const url = new URL('https://api.workos.com/user_management/authorize')
  url.searchParams.set('client_id', clientId)
  url.searchParams.set('redirect_uri', redirectUri)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('state', state)
  url.searchParams.set('provider', provider || 'authkit')
  return url.toString()
}

// ============================================================================
// Code Exchange
// ============================================================================

/**
 * Exchange an authorization code with WorkOS for tokens + user info.
 *
 * @param clientId - WorkOS client ID
 * @param apiKey - WorkOS API key (the client secret)
 * @param code - Authorization code from the callback
 */
export async function exchangeWorkOSCode(
  clientId: string,
  apiKey: string,
  code: string,
): Promise<WorkOSAuthResult> {
  const response = await fetch('https://api.workos.com/user_management/authenticate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: clientId,
      client_secret: apiKey,
      code,
    }).toString(),
  })

  if (!response.ok) {
    const error = await response.text()
    throw new Error(`WorkOS authentication failed: ${response.status} - ${error}`)
  }

  const data = (await response.json()) as WorkOSAuthResult

  // Extract roles/permissions/org_id from the WorkOS JWT access_token
  try {
    const parts = data.access_token.split('.')
    if (parts.length === 3) {
      const payload = JSON.parse(atob(parts[1]!.replace(/-/g, '+').replace(/_/g, '/')))
      const role = payload.role as string | undefined
      const roles = payload.roles as string[] | undefined
      const permissions = payload.permissions as string[] | undefined
      const orgId = payload.org_id as string | undefined

      if (role) {
        data.user.role = role
        data.user.roles = roles ? [...roles, role] : [role]
      } else if (roles) {
        data.user.roles = roles
      }
      if (permissions) {
        data.user.permissions = permissions
      }
      // org_id from JWT payload takes precedence over top-level organization_id
      if (orgId) {
        data.user.organization_id = orgId
      }
    }
  } catch {
    // JWT decode failed — continue without roles
  }

  // Propagate top-level organization_id to user if not already set from JWT
  if (data.organization_id && !data.user.organization_id) {
    data.user.organization_id = data.organization_id
  }

  return data
}

// ============================================================================
// State Encoding (CSRF + continue URL)
// ============================================================================

/**
 * Encode a state parameter with a CSRF token and optional continue URL.
 * Format: base64url({ csrf, continue })
 */
export function encodeLoginState(csrf: string, continueUrl?: string): string {
  const payload = JSON.stringify({ csrf, continue: continueUrl })
  return btoa(payload).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

/**
 * Decode a state parameter back to its components.
 */
export function decodeLoginState(state: string): { csrf: string; continue?: string } | null {
  try {
    const padded = state.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - (state.length % 4)) % 4)
    const payload = JSON.parse(atob(padded))
    if (!payload.csrf) return null
    return { csrf: payload.csrf, continue: payload.continue }
  } catch {
    return null
  }
}
