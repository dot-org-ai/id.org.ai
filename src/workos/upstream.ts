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

export interface WorkOSIdentity {
  type: string
  provider: string
  idp_id: string
}

export interface WorkOSUser {
  id: string
  email: string
  first_name?: string
  last_name?: string
  organization_id?: string
  role?: string
  roles?: string[]
  permissions?: string[]
  identities?: WorkOSIdentity[]
}

export interface WorkOSAuthResult {
  access_token: string
  refresh_token?: string
  expires_in?: number
  user: WorkOSUser
  organization_id?: string
}

export interface OrgSelectionError extends Error {
  code: 'organization_selection_required'
  pendingAuthenticationToken: string
  organizations: Array<{ id: string; name: string }>
  user: { id: string; email: string; first_name?: string; last_name?: string }
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
    const errorBody = await response.text()

    // Handle organization_selection_required — user belongs to multiple orgs.
    // Parse the error and throw a typed error so the caller can render an org picker.
    try {
      const parsed = JSON.parse(errorBody)
      if (parsed.code === 'organization_selection_required' && parsed.pending_authentication_token && parsed.organizations?.length) {
        const err = new Error('organization_selection_required') as OrgSelectionError
        err.code = 'organization_selection_required'
        err.pendingAuthenticationToken = parsed.pending_authentication_token
        err.organizations = parsed.organizations
        err.user = parsed.user
        throw err
      }
    } catch (e) {
      if (e instanceof Error && (e as any).code === 'organization_selection_required') throw e
    }

    throw new Error(`WorkOS authentication failed: ${response.status} - ${errorBody}`)
  }

  const data = (await response.json()) as WorkOSAuthResult
  return extractRolesFromToken(data, clientId, apiKey)
}

function extractRolesFromToken(data: WorkOSAuthResult, _clientId: string, _apiKey: string): WorkOSAuthResult {
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

/**
 * Exchange a refresh token for a fresh access token.
 *
 * @param clientId - WorkOS client ID
 * @param apiKey - WorkOS API key (the client secret)
 * @param refreshToken - The refresh token to exchange
 * @param organizationId - Optional organization ID to scope the new token
 */
export async function refreshWorkOSAccessToken(
  clientId: string,
  apiKey: string,
  refreshToken: string,
  organizationId?: string,
): Promise<WorkOSAuthResult> {
  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: clientId,
    client_secret: apiKey,
    refresh_token: refreshToken,
  })
  if (organizationId) params.set('organization_id', organizationId)

  const response = await fetch('https://api.workos.com/user_management/authenticate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  })

  if (!response.ok) {
    const errorBody = await response.text()
    throw new Error(`WorkOS token refresh failed: ${response.status} - ${errorBody}`)
  }

  return (await response.json()) as WorkOSAuthResult
}

/**
 * Complete authentication after org selection.
 * Uses the pending_authentication_token + chosen org ID.
 */
export async function exchangeWorkOSOrgSelection(
  clientId: string,
  apiKey: string,
  pendingAuthenticationToken: string,
  organizationId: string,
): Promise<WorkOSAuthResult> {
  const response = await fetch('https://api.workos.com/user_management/authenticate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:workos:oauth:grant-type:organization-selection',
      client_id: clientId,
      client_secret: apiKey,
      pending_authentication_token: pendingAuthenticationToken,
      organization_id: organizationId,
    }).toString(),
  })

  if (!response.ok) {
    const error = await response.text()
    throw new Error(`WorkOS org selection failed: ${response.status} - ${error}`)
  }

  const data = (await response.json()) as WorkOSAuthResult
  if (!data.organization_id) data.organization_id = organizationId
  return extractRolesFromToken(data, clientId, apiKey)
}

// ============================================================================
// Fetch Full User Profile (includes linked identities)
// ============================================================================

/**
 * Fetch a WorkOS user's full profile including linked identities.
 * The identities array contains provider-specific IDs (e.g. GitHub numeric ID).
 *
 * @param apiKey - WorkOS API key
 * @param userId - WorkOS user ID (from auth result)
 * @returns WorkOS user with identities, or null on failure
 */
export async function fetchWorkOSUser(apiKey: string, userId: string): Promise<WorkOSUser | null> {
  try {
    const response = await fetch(`https://api.workos.com/user_management/users/${userId}`, {
      headers: { Authorization: `Bearer ${apiKey}` },
    })
    if (!response.ok) return null
    return (await response.json()) as WorkOSUser
  } catch {
    return null
  }
}

/**
 * Extract the GitHub numeric user ID from a WorkOS user's identities.
 * Returns the idp_id for the GitHubOAuth identity, or null if not linked.
 */
export function extractGitHubId(user: WorkOSUser): string | null {
  const github = user.identities?.find((i) => i.provider === 'GitHubOAuth')
  return github?.idp_id ?? null
}

// ============================================================================
// Fetch GitHub Username (public API, no auth needed)
// ============================================================================

/**
 * Fetch a GitHub user's login (username) from their numeric user ID.
 * Uses the public GitHub API — no authentication required.
 *
 * @param githubId - GitHub numeric user ID (from WorkOS identity)
 * @returns GitHub username (login), or null on failure
 */
export async function fetchGitHubUsername(githubId: string): Promise<string | null> {
  try {
    const res = await fetch(`https://api.github.com/user/${githubId}`, {
      headers: { 'User-Agent': 'id.org.ai', Accept: 'application/json' },
    })
    if (!res.ok) return null
    const data = (await res.json()) as { login?: string }
    return data.login ?? null
  } catch {
    return null
  }
}

// ============================================================================
// Fetch Organization (includes domains)
// ============================================================================

export interface WorkOSOrganization {
  id: string
  name: string
  external_id?: string
  metadata?: Record<string, string>
  domains?: Array<{ domain: string; state: string }>
}

export interface OrgInfo {
  name: string
  domains: string[]
}

/**
 * Fetch a WorkOS organization's name and verified domains.
 * Domains are the namespace in our data model — they define tenant context.
 *
 * @param apiKey - WorkOS API key
 * @param orgId - WorkOS organization ID
 * @returns Org name + verified domain strings, or null on failure
 */
export async function fetchOrgInfo(apiKey: string, orgId: string): Promise<OrgInfo | null> {
  try {
    const response = await fetch(`https://api.workos.com/organizations/${orgId}`, {
      headers: { Authorization: `Bearer ${apiKey}` },
    })
    if (!response.ok) return null
    const org = (await response.json()) as WorkOSOrganization
    return {
      name: org.name,
      domains: (org.domains ?? []).filter((d) => d.state === 'verified').map((d) => d.domain),
    }
  } catch {
    return null
  }
}

// ============================================================================
// Create Organization + Membership (personal org for every user)
// ============================================================================

/**
 * Create a WorkOS organization.
 *
 * @param apiKey - WorkOS API key
 * @param name - Organization name (e.g. "Nathan Clevenger")
 * @param options - Optional: external_id, metadata
 * @returns The created organization, or null on failure
 */
export async function createWorkOSOrganization(
  apiKey: string,
  name: string,
  options?: { external_id?: string; metadata?: Record<string, string> },
): Promise<WorkOSOrganization | null> {
  try {
    const body: Record<string, unknown> = { name }
    if (options?.external_id) body.external_id = options.external_id
    if (options?.metadata) body.metadata = options.metadata

    const response = await fetch('https://api.workos.com/organizations', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    })
    if (!response.ok) {
      const errorBody = await response.text().catch(() => '')
      console.error(`[createWorkOSOrganization] ${response.status} for "${name}":`, errorBody)
      return null
    }
    return (await response.json()) as WorkOSOrganization
  } catch (err) {
    console.error('[createWorkOSOrganization] exception:', err)
    return null
  }
}

/**
 * Add a user to a WorkOS organization with a given role.
 *
 * @param apiKey - WorkOS API key
 * @param userId - WorkOS user ID
 * @param organizationId - WorkOS organization ID
 * @param roleSlug - Role slug (default: 'admin' for personal orgs)
 * @returns true if membership was created
 */
export async function createWorkOSMembership(
  apiKey: string,
  userId: string,
  organizationId: string,
  roleSlug = 'admin',
): Promise<boolean> {
  try {
    const response = await fetch('https://api.workos.com/user_management/organization_memberships', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        user_id: userId,
        organization_id: organizationId,
        role_slug: roleSlug,
      }),
    })
    if (!response.ok) {
      const errorBody = await response.text().catch(() => '')
      console.error(`[createWorkOSMembership] ${response.status} for user=${userId} org=${organizationId}:`, errorBody)
    }
    return response.ok
  } catch (err) {
    console.error('[createWorkOSMembership] exception:', err)
    return false
  }
}

/**
 * Ensure a user has a personal organization in WorkOS.
 * If they don't have an org, creates one named after them and adds them as admin.
 *
 * @param apiKey - WorkOS API key
 * @param userId - WorkOS user ID
 * @param userName - User's display name (for the org name)
 * @param userEmail - User's email (fallback for org name)
 * @returns The org ID (existing or newly created), or null on failure
 */
export async function ensurePersonalOrg(
  apiKey: string,
  userId: string,
  userName: string | undefined,
  userEmail: string,
): Promise<{ orgId: string; created: boolean } | null> {
  // Check if user already has org memberships
  try {
    const response = await fetch(`https://api.workos.com/user_management/organization_memberships?user_id=${userId}&limit=1`, {
      headers: { Authorization: `Bearer ${apiKey}` },
    })
    if (response.ok) {
      const data = (await response.json()) as { data: Array<{ organization_id: string }> }
      if (data.data.length > 0) {
        return { orgId: data.data[0]!.organization_id, created: false }
      }
    } else {
      console.error(`[ensurePersonalOrg] membership check failed: ${response.status}`, await response.text().catch(() => ''))
    }
  } catch (err) {
    console.error('[ensurePersonalOrg] membership check exception:', err)
    // Continue to create
  }

  // No existing org — create a personal one
  const orgName = userName || userEmail.split('@')[0] || 'Personal'
  const org = await createWorkOSOrganization(apiKey, orgName, {
    metadata: { type: 'personal', owner: userId },
  })
  if (!org) {
    console.error(`[ensurePersonalOrg] failed to create org for user=${userId} name="${orgName}"`)
    return null
  }

  // Add user as admin of their personal org
  const added = await createWorkOSMembership(apiKey, userId, org.id, 'admin')
  if (!added) {
    console.error(`[ensurePersonalOrg] failed to add membership for user=${userId} org=${org.id}`)
    return null
  }

  return { orgId: org.id, created: true }
}

// ============================================================================
// Update WorkOS User (external_id, metadata)
// ============================================================================

/**
 * Update a WorkOS user's external_id and/or metadata.
 * Use this to persist the GitHub numeric ID on the WorkOS side so it's
 * available in JWT templates ({{ user.external_id }}) and searchable
 * in the WorkOS dashboard.
 *
 * @param apiKey - WorkOS API key
 * @param userId - WorkOS user ID
 * @param updates - Fields to update (external_id, metadata, etc.)
 * @returns true if update succeeded
 */
export async function updateWorkOSUser(
  apiKey: string,
  userId: string,
  updates: { external_id?: string; metadata?: Record<string, string> },
): Promise<boolean> {
  try {
    const response = await fetch(`https://api.workos.com/user_management/users/${userId}`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(updates),
    })
    return response.ok
  } catch {
    return false
  }
}

// ============================================================================
// List Organization Memberships
// ============================================================================

export interface WorkOSOrganizationMembership {
  id: string
  user_id: string
  organization_id: string
  role: { slug: string }
  status: string
  created_at: string
  updated_at: string
}

/**
 * List a user's organization memberships in WorkOS.
 *
 * @param apiKey - WorkOS API key
 * @param userId - WorkOS user ID
 * @returns Array of org memberships, or empty array on failure
 */
export async function listUserOrgMemberships(
  apiKey: string,
  userId: string,
): Promise<WorkOSOrganizationMembership[]> {
  try {
    const response = await fetch(`https://api.workos.com/user_management/organization_memberships?user_id=${userId}&limit=100`, {
      headers: { Authorization: `Bearer ${apiKey}` },
    })
    if (!response.ok) return []
    const data = (await response.json()) as { data: WorkOSOrganizationMembership[] }
    return data.data
  } catch {
    return []
  }
}

/**
 * List members of a WorkOS organization.
 *
 * @param apiKey - WorkOS API key
 * @param organizationId - WorkOS organization ID
 * @returns Array of org memberships, or empty array on failure
 */
export async function listOrgMembers(
  apiKey: string,
  organizationId: string,
): Promise<WorkOSOrganizationMembership[]> {
  try {
    const response = await fetch(`https://api.workos.com/user_management/organization_memberships?organization_id=${organizationId}&limit=100`, {
      headers: { Authorization: `Bearer ${apiKey}` },
    })
    if (!response.ok) return []
    const data = (await response.json()) as { data: WorkOSOrganizationMembership[] }
    return data.data
  } catch {
    return []
  }
}

/**
 * Send an invitation to join a WorkOS organization.
 *
 * @param apiKey - WorkOS API key
 * @param email - Email to invite
 * @param organizationId - WorkOS organization ID
 * @param roleSlug - Role slug (default: 'member')
 * @returns true if invitation was sent
 */
export async function sendOrgInvitation(
  apiKey: string,
  email: string,
  organizationId: string,
  roleSlug = 'member',
): Promise<boolean> {
  try {
    const response = await fetch('https://api.workos.com/user_management/invitations', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email,
        organization_id: organizationId,
        role_slug: roleSlug,
      }),
    })
    return response.ok
  } catch {
    return false
  }
}

// ============================================================================
// State Encoding (CSRF + continue URL)
// ============================================================================

/**
 * Encode a state parameter with a CSRF token and optional continue URL.
 * Format: base64url({ csrf, continue })
 */
export function encodeLoginState(csrf: string, continueUrl?: string, origin?: string): string {
  const payload = JSON.stringify({ csrf, continue: continueUrl, origin })
  return btoa(payload).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

/**
 * Decode a state parameter back to its components.
 */
export function decodeLoginState(state: string): { csrf: string; continue?: string; origin?: string } | null {
  try {
    const padded = state.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - (state.length % 4)) % 4)
    const payload = JSON.parse(atob(padded))
    if (!payload.csrf) return null
    return { csrf: payload.csrf, continue: payload.continue, origin: payload.origin }
  } catch {
    return null
  }
}
