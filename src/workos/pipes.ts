/**
 * WorkOS Pipes — Managed OAuth Connections
 *
 * Instead of storing bot tokens ourselves (like configSchema.botToken for Slack),
 * WorkOS Pipes handles the OAuth flow, token storage, and automatic refresh.
 *
 * The primary runtime API is getAccessToken(provider, userId, organizationId) —
 * returns a fresh access token for any connected provider.
 *
 * Currently supported providers: GitHub, Slack, Google, Salesforce, Asana, Box,
 * Dropbox, Front, GitLab, HelpScout, HubSpot, Intercom, Sentry.
 *
 * These functions are standalone helpers (not tied to a class) so they
 * can be called from the Hono routes in worker/index.ts without needing
 * to instantiate a WorkerEntrypoint.
 */

const PIPES_BASE = 'https://api.workos.com/pipes/v1'

// ============================================================================
// Types
// ============================================================================

/** Supported Pipes providers */
export const PIPES_PROVIDERS = [
  'github',
  'slack',
  'google',
  'salesforce',
  'asana',
  'box',
  'dropbox',
  'front',
  'gitlab',
  'helpscout',
  'hubspot',
  'intercom',
  'sentry',
] as const

export type PipesProvider = (typeof PIPES_PROVIDERS)[number]

export interface PipesConnection {
  id: string
  provider: PipesProvider
  user_id: string
  organization_id?: string
  status: 'active' | 'needs_reauth' | 'disconnected'
  created_at: string
  updated_at: string
}

export interface PipesAccessToken {
  access_token: string
  token_type: string
  expires_in?: number
  scopes?: string[]
}

// ============================================================================
// Token Management
// ============================================================================

/**
 * Get a fresh access token for a connected provider.
 * WorkOS handles token refresh automatically.
 * This is the primary runtime API — replaces manual token storage.
 *
 * @param apiKey - WorkOS API key
 * @param provider - The provider (e.g., 'slack', 'github')
 * @param userId - The WorkOS user ID
 * @param organizationId - Optional WorkOS organization ID for org-scoped tokens
 */
export async function getAccessToken(
  apiKey: string,
  provider: PipesProvider,
  userId: string,
  organizationId?: string,
): Promise<PipesAccessToken> {
  const body: Record<string, string> = { provider, user_id: userId }
  if (organizationId) body.organization_id = organizationId

  const resp = await fetch(`${PIPES_BASE}/access-tokens`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  })
  if (!resp.ok) {
    const text = await resp.text()
    throw new Error(`Pipes getAccessToken failed: ${resp.status} ${text}`)
  }
  return resp.json() as Promise<PipesAccessToken>
}

// ============================================================================
// Connection Management
// ============================================================================

/**
 * List all connections for a user or organization.
 */
export async function listConnections(
  apiKey: string,
  options?: { userId?: string; organizationId?: string; provider?: PipesProvider; limit?: number; after?: string },
): Promise<{ data: PipesConnection[]; list_metadata: { after?: string } }> {
  const params = new URLSearchParams()
  if (options?.userId) params.set('user_id', options.userId)
  if (options?.organizationId) params.set('organization_id', options.organizationId)
  if (options?.provider) params.set('provider', options.provider)
  if (options?.limit) params.set('limit', String(options.limit))
  if (options?.after) params.set('after', options.after)

  const url = `${PIPES_BASE}/connections${params.toString() ? '?' + params.toString() : ''}`
  const resp = await fetch(url, {
    headers: { Authorization: `Bearer ${apiKey}` },
  })
  if (!resp.ok) {
    const text = await resp.text()
    throw new Error(`Pipes listConnections failed: ${resp.status} ${text}`)
  }
  return resp.json() as Promise<{ data: PipesConnection[]; list_metadata: { after?: string } }>
}

/**
 * Get a specific connection by ID.
 */
export async function getConnection(apiKey: string, connectionId: string): Promise<PipesConnection> {
  const resp = await fetch(`${PIPES_BASE}/connections/${connectionId}`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  })
  if (!resp.ok) {
    const text = await resp.text()
    throw new Error(`Pipes getConnection failed: ${resp.status} ${text}`)
  }
  return resp.json() as Promise<PipesConnection>
}

/**
 * Disconnect (revoke) a connection.
 */
export async function disconnectConnection(apiKey: string, connectionId: string): Promise<void> {
  const resp = await fetch(`${PIPES_BASE}/connections/${connectionId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${apiKey}` },
  })
  if (!resp.ok && resp.status !== 404) {
    const text = await resp.text()
    throw new Error(`Pipes disconnectConnection failed: ${resp.status} ${text}`)
  }
}

// ============================================================================
// Provider-Specific Helpers
// ============================================================================

/**
 * Get a Slack bot token via Pipes.
 * Replaces the manual configSchema.botToken pattern.
 */
export async function getSlackToken(apiKey: string, userId: string, organizationId?: string): Promise<string> {
  const result = await getAccessToken(apiKey, 'slack', userId, organizationId)
  return result.access_token
}

/**
 * Get a GitHub installation token via Pipes.
 * Replaces the manual getInstallationToken() pattern.
 */
export async function getGitHubToken(apiKey: string, userId: string, organizationId?: string): Promise<string> {
  const result = await getAccessToken(apiKey, 'github', userId, organizationId)
  return result.access_token
}

// ============================================================================
// Status Helpers
// ============================================================================

/**
 * Check if a provider connection is active for a user/org.
 * Useful for UI to show connection status.
 */
export async function isProviderConnected(
  apiKey: string,
  provider: PipesProvider,
  userId: string,
  organizationId?: string,
): Promise<boolean> {
  try {
    const connections = await listConnections(apiKey, { userId, organizationId, provider, limit: 1 })
    return connections.data.some((c) => c.status === 'active')
  } catch {
    return false
  }
}

/**
 * Get all active provider connections for a user, grouped by provider.
 * Used by dashboards to show integration status.
 */
export async function getConnectionStatus(
  apiKey: string,
  userId: string,
  organizationId?: string,
): Promise<Record<string, 'active' | 'needs_reauth' | 'disconnected' | 'not_connected'>> {
  const result: Record<string, string> = {}
  for (const provider of PIPES_PROVIDERS) {
    result[provider] = 'not_connected'
  }

  try {
    const connections = await listConnections(apiKey, { userId, organizationId, limit: 100 })
    for (const conn of connections.data) {
      result[conn.provider] = conn.status
    }
  } catch {
    // Return defaults if API fails
  }

  return result as Record<string, 'active' | 'needs_reauth' | 'disconnected' | 'not_connected'>
}
