/**
 * Auth API calls for id.org.ai CLI
 */

const API_BASE = process.env.ID_ORG_AI_URL || 'https://id.org.ai'

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
 * Call the logout endpoint to invalidate the token server-side.
 */
export async function logout(token: string): Promise<void> {
  try {
    await fetch(`${API_BASE}/logout`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    })
  } catch {
    // Ignore errors — local cleanup is enough
  }
}
