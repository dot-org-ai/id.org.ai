/**
 * WorkOS test user setup for E2E tests.
 *
 * Uses the WorkOS User Management API to ensure test users exist
 * and to create fresh users for specific test scenarios.
 */

const WORKOS_API = 'https://api.workos.com'

interface WorkOSUser {
  id: string
  email: string
  first_name?: string
  last_name?: string
  email_verified: boolean
  created_at: string
}

/**
 * Ensure a test user exists in WorkOS. Creates if not found.
 * Returns the WorkOS user ID.
 */
export async function ensureTestUser(apiKey: string, email: string, password: string): Promise<string> {
  // Check if user already exists
  const listRes = await fetch(`${WORKOS_API}/user_management/users?email=${encodeURIComponent(email)}`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  })

  if (!listRes.ok) {
    throw new Error(`WorkOS list users failed: ${listRes.status} ${await listRes.text()}`)
  }

  const listData = (await listRes.json()) as { data: WorkOSUser[] }
  if (listData.data?.length > 0) {
    return listData.data[0].id
  }

  // Create user with email_verified: true so no verification step needed
  const createRes = await fetch(`${WORKOS_API}/user_management/users`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      email,
      password,
      email_verified: true,
    }),
  })

  if (!createRes.ok) {
    throw new Error(`WorkOS create user failed: ${createRes.status} ${await createRes.text()}`)
  }

  const user = (await createRes.json()) as WorkOSUser
  return user.id
}

/**
 * Delete a WorkOS user (cleanup after tests).
 */
export async function deleteTestUser(apiKey: string, userId: string): Promise<void> {
  const res = await fetch(`${WORKOS_API}/user_management/users/${userId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${apiKey}` },
  })

  if (!res.ok && res.status !== 404) {
    console.warn(`Failed to delete test user ${userId}: ${res.status}`)
  }
}

/**
 * List WorkOS organizations for a user.
 */
export async function listUserOrgs(apiKey: string, userId: string): Promise<Array<{ id: string; name: string }>> {
  const res = await fetch(`${WORKOS_API}/user_management/organization_memberships?user_id=${userId}`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  })

  if (!res.ok) {
    throw new Error(`WorkOS list org memberships failed: ${res.status}`)
  }

  const data = (await res.json()) as { data: Array<{ organization_id: string }> }
  const orgs: Array<{ id: string; name: string }> = []

  for (const membership of data.data) {
    const orgRes = await fetch(`${WORKOS_API}/organizations/${membership.organization_id}`, {
      headers: { Authorization: `Bearer ${apiKey}` },
    })
    if (orgRes.ok) {
      const org = (await orgRes.json()) as { id: string; name: string }
      orgs.push({ id: org.id, name: org.name })
    }
  }

  return orgs
}

/**
 * Remove a user from all organizations (for testing personal org auto-creation).
 */
export async function removeUserFromAllOrgs(apiKey: string, userId: string): Promise<void> {
  const res = await fetch(`${WORKOS_API}/user_management/organization_memberships?user_id=${userId}`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  })

  if (!res.ok) return

  const data = (await res.json()) as { data: Array<{ id: string }> }

  for (const membership of data.data) {
    await fetch(`${WORKOS_API}/user_management/organization_memberships/${membership.id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${apiKey}` },
    })
  }
}
