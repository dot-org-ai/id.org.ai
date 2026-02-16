/**
 * WorkOS API Key Validation
 *
 * Validates WorkOS-issued API keys (sk_* prefix) against the
 * WorkOS API key validations endpoint.
 */

// ============================================================================
// Types
// ============================================================================

export interface WorkOSApiKeyResult {
  valid: boolean
  id?: string
  name?: string
  organization_id?: string
  permissions?: string[]
}

// ============================================================================
// Validation
// ============================================================================

/**
 * Validate a WorkOS API key (sk_* prefix) against WorkOS.
 *
 * @param apiKey - The sk_* API key to validate
 * @param workosApiKey - The platform's WorkOS API key (for authenticating the validation call)
 */
export async function validateWorkOSApiKey(
  apiKey: string,
  workosApiKey: string,
): Promise<WorkOSApiKeyResult> {
  if (!apiKey.startsWith('sk_')) {
    return { valid: false }
  }

  try {
    const response = await fetch('https://api.workos.com/api_keys/validations', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${workosApiKey}`,
      },
      body: JSON.stringify({ api_key: apiKey }),
    })

    if (!response.ok) {
      return { valid: false }
    }

    const data = (await response.json()) as {
      id: string
      name: string
      organization_id?: string
      permissions?: string[]
    }

    return {
      valid: true,
      id: data.id,
      name: data.name,
      organization_id: data.organization_id,
      permissions: data.permissions,
    }
  } catch {
    return { valid: false }
  }
}
