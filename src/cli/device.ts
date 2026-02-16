/**
 * OAuth 2.0 Device Authorization Grant (RFC 8628)
 *
 * Uses id.org.ai's own OAuth device flow endpoint.
 */

export interface DeviceAuthorizationResponse {
  device_code: string
  user_code: string
  verification_uri: string
  verification_uri_complete: string
  expires_in: number
  interval: number
}

export interface TokenResponse {
  access_token: string
  token_type: string
  expires_in?: number
  refresh_token?: string
  scope?: string
}

export type TokenError = 'authorization_pending' | 'slow_down' | 'access_denied' | 'expired_token' | 'unknown'

const API_BASE = process.env.ID_ORG_AI_URL || 'https://id.org.ai'

/**
 * Initiate device authorization flow
 */
export async function authorizeDevice(clientId: string): Promise<DeviceAuthorizationResponse> {
  const response = await fetch(`${API_BASE}/oauth/device`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: clientId,
      scope: 'openid profile email',
    }).toString(),
  })

  if (!response.ok) {
    const text = await response.text()
    throw new Error(`Device authorization failed: ${response.status} - ${text}`)
  }

  return (await response.json()) as DeviceAuthorizationResponse
}

/**
 * Poll for tokens after device authorization
 */
export async function pollForTokens(
  clientId: string,
  deviceCode: string,
  interval: number = 5,
  expiresIn: number = 600,
): Promise<TokenResponse> {
  const startTime = Date.now()
  const timeout = expiresIn * 1000
  let currentInterval = interval * 1000

  while (true) {
    if (Date.now() - startTime > timeout) {
      throw new Error('Device authorization expired. Please try again.')
    }

    await new Promise((resolve) => setTimeout(resolve, currentInterval))

    try {
      const response = await fetch(`${API_BASE}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: deviceCode,
          client_id: clientId,
        }).toString(),
      })

      if (response.ok) {
        return (await response.json()) as TokenResponse
      }

      const errorData = (await response.json().catch(() => ({ error: 'unknown' }))) as { error?: string }
      const error = (errorData.error || 'unknown') as TokenError

      switch (error) {
        case 'authorization_pending':
          continue
        case 'slow_down':
          currentInterval += 5000
          continue
        case 'access_denied':
          throw new Error('Access denied by user')
        case 'expired_token':
          throw new Error('Device code expired')
        default:
          throw new Error(`Token polling failed: ${error}`)
      }
    } catch (error) {
      if (error instanceof Error) throw error
      continue
    }
  }
}
