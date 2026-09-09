/**
 * OAuth 2.0 Device Authorization Grant (RFC 8628)
 *
 * Uses id.org.ai's own OAuth device flow endpoint.
 */

import { CANONICAL_API_ORIGIN } from '../auth/index.js'

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

const API_BASE = process.env.ID_ORG_AI_URL || CANONICAL_API_ORIGIN

/**
 * Initiate device authorization flow
 */
export async function authorizeDevice(
  clientId: string,
  headers?: Record<string, string>,
): Promise<DeviceAuthorizationResponse> {
  const response = await fetch(`${API_BASE}/oauth/device`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
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

/** Transient conditions that should NOT abort polling (RFC 8628 §3.5) */
const TRANSIENT_POLL_STATUSES = new Set([408, 425, 429, 500, 502, 503, 504])

/**
 * Poll for tokens after device authorization (RFC 8628 §3.4–3.5).
 *
 * - `authorization_pending` → keep polling at `interval`
 * - `slow_down`             → add 5s to the interval and keep polling
 * - `expired_token`         → the SERVER says the device code expired
 * - network errors / 5xx    → transient; keep polling until our own deadline
 *
 * The local deadline mirrors the server's `expires_in`; hitting it raises
 * "Device authorization expired" (client side), which is distinct from the
 * server-reported "Device code expired" so the two can be told apart.
 */
export async function pollForTokens(
  clientId: string,
  deviceCode: string,
  interval: number = 5,
  expiresIn: number = 600,
  headers?: Record<string, string>,
): Promise<TokenResponse> {
  const startTime = Date.now()
  const timeout = expiresIn * 1000
  let currentInterval = Math.max(1, interval) * 1000
  const elapsed = () => Math.round((Date.now() - startTime) / 1000)

  while (true) {
    if (Date.now() - startTime > timeout) {
      throw new Error(`Device authorization expired after ${elapsed()}s (expires_in was ${expiresIn}s). Please try again.`)
    }

    await new Promise((resolve) => setTimeout(resolve, currentInterval))

    let response: Response
    try {
      response = await fetch(`${API_BASE}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: deviceCode,
          client_id: clientId,
        }).toString(),
      })
    } catch {
      // Network blip — the device code is still valid server-side; keep polling.
      continue
    }

    if (response.ok) {
      return (await response.json()) as TokenResponse
    }

    const errorData = (await response.json().catch(() => ({}))) as { error?: string; error_description?: string }
    if (!errorData.error && TRANSIENT_POLL_STATUSES.has(response.status)) continue

    const error = (errorData.error || 'unknown') as TokenError
    const detail = errorData.error_description ? `: ${errorData.error_description}` : ''

    switch (error) {
      case 'authorization_pending':
        continue
      case 'slow_down':
        currentInterval += 5000
        continue
      case 'access_denied':
        throw new Error('Access denied by user')
      case 'expired_token':
        throw new Error(
          `Device code expired (server reported expired_token after ${elapsed()}s; expires_in was ${expiresIn}s)${detail}`,
        )
      default:
        throw new Error(`Token polling failed: ${error}${detail} (HTTP ${response.status})`)
    }
  }
}
