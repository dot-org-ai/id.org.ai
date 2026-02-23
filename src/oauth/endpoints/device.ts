/**
 * Device Authorization Grant endpoint handlers (RFC 8628)
 *
 * Implements:
 * - POST /device_authorization - Issue device_code and user_code
 * - GET /device - Device verification page
 * - POST /device - Process device authorization
 */

import type { Context } from 'hono'
import type { OAuthStorage } from '../storage'
import type { DeviceAuthorizationResponse, OAuthError } from '../types'

/**
 * Characters used for user codes - unambiguous characters that are easy to type
 * Excludes vowels (to avoid generating words) and similar-looking characters (0, O, I, 1, L)
 */
const USER_CODE_CHARS = 'BCDFGHJKLMNPQRSTVWXZ'

/**
 * Generate a cryptographically secure device code
 */
function generateDeviceCode(length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  const randomValues = new Uint8Array(length)
  crypto.getRandomValues(randomValues)
  let result = ''
  for (let i = 0; i < length; i++) {
    result += chars[randomValues[i]! % chars.length]
  }
  return result
}

/**
 * Generate a human-readable user code in format XXXX-XXXX
 */
function generateUserCode(): string {
  const randomValues = new Uint8Array(8)
  crypto.getRandomValues(randomValues)
  let code = ''
  for (let i = 0; i < 8; i++) {
    if (i === 4) code += '-'
    code += USER_CODE_CHARS[randomValues[i]! % USER_CODE_CHARS.length]
  }
  return code
}

/**
 * Generate HTML for device verification page
 */
function generateDeviceVerificationHtml(options: { issuer: string; userCode?: string; error?: string }): string {
  const { issuer, userCode, error } = options

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Device Verification - ${issuer}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
    .container { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); max-width: 400px; width: 100%; }
    h1 { font-size: 24px; margin-bottom: 8px; color: #333; }
    p { color: #666; margin-bottom: 24px; line-height: 1.5; }
    .error { background: #fee; border: 1px solid #fcc; color: #c00; padding: 12px; border-radius: 6px; margin-bottom: 20px; }
    form { display: flex; flex-direction: column; gap: 16px; }
    label { font-weight: 500; color: #333; }
    input[type="text"] { padding: 14px; font-size: 24px; text-transform: uppercase; text-align: center; letter-spacing: 4px; border: 2px solid #ddd; border-radius: 8px; font-family: monospace; }
    input[type="text"]:focus { border-color: #0066ff; outline: none; }
    button { padding: 14px 24px; font-size: 16px; font-weight: 600; border: none; border-radius: 8px; cursor: pointer; transition: background 0.2s; }
    button[type="submit"] { background: #0066ff; color: white; }
    button[type="submit"]:hover { background: #0052cc; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Connect a Device</h1>
    <p>Enter the code shown on your device to continue.</p>
    ${error ? `<div class="error">${error}</div>` : ''}
    <form method="POST" action="/device">
      <label for="user_code">Device Code</label>
      <input type="text" id="user_code" name="user_code" placeholder="XXXX-XXXX" value="${userCode || ''}" maxlength="9" pattern="[A-Za-z]{4}-?[A-Za-z]{4}" required autocomplete="off" autofocus />
      <input type="hidden" name="action" value="verify" />
      <button type="submit">Continue</button>
    </form>
  </div>
</body>
</html>`
}

/**
 * Generate HTML for device authorization confirmation page
 */
function generateDeviceAuthorizationHtml(options: { issuer: string; userCode: string; clientName: string; scope?: string }): string {
  const { issuer, userCode, clientName, scope } = options

  const scopeList = scope ? scope.split(/\s+/).filter(Boolean) : []

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize Device - ${issuer}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
    .container { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); max-width: 400px; width: 100%; }
    h1 { font-size: 24px; margin-bottom: 8px; color: #333; }
    p { color: #666; margin-bottom: 16px; line-height: 1.5; }
    .client-name { font-weight: 600; color: #333; }
    .code { font-family: monospace; font-size: 18px; background: #f0f0f0; padding: 8px 16px; border-radius: 6px; display: inline-block; margin: 8px 0 16px; }
    .scopes { margin: 20px 0; padding: 16px; background: #f8f8f8; border-radius: 8px; }
    .scopes h3 { font-size: 14px; color: #666; margin-bottom: 12px; }
    .scopes ul { list-style: none; }
    .scopes li { padding: 8px 0; border-bottom: 1px solid #eee; color: #333; }
    .scopes li:last-child { border-bottom: none; }
    .buttons { display: flex; gap: 12px; margin-top: 24px; }
    button { flex: 1; padding: 14px 24px; font-size: 16px; font-weight: 600; border: none; border-radius: 8px; cursor: pointer; transition: background 0.2s; }
    .authorize { background: #0066ff; color: white; }
    .authorize:hover { background: #0052cc; }
    .deny { background: #f0f0f0; color: #333; }
    .deny:hover { background: #e0e0e0; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Authorize Device</h1>
    <p><span class="client-name">${clientName}</span> wants to access your account.</p>
    <div class="code">${userCode}</div>
    ${
      scopeList.length > 0
        ? `
    <div class="scopes">
      <h3>This will allow the application to:</h3>
      <ul>
        ${scopeList.map((s) => `<li>${s}</li>`).join('')}
      </ul>
    </div>
    `
        : ''
    }
    <form method="POST" action="/device">
      <input type="hidden" name="user_code" value="${userCode}" />
      <div class="buttons">
        <button type="submit" name="action" value="deny" class="deny">Deny</button>
        <button type="submit" name="action" value="authorize" class="authorize">Authorize</button>
      </div>
    </form>
  </div>
</body>
</html>`
}

/**
 * Generate HTML for device authorization success/error page
 */
function generateDeviceSuccessHtml(options: { issuer: string; message: string }): string {
  const { issuer, message } = options

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Device Authorization - ${issuer}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
    .container { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); max-width: 400px; width: 100%; text-align: center; }
    .icon { font-size: 48px; margin-bottom: 20px; }
    h1 { font-size: 24px; margin-bottom: 16px; color: #333; }
    p { color: #666; line-height: 1.5; }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">${message.includes('denied') ? '&#10060;' : '&#10004;'}</div>
    <h1>${message.includes('denied') ? 'Authorization Denied' : 'Success!'}</h1>
    <p>${message}</p>
  </div>
</body>
</html>`
}

/**
 * Configuration for Device Authorization handlers
 */
export interface DeviceHandlerConfig {
  /** Storage backend */
  storage: OAuthStorage
  /** Enable debug logging */
  debug: boolean
  /** Dev mode configuration */
  devMode?: { enabled: boolean; users?: Array<{ id: string }> } | undefined
  /** Function to get effective issuer from request */
  getEffectiveIssuer: (c: Context) => string
  /** Function to validate scopes */
  validateScopes: (requestedScope: string | undefined) => string | undefined
}

/**
 * Create the device authorization endpoint handler (POST /device_authorization)
 */
export function createDeviceAuthorizationHandler(config: DeviceHandlerConfig) {
  const { storage, debug, getEffectiveIssuer, validateScopes } = config

  return async (c: Context): Promise<Response> => {
    const contentType = c.req.header('content-type')
    let params: Record<string, string>

    if (contentType?.includes('application/json')) {
      try {
        const raw: unknown = await c.req.json()
        if (typeof raw !== 'object' || raw === null) {
          return c.json({ error: 'invalid_request', error_description: 'Request body must be a JSON object' } as OAuthError, 400)
        }
        params = Object.fromEntries(Object.entries(raw as Record<string, unknown>).map(([k, v]) => [k, v == null ? '' : String(v)]))
      } catch {
        return c.json({ error: 'invalid_request', error_description: 'Invalid JSON body' } as OAuthError, 400)
      }
    } else {
      const formData = await c.req.parseBody()
      params = Object.fromEntries(Object.entries(formData).map(([k, v]) => [k, String(v)]))
    }

    const clientId = params['client_id']
    const requestedScope = params['scope']

    if (debug) {
      console.log('[OAuth] Device authorization request:', { clientId, scope: requestedScope })
    }

    // Validate client_id is required
    if (!clientId) {
      return c.json({ error: 'invalid_request', error_description: 'client_id is required' } as OAuthError, 400)
    }

    // Validate client exists
    const client = await storage.getClient(clientId)
    if (!client) {
      return c.json({ error: 'invalid_client', error_description: 'Client not found' } as OAuthError, 400)
    }

    // Validate and filter scopes
    const grantedScope = validateScopes(requestedScope)

    // Get effective issuer for multi-tenant support
    const effectiveIssuer = getEffectiveIssuer(c)

    // Generate cryptographically secure device code (64 chars)
    const deviceCode = generateDeviceCode(64)

    // Generate human-readable user code in format XXXX-XXXX
    const userCode = generateUserCode()

    const now = Date.now()
    const expiresIn = 600 // 10 minutes
    const interval = 5 // 5 second polling interval

    // Store device code
    await storage.saveDeviceCode({
      deviceCode,
      userCode,
      clientId,
      ...(grantedScope && { scope: grantedScope }),
      issuedAt: now,
      expiresAt: now + expiresIn * 1000,
      interval,
      effectiveIssuer,
    })

    if (debug) {
      console.log('[OAuth] Device code issued:', { userCode, expiresIn })
    }

    // Build response per RFC 8628
    const response: DeviceAuthorizationResponse = {
      device_code: deviceCode,
      user_code: userCode,
      verification_uri: `${effectiveIssuer}/device`,
      verification_uri_complete: `${effectiveIssuer}/device?user_code=${userCode}`,
      expires_in: expiresIn,
      interval,
    }

    return c.json(response)
  }
}

/**
 * Create the device verification GET handler (GET /device)
 */
export function createDeviceGetHandler(config: DeviceHandlerConfig) {
  const { getEffectiveIssuer } = config

  return async (c: Context): Promise<Response> => {
    const userCode = c.req.query('user_code')
    const effectiveIssuer = getEffectiveIssuer(c)

    // Generate HTML form for device verification
    const html = generateDeviceVerificationHtml({
      issuer: effectiveIssuer,
      ...(userCode && { userCode }),
    })

    return c.html(html)
  }
}

/**
 * Create the device verification POST handler (POST /device)
 */
export function createDevicePostHandler(config: DeviceHandlerConfig) {
  const { storage, devMode, debug, getEffectiveIssuer } = config

  return async (c: Context): Promise<Response> => {
    const formData = await c.req.parseBody()
    const userCode = String(formData['user_code'] || '')
      .toUpperCase()
      .replace(/\s/g, '')
    const action = String(formData['action'] || '')

    const effectiveIssuer = getEffectiveIssuer(c)

    if (debug) {
      console.log('[OAuth] Device verification:', { userCode, action })
    }

    if (!userCode) {
      const html = generateDeviceVerificationHtml({
        issuer: effectiveIssuer,
        error: 'Please enter a code',
      })
      return c.html(html, 400)
    }

    // Look up device code by user code
    const deviceCodeData = await storage.getDeviceCodeByUserCode(userCode)

    if (!deviceCodeData) {
      const html = generateDeviceVerificationHtml({
        issuer: effectiveIssuer,
        userCode,
        error: 'Invalid code. Please check and try again.',
      })
      return c.html(html, 400)
    }

    // Check if expired
    if (Date.now() > deviceCodeData.expiresAt) {
      const html = generateDeviceVerificationHtml({
        issuer: effectiveIssuer,
        error: 'This code has expired. Please request a new code on your device.',
      })
      return c.html(html, 400)
    }

    // Check if already authorized or denied
    if (deviceCodeData.authorized || deviceCodeData.denied) {
      const html = generateDeviceVerificationHtml({
        issuer: effectiveIssuer,
        error: 'This code has already been used.',
      })
      return c.html(html, 400)
    }

    // If action is 'verify', show the authorize/deny form
    if (action === 'verify') {
      const client = await storage.getClient(deviceCodeData.clientId)
      const html = generateDeviceAuthorizationHtml({
        issuer: effectiveIssuer,
        userCode,
        clientName: client?.clientName || deviceCodeData.clientId,
        ...(deviceCodeData.scope && { scope: deviceCodeData.scope }),
      })
      return c.html(html)
    }

    // Handle authorize/deny actions
    if (action === 'authorize') {
      // In dev mode, auto-create a test user for the device
      // In production, this would require the user to be logged in
      let userId = 'device-user'

      if (devMode?.enabled && devMode.users?.length) {
        userId = devMode.users[0]!.id
      }

      // Update device code as authorized
      deviceCodeData.authorized = true
      deviceCodeData.userId = userId
      await storage.updateDeviceCode(deviceCodeData)

      const html = generateDeviceSuccessHtml({
        issuer: effectiveIssuer,
        message: 'Device authorized successfully! You can now close this window.',
      })
      return c.html(html)
    }

    if (action === 'deny') {
      // Update device code as denied
      deviceCodeData.denied = true
      await storage.updateDeviceCode(deviceCodeData)

      const html = generateDeviceSuccessHtml({
        issuer: effectiveIssuer,
        message: 'Authorization denied. You can close this window.',
      })
      return c.html(html)
    }

    // Default: show error
    const html = generateDeviceVerificationHtml({
      issuer: effectiveIssuer,
      error: 'Invalid request',
    })
    return c.html(html, 400)
  }
}
