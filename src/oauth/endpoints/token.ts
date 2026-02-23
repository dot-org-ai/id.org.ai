/**
 * Token endpoint handlers (OAuth 2.1)
 *
 * Implements:
 * - authorization_code grant
 * - refresh_token grant
 * - client_credentials grant
 * - device_code grant (RFC 8628)
 */

import type { Context } from 'hono'
import type { OAuthStorage } from '../storage'
import type { OAuthClient, OAuthError, TokenResponse } from '../types'
import { generateToken, verifyCodeChallenge, verifyClientSecret } from '../pkce'
import { signAccessToken, type AccessTokenClaims } from '../../jwt'
import { computeRefreshTokenExpiry } from '../helpers'

/**
 * Result of client authentication
 */
export type ClientAuthResult =
  | { authenticated: true; client: OAuthClient }
  | { authenticated: false; error: string; errorDescription?: string; statusCode?: number }

/**
 * JWT signing options passed from token endpoint
 */
export interface JWTSigningOptions {
  issuer: string
  getSigningKey: () => Promise<{
    kid: string
    alg: 'RS256'
    privateKey: CryptoKey
    publicKey: CryptoKey
    createdAt: number
  }>
}

/**
 * Authenticate a client at the token endpoint
 *
 * Supports:
 * - client_secret_basic: Authorization: Basic base64(client_id:client_secret)
 * - client_secret_post: client_id and client_secret in request body
 * - none: public clients (no secret required)
 */
export async function authenticateClient(
  c: Context,
  params: Record<string, string>,
  storage: OAuthStorage,
  debug: boolean
): Promise<ClientAuthResult> {
  let clientId: string | undefined
  let clientSecret: string | undefined

  // Check for client_secret_basic (Authorization header)
  const authHeader = c.req.header('authorization')
  if (authHeader?.startsWith('Basic ')) {
    try {
      const base64Credentials = authHeader.slice(6)
      const credentials = atob(base64Credentials)
      const colonIndex = credentials.indexOf(':')
      if (colonIndex !== -1) {
        clientId = decodeURIComponent(credentials.slice(0, colonIndex))
        clientSecret = decodeURIComponent(credentials.slice(colonIndex + 1))
      }
    } catch {
      return {
        authenticated: false,
        error: 'invalid_client',
        errorDescription: 'Invalid Authorization header',
        statusCode: 401,
      }
    }
  }

  // Fall back to client_secret_post (body parameters)
  if (!clientId) {
    clientId = params['client_id']
    clientSecret = params['client_secret']
  }

  if (!clientId) {
    return {
      authenticated: false,
      error: 'invalid_request',
      errorDescription: 'client_id is required',
      statusCode: 400,
    }
  }

  // Fetch the client
  const client = await storage.getClient(clientId)
  if (!client) {
    return {
      authenticated: false,
      error: 'invalid_client',
      errorDescription: 'Client not found',
      statusCode: 401,
    }
  }

  // Check if client requires authentication
  if (client.tokenEndpointAuthMethod !== 'none') {
    // Client requires secret verification
    if (!client.clientSecretHash) {
      // Client is configured to require auth but has no secret stored
      return {
        authenticated: false,
        error: 'invalid_client',
        errorDescription: 'Client authentication failed',
        statusCode: 401,
      }
    }

    if (!clientSecret) {
      return {
        authenticated: false,
        error: 'invalid_client',
        errorDescription: 'Client secret is required',
        statusCode: 401,
      }
    }

    // Verify the secret using constant-time comparison
    const secretValid = await verifyClientSecret(clientSecret, client.clientSecretHash)
    if (!secretValid) {
      if (debug) {
        console.log('[OAuth] Client authentication failed for:', clientId)
      }
      return {
        authenticated: false,
        error: 'invalid_client',
        errorDescription: 'Client authentication failed',
        statusCode: 401,
      }
    }
  }

  if (debug) {
    console.log('[OAuth] Client authenticated:', clientId)
  }

  return {
    authenticated: true,
    client,
  }
}

/**
 * Sign a JWT access token
 */
async function signJWTAccessToken(
  claims: AccessTokenClaims,
  options: JWTSigningOptions,
  expiresIn: number
): Promise<string> {
  const key = await options.getSigningKey()
  return signAccessToken(key, claims, {
    issuer: options.issuer,
    audience: claims.client_id,
    expiresIn,
  })
}

/**
 * Handle authorization_code grant type
 */
export async function handleAuthorizationCodeGrant(
  c: Context,
  params: Record<string, string>,
  storage: OAuthStorage,
  accessTokenTtl: number,
  refreshTokenTtl: number,
  debug: boolean,
  jwtOptions?: JWTSigningOptions
): Promise<Response> {
  const code = params['code']
  const redirect_uri = params['redirect_uri']
  const code_verifier = params['code_verifier']

  if (!code) {
    return c.json({ error: 'invalid_request', error_description: 'code is required' } as OAuthError, 400)
  }

  // Authenticate client (supports client_secret_basic and client_secret_post)
  const authResult = await authenticateClient(c, params, storage, debug)
  if (!authResult.authenticated) {
    const statusCode = (authResult.statusCode || 401) as 400 | 401
    return c.json({ error: authResult.error, error_description: authResult.errorDescription } as OAuthError, statusCode)
  }
  const client = authResult.client

  // Consume authorization code (one-time use)
  const authCode = await storage.consumeAuthorizationCode(code)
  if (!authCode) {
    return c.json({ error: 'invalid_grant', error_description: 'Invalid or expired authorization code' } as OAuthError, 400)
  }

  // Verify client matches the code
  if (authCode.clientId !== client.clientId) {
    return c.json({ error: 'invalid_grant', error_description: 'Client mismatch' } as OAuthError, 400)
  }

  // Verify redirect_uri
  if (redirect_uri && authCode.redirectUri !== redirect_uri) {
    return c.json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' } as OAuthError, 400)
  }

  // Verify PKCE (required in OAuth 2.1)
  // Per OAuth 2.1 spec, PKCE is REQUIRED for authorization_code flow
  if (!authCode.codeChallenge) {
    // This should never happen if the authorize endpoint is working correctly
    return c.json({ error: 'server_error', error_description: 'Authorization code missing code_challenge' } as OAuthError, 500)
  }

  if (!code_verifier) {
    return c.json({ error: 'invalid_request', error_description: 'code_verifier is required' } as OAuthError, 400)
  }

  const valid = await verifyCodeChallenge(code_verifier, authCode.codeChallenge, authCode.codeChallengeMethod || 'S256')
  if (!valid) {
    return c.json({ error: 'invalid_grant', error_description: 'Invalid code_verifier' } as OAuthError, 400)
  }

  // Check expiration
  if (Date.now() > authCode.expiresAt) {
    return c.json({ error: 'invalid_grant', error_description: 'Authorization code expired' } as OAuthError, 400)
  }

  // Generate tokens
  const refreshToken = generateToken(64)
  const now = Date.now()

  // Generate access token (JWT if configured, otherwise opaque)
  let accessToken: string
  if (jwtOptions) {
    // Use effectiveIssuer from auth code if set (for multi-tenant support)
    const tokenJwtOptions = authCode.effectiveIssuer ? { ...jwtOptions, issuer: authCode.effectiveIssuer } : jwtOptions
    accessToken = await signJWTAccessToken(
      {
        sub: authCode.userId,
        client_id: authCode.clientId,
        ...(authCode.scope && { scope: authCode.scope }),
      },
      tokenJwtOptions,
      accessTokenTtl
    )
    // Note: JWT access tokens are stateless, so we don't store them
    // But we can optionally store metadata for tracking/revocation
  } else {
    accessToken = generateToken(48)
    await storage.saveAccessToken({
      token: accessToken,
      tokenType: 'Bearer',
      clientId: authCode.clientId,
      userId: authCode.userId,
      ...(authCode.scope !== undefined && { scope: authCode.scope }),
      issuedAt: now,
      expiresAt: now + accessTokenTtl * 1000,
    })
  }

  const refreshExpiresAt = computeRefreshTokenExpiry(refreshTokenTtl, now)
  await storage.saveRefreshToken({
    token: refreshToken,
    clientId: authCode.clientId,
    userId: authCode.userId,
    ...(authCode.scope !== undefined && { scope: authCode.scope }),
    issuedAt: now,
    ...(refreshExpiresAt !== undefined && { expiresAt: refreshExpiresAt }),
  })

  // Save grant
  await storage.saveGrant({
    id: `${authCode.userId}:${authCode.clientId}`,
    userId: authCode.userId,
    clientId: authCode.clientId,
    ...(authCode.scope !== undefined && { scope: authCode.scope }),
    createdAt: now,
    lastUsedAt: now,
  })

  if (debug) {
    console.log('[OAuth] Tokens issued for user:', authCode.userId, jwtOptions ? '(JWT)' : '(opaque)')
  }

  const response: TokenResponse = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: accessTokenTtl,
    refresh_token: refreshToken,
    ...(authCode.scope !== undefined && { scope: authCode.scope }),
  }

  return c.json(response)
}

/**
 * Handle refresh_token grant type
 */
export async function handleRefreshTokenGrant(
  c: Context,
  params: Record<string, string>,
  storage: OAuthStorage,
  accessTokenTtl: number,
  refreshTokenTtl: number,
  debug: boolean,
  jwtOptions?: JWTSigningOptions
): Promise<Response> {
  const refresh_token = params['refresh_token']

  if (!refresh_token) {
    return c.json({ error: 'invalid_request', error_description: 'refresh_token is required' } as OAuthError, 400)
  }

  // Authenticate client (supports client_secret_basic and client_secret_post)
  const authResult = await authenticateClient(c, params, storage, debug)
  if (!authResult.authenticated) {
    const statusCode = (authResult.statusCode || 401) as 400 | 401
    return c.json({ error: authResult.error, error_description: authResult.errorDescription } as OAuthError, statusCode)
  }
  const client = authResult.client

  const storedRefresh = await storage.getRefreshToken(refresh_token)
  if (!storedRefresh) {
    return c.json({ error: 'invalid_grant', error_description: 'Invalid refresh token' } as OAuthError, 400)
  }

  if (storedRefresh.revoked) {
    return c.json({ error: 'invalid_grant', error_description: 'Refresh token has been revoked' } as OAuthError, 400)
  }

  if (storedRefresh.expiresAt && Date.now() > storedRefresh.expiresAt) {
    return c.json({ error: 'invalid_grant', error_description: 'Refresh token expired' } as OAuthError, 400)
  }

  // Verify the refresh token belongs to the authenticated client
  if (storedRefresh.clientId !== client.clientId) {
    return c.json({ error: 'invalid_grant', error_description: 'Client mismatch' } as OAuthError, 400)
  }

  // Generate new tokens
  const newRefreshToken = generateToken(64)
  const now = Date.now()

  // Generate access token (JWT if configured, otherwise opaque)
  let accessToken: string
  if (jwtOptions) {
    accessToken = await signJWTAccessToken(
      {
        sub: storedRefresh.userId,
        client_id: storedRefresh.clientId,
        ...(storedRefresh.scope && { scope: storedRefresh.scope }),
      },
      jwtOptions,
      accessTokenTtl
    )
  } else {
    accessToken = generateToken(48)
    await storage.saveAccessToken({
      token: accessToken,
      tokenType: 'Bearer',
      clientId: storedRefresh.clientId,
      userId: storedRefresh.userId,
      ...(storedRefresh.scope !== undefined && { scope: storedRefresh.scope }),
      issuedAt: now,
      expiresAt: now + accessTokenTtl * 1000,
    })
  }

  // Rotate refresh token
  const refreshExpiresAt = computeRefreshTokenExpiry(refreshTokenTtl, now)
  await storage.revokeRefreshToken(refresh_token)
  await storage.saveRefreshToken({
    token: newRefreshToken,
    clientId: storedRefresh.clientId,
    userId: storedRefresh.userId,
    ...(storedRefresh.scope !== undefined && { scope: storedRefresh.scope }),
    issuedAt: now,
    ...(refreshExpiresAt !== undefined && { expiresAt: refreshExpiresAt }),
  })

  // Update grant last used
  const grant = await storage.getGrant(storedRefresh.userId, storedRefresh.clientId)
  if (grant) {
    grant.lastUsedAt = now
    await storage.saveGrant(grant)
  }

  if (debug) {
    console.log('[OAuth] Tokens refreshed for user:', storedRefresh.userId, jwtOptions ? '(JWT)' : '(opaque)')
  }

  const response: TokenResponse = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: accessTokenTtl,
    refresh_token: newRefreshToken,
    ...(storedRefresh.scope !== undefined && { scope: storedRefresh.scope }),
  }

  return c.json(response)
}

/**
 * Handle client_credentials grant type (OAuth 2.1 machine-to-machine)
 */
export async function handleClientCredentialsGrant(
  c: Context,
  params: Record<string, string>,
  storage: OAuthStorage,
  accessTokenTtl: number,
  debug: boolean,
  jwtOptions?: JWTSigningOptions
): Promise<Response> {
  // Authenticate client (supports client_secret_basic and client_secret_post)
  const authResult = await authenticateClient(c, params, storage, debug)
  if (!authResult.authenticated) {
    const statusCode = (authResult.statusCode || 401) as 400 | 401
    return c.json({ error: authResult.error, error_description: authResult.errorDescription } as OAuthError, statusCode)
  }
  const client = authResult.client

  // Verify client is authorized for client_credentials grant
  if (!client.grantTypes.includes('client_credentials')) {
    return c.json(
      { error: 'unauthorized_client', error_description: 'Client is not authorized for client_credentials grant' } as OAuthError,
      400
    )
  }

  // Get requested scope (optional)
  const requestedScope = params['scope']

  const now = Date.now()

  // Generate access token (JWT if configured, otherwise opaque)
  // Note: client_credentials does not have a userId (machine-to-machine)
  let accessToken: string
  if (jwtOptions) {
    accessToken = await signJWTAccessToken(
      {
        sub: client.clientId, // Use client_id as subject for M2M
        client_id: client.clientId,
        ...(requestedScope && { scope: requestedScope }),
      },
      jwtOptions,
      accessTokenTtl
    )
  } else {
    accessToken = generateToken(48)
    await storage.saveAccessToken({
      token: accessToken,
      tokenType: 'Bearer',
      clientId: client.clientId,
      userId: client.clientId, // Use client_id as userId for M2M (client_credentials)
      ...(requestedScope && { scope: requestedScope }),
      issuedAt: now,
      expiresAt: now + accessTokenTtl * 1000,
    })
  }

  if (debug) {
    console.log('[OAuth] Client credentials token issued for client:', client.clientId, jwtOptions ? '(JWT)' : '(opaque)')
  }

  const response: TokenResponse = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: accessTokenTtl,
    ...(requestedScope && { scope: requestedScope }),
  }

  return c.json(response)
}

/**
 * Handle device_code grant type (RFC 8628)
 */
export async function handleDeviceCodeGrant(
  c: Context,
  params: Record<string, string>,
  storage: OAuthStorage,
  accessTokenTtl: number,
  refreshTokenTtl: number,
  debug: boolean,
  jwtOptions?: JWTSigningOptions
): Promise<Response> {
  const device_code = params['device_code']
  const client_id = params['client_id']

  if (!device_code) {
    return c.json({ error: 'invalid_request', error_description: 'device_code is required' } as OAuthError, 400)
  }

  if (!client_id) {
    return c.json({ error: 'invalid_request', error_description: 'client_id is required' } as OAuthError, 400)
  }

  // Fetch the device code
  const deviceCodeData = await storage.getDeviceCode(device_code)
  if (!deviceCodeData) {
    return c.json({ error: 'invalid_grant', error_description: 'Invalid device code' } as OAuthError, 400)
  }

  // Verify client_id matches
  if (deviceCodeData.clientId !== client_id) {
    return c.json({ error: 'invalid_grant', error_description: 'Client mismatch' } as OAuthError, 400)
  }

  // Check if expired
  if (Date.now() > deviceCodeData.expiresAt) {
    // Clean up expired device code
    await storage.deleteDeviceCode(device_code)
    return c.json({ error: 'expired_token', error_description: 'Device code has expired' } as OAuthError, 400)
  }

  // Check polling interval (slow_down)
  const now = Date.now()
  // Access lastPollTime from the device code data (may be added by storage implementation)
  const lastPollTime = (deviceCodeData as { lastPollTime?: number }).lastPollTime
  if (lastPollTime) {
    const timeSinceLastPoll = now - lastPollTime
    const minInterval = deviceCodeData.interval * 1000 // Convert to milliseconds
    if (timeSinceLastPoll < minInterval) {
      // Update last poll time even on slow_down
      ;(deviceCodeData as { lastPollTime?: number }).lastPollTime = now
      await storage.updateDeviceCode(deviceCodeData)
      return c.json({ error: 'slow_down', error_description: 'Polling too fast' } as OAuthError, 400)
    }
  }

  // Update last poll time
  ;(deviceCodeData as { lastPollTime?: number }).lastPollTime = now
  await storage.updateDeviceCode(deviceCodeData)

  // Check if user denied
  if (deviceCodeData.denied) {
    // Clean up denied device code
    await storage.deleteDeviceCode(device_code)
    return c.json({ error: 'access_denied', error_description: 'User denied authorization' } as OAuthError, 400)
  }

  // Check if user has not yet authorized
  if (!deviceCodeData.authorized || !deviceCodeData.userId) {
    return c.json({ error: 'authorization_pending', error_description: 'User has not yet authorized' } as OAuthError, 400)
  }

  // User has authorized - issue tokens
  if (debug) {
    console.log('[OAuth] Device code authorized, issuing tokens for user:', deviceCodeData.userId)
  }

  // Generate tokens
  const refreshToken = generateToken(64)

  // Generate access token (JWT if configured, otherwise opaque)
  let accessToken: string
  if (jwtOptions) {
    // Use effectiveIssuer from device code if set (for multi-tenant support)
    const tokenJwtOptions = deviceCodeData.effectiveIssuer ? { ...jwtOptions, issuer: deviceCodeData.effectiveIssuer } : jwtOptions
    accessToken = await signJWTAccessToken(
      {
        sub: deviceCodeData.userId,
        client_id: deviceCodeData.clientId,
        ...(deviceCodeData.scope && { scope: deviceCodeData.scope }),
      },
      tokenJwtOptions,
      accessTokenTtl
    )
  } else {
    accessToken = generateToken(48)
    await storage.saveAccessToken({
      token: accessToken,
      tokenType: 'Bearer',
      clientId: deviceCodeData.clientId,
      userId: deviceCodeData.userId,
      ...(deviceCodeData.scope && { scope: deviceCodeData.scope }),
      issuedAt: now,
      expiresAt: now + accessTokenTtl * 1000,
    })
  }

  const refreshExpiresAt = computeRefreshTokenExpiry(refreshTokenTtl, now)
  await storage.saveRefreshToken({
    token: refreshToken,
    clientId: deviceCodeData.clientId,
    userId: deviceCodeData.userId,
    ...(deviceCodeData.scope && { scope: deviceCodeData.scope }),
    issuedAt: now,
    ...(refreshExpiresAt !== undefined && { expiresAt: refreshExpiresAt }),
  })

  // Save grant
  await storage.saveGrant({
    id: `${deviceCodeData.userId}:${deviceCodeData.clientId}`,
    userId: deviceCodeData.userId,
    clientId: deviceCodeData.clientId,
    ...(deviceCodeData.scope && { scope: deviceCodeData.scope }),
    createdAt: now,
    lastUsedAt: now,
  })

  // Clean up device code after successful token exchange
  await storage.deleteDeviceCode(device_code)

  const response: TokenResponse = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: accessTokenTtl,
    refresh_token: refreshToken,
    ...(deviceCodeData.scope && { scope: deviceCodeData.scope }),
  }

  return c.json(response)
}
