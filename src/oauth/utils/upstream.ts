/**
 * Upstream OAuth provider utilities
 *
 * Functions for interacting with upstream OAuth providers (WorkOS, Auth0, Okta, custom)
 */

import type { OAuthStorage } from '../storage'
import type { OAuthUser, UpstreamOAuthConfig } from '../types'
import { decodeJWT } from '../jwt-verify'

/**
 * User info extracted from upstream provider
 */
export interface UpstreamUser {
  id: string
  email: string
  first_name?: string | undefined
  last_name?: string | undefined
  organization_id?: string | undefined
  role?: string | undefined
  roles?: string[] | undefined
  permissions?: string[] | undefined
}

/**
 * Build the authorization URL for the upstream provider
 */
export function buildUpstreamAuthUrl(
  upstream: UpstreamOAuthConfig,
  params: { redirectUri: string; state: string; scope: string },
): string {
  if (upstream.provider === 'workos') {
    const url = new URL('https://api.workos.com/user_management/authorize')
    url.searchParams.set('client_id', upstream.clientId)
    url.searchParams.set('redirect_uri', params.redirectUri)
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('state', params.state)
    url.searchParams.set('provider', 'authkit')
    return url.toString()
  }

  if (upstream.provider === 'auth0') {
    if (!upstream.authorizationEndpoint) {
      throw new Error('authorizationEndpoint is required for Auth0 (e.g., https://mytenant.auth0.com/authorize)')
    }
    const url = new URL(upstream.authorizationEndpoint)
    url.searchParams.set('client_id', upstream.clientId)
    url.searchParams.set('redirect_uri', params.redirectUri)
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('state', params.state)
    url.searchParams.set('scope', params.scope || 'openid profile email')
    return url.toString()
  }

  if (upstream.provider === 'okta') {
    if (!upstream.authorizationEndpoint) {
      throw new Error('authorizationEndpoint is required for Okta (e.g., https://dev-123456.okta.com/oauth2/v1/authorize)')
    }
    const url = new URL(upstream.authorizationEndpoint)
    url.searchParams.set('client_id', upstream.clientId)
    url.searchParams.set('redirect_uri', params.redirectUri)
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('state', params.state)
    url.searchParams.set('scope', params.scope || 'openid profile email')
    return url.toString()
  }

  // Custom provider
  if (!upstream.authorizationEndpoint) {
    throw new Error('authorizationEndpoint is required for custom providers')
  }

  const url = new URL(upstream.authorizationEndpoint)
  url.searchParams.set('client_id', upstream.clientId)
  url.searchParams.set('redirect_uri', params.redirectUri)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('state', params.state)
  url.searchParams.set('scope', params.scope)
  return url.toString()
}

/**
 * Fetch user info from Auth0 userinfo endpoint
 */
async function fetchAuth0UserInfo(accessToken: string, authorizationEndpoint: string): Promise<UpstreamUser> {
  const baseUrl = new URL(authorizationEndpoint)
  const userinfoUrl = `${baseUrl.origin}/userinfo`

  const response = await fetch(userinfoUrl, {
    headers: { Authorization: `Bearer ${accessToken}` },
  })

  if (!response.ok) {
    const error = await response.text()
    throw new Error(`Auth0 userinfo failed: ${response.status} - ${error}`)
  }

  const userInfo = (await response.json()) as {
    sub: string
    email?: string
    given_name?: string
    family_name?: string
    [key: string]: unknown
  }

  const roles: string[] = []
  const permissions: string[] = []
  for (const [key, value] of Object.entries(userInfo)) {
    if (key.endsWith('/roles') && Array.isArray(value)) {
      roles.push(...(value as string[]))
    }
    if (key.endsWith('/permissions') && Array.isArray(value)) {
      permissions.push(...(value as string[]))
    }
  }

  return {
    id: userInfo.sub,
    email: userInfo.email || '',
    ...(userInfo.given_name !== undefined && { first_name: userInfo.given_name }),
    ...(userInfo.family_name !== undefined && { last_name: userInfo.family_name }),
    ...(roles.length > 0 && { roles }),
    ...(permissions.length > 0 && { permissions }),
  }
}

/**
 * Fetch user info from Okta userinfo endpoint
 */
async function fetchOktaUserInfo(accessToken: string, authorizationEndpoint: string): Promise<UpstreamUser> {
  const userinfoUrl = authorizationEndpoint.replace('/authorize', '/userinfo')

  const response = await fetch(userinfoUrl, {
    headers: { Authorization: `Bearer ${accessToken}` },
  })

  if (!response.ok) {
    const error = await response.text()
    throw new Error(`Okta userinfo failed: ${response.status} - ${error}`)
  }

  const userInfo = (await response.json()) as {
    sub: string
    email?: string
    given_name?: string
    family_name?: string
    groups?: string[]
    [key: string]: unknown
  }

  const roles = userInfo.groups || []

  return {
    id: userInfo.sub,
    email: userInfo.email || '',
    ...(userInfo.given_name !== undefined && { first_name: userInfo.given_name }),
    ...(userInfo.family_name !== undefined && { last_name: userInfo.family_name }),
    ...(roles.length > 0 && { roles }),
  }
}

/**
 * Exchange an authorization code with the upstream provider for tokens
 */
export async function exchangeUpstreamCode(
  upstream: UpstreamOAuthConfig,
  code: string,
  redirectUri: string,
): Promise<{
  access_token: string
  refresh_token?: string
  expires_in?: number
  user: UpstreamUser
}> {
  if (upstream.provider === 'workos') {
    const response = await fetch('https://api.workos.com/user_management/authenticate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: upstream.clientId,
        client_secret: upstream.apiKey,
        code,
      }).toString(),
    })

    if (!response.ok) {
      const error = await response.text()
      throw new Error(`WorkOS authentication failed: ${response.status} - ${error}`)
    }

    const data = (await response.json()) as {
      access_token: string
      refresh_token?: string
      expires_in?: number
      user: UpstreamUser
    }

    try {
      const decoded = decodeJWT(data.access_token)
      if (decoded?.payload) {
        const role = decoded.payload['role'] as string | undefined
        const roles = decoded.payload['roles'] as string[] | undefined
        const permissions = decoded.payload['permissions'] as string[] | undefined

        if (role) {
          data.user.role = role
          data.user.roles = roles ? [...roles, role] : [role]
        } else if (roles) {
          data.user.roles = roles
        }

        if (permissions) {
          data.user.permissions = permissions
        }
      }
    } catch {
      // JWT decode failed - continue without roles
    }

    return data
  }

  if (upstream.provider === 'auth0') {
    if (!upstream.tokenEndpoint) {
      throw new Error('tokenEndpoint is required for Auth0 (e.g., https://mytenant.auth0.com/oauth/token)')
    }

    const response = await fetch(upstream.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: upstream.clientId,
        client_secret: upstream.apiKey,
        code,
        redirect_uri: redirectUri,
      }).toString(),
    })

    if (!response.ok) {
      const error = await response.text()
      throw new Error(`Auth0 token exchange failed: ${response.status} - ${error}`)
    }

    const tokenData = (await response.json()) as {
      access_token: string
      refresh_token?: string
      expires_in?: number
      id_token?: string
      token_type: string
    }

    const user = await fetchAuth0UserInfo(tokenData.access_token, upstream.authorizationEndpoint!)

    return {
      access_token: tokenData.access_token,
      ...(tokenData.refresh_token !== undefined && { refresh_token: tokenData.refresh_token }),
      ...(tokenData.expires_in !== undefined && { expires_in: tokenData.expires_in }),
      user,
    }
  }

  if (upstream.provider === 'okta') {
    if (!upstream.tokenEndpoint) {
      throw new Error('tokenEndpoint is required for Okta (e.g., https://dev-123456.okta.com/oauth2/v1/token)')
    }

    const response = await fetch(upstream.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: upstream.clientId,
        client_secret: upstream.apiKey,
        code,
        redirect_uri: redirectUri,
      }).toString(),
    })

    if (!response.ok) {
      const error = await response.text()
      throw new Error(`Okta token exchange failed: ${response.status} - ${error}`)
    }

    const tokenData = (await response.json()) as {
      access_token: string
      refresh_token?: string
      expires_in?: number
      id_token?: string
      token_type: string
    }

    const user = await fetchOktaUserInfo(tokenData.access_token, upstream.authorizationEndpoint!)

    return {
      access_token: tokenData.access_token,
      ...(tokenData.refresh_token !== undefined && { refresh_token: tokenData.refresh_token }),
      ...(tokenData.expires_in !== undefined && { expires_in: tokenData.expires_in }),
      user,
    }
  }

  // Custom provider
  if (!upstream.tokenEndpoint) {
    throw new Error('tokenEndpoint is required for custom providers')
  }

  const response = await fetch(upstream.tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: upstream.clientId,
      client_secret: upstream.apiKey,
      code,
      redirect_uri: redirectUri,
    }).toString(),
  })

  if (!response.ok) {
    const error = await response.text()
    throw new Error(`Token exchange failed: ${response.status} - ${error}`)
  }

  return response.json()
}

/**
 * Get or create a user in storage from upstream provider user info
 */
export async function getOrCreateUser(
  storage: OAuthStorage,
  upstreamUser: UpstreamUser,
  onUserAuthenticated?: (user: OAuthUser) => void | Promise<void>,
): Promise<OAuthUser> {
  let user = await storage.getUserByEmail(upstreamUser.email)

  if (!user) {
    const fullName = [upstreamUser.first_name, upstreamUser.last_name].filter(Boolean).join(' ')
    user = {
      id: upstreamUser.id,
      email: upstreamUser.email,
      ...(fullName && { name: fullName }),
      ...(upstreamUser.organization_id !== undefined && { organizationId: upstreamUser.organization_id }),
      ...(upstreamUser.roles && upstreamUser.roles.length > 0 && { roles: upstreamUser.roles }),
      ...(upstreamUser.permissions && upstreamUser.permissions.length > 0 && { permissions: upstreamUser.permissions }),
      createdAt: Date.now(),
      updatedAt: Date.now(),
      lastLoginAt: Date.now(),
    }
    await storage.saveUser(user)
  } else {
    user.lastLoginAt = Date.now()
    user.updatedAt = Date.now()
    if (upstreamUser.organization_id !== undefined) {
      user.organizationId = upstreamUser.organization_id
    }
    if (upstreamUser.roles && upstreamUser.roles.length > 0) {
      user.roles = upstreamUser.roles
    }
    if (upstreamUser.permissions && upstreamUser.permissions.length > 0) {
      user.permissions = upstreamUser.permissions
    }
    await storage.saveUser(user)
  }

  if (onUserAuthenticated) {
    await onUserAuthenticated(user)
  }

  return user
}
