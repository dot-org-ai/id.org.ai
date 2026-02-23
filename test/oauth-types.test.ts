/**
 * OAuth Types Export Test
 *
 * Verifies that all core OAuth 2.1 types are properly exported
 * from id.org.ai/oauth and that types.ts has zero external dependencies.
 */

import { describe, it, expect } from 'vitest'
import * as oauthExports from '../src/oauth/index'
import * as typesExports from '../src/oauth/types'

describe('OAuth types exports', () => {
  it('exports all types from types.ts via oauth/index.ts', () => {
    // Verify that the oauth barrel re-exports the OAuthProvider class
    expect(oauthExports.OAuthProvider).toBeDefined()
    expect(typeof oauthExports.OAuthProvider).toBe('function')
  })

  it('types.ts exports are pure type definitions (no runtime values)', () => {
    // types.ts should only contain type/interface exports
    // When compiled, this module should have no runtime exports
    // (all exports are erased by TypeScript)
    const runtimeKeys = Object.keys(typesExports)
    expect(runtimeKeys).toEqual([])
  })
})

// Type-level tests: these verify the types compile correctly.
// If any of these type assertions fail, the file won't compile.

describe('OAuth type shapes', () => {
  it('OAuthUser has required fields', () => {
    const user: oauthExports.OAuthUser = {
      id: 'usr_123',
      createdAt: Date.now(),
      updatedAt: Date.now(),
    }
    expect(user.id).toBe('usr_123')
    expect(user.createdAt).toBeTypeOf('number')
    expect(user.updatedAt).toBeTypeOf('number')
  })

  it('OAuthUser supports optional fields', () => {
    const user: oauthExports.OAuthUser = {
      id: 'usr_456',
      email: 'alice@example.com',
      name: 'Alice',
      organizationId: 'org_789',
      provider: 'workos',
      providerId: 'workos_abc',
      roles: ['admin'],
      permissions: ['read:all', 'write:all'],
      metadata: { team: 'engineering' },
      createdAt: Date.now(),
      updatedAt: Date.now(),
      lastLoginAt: Date.now(),
    }
    expect(user.email).toBe('alice@example.com')
    expect(user.roles).toEqual(['admin'])
  })

  it('OAuthOrganization has required fields', () => {
    const org: oauthExports.OAuthOrganization = {
      id: 'org_123',
      name: 'Acme Corp',
      createdAt: Date.now(),
      updatedAt: Date.now(),
    }
    expect(org.id).toBe('org_123')
    expect(org.name).toBe('Acme Corp')
  })

  it('OAuthClient has required fields', () => {
    const client: oauthExports.OAuthClient = {
      clientId: 'cid_abc',
      clientName: 'Test App',
      redirectUris: ['https://example.com/callback'],
      grantTypes: ['authorization_code'],
      responseTypes: ['code'],
      tokenEndpointAuthMethod: 'none',
      createdAt: Date.now(),
    }
    expect(client.clientId).toBe('cid_abc')
    expect(client.clientName).toBe('Test App')
    expect(client.grantTypes).toContain('authorization_code')
  })

  it('OAuthClient supports all grant types', () => {
    const client: oauthExports.OAuthClient = {
      clientId: 'cid_full',
      clientName: 'Full Client',
      redirectUris: ['https://example.com/callback'],
      grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
      responseTypes: ['code', 'token'],
      tokenEndpointAuthMethod: 'client_secret_basic',
      scope: 'openid profile email',
      clientSecretHash: 'hashed_secret',
      metadata: { logo_uri: 'https://example.com/logo.png' },
      createdAt: Date.now(),
      expiresAt: Date.now() + 86400000,
    }
    expect(client.grantTypes).toHaveLength(3)
    expect(client.responseTypes).toHaveLength(2)
  })

  it('OAuthAuthorizationCode has required fields', () => {
    const code: oauthExports.OAuthAuthorizationCode = {
      code: 'ac_xyz',
      clientId: 'cid_abc',
      userId: 'usr_123',
      redirectUri: 'https://example.com/callback',
      issuedAt: Date.now(),
      expiresAt: Date.now() + 600000,
    }
    expect(code.code).toBe('ac_xyz')
    expect(code.expiresAt).toBeGreaterThan(code.issuedAt)
  })

  it('OAuthAuthorizationCode supports PKCE and exchange fields', () => {
    const code: oauthExports.OAuthAuthorizationCode = {
      code: 'ac_pkce',
      clientId: 'cid_abc',
      userId: 'usr_123',
      redirectUri: 'https://example.com/callback',
      scope: 'openid',
      codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      codeChallengeMethod: 'S256',
      issuedAt: Date.now(),
      expiresAt: Date.now() + 600000,
      state: 'csrf_state',
      upstreamState: 'upstream_state',
      effectiveIssuer: 'https://id.org.ai',
      exchangeAccessToken: 'at_exchange',
      exchangeRefreshToken: 'rt_exchange',
    }
    expect(code.codeChallengeMethod).toBe('S256')
    expect(code.effectiveIssuer).toBe('https://id.org.ai')
  })

  it('OAuthAccessToken has required fields', () => {
    const token: oauthExports.OAuthAccessToken = {
      token: 'at_123',
      tokenType: 'Bearer',
      clientId: 'cid_abc',
      userId: 'usr_123',
      issuedAt: Date.now(),
      expiresAt: Date.now() + 3600000,
    }
    expect(token.tokenType).toBe('Bearer')
  })

  it('OAuthRefreshToken has required fields', () => {
    const token: oauthExports.OAuthRefreshToken = {
      token: 'rt_123',
      clientId: 'cid_abc',
      userId: 'usr_123',
      issuedAt: Date.now(),
    }
    expect(token.token).toBe('rt_123')
  })

  it('OAuthGrant has required fields', () => {
    const grant: oauthExports.OAuthGrant = {
      id: 'grant_123',
      userId: 'usr_123',
      clientId: 'cid_abc',
      createdAt: Date.now(),
    }
    expect(grant.id).toBe('grant_123')
  })

  it('OAuthServerMetadata has required fields (RFC 8414)', () => {
    const metadata: oauthExports.OAuthServerMetadata = {
      issuer: 'https://id.org.ai',
      authorization_endpoint: 'https://id.org.ai/authorize',
      token_endpoint: 'https://id.org.ai/token',
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_basic'],
      code_challenge_methods_supported: ['S256'],
    }
    expect(metadata.issuer).toBe('https://id.org.ai')
    expect(metadata.code_challenge_methods_supported).toContain('S256')
  })

  it('OAuthResourceMetadata has required fields', () => {
    const resource: oauthExports.OAuthResourceMetadata = {
      resource: 'https://api.headless.ly',
    }
    expect(resource.resource).toBe('https://api.headless.ly')
  })

  it('TokenResponse has required fields', () => {
    const response: oauthExports.TokenResponse = {
      access_token: 'at_abc',
      token_type: 'Bearer',
      expires_in: 3600,
    }
    expect(response.token_type).toBe('Bearer')
    expect(response.expires_in).toBe(3600)
  })

  it('OAuthError has required fields', () => {
    const error: oauthExports.OAuthError = {
      error: 'invalid_request',
      error_description: 'Missing redirect_uri parameter',
    }
    expect(error.error).toBe('invalid_request')
  })

  it('OAuthDeviceCode has required fields (RFC 8628)', () => {
    const device: oauthExports.OAuthDeviceCode = {
      deviceCode: 'dc_123',
      userCode: 'WDJB-MJHT',
      clientId: 'cid_abc',
      issuedAt: Date.now(),
      expiresAt: Date.now() + 900000,
      interval: 5,
    }
    expect(device.userCode).toBe('WDJB-MJHT')
    expect(device.interval).toBe(5)
  })

  it('OAuthConsent has required fields', () => {
    const consent: oauthExports.OAuthConsent = {
      userId: 'usr_123',
      clientId: 'cid_abc',
      scopes: ['openid', 'profile'],
      createdAt: Date.now(),
      updatedAt: Date.now(),
    }
    expect(consent.scopes).toContain('openid')
  })

  it('DeviceAuthorizationResponse has required fields (RFC 8628 Section 3.2)', () => {
    const response: oauthExports.DeviceAuthorizationResponse = {
      device_code: 'dc_xyz',
      user_code: 'ABCD-EFGH',
      verification_uri: 'https://id.org.ai/device',
      expires_in: 900,
    }
    expect(response.verification_uri).toBe('https://id.org.ai/device')
  })

  it('OAuthProviderClient is exported and distinct from OAuthClient', () => {
    // OAuthProviderClient is the provider's internal storage format
    const providerClient: oauthExports.OAuthProviderClient = {
      id: 'cid_123',
      name: 'Test App',
      redirectUris: ['https://example.com/callback'],
      grantTypes: ['authorization_code'],
      responseTypes: ['code'],
      scopes: ['openid'],
      trusted: false,
      tokenEndpointAuthMethod: 'none',
      createdAt: Date.now(),
    }
    expect(providerClient.id).toBe('cid_123')
    expect(providerClient.trusted).toBe(false)

    // OAuthClient is the canonical wire format from @dotdo/oauth
    const client: oauthExports.OAuthClient = {
      clientId: 'cid_456',
      clientName: 'Wire Format Client',
      redirectUris: ['https://example.com/callback'],
      grantTypes: ['authorization_code'],
      responseTypes: ['code'],
      tokenEndpointAuthMethod: 'none',
      createdAt: Date.now(),
    }
    expect(client.clientId).toBe('cid_456')
    expect(client.clientName).toBe('Wire Format Client')
  })
})
