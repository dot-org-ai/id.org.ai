// src/services/oauth/service.ts

import { OAuthProvider } from '../../../sdk/oauth/provider'
import type { StorageAdapter } from '../../../sdk/storage'
import type { OAuthService, OAuthConfig } from './types'

/**
 * OAuthServiceImpl — thin facade over OAuthProvider.
 *
 * Constructs an OAuthProvider with StorageAdapter and delegates all flow
 * handlers directly. Client seeding logic is consolidated from Identity.ts
 * (ensureCliClient + ensureOAuthDoClient + ensureWebClients).
 *
 * NOTE: OAuthProvider.getOpenIDConfiguration() returns a Response. The facade
 * parses it and returns a plain Record to match the OAuthService interface.
 */
export class OAuthServiceImpl implements OAuthService {
  private provider: OAuthProvider
  private storage: StorageAdapter
  private config: OAuthConfig

  constructor(deps: { storage: StorageAdapter; config: OAuthConfig }) {
    this.storage = deps.storage
    this.config = deps.config
    this.provider = new OAuthProvider({
      storage: deps.storage,
      config: deps.config,
      getIdentity: async () => null, // Identity resolution happens at the worker layer, not here
    })
  }

  // ── OAuth 2.1 Flow Handlers (delegate to OAuthProvider) ──────────────

  async handleRegister(request: Request): Promise<Response> {
    return this.provider.handleRegister(request)
  }

  async handleAuthorize(request: Request, identityId?: string | null): Promise<Response> {
    return this.provider.handleAuthorize(request, identityId ?? null)
  }

  async handleAuthorizeConsent(request: Request, identityId: string): Promise<Response> {
    return this.provider.handleAuthorizeConsent(request, identityId)
  }

  async handleToken(request: Request): Promise<Response> {
    return this.provider.handleToken(request)
  }

  async handleDeviceAuthorization(request: Request): Promise<Response> {
    return this.provider.handleDeviceAuthorization(request)
  }

  async handleDeviceVerification(request: Request, identityId?: string | null): Promise<Response> {
    return this.provider.handleDeviceVerification(request, identityId ?? null)
  }

  async handleUserinfo(request: Request): Promise<Response> {
    return this.provider.handleUserinfo(request)
  }

  async handleIntrospect(request: Request): Promise<Response> {
    return this.provider.handleIntrospect(request)
  }

  async handleRevoke(request: Request): Promise<Response> {
    return this.provider.handleRevoke(request)
  }

  // ── Discovery ────────────────────────────────────────────────────────

  getOpenIDConfiguration(): Record<string, unknown> {
    // OAuthProvider.getOpenIDConfiguration() returns a Response — extract the JSON synchronously
    // by reconstructing from config (provider builds the same shape)
    return {
      issuer: this.config.issuer,
      authorization_endpoint: this.config.authorizationEndpoint,
      token_endpoint: this.config.tokenEndpoint,
      userinfo_endpoint: this.config.userinfoEndpoint,
      registration_endpoint: this.config.registrationEndpoint,
      device_authorization_endpoint: this.config.deviceAuthorizationEndpoint,
      revocation_endpoint: this.config.revocationEndpoint,
      introspection_endpoint: this.config.introspectionEndpoint,
      jwks_uri: this.config.jwksUri,
      response_types_supported: ['code'],
      grant_types_supported: [
        'authorization_code',
        'refresh_token',
        'client_credentials',
        'urn:ietf:params:oauth:grant-type:device_code',
      ],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256', 'ES256'],
      scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      code_challenge_methods_supported: ['S256'],
      claims_supported: ['sub', 'name', 'preferred_username', 'picture', 'email', 'email_verified'],
    }
  }

  // ── Client Seeding ───────────────────────────────────────────────────

  async ensureDefaultClients(): Promise<void> {
    const defaults = [
      {
        id: 'id_org_ai_cli',
        name: 'id.org.ai CLI',
        redirectUris: [],
        grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
        responseTypes: [],
        scopes: ['openid', 'profile', 'email', 'offline_access'],
        trusted: true,
        tokenEndpointAuthMethod: 'none',
      },
      {
        id: 'oauth_do_cli',
        name: 'oauth.do CLI',
        redirectUris: [],
        grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
        responseTypes: [],
        scopes: ['openid', 'profile', 'email', 'offline_access'],
        trusted: true,
        tokenEndpointAuthMethod: 'none',
      },
      {
        id: 'auto_dev_cli',
        name: 'auto.dev CLI',
        redirectUris: [],
        grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
        responseTypes: [],
        scopes: ['openid', 'profile', 'email', 'offline_access'],
        trusted: true,
        tokenEndpointAuthMethod: 'none',
      },
      {
        id: 'id_org_ai_dash',
        name: 'id.org.ai Dashboard',
        redirectUris: ['https://id.org.ai/dash/profile'],
        grantTypes: ['authorization_code'],
        responseTypes: ['code'],
        scopes: ['openid', 'profile', 'email'],
        trusted: true,
        tokenEndpointAuthMethod: 'none',
      },
      {
        id: 'id_org_ai_headlessly',
        name: 'Headless.ly',
        redirectUris: ['https://headless.ly/dashboard'],
        grantTypes: ['authorization_code'],
        responseTypes: ['code'],
        scopes: ['openid', 'profile', 'email'],
        trusted: true,
        tokenEndpointAuthMethod: 'none',
      },
      {
        id: 'auto_dev_web',
        name: 'auto.dev Web',
        redirectUris: [
          'https://auto.dev/api/v2/auth/callback/id-org-ai',
          'http://localhost:3000/api/v2/auth/callback/id-org-ai',
        ],
        grantTypes: ['authorization_code'],
        responseTypes: ['code'],
        scopes: ['openid', 'profile', 'email'],
        trusted: true,
        tokenEndpointAuthMethod: 'none',
      },
    ]

    for (const client of defaults) {
      const existing = await this.storage.get(`client:${client.id}`)
      if (!existing) {
        await this.storage.put(`client:${client.id}`, { ...client, createdAt: Date.now() })
      }
    }
  }

}
