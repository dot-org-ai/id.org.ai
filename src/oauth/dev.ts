/**
 * Development Mode & Test Helpers
 *
 * Provides a self-contained OAuth 2.1 server mode for testing:
 * - Simple username/password authentication (no upstream provider)
 * - Pre-seeded test users
 * - Programmatic token creation for E2E tests
 * - Login form UI
 *
 * Ported from @dotdo/oauth core/src/dev.ts
 */

import type { OAuthUser, OAuthAccessToken, OAuthRefreshToken } from './types'
import type { OAuthStorage } from './storage'
import { generateToken, generateAuthorizationCode } from './pkce'

/**
 * Compute the refresh token expiresAt timestamp in milliseconds.
 *
 * @param refreshTokenTtl - TTL in seconds (e.g. 2592000 for 30 days)
 * @param now - Current time in milliseconds (default: Date.now())
 */
function computeRefreshTokenExpiry(refreshTokenTtl: number, now: number = Date.now()): number | undefined {
  if (refreshTokenTtl <= 0) return undefined
  return now + refreshTokenTtl * 1000
}

/**
 * Test user configuration
 */
export interface DevUser {
  /** User ID */
  id: string
  /** Email address (used as username) */
  email: string
  /** Password for login */
  password: string
  /** Display name */
  name?: string
  /** Organization ID */
  organizationId?: string
  /** User roles */
  roles?: string[]
}

/**
 * Development mode configuration
 *
 * @warning SECURITY: devMode should NEVER be enabled in production environments.
 * It bypasses upstream OAuth providers and uses simple password authentication,
 * which is insecure for production use. Only use for local development and testing.
 */
export interface DevModeConfig {
  /**
   * Enable dev mode (disables upstream OAuth)
   *
   * @warning SECURITY: Never enable in production! This bypasses all upstream
   * OAuth security and allows simple password-based authentication.
   */
  enabled: boolean
  /** Pre-configured test users */
  users?: DevUser[]
  /** Allow any email/password (creates user on the fly) */
  allowAnyCredentials?: boolean
  /** Custom login page HTML */
  customLoginPage?: string
}

/**
 * Test helpers for E2E testing with Playwright
 */
export interface TestHelpers {
  /**
   * Create a test user
   */
  createUser(user: Omit<DevUser, 'password'> & { password?: string }): Promise<OAuthUser>

  /**
   * Get an access token directly (bypasses OAuth flow)
   */
  getAccessToken(
    userId: string,
    clientId: string,
    scope?: string,
  ): Promise<{
    accessToken: string
    refreshToken: string
    expiresIn: number
  }>

  /**
   * Get cookies for a user session (for Playwright)
   */
  getSessionCookies(
    userId: string,
  ): Promise<
    Array<{
      name: string
      value: string
      domain?: string
      path?: string
      expires?: number
      httpOnly?: boolean
      secure?: boolean
      sameSite?: 'Strict' | 'Lax' | 'None'
    }>
  >

  /**
   * Create an authorization code (for testing token endpoint)
   */
  createAuthorizationCode(params: {
    clientId: string
    userId: string
    redirectUri: string
    scope?: string
    codeChallenge: string
  }): Promise<string>

  /**
   * Validate credentials
   */
  validateCredentials(email: string, password: string): Promise<DevUser | null>
}

/**
 * Create test helpers for a storage instance
 */
export function createTestHelpers(
  storage: OAuthStorage,
  devUsers: Map<string, DevUser>,
  options: {
    accessTokenTtl: number
    refreshTokenTtl: number
    authCodeTtl: number
    allowAnyCredentials?: boolean
  },
): TestHelpers {
  const { accessTokenTtl, refreshTokenTtl, authCodeTtl, allowAnyCredentials } = options

  return {
    async createUser(userData) {
      const user: OAuthUser = {
        id: userData.id,
        email: userData.email,
        ...(userData.name !== undefined && { name: userData.name }),
        ...(userData.organizationId !== undefined && { organizationId: userData.organizationId }),
        ...(userData.roles !== undefined && { roles: userData.roles }),
        createdAt: Date.now(),
        updatedAt: Date.now(),
      }

      await storage.saveUser(user)

      // Also add to dev users map if password provided
      if (userData.password) {
        devUsers.set(userData.email.toLowerCase(), {
          ...userData,
          password: userData.password,
        } as DevUser)
      }

      return user
    },

    async getAccessToken(userId, clientId, scope = 'openid profile email') {
      const accessToken = generateToken(64)
      const refreshToken = generateToken(64)
      const now = Date.now()

      const accessTokenObj: OAuthAccessToken = {
        token: accessToken,
        tokenType: 'Bearer',
        userId,
        clientId,
        scope,
        issuedAt: now,
        expiresAt: now + accessTokenTtl * 1000,
      }

      const refreshExpiresAt = computeRefreshTokenExpiry(refreshTokenTtl, now)
      const refreshTokenObj: OAuthRefreshToken = {
        token: refreshToken,
        userId,
        clientId,
        scope,
        issuedAt: now,
        ...(refreshExpiresAt !== undefined && { expiresAt: refreshExpiresAt }),
      }

      await storage.saveAccessToken(accessTokenObj)
      await storage.saveRefreshToken(refreshTokenObj)

      return {
        accessToken,
        refreshToken,
        expiresIn: accessTokenTtl,
      }
    },

    async getSessionCookies(userId) {
      // Create an access token and return it as a cookie
      const { accessToken } = await this.getAccessToken(userId, 'test-client')

      return [
        {
          name: 'oauth_access_token',
          value: accessToken,
          path: '/',
          httpOnly: true,
          secure: true,
          sameSite: 'Lax' as const,
          expires: Date.now() / 1000 + accessTokenTtl,
        },
      ]
    },

    async createAuthorizationCode(params) {
      const code = generateAuthorizationCode()

      await storage.saveAuthorizationCode({
        code,
        clientId: params.clientId,
        userId: params.userId,
        redirectUri: params.redirectUri,
        ...(params.scope !== undefined && { scope: params.scope }),
        codeChallenge: params.codeChallenge,
        codeChallengeMethod: 'S256',
        issuedAt: Date.now(),
        expiresAt: Date.now() + authCodeTtl * 1000,
      })

      return code
    },

    async validateCredentials(email, password) {
      const user = devUsers.get(email.toLowerCase())
      if (user && user.password === password) {
        return user
      }

      // If allowAnyCredentials is enabled, create a new user
      if (allowAnyCredentials) {
        const namePart = email.split('@')[0]
        const newUser: DevUser = {
          id: `dev_${generateToken(12)}`,
          email,
          password,
          ...(namePart && { name: namePart }),
        }
        devUsers.set(email.toLowerCase(), newUser)
        return newUser
      }

      return null
    },
  }
}

/**
 * Generate a simple login form HTML
 */
export function generateLoginFormHtml(options: {
  issuer: string
  clientId: string
  redirectUri: string
  scope?: string
  state?: string
  codeChallenge: string
  codeChallengeMethod: string
  error?: string
}): string {
  const { issuer, clientId, redirectUri, scope, state, codeChallenge, codeChallengeMethod, error } = options

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In - ${issuer}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 16px;
      padding: 40px;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
    }
    .logo {
      text-align: center;
      margin-bottom: 32px;
    }
    .logo h1 {
      font-size: 24px;
      color: #1a1a2e;
      margin-bottom: 8px;
    }
    .logo p {
      color: #666;
      font-size: 14px;
    }
    .dev-badge {
      display: inline-block;
      background: #fef3c7;
      color: #92400e;
      padding: 4px 12px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 600;
      margin-top: 12px;
    }
    .error {
      background: #fee2e2;
      border: 1px solid #fecaca;
      color: #dc2626;
      padding: 12px 16px;
      border-radius: 8px;
      margin-bottom: 24px;
      font-size: 14px;
    }
    .form-group {
      margin-bottom: 20px;
    }
    label {
      display: block;
      font-size: 14px;
      font-weight: 500;
      color: #374151;
      margin-bottom: 6px;
    }
    input[type="email"],
    input[type="password"] {
      width: 100%;
      padding: 12px 16px;
      border: 1px solid #d1d5db;
      border-radius: 8px;
      font-size: 16px;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    input:focus {
      outline: none;
      border-color: #667eea;
      box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }
    button {
      width: 100%;
      padding: 14px 24px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    button:hover {
      transform: translateY(-1px);
      box-shadow: 0 10px 20px -10px rgba(102, 126, 234, 0.5);
    }
    button:active {
      transform: translateY(0);
    }
    .footer {
      text-align: center;
      margin-top: 24px;
      color: #9ca3af;
      font-size: 12px;
    }
    .client-info {
      background: #f3f4f6;
      border-radius: 8px;
      padding: 12px 16px;
      margin-bottom: 24px;
      font-size: 13px;
      color: #4b5563;
    }
    .client-info strong {
      color: #1f2937;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">
      <h1>Sign In</h1>
      <p>${issuer}</p>
      <span class="dev-badge">Development Mode</span>
    </div>

    ${error ? `<div class="error">${error}</div>` : ''}

    <div class="client-info">
      Signing in to <strong>${clientId}</strong>
    </div>

    <form method="POST" action="/login">
      <input type="hidden" name="client_id" value="${clientId}">
      <input type="hidden" name="redirect_uri" value="${redirectUri}">
      <input type="hidden" name="scope" value="${scope || ''}">
      <input type="hidden" name="state" value="${state || ''}">
      <input type="hidden" name="code_challenge" value="${codeChallenge}">
      <input type="hidden" name="code_challenge_method" value="${codeChallengeMethod}">

      <div class="form-group">
        <label for="email">Email</label>
        <input type="email" id="email" name="email" required autofocus placeholder="test@example.com">
      </div>

      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required placeholder="Enter password">
      </div>

      <button type="submit">Sign In</button>
    </form>

    <div class="footer">
      <p>This is a development server for testing.</p>
      <p>Do not use real credentials.</p>
    </div>
  </div>
</body>
</html>`
}
