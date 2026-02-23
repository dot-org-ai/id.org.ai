import { describe, it, expect } from 'vitest'
import { createTestHelpers, generateLoginFormHtml } from '../src/oauth/dev'
import type { DevUser, TestHelpers } from '../src/oauth/dev'
import { MemoryOAuthStorage } from '../src/oauth/storage'

describe('OAuth Dev Helpers', () => {
  describe('createTestHelpers', () => {
    function setup(opts?: { allowAnyCredentials?: boolean }) {
      const storage = new MemoryOAuthStorage()
      const devUsers = new Map<string, DevUser>()
      devUsers.set('admin@test.com', {
        id: 'user_admin',
        email: 'admin@test.com',
        password: 'admin123',
        name: 'Admin User',
      })

      const helpers = createTestHelpers(storage, devUsers, {
        accessTokenTtl: 3600,
        refreshTokenTtl: 86400,
        authCodeTtl: 300,
        ...opts,
      })

      return { storage, devUsers, helpers }
    }

    it('returns object with expected methods', () => {
      const { helpers } = setup()
      expect(helpers).toBeDefined()
      expect(typeof helpers.createUser).toBe('function')
      expect(typeof helpers.getAccessToken).toBe('function')
      expect(typeof helpers.getSessionCookies).toBe('function')
      expect(typeof helpers.createAuthorizationCode).toBe('function')
      expect(typeof helpers.validateCredentials).toBe('function')
    })

    it('createUser saves user and returns OAuthUser', async () => {
      const { helpers, storage } = setup()
      const user = await helpers.createUser({
        id: 'user_new',
        email: 'new@test.com',
        password: 'pass123',
        name: 'New User',
      })

      expect(user.id).toBe('user_new')
      expect(user.email).toBe('new@test.com')
      expect(user.name).toBe('New User')
      expect(user.createdAt).toBeTypeOf('number')

      // Should be persisted in storage
      const stored = await storage.getUser('user_new')
      expect(stored).toBeDefined()
      expect(stored!.email).toBe('new@test.com')
    })

    it('getAccessToken returns token details', async () => {
      const { helpers, storage } = setup()
      await helpers.createUser({ id: 'user_1', email: 'u1@test.com', password: 'p' })

      const result = await helpers.getAccessToken('user_1', 'client_test')

      expect(result.accessToken).toBeTypeOf('string')
      expect(result.accessToken.length).toBeGreaterThan(0)
      expect(result.refreshToken).toBeTypeOf('string')
      expect(result.refreshToken.length).toBeGreaterThan(0)
      expect(result.expiresIn).toBe(3600)

      // Token should be retrievable from storage
      const stored = await storage.getAccessToken(result.accessToken)
      expect(stored).toBeDefined()
      expect(stored!.userId).toBe('user_1')
      expect(stored!.clientId).toBe('client_test')
    })

    it('getSessionCookies returns cookie array', async () => {
      const { helpers } = setup()
      await helpers.createUser({ id: 'user_2', email: 'u2@test.com' })

      const cookies = await helpers.getSessionCookies('user_2')
      expect(Array.isArray(cookies)).toBe(true)
      expect(cookies.length).toBeGreaterThan(0)
      expect(cookies[0].name).toBe('oauth_access_token')
      expect(cookies[0].value).toBeTypeOf('string')
      expect(cookies[0].httpOnly).toBe(true)
      expect(cookies[0].secure).toBe(true)
    })

    it('createAuthorizationCode returns a code string', async () => {
      const { helpers } = setup()
      const code = await helpers.createAuthorizationCode({
        clientId: 'client_1',
        userId: 'user_1',
        redirectUri: 'https://example.com/callback',
        codeChallenge: 'test-challenge',
      })

      expect(code).toBeTypeOf('string')
      expect(code.length).toBeGreaterThan(0)
    })

    it('validateCredentials returns user for valid credentials', async () => {
      const { helpers } = setup()
      const user = await helpers.validateCredentials('admin@test.com', 'admin123')
      expect(user).not.toBeNull()
      expect(user!.id).toBe('user_admin')
      expect(user!.email).toBe('admin@test.com')
    })

    it('validateCredentials returns null for invalid credentials', async () => {
      const { helpers } = setup()
      const user = await helpers.validateCredentials('admin@test.com', 'wrong')
      expect(user).toBeNull()
    })

    it('validateCredentials with allowAnyCredentials creates new user', async () => {
      const { helpers } = setup({ allowAnyCredentials: true })
      const user = await helpers.validateCredentials('anyone@test.com', 'anypass')
      expect(user).not.toBeNull()
      expect(user!.email).toBe('anyone@test.com')
    })
  })

  describe('generateLoginFormHtml', () => {
    it('returns HTML string', () => {
      const html = generateLoginFormHtml({
        issuer: 'https://auth.example.com',
        clientId: 'client_123',
        redirectUri: 'https://app.example.com/callback',
        codeChallenge: 'challenge_abc',
        codeChallengeMethod: 'S256',
      })

      expect(typeof html).toBe('string')
      expect(html).toContain('<!DOCTYPE html>')
    })

    it('contains issuer, clientId, and form elements', () => {
      const html = generateLoginFormHtml({
        issuer: 'https://auth.example.com',
        clientId: 'my-agent-client',
        redirectUri: 'https://app.example.com/callback',
        codeChallenge: 'challenge_abc',
        codeChallengeMethod: 'S256',
      })

      expect(html).toContain('https://auth.example.com')
      expect(html).toContain('my-agent-client')
      expect(html).toContain('challenge_abc')
      expect(html).toContain('S256')
      expect(html).toContain('Sign In')
      expect(html).toContain('Development Mode')
      expect(html).toContain('<form')
      expect(html).toContain('type="email"')
      expect(html).toContain('type="password"')
    })

    it('includes error message when provided', () => {
      const html = generateLoginFormHtml({
        issuer: 'https://auth.example.com',
        clientId: 'client_123',
        redirectUri: 'https://app.example.com/callback',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'S256',
        error: 'Invalid credentials',
      })

      expect(html).toContain('Invalid credentials')
      expect(html).toContain('class="error"')
    })

    it('does not include error div when no error', () => {
      const html = generateLoginFormHtml({
        issuer: 'https://auth.example.com',
        clientId: 'client_123',
        redirectUri: 'https://app.example.com/callback',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'S256',
      })

      expect(html).not.toContain('class="error"')
    })

    it('includes hidden fields for state and scope', () => {
      const html = generateLoginFormHtml({
        issuer: 'https://auth.example.com',
        clientId: 'client_123',
        redirectUri: 'https://app.example.com/callback',
        scope: 'openid profile',
        state: 'random_state',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'S256',
      })

      expect(html).toContain('openid profile')
      expect(html).toContain('random_state')
    })
  })
})
