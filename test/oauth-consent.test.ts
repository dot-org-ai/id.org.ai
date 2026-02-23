import { describe, it, expect } from 'vitest'
import { generateConsentScreenHtml, getScopeDescription, consentCoversScopes } from '../src/oauth/consent'
import type { OAuthConsent } from '../src/oauth/types'

describe('OAuth Consent', () => {
  describe('generateConsentScreenHtml', () => {
    it('returns HTML with client name, scopes, and URLs', () => {
      const html = generateConsentScreenHtml({
        issuer: 'https://auth.example.com',
        clientName: 'My Agent App',
        clientId: 'client_123',
        redirectUri: 'https://app.example.com/callback',
        scopes: ['openid', 'profile', 'email'],
        consentToken: 'consent_token_abc',
      })

      expect(html).toContain('My Agent App')
      expect(html).toContain('client_123')
      expect(html).toContain('app.example.com')
      expect(html).toContain('openid')
      expect(html).toContain('profile')
      expect(html).toContain('email')
      expect(html).toContain('consent_token_abc')
      expect(html).toContain('<!DOCTYPE html>')
      expect(html).toContain('Authorize Access')
    })

    it('escapes HTML in client name to prevent XSS', () => {
      const html = generateConsentScreenHtml({
        issuer: 'https://auth.example.com',
        clientName: '<script>alert("xss")</script>',
        clientId: 'client_123',
        redirectUri: 'https://app.example.com/callback',
        scopes: ['openid'],
        consentToken: 'token',
      })

      expect(html).not.toContain('<script>')
      expect(html).toContain('&lt;script&gt;')
    })

    it('renders scope descriptions for each requested scope', () => {
      const html = generateConsentScreenHtml({
        issuer: 'https://auth.example.com',
        clientName: 'Test',
        clientId: 'client_123',
        redirectUri: 'https://app.example.com/callback',
        scopes: ['openid', 'offline_access'],
        consentToken: 'token',
      })

      expect(html).toContain('Verify your identity')
      expect(html).toContain('Maintain access when you are not actively using the app')
    })

    it('handles invalid redirect URI gracefully', () => {
      const html = generateConsentScreenHtml({
        issuer: 'https://auth.example.com',
        clientName: 'Test',
        clientId: 'client_123',
        redirectUri: 'not-a-url',
        scopes: ['openid'],
        consentToken: 'token',
      })

      expect(html).toContain('not-a-url')
    })
  })

  describe('getScopeDescription', () => {
    it('returns truthy description for standard scopes', () => {
      expect(getScopeDescription('openid')).toBeTruthy()
      expect(getScopeDescription('profile')).toBeTruthy()
      expect(getScopeDescription('email')).toBeTruthy()
      expect(getScopeDescription('offline_access')).toBeTruthy()
    })

    it('returns specific descriptions for known scopes', () => {
      expect(getScopeDescription('openid')).toBe('Verify your identity')
      expect(getScopeDescription('profile')).toBe('View your profile information (name, picture)')
      expect(getScopeDescription('email')).toBe('View your email address')
    })

    it('returns a fallback description for unknown scopes', () => {
      expect(getScopeDescription('custom:scope')).toBe('Access: custom:scope')
    })
  })

  describe('consentCoversScopes', () => {
    const consent: OAuthConsent = {
      userId: 'user_1',
      clientId: 'client_1',
      scopes: ['openid', 'profile', 'email'],
      grantedAt: Date.now(),
    }

    it('returns true when granted scopes cover all requested scopes', () => {
      expect(consentCoversScopes(consent, ['openid', 'profile'])).toBe(true)
      expect(consentCoversScopes(consent, ['openid'])).toBe(true)
      expect(consentCoversScopes(consent, ['openid', 'profile', 'email'])).toBe(true)
    })

    it('returns true for empty requested scopes', () => {
      expect(consentCoversScopes(consent, [])).toBe(true)
    })

    it('returns false when a requested scope is missing from granted', () => {
      expect(consentCoversScopes(consent, ['openid', 'offline_access'])).toBe(false)
      expect(consentCoversScopes(consent, ['mcp:write'])).toBe(false)
    })
  })
})
