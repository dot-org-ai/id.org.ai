/**
 * Flow 4: Google OAuth Login
 *
 * Tests the Google OAuth auth flow:
 *   1. Navigate to id.org.ai/login?provider=GoogleOAuth
 *   2. Redirects to Google consent screen
 *   3. Log in with test Google account
 *   4. Google redirects back → WorkOS → /callback
 *   5. Verify: JWT claims correct, email matches test Google account
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { newPage, closeBrowser, getAuthCookie } from './helpers/browser'
import { decodeJwtPayload, assertJwtClaims } from './helpers/jwt'
import type { Page } from 'playwright'

const ID_URL = process.env.ID_URL || 'https://oauth.do'
const GOOGLE_EMAIL = process.env.E2E_GOOGLE_EMAIL
const GOOGLE_PASSWORD = process.env.E2E_GOOGLE_PASSWORD

describe('Google OAuth Login', () => {
  let page: Page

  beforeAll(async () => {
    if (!GOOGLE_EMAIL || !GOOGLE_PASSWORD) {
      console.warn('Skipping Google OAuth tests: E2E_GOOGLE_EMAIL and/or E2E_GOOGLE_PASSWORD not set')
      return
    }

    page = await newPage()
  }, 30_000)

  afterAll(async () => {
    await closeBrowser()
  })

  it('should redirect to Google when provider=GoogleOAuth', async () => {
    if (!GOOGLE_EMAIL || !GOOGLE_PASSWORD) return

    await page.goto(`${ID_URL}/login?provider=GoogleOAuth`)

    // Should redirect through WorkOS to Google
    await page.waitForURL(/accounts\.google\.com/, { timeout: 15_000 })
    expect(page.url()).toMatch(/accounts\.google\.com/)
  })

  it('should authenticate with Google credentials', async () => {
    if (!GOOGLE_EMAIL || !GOOGLE_PASSWORD) return

    // Fill in Google login form
    // Google's login is a multi-step flow: email → password
    await page.waitForSelector('input[type="email"]', { timeout: 10_000 })
    await page.fill('input[type="email"]', GOOGLE_EMAIL)
    await page.click('#identifierNext, button[type="submit"]')

    await page.waitForSelector('input[type="password"]', { timeout: 10_000 })
    await page.fill('input[type="password"]', GOOGLE_PASSWORD)
    await page.click('#passwordNext, button[type="submit"]')

    // Handle potential consent screen
    const allowBtn = await page.$('#submit_approve_access').catch(() => null)
    if (allowBtn) {
      await allowBtn.click()
    }

    // Wait for the redirect chain to complete back to id.org.ai
    await page.waitForURL((url) => {
      const u = url.toString()
      return u.includes('id.org.ai') && !u.includes('/callback') && !u.includes('google.com')
    }, { timeout: 30_000 })

    // Verify auth cookie was set
    const jwt = await getAuthCookie(page)
    expect(jwt).toBeTruthy()
  }, 60_000)

  it('should have correct JWT claims with matching email', async () => {
    if (!GOOGLE_EMAIL || !GOOGLE_PASSWORD) return

    const jwt = await getAuthCookie(page)
    expect(jwt).toBeTruthy()

    const claims = decodeJwtPayload(jwt!)
    assertJwtClaims(claims)

    // Email should match the Google account
    expect(claims.email).toBe(GOOGLE_EMAIL)
  })
})
