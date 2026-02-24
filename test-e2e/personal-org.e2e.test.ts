/**
 * Flow 5: Personal Org Auto-Creation
 *
 * Tests that a brand-new user who signs up through AuthKit
 * automatically gets a personal org created during the callback.
 *
 * Uses the real sign-up flow (no direct WorkOS API calls):
 *   1. Navigate to AuthKit sign-up with a fresh @emails.do address
 *   2. Create account with email + password
 *   3. AuthKit sends verification email → poll emails.do
 *   4. Follow verification link → complete sign-up
 *   5. Login with the new account
 *   6. Verify JWT org claim exists with { id, name }
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { newPage, closeBrowser, getAuthCookie, isAuthKitUrl, isPostCallback, fillAuthKitCredentials } from './helpers/browser'
import { waitForEmail } from './helpers/email'
import { decodeJwtPayload, assertJwtClaims, assertNestedOrgClaim } from './helpers/jwt'
import type { Page } from 'playwright'

const ID_URL = process.env.ID_URL || 'https://oauth.do'
const TEST_PASSWORD = process.env.E2E_AUTH_PASSWORD

// Unique email for this test — each run creates a brand new user
const FRESH_USER_EMAIL = `e2e-personal-org-${Date.now()}@emails.do`

describe('Personal Org Auto-Creation', () => {
  let page: Page
  let testStartTs: number

  beforeAll(async () => {
    if (!TEST_PASSWORD) {
      console.warn('Skipping personal org tests: E2E_AUTH_PASSWORD not set')
      return
    }
    testStartTs = Date.now()
    page = await newPage()
  }, 30_000)

  afterAll(async () => {
    await closeBrowser()
  })

  it('should sign up as a new user via AuthKit', async () => {
    if (!TEST_PASSWORD) return

    await page.goto(`${ID_URL}/login`)
    await page.waitForTimeout(3000)

    const url = page.url()

    if (isAuthKitUrl(url)) {
      // Click "Sign up" link
      const signUpLink = await page.$('text=Sign up')
        ?? await page.$('text=Create account')
        ?? await page.$("text=Don't have an account")
        ?? await page.$('[data-testid="sign-up-link"]')
        ?? await page.$('a[href*="sign-up"]')

      if (signUpLink) {
        await signUpLink.click()
        await page.waitForTimeout(1000)
      }

      await fillAuthKitCredentials(page, FRESH_USER_EMAIL, TEST_PASSWORD)
      await page.waitForTimeout(3000)
    }
  }, 30_000)

  it('should complete email verification if required', async () => {
    if (!TEST_PASSWORD) return

    const url = page.url()

    // Check if we landed back home (no verification needed)
    if (isPostCallback(url)) {
      const jwt = await getAuthCookie(page)
      if (jwt) return
    }

    // AuthKit may have sent a verification email — poll for it
    try {
      const email = await waitForEmail(FRESH_USER_EMAIL, {
        timeoutMs: 30_000,
        afterTs: testStartTs,
      })

      const verifyMatch = email.html_body?.match(/href="(https:\/\/[^"]*(?:verify|confirm|activate)[^"]*)"/)
        ?? email.html_body?.match(/href="(https:\/\/[^"]*workos[^"]*)"/)
        ?? email.text_body?.match(/(https:\/\/\S*(?:verify|confirm|activate)\S*)/)

      if (verifyMatch) {
        await page.goto(verifyMatch[1])
        await page.waitForTimeout(3000)
      }
    } catch {
      console.warn('No verification email received — AuthKit may auto-verify')
    }
  }, 60_000)

  it('should log in as the new user and get a JWT', async () => {
    if (!TEST_PASSWORD) return

    // If already authenticated from sign-up flow, skip
    const existingJwt = await getAuthCookie(page)
    if (existingJwt) return

    await page.goto(`${ID_URL}/login`)
    await page.waitForTimeout(3000)

    const url = page.url()
    if (isAuthKitUrl(url)) {
      await fillAuthKitCredentials(page, FRESH_USER_EMAIL, TEST_PASSWORD)
    }

    await page.waitForURL((url) => isPostCallback(url.toString()), { timeout: 30_000 })

    const jwt = await getAuthCookie(page)
    expect(jwt).toBeTruthy()
  }, 60_000)

  it('should have auto-created a personal org in the JWT', async () => {
    if (!TEST_PASSWORD) return

    const jwt = await getAuthCookie(page)
    expect(jwt).toBeTruthy()

    const claims = decodeJwtPayload(jwt!)
    assertJwtClaims(claims)

    // The key assertion: org should exist for a brand-new user
    assertNestedOrgClaim(claims)

    const org = claims.org as Record<string, unknown>
    expect(org.id).toBeTruthy()
    if (org.name) {
      expect(typeof org.name).toBe('string')
    }
  })
})
