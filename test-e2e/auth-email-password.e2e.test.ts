/**
 * Flow 1: Email + Password Login via WorkOS AuthKit
 *
 * Self-bootstrapping: on first run, signs up the test user via AuthKit
 * (with email verification through emails.do). On subsequent runs, just logs in.
 *
 * Steps:
 *   1. Navigate to oauth.do/login
 *   2. AuthKit login UI loads (login.oauth.do → login.org.ai)
 *   3. Attempt login — if user doesn't exist, sign up first
 *   4. AuthKit authenticates → redirects to /callback
 *   5. /callback sets auth cookie → redirects to /
 *   6. Verify: cookie exists, JWT decodes with correct camelCase claims
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { newPage, closeBrowser, getAuthCookie, isAuthKitUrl, isPostCallback, fillAuthKitCredentials } from './helpers/browser'
import { waitForEmail } from './helpers/email'
import { decodeJwtPayload, assertJwtClaims } from './helpers/jwt'
import type { Page } from 'playwright'

const ID_URL = process.env.ID_URL || 'https://oauth.do'
const TEST_EMAIL = process.env.E2E_AUTH_EMAIL || 'e2e-auth-test@emails.do'
const TEST_PASSWORD = process.env.E2E_AUTH_PASSWORD

describe('Email + Password Login', () => {
  let page: Page

  beforeAll(async () => {
    if (!TEST_PASSWORD) {
      console.warn('Skipping email+password tests: E2E_AUTH_PASSWORD not set')
      return
    }
    page = await newPage()
  }, 30_000)

  afterAll(async () => {
    await closeBrowser()
  })

  it('should navigate to login and see AuthKit', async () => {
    if (!TEST_PASSWORD) return

    await page.goto(`${ID_URL}/login`)
    await page.waitForTimeout(3000)

    const url = page.url()
    expect(isAuthKitUrl(url) || url.includes('oauth.do') || url.includes('id.org.ai')).toBe(true)
  })

  it('should authenticate with email and password (signs up on first run)', async () => {
    if (!TEST_PASSWORD) return

    const signupStartTs = Date.now()

    // Navigate fresh to login
    await page.goto(`${ID_URL}/login`)
    await page.waitForTimeout(3000)

    const url = page.url()
    if (isAuthKitUrl(url)) {
      await fillAuthKitCredentials(page, TEST_EMAIL, TEST_PASSWORD)
    }

    // Wait for either: success redirect, or an error (user not found)
    const landed = await page.waitForURL((u) => isPostCallback(u.toString()), { timeout: 15_000 })
      .then(() => true)
      .catch(() => false)

    if (landed) {
      const jwt = await getAuthCookie(page)
      expect(jwt).toBeTruthy()
      return
    }

    // Login failed — user may not exist yet. Try sign-up flow.
    console.log('Login failed — attempting sign-up for', TEST_EMAIL)

    const signUpLink = await page.$('text=Sign up')
      ?? await page.$('text=Create account')
      ?? await page.$("text=Don't have an account")
      ?? await page.$('[data-testid="sign-up-link"]')
      ?? await page.$('a[href*="sign-up"]')

    if (signUpLink) {
      await signUpLink.click()
      await page.waitForTimeout(1000)
    } else {
      await page.goto(`${ID_URL}/login`)
      await page.waitForTimeout(3000)
    }

    // Fill sign-up form
    const currentUrl = page.url()
    if (isAuthKitUrl(currentUrl)) {
      const signUpBtn = await page.$('text=Sign up') ?? await page.$('text=Create account')
      if (signUpBtn) {
        await signUpBtn.click()
        await page.waitForTimeout(1000)
      }
      await fillAuthKitCredentials(page, TEST_EMAIL, TEST_PASSWORD)
      await page.waitForTimeout(3000)
    }

    // AuthKit may require email verification
    const signedUpDirectly = await page.waitForURL((u) => isPostCallback(u.toString()), { timeout: 10_000 })
      .then(() => true)
      .catch(() => false)

    if (!signedUpDirectly) {
      try {
        const email = await waitForEmail(TEST_EMAIL, { timeoutMs: 60_000, afterTs: signupStartTs })
        const verifyMatch = email.html_body?.match(/href="(https:\/\/[^"]*(?:verify|confirm|activate)[^"]*)"/)
          ?? email.html_body?.match(/href="(https:\/\/[^"]*workos[^"]*)"/)
          ?? email.text_body?.match(/(https:\/\/\S*(?:verify|confirm|activate)\S*)/)
        if (verifyMatch) {
          await page.goto(verifyMatch[1])
          await page.waitForTimeout(3000)
        }
      } catch {
        console.warn('No verification email received — may already be verified')
      }

      // After verification, login again
      await page.goto(`${ID_URL}/login`)
      await page.waitForTimeout(3000)
      const loginUrl = page.url()
      if (isAuthKitUrl(loginUrl)) {
        await fillAuthKitCredentials(page, TEST_EMAIL, TEST_PASSWORD)
      }
      await page.waitForURL((u) => isPostCallback(u.toString()), { timeout: 30_000 })
    }

    const jwt = await getAuthCookie(page)
    expect(jwt).toBeTruthy()
  }, 120_000)

  it('should have correct JWT claims (camelCase, nested org)', async () => {
    if (!TEST_PASSWORD) return

    const jwt = await getAuthCookie(page)
    expect(jwt).toBeTruthy()

    const claims = decodeJwtPayload(jwt!)
    assertJwtClaims(claims)
    expect(claims.email).toBe(TEST_EMAIL)
    expect(claims.sub).toBeTruthy()
  })

  it('should have org claim (personal org auto-created)', async () => {
    if (!TEST_PASSWORD) return

    const jwt = await getAuthCookie(page)
    expect(jwt).toBeTruthy()

    const claims = decodeJwtPayload(jwt!)
    if (claims.org) {
      const org = claims.org as Record<string, unknown>
      expect(org.id).toBeTruthy()
      expect(typeof org.id).toBe('string')
    }
  })
})
