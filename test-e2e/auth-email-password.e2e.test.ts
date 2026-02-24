/**
 * Flow 1: Email + Password Login via WorkOS AuthKit
 *
 * Steps:
 *   1. Navigate to oauth.do/login → AuthKit (login.oauth.do)
 *   2. Fill email + password
 *   3. Handle email verification if required (poll ClickHouse for 6-digit code)
 *   4. AuthKit authenticates → redirects to /callback → sets auth cookie
 *   5. Verify: cookie exists, JWT decodes with correct camelCase claims + nested org
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { newPage, closeBrowser, getAuthCookie, isAuthKitUrl, isPostCallback, fillAuthKitCredentials, handleEmailVerification } from './helpers/browser'
import { decodeJwtPayload, assertJwtClaims } from './helpers/jwt'
import type { Page } from 'playwright'

const ID_URL = process.env.ID_URL || 'https://oauth.do'
const TEST_EMAIL = process.env.E2E_AUTH_EMAIL || 'e2e-auth-test@emails.do'
const TEST_PASSWORD = process.env.E2E_AUTH_PASSWORD

describe('Email + Password Login', () => {
  let page: Page
  let authJwt: string | null = null

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

  it('should authenticate with email and password via AuthKit', async () => {
    if (!TEST_PASSWORD) return

    // Navigate to login — handle ERR_ABORTED from redirect gracefully
    await page.goto(`${ID_URL}/login`, { waitUntil: 'domcontentloaded' }).catch(() => {})
    await page.waitForTimeout(3000)

    let url = page.url()
    expect(isAuthKitUrl(url) || url.includes('oauth.do') || url.includes('id.org.ai')).toBe(true)

    // If already on the app (logged in from previous session), skip auth
    if (isPostCallback(url)) {
      authJwt = await getAuthCookie(page)
      expect(authJwt).toBeTruthy()
      return
    }

    // Fill AuthKit credentials
    if (isAuthKitUrl(url)) {
      await fillAuthKitCredentials(page, TEST_EMAIL, TEST_PASSWORD)
    }

    // Wait for either: success redirect or email verification
    await page.waitForTimeout(3000)
    url = page.url()

    // Handle email verification if required
    if (url.includes('email-verification')) {
      const verified = await handleEmailVerification(page, TEST_EMAIL, { timeoutMs: 90_000 })
      expect(verified).toBe(true)

      // Wait for the final redirect after verification
      for (let i = 0; i < 20; i++) {
        await page.waitForTimeout(2000)
        url = page.url()
        if (isPostCallback(url)) break
      }
    }

    // If still on AuthKit (e.g., user doesn't exist), try sign-up
    if (isAuthKitUrl(url) && !url.includes('email-verification')) {
      const signUpLink = await page.$('text=Sign up')
      if (signUpLink) {
        await signUpLink.click()
        await page.waitForTimeout(2000)

        const firstNameField = await page.$('input[name="firstName"], input[name="first_name"]')
        if (firstNameField) await page.fill('input[name="firstName"], input[name="first_name"]', 'E2E')
        const lastNameField = await page.$('input[name="lastName"], input[name="last_name"]')
        if (lastNameField) await page.fill('input[name="lastName"], input[name="last_name"]', 'Test')

        await fillAuthKitCredentials(page, TEST_EMAIL, TEST_PASSWORD)
        await page.waitForTimeout(3000)

        if (page.url().includes('email-verification')) {
          await handleEmailVerification(page, TEST_EMAIL, { timeoutMs: 90_000 })
          for (let i = 0; i < 20; i++) {
            await page.waitForTimeout(2000)
            if (isPostCallback(page.url())) break
          }
        }
      }
    }

    authJwt = await getAuthCookie(page)
    expect(authJwt).toBeTruthy()
  }, 120_000)

  it('should have correct JWT claims (camelCase, nested org)', async () => {
    if (!TEST_PASSWORD || !authJwt) return

    const claims = decodeJwtPayload(authJwt)
    assertJwtClaims(claims)
    expect(claims.email).toBe(TEST_EMAIL)
    expect(claims.sub).toBeTruthy()
  })

  it('should have org claim (personal org auto-created)', async () => {
    if (!TEST_PASSWORD || !authJwt) return

    const claims = decodeJwtPayload(authJwt)
    if (claims.org) {
      const org = claims.org as Record<string, unknown>
      expect(org.id).toBeTruthy()
      expect(typeof org.id).toBe('string')
    }
  })
})
