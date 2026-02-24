/**
 * Flow 2: Magic Link Login via .do/email catch-all
 *
 * Tests the magic link auth flow using Playwright + email polling:
 *   1. Navigate to oauth.do/login
 *   2. AuthKit login UI loads (login.oauth.do → login.org.ai)
 *   3. Enter test email, choose magic link / email code option
 *   4. AuthKit sends email to catch-all @emails.do
 *   5. Poll ClickHouse for the email
 *   6. Extract magic link URL or verification code from email
 *   7. Navigate to magic link or enter code → AuthKit validates → /callback → cookie
 *   8. Verify authenticated, JWT claims correct
 *
 * Prerequisites:
 *   - E2E_AUTH_PASSWORD must be set (indicates test user exists)
 *   - Test user must exist in WorkOS (created by email+password test or manually)
 *   - emails.do catch-all must be configured in Cloudflare Email Routing
 *   - WorkOS AuthKit must have magic link / email code auth method enabled
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { newPage, closeBrowser, getAuthCookie, isAuthKitUrl, isPostCallback, handleEmailVerification } from './helpers/browser'
import { waitForEmail, extractMagicLink, extractVerificationCode } from './helpers/email'
import { decodeJwtPayload, assertJwtClaims } from './helpers/jwt'
import type { Page } from 'playwright'

const ID_URL = process.env.ID_URL || 'https://oauth.do'
const TEST_EMAIL = process.env.E2E_MAGIC_LINK_EMAIL || 'e2e-auth-test@emails.do'
const TEST_PASSWORD = process.env.E2E_AUTH_PASSWORD

describe('Magic Link Login', () => {
  let page: Page
  let testStartTs: number
  let magicLinkAvailable = false

  beforeAll(async () => {
    if (!TEST_PASSWORD) {
      console.warn('Skipping magic link tests: E2E_AUTH_PASSWORD not set (test user may not exist)')
      return
    }

    testStartTs = Date.now()
    page = await newPage()
  }, 30_000)

  afterAll(async () => {
    await closeBrowser()
  })

  it('should request a magic link email via AuthKit', async () => {
    if (!TEST_PASSWORD) return

    await page.goto(`${ID_URL}/login`, { waitUntil: 'domcontentloaded' }).catch(() => {})
    await page.waitForTimeout(3000)

    const url = page.url()

    if (isAuthKitUrl(url)) {
      await page.waitForSelector('input[type="email"], input[name="email"]', { timeout: 10_000 })
      await page.fill('input[type="email"], input[name="email"]', TEST_EMAIL)

      // Look for magic link / email code option BEFORE submitting
      const magicLinkBtn = await page.$('text=magic link')
        ?? await page.$('text=email link')
        ?? await page.$('text=Email me a sign-in link')
        ?? await page.$('text=Sign in with email')
        ?? await page.$('[data-testid="magic-link"]')

      if (magicLinkBtn) {
        await magicLinkBtn.click()
        magicLinkAvailable = true
        await page.waitForTimeout(3000)
        return
      }

      // Submit email first, then look for magic link option
      await page.click('button[type="submit"]')
      await page.waitForTimeout(2000)

      // Check for email code / magic link button on the password page
      const emailCodeBtn = await page.$('text=email code')
        ?? await page.$('text=email link')
        ?? await page.$('text=Email me a code')
        ?? await page.$('text=Use a different method')

      if (emailCodeBtn) {
        await emailCodeBtn.click()
        magicLinkAvailable = true
        await page.waitForTimeout(3000)
      } else {
        console.warn('[magic-link] No magic link / email code option found in AuthKit UI — test will skip remaining assertions')
        console.warn('[magic-link] WorkOS AuthKit may not have magic link auth method enabled')
      }
    }
  }, 30_000)

  it('should receive the magic link email at emails.do', async () => {
    if (!TEST_PASSWORD) return
    if (!magicLinkAvailable) {
      console.warn('Skipping: magic link option not available in AuthKit')
      return
    }

    const url = page.url()

    // If we ended up on email-verification (6-digit code flow), handle it directly
    if (url.includes('email-verification') || url.includes('verify')) {
      const verified = await handleEmailVerification(page, TEST_EMAIL, { timeoutMs: 90_000 })
      expect(verified).toBe(true)
      return
    }

    const email = await waitForEmail(TEST_EMAIL, {
      timeoutMs: 60_000,
      afterTs: testStartTs,
    })

    expect(email.subject).toBeTruthy()
    expect(email.html || email.text).toBeTruthy()

    // Check if it's a verification code or a magic link
    const code = extractVerificationCode(email.text || email.html || '')
    if (code) {
      // It's a 6-digit code, not a magic link — enter it
      const firstInput = await page.$('input[inputmode="numeric"], input[autocomplete="one-time-code"], input[type="text"]')
      if (firstInput) await firstInput.click()
      await page.keyboard.type(code, { delay: 200 })
      await page.waitForTimeout(5000)
    }
  }, 90_000)

  it('should authenticate via the magic link or code and get JWT', async () => {
    if (!TEST_PASSWORD) return
    if (!magicLinkAvailable) {
      console.warn('Skipping: magic link option not available in AuthKit')
      return
    }

    // Check if we're already authenticated from code entry
    if (isPostCallback(page.url())) {
      const jwt = await getAuthCookie(page)
      expect(jwt).toBeTruthy()

      const claims = decodeJwtPayload(jwt!)
      assertJwtClaims(claims)
      expect(claims.email).toBe(TEST_EMAIL)
      return
    }

    // Try to get the magic link from email
    try {
      const email = await waitForEmail(TEST_EMAIL, {
        timeoutMs: 10_000,
        afterTs: testStartTs,
      })

      const magicLinkUrl = extractMagicLink(email.html)
      expect(magicLinkUrl).toMatch(/^https:\/\//)

      await page.goto(magicLinkUrl, { waitUntil: 'domcontentloaded' }).catch(() => {})

      for (let i = 0; i < 20; i++) {
        await page.waitForTimeout(2000)
        if (isPostCallback(page.url())) break
      }
    } catch {
      // Magic link extraction may fail if the email was a code — that's fine
    }

    const jwt = await getAuthCookie(page)
    expect(jwt).toBeTruthy()

    const claims = decodeJwtPayload(jwt!)
    assertJwtClaims(claims)
    expect(claims.email).toBe(TEST_EMAIL)
  }, 60_000)
})
