/**
 * Flow 2: Magic Link Login via .do/email catch-all
 *
 * Tests the magic link auth flow using only Playwright + email polling:
 *   1. Navigate to oauth.do/login
 *   2. WorkOS AuthKit UI loads
 *   3. Enter test email, choose magic link option
 *   4. WorkOS sends magic link email to catch-all @emails.do
 *   5. Poll email.dotdo.workers.dev for the email
 *   6. Extract magic link URL from email HTML
 *   7. Navigate to magic link → WorkOS validates → /callback → cookie
 *   8. Verify authenticated, JWT claims correct
 *
 * Prerequisites:
 *   - E2E_AUTH_PASSWORD must be set (indicates test user exists)
 *   - Test user must exist in WorkOS (created by email+password test or manually)
 *   - emails.do catch-all must be configured in Cloudflare Email Routing
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { newPage, closeBrowser, getAuthCookie } from './helpers/browser'
import { waitForEmail, extractMagicLink } from './helpers/email'
import { decodeJwtPayload, assertJwtClaims } from './helpers/jwt'
import type { Page } from 'playwright'

const ID_URL = process.env.ID_URL || 'https://oauth.do'
const TEST_EMAIL = process.env.E2E_MAGIC_LINK_EMAIL || 'e2e-magic-link@emails.do'
const TEST_PASSWORD = process.env.E2E_AUTH_PASSWORD

describe('Magic Link Login', () => {
  let page: Page
  let testStartTs: number

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

    await page.goto(`${ID_URL}/login`)
    await page.waitForTimeout(2000)

    const url = page.url()

    if (url.includes('workos.com') || url.includes('authkit')) {
      // WorkOS AuthKit hosted UI — enter email
      await page.waitForSelector('input[type="email"], input[name="email"]', { timeout: 10_000 })
      await page.fill('input[type="email"], input[name="email"]', TEST_EMAIL)

      // Look for magic link / email link option
      // AuthKit may show "Sign in with email link", "Magic link", or similar
      const magicLinkBtn = await page.$('text=magic link')
        ?? await page.$('text=email link')
        ?? await page.$('text=Email me a sign-in link')
        ?? await page.$('text=Sign in with email')
        ?? await page.$('[data-testid="magic-link"]')

      if (magicLinkBtn) {
        await magicLinkBtn.click()
      } else {
        // Submit the form — AuthKit may auto-send a magic link depending on config
        await page.click('button[type="submit"]')
      }

      // Wait for email to be dispatched
      await page.waitForTimeout(3000)
    }
  }, 30_000)

  it('should receive the magic link email at emails.do', async () => {
    if (!TEST_PASSWORD) return

    const email = await waitForEmail(TEST_EMAIL, {
      timeoutMs: 60_000,
      afterTs: testStartTs,
    })

    expect(email.subject).toBeTruthy()
    expect(email.html_body || email.text_body).toBeTruthy()
  }, 90_000)

  it('should authenticate via the magic link URL', async () => {
    if (!TEST_PASSWORD) return

    const email = await waitForEmail(TEST_EMAIL, {
      timeoutMs: 10_000,
      afterTs: testStartTs,
    })

    const magicLinkUrl = extractMagicLink(email.html_body)
    expect(magicLinkUrl).toMatch(/^https:\/\//)

    // Navigate to the magic link in the browser
    await page.goto(magicLinkUrl)

    // Wait for the redirect chain: WorkOS → /callback → set cookie → /
    await page.waitForURL((url) => {
      const u = url.toString()
      return (u.includes('oauth.do') || u.includes('id.org.ai') || u.includes('auth.headless.ly'))
        && !u.includes('/callback')
        && !u.includes('workos.com')
    }, { timeout: 30_000 })

    // Verify auth cookie was set
    const jwt = await getAuthCookie(page)
    expect(jwt).toBeTruthy()

    const claims = decodeJwtPayload(jwt!)
    assertJwtClaims(claims)
    expect(claims.email).toBe(TEST_EMAIL)
  }, 60_000)
})
