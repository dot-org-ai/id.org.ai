/**
 * Flow 2: Magic Link Login via .do/email catch-all
 *
 * Tests the magic link auth flow:
 *   1. Navigate to id.org.ai/login
 *   2. WorkOS AuthKit sends magic link email
 *   3. Poll email.dotdo.workers.dev for the email
 *   4. Extract magic link URL from email HTML
 *   5. Navigate to magic link → WorkOS validates → /callback → cookie
 *   6. Verify authenticated
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { newPage, closeBrowser, getAuthCookie } from './helpers/browser'
import { waitForEmail, extractMagicLink } from './helpers/email'
import { decodeJwtPayload, assertJwtClaims } from './helpers/jwt'
import { ensureTestUser } from './helpers/workos-setup'
import type { Page } from 'playwright'

const ID_URL = process.env.ID_URL || 'https://oauth.do'
const TEST_EMAIL = process.env.E2E_MAGIC_LINK_EMAIL || 'e2e-magic-link@emails.do'
const TEST_PASSWORD = process.env.E2E_AUTH_PASSWORD
const WORKOS_API_KEY = process.env.WORKOS_API_KEY

describe('Magic Link Login', () => {
  let page: Page
  let testStartTs: number

  beforeAll(async () => {
    if (!WORKOS_API_KEY) {
      console.warn('Skipping magic link tests: WORKOS_API_KEY not set')
      return
    }

    // Ensure user exists (magic link still requires an existing user in WorkOS)
    if (TEST_PASSWORD) {
      await ensureTestUser(WORKOS_API_KEY, TEST_EMAIL, TEST_PASSWORD)
    }

    testStartTs = Date.now()
    page = await newPage()
  }, 30_000)

  afterAll(async () => {
    await closeBrowser()
  })

  it('should request a magic link email', async () => {
    if (!WORKOS_API_KEY) return

    await page.goto(`${ID_URL}/login`)
    await page.waitForTimeout(2000)

    const url = page.url()

    if (url.includes('workos.com') || url.includes('authkit')) {
      // WorkOS AuthKit — enter email
      await page.waitForSelector('input[type="email"], input[name="email"]', { timeout: 10_000 })
      await page.fill('input[type="email"], input[name="email"]', TEST_EMAIL)

      // Look for magic link / email link option
      // AuthKit may show "Sign in with email" or "Magic link" button
      const magicLinkBtn = await page.$('text=magic link')
        ?? await page.$('text=email link')
        ?? await page.$('text=Email me a sign-in link')
        ?? await page.$('[data-testid="magic-link"]')

      if (magicLinkBtn) {
        await magicLinkBtn.click()
      } else {
        // If no explicit magic link button, submit the email form
        // WorkOS may send a magic link automatically depending on configuration
        await page.click('button[type="submit"]')
      }

      // Wait briefly for email to be sent
      await page.waitForTimeout(3000)
    }
  }, 30_000)

  it('should receive the magic link email', async () => {
    if (!WORKOS_API_KEY) return

    const email = await waitForEmail(TEST_EMAIL, {
      timeoutMs: 60_000,
      afterTs: testStartTs,
    })

    expect(email.subject).toBeTruthy()
    expect(email.html_body || email.text_body).toBeTruthy()
  }, 90_000)

  it('should authenticate via magic link', async () => {
    if (!WORKOS_API_KEY) return

    const email = await waitForEmail(TEST_EMAIL, {
      timeoutMs: 10_000,
      afterTs: testStartTs,
    })

    const magicLinkUrl = extractMagicLink(email.html_body)
    expect(magicLinkUrl).toMatch(/^https:\/\//)

    // Navigate to the magic link
    await page.goto(magicLinkUrl)

    // Wait for the redirect chain to complete
    await page.waitForURL((url) => {
      const u = url.toString()
      return u.includes('id.org.ai') && !u.includes('/callback') && !u.includes('workos.com')
    }, { timeout: 30_000 })

    // Verify auth cookie was set
    const jwt = await getAuthCookie(page)
    expect(jwt).toBeTruthy()

    const claims = decodeJwtPayload(jwt!)
    assertJwtClaims(claims)
    expect(claims.email).toBe(TEST_EMAIL)
  }, 60_000)
})
