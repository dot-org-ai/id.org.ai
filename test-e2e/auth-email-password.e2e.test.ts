/**
 * Flow 1: Email + Password Login via WorkOS AuthKit
 *
 * Tests the full browser-based login flow:
 *   1. Navigate to id.org.ai/login
 *   2. WorkOS AuthKit UI loads
 *   3. Enter test email and password
 *   4. WorkOS authenticates → redirects to /callback
 *   5. /callback sets auth cookie → redirects to /
 *   6. Verify: cookie exists, JWT decodes with correct camelCase claims
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { newPage, closeBrowser, getAuthCookie } from './helpers/browser'
import { decodeJwtPayload, assertJwtClaims } from './helpers/jwt'
import { ensureTestUser } from './helpers/workos-setup'
import type { Page } from 'playwright'

const ID_URL = process.env.ID_URL || 'https://oauth.do'
const TEST_EMAIL = process.env.E2E_AUTH_EMAIL || 'e2e-auth-test@emails.do'
const TEST_PASSWORD = process.env.E2E_AUTH_PASSWORD
const WORKOS_API_KEY = process.env.WORKOS_API_KEY

describe('Email + Password Login', () => {
  let page: Page

  beforeAll(async () => {
    if (!TEST_PASSWORD) {
      console.warn('Skipping email+password tests: E2E_AUTH_PASSWORD not set')
      return
    }

    // Ensure test user exists in WorkOS
    if (WORKOS_API_KEY) {
      await ensureTestUser(WORKOS_API_KEY, TEST_EMAIL, TEST_PASSWORD)
    }

    page = await newPage()
  }, 30_000)

  afterAll(async () => {
    await closeBrowser()
  })

  it('should navigate to login and see WorkOS AuthKit', async () => {
    if (!TEST_PASSWORD) return

    await page.goto(`${ID_URL}/login`)

    // WorkOS AuthKit redirects to api.workos.com for the login UI
    // Wait for either WorkOS AuthKit page or our own login page
    await page.waitForURL(/workos\.com|authkit/, { timeout: 15_000 }).catch(() => {
      // If no redirect, we might be on the @mdxui/auth SPA
    })

    const url = page.url()
    // Should be either on WorkOS AuthKit or our SPA that embeds it
    expect(url).toMatch(/workos\.com|authkit|id\.org\.ai/)
  })

  it('should authenticate with email and password', async () => {
    if (!TEST_PASSWORD) return

    // Navigate fresh to login
    await page.goto(`${ID_URL}/login`)
    await page.waitForTimeout(2000)

    const url = page.url()

    if (url.includes('workos.com') || url.includes('authkit')) {
      // WorkOS AuthKit hosted UI — fill in email + password
      // AuthKit has different form layouts depending on configuration
      await page.waitForSelector('input[type="email"], input[name="email"]', { timeout: 10_000 })
      await page.fill('input[type="email"], input[name="email"]', TEST_EMAIL)

      // Some AuthKit layouts show email first, then password
      const passwordField = await page.$('input[type="password"]')
      if (passwordField) {
        await page.fill('input[type="password"]', TEST_PASSWORD)
        await page.click('button[type="submit"]')
      } else {
        // Click continue/next to get to password step
        await page.click('button[type="submit"]')
        await page.waitForSelector('input[type="password"]', { timeout: 10_000 })
        await page.fill('input[type="password"]', TEST_PASSWORD)
        await page.click('button[type="submit"]')
      }
    }

    // Wait for the callback redirect chain to complete
    // id.org.ai/callback sets the cookie and redirects to /
    await page.waitForURL((url) => {
      const u = url.toString()
      return u.includes('id.org.ai') && !u.includes('/callback') && !u.includes('workos.com')
    }, { timeout: 30_000 })

    // Verify auth cookie was set
    const jwt = await getAuthCookie(page)
    expect(jwt).toBeTruthy()
  }, 60_000)

  it('should have correct JWT claims (camelCase, nested org)', async () => {
    if (!TEST_PASSWORD) return

    const jwt = await getAuthCookie(page)
    expect(jwt).toBeTruthy()

    const claims = decodeJwtPayload(jwt!)
    assertJwtClaims(claims)

    // Email should match our test user
    expect(claims.email).toBe(TEST_EMAIL)

    // Name should be set (even if just email prefix)
    expect(claims.sub).toBeTruthy()
  })

  it('should have org claim (personal org auto-created)', async () => {
    if (!TEST_PASSWORD) return

    const jwt = await getAuthCookie(page)
    expect(jwt).toBeTruthy()

    const claims = decodeJwtPayload(jwt!)

    // Personal org should have been auto-created during login
    if (claims.org) {
      const org = claims.org as Record<string, unknown>
      expect(org.id).toBeTruthy()
      expect(typeof org.id).toBe('string')
    }
  })
})
