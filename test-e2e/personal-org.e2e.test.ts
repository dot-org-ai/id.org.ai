/**
 * Flow 5: Personal Org Auto-Creation
 *
 * Tests that new users without an org membership
 * automatically get a personal org created during login.
 *
 * Steps:
 *   1. Create a fresh test user in WorkOS (no org membership)
 *   2. Log in via email+password
 *   3. Verify JWT org claim exists with { id, name }
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { newPage, closeBrowser, getAuthCookie } from './helpers/browser'
import { decodeJwtPayload, assertJwtClaims, assertNestedOrgClaim } from './helpers/jwt'
import { ensureTestUser, deleteTestUser, removeUserFromAllOrgs } from './helpers/workos-setup'
import type { Page } from 'playwright'

const ID_URL = process.env.ID_URL || 'https://oauth.do'
const WORKOS_API_KEY = process.env.WORKOS_API_KEY
const TEST_PASSWORD = process.env.E2E_AUTH_PASSWORD || 'E2eTest!Passw0rd'

// Unique email for this test to avoid collision with other test suites
const FRESH_USER_EMAIL = `e2e-personal-org-${Date.now()}@emails.do`

describe('Personal Org Auto-Creation', () => {
  let page: Page
  let freshUserId: string | null = null

  beforeAll(async () => {
    if (!WORKOS_API_KEY) {
      console.warn('Skipping personal org tests: WORKOS_API_KEY not set')
      return
    }

    // Create a fresh user with no org memberships
    freshUserId = await ensureTestUser(WORKOS_API_KEY, FRESH_USER_EMAIL, TEST_PASSWORD)

    // Remove from any orgs that may have been auto-assigned
    await removeUserFromAllOrgs(WORKOS_API_KEY, freshUserId)

    page = await newPage()
  }, 30_000)

  afterAll(async () => {
    // Clean up the test user
    if (WORKOS_API_KEY && freshUserId) {
      await deleteTestUser(WORKOS_API_KEY, freshUserId).catch(() => {})
    }
    await closeBrowser()
  })

  it('should log in as a user with no existing org', async () => {
    if (!WORKOS_API_KEY) return

    await page.goto(`${ID_URL}/login`)
    await page.waitForTimeout(2000)

    const url = page.url()

    if (url.includes('workos.com') || url.includes('authkit')) {
      await page.waitForSelector('input[type="email"], input[name="email"]', { timeout: 10_000 })
      await page.fill('input[type="email"], input[name="email"]', FRESH_USER_EMAIL)

      const passwordField = await page.$('input[type="password"]')
      if (passwordField) {
        await page.fill('input[type="password"]', TEST_PASSWORD)
        await page.click('button[type="submit"]')
      } else {
        await page.click('button[type="submit"]')
        await page.waitForSelector('input[type="password"]', { timeout: 10_000 })
        await page.fill('input[type="password"]', TEST_PASSWORD)
        await page.click('button[type="submit"]')
      }
    }

    await page.waitForURL((url) => {
      const u = url.toString()
      return u.includes('id.org.ai') && !u.includes('/callback') && !u.includes('workos.com')
    }, { timeout: 30_000 })

    const jwt = await getAuthCookie(page)
    expect(jwt).toBeTruthy()
  }, 60_000)

  it('should have auto-created a personal org in the JWT', async () => {
    if (!WORKOS_API_KEY) return

    const jwt = await getAuthCookie(page)
    expect(jwt).toBeTruthy()

    const claims = decodeJwtPayload(jwt!)
    assertJwtClaims(claims)

    // The key assertion: org should exist even though user had no org
    assertNestedOrgClaim(claims)

    const org = claims.org as Record<string, unknown>
    expect(org.id).toBeTruthy()
    // Personal org name is typically the user's name or email prefix
    if (org.name) {
      expect(typeof org.name).toBe('string')
    }
  })
})
