/**
 * Flow 3: GitHub OAuth Login
 *
 * Tests the GitHub OAuth auth flow:
 *   1. Navigate to id.org.ai/login?provider=GitHubOAuth
 *   2. Redirects to GitHub consent screen
 *   3. Log in with test GitHub account
 *   4. GitHub redirects back → WorkOS → /callback
 *   5. Verify: JWT includes githubId claim
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { newPage, closeBrowser, getAuthCookie } from './helpers/browser'
import { decodeJwtPayload, assertJwtClaims, assertGitHubIdClaim } from './helpers/jwt'
import type { Page } from 'playwright'

const ID_URL = process.env.ID_URL || 'https://oauth.do'
const GITHUB_EMAIL = process.env.E2E_GITHUB_EMAIL
const GITHUB_PASSWORD = process.env.E2E_GITHUB_PASSWORD

describe('GitHub OAuth Login', () => {
  let page: Page

  beforeAll(async () => {
    if (!GITHUB_EMAIL || !GITHUB_PASSWORD) {
      console.warn('Skipping GitHub OAuth tests: E2E_GITHUB_EMAIL and/or E2E_GITHUB_PASSWORD not set')
      return
    }

    page = await newPage()
  }, 30_000)

  afterAll(async () => {
    await closeBrowser()
  })

  it('should redirect to GitHub when provider=GitHubOAuth', async () => {
    if (!GITHUB_EMAIL || !GITHUB_PASSWORD) return

    await page.goto(`${ID_URL}/login?provider=GitHubOAuth`)

    // Should redirect through WorkOS to GitHub
    await page.waitForURL(/github\.com/, { timeout: 15_000 })
    expect(page.url()).toMatch(/github\.com/)
  })

  it('should authenticate with GitHub credentials', async () => {
    if (!GITHUB_EMAIL || !GITHUB_PASSWORD) return

    // Fill in GitHub login form
    const loginField = await page.$('#login_field')
    if (loginField) {
      await page.fill('#login_field', GITHUB_EMAIL)
      await page.fill('#password', GITHUB_PASSWORD)
      await page.click('[name="commit"]')
    }

    // Handle potential 2FA or consent screen
    // If the app was already authorized, GitHub auto-redirects
    const authorizeBtn = await page.$('#js-oauth-authorize-btn').catch(() => null)
    if (authorizeBtn) {
      await authorizeBtn.click()
    }

    // Wait for the redirect chain to complete back to the identity worker
    await page.waitForURL((url) => {
      const u = url.toString()
      return (u.includes('oauth.do') || u.includes('id.org.ai') || u.includes('auth.headless.ly'))
        && !u.includes('/callback') && !u.includes('github.com')
    }, { timeout: 30_000 })

    // Verify auth cookie was set
    const jwt = await getAuthCookie(page)
    expect(jwt).toBeTruthy()
  }, 60_000)

  it('should have correct JWT claims with githubId', async () => {
    if (!GITHUB_EMAIL || !GITHUB_PASSWORD) return

    const jwt = await getAuthCookie(page)
    expect(jwt).toBeTruthy()

    const claims = decodeJwtPayload(jwt!)
    assertJwtClaims(claims)
    assertGitHubIdClaim(claims)
  })
})
