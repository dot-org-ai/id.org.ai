/**
 * Browser automation helper for E2E auth tests.
 *
 * Uses Playwright to drive a real browser through OAuth flows
 * on the live deployed workers (id.org.ai, WorkOS AuthKit, GitHub, Google).
 */

import { chromium, type Browser, type BrowserContext, type Page } from 'playwright'

let browser: Browser | null = null
let context: BrowserContext | null = null

/**
 * Launch browser (reused across tests in the same suite).
 */
export async function launchBrowser(): Promise<BrowserContext> {
  if (context) return context

  browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  })

  context = await browser.newContext({
    userAgent: 'headlessly-e2e-tests/1.0',
    ignoreHTTPSErrors: true,
  })

  return context
}

/**
 * Get a new page from the shared browser context.
 */
export async function newPage(): Promise<Page> {
  const ctx = await launchBrowser()
  return ctx.newPage()
}

/**
 * Close browser and clean up.
 */
export async function closeBrowser(): Promise<void> {
  if (context) {
    await context.close().catch(() => {})
    context = null
  }
  if (browser) {
    await browser.close().catch(() => {})
    browser = null
  }
}

/**
 * Extract all cookies from a page as a cookie string.
 */
export async function getCookieString(page: Page, url?: string): Promise<string> {
  const cookies = await page.context().cookies(url ? [url] : undefined)
  return cookies.map((c) => `${c.name}=${c.value}`).join('; ')
}

/**
 * Extract auth cookie (JWT) from the browser context for a given domain.
 * Handles both single `auth` and chunked `auth.0, auth.1, ...` cookies.
 */
export async function getAuthCookie(page: Page, domain?: string): Promise<string | null> {
  const allCookies = await page.context().cookies()
  const filtered = domain ? allCookies.filter((c) => c.domain.includes(domain)) : allCookies

  // Try single auth cookie
  const single = filtered.find((c) => c.name === 'auth')
  if (single) return single.value

  // Try chunked cookies
  let result = ''
  for (let i = 0; ; i++) {
    const chunk = filtered.find((c) => c.name === `auth.${i}`)
    if (!chunk) break
    result += chunk.value
  }

  return result || null
}

/**
 * Wait for a navigation to complete after a redirect chain.
 * Useful for OAuth flows that involve multiple redirects.
 */
export async function waitForFinalRedirect(page: Page, urlPattern: string | RegExp, timeoutMs = 30_000): Promise<void> {
  await page.waitForURL(urlPattern, { timeout: timeoutMs, waitUntil: 'networkidle' })
}

/**
 * Follow a redirect chain manually using fetch (no browser needed).
 * Returns the final response with all Set-Cookie headers collected.
 */
export async function followRedirects(
  url: string,
  opts?: { cookies?: string; maxRedirects?: number },
): Promise<{ url: string; status: number; headers: Headers; cookies: string[] }> {
  const maxRedirects = opts?.maxRedirects ?? 10
  const collectedCookies: string[] = []
  let currentUrl = url
  let cookieJar = opts?.cookies || ''

  for (let i = 0; i < maxRedirects; i++) {
    const res = await fetch(currentUrl, {
      redirect: 'manual',
      headers: cookieJar ? { Cookie: cookieJar } : {},
    })

    // Collect Set-Cookie headers
    res.headers.forEach((value, key) => {
      if (key.toLowerCase() === 'set-cookie') {
        collectedCookies.push(value)
        const nameValue = value.split(';')[0]
        cookieJar = cookieJar ? `${cookieJar}; ${nameValue}` : nameValue
      }
    })

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location')
      if (!location) break
      currentUrl = location.startsWith('http') ? location : new URL(location, currentUrl).toString()
      continue
    }

    return { url: currentUrl, status: res.status, headers: res.headers, cookies: collectedCookies }
  }

  return { url: currentUrl, status: 0, headers: new Headers(), cookies: collectedCookies }
}
