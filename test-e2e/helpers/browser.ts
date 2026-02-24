/**
 * Browser automation helper for E2E auth tests.
 *
 * Launches a real Chrome process separately, then connects Playwright via CDP.
 * Uses CDP-level script injection to override navigator.webdriver BEFORE any page loads,
 * which prevents Cloudflare Turnstile from detecting automation.
 */

import { chromium, type Browser, type BrowserContext, type Page } from 'playwright'
import { spawn, type ChildProcess } from 'child_process'
import { existsSync, mkdtempSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'

let browser: Browser | null = null
let context: BrowserContext | null = null
let chromeProcess: ChildProcess | null = null
let tempUserDataDir: string | null = null

const CHROME_PATHS = ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable']

function findChrome(): string {
  for (const p of CHROME_PATHS) {
    if (existsSync(p)) return p
  }
  throw new Error('Chrome not found. Install Google Chrome to run E2E tests.')
}

/**
 * Script injected via CDP before ANY page JavaScript runs.
 * Hides all automation signals that Cloudflare Turnstile checks.
 */
const STEALTH_SCRIPT = `
  Object.defineProperty(navigator, 'webdriver', { get: () => undefined, configurable: true });
  try { delete navigator.__proto__.webdriver; } catch(e) {}

  if (!window.chrome) window.chrome = {};
  if (!window.chrome.runtime) window.chrome.runtime = {};

  const origQuery = window.navigator.permissions.query.bind(window.navigator.permissions);
  window.navigator.permissions.query = (p) =>
    p.name === 'notifications'
      ? Promise.resolve({ state: Notification.permission })
      : origQuery(p);

  for (const p of Object.getOwnPropertyNames(window)) {
    if (p.startsWith('cdc_')) { try { delete window[p]; } catch(e) {} }
  }
`

/**
 * Launch a real Chrome process and connect Playwright via CDP.
 * Chrome is launched WITHOUT Playwright's automation flags, so Turnstile sees a normal browser.
 * CDP-injected stealth script removes navigator.webdriver before any page JS runs.
 */
export async function launchBrowser(): Promise<BrowserContext> {
  if (context) return context

  const chromePath = findChrome()
  tempUserDataDir = mkdtempSync(join(tmpdir(), 'e2e-chrome-'))

  const chrome = spawn(
    chromePath,
    [
      '--remote-debugging-port=0',
      `--user-data-dir=${tempUserDataDir}`,
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-default-apps',
      '--disable-extensions',
      '--disable-sync',
      '--disable-translate',
      '--metrics-recording-only',
      '--disable-hang-monitor',
      '--disable-prompt-on-repost',
      '--disable-client-side-phishing-detection',
      '--password-store=basic',
      '--use-mock-keychain',
      '--disable-component-update',
      '--disable-background-timer-throttling',
      '--disable-backgrounding-occluded-windows',
      '--disable-renderer-backgrounding',
      '--disable-ipc-flooding-protection',
      '--disable-blink-features=AutomationControlled',
      '--window-size=1280,900',
    ],
    { stdio: ['pipe', 'pipe', 'pipe'] },
  )

  chromeProcess = chrome

  const wsUrl = await new Promise<string>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Chrome startup timeout (15s)')), 15_000)
    let stderrBuf = ''
    chrome.stderr?.on('data', (data: Buffer) => {
      stderrBuf += data.toString()
      const match = stderrBuf.match(/DevTools listening on (ws:\/\/\S+)/)
      if (match) {
        clearTimeout(timeout)
        resolve(match[1])
      }
    })
    chrome.on('error', (err) => {
      clearTimeout(timeout)
      reject(err)
    })
    chrome.on('exit', (code) => {
      clearTimeout(timeout)
      reject(new Error(`Chrome exited with code ${code} before DevTools ready`))
    })
  })

  browser = await chromium.connectOverCDP(wsUrl)

  // Create a NEW context (not default) so we can inject stealth scripts
  context = await browser.newContext({ ignoreHTTPSErrors: true })

  // Inject stealth script via CDP on a throwaway page, then close it
  const setupPage = await context.newPage()
  const cdp = await setupPage.context().newCDPSession(setupPage)
  await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: STEALTH_SCRIPT })
  await cdp.detach()
  await setupPage.close()

  // Also add via context.addInitScript as a fallback for subsequent pages
  await context.addInitScript(STEALTH_SCRIPT)

  return context
}

/**
 * Get a new page from the shared browser context.
 * Each page gets the stealth script injected via both CDP and context.addInitScript.
 */
export async function newPage(): Promise<Page> {
  const ctx = await launchBrowser()
  const page = await ctx.newPage()

  // Belt-and-suspenders: also inject via CDP on this specific page
  try {
    const cdp = await page.context().newCDPSession(page)
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: STEALTH_SCRIPT })
    await cdp.detach()
  } catch {
    // CDP injection is best-effort; context.addInitScript should cover it
  }

  return page
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
  if (chromeProcess) {
    chromeProcess.kill('SIGTERM')
    await new Promise((r) => setTimeout(r, 1000))
    if (!chromeProcess.killed) chromeProcess.kill('SIGKILL')
    chromeProcess = null
  }
  if (tempUserDataDir) {
    rmSync(tempUserDataDir, { recursive: true, force: true })
    tempUserDataDir = null
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

  const single = filtered.find((c) => c.name === 'auth')
  if (single) return single.value

  let result = ''
  for (let i = 0; ; i++) {
    const chunk = filtered.find((c) => c.name === `auth.${i}`)
    if (!chunk) break
    result += chunk.value
  }

  return result || null
}

/**
 * Check if a URL is the AuthKit login page.
 * Matches: login.oauth.do, login.org.ai, *.workos.com, authkit.*
 */
export function isAuthKitUrl(url: string): boolean {
  return url.includes('login.oauth.do') || url.includes('login.org.ai') || url.includes('workos.com') || url.includes('authkit')
}

/**
 * Check if a URL is "back home" — on the identity worker, past the callback.
 * True when on oauth.do/id.org.ai/auth.headless.ly but NOT on /callback or the AuthKit login.
 */
export function isPostCallback(url: string): boolean {
  return (url.includes('oauth.do') || url.includes('id.org.ai') || url.includes('auth.headless.ly')) && !url.includes('/callback') && !isAuthKitUrl(url)
}

/**
 * Fill email + password in AuthKit and submit.
 */
export async function fillAuthKitCredentials(page: Page, email: string, password: string) {
  await page.waitForSelector('input[type="email"], input[name="email"]', { timeout: 10_000 })
  await page.fill('input[type="email"], input[name="email"]', email)

  const passwordField = await page.$('input[type="password"]')
  if (passwordField) {
    await page.fill('input[type="password"]', password)
    await page.click('button[type="submit"]')
  } else {
    await page.click('button[type="submit"]')
    await page.waitForSelector('input[type="password"]', { timeout: 10_000 })
    await page.fill('input[type="password"]', password)
    await page.click('button[type="submit"]')
  }
}

/**
 * Handle email verification code if AuthKit requires it.
 * Waits for the email pipeline to deliver the verification email to ClickHouse,
 * extracts the 6-digit code, and enters it into AuthKit's individual digit inputs.
 * Returns true if verification was needed and completed, false if not needed.
 */
export async function handleEmailVerification(page: Page, email: string, opts?: { timeoutMs?: number }): Promise<boolean> {
  const timeout = opts?.timeoutMs ?? 60_000

  // Check if we're on the email verification page
  await page.waitForTimeout(2000)
  const url = page.url()
  if (!url.includes('email-verification') && !url.includes('verify')) {
    return false
  }

  console.log('[browser] Email verification required — waiting for email pipeline...')

  // Wait 15s for the email to arrive through the pipeline:
  // WorkOS → email → Cloudflare Email Routing → email worker → ClickHouse
  await page.waitForTimeout(15_000)

  const { waitForEmail, extractVerificationCode } = await import('./email.js')
  const start = Date.now()

  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      // Look for emails received in the last 2 minutes (covers pipeline latency)
      const emailData = await waitForEmail(email, {
        timeoutMs: Math.max(timeout - (Date.now() - start), 10_000),
        afterTs: Date.now() - 2 * 60 * 1000,
        pollMs: 3_000,
      })
      const code = extractVerificationCode(emailData.text || emailData.html || '')

      if (!code) {
        console.log('[browser] Email found but no 6-digit code in body')
        return false
      }

      console.log(`[browser] Verification code: ${code}`)

      // Focus first input and type digits sequentially — AuthKit auto-advances
      const firstInput = await page.$('input[inputmode="numeric"], input[autocomplete="one-time-code"], input[type="text"]')
      if (firstInput) await firstInput.click()
      await page.keyboard.type(code, { delay: 200 })

      console.log('[browser] Entered code, waiting for redirect...')

      // Wait for the code to be validated and redirect to happen
      for (let j = 0; j < 15; j++) {
        await page.waitForTimeout(2000)
        const currentUrl = page.url()
        if (!currentUrl.includes('email-verification') && !currentUrl.includes('login.oauth.do')) {
          console.log('[browser] Verification complete — redirected')
          return true
        }
        // Check for "Invalid" error
        const body = await page.textContent('body').catch(() => '')
        if (body?.includes('Invalid one-time code')) {
          console.log(`[browser] Code invalid (attempt ${attempt + 1}), clicking Resend...`)
          const resendBtn = await page.$('a:has-text("Resend"), button:has-text("Resend")')
          if (resendBtn) await resendBtn.click()
          await page.waitForTimeout(15_000) // Wait for resent email
          break // Retry with next code
        }
      }
    } catch (err) {
      console.log(`[browser] Attempt ${attempt + 1} failed:`, (err as Error).message?.slice(0, 100))
    }
  }

  console.log('[browser] Email verification failed after 3 attempts')
  return false
}

/**
 * Wait for a navigation to complete after a redirect chain.
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
