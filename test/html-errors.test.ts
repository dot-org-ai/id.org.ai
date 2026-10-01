/**
 * B1 (docs/product-update/spec/backend.md#b1, prompts/04-errors-and-security.md):
 * browsers get the error template with a request ID; API callers keep
 * byte-identical JSON; a bad client or redirect_uri renders 7a and never
 * redirects.
 */
import { describe, it, expect } from 'vitest'
import { SELF } from 'cloudflare:test'
import { Hono } from 'hono'
import { wantsHtml } from '../worker/middleware/html-errors'
import { kindForApiError } from '../worker/ui/errors'

const BASE = 'https://id.org.ai'
const BROWSER = { accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'sec-fetch-mode': 'navigate' }
const API = { accept: 'application/json', 'sec-fetch-mode': 'cors' }

async function probe(headers: Record<string, string>, method = 'GET'): Promise<boolean> {
  const app = new Hono()
  app.all('*', (c) => c.text(String(wantsHtml(c))))
  return (await (await app.request('/x', { method, headers })).text()) === 'true'
}

describe('wantsHtml', () => {
  it('is true for browser navigations and form posts, false for fetch and curl', async () => {
    expect(await probe(BROWSER)).toBe(true) // address bar
    expect(await probe({ accept: 'text/html', 'sec-fetch-mode': 'navigate' }, 'POST')).toBe(true) // form post
    expect(await probe({ 'sec-fetch-mode': 'navigate' })).toBe(true) // navigation without Accept
    expect(await probe(API)).toBe(false) // fetch() asking for JSON
    expect(await probe({ accept: '*/*' })).toBe(false) // curl
    expect(await probe({})).toBe(false)
  })
})

async function registerClient(): Promise<string> {
  const res = await SELF.fetch(`${BASE}/oauth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: 'HTML errors test', redirect_uris: ['https://app.example.com/cb'], token_endpoint_auth_method: 'none' }),
  })
  return ((await res.json()) as { client_id: string }).client_id
}

function authorizeUrl(params: Record<string, string>): string {
  const u = new URL(`${BASE}/oauth/authorize`)
  for (const [k, v] of Object.entries({ response_type: 'code', code_challenge: 'x'.repeat(43), code_challenge_method: 'S256', state: 's', ...params })) u.searchParams.set(k, v)
  return u.toString()
}

describe('7a: a bad client or redirect_uri never redirects', () => {
  it('an unknown client: 7a with a request ID, the security headers, and no Location', async () => {
    const res = await SELF.fetch(authorizeUrl({ client_id: 'nope', redirect_uri: 'https://attacker.example/steal' }), { headers: BROWSER, redirect: 'manual' })
    expect(res.status).toBe(400)
    expect(res.headers.get('location')).toBeNull()
    expect(res.headers.get('content-type')).toBe('text/html; charset=utf-8')
    expect(res.headers.get('content-security-policy')).toContain("frame-ancestors 'none'")
    expect(res.headers.get('cache-control')).toBe('no-store')
    const html = await res.text()
    expect(html).toContain('We don’t recognise this app')
    const requestId = res.headers.get('x-request-id')!
    expect(requestId).toMatch(/^req_/)
    expect(html).toContain(requestId)
  })

  it('an unregistered redirect_uri: 7a naming the app’s attempt, the attacker URL as text only', async () => {
    const clientId = await registerClient()
    const attacker = 'https://attacker.example/steal?x=<b>1</b>'
    const res = await SELF.fetch(authorizeUrl({ client_id: clientId, redirect_uri: attacker }), { headers: BROWSER, redirect: 'manual' })
    expect(res.status).toBe(400)
    expect(res.headers.get('location')).toBeNull()
    const html = await res.text()
    expect(html).toContain('We stopped this sign-in')
    expect(html).toContain('redirect_uri') // the developer details
    expect(html).toContain('https://attacker.example/steal?x=&lt;b&gt;1&lt;/b&gt;') // shown, escaped
    expect(html).not.toMatch(/href="https:\/\/attacker\.example/) // never a link
    expect(html).not.toContain('<b>1</b>')
  })

  it('API callers keep byte-identical JSON', async () => {
    const res = await SELF.fetch(authorizeUrl({ client_id: 'nope', redirect_uri: 'https://attacker.example/steal' }), { headers: API, redirect: 'manual' })
    expect(res.status).toBe(400)
    expect(res.headers.get('content-type')).toContain('application/json')
    expect(await res.text()).toBe('{"error":"invalid_client","error_description":"Unknown client_id"}')
    expect(res.headers.get('x-request-id')).toMatch(/^req_/)
  })
})

describe('the catch-all 404', () => {
  it('is the not-found page for a navigation, JSON for an API caller', async () => {
    const page = await SELF.fetch(`${BASE}/no/such/page`, { headers: BROWSER })
    expect(page.status).toBe(404)
    expect(await page.text()).toContain('Page not found')
    const api = await SELF.fetch(`${BASE}/no/such/page`, { headers: API })
    expect(api.status).toBe(404)
    expect(await api.text()).toBe('{"error":"not_found","error_description":"The requested endpoint does not exist"}')
  })
})

describe('browser-facing errors render the template; APIs never do', () => {
  it('/api/callback without state shows the template to a browser', async () => {
    const res = await SELF.fetch(`${BASE}/api/callback?code=x`, { headers: BROWSER, redirect: 'manual' })
    expect(res.status).toBe(400)
    expect(res.headers.get('content-type')).toBe('text/html; charset=utf-8')
    expect(await res.text()).toContain('We couldn’t finish this')
  })

  it('an /api route keeps JSON even when the caller sends Accept: text/html', async () => {
    const res = await SELF.fetch(`${BASE}/api/orgs`, { headers: BROWSER })
    expect(res.status).toBe(401)
    expect(res.headers.get('content-type')).toContain('application/json')
  })

  it('an expired magic-link flow is 7b', async () => {
    const res = await SELF.fetch(`${BASE}/magic-link/flw_does_not_exist`, { headers: BROWSER })
    expect(res.status).toBe(410)
    const html = await res.text()
    expect(html).toContain('This link has expired')
    expect(html).toContain('Sign-in links last 10 minutes and work once.')
  })
})

describe('kindForApiError', () => {
  it('maps API errors onto the catalogue', () => {
    expect(kindForApiError(404, 'not_found')).toBe('not_found')
    expect(kindForApiError(429, 'rate_limited')).toBe('rate_limited')
    expect(kindForApiError(400, 'invalid_client', 'Unknown client_id')).toBe('invalid_client')
    expect(kindForApiError(400, 'invalid_request', 'Invalid redirect_uri')).toBe('redirect_not_registered')
    expect(kindForApiError(403, 'forbidden', 'Invalid or expired CSRF token — please try logging in again')).toBe('csrf')
    expect(kindForApiError(400, 'invalid_grant', 'Invalid or expired auth code')).toBe('expired')
    expect(kindForApiError(502, 'server_error')).toBe('server_error')
    expect(kindForApiError(400, 'invalid_request', 'Missing state parameter')).toBe('bad_request')
  })
})
