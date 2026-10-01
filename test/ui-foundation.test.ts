/**
 * Auth UI foundation (docs/product-update/prompts/01-foundation.md):
 * the page renderer's security headers and CSP, request IDs, the design
 * gallery's flag gate, the hashed-asset cache header and the WorkOS base seam.
 */
import { describe, it, expect } from 'vitest'
import { SELF, env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test'
import worker from '../worker/index'
import assets from '../worker/ui/assets.json'
import { contentSecurityPolicy } from '../worker/ui/render'
import { newRequestId } from '../worker/middleware/request-id'
import { workosBase, isLocalStubOrigin, WORKOS_API_BASE_DEFAULT } from '../src/sdk/workos/base'
import type { Env } from '../worker/types'

const BASE = 'https://id.org.ai'

/** The worker with extra env vars (the test pool's bindings never set DESIGN_GALLERY). */
async function fetchWith(extra: Partial<Env>, path: string, init?: RequestInit): Promise<Response> {
  const ctx = createExecutionContext()
  const res = await worker.fetch(new Request(`${BASE}${path}`, init), { ...(env as unknown as Env), ...extra } as never, ctx)
  await waitOnExecutionContext(ctx)
  return res
}

const EXPECTED_CSP =
  "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' https: data:; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

describe('design gallery gate', () => {
  it('is a plain 404 without DESIGN_GALLERY', async () => {
    for (const path of ['/__design', '/__design/smoke', '/__design/smoke?state=x']) {
      const res = await SELF.fetch(`${BASE}${path}`)
      expect(res.status, path).toBe(404)
      expect(await res.text(), path).not.toContain('Design gallery')
    }
  })

  it('serves the index and fixtures with DESIGN_GALLERY=1', async () => {
    const index = await fetchWith({ DESIGN_GALLERY: '1' }, '/__design')
    expect(index.status).toBe(200)
    const html = await index.text()
    expect(html).toContain('Design gallery')
    // every manifest slug is listed
    expect(html).toContain('4b · Confirm device code')
    expect(html).toContain('8c')

    const smoke = await fetchWith({ DESIGN_GALLERY: '1' }, '/__design/smoke')
    expect(smoke.status).toBe(200)
    expect(await smoke.text()).toContain('<html lang="en" data-frozen="">')
  })

  it('does not treat other values as on', async () => {
    for (const v of ['true', '0', 'yes', '']) {
      const res = await fetchWith({ DESIGN_GALLERY: v }, '/__design')
      expect(res.status, v).toBe(404)
    }
  })

  it('404s an unknown slug or state', async () => {
    expect((await fetchWith({ DESIGN_GALLERY: '1' }, '/__design/nope')).status).toBe(404)
    expect((await fetchWith({ DESIGN_GALLERY: '1' }, '/__design/smoke?state=nope')).status).toBe(404)
  })
})

describe('renderPage', () => {
  it('sends every security header from spec/security.md', async () => {
    const res = await fetchWith({ DESIGN_GALLERY: '1' }, '/__design/smoke')
    expect(res.headers.get('content-type')).toBe('text/html; charset=utf-8')
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(res.headers.get('x-frame-options')).toBe('DENY')
    expect(res.headers.get('referrer-policy')).toBe('no-referrer')
    expect(res.headers.get('x-content-type-options')).toBe('nosniff')
    expect(res.headers.get('content-security-policy')).toBe(EXPECTED_CSP)
  })

  it('has no inline script or style', async () => {
    const html = await (await fetchWith({ DESIGN_GALLERY: '1' }, '/__design/smoke')).text()
    expect(html).not.toMatch(/\sstyle=/i)
    expect(html).not.toMatch(/<style[\s>]/i)
    // every <script> has a src
    for (const tag of html.match(/<script\b[^>]*>/gi) ?? []) expect(tag).toMatch(/\ssrc="/)
    expect(html).toContain(`<link rel="stylesheet" href="${assets['ui.css']}"/>`)
    expect(html.startsWith('<!doctype html><html lang="en"')).toBe(true)
  })

  it('extends form-action with validated origins only', () => {
    expect(contentSecurityPolicy(['https://app.example.com', 'http://127.0.0.1:3000', 'http://[::1]:57585'])).toContain(
      "form-action 'self' https://app.example.com http://127.0.0.1:3000 http://[::1]:57585;",
    )
    // anything that isn't a bare origin is dropped, so CSP can't be injected
    expect(
      contentSecurityPolicy(["https://a.com; script-src 'unsafe-inline'", 'javascript:alert(1)', 'https://b.com/path', 'https://u:p@c.com', 'https://d.com/', ' https://e.com']),
    ).toContain(
      "form-action 'self';",
    )
  })
})

describe('request IDs', () => {
  it('puts X-Request-Id on HTML and JSON responses', async () => {
    const html = await fetchWith({ DESIGN_GALLERY: '1' }, '/__design/smoke')
    expect(html.headers.get('x-request-id')).toMatch(/^req_[0-9A-Za-z]{8}$/)
    const json = await SELF.fetch(`${BASE}/health`)
    expect(json.headers.get('x-request-id')).toMatch(/^req_[0-9A-Za-z]{8}$/)
    const missing = await SELF.fetch(`${BASE}/definitely-not-a-route`)
    expect(missing.status).toBe(404)
    expect(missing.headers.get('x-request-id')).toMatch(/^req_[0-9A-Za-z]{8}$/)
  })

  it('adds the header to responses with immutable headers (ASSETS, redirects)', async () => {
    const asset = await SELF.fetch(`${BASE}/robots.txt`)
    expect(asset.status).toBe(200)
    expect(asset.headers.get('x-request-id')).toMatch(/^req_[0-9A-Za-z]{8}$/)
    await asset.arrayBuffer()
    const redirect = await SELF.fetch(`${BASE}/dash`, { redirect: 'manual' })
    expect(redirect.status).toBe(302)
    expect(redirect.headers.get('x-request-id')).toMatch(/^req_[0-9A-Za-z]{8}$/)
  })

  it('uses cf-ray when present, and never reflects anything else', async () => {
    const ray = await SELF.fetch(`${BASE}/health`, { headers: { 'cf-ray': '8f0c1d2e3a4b5c6d-MIA' } })
    expect(ray.headers.get('x-request-id')).toBe('8f0c1d2e3a4b5c6d-MIA')
    const junk = await SELF.fetch(`${BASE}/health`, { headers: { 'cf-ray': '<script>' } })
    expect(junk.headers.get('x-request-id')).toMatch(/^req_[0-9A-Za-z]{8}$/)
  })

  it('generates distinct ids', () => {
    const ids = new Set(Array.from({ length: 200 }, () => newRequestId()))
    expect(ids.size).toBe(200)
  })
})

describe('hashed assets', () => {
  it('serves the stylesheet and fonts with an immutable cache header', async () => {
    for (const path of [assets['ui.css'], '/fonts/geist/Geist-Variable.woff2', '/fonts/geist/GeistMono-Variable.woff2']) {
      const res = await SELF.fetch(`${BASE}${path}`)
      expect(res.status, path).toBe(200)
      expect(res.headers.get('cache-control'), path).toBe('public, max-age=31536000, immutable')
      await res.arrayBuffer()
    }
  })

  it('falls through for files that do not exist', async () => {
    const res = await SELF.fetch(`${BASE}/auth/ui.0000000000.css`)
    expect(res.status).toBe(404)
    expect(res.headers.get('cache-control')).not.toBe('public, max-age=31536000, immutable')
  })

  it('only treats content-hashed names as immutable', async () => {
    for (const path of ['/auth/ui.css', '/auth/../orgLogo.svg', '/fonts/orgLogo.svg']) {
      const res = await SELF.fetch(`${BASE}${path}`)
      expect(res.headers.get('cache-control'), path).not.toBe('public, max-age=31536000, immutable')
      await res.arrayBuffer()
    }
  })

  it('lets the fonts load cross-origin (email templates) but not the stylesheet', async () => {
    const font = await SELF.fetch(`${BASE}/fonts/geist/Geist-Variable.woff2`)
    expect(font.headers.get('access-control-allow-origin')).toBe('*')
    await font.arrayBuffer()
    const css = await SELF.fetch(`${BASE}${assets['ui.css']}`)
    expect(css.headers.get('access-control-allow-origin')).toBeNull()
    await css.arrayBuffer()
  })
})

describe('WorkOS base seam', () => {
  it('defaults to api.workos.com and honours loopback overrides only', () => {
    expect(workosBase(undefined)).toBe(WORKOS_API_BASE_DEFAULT)
    expect(workosBase({})).toBe(WORKOS_API_BASE_DEFAULT)
    expect(workosBase({ WORKOS_API_BASE: 'http://127.0.0.1:8788' })).toBe('http://127.0.0.1:8788')
    expect(workosBase({ WORKOS_API_BASE: 'http://localhost:8788/' })).toBe('http://localhost:8788')
    for (const bad of ['https://evil.example', 'http://127.0.0.1.evil.example', 'not a url', 'file:///etc/passwd']) {
      expect(workosBase({ WORKOS_API_BASE: bad }), bad).toBe(WORKOS_API_BASE_DEFAULT)
    }
  })

  it('only lets loopback origins keep their own callback against a local stub', () => {
    expect(isLocalStubOrigin({}, 'http://127.0.0.1:8787')).toBe(false)
    expect(isLocalStubOrigin({ WORKOS_API_BASE: 'http://127.0.0.1:8788' }, 'http://127.0.0.1:8787')).toBe(true)
    expect(isLocalStubOrigin({ WORKOS_API_BASE: 'http://127.0.0.1:8788' }, 'https://evil.example')).toBe(false)
  })

  it('the test env (production config) never sets WORKOS_API_BASE or DESIGN_GALLERY', () => {
    // vitest.config.ts blanks anything a local worker/.dev.vars sets
    const e = env as unknown as Env
    expect(e.WORKOS_API_BASE || undefined).toBeUndefined()
    expect(e.DESIGN_GALLERY || undefined).toBeUndefined()
    expect(workosBase(e)).toBe(WORKOS_API_BASE_DEFAULT)
    // no local feature flag leaks in either
    for (const [k, v] of Object.entries(e as unknown as Record<string, unknown>)) {
      if (/^(FEATURE_|DIRECT_|LEGACY_)/.test(k)) expect(v, k).not.toBe('1')
    }
  })
})
