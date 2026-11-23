import { describe, expect, it } from 'vitest'
import { Card, CardFoot, Page } from './components'
import { contentSecurityPolicy, renderHtml } from './render'

describe('renderHtml', () => {
  it('writes the document shell with the hashed stylesheet and no inline style', async () => {
    const html = await renderHtml(
      <Page>
        <Card foot={<CardFoot>foot</CardFoot>}>body</Card>
      </Page>,
      { title: 'Sign in · id.org.ai', frozen: true },
    )
    expect(html.startsWith('<!doctype html><html lang="en" data-frozen="">')).toBe(true)
    expect(html).toContain('<title>Sign in · id.org.ai</title>')
    expect(html).toMatch(/<link rel="stylesheet" href="\/auth\/ui\.[0-9a-f]{10}\.css"\/>/)
    expect(html).not.toMatch(/\sstyle=/)
    const doc = new DOMParser().parseFromString(html, 'text/html')
    expect(doc.querySelectorAll('header, main, footer').length).toBe(3)
    expect(doc.querySelector('.id-card__foot')?.textContent).toBe('foot')
  })

  it('omits data-frozen outside the gallery', async () => {
    const html = await renderHtml(<Page>{null}</Page>, { title: 't' })
    expect(html).toContain('<html lang="en"><head>')
  })

  it('escapes the title', async () => {
    const html = await renderHtml(<Page>{null}</Page>, { title: '<script>x</script>' })
    expect(html).toContain('<title>&lt;script&gt;x&lt;/script&gt;</title>')
  })

  it('builds the CSP from spec/security.md', () => {
    expect(contentSecurityPolicy()).toBe(
      "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' https: data:; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    )
  })
})

describe('Stripe pages', () => {
  it('only a page that opts in admits Stripe: its script, frames (3DS included) and API, and Link', () => {
    const plain = contentSecurityPolicy()
    expect(plain).not.toMatch(/stripe|link\.com|frame-src/)
    const stripe = contentSecurityPolicy([], true)
    expect(stripe).toContain("script-src 'self' https://js.stripe.com https://*.js.stripe.com")
    expect(stripe).toContain('frame-src https://js.stripe.com https://*.js.stripe.com https://hooks.stripe.com https://link.com https://*.link.com')
    expect(stripe).toContain("connect-src 'self' https://api.stripe.com https://link.com https://*.link.com")
    // Everything else stays as strict as before.
    expect(stripe).toContain("default-src 'none'")
    expect(stripe).toContain("style-src 'self'")
    expect(stripe).not.toContain("'unsafe-inline'")
  })
})
