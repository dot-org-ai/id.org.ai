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
