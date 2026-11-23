/** A product can send its own logo for its tile; its letters stand in when it doesn't, or can't (owner direction, 2026-11-23). */
import { describe, expect, it } from 'vitest'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { productTile } from '../../agent-setup/tiles'
import { connectFixtures, connectProps } from '../../gallery/fixtures/connect'
import { paymentFixtures } from '../../gallery/fixtures/payments'
import { setupFixtures, setupProps } from '../../gallery/fixtures/setup'
import { renderHtml } from '../../render'
import { ConnectPlan } from './Connect'
import { SetupPage } from './SetupPage'

async function dom(el: JSX.Element): Promise<Document> {
  return new DOMParser().parseFromString(await renderHtml(el, { title: 't' }), 'text/html')
}
const rightTile = (d: Document) => [...d.querySelectorAll('.id-conn .id-tile')][1]!

describe('product branding', () => {
  it('a product’s tile is its logo when it sends one, its letters otherwise', () => {
    expect(productTile({ tile: 'Ad' })).toEqual({ kind: 'monogram', text: 'Ad' })
    expect(productTile({ tile: 'Ad', logo_url: '/brand/auto-dev.svg' })).toEqual({ kind: 'logo', src: '/brand/auto-dev.svg', monogram: 'Ad' })
  })
  it('with no logo the screens are unchanged: letters, as drawn', async () => {
    const d = await dom(<SetupPage {...setupProps.running} />)
    expect(rightTile(d).textContent).toBe('Ad')
    expect(rightTile(d).querySelector('img')).toBeNull()
  })
  it('with a logo the tile carries it, decoratively, with the letters ready as the fallback', async () => {
    const d = await dom(<SetupPage {...setupProps.running} setup={{ ...setupProps.running.setup, product: { ...setupProps.running.setup.product, logo_url: '/brand/auto-dev.svg' } }} />)
    const img = rightTile(d).querySelector('img')!
    expect(img.getAttribute('src')).toBe('/brand/auto-dev.svg')
    expect(img.getAttribute('alt')).toBe('')
    expect(img.getAttribute('referrerpolicy')).toBe('no-referrer')
    expect(rightTile(d).getAttribute('data-js')).toBe('logo')
    expect(rightTile(d).getAttribute('data-monogram')).toBe('Ad')
    // The title still names the product in words: the logo never carries meaning alone.
    expect(d.querySelector('h1')!.textContent).toContain('Auto.dev')
  })
  it('refuses a logo that is not https or first-party, and shows the letters', async () => {
    for (const bad of ['http://insecure.example/logo.png', 'javascript:alert(1)', '//evil.example/x.svg']) {
      const d = await dom(<SetupPage {...setupProps.running} setup={{ ...setupProps.running.setup, product: { ...setupProps.running.setup.product, logo_url: bad } }} />)
      expect(rightTile(d).querySelector('img'), bad).toBeNull()
      expect(rightTile(d).textContent, bad).toBe('Ad')
    }
  })
  it('connect: the product and the connecting app can each carry a logo', async () => {
    const d = await dom(<ConnectPlan {...connectProps.plan} product={{ ...connectProps.plan.product, logo_url: 'https://www.auto.dev/logo.svg' }} client={{ ...connectProps.plan.client, logoUrl: 'https://claude.ai/logo.svg' }} />)
    expect([...d.querySelectorAll('.id-conn .id-tile img')].map((i) => i.getAttribute('src'))).toEqual(['https://claude.ai/logo.svg', 'https://www.auto.dev/logo.svg'])
  })
  it('the gallery shows a branded state on the screens where the product is the subject, and loads the fallback script', () => {
    const branded: [string, { derived: Record<string, unknown>; scripts: string[] }][] = [
      ['9b', setupFixtures['9b-setup-running']!],
      ['9e', setupFixtures['9e-setup-live']!],
      ['19b', paymentFixtures['19b-pay-plan-usage']!],
      ['19e', paymentFixtures['19e-pay-confirm-bank']!],
      ['20c', paymentFixtures['20c-charge']!],
      ['24a', connectFixtures['24a-connect-plan']!],
      ['24b', connectFixtures['24b-connect-pay']!],
      ['24c', connectFixtures['24c-connect-done']!],
    ]
    for (const [id, f] of branded) {
      expect(f.derived['branded'], id).toBeDefined()
      expect(f.scripts, id).toContain('logo.js')
    }
  })
})
