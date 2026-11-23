/** A product can send its own logo for its tile; its letters stand in when it doesn't, or can't (owner direction, 2026-11-23). */
import { describe, expect, it } from 'vitest'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { productTile } from '../../agent-setup/tiles'
import { connectFixtures, connectProps } from '../../gallery/fixtures/connect'
import { setupProps } from '../../gallery/fixtures/setup'
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
  it('every gallery setup page about Auto.dev has a branded state and loads the fallback script; other products keep their letters', async () => {
    const { fixtures } = await import('../../gallery/fixtures')
    const { AGENT_SCREENS, fixtureSlug } = await import('../../gallery/agent-setup-index')
    const withBranded = AGENT_SCREENS.filter((s) => fixtures[fixtureSlug(s)]?.derived['branded']).map((s) => s.id)
    // Auto.dev's setup run, its failure and payment states, the migration onto it, the charge, and Connect.
    expect(withBranded).toEqual(['9b', '9c', '9d', '9e', '11a', '11b', '11c', '11d', '11f', '12d', '16a', '16b', '16c', '16d', '19b', '19e', '19f', '20c', '21b', '24a', '24b', '24c'])
    for (const s of AGENT_SCREENS.filter((x) => withBranded.includes(x.id))) expect(fixtures[fixtureSlug(s)]!.scripts, s.id).toContain('logo.js')
    // apis.email, apis.directory, headless.ly and APIs.ax have no mark in the repo yet.
    for (const id of ['12a', '15a', '18b', '21a', '22a']) expect(withBranded, id).not.toContain(id)
  })
  it('Connect’s branded states carry Claude’s mark as auto.dev serves it, never a stored copy', async () => {
    const d = new DOMParser().parseFromString(await renderHtml(connectFixtures['24a-connect-plan']!.derived['branded']!.render(), { title: 't' }), 'text/html')
    expect([...d.querySelectorAll('.id-conn .id-tile img')].map((i) => i.getAttribute('src'))).toEqual(['https://www.auto.dev/logos/ai/claude.svg', '/brand/auto-dev.svg'])
    expect([...d.querySelectorAll('.id-conn .id-tile')].map((t) => t.getAttribute('data-monogram'))).toEqual(['Cl', 'Ad'])
  })
  it('setup pages’ branded states carry Claude’s mark for Claude Code and the product’s own', async () => {
    const { fixtures } = await import('../../gallery/fixtures')
    for (const slug of ['9b-setup-running', '19b-pay-plan-usage', '20c-charge']) {
      const d = new DOMParser().parseFromString(await renderHtml(fixtures[slug]!.derived['branded']!.render(), { title: 't' }), 'text/html')
      expect([...d.querySelectorAll('.id-conn .id-tile img')].map((i) => i.getAttribute('src')), slug).toEqual(['https://www.auto.dev/logos/ai/claude.svg', '/brand/auto-dev.svg'])
    }
  })
})
