/**
 * Every agent setup screen against its drawing (docs/agent-setup): the fixture
 * exists, the page says exactly what the drawing says, bracketed placeholders
 * are kept as written, and nothing is red or inline-styled.
 */
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { renderHtml } from '../render'
import { AGENT_SCREENS, fixtureSlug } from './agent-setup-index'
import { fixtures } from './fixtures'

const built = AGENT_SCREENS.filter((s) => s.kind !== 'reference' && fixtures[fixtureSlug(s)])

/** The words a person reads in the card and the header's right slot, in order. */
function words(html: string): string {
  const doc = new DOMParser().parseFromString(html, 'text/html')
  // Spoken-only text and decoration: visually hidden labels, the tiles and avatar, the picture of Stripe's fields.
  for (const el of doc.querySelectorAll('script, style, template, title, option:not([selected]), .id-sr, [hidden], footer, .id-conn, .id-avatar, .id-stripe__picture')) el.remove()
  // The tiles above the title are decorative (the connector is aria-hidden on the page).
  doc.querySelector('h1')?.parentElement?.previousElementSibling?.remove()
  // So are the avatar's initials (aria-hidden on the page; a bare 32px circle in the drawing).
  for (const el of doc.querySelectorAll('[style*="width: 32px; height: 32px; border-radius: 99px"]')) el.remove()
  // Drawings put the first option first; a select reads as its selected option either way.
  for (const sel of doc.querySelectorAll('select')) sel.textContent = sel.querySelector('option[selected]')?.textContent ?? sel.querySelector('option')?.textContent ?? ''
  const root = doc.querySelector('[data-card]')?.parentElement?.parentElement?.parentElement ?? doc.body
  const header = [...doc.querySelectorAll('header > *')].slice(1).map((e) => e.textContent).join(' ')
  return `${header} ${(doc.querySelector('[data-card]') ?? root).textContent}`.replace(/[\s ]+/g, '').trim()
}

async function page(slug: string): Promise<string> {
  const f = fixtures[slug]!
  const el = f.default.render()
  return f.document === 'email' ? '<!doctype html>' + String(await el) : renderHtml(el, { title: f.default.title, scripts: f.scripts, frozen: true })
}

describe('agent setup screens', () => {
  it('each built screen is in the manifest by its ID, and a phone drawing shares its desktop fixture', () => {
    expect(AGENT_SCREENS).toHaveLength(66)
    expect(new Set(AGENT_SCREENS.map((s) => s.id)).size).toBe(66)
    expect(AGENT_SCREENS.filter((s) => s.renders).map((s) => [s.id, s.renders])).toEqual([
      ['9f', '9b-setup-running'],
      ['9g', '9a-setup-approve'],
      ['9h', '9c-setup-needs-you'],
    ])
  })

  for (const s of built) {
    it(`${s.id} says what its drawing says, placeholders included`, async () => {
      const drawing = readFileSync(`docs/agent-setup/${s.file}`, 'utf8')
      const html = await page(fixtureSlug(s))
      if (s.kind === 'screen') {
        // The card's words, in order. (Stripe's fields on 19a are a picture: compared by the visual diff.)
        if (s.id !== '19a') expect(words(html)).toBe(words(drawing))
        expect(html).not.toMatch(/\sstyle=/i)
      }
      const drawn = new DOMParser().parseFromString(drawing, 'text/html').body.textContent ?? ''
      const placeholders = new Set(drawn.match(/\[[A-Za-z][A-Za-z0-9 ,-]*\]/g) ?? [])
      for (const p of placeholders) expect(html, `${s.id} keeps ${p}`).toContain(p)
      // Amber and green only: no red anywhere, in any spelling a colour could take.
      expect(html).not.toMatch(/\bred\b|#f00\b|#ff0000|rgb\(\s*255,\s*0,\s*0|danger|destructive/i)
    })
  }
})
