/**
 * Every agent setup screen against its drawing (docs/agent-setup): the fixture
 * exists, the page says exactly what the drawing says (with "a month" and "a call"
 * written "/month" and "/call", by owner direction), bracketed placeholders
 * are kept as written, and nothing is red or inline-styled.
 */
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { slashUnits } from '../agent-setup/format'
import { renderHtml } from '../render'
import { AGENT_SCREENS, fixtureSlug } from './agent-setup-index'
import { fixtures } from './fixtures'

const built = AGENT_SCREENS.filter((s) => s.kind !== 'reference' && fixtures[fixtureSlug(s)])

/** The words a person reads in the card and the header's right slot, in order. */
function words(html: string): string {
  const doc = new DOMParser().parseFromString(html, 'text/html')
  // Owner direction (2026-11-23): "/month" and "/call" where the drawings say "a month" and "a call".
  const walk = (n: Node): void => {
    if (n.nodeType === 3) n.textContent = slashUnits(n.textContent ?? '')
    else n.childNodes.forEach(walk)
  }
  walk(doc.body)
  // Spoken-only text and decoration: visually hidden labels, the tiles and avatar, the picture of Stripe's fields.
  for (const el of doc.querySelectorAll('script, style, template, title, option:not([selected]), .id-sr, [hidden], footer, .id-conn, .id-avatar, .id-stripe__picture, [data-price="yearly"], [style*="clip: rect(0 0 0 0)"]')) el.remove()
  // The tiles above the title are decorative (the connector is aria-hidden on the page).
  doc.querySelector('h1')?.parentElement?.previousElementSibling?.remove()
  // So are the avatar's initials (aria-hidden on the page; a bare 32px circle in the drawing).
  for (const el of doc.querySelectorAll('[style*="width: 32px; height: 32px; border-radius: 99px"]')) el.remove()
  // What a closed row hides isn't read until it is opened (drawings use <details>; pages use it or a hidden panel).
  for (const el of doc.querySelectorAll('details:not([open]) > :not(summary)')) el.remove()
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
  it('lists every screen once by its ID; the three phone drawings are not separate entries', () => {
    expect(AGENT_SCREENS).toHaveLength(63)
    expect(new Set(AGENT_SCREENS.map((s) => s.id)).size).toBe(63)
    for (const id of ['9f', '9g', '9h']) expect(AGENT_SCREENS.find((s) => s.id === id)).toBeUndefined()
    expect(AGENT_SCREENS.filter((s) => s.renders)).toEqual([])
  })

  for (const s of built) {
    it(`${s.id} says what its drawing says, placeholders included`, async () => {
      const drawing = readFileSync(`docs/agent-setup/${s.file}`, 'utf8')
      const html = await page(fixtureSlug(s))
      if (s.kind === 'screen') {
        // The card's words, in order. (Stripe's fields on 19a are a picture: compared by the visual diff.)
        // 20c offers one action for now: the drawing's "Ask for a refund" is not on the page.
        const drawn = s.id === '20c' ? words(drawing).replace('Askforarefund', '') : words(drawing)
        if (s.id === '20c') expect(html).not.toContain('Ask for a refund')
        if (s.id !== '19a') expect(words(html)).toBe(drawn)
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
