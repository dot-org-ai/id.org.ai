/**
 * Which screens use the narrow 440px column (owner direction, 2026-10-01):
 * the sign-in journey and the account screens, so the card keeps one width
 * from sign-in onward. Consent, approvals, the device flow, agents and errors
 * keep the 560px column for their permission lists and details.
 *
 * Every state of every gallery fixture is checked, so a new state can't
 * quietly fall back to the other width.
 */
import { describe, expect, it } from 'vitest'
import { renderHtml } from '../render'
import { fixtures } from '../gallery/fixtures'

const NARROW = new Set([
  '1a-sign-in',
  '1b-email-code',
  '1c-sso',
  '1d-first-run',
  '1e-link-account',
  '1f-provider-fallback',
  '1g-branded-sign-in',
  '2a-account-chooser',
  '2b-workspace-chooser',
  '2c-handoff',
  '2e-invitation',
  '6a-step-up',
  '6b-sign-out',
  '6c-add-passkey',
  '6d-two-step',
])

describe('column width', () => {
  for (const [slug, f] of Object.entries(fixtures)) {
    if (f.document !== 'page') continue
    it(`${slug}: ${NARROW.has(slug) ? 'narrow' : 'standard'} in every state`, async () => {
      const variants = [f.default, ...Object.values(f.states), ...Object.values(f.derived)]
      for (const v of variants) {
        const doc = new DOMParser().parseFromString(await renderHtml(v.render(), { title: 't' }), 'text/html')
        const column = doc.querySelector('.id-column')
        if (!column) continue // not a card screen (the flow map, the terminal)
        expect(column.classList.contains('id-column--narrow'), `${slug} · ${v.title}`).toBe(NARROW.has(slug))
      }
    })
  }

  it('covers every narrow slug', () => {
    for (const slug of NARROW) expect(fixtures[slug], slug).toBeDefined()
  })
})
