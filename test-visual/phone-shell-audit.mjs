#!/usr/bin/env node
/**
 * Every gallery page and state at 390×844: does it follow the phone shell rules?
 *   card starts where the header ends · card reaches the bottom of the screen (or runs past it)
 *   the action band is the last thing in the card · two actions are stacked, 48px, primary on top
 *   footer links start below the fold · the header is sticky
 *   node test-visual/phone-shell-audit.mjs [--base http://localhost:8787]
 */
import { chromium } from 'playwright'
import { findChromium } from '../scripts/chromium.mjs'
const argv = process.argv.slice(2)
const BASE = String(argv.includes('--base') ? argv[argv.indexOf('--base') + 1] : process.env.VISUAL_BASE || 'http://localhost:8787').replace(/\/$/, '')
const browser = await chromium.launch({ executablePath: findChromium() })
const index = await browser.newPage()
const links = new Set()
for (const path of ['/__design', '/__design/agent-setup']) {
  await index.goto(BASE + path)
  for (const h of await index.evaluate(() => [...document.querySelectorAll('a[href^="/__design/"]')].map((a) => a.getAttribute('href')))) links.add(h)
}
await index.close()
links.delete('/__design/components')
links.delete('/__design/agent-setup')
let bad = 0
let n = 0
for (const href of [...links].sort()) {
  const page = await browser.newPage({ viewport: { width: 390, height: 844 }, hasTouch: true })
  const res = await page.goto(BASE + href, { waitUntil: 'load' })
  const out = await page.evaluate(() => {
    const card = document.querySelector('.id-card')
    const header = document.querySelector('.id-header')
    if (!card || !header) return null // emails and other documents that aren't pages
    const p = []
    const c = card.getBoundingClientRect()
    const h = header.getBoundingClientRect()
    if (Math.abs(c.top - h.bottom) > 0.5) p.push(`gap of ${Math.round(c.top - h.bottom)}px under the header`)
    // Branded sign-in keeps "Secured by id.org.ai" in view, so there the card runs to that footer instead.
    const secured = document.querySelector('.id-footer--secured')
    const reach = secured ? Math.min(innerHeight, secured.getBoundingClientRect().top) : innerHeight
    if (c.bottom < reach - 0.5) p.push(`card stops ${Math.round(reach - c.bottom)}px short of the bottom`)
    const foot = card.querySelector('.id-card__foot')
    if (foot && Math.abs(foot.getBoundingClientRect().bottom - c.bottom) > 1.5) p.push('action band is not at the bottom of the card')
    const footer = document.querySelector('.id-footer:not(.id-footer--secured)')
    if (footer && footer.getBoundingClientRect().top < innerHeight - 0.5) p.push('footer links are above the fold')
    if (getComputedStyle(header).position !== 'sticky') p.push('header is not sticky')
    for (const band of card.querySelectorAll('.id-card__foot [data-actions]')) {
      const kids = [...band.children].filter((k) => k.getBoundingClientRect().height)
      const r = kids.map((k) => k.getBoundingClientRect())
      if (new Set(r.map((x) => Math.round(x.left))).size > 1) p.push('actions not stacked')
      if (r.some((x) => Math.round(x.height) < 48)) p.push('action under 48px')
      const pi = kids.findIndex((k) => k.classList.contains('id-btn--primary'))
      if (pi >= 0 && r.some((x, i) => i !== pi && x.top < r[pi].top)) p.push('primary not on top')
    }
    return p
  })
  await page.close()
  if (out === null || (res && res.status() >= 400)) continue
  n++
  if (out.length) {
    bad++
    console.log(`FAIL  ${href.replace('/__design/', '')}  ${out.join(' · ')}`)
  }
}
await browser.close()
console.log(`\n${n - bad}/${n} gallery pages follow the phone shell rules`)
process.exit(bad ? 1 : 0)
