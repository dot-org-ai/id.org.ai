#!/usr/bin/env node
/**
 * Every dropdown on every gallery page opens a list a person can see, and a
 * tapped option is selected, at phone size in Chromium.
 *
 * Chromium only. The bug this was written for was Safari's: the styled list
 * (appearance: base-select) opened at opacity 0 there, because its fade-in was
 * keyed on ::picker(select):popover-open, which Safari never matches. Driving
 * that list in Playwright's WebKit stalls, so Safari's rule is guarded by
 * worker/ui/phone.test.ts instead, and was checked by hand in WebKit
 * (2026-11-23: 9a and 3a open visibly and select the tapped option).
 *
 *   node test-visual/select-open-check.mjs [--base http://localhost:8787]
 */
import { chromium } from 'playwright'
import { findChromium } from '../scripts/chromium.mjs'

const argv = process.argv.slice(2)
const BASE = String(argv.includes('--base') ? argv[argv.indexOf('--base') + 1] : process.env.VISUAL_BASE || 'http://localhost:8787').replace(/\/$/, '')
const engines = [['chromium', chromium, findChromium(), { viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true }]]
let failed = 0
for (const [name, type, executablePath, context] of engines) {
  const browser = await type.launch({ executablePath })
  const ctx = await browser.newContext(context)
  const index = await ctx.newPage()
  const links = new Set()
  for (const path of ['/__design', '/__design/agent-setup']) {
    await index.goto(BASE + path)
    for (const h of await index.evaluate(() => [...document.querySelectorAll('a[href^="/__design/"]')].map((a) => a.getAttribute('href')))) if (!h.includes('?')) links.add(h)
  }
  await index.close()
  const pages = [...links].sort()
  let selects = 0
  const page = await ctx.newPage()
  page.setDefaultTimeout(5000)
  for (const href of pages) {
    await page.goto(BASE + href, { waitUntil: 'domcontentloaded' })
    if (!(await page.locator('.id-card select').count())) continue
    const count = await page.locator('.id-card select').count()
    for (let i = 0; i < count; i++) {
      const sel = page.locator('.id-card select').nth(i)
      if (!(await sel.isVisible())) continue
      selects++
      await sel.scrollIntoViewIfNeeded()
      await sel.tap({ timeout: 3000 }).catch(() => {})
      await page.waitForTimeout(400)
      const st = await sel.evaluate((s) => {
        if (!CSS.supports('appearance: base-select')) return { native: true }
        return { open: s.matches(':open'), opacity: getComputedStyle(s, '::picker(select)').opacity, options: s.options.length }
      })
      if (st.native) continue // the OS draws the list
      let problem = ''
      if (!st.open) problem = 'did not open'
      else if (Number(st.opacity) < 1) problem = `list is invisible (opacity ${st.opacity})`
      else if (st.options > 1) {
        const target = await sel.evaluate((s) => (s.selectedIndex === 0 ? 1 : 0))
        await sel.locator('option').nth(target).tap({ timeout: 3000 }).catch(() => {})
        await page.waitForTimeout(250)
        if ((await sel.evaluate((s) => s.selectedIndex)) !== target) problem = 'tapping an option did not select it'
      }
      // Close the list before the next one, so it can't cover it.
      await page.keyboard.press('Escape').catch(() => {})
      if (problem) {
        failed++
        console.log(`FAIL  ${name}  ${href.replace('/__design/', '')}  ${await sel.getAttribute('name')}: ${problem}`)
      }
    }
  }
  await page.close()
  console.log(`${name}: ${selects} dropdowns opened and picked from`)
  await browser.close()
}
console.log(failed ? `\n${failed} dropdown(s) failed` : '\nselect check passed')
process.exit(failed ? 1 : 0)
