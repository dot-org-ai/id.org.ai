#!/usr/bin/env node
/**
 * Reduced motion (spec/motion.md#testing-motion): against the running gallery,
 * with prefers-reduced-motion: reduce, every connector node, swapped-in block
 * and status dot must have animation-name: none. With no preference the same
 * pages must animate (so the check can't pass vacuously).
 *
 *   pnpm test:motion [--base http://localhost:8787]
 */
import { chromium } from 'playwright'
import { findChromium } from '../scripts/chromium.mjs'

const argv = process.argv.slice(2)
const base = (argv.includes('--base') ? argv[argv.indexOf('--base') + 1] : process.env.VISUAL_BASE || 'http://localhost:8787').replace(/\/$/, '')
const PAGES = ['/__design/4b-device-confirm?state=connecting', '/__design/4b-device-confirm?state=verdict', '/__design/4b-device-confirm?state=cancelling', '/__design/4b-device-confirm?state=signed', '/__design/components']
// Every element: anything animated under reduced motion fails, not just the nodes the CSS block names.
const SELECTOR = '*'

const executablePath = findChromium()
const browser = await chromium.launch(executablePath ? { executablePath } : {})
let failed = 0
for (const reducedMotion of ['reduce', 'no-preference']) {
  const page = await browser.newPage()
  await page.emulateMedia({ reducedMotion })
  let animated = 0
  for (const path of PAGES) {
    const res = await page.goto(base + path)
    if (!res || res.status() !== 200) {
      console.log(`FAIL ${path}: HTTP ${res?.status()}`)
      failed++
      continue
    }
    const names = await page.$$eval(SELECTOR, (els) => els.map((e) => getComputedStyle(e).animationName).filter((n) => n !== 'none'))
    animated += names.length
    if (reducedMotion === 'reduce' && names.length) {
      console.log(`FAIL ${path}: ${names.length} node(s) still animate under reduced motion (${[...new Set(names)].join(', ')})`)
      failed++
    }
  }
  if (reducedMotion === 'no-preference' && animated === 0) {
    console.log('FAIL nothing animates without reduced motion: the check would pass vacuously')
    failed++
  }
  console.log(`${reducedMotion}: ${animated} animated node(s) across ${PAGES.length} pages`)
  await page.close()
}
await browser.close()
console.log(failed ? `\n${failed} failure(s)` : '\nmotion: ok')
process.exit(failed ? 1 : 0)
