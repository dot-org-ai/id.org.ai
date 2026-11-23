#!/usr/bin/env node
/**
 * Dev aid: screenshots 19a with Stripe's real Payment Element next to the picture of it,
 * for matching the element to the card by eye. Needs the dev server started with
 * `--var STRIPE_PUBLISHABLE_KEY:pk_test_…` and network access to js.stripe.com.
 *   node test-visual/stripe-live-shot.mjs <out.png> [--width 720] [--tab bank]
 */
import { writeFileSync } from 'node:fs'
import { chromium } from 'playwright'
import { PNG } from 'pngjs'
import { findChromium } from '../scripts/chromium.mjs'
const argv = process.argv.slice(2)
const arg = (n, d) => (argv.includes(`--${n}`) ? argv[argv.indexOf(`--${n}`) + 1] : d)
const W = Number(arg('width', 720))
const H = Number(arg('height', 1000))
const BASE = process.env.VISUAL_BASE || 'http://localhost:8787'
const browser = await chromium.launch({ executablePath: findChromium() })
const shots = []
for (const path of ['/__design/19a-pay-add', '/__design/19a-stripe-live']) {
  const page = await browser.newPage({ viewport: { width: W, height: H }, hasTouch: W <= 480 })
  const errors = []
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text().slice(0, 200)))
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 200)))
  await page.goto(BASE + path, { waitUntil: 'load' })
  await page.evaluate(() => document.fonts.ready)
  if (path.includes('live')) {
    await page.waitForSelector('[data-stripe-mount] iframe', { timeout: 20000 }).catch(() => errors.push('no Stripe iframe after 20s'))
    await page.waitForTimeout(3500)
    const tab = arg('tab')
    if (tab) {
      const frame = page.frameLocator('[data-stripe-mount] iframe').first()
      await frame.locator(`[data-testid="${tab}"], #${tab}-tab, button:has-text("${tab}")`).first().click({ timeout: 5000 }).catch(() => errors.push(`no tab ${tab}`))
      await page.waitForTimeout(1500)
    }
    console.log('stripe mount height:', await page.evaluate(() => Math.round(document.querySelector('[data-stripe-mount]')?.getBoundingClientRect().height ?? 0)))
  }
  if (errors.length) console.log(path, 'errors:', errors.join(' | '))
  shots.push(PNG.sync.read(await page.screenshot({ animations: 'disabled' })))
  await page.close()
}
await browser.close()
const out = new PNG({ width: W * 2 + 12, height: H })
out.data.fill(70)
shots.forEach((im, k) => PNG.bitblt(im, out, 0, 0, W, H, k * (W + 12), 0))
writeFileSync(argv[0], PNG.sync.write(out))
