#!/usr/bin/env node
/**
 * Contact sheets of the agent setup screens at a phone width, for review by eye.
 *   node test-visual/agent-phone-sheet.mjs <out-prefix> [--width 320] [--only 24a,24b] [--per 5] [--open]
 * Writes <out-prefix>-1.png, -2.png … with `per` full-page screens side by side.
 * --open presses every disclosure first, so the expanded rows are shown too.
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright'
import { PNG } from 'pngjs'
import { findChromium } from '../scripts/chromium.mjs'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const manifest = JSON.parse(readFileSync(join(ROOT, 'docs/agent-setup/manifest.json'), 'utf8'))
const argv = process.argv.slice(2)
const arg = (name, fallback) => (argv.includes(`--${name}`) ? argv[argv.indexOf(`--${name}`) + 1] : fallback)
const out = argv[0]
const W = Number(arg('width', 320))
const per = Number(arg('per', 5))
const only = arg('only') ? String(arg('only')).split(',') : null
const BASE = String(arg('base', process.env.VISUAL_BASE || 'http://localhost:8787')).replace(/\/$/, '')
const browser = await chromium.launch({ executablePath: findChromium() })
const shots = []
const seen = new Set()
for (const s of manifest.screens) {
  const slug = s.renders ?? s.slug
  if (s.kind !== 'screen' || seen.has(slug) || (only && !only.includes(s.id))) continue
  seen.add(slug)
  const page = await browser.newPage({ viewport: { width: W, height: 700 }, deviceScaleFactor: 1, hasTouch: true })
  await page.goto(`${BASE}/__design/${slug}`, { waitUntil: 'load' })
  await page.evaluate(() => document.fonts.ready)
  if (argv.includes('--open')) {
    const closed = page.locator('[data-js=disclose][aria-expanded=false]')
    while (await closed.count()) await closed.first().click()
    await page.evaluate(() => document.querySelectorAll('details').forEach((d) => (d.open = true)))
  }
  shots.push({ id: s.id, png: PNG.sync.read(await page.screenshot({ fullPage: true, animations: 'disabled' })) })
  await page.close()
}
await browser.close()
for (let i = 0, n = 1; i < shots.length; i += per, n++) {
  const group = shots.slice(i, i + per)
  const height = Math.max(...group.map((g) => g.png.height))
  const sheet = new PNG({ width: group.length * (W + 12), height })
  sheet.data.fill(60)
  group.forEach((g, k) => PNG.bitblt(g.png, sheet, 0, 0, g.png.width, g.png.height, k * (W + 12), 0))
  writeFileSync(`${out}-${n}.png`, PNG.sync.write(sheet))
  console.log(`${out}-${n}.png  ${group.map((g) => g.id).join(' ')}  ${sheet.width}x${height}`)
}
