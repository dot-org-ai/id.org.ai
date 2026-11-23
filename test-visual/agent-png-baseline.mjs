#!/usr/bin/env node
/**
 * How far each drawing's own HTML, rendered here at 2x, is from its supplied
 * PNG. That figure is renderer noise (text anti-aliasing, the browser that
 * exported the PNG), so it is the floor for `agent-diff.mjs --against png`:
 * an implementation that matches the HTML at 0 px can't get closer to the PNG
 * than the HTML itself does.
 *
 *   node test-visual/agent-png-baseline.mjs [--only 9a,9c] [--phase 2] [--base http://localhost:8787]
 *
 * Prints, per screen: HTML vs PNG, implementation vs PNG, and implementation vs
 * HTML at 2x. The org.ai mark is hidden in the two renders (the PNG keeps the
 * older mark), so both PNG figures include it.
 */
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { chromium } from 'playwright'
import pixelmatch from 'pixelmatch'
import { PNG } from 'pngjs'
import { findChromium } from '../scripts/chromium.mjs'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SPEC = join(ROOT, 'docs/agent-setup')
const manifest = JSON.parse(readFileSync(join(SPEC, 'manifest.json'), 'utf8'))
const argv = process.argv.slice(2)
const arg = (name, fallback) => (argv.includes(`--${name}`) ? argv[argv.indexOf(`--${name}`) + 1] : fallback)
const BASE = String(arg('base', process.env.VISUAL_BASE || 'http://localhost:8787')).replace(/\/$/, '')
const only = arg('only') ? String(arg('only')).split(',') : null
const phase = arg('phase') ? Number(arg('phase')) : null

const bin = findChromium()
const browser = await chromium.launch(bin ? { executablePath: bin } : {})
async function shoot(url, [width, height]) {
  const page = await browser.newPage({ viewport: { width, height }, deviceScaleFactor: 2 })
  await page.emulateMedia({ reducedMotion: 'no-preference', colorScheme: 'dark' })
  await page.goto(url, { waitUntil: 'load' })
  await page.evaluate(() => document.fonts.ready)
  await page.mouse.move(0, 0)
  // The org.ai mark changed on main after the drawings: hide it on both, as agent-diff.mjs does.
  await page.evaluate(() => {
    for (const el of document.querySelectorAll('.id-mark, svg')) if (el.matches('.id-mark') || el.querySelector('path[d^="M90.1943"]')) el.style.visibility = 'hidden'
  })
  const buf = await page.screenshot({ animations: 'disabled', caret: 'hide' })
  await page.close()
  return PNG.sync.read(buf)
}
const count = (a, b) => (a.width === b.width && a.height === b.height ? pixelmatch(a.data, b.data, null, a.width, a.height, { threshold: 0.05, includeAA: true }) : -1)
let worse = 0
for (const s of manifest.screens) {
  if (s.kind === 'reference') continue
  if (only && !only.includes(s.id)) continue
  if (phase && s.phase !== phase) continue
  const png = PNG.sync.read(readFileSync(join(SPEC, s.png)))
  const html = await shoot(pathToFileURL(join(SPEC, s.file)).href, s.size)
  const impl = await shoot(`${BASE}/__design/${s.slug}`, s.size)
  const [floor, ours, apart] = [count(html, png), count(impl, png), count(html, impl)]
  const pct = (n) => ((n / (png.width * png.height)) * 100).toFixed(2) + '%'
  if (apart > 0) worse++
  console.log(`${s.id.padEnd(4)} drawing vs PNG ${String(floor).padStart(6)} (${pct(floor)})   page vs PNG ${String(ours).padStart(6)} (${pct(ours)})   page vs drawing at 2x ${String(apart).padStart(5)}`)
}
await browser.close()
console.log(worse ? `\n${worse} page(s) differ from their drawing at 2x` : '\nEvery page equals its drawing at 2x (org.ai mark aside), so what separates it from the PNG is what separates the drawing from its own PNG.')
