#!/usr/bin/env node
/**
 * 24a and 24b with every expandable thing open, against the drawings with
 * every <details> open (the two ".all-open" PNGs show the same state).
 *
 *   node test-visual/agent-all-open.mjs [--base http://localhost:8787]
 *
 * On the page the rows are opened the way a person would: each chevron button
 * is pressed, each native <details> is opened.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { chromium } from 'playwright'
import pixelmatch from 'pixelmatch'
import { PNG } from 'pngjs'
import { findChromium } from '../scripts/chromium.mjs'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SPEC = join(ROOT, 'docs/agent-setup')
const argv = process.argv.slice(2)
const BASE = String(argv.includes('--base') ? argv[argv.indexOf('--base') + 1] : process.env.VISUAL_BASE || 'http://localhost:8787').replace(/\/$/, '')
const OUT = resolve('test-visual/output/agent')
mkdirSync(OUT, { recursive: true })
const manifest = JSON.parse(readFileSync(join(SPEC, 'manifest.json'), 'utf8'))
const bin = findChromium()
const browser = await chromium.launch(bin ? { executablePath: bin } : {})

async function shoot(url, width, height, open) {
  const page = await browser.newPage({ viewport: { width, height }, deviceScaleFactor: 1 })
  await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: 'dark' })
  await page.goto(url, { waitUntil: 'load' })
  await page.evaluate(() => document.fonts.ready)
  await open(page)
  await page.mouse.move(0, 0)
  await page.evaluate(() => {
    document.activeElement?.blur?.()
    for (const el of document.querySelectorAll('.id-mark, svg')) if (el.matches('.id-mark') || el.querySelector('path[d^="M90.1943"]')) el.style.visibility = 'hidden'
  })
  const buf = await page.screenshot({ animations: 'disabled', caret: 'hide' })
  await page.close()
  return PNG.sync.read(buf)
}
const openDrawing = (page) => page.evaluate(() => document.querySelectorAll('details').forEach((d) => (d.open = true)))
const openPage = async (page) => {
  const closed = page.locator('[data-js=disclose][aria-expanded=false]')
  while (await closed.count()) await closed.first().click()
  await page.evaluate(() => document.querySelectorAll('details').forEach((d) => (d.open = true)))
}

let failed = 0
for (const s of manifest.screens) {
  const png = join(SPEC, s.png.replace(/\.png$/, '.all-open.png'))
  if (!existsSync(png)) continue
  const ref = PNG.sync.read(readFileSync(png))
  const [w, h] = [ref.width / 2, ref.height / 2]
  const mock = await shoot(pathToFileURL(join(SPEC, s.file)).href, w, h, openDrawing)
  const impl = await shoot(`${BASE}/__design/${s.slug}`, w, h, openPage)
  const diff = new PNG({ width: w, height: h })
  const n = pixelmatch(mock.data, impl.data, diff.data, w, h, { threshold: 0.05, includeAA: true })
  if (n) {
    failed++
    writeFileSync(join(OUT, `${s.id}.all-open.mock.png`), PNG.sync.write(mock))
    writeFileSync(join(OUT, `${s.id}.all-open.impl.png`), PNG.sync.write(impl))
    writeFileSync(join(OUT, `${s.id}.all-open.diff.png`), PNG.sync.write(diff))
  }
  console.log(`${n ? 'FAIL' : 'PASS'}  ${s.id} all open, ${w}x${h}: ${n} px`)
}
await browser.close()
process.exit(failed ? 1 : 0)
