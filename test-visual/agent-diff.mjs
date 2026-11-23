#!/usr/bin/env node
/**
 * Visual diff for the agent setup, payment and connect screens (docs/agent-setup).
 * A sibling of docs/product-update/tools/visual-diff.mjs, which is never edited.
 *
 *   node test-visual/agent-diff.mjs [--base http://localhost:8787] [--only 9a,9b] [--phase 2]
 *                                   [--against html|png] [--max-pixels 0] [--out test-visual/output/agent]
 *
 * For every screen in docs/agent-setup/manifest.json that has a fixture, it renders
 *   the drawing         docs/agent-setup/screens/html/<file>   (--against html, the default)
 *                       or reads screens/png/<file>.png at 2x  (--against png)
 *   the implementation  <base>/__design/<slug>
 * at the size HANDOFF.md section 2 lists, animations disabled, and compares them.
 * The org.ai mark is hidden on both sides (it changed on main after the drawings;
 * pass --with-mark to include it).
 * It prints the differing pixel count and where the first difference is, and
 * writes mock, impl and diff images for anything over the bar.
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
const manifest = JSON.parse(readFileSync(join(SPEC, 'manifest.json'), 'utf8'))
const argv = process.argv.slice(2)
const arg = (name, fallback) => (argv.includes(`--${name}`) ? argv[argv.indexOf(`--${name}`) + 1] : fallback)
const BASE = String(arg('base', process.env.VISUAL_BASE || 'http://localhost:8787')).replace(/\/$/, '')
const OUT = resolve(arg('out', 'test-visual/output/agent'))
const AGAINST = arg('against', 'html')
const MAX = Number(arg('max-pixels', 0))
const only = arg('only') ? String(arg('only')).split(',') : null
const phase = arg('phase') ? Number(arg('phase')) : null
const scale = AGAINST === 'png' ? 2 : 1

/** Owner direction (2026-11-23): pages write "/month" and "/call" where the drawings say "a month" and "a call". Apply that to the drawing (--as-drawn skips it). */
const SLASH_MONTH = () => {
  const walk = (n) => {
    if (n.nodeType === 3) {
      const t = n.textContent.replace(/(?<=[\d\]]) a (month|call)/g, '/$1')
      if (/^a month \+/.test(t)) {
        n.textContent = t.replace(/^a month \+/, '/month +')
        n.parentElement.style.marginLeft = '-6px'
      } else if (t !== n.textContent) n.textContent = t
    } else n.childNodes.forEach(walk)
  }
  walk(document.body)
}

async function shoot(browser, url, [width, height]) {
  const page = await browser.newPage({ viewport: { width, height }, deviceScaleFactor: scale })
  await page.emulateMedia({ reducedMotion: 'no-preference', colorScheme: 'dark' })
  const res = await page.goto(url, { waitUntil: 'load' })
  if (res && res.status() >= 400) {
    await page.close()
    throw new Error(`HTTP ${res.status()}`)
  }
  await page.evaluate(() => document.fonts.ready)
  if (url.startsWith('file:') && !argv.includes('--as-drawn')) await page.evaluate(SLASH_MONTH)
  await page.mouse.move(0, 0)
  // The org.ai mark changed after these screens were drawn (main's six-mark ring;
  // the drawings carry the older one). Hide it on both sides unless --with-mark.
  if (!argv.includes('--with-mark')) {
    await page.evaluate(() => {
      for (const el of document.querySelectorAll('.id-mark, svg')) {
        if (el.matches('.id-mark') || el.querySelector('path[d^="M90.1943"]')) el.style.visibility = 'hidden'
      }
    })
  }
  const buf = await page.screenshot({ animations: 'disabled', caret: 'hide' })
  const tall = await page.evaluate(() => document.documentElement.scrollHeight)
  await page.close()
  return { png: PNG.sync.read(buf), tall }
}

function compare(a, b) {
  if (a.width !== b.width || a.height !== b.height) return { n: -1, first: `size ${a.width}x${a.height} vs ${b.width}x${b.height}` }
  const diff = new PNG({ width: a.width, height: a.height })
  const n = pixelmatch(a.data, b.data, diff.data, a.width, a.height, { threshold: 0.05, includeAA: true })
  let top = -1
  let bottom = -1
  for (let y = 0; y < a.height && n; y++) {
    for (let x = 0; x < a.width; x++) {
      const i = (y * a.width + x) * 4
      if (a.data[i] !== b.data[i] || a.data[i + 1] !== b.data[i + 1] || a.data[i + 2] !== b.data[i + 2]) {
        if (top < 0) top = y
        bottom = y
        break
      }
    }
  }
  return { n, diff, first: n ? `rows ${Math.round(top / scale)}-${Math.round(bottom / scale)}` : '' }
}

mkdirSync(OUT, { recursive: true })
const bin = findChromium()
const browser = await chromium.launch(bin ? { executablePath: bin } : {})
let failed = 0
let ran = 0
for (const s of manifest.screens) {
  if (s.kind === 'reference') continue
  if (only && !only.includes(s.id)) continue
  if (phase && s.phase !== phase) continue
  ran++
  try {
    const impl = await shoot(browser, `${BASE}/__design/${s.slug}`, s.size)
    const mock = AGAINST === 'png' ? { png: PNG.sync.read(readFileSync(join(SPEC, s.png))), tall: 0 } : await shoot(browser, pathToFileURL(join(SPEC, s.file)).href, s.size)
    const r = compare(mock.png, impl.png)
    const height = AGAINST === 'html' && mock.tall !== impl.tall ? ` · page height ${mock.tall} vs ${impl.tall}` : ''
    const pass = r.n >= 0 && r.n <= MAX && !height
    if (!pass) {
      failed++
      writeFileSync(join(OUT, `${s.id}.mock.png`), PNG.sync.write(mock.png))
      writeFileSync(join(OUT, `${s.id}.impl.png`), PNG.sync.write(impl.png))
      if (r.diff) writeFileSync(join(OUT, `${s.id}.diff.png`), PNG.sync.write(r.diff))
    }
    console.log(`${pass ? 'PASS' : 'FAIL'}  ${s.id.padEnd(4)} ${String(r.n).padStart(7)} px  ${r.first}${height}`)
  } catch (e) {
    failed++
    console.log(`FAIL  ${s.id.padEnd(4)} ${String(e.message || e)}`)
  }
}
await browser.close()
console.log(`\n${ran - failed}/${ran} match (${AGAINST}, at most ${MAX} px) · images in ${OUT}`)
process.exit(failed ? 1 : 0)
