#!/usr/bin/env node
/**
 * Visual diff: the implementation against the reference mocks.
 *
 * For every screen and state in docs/product-update/mocks/manifest.json it renders
 *   the mock            file://…/mocks/screens/<file>
 *   the implementation  <base>/__design/<slug>?state=<state>
 * at the same viewport, with animations disabled, and compares them pixel by pixel.
 *
 * Usage
 *   node docs/product-update/tools/visual-diff.mjs --base http://localhost:8787
 *   node docs/product-update/tools/visual-diff.mjs --base http://localhost:8787 --only 1a,4b
 *   node docs/product-update/tools/visual-diff.mjs --self-test     # mocks vs mocks: proves the harness
 *
 * Options
 *   --base <url>         running worker with DESIGN_GALLERY=1 (wrangler dev)
 *   --only <ids>         comma-separated screen ids or slugs (1a, 4b, 4b-device-confirm)
 *   --out <dir>          where diffs and the report go (default test-visual/output)
 *   --threshold <0-1>    per-pixel colour tolerance for pixelmatch (default 0.05)
 *   --max-pixels <n>     differing pixels allowed per image (default 0: pixel perfect)
 *   --allowances <file>  JSON map of case name -> allowed pixels, for documented engine-rounding
 *                        exceptions only (default test-visual/allowances.json if present; max 4 each)
 *
 * Same Chromium + same font files + same CSS = identical pixels, so the default bar is zero.
 * Anti-aliased pixels count too: a 2px corner-radius change must fail.
 *   --self-test          serve the mocks themselves as the "implementation"
 *
 * Requires devDependencies: playwright, pixelmatch, pngjs.
 * Uses CHROMIUM_PATH if set (for pre-installed browsers).
 */
import { readFileSync, mkdirSync, writeFileSync, existsSync } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { chromium } from 'playwright'
import pixelmatch from 'pixelmatch'
import { PNG } from 'pngjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const MOCKS = resolve(HERE, '../mocks')
const manifest = JSON.parse(readFileSync(join(MOCKS, 'manifest.json'), 'utf8'))

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => {
    if (a.startsWith('--')) acc.push([a.slice(2), all[i + 1] && !all[i + 1].startsWith('--') ? all[i + 1] : true])
    return acc
  }, []),
)
const OUT = resolve(args.out || 'test-visual/output')
const THRESHOLD = Number(args.threshold ?? 0.05)
const MAX_PIXELS = Number(args['max-pixels'] ?? 0)
const ALLOW_FILE = resolve(args.allowances || 'test-visual/allowances.json')
const ALLOW = existsSync(ALLOW_FILE) ? JSON.parse(readFileSync(ALLOW_FILE, 'utf8')) : {}
for (const [k, v] of Object.entries(ALLOW)) {
  if (typeof v !== 'number' || v > 4) throw new Error(`allowance for ${k} must be a number <= 4 (got ${v})`)
}
const only = args.only ? String(args.only).split(',').map((s) => s.trim()) : null

// Pages, not references: the flow map, motion spec and terminal are not built as routes.
const COMPARED_FIXED = new Set(['8a', '8b', '8c'])

function cases() {
  const out = []
  for (const s of manifest.screens) {
    if (s.kind === 'fixed' && !COMPARED_FIXED.has(s.id)) continue
    if (only && !only.includes(s.id) && !only.includes(s.slug)) continue
    for (const [vp, [w, h]] of Object.entries(s.viewports)) {
      out.push({ slug: s.slug, state: null, file: s.file, vp, w, h })
    }
    for (const st of s.states) {
      const [vp, [w, h]] = Object.entries(s.viewports)[0] // states: primary viewport only
      out.push({ slug: s.slug, state: st.name, file: st.file, vp, w, h })
    }
  }
  return out
}

function serveMocks() {
  // /__design/<slug>?state=<s>  ->  mocks/screens/<slug>[--<s>].html ; /fonts/* -> mocks/fonts/*
  const server = createServer((req, res) => {
    const u = new URL(req.url, 'http://x')
    let file = null
    const m = u.pathname.match(/^\/__design\/([\w-]+)$/)
    if (m) {
      const st = u.searchParams.get('state')
      file = join(MOCKS, 'screens', `${m[1]}${st ? `--${st}` : ''}.html`)
    } else if (u.pathname.startsWith('/fonts/')) {
      file = join(MOCKS, 'fonts', u.pathname.slice('/fonts/'.length))
    }
    if (!file || !existsSync(file)) {
      res.writeHead(404).end()
      return
    }
    const type = file.endsWith('.html') ? 'text/html; charset=utf-8' : 'font/woff2'
    res.writeHead(200, { 'content-type': type }).end(readFileSync(file))
  })
  return new Promise((ok) => server.listen(0, '127.0.0.1', () => ok(server)))
}

async function shoot(browser, url, c) {
  const page = await browser.newPage({ viewport: { width: c.w, height: c.h }, deviceScaleFactor: 1 })
  await page.emulateMedia({ reducedMotion: 'no-preference', colorScheme: 'dark' })
  const res = await page.goto(url, { waitUntil: 'load' })
  if (res && res.status() >= 400) {
    await page.close()
    throw new Error(`HTTP ${res.status()} for ${url}`)
  }
  await page.evaluate(() => document.fonts.ready)
  await page.mouse.move(0, 0)
  const buf = await page.screenshot({ fullPage: c.vp === 'phone', animations: 'disabled', caret: 'hide' })
  await page.close()
  return PNG.sync.read(buf)
}

function compare(a, b) {
  const w = Math.min(a.width, b.width)
  const h = Math.min(a.height, b.height)
  const crop = (img) => {
    if (img.width === w && img.height === h) return img
    const out = new PNG({ width: w, height: h })
    PNG.bitblt(img, out, 0, 0, w, h, 0, 0)
    return out
  }
  const A = crop(a)
  const B = crop(b)
  const diff = new PNG({ width: w, height: h })
  const n = pixelmatch(A.data, B.data, diff.data, w, h, { threshold: THRESHOLD, includeAA: true })
  return { n, ratio: n / (w * h), diff, sizeMatch: a.width === b.width && a.height === b.height }
}

async function main() {
  let server = null
  let base = args.base
  if (args['self-test']) {
    server = await serveMocks()
    base = `http://127.0.0.1:${server.address().port}`
  }
  if (!base) {
    console.error('Pass --base http://localhost:8787 (wrangler dev with DESIGN_GALLERY=1) or --self-test')
    process.exit(2)
  }
  mkdirSync(OUT, { recursive: true })
  const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {})
  const results = []
  for (const c of cases()) {
    const name = `${c.slug}${c.state ? `--${c.state}` : ''}.${c.vp}`
    const mockUrl = pathToFileURL(join(MOCKS, c.file)).href
    const implUrl = `${base.replace(/\/$/, '')}/__design/${c.slug}${c.state ? `?state=${c.state}` : ''}`
    try {
      const [mock, impl] = [await shoot(browser, mockUrl, c), await shoot(browser, implUrl, c)]
      const r = compare(mock, impl)
      const pass = r.sizeMatch && r.n <= (ALLOW[name] ?? MAX_PIXELS)
      if (!pass) {
        writeFileSync(join(OUT, `${name}.mock.png`), PNG.sync.write(mock))
        writeFileSync(join(OUT, `${name}.impl.png`), PNG.sync.write(impl))
        writeFileSync(join(OUT, `${name}.diff.png`), PNG.sync.write(r.diff))
      }
      results.push({
        name,
        pass,
        ratio: r.ratio,
        pixels: r.n,
        size: r.sizeMatch ? 'ok' : `mock ${mock.width}x${mock.height} vs impl ${impl.width}x${impl.height}`,
      })
    } catch (e) {
      results.push({ name, pass: false, ratio: 1, pixels: -1, size: String(e.message || e) })
    }
  }
  await browser.close()
  if (server) server.close()
  const failed = results.filter((r) => !r.pass)
  for (const r of results) {
    console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${r.name.padEnd(46)} ${String(r.pixels).padStart(7)} px ${(r.ratio * 100).toFixed(3).padStart(8)}%  ${r.size}`)
  }
  writeFileSync(join(OUT, 'report.json'), JSON.stringify({ threshold: THRESHOLD, maxPixels: MAX_PIXELS, results }, null, 2))
  console.log(`\n${results.length - failed.length}/${results.length} passed · diffs in ${OUT}`)
  process.exit(failed.length ? 1 : 0)
}

main().catch((e) => {
  console.error(e)
  process.exit(2)
})
