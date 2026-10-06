#!/usr/bin/env node
/**
 * Phones and touch screens (owner direction, 2026-10-06), in real Chromium and
 * WebKit (Safari's engine), against every page and state of the running gallery:
 *
 * - Phone (390×844, touch): every visible field is 16px text or larger (iOS
 *   Safari zooms the page on focus below 16px); inputs, selects and md buttons
 *   are 48px tall; the connector shows three dots and 48px tiles; the tap
 *   flash is off.
 * - Landscape phone (844×390, touch): fields are still 16px (wider than the
 *   phone breakpoint, so this needs the coarse-pointer rule).
 * - Focus: a focused field shows the select border and the 3px ring.
 * - Desktop (1280×800, mouse): fields stay 14px and tiles 56px, as the mocks.
 *
 *   pnpm test:phone [--base http://localhost:8787] [--browser chromium|webkit]
 */
import { chromium, webkit } from 'playwright'
import { findChromium, findWebkit } from '../scripts/chromium.mjs'

const argv = process.argv.slice(2)
const arg = (name) => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : undefined)
const base = (arg('--base') || process.env.VISUAL_BASE || 'http://localhost:8787').replace(/\/$/, '')
const only = arg('--browser')

const FIELDS = 'input:not([type=hidden]):not(.id-hidden-input), select, textarea'

/** Every gallery page and state, from the index. */
async function galleryPaths(page) {
  await page.goto(`${base}/__design`)
  const hrefs = await page.$$eval('a[href^="/__design/"]', (as) => as.map((a) => a.getAttribute('href')))
  return [...new Set(hrefs)].filter((h) => !h.startsWith('/__design/components'))
}

/** Measures one page: visible fields, md controls, the connector, the tap flash. */
function measure(FIELDS) {
  const visible = (el) => {
    const r = el.getBoundingClientRect()
    return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden'
  }
  const fields = [...document.querySelectorAll(FIELDS)].filter(visible).map((el) => ({
    what: el.id || el.name || el.className,
    font: parseFloat(getComputedStyle(el).fontSize),
    height: el.classList.contains('id-input') && el.tagName !== 'TEXTAREA' ? el.getBoundingClientRect().height : null,
  }))
  const buttons = [...document.querySelectorAll('.id-btn:not(.id-btn--sm)')].filter(visible).map((el) => ({ what: el.textContent.trim().slice(0, 30), height: el.getBoundingClientRect().height }))
  const conn = document.querySelector('.id-conn')
  const dots = conn ? [...conn.querySelectorAll('.id-conn__dot')].filter((d) => getComputedStyle(d).display !== 'none').length : null
  const tile = document.querySelector('.id-head .id-tile')
  const tileSize = tile ? tile.getBoundingClientRect().width : null
  // Email previews (8a–8c) carry their own inline styles, not the page stylesheet.
  const styled = !!document.querySelector('link[rel=stylesheet][href*="/auth/ui."]')
  return { fields, buttons, dots, tileSize, tap: styled ? getComputedStyle(document.body).webkitTapHighlightColor : null }
}

let failed = 0
const fail = (msg) => {
  console.log(`FAIL ${msg}`)
  failed++
}

const webkitPath = findWebkit()
if (!webkitPath && only !== 'chromium') console.log('note: no WebKit in the Playwright cache; checking Chromium only (`pnpm exec playwright install webkit` adds it)')
const engines = [
  ['chromium', chromium, findChromium()],
  ['webkit', webkit, webkitPath],
].filter(([name, , path]) => (!only || only === name) && (name !== 'webkit' || path))

for (const [name, type, executablePath] of engines) {
  const browser = await type.launch(executablePath ? { executablePath } : {})
  const phone = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: name !== 'firefox', hasTouch: true, deviceScaleFactor: 2 })
  const page = await phone.newPage()
  const paths = await galleryPaths(page)
  let fieldCount = 0
  let connectors = 0
  for (const path of paths) {
    const res = await page.goto(base + path)
    if (!res || res.status() !== 200) {
      fail(`${name} ${path}: HTTP ${res?.status()}`)
      continue
    }
    const m = await page.evaluate(measure, FIELDS)
    for (const f of m.fields) {
      fieldCount++
      if (f.font < 16) fail(`${name} phone ${path}: field ${f.what} is ${f.font}px text (iOS zooms below 16px)`)
      if (f.height !== null && f.height < 47.5) fail(`${name} phone ${path}: field ${f.what} is ${f.height}px tall (want 48)`)
    }
    for (const b of m.buttons) if (b.height < 47.5) fail(`${name} phone ${path}: button "${b.what}" is ${b.height}px tall (want 48)`)
    if (m.dots !== null) {
      connectors++
      if (m.dots !== 3) fail(`${name} phone ${path}: connector shows ${m.dots} dots (want 3)`)
    }
    if (m.tileSize !== null && Math.abs(m.tileSize - 48) > 0.5) fail(`${name} phone ${path}: head tile is ${m.tileSize}px (want 48)`)
    if (m.tap !== null && m.tap !== 'rgba(0, 0, 0, 0)') fail(`${name} phone ${path}: tap highlight is ${m.tap}`)
  }
  if (!fieldCount || !connectors) fail(`${name}: measured ${fieldCount} fields and ${connectors} connectors; the check found nothing to check`)

  // Focus: the sign-in email field gets the select border and the 3px ring.
  await page.goto(`${base}/__design/1a-sign-in`)
  await page.focus('input[type=email]')
  const ring = await page.$eval('input[type=email]', (el) => ({ shadow: getComputedStyle(el).boxShadow, border: getComputedStyle(el).borderTopColor }))
  if (!/0px 0px 0px 3px/.test(ring.shadow)) fail(`${name}: focused field has no ring (box-shadow ${ring.shadow})`)
  await page.goto(`${base}/__design/1a-sign-in`)
  const rest = await page.$eval('input[type=email]', (el) => getComputedStyle(el).borderTopColor)
  if (rest === ring.border) fail(`${name}: focused field border doesn't change (${rest})`)
  await phone.close()

  // Landscape phone: wider than 480px, still a touch screen.
  const landscape = await browser.newContext({ viewport: { width: 844, height: 390 }, isMobile: true, hasTouch: true })
  const lpage = await landscape.newPage()
  for (const path of ['/__design/1a-sign-in', '/__design/1d-first-run', '/__design/5a-agent-approve']) {
    await lpage.goto(base + path)
    const coarse = await lpage.evaluate(() => matchMedia('(pointer: coarse)').matches)
    if (!coarse) {
      console.log(`note ${name} landscape: the browser doesn't emulate a coarse pointer; skipped`)
      break
    }
    const m = await lpage.evaluate(measure, FIELDS)
    for (const f of m.fields) if (f.font < 16) fail(`${name} landscape ${path}: field ${f.what} is ${f.font}px text`)
  }
  await landscape.close()

  // Desktop with a mouse: unchanged from the mocks.
  const desktop = await browser.newContext({ viewport: { width: 1280, height: 800 } })
  const dpage = await desktop.newPage()
  for (const path of ['/__design/1a-sign-in', '/__design/5a-agent-approve']) {
    await dpage.goto(base + path)
    const m = await dpage.evaluate(measure, FIELDS)
    for (const f of m.fields) if (f.font !== 14 && !/id-code__box/.test(f.what)) fail(`${name} desktop ${path}: field ${f.what} is ${f.font}px (desktop stays 14px)`)
    if (m.dots !== null && m.dots !== 5) fail(`${name} desktop ${path}: connector shows ${m.dots} dots (want 5)`)
    if (m.tileSize !== null && Math.abs(m.tileSize - 56) > 0.5) fail(`${name} desktop ${path}: head tile is ${m.tileSize}px (want 56)`)
  }
  await desktop.close()
  await browser.close()
  console.log(`${name}: ${paths.length} pages, ${fieldCount} fields, ${connectors} connectors checked`)
}

console.log(failed ? `${failed} failure(s)` : 'phone check passed')
process.exit(failed ? 1 : 0)
