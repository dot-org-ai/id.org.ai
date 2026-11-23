#!/usr/bin/env node
/**
 * Dev aid: measures Stripe's real Payment Element (inside its frame) against our own
 * controls and tokens, property by property, so "it matches" is a measurement.
 * Needs the dev server started with `--var STRIPE_PUBLISHABLE_KEY:pk_test_…`.
 *   node test-visual/stripe-live-measure.mjs [--width 720]
 */
import { chromium } from 'playwright'
import { findChromium } from '../scripts/chromium.mjs'
const argv = process.argv.slice(2)
const W = Number(argv.includes('--width') ? argv[argv.indexOf('--width') + 1] : 720)
const BASE = process.env.VISUAL_BASE || 'http://localhost:8787'
const browser = await chromium.launch({ executablePath: findChromium() })
const PROPS = ['height', 'fontFamily', 'fontSize', 'fontWeight', 'lineHeight', 'color', 'backgroundColor', 'borderTopColor', 'borderTopWidth', 'borderTopLeftRadius', 'boxShadow', 'paddingLeft', 'letterSpacing']
// Colours are compared as painted pixels, so oklch() on our side and rgb() on Stripe's are the same thing when they are.
const read = (el, props) => {
  const ctx = document.createElement('canvas').getContext('2d', { willReadFrequently: true })
  const px = (c) => { ctx.clearRect(0, 0, 1, 1); ctx.fillStyle = c; ctx.fillRect(0, 0, 1, 1); const [r, g, b, a] = ctx.getImageData(0, 0, 1, 1).data; return `rgba(${r},${g},${b},${(a / 255).toFixed(2)})` }
  const norm = (v) => String(v).replace(/(oklch|rgba?)\([^)]*\)/g, px)
  const s = getComputedStyle(el)
  return Object.fromEntries(props.map((p) => [p, p === 'height' ? Math.round(el.getBoundingClientRect().height) + 'px' : norm(s[p])]))
}

// Ours: a real .id-input, .id-label and the segmented cells, from the component sheet.
const ours = await browser.newPage({ viewport: { width: W, height: 900 }, hasTouch: W <= 480 })
await ours.goto(BASE + '/__design/components'); await ours.evaluate(() => document.fonts.ready)
const want = await ours.evaluate(([props, readSrc]) => {
  const read = eval(readSrc)
  const input = document.querySelector('input.id-input'); const label = document.querySelector('label.id-label')
  // Our picture of Stripe's tabs (what shows until the element mounts), so nothing shifts when it does.
  const on = document.querySelector('.id-stripe__tab--on'); const off = document.querySelector('.id-stripe__tab:not(.id-stripe__tab--on)')
  input.focus(); const focus = read(input, props); input.blur()
  const ph = read(input, []) && getComputedStyle(input, '::placeholder').color
  return { input: read(input, props), inputFocus: focus, placeholder: ph, label: read(label, props), tabOn: read(on, props), tabOff: read(off, props) }
}, [PROPS, `(${read.toString()})`])
await ours.close()

const page = await browser.newPage({ viewport: { width: W, height: 1000 }, hasTouch: W <= 480 })
await page.goto(BASE + '/__design/19a-stripe-live'); await page.evaluate(() => document.fonts.ready)
await page.waitForSelector('[data-stripe-mount] iframe', { timeout: 20000 }); await page.waitForTimeout(4000)
const frame = page.frames().find((f) => f.url().includes('elements-inner-payment'))
if (!frame) { console.log('Stripe payment frame not found:', page.frames().map((f) => f.url().slice(0, 60))); process.exit(1) }
const got = await frame.evaluate(async ([props, readSrc]) => {
  const read = eval(readSrc)
  await document.fonts.ready
  const input = document.querySelector('input.Input, .Input'); const label = document.querySelector('.Label')
  const on = document.querySelector('.Tab--selected'); const off = document.querySelector('.Tab:not(.Tab--selected)')
  const ph = getComputedStyle(input, '::placeholder').color
  const rest = read(input, props)
  input.focus(); await new Promise((r) => setTimeout(r, 400)); const focus = read(input, props); input.blur()
  return { input: rest, inputFocus: focus, placeholder: ph, label: read(label, props), tabOn: read(on, props), tabOff: off ? read(off, props) : null,
    geist: document.fonts.check('14px Geist'), fonts: [...document.fonts].map((f) => f.family + ':' + f.status).slice(0, 6),
    text: [...document.querySelectorAll('.Text, p')].slice(0, 2).map((e) => read(e, ['fontSize', 'color', 'lineHeight'])) }
}, [PROPS, `(${read.toString()})`])
await browser.close()

let diffs = 0
for (const part of ['input', 'inputFocus', 'label', 'tabOn', 'tabOff']) {
  for (const p of PROPS) {
    const a = want[part]?.[p]; const b = got[part]?.[p]
    if (p === 'lineHeight') continue // ours is `normal`; the box heights are what must agree
    if (a !== b) { diffs++; console.log(`${part.padEnd(10)} ${p.padEnd(20)} ours ${String(a).slice(0, 70).padEnd(40)} stripe ${String(b).slice(0, 90)}`) }
  }
}
console.log(`placeholder colour: ours ${want.placeholder} · stripe ${got.placeholder}`)
console.log(`\nGeist loaded in Stripe's frame: ${got.geist}  (${got.fonts.join(', ')})`)
console.log('Stripe note text:', JSON.stringify(got.text))
console.log(`${diffs} differences at ${W}px`)
