#!/usr/bin/env node
/** Dev aid: node test-visual/shot.mjs <path> <out.png> [width] [height] [--full] [--clip-from <text>] */
import { chromium } from 'playwright'
import { findChromium } from '../scripts/chromium.mjs'
const [path, out, w = '720', h = '900'] = process.argv.slice(2)
const full = process.argv.includes('--full')
const bin = findChromium()
const browser = await chromium.launch(bin ? { executablePath: bin } : {})
const page = await browser.newPage({ viewport: { width: Number(w), height: Number(h) }, deviceScaleFactor: 1 })
const errors = []
page.on('console', (m) => m.type() === 'error' && errors.push(m.text()))
page.on('pageerror', (e) => errors.push(String(e)))
const res = await page.goto((process.env.VISUAL_BASE || 'http://localhost:8787') + path, { waitUntil: 'load' })
await page.evaluate(() => document.fonts.ready)
await page.screenshot({ path: out, fullPage: full, animations: 'disabled' })
console.log(res.status(), await page.evaluate(() => document.documentElement.scrollHeight), errors.join(' | '))
await browser.close()
