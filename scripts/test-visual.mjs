#!/usr/bin/env node
/**
 * pnpm test:visual [--base <url>] [--only 1a,4b] …
 *
 * Runs docs/product-update/tools/visual-diff.mjs against a running
 * `wrangler dev` (DESIGN_GALLERY=1). The harness itself is never edited; this
 * wrapper only supplies the default --base and CHROMIUM_PATH (scripts/chromium.mjs).
 */
import { spawnSync } from 'node:child_process'
import { findChromium } from './chromium.mjs'

const args = process.argv.slice(2)
if (!args.includes('--base') && !args.includes('--self-test')) args.unshift('--base', process.env.VISUAL_BASE || 'http://localhost:8787')

const env = { ...process.env }
const bin = findChromium()
if (bin) env.CHROMIUM_PATH = bin
console.log(`test:visual · chromium ${bin ?? '(playwright default)'}`)
const r = spawnSync(process.execPath, ['docs/product-update/tools/visual-diff.mjs', ...args], { stdio: 'inherit', env })
process.exit(r.status ?? 1)
