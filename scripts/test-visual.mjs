#!/usr/bin/env node
/**
 * pnpm test:visual [--base <url>] [--only 1a,4b] …
 *
 * Runs docs/product-update/tools/visual-diff.mjs against a running
 * `wrangler dev` (DESIGN_GALLERY=1). The harness itself is never edited; this
 * wrapper only supplies the default --base and, when Playwright's pinned
 * Chromium isn't installed, points CHROMIUM_PATH at the newest headless shell
 * already in the Playwright cache, so no browser download is needed.
 */
import { spawnSync } from 'node:child_process'
import { existsSync, readdirSync } from 'node:fs'
import { homedir, platform } from 'node:os'
import { join } from 'node:path'

const args = process.argv.slice(2)
if (!args.includes('--base') && !args.includes('--self-test')) args.unshift('--base', process.env.VISUAL_BASE || 'http://localhost:8787')

const env = { ...process.env }
if (!env.CHROMIUM_PATH) {
  const cache = process.env.PLAYWRIGHT_BROWSERS_PATH || (platform() === 'darwin' ? join(homedir(), 'Library/Caches/ms-playwright') : join(homedir(), '.cache/ms-playwright'))
  const shells = existsSync(cache) ? readdirSync(cache).filter((d) => d.startsWith('chromium_headless_shell-')).sort((a, b) => Number(b.split('-')[1]) - Number(a.split('-')[1])) : []
  for (const dir of shells) {
    for (const sub of readdirSync(join(cache, dir))) {
      const bin = join(cache, dir, sub, platform() === 'win32' ? 'chrome-headless-shell.exe' : 'chrome-headless-shell')
      if (existsSync(bin)) {
        env.CHROMIUM_PATH = bin
        break
      }
    }
    if (env.CHROMIUM_PATH) break
  }
}

const r = spawnSync(process.execPath, ['docs/product-update/tools/visual-diff.mjs', ...args], { stdio: 'inherit', env })
process.exit(r.status ?? 1)
