/**
 * Which Chromium the browser checks use: CHROMIUM_PATH if set, Playwright's
 * pinned build if installed, otherwise the newest headless shell already in
 * the Playwright cache (so no browser download is ever needed).
 */
import { existsSync, readdirSync } from 'node:fs'
import { homedir, platform } from 'node:os'
import { join } from 'node:path'
import { chromium } from 'playwright'

export function findChromium() {
  if (process.env.CHROMIUM_PATH) return process.env.CHROMIUM_PATH
  if (existsSync(chromium.executablePath())) return chromium.executablePath()
  const cache = process.env.PLAYWRIGHT_BROWSERS_PATH || (platform() === 'darwin' ? join(homedir(), 'Library/Caches/ms-playwright') : join(homedir(), '.cache/ms-playwright'))
  const shells = existsSync(cache)
    ? readdirSync(cache)
        .filter((d) => d.startsWith('chromium_headless_shell-'))
        .sort((a, b) => Number(b.split('-')[1]) - Number(a.split('-')[1]))
    : []
  for (const dir of shells) {
    for (const sub of readdirSync(join(cache, dir))) {
      const bin = join(cache, dir, sub, platform() === 'win32' ? 'chrome-headless-shell.exe' : 'chrome-headless-shell')
      if (existsSync(bin)) return bin
    }
  }
  return undefined
}
