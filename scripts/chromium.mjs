/**
 * Which Chromium the browser checks use: CHROMIUM_PATH if set, Playwright's
 * pinned build if installed, otherwise the newest headless shell already in
 * the Playwright cache (so no browser download is ever needed).
 */
import { existsSync, readdirSync } from 'node:fs'
import { homedir, platform } from 'node:os'
import { join } from 'node:path'
import { chromium, webkit } from 'playwright'

const cacheDir = () => process.env.PLAYWRIGHT_BROWSERS_PATH || (platform() === 'darwin' ? join(homedir(), 'Library/Caches/ms-playwright') : join(homedir(), '.cache/ms-playwright'))

export function findChromium() {
  if (process.env.CHROMIUM_PATH) return process.env.CHROMIUM_PATH
  if (existsSync(chromium.executablePath())) return chromium.executablePath()
  const cache = cacheDir()
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

/**
 * Which WebKit (Safari's engine) the phone check uses: WEBKIT_PATH if set,
 * Playwright's pinned build if installed, otherwise the newest WebKit already
 * in the Playwright cache. Undefined when there is none: the check skips WebKit.
 */
export function findWebkit() {
  if (process.env.WEBKIT_PATH) return process.env.WEBKIT_PATH
  if (existsSync(webkit.executablePath())) return webkit.executablePath()
  const cache = cacheDir()
  const builds = existsSync(cache)
    ? readdirSync(cache)
        .filter((d) => d.startsWith('webkit-'))
        .sort((a, b) => Number(b.split('-')[1]) - Number(a.split('-')[1]))
    : []
  for (const dir of builds) {
    const bin = join(cache, dir, 'pw_run.sh')
    if (existsSync(bin)) return bin
  }
  return undefined
}
