/**
 * CLI version — read from the nearest package.json at runtime so `--version`
 * always matches what was published (the bundled dist lives at
 * dist/sdk/cli/index.js, the source at src/sdk/cli/index.ts; both are three
 * levels below the package root).
 */

import { readFileSync } from 'fs'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

const PACKAGE_NAME = 'id.org.ai'

export function getCliVersion(from: string = import.meta.url): string {
  try {
    let dir = dirname(fileURLToPath(from))
    for (let i = 0; i < 6; i++) {
      try {
        const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf-8')) as { name?: string; version?: string }
        if (pkg.name === PACKAGE_NAME && pkg.version) return pkg.version
      } catch {
        // no package.json here — keep walking up
      }
      const parent = dirname(dir)
      if (parent === dir) break
      dir = parent
    }
  } catch {
    // fileURLToPath can throw for non-file URLs
  }
  return 'unknown'
}
