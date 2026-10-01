#!/usr/bin/env node
/**
 * pnpm gate: the phase gate from docs/product-update/autopilot.md, in order:
 *   1. pnpm build:ui        (first, so worker/ui/assets.json is fresh)
 *   2. pnpm typecheck       (root, worker, client scripts, UI tests)
 *   3. pnpm test            (workers pool, node config, UI config)
 *   4. wrangler deploy --dry-run   (bundle check only; never deploys)
 * Then it fails if the gate itself changed the working tree (build:ui must be
 * deterministic). The visual diff is separate: it needs `wrangler dev` running.
 */
import { execSync, spawnSync } from 'node:child_process'

const status = () => execSync('git status --porcelain', { encoding: 'utf8' })
const before = status()

const steps = [
  ['build:ui', 'pnpm', ['build:ui']],
  ['typecheck', 'pnpm', ['typecheck']],
  ['test', 'pnpm', ['test']],
  ['dry-run', 'npx', ['wrangler', 'deploy', '--dry-run', '--outdir', '/tmp/idorg-dry'], { cwd: 'worker' }],
]
for (const [name, cmd, argv, opts] of steps) {
  console.log(`\n── gate: ${name} ──`)
  const r = spawnSync(cmd, argv, { stdio: 'inherit', ...(opts ?? {}) })
  if (r.status !== 0) {
    console.error(`\ngate FAILED at ${name}`)
    process.exit(1)
  }
}

const after = status()
if (after !== before) {
  console.error('\ngate FAILED: the gate changed the working tree:\n' + after)
  process.exit(1)
}
console.log('\ngate: green')
