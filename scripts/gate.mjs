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
import { createHash } from 'node:crypto'
import { execSync, spawnSync } from 'node:child_process'

/** Content hash of every change against HEAD plus the untracked file list (not just paths). */
function treeState() {
  const diff = execSync('git diff HEAD --binary', { maxBuffer: 1 << 30 })
  const untracked = execSync('git ls-files --others --exclude-standard', { encoding: 'utf8' })
  const hash = createHash('sha256').update(diff).update(untracked)
  for (const f of untracked.split('\n').filter(Boolean)) {
    try {
      hash.update(execSync(`git hash-object -- ${JSON.stringify(f)}`))
    } catch {
      // vanished mid-run; the list hash already records it
    }
  }
  return hash.digest('hex')
}
const status = () => execSync('git status --porcelain', { encoding: 'utf8' })
const before = treeState()

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

if (treeState() !== before) {
  console.error('\ngate FAILED: the gate changed the working tree:\n' + status())
  process.exit(1)
}
console.log('\ngate: green')
