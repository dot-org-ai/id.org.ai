#!/usr/bin/env node
/**
 * Smart publish script (ported from primitives.org.ai/scripts/publish.ts).
 *
 * 1. Discovers publishable packages in this repo (private ones are skipped)
 * 2. Rewrites local-only dep specs (`workspace:*`, `file:../…`) to real versions
 * 3. Preflights: dist present, deps resolvable on npm, no `latest` downgrade
 * 4. Auto-logs in to npm if the existing token is missing or expired
 * 5. Publishes with npm web auth (TouchID / WebAuthn)
 * 6. Works both interactively AND from a non-TTY caller (an agent, a CI runner) —
 *    when stdin isn't a TTY, npm refuses to prompt; we wrap the call in `expect`
 *    so npm sees a PTY and we auto-press Enter on its "Press ENTER to open in
 *    the browser…" prompt. The browser opens, the owner authorizes once per OTP,
 *    and the publish proceeds.
 * 7. Restores original package.json files
 *
 * There is no way to publish from this script without a human completing the
 * browser web-auth step: npm is always invoked with `--auth-type=web` login and
 * no token is ever minted here.
 *
 * Usage:
 *   node scripts/publish.ts             # publish (opens the browser)
 *   node scripts/publish.ts --dry-run   # preflight + `npm pack --dry-run`, never publishes
 *   node scripts/publish.ts --only=foo  # restrict to one package (repeatable / comma-separated)
 *
 * Escape hatches (set only if you know what you are doing):
 *   ALLOW_UNPUBLISHABLE_DEPS=1  publish even if a runtime dep isn't on npm
 *   ALLOW_DOWNGRADE=1           publish a version older than the current `latest`
 */

import { execSync, spawnSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const rootDir = join(__dirname, '..')

// ─── repo config (id.org.ai) ────────────────────────────────────────────────
// This repo has no pnpm workspace: the repo root *is* the `id.org.ai` package,
// and `packages/react` (@org.ai/react) is a sibling package installed on its own
// (same convention as `site/`, which uses `pnpm install --ignore-workspace`).
/** Where publishable packages live, relative to the repo root. `dir/*` = every child dir. */
const PACKAGE_GLOBS: string[] = ['packages/*']
/** Is the repo root itself a published package? */
const INCLUDE_ROOT = true
/** Packages never to publish from here, by name. */
const EXCLUDED_PACKAGES = new Set<string>([])
/** Printed when a package that ships `dist` hasn't been built. */
const BUILD_HINT = 'pnpm build && pnpm build:react'
// ────────────────────────────────────────────────────────────────────────────

const DRY_RUN = process.argv.includes('--dry-run')
/** `--only=a,b` narrows the run to those package names. Empty = every publishable package. */
const ONLY = new Set(
  process.argv
    .filter((a) => a.startsWith('--only='))
    .flatMap((a) => a.slice('--only='.length).split(',').filter(Boolean)),
)

/** A dep whose spec only resolves inside this checkout. `version: null` = target missing. */
interface LocalDep {
  name: string
  spec: string
  version: string | null
}

interface PackageJson {
  name: string
  version: string
  private?: boolean
  files?: string[]
  dependencies?: Record<string, string>
  devDependencies?: Record<string, string>
  peerDependencies?: Record<string, string>
}

function getPackageDirs(): string[] {
  const dirs: string[] = []
  if (INCLUDE_ROOT) dirs.push(rootDir)
  for (const glob of PACKAGE_GLOBS) {
    if (glob.endsWith('/*')) {
      const parent = join(rootDir, glob.slice(0, -2))
      if (!existsSync(parent)) continue
      for (const name of readdirSync(parent)) {
        const dir = join(parent, name)
        if (isPackageDir(dir)) dirs.push(dir)
      }
    } else {
      const dir = join(rootDir, glob)
      if (isPackageDir(dir)) dirs.push(dir)
    }
  }
  return dirs
}

function isPackageDir(dir: string): boolean {
  try {
    return statSync(dir).isDirectory() && statSync(join(dir, 'package.json')).isFile()
  } catch {
    return false
  }
}

function readPackageJson(pkgDir: string): PackageJson {
  return JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf-8'))
}

function writePackageJson(pkgDir: string, pkg: PackageJson): void {
  writeFileSync(join(pkgDir, 'package.json'), JSON.stringify(pkg, null, 2) + '\n')
}

/** `true` if this exact name@version is already on the registry. */
function isPublished(name: string, version: string): boolean {
  try {
    execSync(`npm view "${name}@${version}" version`, { stdio: 'pipe' })
    return true
  } catch {
    return false
  }
}

/** The registry's current `latest` for `name`, or null if never published. */
function latestVersion(name: string): string | null {
  try {
    return execSync(`npm view "${name}" version`, { stdio: 'pipe' }).toString().trim() || null
  } catch {
    return null
  }
}

/** -1 | 0 | 1 — plain semver core compare (prerelease tags ignored). */
function compareVersions(a: string, b: string): number {
  const pa = a.split('-')[0].split('.').map(Number)
  const pb = b.split('-')[0].split('.').map(Number)
  for (let i = 0; i < 3; i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0)
    if (d !== 0) return d < 0 ? -1 : 1
  }
  return 0
}

/**
 * `true` if both stdin and stdout are real TTYs — meaning the user is running
 * the script in a terminal and can respond to prompts directly. `false` means
 * we're being invoked by an agent / CI / pipe; npm will refuse to prompt and
 * we need to wrap with `expect` to provide a PTY.
 */
function isInteractive(): boolean {
  return Boolean(process.stdin.isTTY && process.stdout.isTTY)
}

/** `true` if `expect` (the Tcl tool, ships with macOS) is on PATH. */
function hasExpect(): boolean {
  return spawnSync('which', ['expect'], { stdio: 'pipe' }).status === 0
}

/**
 * Tcl program that drives an interactive npm command on our behalf:
 *  - spawns the command with a PTY (so npm thinks it's interactive)
 *  - sends Enter when npm prompts "Press ENTER to open in the browser…"
 *  - waits up to 10 minutes for the user to authorize in the browser
 *  - inherits stdout so all npm output streams through
 */
function expectScript(spawnLine: string): string {
  return [
    'set timeout 600',
    'log_user 1',
    spawnLine,
    'expect {',
    '  -re {Press \\[Enter\\] to open in the browser} { send "\\r"; exp_continue }',
    '  -re {Press ENTER to open}                      { send "\\r"; exp_continue }',
    '  -re {to open in the browser}                   { send "\\r"; exp_continue }',
    '  timeout                                         { puts stderr "*** timeout ***"; exit 2 }',
    '  eof',
    '}',
    'catch wait result',
    'exit [lindex $result 3]',
  ].join('\n')
}

/**
 * Run `npm <args>` in `cwd`, auto-handling the WebAuthn prompt.
 *
 * - TTY mode (a human in a terminal): inherit stdio — npm shows its prompts
 *   directly to the user, who presses Enter and authorizes in the browser
 *   themselves.
 * - Non-TTY mode (agent / pipe): wrap with `expect` so npm sees a PTY and we
 *   auto-feed Enter on "Press ENTER to open in the browser…". The browser opens
 *   via npm's own `open` call; the human authorizes once; publish proceeds. If
 *   `expect` isn't on PATH we fall back to inherit-stdio with a loud warning —
 *   the call will likely fail in non-TTY mode but at least the reason is visible.
 *
 * Returns the process exit code.
 */
function runNpmWithAutoAuth(args: string[], cwd: string): number {
  if (isInteractive()) {
    const result = spawnSync('npm', args, { cwd, stdio: 'inherit' })
    return result.status ?? 1
  }
  if (!hasExpect()) {
    console.warn(
      '[publish] non-TTY caller and `expect` not on PATH — npm prompts will fail. ' +
        'Install expect (macOS ships it; on Linux: `apt install expect`).',
    )
    const result = spawnSync('npm', args, { cwd, stdio: 'inherit' })
    return result.status ?? 1
  }
  const spawnLine = ['spawn', 'npm', ...args].map(quoteForTcl).join(' ')
  const result = spawnSync('expect', ['-c', expectScript(spawnLine)], { cwd, stdio: 'inherit' })
  return result.status ?? 1
}

/** Minimal Tcl quoting: leave alphanum/safe punctuation alone, brace-wrap the rest. */
function quoteForTcl(s: string): string {
  if (/^[A-Za-z0-9._/@:=-]+$/.test(s)) return s
  if (!/[{}\\]/.test(s)) return `{${s}}`
  return `"${s.replace(/[\\$\[\]"]/g, (c) => `\\${c}`)}"`
}

/**
 * Make sure we're logged in before the publish loop kicks off. `npm whoami`
 * exits non-zero with `E401` if the cached token is missing / expired; in that
 * case we trigger `npm login --auth-type=web`, which prints a CLI URL and (with
 * Enter — auto-sent in non-TTY mode) opens it in the browser. After the owner
 * authorizes there, the token is saved to ~/.npmrc and the publish loop reuses it.
 */
function ensureLoggedIn(): void {
  const whoami = spawnSync('npm', ['whoami'], { stdio: 'pipe' })
  if (whoami.status === 0) {
    console.log(`✅ npm logged in as ${whoami.stdout.toString().trim()}`)
    return
  }
  console.log('🔑 npm not logged in — opening browser for web auth...')
  const code = runNpmWithAutoAuth(
    ['login', '--auth-type=web', '--registry=https://registry.npmjs.org/'],
    process.cwd(),
  )
  if (code !== 0) {
    console.error('❌ npm login failed')
    process.exit(code || 1)
  }
}

/**
 * Rewrite dep specs that only resolve inside this checkout:
 *   workspace:*        → the local package's version
 *   workspace:^        → ^version
 *   file:../foo        → ^version read from ../foo/package.json
 * Everything else is left alone. Returns the rewritten map plus the names of
 * every dep we had to rewrite (so the caller can check they exist on npm).
 */
function rewriteLocalDeps(
  deps: Record<string, string> | undefined,
  versionMap: Map<string, string>,
  pkgDir: string,
): { deps: Record<string, string> | undefined; rewritten: LocalDep[] } {
  if (!deps) return { deps, rewritten: [] }

  const result: Record<string, string> = {}
  const rewritten: LocalDep[] = []

  for (const [name, spec] of Object.entries(deps)) {
    if (spec.startsWith('workspace:')) {
      const actual = versionMap.get(name)
      if (!actual) throw new Error(`Could not find version for workspace dependency: ${name}`)
      const prefix = spec.replace('workspace:', '').replace('*', '')
      result[name] = prefix + actual
      rewritten.push({ name, spec, version: actual })
    } else if (spec.startsWith('file:')) {
      const target = resolve(pkgDir, spec.slice('file:'.length))
      let actual = versionMap.get(name) ?? null
      if (!actual && existsSync(join(target, 'package.json'))) {
        actual = (JSON.parse(readFileSync(join(target, 'package.json'), 'utf-8')) as PackageJson).version
      }
      // A null version means the target isn't on disk either — the dep is
      // unresolvable and the preflight will refuse to publish. Leave the original
      // spec in place so the restored package.json is never silently corrupted.
      result[name] = actual ? `^${actual}` : spec
      rewritten.push({ name, spec, version: actual })
    } else {
      result[name] = spec
    }
  }
  return { deps: result, rewritten }
}

async function main() {
  const dirs = getPackageDirs()
  const versionMap = new Map<string, string>()
  const originalContents = new Map<string, string>()
  const toPublish: { dir: string; name: string; version: string }[] = []

  console.log(`Checking which packages need publishing${DRY_RUN ? ' (dry run)' : ''}...\n`)

  for (const dir of dirs) {
    const pkg = readPackageJson(dir)
    versionMap.set(pkg.name, pkg.version)

    if (pkg.private) {
      console.log(`⏭️  ${pkg.name} (private)`)
      continue
    }
    if (EXCLUDED_PACKAGES.has(pkg.name)) {
      console.log(`⏭️  ${pkg.name} (excluded)`)
      continue
    }
    if (ONLY.size > 0 && !ONLY.has(pkg.name)) {
      console.log(`⏭️  ${pkg.name} (not in --only)`)
      continue
    }
    if (isPublished(pkg.name, pkg.version)) {
      console.log(`✅ ${pkg.name}@${pkg.version} (already published)`)
      continue
    }
    console.log(`📦 ${pkg.name}@${pkg.version} (needs publish)`)
    toPublish.push({ dir, name: pkg.name, version: pkg.version })
  }

  if (toPublish.length === 0) {
    console.log('\nAll packages are already published!')
    return
  }

  // ── Preflight. Every failure here is a reason NOT to ship; we bail before
  //    touching a single package.json or contacting the registry to publish.
  console.log('\nPreflight...')
  const problems: string[] = []
  const rewrites = new Map<string, PackageJson>()

  for (const { dir, name, version } of toPublish) {
    const pkg = readPackageJson(dir)

    // 1. Built output must exist if the package ships it.
    for (const entry of pkg.files ?? []) {
      if (entry !== 'dist') continue
      if (!existsSync(join(dir, 'dist'))) {
        problems.push(`${name}: ships "dist" but ${join(dir, 'dist')} is missing — run \`${BUILD_HINT}\` first`)
      }
    }

    // 2. Local-only dep specs must resolve to something a consumer can install.
    let deps, devDeps, peerDeps
    try {
      deps = rewriteLocalDeps(pkg.dependencies, versionMap, dir)
      devDeps = rewriteLocalDeps(pkg.devDependencies, versionMap, dir)
      peerDeps = rewriteLocalDeps(pkg.peerDependencies, versionMap, dir)
    } catch (err) {
      problems.push(`${name}: ${(err as Error).message}`)
      continue
    }

    // devDependencies are never installed by consumers, so a local-only devDep is
    // rewritten but not fatal. dependencies / peerDependencies are load-bearing:
    // a "workspace:*"/"file:" spec that has no registry counterpart means we would
    // ship a package that nobody can install.
    for (const dep of [...deps.rewritten, ...peerDeps.rewritten]) {
      if (!dep.version) {
        problems.push(`${name}: dependency ${dep.name} is "${dep.spec}" and its target is not on disk — unresolvable`)
      } else if (!isPublished(dep.name, dep.version)) {
        problems.push(
          `${name}: dependency ${dep.name}@${dep.version} (from "${dep.spec}") is not on npm — ` +
            `publishing would ship a package nobody can install`,
        )
      }
    }
    for (const dep of devDeps.rewritten) {
      if (!dep.version || !isPublished(dep.name, dep.version)) {
        console.warn(
          `⚠️  ${name}: devDependency ${dep.name} ("${dep.spec}") is not on npm (harmless for consumers)`,
        )
      }
    }

    // 3. Never move the `latest` dist-tag backwards.
    const latest = latestVersion(name)
    if (latest && compareVersions(version, latest) < 0) {
      problems.push(
        `${name}: local version ${version} is older than the published latest ${latest} — ` +
          `publishing would move the \`latest\` tag backwards. Bump the version first.`,
      )
    }

    pkg.dependencies = deps.deps
    pkg.devDependencies = devDeps.deps
    pkg.peerDependencies = peerDeps.deps
    rewrites.set(dir, pkg)
  }

  const fatal = problems.filter(
    (p) =>
      !(
        process.env.ALLOW_UNPUBLISHABLE_DEPS === '1' &&
        (p.includes('is not on npm') || p.includes('unresolvable'))
      ) &&
      !(process.env.ALLOW_DOWNGRADE === '1' && p.includes('backwards')),
  )
  if (fatal.length > 0) {
    console.error('\n❌ Preflight failed — nothing was published:\n')
    for (const p of fatal) console.error(`   • ${p}`)
    console.error(
      '\nPreflight is all-or-nothing on purpose. To ship a package whose siblings are broken, ' +
        'narrow the run: `--only=<name>`.\n',
    )
    process.exit(1)
  }
  console.log('✅ preflight clean')

  // Verify login BEFORE mutating any package.json — if auth is broken we want to
  // bail before touching the workspace. (Skipped on --dry-run: pack needs no auth.)
  if (!DRY_RUN) ensureLoggedIn()

  console.log('\nPreparing packages...')
  for (const { dir } of toPublish) {
    const pkgJsonPath = join(dir, 'package.json')
    originalContents.set(pkgJsonPath, readFileSync(pkgJsonPath, 'utf-8'))
    const rewritten = rewrites.get(dir)
    if (rewritten) writePackageJson(dir, rewritten)
  }

  let failed = false
  try {
    console.log(`\n${DRY_RUN ? 'Packing' : 'Publishing'} ${toPublish.length} package(s)...\n`)
    for (const { dir, name, version } of toPublish) {
      if (DRY_RUN) {
        console.log(`\n📦 npm pack --dry-run ${name}@${version}...`)
        const status = spawnSync('npm', ['pack', '--dry-run'], { cwd: dir, stdio: 'inherit' }).status ?? 1
        if (status !== 0) {
          console.error(`❌ pack failed for ${name}@${version}`)
          failed = true
          break
        }
        continue
      }
      console.log(`\n📤 Publishing ${name}@${version}...`)
      const status = runNpmWithAutoAuth(['publish', '--access', 'public'], dir)
      if (status !== 0) {
        console.error(`❌ Failed to publish ${name}@${version}`)
        failed = true
        break
      }
      console.log(`✅ Published ${name}@${version}`)
    }
  } finally {
    // Always restore, even if a publish threw — a half-rewritten workspace is worse
    // than a failed publish.
    console.log('\nRestoring package.json files...')
    for (const [path, content] of originalContents) writeFileSync(path, content)
  }

  if (failed) process.exit(1)
  console.log(DRY_RUN ? '\n🎉 Dry run complete — nothing published.' : '\n🎉 All packages published!')
}

main()
