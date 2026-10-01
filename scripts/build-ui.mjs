#!/usr/bin/env node
/**
 * Build the auth UI's static assets into worker/public (docs/product-update/prompts/01-foundation.md).
 *
 *   worker/ui/client/<name>.ts      → worker/public/auth/<name>.<hash>.js   (esbuild, esm, minified)
 *   worker/ui/tokens.css + ui.css   → worker/public/auth/ui.<hash>.css      (concatenated as is)
 *   geist@1.7.2 variable woff2      → worker/public/fonts/geist/
 *   worker/ui/static/**             → worker/public/**
 *   worker/ui/assets.json           ← logical name → hashed path
 *
 * Runs after build:site (which wipes worker/public). Deterministic and idempotent:
 * it deletes its own outputs first, so no stale hashed files are left behind.
 * The CSS is not minified: colour minification could change oklch() values.
 */
import { createHash } from 'node:crypto'
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const UI = join(ROOT, 'worker/ui')
const PUBLIC = join(ROOT, 'worker/public')
const OUT_AUTH = join(PUBLIC, 'auth')
const OUT_FONTS = join(PUBLIC, 'fonts/geist')
const require_ = (p) => join(ROOT, 'node_modules', p)

const hash = (buf) => createHash('sha256').update(buf).digest('hex').slice(0, 10)

rmSync(OUT_AUTH, { recursive: true, force: true })
rmSync(OUT_FONTS, { recursive: true, force: true })
mkdirSync(OUT_AUTH, { recursive: true })
mkdirSync(OUT_FONTS, { recursive: true })

const assets = {}

// ── Client scripts: one bundle per top-level worker/ui/client/*.ts ──────────
const CLIENT = join(UI, 'client')
const entries = existsSync(CLIENT)
  ? readdirSync(CLIENT)
      .filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts') && !f.endsWith('.d.ts'))
      .sort()
  : []
for (const file of entries) {
  const name = file.replace(/\.ts$/, '')
  const result = await build({
    entryPoints: [join(CLIENT, file)],
    bundle: true,
    format: 'esm',
    minify: true,
    target: 'es2020',
    write: false,
    legalComments: 'none',
    tsconfig: join(CLIENT, 'tsconfig.json'),
  })
  const code = result.outputFiles[0].contents
  const out = `${name}.${hash(code)}.js`
  writeFileSync(join(OUT_AUTH, out), code)
  assets[`${name}.js`] = `/auth/${out}`
}

// ── Stylesheet ──────────────────────────────────────────────────────────────
const css = Buffer.from(readFileSync(join(UI, 'tokens.css'), 'utf8') + '\n' + readFileSync(join(UI, 'ui.css'), 'utf8'))
const cssOut = `ui.${hash(css)}.css`
writeFileSync(join(OUT_AUTH, cssOut), css)
assets['ui.css'] = `/auth/${cssOut}`

// ── Gallery stylesheet (dev only; never linked from a production page) ───────
const galleryCss = readFileSync(join(UI, 'gallery/gallery.css'))
const galleryOut = `gallery.${hash(galleryCss)}.css`
writeFileSync(join(OUT_AUTH, galleryOut), galleryCss)
assets['gallery.css'] = `/auth/${galleryOut}`

// ── Fonts (byte-identical to docs/product-update/mocks/fonts) ────────────────
cpSync(require_('geist/dist/fonts/geist-sans/Geist-Variable.woff2'), join(OUT_FONTS, 'Geist-Variable.woff2'))
cpSync(require_('geist/dist/fonts/geist-mono/GeistMono-Variable.woff2'), join(OUT_FONTS, 'GeistMono-Variable.woff2'))

// ── Static files (brand marks …) ─────────────────────────────────────────────
// worker/ui/static.json lists what the last run copied, so a renamed or
// deleted file doesn't linger in worker/public.
const STATIC = join(UI, 'static')
const STATIC_LIST = join(UI, 'static.json')
const previous = existsSync(STATIC_LIST) ? JSON.parse(readFileSync(STATIC_LIST, 'utf8')) : []
for (const rel of previous) rmSync(join(PUBLIC, rel), { force: true })
const copied = []
function copyTree(dir) {
  for (const f of readdirSync(dir).sort()) {
    const p = join(dir, f)
    if (statSync(p).isDirectory()) copyTree(p)
    else if (f !== '.gitkeep') {
      const rel = relative(STATIC, p)
      const dest = join(PUBLIC, rel)
      mkdirSync(dirname(dest), { recursive: true })
      cpSync(p, dest)
      copied.push(rel)
    }
  }
}
if (existsSync(STATIC)) copyTree(STATIC)
writeFileSync(STATIC_LIST, JSON.stringify(copied, null, 2) + '\n')

// ── Manifest (sorted, so the file only changes when an asset does) ───────────
const sorted = Object.fromEntries(Object.entries(assets).sort(([a], [b]) => a.localeCompare(b)))
writeFileSync(join(UI, 'assets.json'), JSON.stringify(sorted, null, 2) + '\n')
console.log(`build:ui · ${entries.length} script(s), ${cssOut}, fonts`)
