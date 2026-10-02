#!/usr/bin/env node
/**
 * Catalogue every distinct inline style in the mocks (tag + style), with how
 * many screens use it. Dev aid for building the component CSS.
 *   node test-visual/mock-styles.mjs [--min 2] [--grep border-radius]
 */
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Window } from 'happy-dom'

const SCREENS = resolve(dirname(fileURLToPath(import.meta.url)), '../docs/product-update/mocks/screens')
const argv = process.argv.slice(2)
const min = Number(argv[argv.indexOf('--min') + 1] || 1) || 1
const grep = argv.includes('--grep') ? argv[argv.indexOf('--grep') + 1] : null
const skip = new Set(['0-flow-map.html', '2d-connect-motion.html', '4a-cli-terminal.html'])
const seen = new Map()
for (const f of readdirSync(SCREENS).filter((f) => f.endsWith('.html') && !skip.has(f))) {
  const w = new Window()
  w.document.write(readFileSync(join(SCREENS, f), 'utf8'))
  for (const el of w.document.querySelectorAll('[style]')) {
    if (el.closest('svg') && el.tagName.toLowerCase() !== 'svg') continue
    const style = el.getAttribute('style').replace(/\s+/g, ' ').trim().replace(/;\s*$/, '')
    const key = `${el.tagName.toLowerCase()} { ${style} }`
    const e = seen.get(key) ?? { n: 0, files: new Set() }
    e.n++
    e.files.add(f.replace('.html', ''))
    seen.set(key, e)
  }
}
const rows = [...seen].filter(([k, e]) => e.files.size >= min && (!grep || k.includes(grep))).sort((a, b) => b[1].files.size - a[1].files.size)
for (const [k, e] of rows) console.log(`${String(e.files.size).padStart(3)} ${String(e.n).padStart(4)}  ${k}${e.files.size <= 3 ? '   [' + [...e.files].join(', ') + ']' : ''}`)
console.log(`\n${rows.length} distinct styles`)
