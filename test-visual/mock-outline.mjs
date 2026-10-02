#!/usr/bin/env node
/**
 * Print a mock's element tree with each element's inline style, so a component
 * can be matched to the mock without reading minified HTML.
 *
 *   node test-visual/mock-outline.mjs 1a-sign-in            # by slug (or file name)
 *   node test-visual/mock-outline.mjs 4b-device-confirm --svg # include <svg> internals
 *
 * Dev aid only: it reads docs/product-update/mocks/screens/*.html and never writes.
 */
import { readFileSync, existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Window } from 'happy-dom'

const HERE = dirname(fileURLToPath(import.meta.url))
const SCREENS = resolve(HERE, '../docs/product-update/mocks/screens')

const arg = process.argv[2]
if (!arg) {
  console.error('usage: node test-visual/mock-outline.mjs <slug> [--svg]')
  process.exit(2)
}
const showSvg = process.argv.includes('--svg')
const file = [arg, `${arg}.html`].map((f) => join(SCREENS, f)).find((f) => existsSync(f))
if (!file) {
  console.error(`no mock named ${arg}`)
  process.exit(2)
}

const window = new Window()
window.document.write(readFileSync(file, 'utf8'))
const { document } = window

function attrs(el) {
  const out = []
  for (const a of el.attributes) {
    if (a.name === 'style') continue
    if (a.name === 'd' && a.value.length > 40) {
      out.push(`d="${a.value.slice(0, 40)}…"`)
      continue
    }
    out.push(a.value === '' ? a.name : `${a.name}="${a.value}"`)
  }
  return out.length ? ' ' + out.join(' ') : ''
}

function walk(node, depth) {
  const pad = '  '.repeat(depth)
  if (node.nodeType === 3) {
    const t = node.textContent.replace(/\s+/g, ' ')
    if (t.trim()) console.log(`${pad}"${t}"`)
    return
  }
  if (node.nodeType !== 1) return
  const tag = node.tagName.toLowerCase()
  if (tag === 'script' || tag === 'style') {
    console.log(`${pad}<${tag}> (${node.textContent.length} chars)`)
    return
  }
  const style = node.getAttribute('style')
  console.log(`${pad}<${tag}${attrs(node)}>${style ? `  { ${style} }` : ''}`)
  if (tag === 'svg' && !showSvg) return
  for (const child of node.childNodes) walk(child, depth + 1)
}

walk(document.body, 0)
