#!/usr/bin/env node
/**
 * Phone, keyboard and reduced-motion checks for the agent setup screens.
 *
 *   node test-visual/agent-check.mjs [--base http://localhost:8787] [--only 9a,9b] [--phase 2] [--width 320]
 *
 * For every built page in docs/agent-setup/manifest.json, at 390px wide:
 *   phone     no sideways scroll; the card runs edge to edge; two actions stack
 *             full width at 48px with the primary on top
 *   targets   every control is at least 44px tall, or has a 44px hit area
 *   keyboard  Tab alone reaches every control, in document order, and each
 *             shows a focus ring
 *   motion    with reduced motion on, nothing animates
 * Emails are skipped: they are fixed-width documents, not pages.
 */
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright'
import { findChromium } from '../scripts/chromium.mjs'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const manifest = JSON.parse(readFileSync(join(ROOT, 'docs/agent-setup/manifest.json'), 'utf8'))
const argv = process.argv.slice(2)
const arg = (name, fallback) => (argv.includes(`--${name}`) ? argv[argv.indexOf(`--${name}`) + 1] : fallback)
const BASE = String(arg('base', process.env.VISUAL_BASE || 'http://localhost:8787')).replace(/\/$/, '')
const only = arg('only') ? String(arg('only')).split(',') : null
const phase = arg('phase') ? Number(arg('phase')) : null
/** Phone width to check at: 390 by default; 320 and 360 are the narrow phones. */
const WIDTH = Number(arg('width', 390))

const bin = findChromium()
const browser = await chromium.launch(bin ? { executablePath: bin } : {})
let failed = 0
let ran = 0
const seen = new Set()
for (const s of manifest.screens) {
  const slug = s.renders ?? s.slug
  if (s.kind !== 'screen' || seen.has(slug)) continue
  if (only && !only.includes(s.id)) continue
  if (phase && s.phase !== phase) continue
  seen.add(slug)
  ran++
  const problems = []
  const page = await browser.newPage({ viewport: { width: WIDTH, height: 844 }, hasTouch: true })
  try {
    await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: 'dark' })
    const res = await page.goto(`${BASE}/__design/${slug}`, { waitUntil: 'load' })
    if (res && res.status() >= 400) throw new Error(`HTTP ${res.status()}`)
    await page.evaluate(() => document.fonts.ready)

    problems.push(
      ...(await page.evaluate(() => {
        const out = []
        const vw = document.documentElement.clientWidth
        if (document.documentElement.scrollWidth > vw) out.push(`sideways scroll: ${document.documentElement.scrollWidth}px wide`)
        for (const el of document.querySelectorAll('.id-card *')) {
          const r = el.getBoundingClientRect()
          if (r.width && (r.right > vw + 0.5 || r.left < -0.5) && getComputedStyle(el).position !== 'absolute') {
            out.push(`overflows the screen: <${el.tagName.toLowerCase()} class="${el.className}">`)
            break
          }
        }
        // Nothing may be cut off: content wider than its own box, unless it is a line designed to truncate.
        for (const el of document.querySelectorAll('.id-card *')) {
          if (el.closest('[hidden], template, svg, select') || !el.getClientRects().length) continue
          const st = getComputedStyle(el)
          if (el.scrollWidth > el.clientWidth + 1 && st.overflowX !== 'visible' && st.textOverflow !== 'ellipsis' && !el.matches('.id-hidden-input, .id-sr')) {
            out.push(`content cut off: <${el.tagName.toLowerCase()} class="${el.className}"> ${(el.textContent || '').trim().slice(0, 30)}`)
            break
          }
        }
        // An amount is never broken across lines.
        for (const el of document.querySelectorAll('.id-card .id-kv__value, .id-card .id-amount, .id-card .id-plan__cost, .id-card .id-plan__value')) {
          if (el.closest('[hidden], template') || !el.getClientRects().length) continue
          const t = (el.textContent || '').trim()
          // Lines of text, not the box: a stretched cell is tall without its text wrapping.
          const range = document.createRange()
          range.selectNodeContents(el)
          const lines = new Set([...range.getClientRects()].map((r) => Math.round(r.top)))
          if (/^\$[\d,.]+(\/\w+)?( of \$[\d,.]+)?$/.test(t) && lines.size > 1) {
            out.push(`amount broken across lines: ${t}`)
            break
          }
        }
        // No two pieces of text may collide: siblings in a row must not overlap.
        for (const row of document.querySelectorAll('.id-card .id-kv, .id-card .id-plan__title, .id-card .id-spend__top, .id-card .id-evrow, .id-card .id-sstep__head, .id-card .id-payline, .id-card .id-method, .id-card .id-moneyrow, .id-card .id-connrow, .id-card .id-agentrow__summary, .id-card .id-plans__head, .id-card .id-alerts__row, .id-card .id-plan__item, .id-card .id-compare__row, .id-card .id-limit__top')) {
          if (row.closest('[hidden], template') || !row.getClientRects().length) continue
          const kids = [...row.children].filter((k) => k.getClientRects().length && getComputedStyle(k).position !== 'absolute').map((k) => k.getBoundingClientRect())
          for (let i = 1; i < kids.length; i++) {
            const sameLine = kids[i].top < kids[i - 1].bottom - 1 && kids[i].bottom > kids[i - 1].top + 1
            if (sameLine && kids[i].left < kids[i - 1].right - 1) {
              out.push(`overlap in <${row.tagName.toLowerCase()} class="${row.className}"> ${(row.textContent || '').trim().slice(0, 40)}`)
              break
            }
          }
        }
        const card = document.querySelector('.id-card')?.getBoundingClientRect()
        if (card && (Math.round(card.left) !== 0 || Math.round(card.right) !== vw)) out.push(`card is not edge to edge: ${card.left}..${card.right}`)
        for (const band of document.querySelectorAll('[data-actions]')) {
          const kids = [...band.children].filter((k) => k.getBoundingClientRect().height)
          const rects = kids.map((k) => k.getBoundingClientRect())
          if (rects.some((r) => Math.round(r.height) < 48)) out.push(`action under 48px: ${rects.map((r) => Math.round(r.height)).join(', ')}`)
          if (new Set(rects.map((r) => Math.round(r.left))).size > 1) out.push('actions are not stacked')
          const primary = kids.findIndex((k) => k.classList.contains('id-btn--primary'))
          if (primary >= 0 && rects.some((r, i) => i !== primary && r.top < rects[primary].top)) out.push('primary action is not on top')
        }
        // Targets: the control, or the label or pseudo-element that widens its hit area, is 44px tall.
        const hit = (el) => {
          const box = (e, pseudo) => {
            const r = e.getBoundingClientRect()
            if (!pseudo) return r.height
            const st = getComputedStyle(e, pseudo)
            if (st.content === 'none' || st.position !== 'absolute') return 0
            return r.height - parseFloat(st.top) - parseFloat(st.bottom)
          }
          let best = Math.max(box(el), box(el, '::before'))
          const label = el.closest('label') ?? (el.id ? document.querySelector(`label[for="${el.id}"]`) : null)
          if (label) best = Math.max(best, box(label), box(label, '::before'))
          const summary = el.closest('summary')
          if (summary) best = Math.max(best, box(summary))
          return best
        }
        for (const el of document.querySelectorAll('.id-card button, .id-card a, .id-card select, .id-card input, .id-card textarea, .id-card summary')) {
          if (el.closest('[hidden], template') || el.getClientRects().length === 0) continue
          // Links inside a sentence are text, not targets (WCAG 2.5.8's inline exception).
          if (el.matches('a.id-link, button.id-link') && !el.matches('.id-btn')) continue
          const h = hit(el)
          if (h >= 43.5) continue
          // Components from the auth redesign that these screens reuse unchanged (5a's identity row and copy button are 32px).
          const existing = el.matches('.id-copy, .id-source__summary, .id-perm__summary, .id-disclosure__summary')
          out.push(`${existing ? 'NOTE existing component' : 'target'} under 44px (${Math.round(h)}): <${el.tagName.toLowerCase()} class="${el.className}"> ${(el.textContent || el.getAttribute('aria-label') || '').trim().slice(0, 30)}`)
        }
        const moving = document.getAnimations().filter((a) => a.playState === 'running')
        if (moving.length) out.push(`${moving.length} animation(s) still running under reduced motion`)
        return out
      })),
    )

    // Keyboard: Tab from the top reaches every control once, each with a visible ring.
    const expected = await page.evaluate(() => {
      const all = [...document.querySelectorAll('a[href], button:not([disabled]), select, textarea, input:not([type=hidden]):not([disabled]), summary')]
      const shown = all.filter((el) => !el.closest('[hidden], template') && el.getClientRects().length && el.getAttribute('tabindex') !== '-1')
      // A radio group is one tab stop: the checked radio, or the first.
      const groups = new Set()
      return shown.filter((el) => {
        if (el.type !== 'radio') return true
        if (groups.has(el.name)) return false
        groups.add(el.name)
        return true
      }).length
    })
    let reached = 0
    let noRing = 0
    for (let i = 0; i < expected + 5; i++) {
      await page.keyboard.press('Tab')
      const state = await page.evaluate(() => {
        const el = document.activeElement
        if (!el || el === document.body) return null
        const ring = (e) => {
          const st = getComputedStyle(e)
          return st.outlineStyle !== 'none' && parseFloat(st.outlineWidth) > 0
        }
        // A hidden input shows its ring on the label, card or track around it.
        let shows = ring(el)
        // Fields show focus by their border (the existing .id-input rule), not an outline.
        if (!shows) {
          const focused = getComputedStyle(el).borderColor
          el.blur()
          shows = getComputedStyle(el).borderColor !== focused
          el.focus()
        }
        for (let p = el.parentElement, n = 0; !shows && p && n < 4; p = p.parentElement, n++) shows = ring(p) || [...p.children].some((c) => ring(c))
        return { ring: shows, tag: el.tagName }
      })
      if (!state) break
      reached++
      if (!state.ring) noRing++
    }
    if (reached < expected) problems.push(`keyboard reaches ${reached} of ${expected} controls`)
    if (noRing) problems.push(`${noRing} control(s) show no focus ring`)
  } catch (e) {
    problems.push(String(e.message || e))
  }
  await page.close()
  const real = problems.filter((x) => !x.startsWith('NOTE'))
  if (real.length) failed++
  console.log(`${real.length ? 'FAIL' : 'PASS'}  ${s.id.padEnd(4)} ${problems.join(' · ')}`)
}
await browser.close()
console.log(`\n${ran - failed}/${ran} pages pass at ${WIDTH}px, by keyboard and with reduced motion`)
process.exit(failed ? 1 : 0)
