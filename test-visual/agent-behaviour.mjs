#!/usr/bin/env node
/**
 * Drives the real controls on the agent setup screens in a browser, by
 * keyboard where it matters (docs/agent-setup/HANDOFF.md section 5):
 *   19b  the terms line gates the primary action; the alerts switch and
 *        chevron are separate controls
 *   24a  a plan is a radio; its chevron is a separate button; the billing
 *        toggle swaps prices; the primary label follows the plan
 *   9c   the primary label follows the spend limit
 *   19a  the fields are Stripe's: no card input exists on the page
 *
 *   node test-visual/agent-behaviour.mjs [--base http://localhost:8787]
 */
import { chromium } from 'playwright'
import { findChromium } from '../scripts/chromium.mjs'

const argv = process.argv.slice(2)
const BASE = String(argv.includes('--base') ? argv[argv.indexOf('--base') + 1] : process.env.VISUAL_BASE || 'http://localhost:8787').replace(/\/$/, '')
const bin = findChromium()
const browser = await chromium.launch(bin ? { executablePath: bin } : {})
let failed = 0
const check = (name, ok, got) => {
  if (!ok) failed++
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  (got ${JSON.stringify(got)})`}`)
}
async function open(path) {
  const page = await browser.newPage({ viewport: { width: 720, height: 1300 } })
  const errors = []
  page.on('pageerror', (e) => errors.push(String(e)))
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()))
  const res = await page.goto(BASE + path, { waitUntil: 'load' })
  if (!res || res.status() >= 400) throw new Error(`${path}: HTTP ${res?.status()}`)
  return { page, errors }
}

// ── 19b ─────────────────────────────────────────────────────────────────────
if (!argv.includes('--only') || argv.includes('19b')) {
  const { page, errors } = await open('/__design/19b-pay-plan-usage?state=unticked')
  const primary = page.locator('.id-btn--primary')
  const terms = page.locator('input[data-terms]')
  check('19b loads with the terms line unticked and the primary action disabled', !(await terms.isChecked()) && (await primary.isDisabled()), [await terms.isChecked(), await primary.isDisabled()])
  check('19b the secondary action stays usable', await page.locator('.id-btn--secondary').isEnabled())
  await terms.focus()
  await page.keyboard.press('Space')
  check('19b ticking the terms line by keyboard enables the primary action', (await terms.isChecked()) && (await primary.isEnabled()), [await terms.isChecked(), await primary.isEnabled()])
  await page.keyboard.press('Space')
  check('19b unticking it disables the action again', await primary.isDisabled())

  const sw = page.locator('input[role=switch]')
  const chev = page.locator('.id-alerts [data-js=disclose]')
  const panel = page.locator('.id-alerts__panel')
  check('19b spend alerts are on by default, with the row closed', (await sw.isChecked()) && (await panel.isHidden()), [await sw.isChecked(), await panel.isHidden()])
  await sw.focus()
  await page.keyboard.press('Space')
  check('19b flipping the switch turns alerts off and does not open the row', !(await sw.isChecked()) && (await panel.isHidden()), [await sw.isChecked(), await panel.isHidden()])
  await chev.focus()
  await page.keyboard.press('Enter')
  check('19b the chevron opens the row and does not flip the switch', (await panel.isVisible()) && !(await sw.isChecked()) && (await chev.getAttribute('aria-expanded')) === 'true', [await panel.isVisible(), await sw.isChecked()])
  check('19b the open row lists the marks', (await panel.innerText()).trim() === 'Emails at $100, $500, $1,000, $2,000 and $5,000.', await panel.innerText())
  check('19b the spend limit defaults to No limit', (await page.locator('select[name=spend_limit]').inputValue()) === 'none')
  check('19b no script errors', errors.length === 0, errors)
  await page.close()
}

// ── 24a ─────────────────────────────────────────────────────────────────────
if (!argv.includes('--only') || argv.includes('24a')) {
  const { page, errors } = await open('/__design/24a-connect-plan')
  const label = page.locator('[data-js=follow]')
  const checked = () => page.locator('input[name=plan]:checked').inputValue()
  check('24a loads with the recommended plan selected and open, the rest closed', (await checked()) === 'growth' && (await page.locator('#plan-growth-included').isVisible()) && (await page.locator('#plan-free-included').isHidden()) && (await page.locator('#plan-scale-included').isHidden()), await checked())
  const more = page.locator('[aria-controls=plan-scale-included]')
  await more.focus()
  await page.keyboard.press('Enter')
  check('24a a plan’s chevron shows what it includes without selecting it', (await page.locator('#plan-scale-included').isVisible()) && (await checked()) === 'growth' && (await more.getAttribute('aria-expanded')) === 'true', await checked())
  await page.locator('input[name=plan][value=growth]').focus()
  await page.keyboard.press('ArrowDown')
  check('24a arrow keys move the selection, and the primary label follows it', (await checked()) === 'scale' && (await label.innerText()).trim() === 'Continue with Scale', [await checked(), await label.innerText()])
  await page.keyboard.press('ArrowUp')
  await page.keyboard.press('ArrowUp')
  check('24a selecting Free renames the action', (await label.innerText()).trim() === 'Continue with Free', await label.innerText())
  const price = () => page.locator('.id-plan:nth-of-type(2) .id-plan__price').innerText()
  check('24a billing defaults to Monthly', (await page.locator('[data-billing=monthly]').isChecked()) && (await price()).trim() === '$299', await price())
  await page.locator('[data-billing=monthly]').focus()
  await page.keyboard.press('ArrowRight')
  check('24a Yearly swaps every card’s price', (await price()).trim() === '$249' && (await page.locator('.id-plan:nth-of-type(3) .id-plan__price').innerText()).trim() === '$499', await price())
  check('24a no script errors', errors.length === 0, errors)
  await page.close()
}

// ── 9c ──────────────────────────────────────────────────────────────────────
if (!argv.includes('--only') || argv.includes('9c')) {
  const { page, errors } = await open('/__design/9c-setup-needs-you')
  await page.locator('select[name=answer_spend]').selectOption('100000')
  check('9c the primary label follows the spend limit', (await page.locator('[data-js=follow]').innerText()).trim() === 'Approve $1,000 a month', await page.locator('[data-js=follow]').innerText())
  check('9c no script errors', errors.length === 0, errors)
  await page.close()
}

// ── 19a ─────────────────────────────────────────────────────────────────────
if (!argv.includes('--only') || argv.includes('19a')) {
  const { page, errors } = await open('/__design/19a-pay-add')
  const inputs = await page.locator('[data-js=stripe-fields] input, [data-js=stripe-fields] select, [data-js=stripe-fields] textarea').count()
  check('19a holds no card inputs of its own', inputs === 0, inputs)
  const named = await page.evaluate(() => [...document.querySelectorAll('input:not([type=radio]):not([type=checkbox]):not([type=hidden]), select, textarea')].filter((e) => /card|cvc|expiry|number|cc-/i.test(e.name + e.id + (e.getAttribute('autocomplete') ?? ''))).length)
  check('19a has no text field for a card number, expiry or code anywhere', named === 0, named)
  await page.locator('input[name=method_type][value=card]').focus()
  await page.keyboard.press('ArrowRight')
  check('19a the method tabs are a keyboard radio group', (await page.locator('input[name=method_type]:checked').inputValue()) === 'bank')
  await page.setViewportSize({ width: 390, height: 844 })
  const pair = await page.evaluate(() => [...document.querySelectorAll('.id-stripe__pair')].map((p) => [...p.children].map((c) => Math.round(c.getBoundingClientRect().top))))
  check('19a two-up fields stay two-up on a phone', pair.every(([a, b]) => a === b), pair)
  check('19a no script errors', errors.length === 0, errors)
  await page.close()
}

await browser.close()
console.log(failed ? `\n${failed} check(s) failed` : '\nAll behaviour checks pass')
process.exit(failed ? 1 : 0)
