/**
 * Accessibility and form contracts for the Authorize screens (3a–3d):
 * one h1, labelled controls, forms posting to the routes in spec/screens.md
 * with a CSRF field, a role=status region, and request data escaped.
 */
import { describe, expect, it } from 'vitest'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { renderHtml } from '../render'
import { authorizeFixtures } from '../gallery/fixtures/authorize'
import type { Variant } from '../gallery/types'
import { Consent, type ConsentProps } from './Consent'
import { AdminApprove, type AdminApproveProps } from './AdminApprove'

async function dom(el: JSX.Element): Promise<Document> {
  const html = await renderHtml(el, { title: 't' })
  expect(html).not.toMatch(/\sstyle=/)
  return new DOMParser().parseFromString(html, 'text/html')
}

const render = (v: Variant | undefined) => {
  if (!v) throw new Error('missing fixture variant')
  return dom(v.render())
}

const text = (el: Element | null | undefined) => (el?.textContent ?? '').replace(/\s+/g, ' ').trim()

/** Every visible form control has an accessible name: a <label for>, a wrapping label, aria-label or text. */
function expectLabelled(d: Document): void {
  for (const el of d.querySelectorAll('input:not([type="hidden"]), select, textarea')) {
    const id = el.getAttribute('id')
    const byFor = id ? d.querySelector(`label[for="${id}"]`) : null
    const wrapped = el.closest('label')
    expect(byFor || wrapped || el.getAttribute('aria-label'), el.outerHTML).toBeTruthy()
  }
  for (const b of d.querySelectorAll('button, a')) {
    expect(text(b) || b.getAttribute('aria-label'), b.outerHTML).toBeTruthy()
  }
}

function hiddenValue(form: Element, name: string): string | null {
  return form.querySelector(`input[type="hidden"][name="${name}"]`)?.getAttribute('value') ?? null
}

const f3a = authorizeFixtures['3a-consent']!
const f3b = authorizeFixtures['3b-consent-basic']!
const f3c = authorizeFixtures['3c-consent-unverified']!
const f3d = authorizeFixtures['3d-admin-approve']!

describe('3a · Authorize app', () => {
  it('has one h1, labelled controls and a status region', async () => {
    const d = await render(f3a.default)
    expect(d.querySelectorAll('h1').length).toBe(1)
    expect(text(d.querySelector('h1'))).toBe('Codex wants to use api.sb as you')
    expectLabelled(d)
    expect(d.querySelector('[role="status"][data-status]')).toBeTruthy()
  })

  it('posts to /oauth/authorize with CSRF, the existing hidden fields, org_id and access', async () => {
    const d = await render(f3a.default)
    const form = d.querySelector('form')!
    expect(form.getAttribute('method')).toBe('post')
    expect(form.getAttribute('action')).toBe('/oauth/authorize')
    expect(form.getAttribute('data-js')).toBe('submit')
    expect(hiddenValue(form, 'csrf')).toBe('gallery')
    for (const name of ['client_id', 'redirect_uri', 'scope', 'state', 'code_challenge', 'code_challenge_method', 'nonce', 'resource']) {
      expect(hiddenValue(form, name), name).not.toBeNull()
    }
    const select = form.querySelector('select[name="org_id"]')!
    expect(d.querySelector(`label[for="${select.id}"]`)?.textContent).toBe('Workspace')
    expect(select.querySelector('option[selected]')?.getAttribute('value')).toBe('org_do')
    const access = [...form.querySelectorAll('input[type="radio"][name="access"]')]
    expect(access.map((r) => r.getAttribute('value'))).toEqual(['read', 'act'])
    expect(form.querySelector('input[name="access"][checked]')?.getAttribute('value')).toBe('act')
    expect(form.querySelector('fieldset legend')?.textContent).toBe('Access')
  })

  it('Cancel (secondary) then Allow (primary, "Allowing…"), both submitting approved', async () => {
    const d = await render(f3a.default)
    const [cancel, allow] = [...d.querySelectorAll('[data-actions] > button')]
    expect(text(cancel)).toBe('Cancel')
    expect(cancel!.className).toContain('id-btn--secondary')
    expect(cancel!.getAttribute('name')).toBe('approved')
    expect(cancel!.getAttribute('value')).toBe('false')
    expect(text(allow)).toBe('Allow')
    expect(allow!.className).toContain('id-btn--primary')
    expect(allow!.getAttribute('type')).toBe('submit')
    expect(allow!.getAttribute('value')).toBe('true')
    expect(allow!.getAttribute('data-busy-label')).toBe('Allowing…')
  })

  it('the Switch link and the source row with copy', async () => {
    const d = await render(f3a.default)
    const sw = [...d.querySelectorAll('a')].find((a) => text(a) === 'Switch')!
    expect(sw.getAttribute('href')).toMatch(/^\/login\?prompt=login&continue=/)
    expect(d.querySelector('[data-js="copy"]')?.getAttribute('data-value')).toBe('https://chatgpt.com/oauth/codex/client.json')
    expect(text(d.querySelector('.id-source__value'))).toBe('chatgpt.com/oauth/codex/client.json')
  })

  it('copied state announces through the copy status', async () => {
    const d = await render(f3a.states.copied)
    expect(d.querySelector('[data-js="copy"]')?.hasAttribute('data-copied')).toBe(true)
    expect(text(d.querySelector('[data-js="copy"] + [role="status"]'))).toBe('Copied')
  })

  it('busy: connecting, Allow busy and announced, Cancel disabled', async () => {
    const d = await render(f3a.derived.busy)
    expect(d.querySelector('[data-js="connector"]')?.getAttribute('data-state')).toBe('connecting')
    const [cancel, allow] = [...d.querySelectorAll('[data-actions] > button')]
    expect(cancel!.hasAttribute('disabled')).toBe(true)
    expect(allow!.getAttribute('aria-busy')).toBe('true')
    expect(text(allow)).toBe('Allowing…')
    expect(text(d.querySelector('[role="status"][data-status]'))).toBe('Allowing…')
  })

  it('logo: the app tile renders its logo_uri with the monogram fallback hook', async () => {
    const d = await render(f3a.derived.logo)
    const tile = d.querySelector('[data-js="logo"]')!
    expect(tile.getAttribute('data-monogram')).toBe('Cx')
    expect(tile.querySelector('img')?.getAttribute('alt')).toBe('')
  })
})

describe('3b · Sign in with id.org.ai', () => {
  it('has one h1, labelled controls, the identity summary and no permission list', async () => {
    const d = await render(f3b.default)
    expect(d.querySelectorAll('h1').length).toBe(1)
    expect(text(d.querySelector('h1'))).toBe('Sign in to api.sb')
    expect(text(d.querySelector('.id-desc'))).toBe('api.sb will get your name, email address and profile photo.')
    expectLabelled(d)
    expect(d.querySelector('.id-perm')).toBeNull()
    expect(d.querySelector('select')).toBeNull()
    expect(d.querySelector('[role="status"][data-status]')).toBeTruthy()
  })

  it('posts to /oauth/authorize; the primary reads "Continue as {first name}"', async () => {
    const d = await render(f3b.default)
    const form = d.querySelector('form')!
    expect(form.getAttribute('action')).toBe('/oauth/authorize')
    expect(hiddenValue(form, 'csrf')).toBe('gallery')
    expect(hiddenValue(form, 'scope')).toBe('openid profile email')
    const [cancel, allow] = [...d.querySelectorAll('[data-actions] > button')]
    expect(text(cancel)).toBe('Cancel')
    expect(text(allow)).toBe('Continue as Bryant')
    expect(allow!.getAttribute('value')).toBe('true')
  })
})

describe('3c · Unverified app', () => {
  it('has one h1 naming the host, the warning callout and labelled controls', async () => {
    const d = await render(f3c.default)
    expect(d.querySelectorAll('h1').length).toBe(1)
    expect(text(d.querySelector('h1'))).toBe('agent-tools.dev wants to read your Startups')
    expect(text(d.querySelector('.id-desc'))).toBe('It runs on your computer and asked for read access to api.sb.')
    expect(text(d.querySelector('.id-warning__title'))).toBe('id.org.ai can’t vouch for this app')
    expect(d.querySelector('[role="note"]')).toBeTruthy()
    expectLabelled(d)
    expect(d.querySelector('[role="status"][data-status]')).toBeTruthy()
  })

  it('flips the buttons: Allow outlined on the left, Cancel primary on the right', async () => {
    const d = await render(f3c.default)
    const [allow, cancel] = [...d.querySelectorAll('[data-actions] > button')]
    expect(text(allow)).toBe('Allow')
    expect(allow!.className).toContain('id-btn--secondary')
    expect(allow!.getAttribute('value')).toBe('true')
    expect(allow!.getAttribute('data-busy-label')).toBe('Allowing…')
    expect(text(cancel)).toBe('Cancel')
    expect(cancel!.className).toContain('id-btn--primary')
    expect(cancel!.getAttribute('value')).toBe('false')
  })

  it('posts the workspace and read access as hidden fields; source details say Verified: No', async () => {
    const d = await render(f3c.default)
    const form = d.querySelector('form')!
    expect(form.getAttribute('action')).toBe('/oauth/authorize')
    expect(hiddenValue(form, 'csrf')).toBe('gallery')
    expect(hiddenValue(form, 'org_id')).toBe('org_do')
    expect(hiddenValue(form, 'access')).toBe('read')
    const kv = [...d.querySelectorAll('.id-source__panel .id-kv')].map((r) => [...r.children].map((c) => text(c)).join(': '))
    expect(kv).toContain('Verified: No')
  })
})

describe('3d · Admin approves an app', () => {
  it('has one h1, labelled controls and a status region', async () => {
    const d = await render(f3d.default)
    expect(d.querySelectorAll('h1').length).toBe(1)
    expect(text(d.querySelector('h1'))).toBe('Approve Codex for Drivly?')
    expect(text(d.querySelector('.id-desc'))).toBe('Alex Rivera asked to use Codex in the Drivly workspace.')
    expect(text(d.querySelector('.id-who'))).toContain('nathan@do.industries · Drivly admin')
    expectLabelled(d)
    expect(d.querySelector('[role="status"][data-status]')).toBeTruthy()
  })

  it('posts to /admin/requests/:id with CSRF, the scope radios and the decision', async () => {
    const d = await render(f3d.default)
    const form = d.querySelector('form')!
    expect(form.getAttribute('method')).toBe('post')
    expect(form.getAttribute('action')).toMatch(/^\/admin\/requests\/[^/]+$/)
    expect(hiddenValue(form, 'csrf')).toBe('gallery')
    expect([...form.querySelectorAll('input[type="radio"][name="scope"]')].map((r) => r.getAttribute('value'))).toEqual(['everyone', 'requester'])
    expect(form.querySelector('input[name="scope"][checked]')?.getAttribute('value')).toBe('requester')
    expect(form.querySelector('fieldset legend')?.textContent).toBe('Approve for')
    const [decline, approve] = [...d.querySelectorAll('[data-actions] > button')]
    expect([text(decline), decline!.getAttribute('name'), decline!.getAttribute('value')]).toEqual(['Decline', 'decision', 'decline'])
    expect([text(approve), approve!.getAttribute('name'), approve!.getAttribute('value')]).toEqual(['Approve', 'decision', 'approve'])
    expect(approve!.getAttribute('data-busy-label')).toBe('Approving…')
    expect(text(d.querySelector('.id-quote__text'))).toBe('“Need it to run the weekly pipeline cleanup on api.sb.”')
  })

  it('approved and declined render the result in place, announced, with no form', async () => {
    const ok = await render(f3d.derived.approved)
    expect(ok.querySelectorAll('h1').length).toBe(1)
    expect(text(ok.querySelector('h1'))).toBe('Codex is approved for Drivly')
    expect(ok.querySelector('[data-js="connector"]')?.getAttribute('data-state')).toBe('ok')
    expect(text(ok.querySelector('[role="status"][data-status]'))).toBe('Approved')
    expect(ok.querySelector('form')).toBeNull()

    const no = await render(f3d.derived.declined)
    expect(no.querySelectorAll('h1').length).toBe(1)
    expect(text(no.querySelector('h1'))).toBe('Request declined')
    expect(no.querySelector('[data-js="connector"]')?.getAttribute('data-state')).toBe('fail')
    expect(text(no.querySelector('[role="status"][data-status]'))).toBe('Declined')
    expect(no.querySelector('form')).toBeNull()
  })
})

describe('request data is escaped', () => {
  const evil = '<script>alert(1)</script>'
  const quote = '"><img src=x onerror=alert(1)>'

  it('consent: client name, permission strings, hidden values and the source row', async () => {
    const p: ConsentProps = {
      variant: 'unverified',
      client: { name: evil, tile: { kind: 'monogram', text: 'x' } },
      resource: 'api.sb',
      account: { name: evil, email: 'e@x' },
      switchHref: `/login?continue=${quote}`,
      permissions: [{ icon: 'globe', title: evil, detail: evil, scope: evil }],
      source: { display: evil, copyValue: quote, details: [{ k: 'Returns to', v: evil }] },
      hidden: { scope: evil, state: quote },
      action: '/oauth/authorize',
      csrf: quote,
    }
    const html = await renderHtml(<Consent {...p} />, { title: 't' })
    expect(html).not.toContain('<script>alert(1)</script>')
    expect(html).not.toContain('<img src=x')
    const d = new DOMParser().parseFromString(html, 'text/html')
    expect(d.querySelectorAll('script:not([src])').length).toBe(0)
    expect(d.querySelectorAll('img').length).toBe(0)
    expect(text(d.querySelector('h1'))).toBe(`${evil} wants to use api.sb as you`)
    expect(hiddenValue(d.querySelector('form')!, 'scope')).toBe(evil)
    expect(hiddenValue(d.querySelector('form')!, 'state')).toBe(quote)
    expect(hiddenValue(d.querySelector('form')!, 'csrf')).toBe(quote)
    expect(d.querySelector('[data-js="copy"]')?.getAttribute('data-value')).toBe(quote)
  })

  it('admin approve: requester, note and client', async () => {
    const p: AdminApproveProps = {
      requester: { name: evil },
      client: { name: evil, tile: { kind: 'monogram', text: 'x' } },
      workspace: { name: evil, tile: { kind: 'monogram', text: 'y' } },
      note: evil,
      permissions: [{ icon: 'search', title: evil, detail: evil, scope: evil }],
      scope: 'requester',
      admin: { name: 'A B', email: evil },
      source: { display: evil, copyValue: quote, details: [] },
      action: '/admin/requests/req_1',
      csrf: quote,
    }
    const html = await renderHtml(<AdminApprove {...p} />, { title: 't' })
    expect(html).not.toContain('<script>alert(1)</script>')
    const d = new DOMParser().parseFromString(html, 'text/html')
    expect(d.querySelectorAll('script:not([src])').length).toBe(0)
    expect(text(d.querySelector('.id-quote__text'))).toBe(`“${evil}”`)
    expect(hiddenValue(d.querySelector('form')!, 'csrf')).toBe(quote)
  })
})
