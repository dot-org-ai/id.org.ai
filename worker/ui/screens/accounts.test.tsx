/**
 * Accessibility and wiring contracts for the accounts and devices screens
 * (2a, 2b, 2c, 2e, 4c, 4d; docs/product-update/spec/screens.md sections 2 and 4):
 * one h1, every control labelled, forms posting to their route with a CSRF
 * field, a role=status region, request data escaped, no inline style.
 */
import { describe, expect, it } from 'vitest'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { renderHtml } from '../render'
import { accountsFixtures } from '../gallery/fixtures/accounts'
import { deviceFixtures } from '../gallery/fixtures/devices'
import { AccountChooser, type AccountChooserProps } from './AccountChooser'
import { WorkspaceChooser, type WorkspaceChooserProps } from './WorkspaceChooser'
import { Handoff, type HandoffProps } from './Handoff'
import { Invitation, emailMismatch, type InvitationProps } from './Invitation'
import { DeviceEntry } from './DeviceEntry'
import { DeviceDone, type DeviceSignedProps } from './DeviceDone'

const EVIL = '<script>alert(1)</script>'

async function dom(el: JSX.Element): Promise<Document> {
  const html = await renderHtml(el, { title: 't' })
  return new DOMParser().parseFromString(html, 'text/html')
}

/** Every visible control has an accessible name. */
function expectLabelled(doc: Document): void {
  for (const el of doc.querySelectorAll<HTMLInputElement>('input:not([type="hidden"]), select, textarea')) {
    const id = el.getAttribute('id')
    const named = el.getAttribute('aria-label') || el.getAttribute('aria-labelledby') || (id && doc.querySelector(`label[for="${id}"]`)) || el.closest('label')
    expect(named, `control ${el.outerHTML} has no label`).toBeTruthy()
  }
  for (const el of doc.querySelectorAll('button, a')) {
    expect((el.textContent ?? '').trim() || el.getAttribute('aria-label'), `${el.outerHTML} has no name`).toBeTruthy()
  }
}

function expectOneH1(doc: Document, text: string): void {
  const h1s = doc.querySelectorAll('h1')
  expect(h1s.length).toBe(1)
  expect(h1s[0]!.textContent).toBe(text)
}

function expectForm(doc: Document, action: string): HTMLFormElement {
  const form = doc.querySelector<HTMLFormElement>(`form[action="${action}"]`)
  expect(form, `no form posting to ${action}`).toBeTruthy()
  expect(form!.getAttribute('method')).toBe('post')
  const csrf = form!.querySelector<HTMLInputElement>('input[name="csrf"]')
  expect(csrf?.getAttribute('type')).toBe('hidden')
  expect(csrf?.getAttribute('value')).toBe('tok')
  return form!
}

function expectStatus(doc: Document): Element {
  const status = doc.querySelector('[role="status"]')
  expect(status).toBeTruthy()
  return status!
}

/** Untrusted text arrives as text: no element was injected and the string reads back verbatim. */
function expectEscaped(doc: Document, html: string): void {
  expect(doc.querySelectorAll('body script').length).toBe(0)
  expect(html).not.toContain(EVIL)
  expect(doc.body.textContent).toContain(EVIL)
}

describe('every accounts and devices fixture', () => {
  const variants = Object.entries({ ...accountsFixtures, ...deviceFixtures }).flatMap(([slug, f]) => [
    [slug, f.default] as const,
    ...Object.entries(f.states).map(([k, v]) => [`${slug}?state=${k}`, v] as const),
    ...Object.entries(f.derived).map(([k, v]) => [`${slug}?state=${k}`, v] as const),
  ])
  it.each(variants)('%s renders one h1, labelled controls and no inline style', async (_name, v) => {
    const html = await renderHtml(v.render(), { title: v.title })
    expect(html).not.toMatch(/\sstyle=/i)
    expect(html).not.toMatch(/<style[\s>]/i)
    expect(html).not.toMatch(/\son[a-z]+=/i)
    const doc = new DOMParser().parseFromString(html, 'text/html')
    expect(doc.querySelectorAll('h1').length).toBe(1)
    expectLabelled(doc)
    expect(doc.querySelector('[role="status"]')).toBeTruthy()
  })
})

describe('2a · Choose account', () => {
  const base: AccountChooserProps = {
    app: { name: 'startups.studio', tile: { kind: 'monogram', text: 'S' } },
    accounts: [
      { sessionId: 'ses_a', name: 'Bryant Skarda', email: 'bryant@do.industries', lastUsedHere: true },
      { sessionId: 'ses_b', name: 'Bryant Skarda', email: 'bryant@driv.ly', lastUsedHere: false },
    ],
    anotherAccountHref: '/login?prompt=login&continue=%2Fauthorize',
    action: '/account/choose?continue=%2Fauthorize',
    signOutAction: '/signout',
    csrf: 'tok',
  }

  it('posts the chosen session to /account/choose and signs out the browser from its own form', async () => {
    const doc = await dom(<AccountChooser {...base} />)
    expectOneH1(doc, 'Choose an account')
    expectLabelled(doc)
    expectStatus(doc)
    const form = expectForm(doc, base.action)
    const rows = form.querySelectorAll('button[type="submit"][name="session"]')
    expect(Array.from(rows).map((b) => b.getAttribute('value'))).toEqual(['ses_a', 'ses_b'])
    expect(rows[0]!.textContent).toContain('Last used here')
    expect(form.querySelector(`a[href="${base.anotherAccountHref}"]`)?.textContent).toBe('Use another account')
    const signOut = expectForm(doc, '/signout')
    expect(signOut.querySelector('input[name="scope"]')?.getAttribute('value')).toBe('browser')
    expect(signOut.querySelector('button[type="submit"]')?.textContent).toBe('Sign out of all accounts')
  })

  it('escapes account data', async () => {
    const html = await renderHtml(<AccountChooser {...base} accounts={[{ sessionId: EVIL, name: EVIL, email: EVIL, lastUsedHere: false }]} />, { title: 't' })
    expectEscaped(new DOMParser().parseFromString(html, 'text/html'), html)
  })
})

describe('2b · Choose workspace', () => {
  const base: WorkspaceChooserProps = {
    mode: { kind: 'choose', action: '/workspace/choose?continue=%2Fauthorize' },
    app: { name: 'headless.ly', tile: { kind: 'monogram', text: 'h' } },
    account: { name: 'Bryant Skarda', email: 'bryant@driv.ly' },
    switchHref: '/account/choose',
    workspaces: [
      { id: 'org_1', name: 'Drivly', role: 'owner' },
      { id: 'org_2', name: 'Personal', role: 'personal' },
    ],
    selectedId: 'org_1',
    remember: true,
    newWorkspaceHref: '/workspace/new',
    csrf: 'tok',
  }

  it('posts org_id and remember to /workspace/choose from a fieldset of radio cards', async () => {
    const doc = await dom(<WorkspaceChooser {...base} />)
    expectOneH1(doc, 'Choose a workspace')
    expectLabelled(doc)
    expectStatus(doc)
    const form = expectForm(doc, base.mode.action)
    expect(form.querySelector('fieldset legend')?.textContent).toBe('Workspace')
    const radios = form.querySelectorAll<HTMLInputElement>('input[type="radio"][name="org_id"]')
    expect(radios.length).toBe(2)
    expect(radios[0]!.hasAttribute('checked')).toBe(true)
    expect(radios[1]!.hasAttribute('checked')).toBe(false)
    expect(form.querySelector('label[for="ws-org_2"]')?.textContent).toContain('Just you')
    const remember = form.querySelector('input[type="checkbox"][name="remember"]')
    expect(remember?.hasAttribute('checked')).toBe(true)
    expect(form.querySelector('label[for="ws-remember"]')?.textContent).toBe('Remember for headless.ly')
    expect(form.querySelector('a[href="/workspace/new"]')?.textContent).toBe('New workspace')
    expect(form.querySelector('button[type="submit"]')?.textContent).toBe('Continue')
  })

  it('posts the existing /api/org-select contract in sign-in mode', async () => {
    const doc = await dom(
      <WorkspaceChooser
        {...base}
        mode={{ kind: 'sign-in', action: '/api/org-select', pendingAuthenticationToken: 'pat_1', state: 'st_1' }}
        remember={undefined}
        newWorkspaceHref={undefined}
      />,
    )
    const form = expectForm(doc, '/api/org-select')
    expect(form.querySelector('input[name="pending_token"]')?.getAttribute('value')).toBe('pat_1')
    expect(form.querySelector('input[name="state"]')?.getAttribute('value')).toBe('st_1')
    expect(form.querySelectorAll('input[type="radio"][name="organization_id"]').length).toBe(2)
    expect(form.querySelector('input[name="remember"]')).toBeNull()
    expect(form.querySelector('a[href="/workspace/new"]')).toBeNull()
  })

  it('escapes workspace and account data', async () => {
    const html = await renderHtml(
      <WorkspaceChooser {...base} app={{ name: EVIL, tile: { kind: 'monogram', text: 'x' } }} account={{ name: EVIL, email: EVIL }} workspaces={[{ id: EVIL, name: EVIL, role: 'member' }]} />,
      { title: 't' },
    )
    expectEscaped(new DOMParser().parseFromString(html, 'text/html'), html)
  })
})

describe('2c · Handing off', () => {
  const base: HandoffProps = {
    app: { name: 'headless.ly', tile: { kind: 'monogram', text: 'h' } },
    account: { name: 'Bryant Skarda' },
    workspace: { name: 'Drivly' },
    target: 'https://headless.ly/cb?code=abc&state=xyz',
  }

  it('shows the connector connecting and a continue link, with no redirect in frozen mode', async () => {
    const doc = await dom(<Handoff {...base} />)
    expectOneH1(doc, 'Signing you in to headless.ly')
    expectLabelled(doc)
    expect(expectStatus(doc).textContent).toBe('Signing you in to headless.ly…')
    expect(doc.querySelector('.id-conn')?.getAttribute('data-state')).toBe('connecting')
    expect(doc.querySelector(`a[href="${base.target}"]`)?.textContent).toBe('Continue to headless.ly')
    expect(doc.querySelector('meta[http-equiv="refresh"]')).toBeNull()
    expect(doc.querySelector('form')).toBeNull()
  })

  it('when redirecting: the handoff.js hook in the page and the meta refresh fallback in the head', async () => {
    const html = await renderHtml(<Handoff {...base} redirect />, { title: 't', refreshTo: { url: base.target, seconds: 1 } })
    const doc = new DOMParser().parseFromString(html, 'text/html')
    expect(doc.querySelector('[data-js="handoff"]')?.getAttribute('data-target')).toBe(base.target)
    const meta = doc.head.querySelector('meta[http-equiv="refresh"]')
    expect(meta?.getAttribute('content')).toBe(`1;url=${base.target}`)
    expect(doc.body.querySelector('meta')).toBeNull()
  })

  it('never refreshes in the frozen gallery', async () => {
    const html = await renderHtml(<Handoff {...base} redirect />, { title: 't', refreshTo: { url: base.target, seconds: 1 }, frozen: true })
    expect(html).not.toContain('http-equiv="refresh"')
  })

  it('escapes names', async () => {
    const html = await renderHtml(<Handoff {...base} account={{ name: EVIL }} workspace={{ name: EVIL }} />, { title: 't' })
    expectEscaped(new DOMParser().parseFromString(html, 'text/html'), html)
  })
})

describe('2e · Accept invitation', () => {
  const base: InvitationProps = {
    inviter: { name: 'Nathan Clevenger' },
    workspace: { name: '.do Industries', tile: { kind: 'monogram', text: '.d' } },
    role: 'Admin',
    invitedEmail: 'bryant@driv.ly',
    expiresIn: 'in 6 days',
    account: { name: 'Bryant Skarda', email: 'bryant@driv.ly' },
    switchHref: '/account/choose',
    action: '/invite/tok_123',
    csrf: 'tok',
  }

  it('posts accept or decline to /invite/:token', async () => {
    const doc = await dom(<Invitation {...base} />)
    expectOneH1(doc, 'Join .do Industries')
    expect(doc.querySelector('.id-desc')?.textContent).toBe('Nathan Clevenger invited you as an Admin.')
    expectLabelled(doc)
    expectStatus(doc)
    const form = expectForm(doc, '/invite/tok_123')
    const buttons = Array.from(form.querySelectorAll<HTMLButtonElement>('button[type="submit"][name="decision"]'))
    expect(buttons.map((b) => [b.getAttribute('value'), b.textContent, b.hasAttribute('disabled')])).toEqual([
      ['decline', 'Decline', false],
      ['accept', 'Join workspace', false],
    ])
    expect(form.querySelector('a.id-link[href="/account/choose"]')?.textContent).toBe('Switch')
  })

  it('disables Join and makes Switch prominent when the signed-in email is not the invited one', async () => {
    const props = { ...base, account: { name: 'Bryant Skarda', email: 'bryant@do.industries' } }
    expect(emailMismatch(props)).toBe(true)
    expect(emailMismatch({ ...base, account: { name: 'B', email: 'Bryant@Driv.ly' } })).toBe(false)
    const doc = await dom(<Invitation {...props} />)
    expect(doc.querySelector('button[value="accept"]')?.hasAttribute('disabled')).toBe(true)
    expect(doc.querySelector('button[value="decline"]')?.hasAttribute('disabled')).toBe(false)
    expect(doc.querySelector('a.id-btn[href="/account/choose"]')?.textContent).toBe('Switch account')
    expect(doc.querySelector('.id-note')?.textContent).toBe('This invitation is for bryant@driv.ly. Switch to that account to join.')
  })

  it('shows the declined confirmation in place', async () => {
    const doc = await dom(<Invitation {...base} state="declined" />)
    expectOneH1(doc, 'Invitation declined')
    expect(expectStatus(doc).textContent).toBe('Declined')
    expect(doc.querySelector('.id-conn')?.getAttribute('data-state')).toBe('fail')
    expect(doc.querySelector('form')).toBeNull()
  })

  it('uses "a" before a consonant role', async () => {
    const doc = await dom(<Invitation {...base} role="Member" />)
    expect(doc.querySelector('.id-desc')?.textContent).toBe('Nathan Clevenger invited you as a Member.')
  })

  it('escapes invitation data', async () => {
    const html = await renderHtml(<Invitation {...base} inviter={{ name: EVIL }} role={EVIL} invitedEmail={EVIL} />, { title: 't' })
    expectEscaped(new DOMParser().parseFromString(html, 'text/html'), html)
  })
})

describe('4c · Enter device code', () => {
  it('posts eight labelled code boxes to /device', async () => {
    const doc = await dom(<DeviceEntry action="/device" csrf="tok" focusIndex={0} />)
    expectOneH1(doc, 'Connect a device')
    expectLabelled(doc)
    expectStatus(doc)
    const form = expectForm(doc, '/device')
    const group = form.querySelector('[role="group"]')
    expect(group?.getAttribute('aria-label')).toBe('Enter the 8-character device code')
    const boxes = form.querySelectorAll('input[name="code"]')
    expect(boxes.length).toBe(8)
    expect(boxes[0]!.getAttribute('class')).toContain('is-focused')
    expect(doc.querySelector('.id-codehint')?.textContent).toBe('Codes look like WDJB-MJHT and last 30 minutes.')
    expect(form.querySelector('button[type="submit"]')?.textContent).toBe('Continue')
  })

  it('links the error to every box and announces it', async () => {
    const doc = await dom(<DeviceEntry action="/device" csrf="tok" value="WDJB-MJHX" error="That code is invalid or has expired." />)
    const boxes = Array.from(doc.querySelectorAll('input[name="code"]'))
    expect(boxes.map((b) => b.getAttribute('value')).join('')).toBe('WDJBMJHX')
    for (const b of boxes) {
      expect(b.getAttribute('aria-invalid')).toBe('true')
      expect(b.getAttribute('aria-describedby')).toBe('device-code-error')
    }
    expect(doc.getElementById('device-code-error')?.textContent).toBe('That code is invalid or has expired.')
    expect(expectStatus(doc).textContent).toBe('That code is invalid or has expired.')
  })

  it('escapes the typed value and the error', async () => {
    const html = await renderHtml(<DeviceEntry action="/device" csrf="tok" error={EVIL} />, { title: 't' })
    expectEscaped(new DOMParser().parseFromString(html, 'text/html'), html)
  })
})

describe('4d · Device connected', () => {
  const base: DeviceSignedProps = {
    client: { name: 'auto.dev CLI', tile: { kind: 'icon', icon: 'terminal' } },
    account: { email: 'bryant@driv.ly' },
    workspace: { name: 'Drivly' },
    device: 'macOS · Miami, FL',
    revokeHref: '/device/dev_1/revoke',
  }

  it('shows the signed-in facts and the revoke link', async () => {
    const doc = await dom(<DeviceDone {...base} />)
    expectOneH1(doc, 'auto.dev CLI is signed in')
    expectLabelled(doc)
    expect(expectStatus(doc).textContent).toBe('Signed in')
    expect(doc.querySelector('.id-conn')?.getAttribute('data-state')).toBe('ok')
    expect(Array.from(doc.querySelectorAll('.id-kv')).map((kv) => kv.textContent)).toEqual(['Accountbryant@driv.ly', 'WorkspaceDrivly', 'DevicemacOS · Miami, FL'])
    expect(doc.querySelector('a[href="/device/dev_1/revoke"]')?.textContent).toBe('Sign this device out')
  })

  it('renders the cancelled card for /device/cancelled', async () => {
    const doc = await dom(<DeviceDone outcome="cancelled" client={base.client} cliName="auto.dev" />)
    expectOneH1(doc, 'Sign-in cancelled')
    expect(expectStatus(doc).textContent).toBe('Cancelled')
    expect(doc.querySelector('.id-conn')?.getAttribute('data-state')).toBe('fail')
    expect(doc.querySelector('.id-foottext')?.textContent).toBe('Started it by mistake? Run auto.dev login again.')
  })

  it('escapes device data', async () => {
    const html = await renderHtml(<DeviceDone {...base} client={{ name: EVIL, tile: { kind: 'icon', icon: 'terminal' } }} device={EVIL} />, { title: 't' })
    expectEscaped(new DOMParser().parseFromString(html, 'text/html'), html)
  })
})
