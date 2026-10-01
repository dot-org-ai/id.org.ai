/**
 * Accessibility and wiring contracts for the accounts and devices screens
 * (2a, 2b, 2c, 2e, 4b, 4c, 4d; docs/product-update/spec/screens.md sections 2
 * and 4): one h1, every control labelled, forms posting to their route with a
 * CSRF field, a role=status region, request data escaped, no inline style.
 * The screens that stay on id.org.ai (2e, 4b) run through the real
 * lib/fetch-form.ts with a fake clock and a fake server.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { renderHtml } from '../render'
import { initFetchForm, type FetchDeps } from '../client/lib/fetch-form'
import { errorPageProps } from '../errors'
import { accountsFixtures } from '../gallery/fixtures/accounts'
import { deviceFixtures } from '../gallery/fixtures/devices'
import { AccountChooser, type AccountChooserProps } from './AccountChooser'
import { WorkspaceChooser, type WorkspaceChooserProps } from './WorkspaceChooser'
import { Handoff, type HandoffProps } from './Handoff'
import { Invitation, article, emailMismatch, type InvitationProps } from './Invitation'
import { DEVICE_CONFIRM_ERRORS, DeviceConfirm, type DeviceConfirmProps } from './DeviceConfirm'
import { DeviceEntry } from './DeviceEntry'
import { DeviceDone, type DeviceSignedProps } from './DeviceDone'

const EVIL = '<script>alert(1)</script>'

const flush = () => new Promise((r) => setTimeout(r, 0))

/** A screen's real markup in the document, driven by lib/fetch-form.ts with a fake clock and server. */
async function mountFetchForm(el: JSX.Element, post: FetchDeps['post']) {
  const html = await renderHtml(el, { title: 't' })
  document.body.innerHTML = new DOMParser().parseFromString(html, 'text/html').body.innerHTML
  const timers: { fn: () => void; at: number }[] = []
  let now = 0
  const later = (fn: () => void, ms: number) => void timers.push({ fn, at: now + ms })
  const advance = (ms: number) => {
    now += ms
    for (const t of timers.filter((t) => t.at <= now)) {
      timers.splice(timers.indexOf(t), 1)
      t.fn()
    }
  }
  const go = vi.fn()
  const form = document.querySelector<HTMLFormElement>('form[data-js="fetch-form"]')!
  initFetchForm(form, { post, later, go })
  const click = (value: string) => {
    const btn = form.querySelector<HTMLButtonElement>(`button[value="${value}"]`)!
    form.dispatchEvent(Object.assign(new Event('submit', { bubbles: true, cancelable: true }), { submitter: btn }))
  }
  return {
    form,
    click,
    advance,
    go,
    connector: () => document.querySelector('[data-js="connector"]')!.getAttribute('data-state'),
    title: () => document.querySelector('[data-region] h1')!.textContent,
    desc: () => document.querySelector('[data-region] .id-desc')?.textContent,
    foot: () => document.querySelector('[data-region="foot"]')!,
    status: () => document.querySelector('[data-status]')!.textContent,
    buttons: () => Array.from(form.querySelectorAll('button')),
  }
}

afterEach(() => (document.body.innerHTML = ''))

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
    continueHref: 'https://do.industries/',
    action: '/invite/tok_123',
    csrf: 'tok',
  }

  it('posts accept or decline to /invite/:token through fetch-form, each naming its result template', async () => {
    const doc = await dom(<Invitation {...base} />)
    expectOneH1(doc, 'Join .do Industries')
    expect(doc.querySelector('.id-desc')?.textContent).toBe('Nathan Clevenger invited you as an Admin.')
    expectLabelled(doc)
    expectStatus(doc)
    const form = expectForm(doc, '/invite/tok_123')
    expect(form.getAttribute('data-js')).toBe('fetch-form')
    expect(doc.querySelector('.id-column')?.classList.contains('id-column--narrow')).toBe(true)
    const buttons = Array.from(form.querySelectorAll<HTMLButtonElement>('button[type="submit"][name="decision"]'))
    expect(buttons.map((b) => [b.getAttribute('value'), b.textContent, b.hasAttribute('disabled'), b.hasAttribute('data-deny'), b.getAttribute('data-done')])).toEqual([
      ['decline', 'Decline', false, true, 'declined'],
      ['accept', 'Join workspace', false, false, 'joined'],
    ])
    expect(form.querySelector('a.id-link[href="/account/choose"]')?.textContent).toBe('Switch')
  })

  it('carries the joined and declined results as templates for both regions; the status region sits outside them', async () => {
    const doc = await dom(<Invitation {...base} />)
    const body = doc.querySelector('[data-region="body"]')!
    const foot = doc.querySelector('[data-region="foot"]')!
    for (const state of ['joined', 'declined']) {
      expect(body.parentElement!.querySelector(`:scope > template[data-state="${state}"]`), `body ${state}`).not.toBeNull()
      expect(foot.parentElement!.querySelector(`:scope > template[data-state="${state}"]`), `foot ${state}`).not.toBeNull()
    }
    expect(doc.querySelector('[data-status]')!.closest('[data-region]')).toBeNull()
  })

  it('disables Join and Decline and makes Switch prominent when the signed-in email is not the invited one', async () => {
    const props = { ...base, account: { name: 'Bryant Skarda', email: 'bryant@do.industries' } }
    expect(emailMismatch(props)).toBe(true)
    expect(emailMismatch({ ...base, account: { name: 'B', email: 'Bryant@Driv.ly' } })).toBe(false)
    const doc = await dom(<Invitation {...props} />)
    expect(doc.querySelector('button[value="accept"]')?.hasAttribute('disabled')).toBe(true)
    expect(doc.querySelector('button[value="decline"]')?.hasAttribute('disabled')).toBe(true)
    expect(doc.querySelector('a.id-btn[href="/account/choose"]')?.textContent).toBe('Switch account')
    expect(doc.querySelector('.id-note')?.textContent).toBe('This invitation is for bryant@driv.ly. Switch to that account to join or decline.')
  })

  it('declined result (no JS): a fail head, the inviter named, no form', async () => {
    const doc = await dom(<Invitation {...base} state="declined" />)
    expectOneH1(doc, 'Invitation declined')
    expect(doc.querySelector('.id-desc')?.textContent).toBe('You didn’t join .do Industries. You can close this tab.')
    expect(expectStatus(doc).textContent).toBe('Declined')
    expect(doc.querySelector('.id-conn')?.getAttribute('data-state')).toBe('fail')
    expect(doc.querySelector('.id-foottext')?.textContent).toBe('Changed your mind? Ask Nathan Clevenger to invite you again.')
    expect(doc.querySelector('form')).toBeNull()
    expect(doc.querySelector('template')).toBeNull()
  })

  it('joined result (no JS, or no redirect): an ok head, the role, and the way on', async () => {
    const doc = await dom(<Invitation {...base} state="joined" />)
    expectOneH1(doc, 'Welcome to .do Industries')
    expect(doc.querySelector('.id-desc')?.textContent).toBe('You joined as an Admin.')
    expect(expectStatus(doc).textContent).toBe('Joined')
    expect(doc.querySelector('.id-conn')?.getAttribute('data-state')).toBe('ok')
    expect(doc.querySelector('.id-foottext a')?.getAttribute('href')).toBe('https://do.industries/')
    expect(doc.querySelector('.id-foottext a')?.textContent).toBe('Continue to .do Industries')
    expect(doc.querySelector('form')).toBeNull()
  })

  it('the article goes by sound: a User, an Admin, an Owner, a Member', async () => {
    expect(['User', 'Admin', 'Owner', 'Member', 'editor'].map((r) => `${article(r)} ${r}`)).toEqual(['a User', 'an Admin', 'an Owner', 'a Member', 'an editor'])
    const user = await dom(<Invitation {...base} role="User" />)
    expect(user.querySelector('.id-desc')?.textContent).toBe('Nathan Clevenger invited you as a User.')
    const member = await dom(<Invitation {...base} role="Member" />)
    expect(member.querySelector('.id-desc')?.textContent).toBe('Nathan Clevenger invited you as a Member.')
  })

  it('escapes invitation data', async () => {
    const html = await renderHtml(<Invitation {...base} inviter={{ name: EVIL }} role={EVIL} invitedEmail={EVIL} workspace={{ name: EVIL, tile: { kind: 'monogram', text: 'x' } }} />, {
      title: 't',
    })
    expectEscaped(new DOMParser().parseFromString(html, 'text/html'), html)
  })
})

describe('2e on lib/fetch-form.ts (motion.md#where-the-person-goes-next)', () => {
  const live = () => accountsFixtures['2e-invitation']!.default.render()

  it('Join: connecting and "Joining…" at once; a {redirect} answer leaves for 2c at once', async () => {
    let resolve!: (r: { ok: boolean; redirect?: string }) => void
    const post = vi.fn<FetchDeps['post']>(() => new Promise((r) => (resolve = r)))
    const m = await mountFetchForm(live(), post)
    m.click('accept')
    expect(m.connector()).toBe('connecting')
    const join = m.form.querySelector<HTMLButtonElement>('button[value="accept"]')!
    expect(join.getAttribute('aria-busy')).toBe('true')
    expect(join.textContent).toBe('Joining…')
    expect(m.form.querySelector<HTMLButtonElement>('button[value="decline"]')!.disabled).toBe(true)
    expect(m.status()).toBe('Joining…')
    expect(post.mock.calls[0]![1]!.value).toBe('accept')
    resolve({ ok: true, redirect: '/oauth/authorize?resume=x' })
    await flush()
    expect(m.go).toHaveBeenCalledWith('/oauth/authorize?resume=x')
    expect(m.title()).toBe('Join .do Industries')
  })

  it('Join with a plain {ok}: done, then the joined result 2150ms later in both regions, focus on its title', async () => {
    const m = await mountFetchForm(live(), async () => ({ ok: true }))
    m.click('accept')
    await flush()
    expect(m.connector()).toBe('done')
    m.advance(2149)
    expect(m.title()).toBe('Join .do Industries')
    m.advance(1)
    expect(m.title()).toBe('Welcome to .do Industries')
    expect(m.connector()).toBe('ok')
    expect(m.foot().textContent).toBe('Continue to .do Industries')
    expect(m.foot().querySelector('a')?.getAttribute('href')).toBe('/')
    expect(document.activeElement).toBe(document.querySelector('[data-region] h1'))
    expect(m.go).not.toHaveBeenCalled()
  })

  it('Decline: broken at once, both disabled, the declined result once 1820ms passed and the server agreed', async () => {
    let resolve!: (r: { ok: boolean }) => void
    const post = vi.fn<FetchDeps['post']>(() => new Promise((r) => (resolve = r)))
    const m = await mountFetchForm(live(), post)
    m.click('decline')
    expect(m.connector()).toBe('broken')
    for (const b of m.buttons()) expect(b.disabled).toBe(true)
    expect(post.mock.calls[0]![1]!.value).toBe('decline')
    m.advance(1820)
    expect(m.title()).toBe('Join .do Industries')
    resolve({ ok: true })
    await flush()
    expect(m.title()).toBe('Invitation declined')
    expect(m.connector()).toBe('fail')
    expect(m.foot().textContent).toBe('Changed your mind? Ask Nathan Clevenger to invite you again.')
  })

  it('Decline answered quickly still waits for 1820ms', async () => {
    const m = await mountFetchForm(live(), async () => ({ ok: true }))
    m.click('decline')
    await flush()
    m.advance(1819)
    expect(m.title()).toBe('Join .do Industries')
    m.advance(1)
    expect(m.title()).toBe('Invitation declined')
  })

  it('a refusal has no 2e template: the buttons come back and the status region says so', async () => {
    const m = await mountFetchForm(live(), async () => ({ ok: false, error: 'server_error' }))
    m.click('accept')
    await flush()
    expect(m.connector()).toBe('broken')
    m.advance(1820)
    expect(m.title()).toBe('Join .do Industries')
    expect(m.status()).toBe('Something went wrong. Try again.')
    for (const b of m.buttons()) expect(b.disabled).toBe(false)
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

  it('links the error to every box and announces it once, through role=alert', async () => {
    const doc = await dom(<DeviceEntry action="/device" csrf="tok" value="WDJB-MJHX" error="That code is invalid or has expired." />)
    const boxes = Array.from(doc.querySelectorAll('input[name="code"]'))
    expect(boxes.map((b) => b.getAttribute('value')).join('')).toBe('WDJBMJHX')
    for (const b of boxes) {
      expect(b.getAttribute('aria-invalid')).toBe('true')
      expect(b.getAttribute('aria-describedby')).toBe('device-code-error')
    }
    const error = doc.getElementById('device-code-error')!
    expect(error.textContent).toBe('That code is invalid or has expired.')
    expect(error.getAttribute('role')).toBe('alert')
    // The status region stays (submit.js writes "Checking…" there) but doesn't repeat the error.
    expect(expectStatus(doc).textContent).toBe('')
    const live = Array.from(doc.querySelectorAll('[role="alert"], [role="status"]')).filter((el) => el.textContent?.includes('That code'))
    expect(live).toHaveLength(1)
  })

  it('escapes the typed value and the error', async () => {
    const html = await renderHtml(<DeviceEntry action="/device" csrf="tok" error={EVIL} />, { title: 't' })
    expectEscaped(new DOMParser().parseFromString(html, 'text/html'), html)
  })
})

describe('4b · Confirm device code: the error templates', () => {
  const p: DeviceConfirmProps = {
    code: 'WDJB-MJHT',
    expiresInMinutes: 29,
    requestId: 'req_gallery',
    client: { name: 'auto.dev CLI', tile: { kind: 'icon', icon: 'terminal' } },
    cliName: 'auto.dev',
    deviceMeta: 'macOS · Miami, FL · requested 1 min ago',
    device: 'macOS · Miami, FL',
    account: { name: 'Bryant Skarda', email: 'bryant@driv.ly' },
    switchHref: '/account/choose',
    workspaces: [{ value: 'org_drivly', label: 'Drivly' }],
    selectedWorkspace: 'org_drivly',
    permissions: [],
    revokeHref: '/device/revoke',
    action: '/device/decision',
    csrf: 'tok',
  }
  const expired = errorPageProps('expired', { requestId: 'req_gallery', expired: { what: 'device code' } })
  const used = errorPageProps('already_used', { requestId: 'req_gallery', expired: { what: 'device code' } })
  const server = errorPageProps('server_error', { requestId: 'req_gallery' })

  it('the live page carries error-expired, error-already_used, error-cancel and error for both regions', async () => {
    const doc = await dom(<DeviceConfirm {...p} />)
    const body = doc.querySelector('[data-region="body"]')!
    const foot = doc.querySelector('[data-region="foot"]')!
    expect(DEVICE_CONFIRM_ERRORS).toEqual(['error-expired', 'error-already_used', 'error-cancel', 'error'])
    for (const state of ['signed', 'cancelled', ...DEVICE_CONFIRM_ERRORS]) {
      expect(body.parentElement!.querySelector(`:scope > template[data-state="${state}"]`), `body ${state}`).not.toBeNull()
      expect(foot.parentElement!.querySelector(`:scope > template[data-state="${state}"]`), `foot ${state}`).not.toBeNull()
    }
  })

  it('only the live (idle) page carries templates', async () => {
    for (const state of ['connecting', 'verdict', 'signed', 'cancelling', 'cancelled', ...DEVICE_CONFIRM_ERRORS] as const) {
      const doc = await dom(<DeviceConfirm {...p} state={state} />)
      expect(doc.querySelector('template'), state).toBeNull()
    }
  })

  it('expired and already used: a fail head with the 7b copy, and Start again to /device', async () => {
    for (const [state, copy] of [
      ['error-expired', expired],
      ['error-already_used', used],
    ] as const) {
      const doc = await dom(<DeviceConfirm {...p} state={state} />)
      expectOneH1(doc, copy.title)
      expect(doc.querySelector('.id-desc')?.textContent).toBe(copy.reason)
      expect(doc.querySelector('.id-conn')?.getAttribute('data-state')).toBe('fail')
      const again = doc.querySelector('[data-region="foot"] a.id-btn--primary')!
      expect(again.textContent).toBe('Start again')
      expect(again.getAttribute('href')).toBe('/device')
    }
    expect(expired.title).toBe('This code has expired')
    expect(expired.reason).toBe('Device codes last 30 minutes and work once. Run the sign-in command again for a new one.')
    expect(used.reason).toBe('This device code was already used. Run the sign-in command again for a new one.')
  })

  it('a failed Cancel: the request may still be pending, so close the tab before the code expires', async () => {
    const doc = await dom(<DeviceConfirm {...p} state="error-cancel" />)
    expectOneH1(doc, 'We couldn’t cancel this request')
    expect(doc.querySelector('.id-desc')?.textContent).toBe('Close this tab; the code expires in 29 minutes.')
    expect(doc.querySelector('.id-conn')?.getAttribute('data-state')).toBe('fail')
    expect(doc.querySelector('[data-region="foot"]')?.textContent).toBe('Nothing is shared with auto.dev CLI unless you confirm.')
    const one = await dom(<DeviceConfirm {...p} state="error-cancel" expiresInMinutes={1} />)
    expect(one.querySelector('.id-desc')?.textContent).toBe('Close this tab; the code expires in 1 minute.')
  })

  it('anything else: the generic error, and Try again back to /device?code=', async () => {
    const doc = await dom(<DeviceConfirm {...p} state="error" />)
    expectOneH1(doc, server.title)
    expect(doc.querySelector('.id-desc')?.textContent).toBe(server.reason)
    const again = doc.querySelector('[data-region="foot"] a.id-btn--primary')!
    expect(again.textContent).toBe('Try again')
    expect(again.getAttribute('href')).toBe('/device?code=WDJB-MJHT')
  })

  it('swaps in on lib/fetch-form.ts: a refused Confirm shows its code’s template 1820ms later', async () => {
    for (const [error, title] of [
      ['expired', expired.title],
      ['already_used', used.title],
      ['server_error', server.title],
      [undefined, server.title],
    ] as const) {
      const m = await mountFetchForm(<DeviceConfirm {...p} />, async () => ({ ok: false, error }))
      m.click('approve')
      await flush()
      expect(m.connector()).toBe('broken')
      m.advance(1819)
      expect(m.title()).toBe('Confirm sign-in on auto.dev CLI')
      m.advance(1)
      expect(m.title(), String(error)).toBe(title)
      expect(m.connector()).toBe('fail')
      expect(m.foot().querySelector('button')).toBeNull()
    }
  })

  it('swaps in on lib/fetch-form.ts: a failed Cancel shows error-cancel', async () => {
    const m = await mountFetchForm(<DeviceConfirm {...p} />, async () => ({ ok: false, error: 'server_error' }))
    m.click('deny')
    await flush()
    m.advance(1820)
    expect(m.title()).toBe('We couldn’t cancel this request')
    expect(m.foot().textContent).toBe('Nothing is shared with auto.dev CLI unless you confirm.')
  })

  it('escapes the client name and code in the error templates', async () => {
    const html = await renderHtml(<DeviceConfirm {...p} code={EVIL} client={{ name: EVIL, tile: { kind: 'icon', icon: 'terminal' } }} />, { title: 't' })
    expect(html).not.toContain(EVIL)
    expect(html).toContain(`href="/device?code=${encodeURIComponent(EVIL)}"`)
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
