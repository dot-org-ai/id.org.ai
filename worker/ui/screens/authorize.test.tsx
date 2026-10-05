/**
 * Accessibility and form contracts for the Authorize screens (3a–3d):
 * one h1, labelled controls, forms posting to the routes in spec/screens.md
 * with a CSRF field, a role=status region, and request data escaped. Consent
 * derives everything the trust level decides from `client.verified`; 3d stays
 * on id.org.ai and swaps its results in through lib/fetch-form.ts.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { renderHtml } from '../render'
import { authorizeFixtures } from '../gallery/fixtures/authorize'
import type { Variant } from '../gallery/types'
import { initFetchForm, type FetchDeps } from '../client/lib/fetch-form'
import { initLeave } from '../client/lib/leave'
import { FAIL_SWAP_MS, SUCCESS_SWAP_MS } from '../client/lib/connector'
import { Consent, consentVariant, firstName, type ConsentProps } from './Consent'
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
    expect(byFor || wrapped || el.getAttribute('aria-label') || el.getAttribute('aria-labelledby'), el.outerHTML).toBeTruthy()
  }
  for (const b of d.querySelectorAll('button, a')) {
    expect(text(b) || b.getAttribute('aria-label'), b.outerHTML).toBeTruthy()
  }
}

function hiddenValue(form: Element, name: string): string | null {
  return form.querySelector(`input[type="hidden"][name="${name}"]`)?.getAttribute('value') ?? null
}

/** Key/value rows under `selector` as "Key: Value" lines. */
const kvRows = (root: ParentNode, selector: string) => [...root.querySelectorAll(`${selector} .id-kv`)].map((r) => [...r.children].map((c) => text(c)).join(': '))
/** The source row's details. */
const sourceRows = (d: Document) => kvRows(d, '.id-source__panel')

const f3a = authorizeFixtures['3a-consent']!
const f3b = authorizeFixtures['3b-consent-basic']!
const f3c = authorizeFixtures['3c-consent-unverified']!
const f3d = authorizeFixtures['3d-admin-approve']!

describe('every authorize fixture', () => {
  const variants = Object.entries(authorizeFixtures).flatMap(([slug, f]) => [
    [slug, f.default] as const,
    ...Object.entries(f.states).map(([k, v]) => [`${slug}?state=${k}`, v] as const),
    ...Object.entries(f.derived).map(([k, v]) => [`${slug}?state=${k}`, v] as const),
  ])
  it.each(variants)('%s renders one h1, labelled controls, a status region and no inline style', async (_name, v) => {
    const html = await renderHtml(v.render(), { title: v.title })
    expect(html).not.toMatch(/\sstyle=/i)
    expect(html).not.toMatch(/<style[\s>]/i)
    expect(html).not.toMatch(/\son[a-z]+=/i)
    const doc = new DOMParser().parseFromString(html, 'text/html')
    expect(doc.querySelectorAll('h1').length).toBe(1)
    expectLabelled(doc)
    expect(doc.querySelector('[role="status"][data-status]')).toBeTruthy()
  })

  it('consent leaves id.org.ai (submit.js); 3d stays (fetch-form.js)', async () => {
    for (const f of [f3a, f3b, f3c]) {
      expect(f.scripts).toContain('submit.js')
      expect(f.scripts).not.toContain('fetch-form.js')
      expect((await render(f.default)).querySelector('form')?.getAttribute('data-js')).toBe('submit')
    }
    expect(f3d.scripts).toContain('fetch-form.js')
    expect(f3d.scripts).not.toContain('submit.js')
  })
})

describe('3a · Authorize app', () => {
  it('has one h1, labelled controls and a status region', async () => {
    const d = await render(f3a.default)
    expect(d.querySelectorAll('h1').length).toBe(1)
    expect(text(d.querySelector('h1'))).toBe('Codex wants to use api.sb as you')
    expect(f3a.default.title).toBe('Authorize Codex · id.org.ai')
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

  it('the Switch link, and the source row built from the client: CIMD URL with copy, details, links', async () => {
    const d = await render(f3a.default)
    const sw = [...d.querySelectorAll('a')].find((a) => text(a) === 'Switch')!
    expect(sw.getAttribute('href')).toMatch(/^\/login\?prompt=login&continue=/)
    expect(d.querySelector('[data-js="copy"]')?.getAttribute('data-value')).toBe('https://chatgpt.com/oauth/codex/client.json')
    expect(text(d.querySelector('.id-source__value'))).toBe('chatgpt.com/oauth/codex/client.json')
    expect(sourceRows(d)).toEqual(['Runs on: This computer', 'Returns to: 127.0.0.1:57585', 'Identified by: chatgpt.com'])
    expect([...d.querySelectorAll('.id-source__links a')].map((a) => [text(a), a.getAttribute('href')])).toEqual([
      ['Codex privacy policy', 'https://example.com/codex/privacy'],
      ['Codex terms', 'https://example.com/codex/terms'],
    ])
    expect(d.querySelector('.id-warning')).toBeNull()
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

  it('the monogram tile without a logoUrl', async () => {
    const d = await render(f3a.default)
    expect([...d.querySelectorAll('.id-tile')].map((t) => text(t))).toContain('Cx')
    expect(d.querySelector('[data-js="logo"]')).toBeNull()
  })

  it('logo and codex-logo: the tile renders client.logoUrl with the monogram fallback hook', async () => {
    for (const [v, src] of [
      [f3a.derived.logo, '/orgLogo.svg'],
      [f3a.derived['codex-logo'], 'https://persistent.oaistatic.com/sonic/misc/openai-logo.png'],
    ] as const) {
      const d = await render(v)
      const tile = d.querySelector('[data-js="logo"]')!
      expect(tile.getAttribute('data-monogram')).toBe('Cx')
      expect(tile.querySelector('img')?.getAttribute('src')).toBe(src)
      expect(tile.querySelector('img')?.getAttribute('alt')).toBe('')
    }
  })
})

describe('3b · Sign in with id.org.ai', () => {
  it('has one h1, labelled controls, the identity summary and no permission list', async () => {
    const d = await render(f3b.default)
    expect(d.querySelectorAll('h1').length).toBe(1)
    expect(text(d.querySelector('h1'))).toBe('Sign in to api.sb')
    expect(f3b.default.title).toBe('Sign in to api.sb · id.org.ai')
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

  it('without a CIMD URL the source row shows the client_id', async () => {
    const d = await render(f3b.default)
    expect(text(d.querySelector('.id-source__value'))).toBe('api.sb')
    expect(d.querySelector('[data-js="copy"]')?.getAttribute('data-value')).toBe('api.sb')
    expect(sourceRows(d)).toEqual(['Identified by: api.sb', 'Returns to: https://api.sb/auth/callback'])
    expect([...d.querySelectorAll('.id-source__links a')].map((a) => text(a))).toEqual(['api.sb privacy policy', 'api.sb terms'])
  })
})

describe('3c · Unverified app', () => {
  it('has one h1 naming the host, the warning callout and labelled controls', async () => {
    const d = await render(f3c.default)
    expect(d.querySelectorAll('h1').length).toBe(1)
    expect(text(d.querySelector('h1'))).toBe('agent-tools.dev wants to read your Startups')
    expect(f3c.default.title).toBe('Authorize agent-tools.dev · id.org.ai')
    expect(text(d.querySelector('.id-desc'))).toBe('It runs on your computer and asked for read access to api.sb.')
    expect(text(d.querySelector('.id-warning__title'))).toBe('id.org.ai can’t vouch for this app')
    expect(d.querySelector('[role="note"]')).toBeTruthy()
    expectLabelled(d)
    expect(d.querySelector('[role="status"][data-status]')).toBeTruthy()
  })

  it('keeps Cancel primary on the left and Allow outlined on the right', async () => {
    const d = await render(f3c.default)
    const [cancel, allow] = [...d.querySelectorAll('[data-actions] > button')]
    expect(text(allow)).toBe('Allow')
    expect(allow!.className).toContain('id-btn--secondary')
    expect(allow!.getAttribute('value')).toBe('true')
    expect(allow!.getAttribute('data-busy-label')).toBe('Allowing…')
    expect(text(cancel)).toBe('Cancel')
    expect(cancel!.className).toContain('id-btn--primary')
    expect(cancel!.getAttribute('value')).toBe('false')
  })

  it('posts the workspace and read access as hidden fields; the component adds Verified: No', async () => {
    const d = await render(f3c.default)
    const form = d.querySelector('form')!
    expect(form.getAttribute('action')).toBe('/oauth/authorize')
    expect(hiddenValue(form, 'csrf')).toBe('gallery')
    expect(hiddenValue(form, 'org_id')).toBe('org_do')
    expect(hiddenValue(form, 'access')).toBe('read')
    expect(sourceRows(d)).toEqual(['Runs on: This computer', 'Returns to: 127.0.0.1:61022', 'Verified: No'])
    expect([...d.querySelectorAll('.id-tile')].map((t) => text(t))).toContain('a')
  })
})

describe('Consent derives the trust level from client.verified (security.md, screens.md#3c)', () => {
  /** An unverified client claiming to be Codex: the 3a props a caller would map from the request. */
  const impostor: ConsentProps = {
    variant: 'full',
    client: {
      displayName: 'Codex',
      host: 'agent-tools.dev',
      verified: false,
      runsOnThisComputer: true,
      redirectHost: '127.0.0.1:61022',
      cimdUrl: 'https://agent-tools.dev/oauth/client.json',
      privacyUrl: 'https://agent-tools.dev/privacy',
      termsUrl: 'https://agent-tools.dev/terms',
      monogram: 'Cx',
    },
    resource: 'api.sb',
    account: { name: 'Bryant Skarda', email: 'bryant@driv.ly' },
    switchHref: '/login?prompt=login',
    workspaces: [{ value: 'org_do', label: '.do Industries' }],
    selectedWorkspace: 'org_do',
    access: { value: 'act', choice: { read: 'Search and read your Startups', act: 'Also run Verbs that change them' } },
    permissions: [{ icon: 'search', title: 'Search and read your Startups on api.sb', detail: 'Read-only.', scope: 'sb:read · resource https://api.sb' }],
    sourceDetails: [
      { k: 'Runs on', v: 'This computer' },
      { k: 'Returns to', v: '127.0.0.1:61022', mono: true },
    ],
    hidden: { client_id: 'https://agent-tools.dev/oauth/client.json', redirect_uri: 'http://127.0.0.1:61022/callback', scope: 'openid profile email sb:read sb:do', state: 's' },
    action: '/oauth/authorize',
    csrf: 'tok',
  }

  it('an unverified client named "Codex" at agent-tools.dev shows the host wherever a name appears, never "Codex"', async () => {
    const html = await renderHtml(<Consent {...impostor} />, { title: 't' })
    expect(html).not.toMatch(/codex/i)
    const d = new DOMParser().parseFromString(html, 'text/html')
    expect(text(d.querySelector('h1'))).toBe('agent-tools.dev wants to use api.sb as you')
    expect(text(d.querySelector('.id-warning'))).toContain('Only continue if you trust agent-tools.dev and started this yourself.')
    expect([...d.querySelectorAll('.id-group-label')].map((l) => text(l))).toContain('agent-tools.dev would like to')
    expect([...d.querySelectorAll('.id-source__links a')].map((a) => text(a))).toEqual(['agent-tools.dev privacy policy', 'agent-tools.dev terms'])
    // The tile's monogram comes from the host too, not the claimed name's "Cx".
    const tiles = [...d.querySelectorAll('.id-tile')].map((t) => text(t))
    expect(tiles).toContain('a')
    expect(tiles).not.toContain('Cx')
  })

  it('verified: false with variant "full" still renders 3c: callout, emphasized Cancel, Verified: No', async () => {
    expect(consentVariant(impostor)).toBe('unverified')
    const d = await dom(<Consent {...impostor} />)
    expect(text(d.querySelector('.id-warning__title'))).toBe('id.org.ai can’t vouch for this app')
    const [cancel, allow] = [...d.querySelectorAll('[data-actions] > button')]
    expect([text(allow), allow!.className.includes('id-btn--secondary')]).toEqual(['Allow', true])
    expect([text(cancel), cancel!.className.includes('id-btn--primary')]).toEqual(['Cancel', true])
    expect(sourceRows(d)).toEqual(['Runs on: This computer', 'Returns to: 127.0.0.1:61022', 'Verified: No'])
  })

  it('verified: false with variant "basic" and identity scopes still renders 3c', async () => {
    const p: ConsentProps = { ...impostor, variant: 'basic', hidden: { ...impostor.hidden, scope: 'openid profile email' } }
    expect(consentVariant(p)).toBe('unverified')
    const d = await dom(<Consent {...p} />)
    expect(text(d.querySelector('h1'))).toBe('agent-tools.dev wants to use api.sb as you')
    expect(d.querySelector('.id-warning')).toBeTruthy()
    expect(text(d.querySelector('[data-actions] > button:last-child'))).toBe('Allow')
  })

  it('a caller-supplied Verified row is replaced, never trusted', async () => {
    const p: ConsentProps = { ...impostor, sourceDetails: [...impostor.sourceDetails, { k: 'Verified', v: 'Yes' }] }
    expect(sourceRows(await dom(<Consent {...p} />))).toEqual(['Runs on: This computer', 'Returns to: 127.0.0.1:61022', 'Verified: No'])
  })

  it('an unverified client keeps its own logo_uri, with the host monogram as the fallback', async () => {
    const p: ConsentProps = { ...impostor, client: { ...impostor.client, logoUrl: 'https://agent-tools.dev/logo.png' } }
    const tile = (await dom(<Consent {...p} />)).querySelector('[data-js="logo"]')!
    expect(tile.getAttribute('data-monogram')).toBe('a')
    expect(tile.querySelector('img')?.getAttribute('src')).toBe('https://agent-tools.dev/logo.png')
  })

  it('a verified client shows its name, no callout and no Verified row', async () => {
    const p: ConsentProps = { ...impostor, client: { ...impostor.client, verified: true, displayName: 'Agent Tools' } }
    expect(consentVariant(p)).toBe('full')
    const d = await dom(<Consent {...p} />)
    expect(text(d.querySelector('h1'))).toBe('Agent Tools wants to use api.sb as you')
    expect(d.querySelector('.id-warning')).toBeNull()
    expect(sourceRows(d)).toEqual(['Runs on: This computer', 'Returns to: 127.0.0.1:61022'])
    expect(text(d.querySelector('[data-actions] > button:last-child'))).toBe('Allow')
  })

  it('basic only for a verified, identity-only request: asked as basic with API scopes, it renders 3a', async () => {
    const verified = { ...impostor.client, verified: true, displayName: 'Agent Tools' }
    const withApi: ConsentProps = { ...impostor, variant: 'basic', client: verified }
    expect(consentVariant(withApi)).toBe('full')
    const d = await dom(<Consent {...withApi} />)
    expect(text(d.querySelector('[data-actions] > button:last-child'))).toBe('Allow')
    expect(d.querySelector('.id-perm')).toBeTruthy()

    const identity: ConsentProps = { ...withApi, hidden: { ...withApi.hidden, scope: 'openid profile email' } }
    expect(consentVariant(identity)).toBe('basic')
    expect(text((await dom(<Consent {...identity} />)).querySelector('[data-actions] > button:last-child'))).toBe('Continue as Bryant')
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
    expect(text(d.querySelector('label[for="approve-requester"]'))).toContain(`${firstName({ name: 'Alex Rivera' })} only`)
  })

  it('the live page is a fetch-form: regions, the result templates, Approve done and Decline deny', async () => {
    const d = await render(f3d.default)
    const form = d.querySelector('form')!
    expect(form.getAttribute('data-js')).toBe('fetch-form')
    expect(form.querySelectorAll('[data-region="body"]').length).toBe(1)
    expect(form.querySelectorAll('[data-region="foot"]').length).toBe(1)
    for (const state of ['approved', 'declined']) {
      // One template beside each region: the body's and the foot's.
      expect(form.querySelectorAll(`template[data-state="${state}"]`).length, state).toBe(2)
    }
    const [decline, approve] = [...d.querySelectorAll('[data-actions] > button')]
    expect(approve!.getAttribute('data-done')).toBe('approved')
    expect(approve!.hasAttribute('data-deny')).toBe(false)
    expect(decline!.getAttribute('data-done')).toBe('declined')
    expect(decline!.hasAttribute('data-deny')).toBe(true)
    expect(d.querySelector('[data-status]')!.closest('[data-region]')).toBeNull()
  })

  it('approved and declined (no-JS results) render in place, announced, with no form and no templates', async () => {
    const ok = await render(f3d.derived.approved)
    expect(ok.querySelectorAll('h1').length).toBe(1)
    expect(text(ok.querySelector('h1'))).toBe('Codex is approved for Drivly')
    expect(text(ok.querySelector('.id-desc'))).toBe('We let Alex Rivera know they can connect it now.')
    expect(ok.querySelector('[data-js="connector"]')?.getAttribute('data-state')).toBe('ok')
    expect(kvRows(ok, '.id-well')).toEqual(['App: Codex', 'Workspace: Drivly', 'Approved for: Alex only'])
    expect(text(ok.querySelector('[role="status"][data-status]'))).toBe('Approved')
    expect(ok.querySelector('form')).toBeNull()
    expect(ok.querySelector('template')).toBeNull()

    const no = await render(f3d.derived.declined)
    expect(no.querySelectorAll('h1').length).toBe(1)
    expect(text(no.querySelector('h1'))).toBe('Request declined')
    expect(no.querySelector('[data-js="connector"]')?.getAttribute('data-state')).toBe('fail')
    expect(text(no.querySelector('[role="status"][data-status]'))).toBe('Declined')
    expect(no.querySelector('form')).toBeNull()
  })

  it('approved for everyone says so on the result page', async () => {
    const d = await dom(<AdminApprove {...approveProps({ state: 'approved', scope: 'everyone' })} />)
    expect(text(d.querySelector('.id-desc'))).toBe('We let Alex Rivera know. Anyone in Drivly can connect it now.')
    expect(kvRows(d, '.id-well')).toContain('Approved for: Everyone in Drivly')
  })
})

/** Props for a hand-built 3d. */
function approveProps(over: Partial<AdminApproveProps> = {}): AdminApproveProps {
  return {
    requester: { name: 'Alex Rivera' },
    client: { displayName: 'Codex', host: 'chatgpt.com', verified: true, monogram: 'Cx' },
    workspace: { name: 'Drivly', tile: { kind: 'monogram', text: 'Dr' } },
    permissions: [{ icon: 'search', title: 'Search and read Startups on api.sb', detail: 'Read-only.', scope: 'sb:read' }],
    scope: 'requester',
    admin: { name: 'Nathan Clevenger', email: 'nathan@do.industries' },
    source: { display: 'chatgpt.com/oauth/codex/client.json', copyValue: 'https://chatgpt.com/oauth/codex/client.json', details: [] },
    action: '/admin/requests/req_1',
    csrf: 'tok',
    ...over,
  }
}

describe('3d derives the app’s name from client.verified (phase 3 re-review)', () => {
  it('an unverified client is named by its host everywhere, in every state, never by the name it claims', async () => {
    const client = { displayName: 'Codex', host: 'agent-tools.dev', verified: false, monogram: 'Cx' }
    const source = { display: 'agent-tools.dev/oauth/client.json', copyValue: 'https://agent-tools.dev/oauth/client.json', details: [] }
    for (const state of ['pending', 'approved', 'declined'] as const) {
      const html = await renderHtml(<AdminApprove {...approveProps({ client, source, state })} />, { title: 't' })
      expect(html, state).not.toMatch(/codex|>Cx</i)
      expect(html, state).toContain('agent-tools.dev')
    }
    const d = await dom(<AdminApprove {...approveProps({ client })} />)
    expect(d.querySelector('h1')!.textContent).toBe('Approve agent-tools.dev for Drivly?')
    expect(d.querySelectorAll('.id-conn .id-tile')[0]!.textContent).toBe('a')
  })

  it('a verified client keeps its name and monogram', async () => {
    const d = await dom(<AdminApprove {...approveProps()} />)
    expect(d.querySelector('h1')!.textContent).toBe('Approve Codex for Drivly?')
    expect(d.querySelectorAll('.id-conn .id-tile')[0]!.textContent).toBe('Cx')
  })
})

describe('3d on lib/fetch-form.ts (motion.md#where-the-person-goes-next)', () => {
  type Post = FetchDeps['post']

  /** The real 3d markup from the gallery fixture, with a fake clock and a fake server. */
  async function mount(post: Post) {
    const html = await renderHtml(f3d.default.render(), { title: 't' })
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
    const form = document.querySelector<HTMLFormElement>('form[data-js="fetch-form"]')!
    initFetchForm(form, { post, later, go: vi.fn() })
    const button = (value: 'approve' | 'decline') => form.querySelector<HTMLButtonElement>(`button[value="${value}"]`)!
    const click = (value: 'approve' | 'decline') => form.dispatchEvent(Object.assign(new Event('submit', { bubbles: true, cancelable: true }), { submitter: button(value) }))
    const state = () => document.querySelector('[data-js="connector"]')!.getAttribute('data-state')
    const title = () => document.querySelector('[data-region] h1')!.textContent
    const foot = () => text(document.querySelector('.id-card__foot [data-region="foot"]'))
    const status = () => document.querySelector('[data-status]')!.textContent
    return { form, button, click, advance, state, title, foot, status }
  }

  const flush = () => new Promise((r) => setTimeout(r, 0))

  afterEach(() => (document.body.innerHTML = ''))

  it('Approve: connecting and busy at once, done on the OK, approved 2150ms later with focus on the title', async () => {
    let resolve!: (r: { ok: boolean }) => void
    const post = vi.fn<Post>(() => new Promise((r) => (resolve = r)))
    const m = await mount(post)
    m.click('approve')
    expect(m.state()).toBe('connecting')
    expect(m.button('approve').getAttribute('aria-busy')).toBe('true')
    expect(m.button('approve').textContent).toBe('Approving…')
    expect(m.button('decline').disabled).toBe(true)
    expect(m.status()).toBe('Approving…')
    expect(post.mock.calls[0]![1]!.value).toBe('approve')
    resolve({ ok: true })
    await flush()
    expect(m.state()).toBe('done')
    m.advance(SUCCESS_SWAP_MS - 1)
    expect(m.title()).toBe('Approve Codex for Drivly?')
    m.advance(1)
    expect(m.title()).toBe('Codex is approved for Drivly')
    expect(m.state()).toBe('ok')
    expect(m.foot()).toBe('You can close this tab.')
    expect(document.querySelector('[data-region] input[name="scope"]')).toBeNull()
    expect(document.activeElement).toBe(document.querySelector('[data-region] h1'))
  })

  it('posts the scope the admin picked; the template only says what is true for either scope', async () => {
    const post = vi.fn<Post>(async () => ({ ok: true }))
    const m = await mount(post)
    m.form.querySelector<HTMLInputElement>('#approve-everyone')!.checked = true
    m.click('approve')
    await flush()
    expect(new FormData(post.mock.calls[0]![0]).get('scope')).toBe('everyone')
    m.advance(SUCCESS_SWAP_MS)
    expect(text(document.querySelector('[data-region] .id-desc'))).toBe('We let Alex Rivera know they can connect it now.')
    expect(kvRows(document, '[data-region] .id-well')).toEqual(['App: Codex', 'Workspace: Drivly'])
  })

  it('Decline: broken at once, both disabled, declined once 1820ms have passed and the server agreed', async () => {
    const post = vi.fn<Post>(async () => ({ ok: true }))
    const m = await mount(post)
    m.click('decline')
    expect(m.state()).toBe('broken')
    for (const b of m.form.querySelectorAll('button')) expect(b.disabled).toBe(true)
    await flush()
    expect(post.mock.calls[0]![1]!.value).toBe('decline')
    m.advance(FAIL_SWAP_MS - 1)
    expect(m.title()).toBe('Approve Codex for Drivly?')
    m.advance(1)
    expect(m.title()).toBe('Request declined')
    expect(m.state()).toBe('fail')
    expect(m.foot()).toBe('You can close this tab.')
  })

  it('Decline waits for a slow server past 1820ms', async () => {
    let resolve!: (r: { ok: boolean }) => void
    const m = await mount(() => new Promise((r) => (resolve = r)))
    m.click('decline')
    m.advance(5000)
    expect(m.title()).toBe('Approve Codex for Drivly?')
    resolve({ ok: true })
    await flush()
    expect(m.title()).toBe('Request declined')
  })

  it('a failure with no error template gives the buttons back, so the admin can try again', async () => {
    const post = vi.fn<Post>(async () => ({ ok: false, error: 'server_error' }))
    const m = await mount(post)
    m.click('approve')
    await flush()
    expect(m.state()).toBe('broken')
    m.advance(FAIL_SWAP_MS)
    expect(m.title()).toBe('Approve Codex for Drivly?')
    expect(m.status()).toBe('Something went wrong. Try again.')
    for (const b of m.form.querySelectorAll('button')) expect(b.disabled).toBe(false)
  })
})

describe('shared helpers', () => {
  it('firstName: the given first name, else the first word of the name', () => {
    expect(firstName({ name: 'Alex Rivera' })).toBe('Alex')
    expect(firstName({ name: '  Bryant  Skarda ' })).toBe('Bryant')
    expect(firstName({ name: 'Alex Rivera', firstName: 'Al' })).toBe('Al')
  })
})

describe('request data is escaped', () => {
  const evil = '<script>alert(1)</script>'
  const quote = '"><img src=x onerror=alert(1)>'

  it('consent: client name and host, permission strings, hidden values and the source row', async () => {
    for (const verified of [true, false]) {
      const p: ConsentProps = {
        variant: 'full',
        client: {
          displayName: evil,
          host: evil,
          verified,
          runsOnThisComputer: false,
          redirectHost: evil,
          cimdUrl: `https://x.example/${quote}`,
          privacyUrl: `https://x.example/${quote}`,
        },
        resource: 'api.sb',
        account: { name: evil, email: 'e@x' },
        switchHref: `/login?continue=${quote}`,
        permissions: [{ icon: 'globe', title: evil, detail: evil, scope: evil }],
        sourceDetails: [{ k: 'Returns to', v: evil }],
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
      expect(d.querySelector('[data-js="copy"]')?.getAttribute('data-value')).toBe(`https://x.example/${quote}`)
    }
  })

  it('admin approve: requester, note and client, in the live page and its templates', async () => {
    const p = approveProps({
      requester: { name: evil },
      // Verified, so the hostile display name is the one rendered.
      client: { displayName: evil, host: 'x.example', verified: true, monogram: 'x' },
      workspace: { name: evil, tile: { kind: 'monogram', text: 'y' } },
      note: evil,
      permissions: [{ icon: 'search', title: evil, detail: evil, scope: evil }],
      admin: { name: 'A B', email: evil },
      source: { display: evil, copyValue: quote, details: [] },
      csrf: quote,
    })
    const html = await renderHtml(<AdminApprove {...p} />, { title: 't' })
    expect(html).not.toContain('<script>alert(1)</script>')
    const d = new DOMParser().parseFromString(html, 'text/html')
    expect(d.querySelectorAll('script:not([src])').length).toBe(0)
    expect(text(d.querySelector('.id-quote__text'))).toBe(`“${evil}”`)
    expect(hiddenValue(d.querySelector('form')!, 'csrf')).toBe(quote)
    const approved = d.querySelector<HTMLTemplateElement>('[data-region="body"] ~ template[data-state="approved"]')!
    expect(approved.content.querySelectorAll('script').length).toBe(0)
    expect(text(approved.content.querySelector('h1'))).toBe(`${evil} is approved for ${evil}`)
  })
})

describe('3a on lib/leave.ts (Task 4: consent leaves id.org.ai)', () => {
  async function mount(): Promise<HTMLFormElement> {
    document.body.innerHTML = await renderHtml(authorizeFixtures['3a-consent']!.default.render(), { title: 't' }).then((h) => h.match(/<body[^>]*>([\s\S]*)<\/body>/)![1]!)
    const form = document.querySelector<HTMLFormElement>('form[data-js="submit"]')!
    initLeave(form)
    form.addEventListener('submit', (e) => e.preventDefault())
    return form
  }
  const press = (form: HTMLFormElement, value: string) => {
    const btn = form.querySelector<HTMLButtonElement>(`button[name="approved"][value="${value}"]`)!
    form.dispatchEvent(Object.assign(new Event('submit', { bubbles: true, cancelable: true }), { submitter: btn }))
    return btn
  }
  afterEach(() => (document.body.innerHTML = ''))

  it('Allow: the connector connects and the button reads "Allowing…" while the post and redirect happen', async () => {
    const form = await mount()
    const allow = press(form, 'true')
    expect(document.querySelector('[data-js="connector"]')!.getAttribute('data-state')).toBe('connecting')
    expect(allow.getAttribute('aria-busy')).toBe('true')
    expect(allow.textContent).toBe('Allowing…')
    expect(form.querySelector<HTMLInputElement>('input[type=hidden][name=approved]')!.value).toBe('true')
  })

  it('Cancel posts the deny (approved=false)', async () => {
    const form = await mount()
    press(form, 'false')
    expect(form.querySelector<HTMLInputElement>('input[type=hidden][name=approved]')!.value).toBe('false')
  })
})

describe('3c for an identity-only request (phase 5 review N3)', () => {
  it('says what it asked for, not "read access to id.org.ai"', async () => {
    const p = authorizeFixtures['3c-consent-unverified']!.default
    const html = await renderHtml(p.render(), { title: 't' })
    expect(html).toContain('read access to api.sb') // the sb request, unchanged
    const props: ConsentProps = {
      variant: 'basic',
      client: { displayName: 'Codex', host: 'agent-tools.dev', verified: false, runsOnThisComputer: true, redirectHost: '127.0.0.1:61022' },
      resource: 'id.org.ai',
      intent: 'sign you in',
      account: { name: 'Bryant Skarda', email: 'bryant@driv.ly' },
      switchHref: '/login',
      sourceDetails: [],
      hidden: { client_id: 'c', scope: 'openid profile email' },
      action: '/oauth/authorize',
      csrf: 't',
    }
    const d = await dom(<Consent {...props} />)
    expect(d.querySelector('h1')!.textContent).toBe('agent-tools.dev wants to sign you in')
    expect(d.querySelector('.id-desc')!.textContent).toBe('It runs on your computer and asked to see your name, email and photo.')
  })
})
