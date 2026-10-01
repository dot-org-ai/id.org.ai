/**
 * Accessibility and safety contracts for the security (6a–6d) and error
 * (7a–7c) screens: one h1, labelled controls, forms posting to the routes in
 * spec/screens.md with a CSRF field, a role=status region, escaped request
 * data, and the rules each screen carries (D8, the reason catalogue, never
 * linking a rejected redirect_uri).
 */
import { describe, expect, it } from 'vitest'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { renderHtml } from '../render'
import { errorsFixtures } from '../gallery/fixtures/errors'
import { securityFixtures } from '../gallery/fixtures/security'
import type { BoundFixture, Variant } from '../gallery/types'
import { AddPasskey } from './AddPasskey'
import { ErrorPage, detailsText, type ErrorPageProps } from './ErrorPage'
import { SignOut, type SignOutProps } from './SignOut'
import { STEP_UP_REASONS, StepUp, type StepUpProps } from './StepUp'
import { TwoStep, type TwoStepProps } from './TwoStep'

async function html(el: JSX.Element): Promise<string> {
  return renderHtml(el, { title: 't' })
}

async function dom(el: JSX.Element): Promise<Document> {
  return new DOMParser().parseFromString(await html(el), 'text/html')
}

function variants(f: BoundFixture): [string, Variant][] {
  return [['default', f.default], ...Object.entries(f.states), ...Object.entries(f.derived)]
}

/** Every visible form control has an accessible name. */
function expectLabelled(d: Document, where: string): void {
  for (const el of Array.from(d.querySelectorAll('main input:not([type=hidden]), main textarea, main select'))) {
    const id = el.getAttribute('id')
    const named = el.getAttribute('aria-label') || (id && d.querySelector(`label[for="${id}"]`)?.textContent?.trim()) || el.closest('label')?.textContent?.trim()
    expect(named, `${where}: ${el.outerHTML}`).toBeTruthy()
  }
  for (const b of Array.from(d.querySelectorAll('main button, main a'))) {
    const name = b.getAttribute('aria-label') || b.textContent?.trim()
    expect(name, `${where}: ${b.outerHTML}`).toBeTruthy()
  }
}

/** Every form posts to `route` (a path prefix) and carries the CSRF field. */
function expectForms(d: Document, route: RegExp): void {
  const forms = Array.from(d.querySelectorAll('form'))
  expect(forms.length).toBe(1)
  for (const f of forms) {
    expect(f.getAttribute('method')).toBe('post')
    expect(f.getAttribute('action')).toMatch(route)
    const csrf = f.querySelector('input[type=hidden][name=csrf]')
    expect(csrf).not.toBeNull()
    expect(csrf!.getAttribute('value')).toBe('gallery')
  }
}

const groups: [string, Record<string, BoundFixture>][] = [
  ['security', securityFixtures],
  ['errors', errorsFixtures],
]

describe.each(groups)('%s fixtures: every state', (_name, group) => {
  for (const [slug, f] of Object.entries(group)) {
    for (const [state, v] of variants(f)) {
      it(`${slug} ${state}: one h1, labelled controls, a status region, no inline style or script`, async () => {
        const out = await html(v.render())
        expect(out).not.toMatch(/\sstyle=/i)
        expect(out).not.toMatch(/\son[a-z]+=/i)
        const d = new DOMParser().parseFromString(out, 'text/html')
        expect(d.querySelectorAll('h1').length).toBe(1)
        expect(d.querySelector('main [role="status"]')).not.toBeNull()
        expectLabelled(d, `${slug} ${state}`)
        expect(v.title).toMatch(/ · id\.org\.ai$/)
      })
    }
  }
})

const EVIL = '<script>alert(1)</script>'
const account = { name: 'Bryant Skarda', email: 'bryant@driv.ly' }

describe('6a · StepUp', () => {
  const p: StepUpProps = {
    app: { name: 'Codex', tile: { kind: 'monogram', text: 'Cx' } },
    reason: 'act_permissions',
    account,
    lastConfirmedAgo: '3 hours ago',
    factors: { passkey: true, email: true },
    action: '/step-up?resume=rsm_1&reason=act_permissions',
    csrf: 'gallery',
  }

  it('posts to /step-up with the resume id and CSRF; each factor is a named submit', async () => {
    const d = await dom(<StepUp {...p} />)
    expectForms(d, /^\/step-up\?resume=[^&]+&reason=act_permissions$/)
    const factors = Array.from(d.querySelectorAll('button[type=submit][name=factor]')).map((b) => b.getAttribute('value'))
    expect(factors).toEqual(['email', 'passkey'])
    expect(d.querySelector('h1')!.textContent).toBe('Confirm it’s you')
    expect(d.querySelector('.id-who__meta')!.textContent).toBe('Confirmed 3 hours ago')
  })

  it('takes the sentence from the reason catalogue, never from free text', async () => {
    for (const reason of Object.keys(STEP_UP_REASONS) as StepUpProps['reason'][]) {
      const d = await dom(<StepUp {...p} reason={reason} />)
      expect(d.querySelector('.id-desc')!.textContent).toBe(STEP_UP_REASONS[reason]('Codex'))
    }
  })

  it('a single factor fills the width as the primary', async () => {
    const d = await dom(<StepUp {...p} factors={{ passkey: false, email: true }} />)
    expect(d.querySelector('[data-actions]')).toBeNull()
    const only = d.querySelectorAll('button[name=factor]')
    expect(only.length).toBe(1)
    expect(only[0]!.getAttribute('value')).toBe('email')
    expect(only[0]!.className).toContain('id-btn--primary')
  })

  it('escapes request data', async () => {
    const out = await html(<StepUp {...p} app={{ name: EVIL, tile: { kind: 'monogram', text: 'X' } }} account={{ name: EVIL, email: EVIL }} />)
    expect(out).not.toContain(EVIL)
    expect(out).toContain('&lt;script&gt;')
  })
})

describe('6b · SignOut', () => {
  const p: SignOutProps = {
    app: { name: 'headless.ly', tile: { kind: 'monogram', text: 'h' } },
    account,
    action: '/signout',
    csrf: 'gallery',
    clientId: 'headless.ly',
    returnUrl: 'https://headless.ly/',
    cancelHref: 'https://headless.ly/',
  }

  it('posts scope, client_id and return_url to /signout; app is the default', async () => {
    const d = await dom(<SignOut {...p} />)
    expectForms(d, /^\/signout$/)
    const radios = Array.from(d.querySelectorAll<HTMLInputElement>('input[type=radio][name=scope]'))
    expect(radios.map((r) => r.value)).toEqual(['app', 'browser', 'everywhere'])
    expect(radios.filter((r) => r.hasAttribute('checked')).map((r) => r.value)).toEqual(['app'])
    expect(d.querySelector('input[name=client_id]')!.getAttribute('value')).toBe('headless.ly')
    expect(d.querySelector('input[name=return_url]')!.getAttribute('value')).toBe('https://headless.ly/')
    expect(d.querySelector('fieldset legend')!.textContent).toBe('How far to sign out')
  })

  it('marks everywhere with the accent dot, and Cancel is a link back', async () => {
    const d = await dom(<SignOut {...p} />)
    const everywhere = d.querySelector('label[for="signout-everywhere"]')!
    expect(everywhere.querySelector('.id-accent-dot')).not.toBeNull()
    expect(d.querySelectorAll('.id-accent-dot').length).toBe(1)
    const cancel = Array.from(d.querySelectorAll('a.id-btn')).find((a) => a.textContent === 'Cancel')!
    expect(cancel.getAttribute('href')).toBe('https://headless.ly/')
  })

  it('without an app, offers browser and everywhere, starting at browser', async () => {
    const d = await dom(<SignOut {...p} app={undefined} clientId={undefined} />)
    const radios = Array.from(d.querySelectorAll<HTMLInputElement>('input[type=radio]'))
    expect(radios.map((r) => r.value)).toEqual(['browser', 'everywhere'])
    expect(radios[0]!.hasAttribute('checked')).toBe(true)
    expect(d.querySelector('input[name=client_id]')).toBeNull()
  })

  it('escapes request data', async () => {
    const out = await html(<SignOut {...p} app={{ name: EVIL, tile: { kind: 'monogram', text: 'X' } }} returnUrl={`"><script>x</script>`} />)
    expect(out).not.toContain(EVIL)
    expect(out).not.toContain('<script>x</script>')
  })
})

describe('6c · AddPasskey', () => {
  it('posts the decision to /passkeys/new with CSRF', async () => {
    const d = await dom(<AddPasskey action="/passkeys/new?continue=%2Fhome" csrf="gallery" />)
    expectForms(d, /^\/passkeys\/new\?continue=/)
    const decisions = Array.from(d.querySelectorAll('button[type=submit][name=decision]')).map((b) => b.getAttribute('value'))
    expect(decisions).toEqual(['later', 'add'])
    expect(d.querySelector('h1')!.textContent).toBe('Sign in faster with a passkey')
  })

  it('busy: the primary shows "Adding…" and Not now is disabled', async () => {
    const d = await dom(<AddPasskey action="/passkeys/new" csrf="gallery" busy />)
    const [later, add] = Array.from(d.querySelectorAll('button'))
    expect(later!.hasAttribute('disabled')).toBe(true)
    expect(add!.getAttribute('aria-busy')).toBe('true')
    expect(add!.textContent).toBe('Adding…')
  })
})

describe('6d · TwoStep', () => {
  const p: TwoStepProps = { workspace: 'Drivly', action: '/login/two-step/mfa_1', csrf: 'gallery' }

  it('posts six labelled code boxes to /login/two-step/:flow with CSRF', async () => {
    const d = await dom(<TwoStep {...p} />)
    expectForms(d, /^\/login\/two-step\/[^/]+$/)
    const boxes = Array.from(d.querySelectorAll('input[name=code]'))
    expect(boxes.length).toBe(6)
    expect(boxes.map((b) => b.getAttribute('aria-label'))).toEqual([1, 2, 3, 4, 5, 6].map((n) => `Character ${n} of 6`))
    expect(boxes[0]!.getAttribute('inputmode')).toBe('numeric')
    expect(d.querySelector('[role=group]')!.getAttribute('aria-label')).toBeTruthy()
    expect(d.querySelector('button[type=submit]')!.textContent).toBe('Verify')
  })

  it('D8: no alternate links by default; each shows only when its href is given', async () => {
    const plain = await dom(<TwoStep {...p} />)
    expect(plain.querySelector('.id-footlinks')).toBeNull()
    const passkey = await dom(<TwoStep {...p} passkeyHref="/login/passkey" />)
    expect(Array.from(passkey.querySelectorAll('.id-footlinks a')).map((a) => a.textContent)).toEqual(['Use a passkey instead'])
    const both = await dom(<TwoStep {...p} passkeyHref="/login/passkey" recoveryHref="/login/recovery" />)
    expect(Array.from(both.querySelectorAll('.id-footlinks a')).map((a) => a.textContent)).toEqual(['Use a passkey instead', 'Use a recovery code'])
  })

  it('wrong code: the boxes are invalid and described by the error', async () => {
    const d = await dom(<TwoStep {...p} error="That code didn’t work." />)
    const err = d.querySelector('.id-inline-error')!
    expect(err.textContent).toBe('That code didn’t work.')
    for (const box of Array.from(d.querySelectorAll('input[name=code]'))) {
      expect(box.getAttribute('aria-invalid')).toBe('true')
      expect(box.getAttribute('aria-describedby')).toBe(err.getAttribute('id'))
    }
  })

  it('escapes request data', async () => {
    const out = await html(<TwoStep {...p} workspace={EVIL} error={EVIL} />)
    expect(out).not.toContain(EVIL)
  })
})

describe('7 · ErrorPage', () => {
  const app: ErrorPageProps = {
    tile: { kind: 'monogram', text: 'sb' },
    title: 'We stopped this sign-in',
    reason: 'api.sb tried to send you to a page it never registered.',
    details: { open: true, error: 'invalid_request', reason: 'redirect_uri not registered', client: 'cid_1', redirect: 'https://evil.example/cb', request: 'req_7Hk2Qp9w' },
    actions: { primary: { label: 'Go to id.org.ai', href: '/' } },
  }

  it('7a: details open with every value, a labelled copy of exactly those values, and no form', async () => {
    const d = await dom(<ErrorPage {...app} />)
    expect(d.querySelectorAll('h1').length).toBe(1)
    expect(d.querySelector('details')!.hasAttribute('open')).toBe(true)
    const keys = Array.from(d.querySelectorAll('.id-kv__key')).map((k) => k.textContent)
    expect(keys).toEqual(['Error', 'Reason', 'Client', 'Redirect', 'Request'])
    const copy = d.querySelector('button[data-js=copy]')!
    expect(copy.getAttribute('type')).toBe('button')
    expect(copy.textContent).toContain('Copy details')
    expect(copy.getAttribute('data-value')).toBe(detailsText(app.details!))
    expect(copy.getAttribute('data-value')).toContain('Request: req_7Hk2Qp9w')
    expect(d.querySelector('form')).toBeNull()
    expect(d.querySelector('a.id-btn')!.getAttribute('href')).toBe('/')
  })

  it('7a: never renders the rejected redirect_uri as a link', async () => {
    const d = await dom(<ErrorPage {...app} />)
    for (const a of Array.from(d.querySelectorAll('a'))) expect(a.getAttribute('href') ?? '').not.toContain('evil.example')
    for (const f of Array.from(d.querySelectorAll('form'))) expect(f.getAttribute('action') ?? '').not.toContain('evil.example')
    expect(d.body.textContent).toContain('https://evil.example/cb')
  })

  it('7a copied: the check and "Copied" are announced', async () => {
    const d = await dom(<ErrorPage {...app} copied />)
    const copy = d.querySelector('button[data-js=copy]')!
    expect(copy.hasAttribute('data-copied')).toBe(true)
    expect(copy.querySelector('[role=status]')!.textContent).toBe('Copied')
  })

  it('escapes every piece of request data, details included', async () => {
    const out = await html(
      <ErrorPage
        {...app}
        title={EVIL}
        reason={EVIL}
        details={{ error: EVIL, reason: EVIL, client: EVIL, redirect: `javascript:alert(1)//${EVIL}`, request: EVIL }}
      />,
    )
    expect(out).not.toContain(EVIL)
    expect(out).not.toMatch(/href="javascript:/)
  })

  it('7b: a posting primary submits a CSRF form; the secondary stays a link', async () => {
    const d = await dom(
      <ErrorPage
        tile={{ kind: 'icon', icon: 'clock' }}
        title="This link has expired"
        reason="Sign-in links last 10 minutes and work once."
        actions={{
          secondary: { label: 'Sign in another way', href: '/login' },
          primary: { label: 'Send a new code', href: '/login/code/flw_1/resend', icon: 'mail', post: true },
        }}
        csrf="gallery"
      />,
    )
    expectForms(d, /^\/login\/code\/[^/]+\/resend$/)
    expect(d.querySelector('button[type=submit]')!.textContent).toBe('Send a new code')
    expect(d.querySelector('a.id-btn')!.getAttribute('href')).toBe('/login')
    expect(d.querySelector('details')).toBeNull()
  })

  const blocked: ErrorPageProps = {
    tile: { kind: 'monogram', text: 'Cx' },
    title: 'Drivly hasn’t approved Codex',
    reason: 'Your workspace only allows apps an admin has approved.',
    actions: {
      secondary: { label: 'Use another workspace', href: '/workspace/choose' },
      primary: { label: 'Request access', href: '/admin/requests', post: true },
    },
    footnote: { icon: 'send', text: 'Admins get an email and can approve in one click.' },
    csrf: 'gallery',
    fields: { client: 'codex', org: 'org_drivly' },
    accessRequest: {},
  }

  it('7c: posts client, org and an optional note (max 500) to /admin/requests', async () => {
    const d = await dom(<ErrorPage {...blocked} />)
    expectForms(d, /^\/admin\/requests$/)
    expect(d.querySelector('input[name=client]')!.getAttribute('value')).toBe('codex')
    expect(d.querySelector('input[name=org]')!.getAttribute('value')).toBe('org_drivly')
    const note = d.querySelector('textarea[name=note]')!
    expect(note.getAttribute('maxlength')).toBe('500')
    expect(note.hasAttribute('required')).toBe(false)
    expect(d.querySelector(`label[for="${note.getAttribute('id')}"]`)!.textContent).toBe('Note to your admins (optional)')
    expect(d.querySelector('.id-footnote')!.textContent).toBe('Admins get an email and can approve in one click.')
  })

  it('7c request sent: shown in place, announced, the note quoted back (escaped)', async () => {
    const out = await html(
      <ErrorPage {...blocked} title="Request sent" actions={{ primary: { label: 'Use another workspace', href: '/workspace/choose' } }} accessRequest={{ sent: true, note: EVIL }} />,
    )
    expect(out).not.toContain(EVIL)
    const d = new DOMParser().parseFromString(out, 'text/html')
    expect(d.querySelector('textarea')).toBeNull()
    expect(d.querySelector('form')).toBeNull()
    expect(d.querySelector('.id-footnote')).toBeNull()
    expect(d.querySelector('main [data-status]')!.textContent).toBe('Request sent')
    expect(d.querySelector('.id-quote__text')!.textContent).toBe(EVIL)
  })
})
