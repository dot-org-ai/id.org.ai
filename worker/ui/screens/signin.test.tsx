/**
 * Accessibility and form contracts for the sign-in screens (1a–1g,
 * docs/product-update/spec/screens.md#1-sign-in): one h1, every control
 * labelled, forms posting to their route with a CSRF field, a status region
 * where state changes, and request data escaped.
 */
import { describe, expect, it } from 'vitest'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { renderHtml } from '../render'
import { EmailCode, type EmailCodeProps } from './EmailCode'
import { FirstRun, type FirstRunProps } from './FirstRun'
import { LinkAccount, type LinkAccountProps } from './LinkAccount'
import { ProviderFallback, type ProviderFallbackProps } from './ProviderFallback'
import { SignIn, type SignInProps } from './SignIn'
import { Sso, type SsoProps } from './Sso'

async function dom(el: JSX.Element): Promise<Document> {
  const html = await renderHtml(el, { title: 't' })
  return new DOMParser().parseFromString(html, 'text/html')
}

const text = (el: Element | null | undefined) => (el?.textContent ?? '').replace(/\s+/g, ' ').trim()

/** Text of each element-separated run, joined by a space ("GitHub" + "Last used" → "GitHub Last used"). */
function leaves(el: Element | null | undefined): string {
  if (!el) return ''
  const out: string[] = []
  const walk = (n: Node) => {
    if (n.nodeType === 3) out.push(n.textContent ?? '')
    else for (const c of n.childNodes) walk(c)
  }
  walk(el)
  return out
    .map((t) => t.trim())
    .filter(Boolean)
    .join(' ')
}

/** Every visible input has a <label for>, or an aria-label; every button and link has a name. */
function expectLabelled(doc: Document): void {
  for (const input of doc.querySelectorAll('input:not([type="hidden"]), select, textarea')) {
    const id = input.getAttribute('id')
    const label = id ? doc.querySelector(`label[for="${id}"]`) : null
    expect(text(label) || input.getAttribute('aria-label'), `control ${input.outerHTML}`).toBeTruthy()
  }
  for (const el of doc.querySelectorAll('button, a')) {
    expect(text(el) || el.getAttribute('aria-label'), `name for ${el.outerHTML}`).toBeTruthy()
  }
}

function expectOneH1(doc: Document, title: string): void {
  const h1s = doc.querySelectorAll('h1')
  expect(h1s.length).toBe(1)
  expect(text(h1s[0])).toBe(title)
}

function expectPostsWithCsrf(form: Element | null, action: string): void {
  expect(form).not.toBeNull()
  expect(form!.getAttribute('method')).toBe('post')
  expect(form!.getAttribute('action')).toBe(action)
  const csrf = form!.querySelector('input[name="csrf"]')
  expect(csrf?.getAttribute('type')).toBe('hidden')
  expect(csrf?.getAttribute('value')).toBe('tok')
}

const HOSTILE = '"><script>alert(1)</script><img src=x onerror=alert(1)>'

function expectEscaped(doc: Document, html: string): void {
  expect(doc.querySelector('script:not([src])')).toBeNull()
  expect(doc.querySelector('img[onerror]')).toBeNull()
  expect(html).not.toContain('<script>alert(1)</script>')
}

const app = { name: 'headless.ly', tile: { kind: 'monogram' as const, text: 'h' } }

// ── 1a / 1g ────────────────────────────────────────────────────────────────

const signIn: SignInProps = {
  app,
  action: '/login/email',
  csrf: 'tok',
  continueUrl: 'https://headless.ly/cb',
  providers: [
    { provider: 'github', href: '/login?provider=GitHubOAuth' },
    { provider: 'google', href: '/login?provider=GoogleOAuth' },
    { provider: 'microsoft', href: '/login?provider=authkit' },
    { provider: 'apple', href: '/login?provider=authkit' },
  ],
  lastUsedProvider: 'github',
  passkey: { href: '/login?provider=authkit' },
}

describe('1a sign in', () => {
  it('one h1, labelled controls, the email form posts to /login/email with CSRF and continue', async () => {
    const doc = await dom(<SignIn {...signIn} />)
    expectOneH1(doc, 'Sign in')
    expectLabelled(doc)
    const form = doc.querySelector('form')
    expectPostsWithCsrf(form, '/login/email')
    expect(form!.querySelector('input[name="continue"]')?.getAttribute('value')).toBe('https://headless.ly/cb')
    const email = form!.querySelector('input[name="email"]')
    expect(email?.getAttribute('type')).toBe('email')
    expect(email?.getAttribute('autocomplete')).toBe('email')
    const submit = form!.querySelector('button')
    expect(submit?.getAttribute('type')).toBe('submit')
    expect(text(submit)).toBe('Continue with email')
    expect(doc.querySelector('[role="status"]')).not.toBeNull()
  })

  it('providers and the passkey are links outside the form; only the last used provider has the pill', async () => {
    const doc = await dom(<SignIn {...signIn} />)
    const providers = [...doc.querySelectorAll('.id-providers a')]
    expect(providers.map((a) => a.getAttribute('href'))).toEqual(signIn.providers.map((p) => p.href))
    expect(providers.map((a) => leaves(a))).toEqual(['GitHub Last used', 'Google', 'Microsoft', 'Apple'])
    expect(providers.every((a) => !a.closest('form'))).toBe(true)
    const passkey = [...doc.querySelectorAll('a')].find((a) => text(a) === 'Sign in with a passkey')
    expect(passkey?.getAttribute('href')).toBe('/login?provider=authkit')
    expect(passkey?.hasAttribute('data-on')).toBe(false)
    const webauthn = await dom(<SignIn {...signIn} passkey={{ href: '/login?provider=authkit', webauthn: true }} />)
    expect([...webauthn.querySelectorAll('a')].find((a) => text(a) === 'Sign in with a passkey')?.getAttribute('data-on')).toBe('passkey')
  })

  it('each provider shows its official mark, hidden from assistive tech (the name is the label)', async () => {
    const doc = await dom(<SignIn {...signIn} />)
    const providers = [...doc.querySelectorAll('.id-providers a')]
    expect(providers.map((a) => a.querySelector('svg.id-provider__mark')?.getAttribute('data-provider'))).toEqual(['github', 'google', 'microsoft', 'apple'])
    for (const a of providers) {
      const mark = a.querySelector('svg.id-provider__mark')!
      expect(mark.getAttribute('aria-hidden')).toBe('true')
      expect(mark.getAttribute('width')).toBe('18')
      expect(mark.getAttribute('height')).toBe('18')
    }
    expect(doc.querySelector('.id-provider__slot')).toBeNull()
  })

  it('sign-in uses the narrow column (owner direction, 2026-10-01)', async () => {
    const doc = await dom(<SignIn {...signIn} />)
    expect(doc.querySelector('.id-column')?.classList.contains('id-column--narrow')).toBe(true)
    const branded = await dom(<SignIn {...signIn} brand={{ name: 'headless.ly', monogram: 'h' }} />)
    expect(branded.querySelector('.id-column')?.classList.contains('id-column--narrow')).toBe(true)
  })

  it('an email error is linked to the field and marks it invalid', async () => {
    const doc = await dom(<SignIn {...signIn} email="bryant@driv" emailError="Enter a full email address." />)
    const input = doc.querySelector('input[name="email"]')!
    expect(input.getAttribute('aria-invalid')).toBe('true')
    expect(input.getAttribute('value')).toBe('bryant@driv')
    const err = doc.getElementById(input.getAttribute('aria-describedby')!)
    expect(text(err)).toBe('Enter a full email address.')
  })

  it('escapes request data (login_hint, app name)', async () => {
    const el = <SignIn {...signIn} email={HOSTILE} app={{ name: HOSTILE, tile: { kind: 'monogram', text: 'x' } }} />
    const html = await renderHtml(el, { title: 't' })
    const doc = new DOMParser().parseFromString(html, 'text/html')
    expectEscaped(doc, html)
    expect(doc.querySelector('input[name="email"]')?.getAttribute('value')).toBe(HOSTILE)
  })
})

describe('1g branded sign in', () => {
  it('shows the app brand in the header, "Secured by id.org.ai" in the footer, and the app tile alone', async () => {
    const doc = await dom(<SignIn {...signIn} brand={{ name: 'headless.ly', monogram: 'h' }} />)
    expectOneH1(doc, 'Sign in to headless.ly')
    expectLabelled(doc)
    expect(leaves(doc.querySelector('header'))).toBe('h headless.ly')
    expect(leaves(doc.querySelector('footer'))).toBe('Secured by id.org.ai')
    expect(doc.querySelector('footer a')).toBeNull()
    expect(doc.querySelector('[data-js="connector"]')).toBeNull()
    expectPostsWithCsrf(doc.querySelector('form'), '/login/email')
  })
})

// ── 1b ─────────────────────────────────────────────────────────────────────

const code: EmailCodeProps = {
  app,
  email: 'bryant@driv.ly',
  expiresInMinutes: 10,
  action: '/login/code/flw_1',
  resendAction: '/login/code/flw_1/resend',
  csrf: 'tok',
  differentEmailHref: '/login',
  resendIn: 42,
}

describe('1b email code', () => {
  it('one h1; six labelled boxes in a group; Verify posts to /login/code/:flow with CSRF', async () => {
    const doc = await dom(<EmailCode {...code} code="4829" />)
    expectOneH1(doc, 'Check your email')
    expectLabelled(doc)
    expect(text(doc.querySelector('.id-desc'))).toBe('We sent a 6-digit code to bryant@driv.ly. It expires in 10 minutes.')
    const form = doc.querySelector('form[data-js="submit"]')
    expectPostsWithCsrf(form, '/login/code/flw_1')
    const group = form!.querySelector('[role="group"]')
    expect(group?.getAttribute('aria-label')).toBe('Enter the 6-digit code')
    const boxes = [...group!.querySelectorAll('input[name="code"]')]
    expect(boxes).toHaveLength(6)
    expect(boxes.map((b) => b.getAttribute('value') ?? '')).toEqual(['4', '8', '2', '9', '', ''])
    expect(boxes.every((b) => b.getAttribute('inputmode') === 'numeric')).toBe(true)
    expect(doc.querySelector('[role="status"]')).not.toBeNull()
  })

  it('Verify is the code form’s default button; Resend belongs to its own form posting to /resend', async () => {
    const doc = await dom(<EmailCode {...code} />)
    const form = doc.querySelector('form[data-js="submit"]')!
    // The first submit button owned by the code form (implicit submission on Enter) is Verify.
    const owned = [...form.querySelectorAll('button[type="submit"]')].filter((b) => !b.hasAttribute('form'))
    expect(text(owned[0])).toBe('Verify')
    const resend = [...doc.querySelectorAll('button')].find((b) => text(b) === 'Resend code')!
    expect(resend.getAttribute('type')).toBe('submit')
    expect(resend.hasAttribute('hidden')).toBe(true)
    expect(resend.hasAttribute('data-countdown-done')).toBe(true)
    const resendForm = doc.getElementById(resend.getAttribute('form')!)
    expect(resendForm?.tagName).toBe('FORM')
    expectPostsWithCsrf(resendForm, '/login/code/flw_1/resend')
    expect(resendForm!.closest('form[data-js="submit"]')).toBeNull()
    const countdown = doc.querySelector('[data-js="countdown"]')
    expect(text(countdown)).toBe('Resend in 0:42')
    expect(countdown?.getAttribute('data-seconds-left')).toBe('42')
    const back = [...doc.querySelectorAll('a')].find((a) => text(a) === 'Use a different email')
    expect(back?.getAttribute('href')).toBe('/login')
  })

  it('the countdown never writes a misleading "expired" message into this page (no [data-status])', async () => {
    const doc = await dom(<EmailCode {...code} />)
    expect(doc.querySelector('[data-status]')).toBeNull()
  })

  it('wrong code: boxes cleared, marked invalid and described by the error', async () => {
    const doc = await dom(<EmailCode {...code} code="4829" error="wrong-code" />)
    const boxes = [...doc.querySelectorAll('input[name="code"]')]
    expect(boxes.every((b) => !b.getAttribute('value'))).toBe(true)
    expect(boxes.every((b) => b.getAttribute('aria-invalid') === 'true')).toBe(true)
    const err = doc.getElementById(boxes[0]!.getAttribute('aria-describedby')!)
    expect(err?.getAttribute('role')).toBe('alert')
    expect(text(err)).toBe('That code didn’t match. Check the email and try again.')
    const verify = [...doc.querySelectorAll('button')].find((b) => text(b) === 'Verify')
    expect(verify?.hasAttribute('disabled')).toBe(false)
  })

  it('too many tries: Verify disabled and "Resend code" offered straight away', async () => {
    const doc = await dom(<EmailCode {...code} error="too-many-tries" />)
    expect(text(doc.querySelector('[role="alert"]'))).toBe('Too many tries. Send a new code to keep going.')
    const verify = [...doc.querySelectorAll('button')].find((b) => text(b) === 'Verify')
    expect(verify?.hasAttribute('disabled')).toBe(true)
    const resend = [...doc.querySelectorAll('button')].find((b) => text(b) === 'Resend code')
    expect(resend?.hasAttribute('hidden')).toBe(false)
    expect(doc.querySelector('[data-js="countdown"]')).toBeNull()
  })

  it('escapes request data', async () => {
    const html = await renderHtml(<EmailCode {...code} email={HOSTILE} code={HOSTILE} />, { title: 't' })
    expectEscaped(new DOMParser().parseFromString(html, 'text/html'), html)
  })
})

// ── 1c ─────────────────────────────────────────────────────────────────────

const sso: SsoProps = {
  app,
  email: 'bryant@northwind.co',
  org: { name: 'Northwind', domain: 'northwind.co' },
  idpName: 'Okta',
  enforced: true,
  continueHref: '/login/sso/start?organization_id=org_1',
  differentEmailHref: '/login',
}

describe('1c SSO', () => {
  it('one h1; continue is a link to the IdP; the lock note shows only when enforced', async () => {
    const doc = await dom(<Sso {...sso} />)
    expectOneH1(doc, 'Northwind uses single sign-on')
    expectLabelled(doc)
    expect(doc.querySelector('form')).toBeNull()
    const links = [...doc.querySelectorAll('.id-card a')]
    expect(links.map((a) => [text(a), a.getAttribute('href')])).toEqual([
      ['Use a different email', '/login'],
      ['Continue with Okta', '/login/sso/start?organization_id=org_1'],
    ])
    expect(leaves(doc.querySelector('.id-orgrow'))).toBe('Northwind Verified domain northwind.co')
    expect(text(doc.querySelector('.id-note'))).toBe('Your admin controls this account. Personal sign-in methods are turned off for it.')
    const open = await dom(<Sso {...sso} enforced={false} />)
    expect(open.querySelector('.id-note')).toBeNull()
  })

  it('escapes request data', async () => {
    const html = await renderHtml(<Sso {...sso} email={HOSTILE} org={{ name: HOSTILE, domain: HOSTILE }} idpName={HOSTILE} />, { title: 't' })
    expectEscaped(new DOMParser().parseFromString(html, 'text/html'), html)
  })
})

// ── 1d ─────────────────────────────────────────────────────────────────────

const firstRun: FirstRunProps = {
  action: '/welcome?continue=%2F',
  csrf: 'tok',
  name: 'Bryant Skarda',
  workspaceName: 'Drivly',
  provider: 'GitHub',
  providerUsername: 'bryant22',
  notYouHref: '/signout?return_url=%2Flogin',
}

describe('1d first run', () => {
  it('one h1; name and workspace labelled and posted to /welcome with CSRF; Not you? links out', async () => {
    const doc = await dom(<FirstRun {...firstRun} />)
    expectOneH1(doc, 'Create your identity')
    expectLabelled(doc)
    const form = doc.querySelector('form')
    expectPostsWithCsrf(form, '/welcome?continue=%2F')
    expect(form!.querySelector('input[name="name"]')?.getAttribute('value')).toBe('Bryant Skarda')
    expect(form!.querySelector('input[name="workspace"]')?.getAttribute('value')).toBe('Drivly')
    expect(text(doc.querySelector('.id-field__aside'))).toBe('From GitHub')
    const ws = form!.querySelector('input[name="workspace"]')!
    expect(text(doc.getElementById(ws.getAttribute('aria-describedby')!))).toBe('A workspace holds your team, apps and agents. Add more anytime.')
    expect(text(doc.querySelector('.id-footnote'))).toBe('Signed in with GitHub as bryant22. Not you?')
    expect(doc.querySelector('.id-footnote a')?.getAttribute('href')).toBe('/signout?return_url=%2Flogin')
    expect(text(form!.querySelector('button[type="submit"]'))).toBe('Create account')
    expect(doc.querySelector('[role="status"]')).not.toBeNull()
    expect(doc.querySelector('[data-js="connector"]')).toBeNull()
  })

  it('new workspace: only the Workspace field, its own title and primary, posting to /workspace/new', async () => {
    const doc = await dom(<FirstRun variant="new-workspace" action="/workspace/new" csrf="tok" backHref="/workspace/choose" />)
    expectOneH1(doc, 'Create a workspace')
    expectLabelled(doc)
    expectPostsWithCsrf(doc.querySelector('form'), '/workspace/new')
    expect(doc.querySelectorAll('input:not([type="hidden"])')).toHaveLength(1)
    expect(doc.querySelector('input[name="workspace"]')).not.toBeNull()
    expect(text(doc.querySelector('button[type="submit"]'))).toBe('Create workspace')
    expect(doc.querySelector('[data-actions] a')?.getAttribute('href')).toBe('/workspace/choose')
  })

  it('escapes request data', async () => {
    const html = await renderHtml(<FirstRun {...firstRun} name={HOSTILE} workspaceName={HOSTILE} providerUsername={HOSTILE} />, { title: 't' })
    expectEscaped(new DOMParser().parseFromString(html, 'text/html'), html)
  })
})

// ── 1e ─────────────────────────────────────────────────────────────────────

const link: LinkAccountProps = {
  app,
  email: 'bryant@driv.ly',
  existingProvider: 'github',
  newProvider: 'google',
  identity: { name: 'Bryant Skarda', email: 'bryant@driv.ly' },
  continueHref: '/login?provider=GitHubOAuth&link=flw_1',
  differentEmailHref: '/login',
}

describe('1e link account', () => {
  it('one h1; names both providers; continue with the existing provider is a link', async () => {
    const doc = await dom(<LinkAccount {...link} />)
    expectOneH1(doc, 'You already have an account')
    expectLabelled(doc)
    expect(text(doc.querySelector('.id-desc'))).toBe('bryant@driv.ly signs in with GitHub. Sign in with GitHub once and we’ll add Google to the same account.')
    expect(leaves(doc.querySelector('.id-who'))).toBe('BS Bryant Skarda bryant@driv.ly · signs in with GitHub')
    const actions = [...doc.querySelectorAll('[data-actions] a')]
    expect(actions.map((a) => [text(a), a.getAttribute('href')])).toEqual([
      ['Use a different email', '/login'],
      ['Continue with GitHub', '/login?provider=GitHubOAuth&link=flw_1'],
    ])
    const mark = actions[1]!.querySelector('svg.id-provider__mark')
    expect(mark?.getAttribute('data-provider')).toBe('github')
    expect(mark?.getAttribute('aria-hidden')).toBe('true')
    expect(text(doc.querySelector('.id-note'))).toBe('We only link accounts after you prove you own both. Nothing is merged until then.')
  })

  it('escapes request data', async () => {
    const html = await renderHtml(<LinkAccount {...link} email={HOSTILE} identity={{ name: HOSTILE, email: HOSTILE }} />, { title: 't' })
    expectEscaped(new DOMParser().parseFromString(html, 'text/html'), html)
  })
})

// ── 1f ─────────────────────────────────────────────────────────────────────

const fallback: ProviderFallbackProps = {
  app,
  provider: 'microsoft',
  reason: 'Northwind’s sign-in policy blocks apps it hasn’t pre-approved.',
  email: 'bryant@northwind.co',
  emailLabel: 'Work email',
  action: '/login/email',
  csrf: 'tok',
  continueUrl: 'https://headless.ly/cb',
  retryHref: '/login?provider=MicrosoftOAuth',
}

describe('1f provider fallback', () => {
  it('one h1; the email form posts to /login/email with CSRF; retry is a link; the connector fails', async () => {
    const doc = await dom(<ProviderFallback {...fallback} />)
    expectOneH1(doc, 'Microsoft sign-in didn’t finish')
    expectLabelled(doc)
    expect(text(doc.querySelector('.id-desc'))).toBe('Northwind’s sign-in policy blocks apps it hasn’t pre-approved. Verify with an emailed code instead.')
    const form = doc.querySelector('form')
    expectPostsWithCsrf(form, '/login/email')
    expect(form!.querySelector('input[name="continue"]')?.getAttribute('value')).toBe('https://headless.ly/cb')
    expect(text(doc.querySelector('label[for="fallback-email"]'))).toBe('Work email')
    expect(form!.querySelector('input[name="email"]')?.getAttribute('value')).toBe('bryant@northwind.co')
    expect(text(form!.querySelector('button[type="submit"]'))).toBe('Email me a code')
    expect(doc.querySelector('[data-actions] a')?.getAttribute('href')).toBe('/login?provider=MicrosoftOAuth')
    expect(doc.querySelector('[data-js="connector"]')?.getAttribute('data-state')).toBe('fail')
    expect(doc.querySelector('[role="status"]')).not.toBeNull()
    expect(doc.querySelector('details')).toBeNull()
  })

  it('developer details sit in a closed disclosure with a copy action', async () => {
    const doc = await dom(<ProviderFallback {...fallback} details={{ items: [{ k: 'Request', v: 'req_1', mono: true }], copy: 'request=req_1' }} />)
    const details = doc.querySelector('details')!
    expect(details.hasAttribute('open')).toBe(false)
    expect(text(details.querySelector('summary'))).toBe('Developer details')
    expect(details.querySelector('[data-js="copy"]')?.getAttribute('data-value')).toBe('request=req_1')
  })

  it('escapes request data', async () => {
    const html = await renderHtml(<ProviderFallback {...fallback} reason={HOSTILE} email={HOSTILE} />, { title: 't' })
    expectEscaped(new DOMParser().parseFromString(html, 'text/html'), html)
  })
})
