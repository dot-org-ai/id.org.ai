import { describe, expect, it } from 'vitest'
import { emailsFixtures } from '../gallery/fixtures/emails'
import { renderInvitationEmail, type InvitationEmailProps } from './Invitation'
import { EMAIL_COLORS, EMAIL_FOOTER, groupCode, oneLine, type RenderedEmail } from './layout'
import { renderSignInAlertEmail, type SignInAlertEmailProps } from './SignInAlert'
import { renderSignInCodeEmail, type SignInCodeEmailProps } from './SignInCode'

const code: SignInCodeEmailProps = { code: '482913', app: 'headless.ly', browser: 'Chrome', os: 'macOS', location: 'Miami, FL' }
const invitation: InvitationEmailProps = {
  inviter: 'Nathan Clevenger',
  email: 'bryant@driv.ly',
  workspace: '.do Industries',
  role: 'Admin',
  acceptUrl: 'https://id.org.ai/invite/inv_123',
}
const alert: SignInAlertEmailProps = {
  app: 'auto.dev CLI',
  os: 'macOS',
  location: 'Miami, FL',
  when: 'Oct 1, 1:52 PM EDT',
  email: 'bryant@driv.ly',
  revokeUrl: 'https://id.org.ai/sessions/revoke/tok_1',
}

const parse = (html: string) => new DOMParser().parseFromString(html, 'text/html')
const squash = (s: string | null | undefined) => (s ?? '').replace(/\s+/g, ' ').trim()

/** Contracts every email meets: a mail-safe, self-contained, light document. */
function expectMailSafe(m: RenderedEmail) {
  expect(m.html.startsWith('<!doctype html><html lang="en"><head><meta charset="utf-8"/>')).toBe(true)
  const doc = parse(m.html)
  expect(doc.title).toBe(m.subject)
  // No scripts, no external stylesheets, no classes to depend on: inline CSS only.
  expect(doc.querySelectorAll('script, link').length).toBe(0)
  expect(m.html).not.toMatch(/<script|javascript:|\son\w+=/i)
  // Mail clients don't support oklch(); colours are the hex palette.
  expect(m.html).not.toContain('oklch(')
  for (const hex of m.html.match(/#[0-9a-f]{3,8}\b/gi) ?? []) expect(Object.values(EMAIL_COLORS)).toContain(hex.toLowerCase())
  // Light only; no auto-linked dates or places.
  expect(doc.querySelector('meta[name="color-scheme"]')?.getAttribute('content')).toBe('light')
  expect(doc.querySelector('meta[name="format-detection"]')?.getAttribute('content')).toContain('date=no')
  // Layout tables are presentational.
  const tables = [...doc.querySelectorAll('table')]
  expect(tables.length).toBeGreaterThan(1)
  for (const t of tables) expect(t.getAttribute('role')).toBe('presentation')
  // Geist from absolute production URLs.
  expect(m.html).toContain("@font-face{font-family:'Geist';src:url(https://id.org.ai/fonts/geist/Geist-Variable.woff2) format('woff2');font-weight:100 900")
  expect(m.html).toContain("@font-face{font-family:'Geist Mono';src:url(https://id.org.ai/fonts/geist/GeistMono-Variable.woff2) format('woff2');font-weight:100 900")
  // One heading; the brand line and the footer line.
  expect(doc.querySelectorAll('h1').length).toBe(1)
  expect(doc.querySelector('svg')?.getAttribute('aria-hidden')).toBe('true')
  expect(squash(doc.body.textContent)).toContain(EMAIL_FOOTER)
  // The text part ends with the footer after the signature delimiter.
  expect(m.text.endsWith(`\n\n-- \n${EMAIL_FOOTER}\n`)).toBe(true)
  return doc
}

describe('8a sign-in code email', () => {
  const m = renderSignInCodeEmail(code)

  it('puts the whole code in the subject and comes from no-reply', () => {
    expect(m.subject).toBe('Your id.org.ai code: 482913')
    expect(m.from).toEqual({ name: 'id.org.ai', email: 'no-reply@id.org.ai' })
  })

  it('renders the card: heading, grouped code, app, expiry, request line', () => {
    const doc = expectMailSafe(m)
    expect(doc.querySelector('h1')?.textContent).toBe('Your sign-in code')
    const paras = [...doc.querySelectorAll('p')].map((p) => p.textContent)
    expect(paras).toEqual([
      'Enter this code to sign in to headless.ly. It expires in 10 minutes and works once.',
      'Didn’t try to sign in? Ignore this email. Someone may have typed your address by mistake; nothing happens without the code.',
      'Requested from Chrome on macOS · Miami, FL',
    ])
    expect(m.html).toContain('letter-spacing:0.18em;color:#18181d">482 913</td>')
    expect(m.html).toContain('Enter this code to sign in to <span style="color:#18181d;font-weight:500">headless.ly</span>. It expires')
  })

  it('has the plain-text part', () => {
    expect(m.text).toBe(
      [
        'Your sign-in code',
        '',
        '482913',
        '',
        'Enter this code to sign in to headless.ly. It expires in 10 minutes and works once.',
        '',
        'Didn’t try to sign in? Ignore this email. Someone may have typed your address by mistake; nothing happens without the code.',
        '',
        'Requested from Chrome on macOS · Miami, FL',
        '',
        '-- ',
        'id.org.ai · Identity for people and agents · You’re getting this because of activity on your account.',
        '',
      ].join('\n'),
    )
  })

  it('drops the location when it is unknown and pluralises the expiry', () => {
    const n = renderSignInCodeEmail({ ...code, location: undefined, expiresInMinutes: 1 })
    expect(n.text).toContain('\n\nRequested from Chrome on macOS\n\n')
    expect(n.text).toContain('It expires in 1 minute and works once.')
  })
})

describe('8b invitation email', () => {
  const m = renderInvitationEmail(invitation)

  it('has the subject and the inviter in the sender name', () => {
    expect(m.subject).toBe('Nathan Clevenger invited you to .do Industries')
    expect(m.from).toEqual({ name: 'Nathan Clevenger via id.org.ai', email: 'no-reply@id.org.ai' })
  })

  it('renders the card with an Accept invitation link to /invite/:token', () => {
    const doc = expectMailSafe(m)
    expect(doc.querySelector('h1')?.textContent).toBe('Join .do Industries')
    expect([...doc.querySelectorAll('p')].map((p) => p.textContent)).toEqual([
      'Nathan Clevenger invited bryant@driv.ly to the .do Industries workspace as an Admin.',
      'The invite expires in 7 days. If you weren’t expecting it, you can ignore this email.',
    ])
    const links = [...doc.querySelectorAll('a')]
    expect(links.length).toBe(1)
    expect(links[0].textContent).toBe('Accept invitation')
    expect(links[0].getAttribute('href')).toBe('https://id.org.ai/invite/inv_123')
    expect(m.html).toContain('<td bgcolor="#18181d" style="background:#18181d;border-radius:10px"><a href="https://id.org.ai/invite/inv_123"')
  })

  it('has the plain-text part', () => {
    expect(m.text).toBe(
      [
        'Join .do Industries',
        '',
        'Nathan Clevenger invited bryant@driv.ly to the .do Industries workspace as an Admin.',
        '',
        'Accept invitation: https://id.org.ai/invite/inv_123',
        '',
        'The invite expires in 7 days. If you weren’t expecting it, you can ignore this email.',
        '',
        '-- ',
        EMAIL_FOOTER,
        '',
      ].join('\n'),
    )
  })

  it('uses "a" before consonant roles and a singular day', () => {
    const n = renderInvitationEmail({ ...invitation, role: 'Member', expiresInDays: 1 })
    expect(n.text).toContain('workspace as a Member.')
    expect(n.text).toContain('The invite expires in 1 day.')
  })

  it('refuses a non-http accept link', () => {
    expect(() => renderInvitationEmail({ ...invitation, acceptUrl: 'javascript:alert(1)' })).toThrow(/http/)
  })
})

describe('8c new sign-in alert', () => {
  const m = renderSignInAlertEmail(alert)

  it('has the subject and comes from security@', () => {
    expect(m.subject).toBe('New sign-in: auto.dev CLI on macOS')
    expect(m.from).toEqual({ name: 'id.org.ai', email: 'security@id.org.ai' })
  })

  it('renders the key/value box and the revoke link', () => {
    const doc = expectMailSafe(m)
    expect(doc.querySelector('h1')?.textContent).toBe('New sign-in to your account')
    expect([...doc.querySelectorAll('p')].map((p) => p.textContent)).toEqual(['auto.dev CLI was just signed in as bryant@driv.ly.', 'If this was you, there’s nothing to do.'])
    const rows = [...doc.querySelectorAll('tr')].filter((tr) => tr.children.length === 2).map((tr) => [...tr.children].map((td) => td.textContent))
    expect(rows).toEqual([
      ['App', 'auto.dev CLI'],
      ['Device', 'macOS'],
      ['Where', 'Miami, FL'],
      ['When', 'Oct 1, 1:52 PM EDT'],
    ])
    const links = [...doc.querySelectorAll('a')]
    expect(links.length).toBe(1)
    expect(links[0].textContent).toBe('This wasn’t me')
    expect(links[0].getAttribute('href')).toBe('https://id.org.ai/sessions/revoke/tok_1')
  })

  it('has the plain-text part', () => {
    expect(m.text).toBe(
      [
        'New sign-in to your account',
        '',
        'auto.dev CLI was just signed in as bryant@driv.ly.',
        '',
        'App: auto.dev CLI',
        'Device: macOS',
        'Where: Miami, FL',
        'When: Oct 1, 1:52 PM EDT',
        '',
        'If this was you, there’s nothing to do.',
        '',
        'This wasn’t me: https://id.org.ai/sessions/revoke/tok_1',
        '',
        '-- ',
        EMAIL_FOOTER,
        '',
      ].join('\n'),
    )
  })
})

describe('request data', () => {
  const hostile = '<script>alert(1)</script>"><img src=x onerror=alert(1)>'

  it('is HTML-escaped in every template', () => {
    const all = [
      renderSignInCodeEmail({ ...code, app: hostile, browser: hostile, os: hostile, location: hostile }),
      renderInvitationEmail({ ...invitation, inviter: hostile, email: hostile, workspace: hostile, role: hostile }),
      renderSignInAlertEmail({ ...alert, app: hostile, os: hostile, location: hostile, when: hostile, email: hostile }),
    ]
    for (const m of all) {
      expect(m.html).not.toContain('<script>')
      expect(m.html).not.toContain('<img')
      expect(m.html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;&quot;&gt;&lt;img src=x onerror=alert(1)&gt;')
      const doc = parse(m.html)
      expect(doc.querySelectorAll('script, img').length).toBe(0)
      expect(doc.body.textContent).toContain(hostile)
    }
  })

  it('cannot break the subject, sender or text part onto new lines', () => {
    const m = renderInvitationEmail({ ...invitation, inviter: 'Eve\r\nBcc: victim@example.com', workspace: 'Acme\n\nAccept invitation: https://evil.example' })
    expect(m.subject).toBe('Eve Bcc: victim@example.com invited you to Acme Accept invitation: https://evil.example')
    expect(m.from.name).not.toMatch(/[\r\n]/)
    expect(m.text.split('\n').filter((l) => l.startsWith('Accept invitation:'))).toEqual(['Accept invitation: https://id.org.ai/invite/inv_123'])
    expect(oneLine(' a b\tc  d ')).toBe('a b c d')
  })
})

describe('helpers and options', () => {
  it('groups the code in threes', () => {
    expect(groupCode('482913')).toBe('482 913')
    expect(groupCode('12345678')).toBe('123 456 78')
  })

  it('loads fonts from fontBase', () => {
    const m = renderSignInCodeEmail(code, { fontBase: '' })
    expect(m.html).toContain('src:url(/fonts/geist/Geist-Variable.woff2)')
    expect(m.html).not.toContain('https://id.org.ai/fonts')
    expect(renderSignInCodeEmail(code, { fontBase: 'https://cdn.example/' }).html).toContain('src:url(https://cdn.example/fonts/geist/Geist-Variable.woff2)')
    expect(() => renderSignInCodeEmail(code, { fontBase: 'javascript:x' })).toThrow(/http/)
  })
})

describe('gallery previews', () => {
  it('render the inbox frame and the template as a whole document', async () => {
    const cases: [string, string, string][] = [
      ['8a-email-sign-in-code', 'id.org.ai <no-reply@id.org.ai>', 'Your id.org.ai code: 482913'],
      ['8b-email-invitation', 'Nathan Clevenger via id.org.ai <no-reply@id.org.ai>', 'Nathan Clevenger invited you to .do Industries'],
      ['8c-email-sign-in-alert', 'id.org.ai <security@id.org.ai>', 'New sign-in: auto.dev CLI on macOS'],
    ]
    for (const [slug, from, subject] of cases) {
      const f = emailsFixtures[slug]
      expect(f.document).toBe('email')
      const html = String(await f.default.render())
      expect(html.startsWith('<html lang="en">')).toBe(true)
      expect(html).toContain('src:url(/fonts/geist/Geist-Variable.woff2)')
      const doc = parse('<!doctype html>' + html)
      const header = doc.body.firstElementChild?.firstElementChild
      expect([...(header?.children ?? [])].map((line) => line.textContent)).toEqual([`From ${from}`, `Subject ${subject}`])
      expect(doc.querySelectorAll('script').length).toBe(0)
    }
  })
})
