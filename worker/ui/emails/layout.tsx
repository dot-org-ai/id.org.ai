/**
 * Email layout (docs/product-update/spec/emails.md): the shared card, its blocks
 * and the footer line, plus the document every email ships in.
 *
 * Mail clients never see ui.css, so emails are the one place inline styles are
 * required. They are light, built from tables (role="presentation"), use the hex
 * palette (mail clients don't support oklch()) and load Geist from an absolute
 * URL with system fallbacks. Spacing the mocks do with flex `gap` is padding on
 * table rows, so the box model (and the gallery's pixel diff) is the mock's.
 * Every email also has a plain-text part.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { OrgMark } from '../components/OrgMark'

/** Production origin for the Geist font files. The gallery passes '' (same origin). */
export const EMAIL_FONT_BASE = 'https://id.org.ai'

/** spec/emails.md#palette: the sRGB equivalents of the mocks' oklch colours. */
export const EMAIL_COLORS = {
  page: '#f3f3f5',
  card: '#ffffff',
  text: '#18181d',
  secondary: '#4c4c52',
  tertiary: '#68686f',
  line: '#dedee0',
} as const

export const EMAIL_FONT = "'Geist', -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
export const EMAIL_MONO = "'Geist Mono', ui-monospace, 'SF Mono', Menlo, Consolas, monospace"

export const NO_REPLY = 'no-reply@id.org.ai'
export const SECURITY_SENDER = 'security@id.org.ai'

/** The footer line under every card, in HTML and text. */
export const EMAIL_FOOTER = 'id.org.ai · Identity for people and agents · You’re getting this because of activity on your account.'

export interface EmailSender {
  /** Display name, for example "id.org.ai" or "Nathan Clevenger via id.org.ai". */
  name: string
  email: string
}

/** What a template builds; `renderEmail` turns it into the message, the gallery into a preview. */
export interface EmailParts {
  from: EmailSender
  subject: string
  /** The template: the white card plus the footer line. */
  content: JSX.Element
  text: string
}

export interface RenderedEmail {
  from: EmailSender
  subject: string
  html: string
  text: string
}

export interface EmailRenderOptions {
  /** Origin the Geist files load from (default https://id.org.ai). '' loads them from the same origin. */
  fontBase?: string
}

const C = EMAIL_COLORS

/**
 * One line of request data: control characters (CR/LF included) become spaces, so a
 * name can't inject a header into the subject or fake extra lines in the text part.
 */
export function oneLine(value: string): string {
  let out = ''
  for (const ch of value) {
    const c = ch.codePointAt(0) ?? 0
    out += c < 0x20 || c === 0x7f || c === 0x2028 || c === 0x2029 ? ' ' : ch
  }
  return out.replace(/ {2,}/g, ' ').trim()
}

/** Links in emails are absolute http(s) URLs built by the server; anything else is a bug. */
export function httpUrl(url: string): string {
  const u = new URL(url)
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error(`email link must be http(s): ${u.protocol}`)
  return u.href
}

/** The plain-text part: blocks separated by a blank line, then the signature delimiter and footer. */
export function emailText(blocks: string[]): string {
  return [...blocks, `-- \n${EMAIL_FOOTER}`].join('\n\n') + '\n'
}

/** `@font-face` for Geist and Geist Mono, from the origin `base` (absolute in mail; '' = same origin, the gallery). */
export function EmailFonts({ base }: { base: string }): JSX.Element {
  const origin = base === '' ? '' : new URL(httpUrl(base)).origin
  const face = (family: string, file: string) => `@font-face{font-family:'${family}';src:url(${origin}/fonts/geist/${file}) format('woff2');font-weight:100 900;font-style:normal;font-display:swap}`
  return <style dangerouslySetInnerHTML={{ __html: face('Geist', 'Geist-Variable.woff2') + face('Geist Mono', 'GeistMono-Variable.woff2') }} />
}

const TABLE = { role: 'presentation', cellpadding: '0', cellspacing: '0', border: 0 } as const

/**
 * The template: the white card (org.ai mark + "id.org.ai", then `blocks` 22px apart)
 * and the footer line 16px below it. Fills its container up to 584px.
 */
export function EmailContent({ blocks }: { blocks: JSX.Element[] }): JSX.Element {
  return (
    <table {...TABLE} align="center" width="100%" style={{ width: '100%', maxWidth: '584px', borderCollapse: 'separate', fontFamily: EMAIL_FONT, color: C.text, WebkitFontSmoothing: 'antialiased' }}>
      <tr>
        <td bgcolor={C.card} style={{ background: C.card, border: `1px solid ${C.line}`, borderRadius: '12px', padding: '40px 44px' }}>
          <table {...TABLE} width="100%" style={{ width: '100%', borderCollapse: 'separate' }}>
            <tr>
              <td style={{ fontSize: '14px', lineHeight: '18px', fontWeight: '600', color: C.text }}>
                <span style={{ display: 'inline-block', verticalAlign: 'top', marginRight: '8px', fontSize: '0', lineHeight: '0', color: C.text }}>
                  <OrgMark size={18} />
                </span>
                id.org.ai
              </td>
            </tr>
            {blocks.map((block) => (
              <tr>
                <td style={{ paddingTop: '22px' }}>{block}</td>
              </tr>
            ))}
          </table>
        </td>
      </tr>
      <tr>
        <td style={{ padding: '16px 4px 0', fontSize: '12px', lineHeight: '18px', color: C.tertiary }}>{EMAIL_FOOTER}</td>
      </tr>
    </table>
  )
}

/** Heading: 22px/28px, 600, -0.02em. */
export function EmailHeading({ children }: { children: string }): JSX.Element {
  return <h1 style={{ margin: '0', fontSize: '22px', lineHeight: '28px', fontWeight: '600', letterSpacing: '-0.02em', color: C.text }}>{children}</h1>
}

/** Body paragraph: 15px/24px, secondary text. */
export function EmailParagraph({ children }: { children: JSX.Element | string | (JSX.Element | string)[] }): JSX.Element {
  return <p style={{ margin: '0', fontSize: '15px', lineHeight: '24px', color: C.secondary }}>{children}</p>
}

/** A name or address inside a paragraph: text colour, 500. */
export function EmailStrong({ children }: { children: string }): JSX.Element {
  return <span style={{ color: C.text, fontWeight: '500' }}>{children}</span>
}

/** Small print under the body (8a's "Requested from …"): 13px, tertiary text. */
export function EmailMeta({ children }: { children: string }): JSX.Element {
  return <p style={{ margin: '0', fontSize: '13px', lineHeight: '17px', color: C.tertiary }}>{children}</p>
}

/** The one-time code: mono 36px/44px, 500, 0.18em, 16px above and below, ruled. Shown grouped ("482 913"). */
export function EmailCode({ code }: { code: string }): JSX.Element {
  return (
    <table {...TABLE} width="100%" style={{ width: '100%', borderCollapse: 'separate' }}>
      <tr>
        <td
          style={{
            padding: '16px 0',
            borderTop: `1px solid ${C.line}`,
            borderBottom: `1px solid ${C.line}`,
            fontFamily: EMAIL_MONO,
            fontSize: '36px',
            lineHeight: '44px',
            fontWeight: '500',
            letterSpacing: '0.18em',
            color: C.text,
          }}
        >
          {groupCode(code)}
        </td>
      </tr>
    </table>
  )
}

/** "482913" → "482 913": groups of three, for reading; the subject and text keep it whole for autofill. */
export function groupCode(code: string): string {
  return code.replace(/(.{3})(?=.)/g, '$1 ')
}

/** Primary button: 44px, padding 0 20px, radius 10px, text-colour fill, white 14px/500. */
export function EmailButton({ href, children }: { href: string; children: string }): JSX.Element {
  return (
    <table {...TABLE} style={{ borderCollapse: 'separate' }}>
      <tr>
        <td bgcolor={C.text} style={{ background: C.text, borderRadius: '10px' }}>
          <a
            href={httpUrl(href)}
            style={{
              display: 'block',
              padding: '0 20px',
              fontSize: '14px',
              lineHeight: '44px',
              fontWeight: '500',
              color: '#ffffff',
              textDecoration: 'none',
              whiteSpace: 'nowrap',
            }}
          >
            {children}
          </a>
        </td>
      </tr>
    </table>
  )
}

/** Key/value box (8c): 1px line border, radius 10px, padding 14px 16px, 14px rows 6px apart, keys tertiary. */
export function EmailKeyValues({ rows }: { rows: [string, string][] }): JSX.Element {
  return (
    <table {...TABLE} width="100%" style={{ width: '100%', borderCollapse: 'separate', border: `1px solid ${C.line}`, borderRadius: '10px' }}>
      <tr>
        <td style={{ padding: '14px 16px' }}>
          <table {...TABLE} width="100%" style={{ width: '100%', borderCollapse: 'separate' }}>
            {rows.map(([key, value], i) => {
              const cell = { paddingTop: i === 0 ? '0' : '6px', fontSize: '14px', lineHeight: '18px', verticalAlign: 'top' }
              return (
                <tr>
                  <td style={{ ...cell, color: C.tertiary, whiteSpace: 'nowrap' }}>{key}</td>
                  <td align="right" style={{ ...cell, paddingLeft: '16px', color: C.text, textAlign: 'right' }}>
                    {value}
                  </td>
                </tr>
              )
            })}
          </table>
        </td>
      </tr>
    </table>
  )
}

/** The message document: page colour, 28px around the template, Geist from `fontBase`. */
function EmailDocument({ title, fontBase, children }: { title: string; fontBase: string; children: JSX.Element }): JSX.Element {
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="color-scheme" content="light" />
        <meta name="supported-color-schemes" content="light" />
        <meta name="format-detection" content="telephone=no, date=no, address=no, email=no" />
        <title>{title}</title>
        <EmailFonts base={fontBase} />
        {/* Apple Mail would otherwise turn 8c's time and place into blue links. */}
        <style dangerouslySetInnerHTML={{ __html: 'a[x-apple-data-detectors]{color:inherit!important;text-decoration:none!important}' }} />
      </head>
      <body style={{ margin: '0', padding: '0', background: C.page, textRendering: 'optimizeLegibility', WebkitFontSmoothing: 'antialiased' }}>
        <table {...TABLE} width="100%" bgcolor={C.page} style={{ width: '100%', background: C.page, borderCollapse: 'separate' }}>
          <tr>
            <td style={{ padding: '28px' }}>{children}</td>
          </tr>
        </table>
      </body>
    </html>
  )
}

/** The sendable message: `{ from, subject, html, text }`. */
export function renderEmail(parts: EmailParts, opts: EmailRenderOptions = {}): RenderedEmail {
  const doc = (
    <EmailDocument title={parts.subject} fontBase={opts.fontBase ?? EMAIL_FONT_BASE}>
      {parts.content}
    </EmailDocument>
  )
  return { from: parts.from, subject: parts.subject, html: '<!doctype html>' + String(doc), text: parts.text }
}
