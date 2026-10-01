/**
 * renderPage: every auth page goes through here, so every page gets the same
 * document head and the security headers in docs/product-update/spec/security.md.
 */
import type { Context } from 'hono'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { assetUrl, FONT_PRELOAD, type ClientScript } from './assets'

export interface RenderOptions {
  /** Document title, for example "Sign in · id.org.ai". */
  title: string
  /** Client scripts this page needs (module scripts, by logical name). */
  scripts?: ClientScript[]
  /**
   * Origins this page's forms may post or redirect to, beyond 'self'. Only
   * already-validated origins (for example the OAuth redirect_uri's origin).
   */
  formActionOrigins?: string[]
  /** Gallery only: `<html data-frozen>`, so client scripts never tick, poll, redirect or autofocus. */
  frozen?: boolean
  status?: number
  /** Extra response headers (never the security headers: those are fixed). */
  headers?: Record<string, string>
}

const ORIGIN_RE = /^https?:\/\/[a-z0-9.-]+(:\d{1,5})?$/i

/** The CSP from spec/security.md. `form-action` extends 'self' with validated origins only. */
export function contentSecurityPolicy(formActionOrigins: readonly string[] = []): string {
  const extra = formActionOrigins.filter((o) => ORIGIN_RE.test(o))
  return [
    "default-src 'none'",
    "style-src 'self'",
    "script-src 'self'",
    "img-src 'self' https: data:",
    "font-src 'self'",
    "connect-src 'self'",
    `form-action ${["'self'", ...new Set(extra)].join(' ')}`,
    "frame-ancestors 'none'",
    "base-uri 'none'",
  ].join('; ')
}

/** The fixed headers on every auth page. */
export function securityHeaders(csp: string): Record<string, string> {
  return {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': csp,
  }
}

export function Document({ title, scripts = [], frozen, children }: { title: string; scripts?: ClientScript[]; frozen?: boolean; children: JSX.Element }): JSX.Element {
  return (
    <html lang="en" data-frozen={frozen ? '' : undefined}>
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{title}</title>
        <link rel="preload" href={FONT_PRELOAD} as="font" type="font/woff2" crossorigin="anonymous" />
        <link rel="stylesheet" href={assetUrl('ui.css')} />
        {scripts.map((s) => (
          <script type="module" src={assetUrl(s)}></script>
        ))}
      </head>
      <body>{children}</body>
    </html>
  )
}

export async function renderHtml(element: JSX.Element, opts: Pick<RenderOptions, 'title' | 'scripts' | 'frozen'>): Promise<string> {
  const doc = <Document title={opts.title} scripts={opts.scripts} frozen={opts.frozen}>{element}</Document>
  return '<!doctype html>' + String(await doc)
}

export async function renderPage(_c: Context, element: JSX.Element, opts: RenderOptions): Promise<Response> {
  const html = await renderHtml(element, opts)
  const headers = new Headers(opts.headers)
  for (const [k, v] of Object.entries(securityHeaders(contentSecurityPolicy(opts.formActionOrigins)))) headers.set(k, v)
  return new Response(html, { status: opts.status ?? 200, headers })
}
