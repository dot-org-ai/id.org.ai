/**
 * The error catalogue (docs/product-update/spec/backend.md#b1): every error a
 * browser can see, mapped onto the one error template (7a/7b/7c,
 * worker/ui/screens/ErrorPage.tsx). The person reads what happened first;
 * developer details (with the request ID) fold underneath.
 *
 * Everything in a context is request data: JSX escapes it, and a rejected
 * redirect_uri only ever appears as text in the details, never as a link.
 */
import type { Context } from 'hono'
import type { TileContent } from './components'
import { renderPage } from './render'
import { ErrorPage, type ErrorAction, type ErrorPageProps } from './screens/ErrorPage'

export type ErrorKind =
  | 'redirect_not_registered'
  | 'invalid_client'
  | 'invalid_client_metadata'
  | 'expired'
  | 'already_used'
  | 'rate_limited'
  | 'csrf'
  | 'blocked_by_policy'
  | 'server_error'
  | 'not_found'
  | 'bad_request'

/** What expired or was already used (7b): each has its own sentence. */
export type ExpiredThing = 'sign-in link' | 'code' | 'device code' | 'invitation' | 'approval' | 'sign-in'

export interface ErrorContext {
  /** X-Request-Id, shown in the developer details. */
  requestId: string
  /** The machine code (`invalid_request`, `invalid_grant` …) for the details. */
  code?: string
  /** The developer-facing reason (error_description) for the details. */
  description?: string
  /** The client involved, when known. */
  client?: { id: string; name?: string; tile?: TileContent }
  /** A rejected redirect_uri: text in the details only. */
  redirect?: string
  /** 429: when to try again. */
  retryAfterSeconds?: number
  /** 7b: what expired, and where a new one comes from. */
  expired?: { what: ExpiredThing; resend?: { href: string; csrf: string; fields?: Record<string, string> } }
  /** Where "start again" goes (defaults to /login for sign-in errors, / otherwise). */
  startHref?: string
}

const HOME: ErrorAction = { label: 'Go to id.org.ai', href: '/' }

const EXPIRED_COPY: Record<ExpiredThing, { title: string; reason: string }> = {
  'sign-in link': { title: 'This link has expired', reason: 'Sign-in links last 10 minutes and work once.' },
  code: { title: 'This code has expired', reason: 'Sign-in codes last 10 minutes and work once. Send a new one to keep going.' },
  'device code': { title: 'This code has expired', reason: 'Device codes last 30 minutes and work once. Run the sign-in command again for a new one.' },
  invitation: { title: 'This invitation has expired', reason: 'Ask the person who invited you to send a new invitation.' },
  approval: { title: 'This request expired', reason: 'Unanswered requests expire as a no, so nothing happened. The agent can ask again.' },
  'sign-in': { title: 'This sign-in has expired', reason: 'Sign-in attempts last a few minutes. Start again from the app you were using.' },
}

const USED_COPY: Record<ExpiredThing, string> = {
  'sign-in link': 'This sign-in link was already used. Each link works once.',
  code: 'This code was already used. Each code works once.',
  'device code': 'This device code was already used. Run the sign-in command again for a new one.',
  invitation: 'This invitation was already accepted or declined.',
  approval: 'This request was already answered.',
  'sign-in': 'This sign-in was already finished. Start again from the app you were using.',
}

function appName(ctx: ErrorContext): string {
  return ctx.client?.name ?? 'This app'
}

function tileFor(ctx: ErrorContext, fallback: TileContent): TileContent {
  return ctx.client?.tile ?? fallback
}

function details(ctx: ErrorContext, fallbackCode: string, fallbackReason: string, label?: string, open?: boolean): ErrorPageProps['details'] {
  return {
    ...(label ? { label } : {}),
    ...(open ? { open } : {}),
    error: ctx.code ?? fallbackCode,
    reason: ctx.description ?? fallbackReason,
    ...(ctx.client?.id ? { client: ctx.client.id } : {}),
    ...(ctx.redirect ? { redirect: ctx.redirect } : {}),
    request: ctx.requestId,
  }
}

/** The template's props for an error. */
export function errorPageProps(kind: ErrorKind, ctx: ErrorContext): ErrorPageProps {
  const support = 'Details for support'
  switch (kind) {
    case 'redirect_not_registered':
      return {
        tile: tileFor(ctx, { kind: 'icon', icon: 'globe' }),
        title: 'We stopped this sign-in',
        reason: `${appName(ctx)} tried to send you to a page it never registered. The app may be misconfigured, or someone may be trying to intercept your sign-in.`,
        details: details(ctx, 'invalid_request', 'redirect_uri not registered', undefined, true),
        actions: { primary: HOME },
      }
    case 'invalid_client':
      return {
        tile: tileFor(ctx, { kind: 'icon', icon: 'globe' }),
        title: 'We don’t recognise this app',
        reason: 'The app that sent you here isn’t registered with id.org.ai, so we stopped. Let its developer know.',
        details: details(ctx, 'invalid_client', 'Unknown client_id', undefined, true),
        actions: { primary: HOME },
      }
    case 'invalid_client_metadata':
      return {
        tile: tileFor(ctx, { kind: 'icon', icon: 'globe' }),
        title: 'We couldn’t verify this app',
        reason: 'The app’s published details didn’t check out, so we stopped. Let its developer know.',
        details: details(ctx, 'invalid_client_metadata', 'Client metadata document is invalid', undefined, true),
        actions: { primary: HOME },
      }
    case 'expired': {
      const what = ctx.expired?.what ?? 'sign-in'
      const resend = ctx.expired?.resend
      return {
        tile: { kind: 'icon', icon: 'clock' },
        ...EXPIRED_COPY[what],
        actions: resend
          ? {
              secondary: { label: 'Sign in another way', href: '/login' },
              primary: { label: 'Send a new code', href: resend.href, icon: 'mail', post: true, busyLabel: 'Sending…' },
            }
          : { primary: { label: 'Start again', href: ctx.startHref ?? '/login' } },
        ...(resend ? { csrf: resend.csrf, fields: resend.fields } : {}),
      }
    }
    case 'already_used': {
      const what = ctx.expired?.what ?? 'sign-in'
      return {
        tile: { kind: 'icon', icon: 'clock' },
        title: 'Already used',
        reason: USED_COPY[what],
        actions: { primary: { label: 'Start again', href: ctx.startHref ?? '/login' } },
      }
    }
    case 'rate_limited': {
      const minutes = Math.max(1, Math.ceil((ctx.retryAfterSeconds ?? 900) / 60))
      return {
        tile: { kind: 'icon', icon: 'clock' },
        title: 'Too many tries',
        reason: `Too many tries. Try again in ${minutes} ${minutes === 1 ? 'minute' : 'minutes'}.`,
        details: details(ctx, 'rate_limited', 'Too many attempts', support),
        actions: { primary: HOME },
      }
    }
    case 'csrf':
      return {
        tile: { kind: 'icon', icon: 'clock' },
        title: 'This page expired',
        reason: 'This page expired. Start again.',
        actions: { primary: { label: 'Start again', href: ctx.startHref ?? '/login' } },
      }
    case 'blocked_by_policy':
      return {
        tile: tileFor(ctx, { kind: 'icon', icon: 'lock' }),
        title: 'Your workspace hasn’t approved this app',
        reason: 'Your workspace only allows apps an admin has approved.',
        actions: { primary: { label: 'Use another workspace', href: ctx.startHref ?? '/workspace/choose' } },
      }
    case 'not_found':
      return {
        tile: { kind: 'icon', icon: 'search' },
        title: 'Page not found',
        reason: 'This link doesn’t go anywhere. Check the address, or start from id.org.ai.',
        actions: { primary: HOME },
      }
    case 'bad_request':
      return {
        tile: { kind: 'icon', icon: 'alert' },
        title: 'We couldn’t finish this',
        reason: 'Something about this request wasn’t right, so nothing happened. Start again from the app you were using.',
        details: details(ctx, 'invalid_request', 'Invalid request', support),
        actions: { primary: { label: 'Start again', href: ctx.startHref ?? '/login' } },
      }
    case 'server_error':
    default:
      return {
        tile: { kind: 'icon', icon: 'alert' },
        title: 'Something went wrong',
        reason: 'We couldn’t finish this request. Nothing was changed. Try again in a moment.',
        details: details(ctx, 'server_error', 'Unexpected error', support),
        actions: { primary: HOME },
      }
  }
}

/** Render an error page (with the security headers) at `status`. */
export function renderErrorPage(c: Context, kind: ErrorKind, ctx: ErrorContext, status: number): Promise<Response> {
  const props = errorPageProps(kind, ctx)
  const scripts: ('copy.js' | 'submit.js')[] = props.details ? ['copy.js'] : []
  if (props.actions.primary.post) scripts.push('submit.js')
  return renderPage(c, ErrorPage(props), { title: `${props.title} · id.org.ai`, scripts, status })
}

/**
 * Map an API error (status + OAuth/JSON code + description) to a catalogue
 * kind, for browser navigations that would otherwise see raw JSON.
 */
export function kindForApiError(status: number, code?: string, description?: string): ErrorKind {
  const desc = (description ?? '').toLowerCase()
  if (status === 404) return 'not_found'
  if (status === 429 || code === 'rate_limited' || code === 'rate_limit_exceeded') return 'rate_limited'
  if (code === 'invalid_client') return 'invalid_client'
  if (code === 'invalid_client_metadata') return 'invalid_client_metadata'
  if ((code === 'invalid_request' || code === 'invalid_redirect_uri') && desc.includes('redirect_uri')) return 'redirect_not_registered'
  if (desc.includes('csrf')) return 'csrf'
  if (code === 'invalid_grant' || code === 'expired_token' || desc.includes('expired')) return 'expired'
  if (status >= 500) return 'server_error'
  return 'bad_request'
}
