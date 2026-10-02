/**
 * 7 · The error template (docs/product-update/spec/screens.md#7): one page
 * for every error a browser can see. 7a misconfigured app, 7b expired link,
 * 7c blocked by workspace policy, and the generic server error (500), rate
 * limit (429), CSRF failure and not found all render through it.
 * `errorPageProps(kind, ctx)` in worker/ui/errors.ts builds these props from
 * the catalogue for each error kind, and `renderErrorPage` there renders the
 * page. ErrorCard is the same card without the page shell, for an error shown
 * in place inside another page.
 *
 * The human reason comes first; developer details fold underneath with a copy
 * action. Everything here is request data and is escaped by JSX. A rejected
 * redirect_uri is shown as text in the details, never as a link, and nothing
 * on this page sends the person to it.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import {
  Actions,
  Button,
  Card,
  CardFoot,
  CardHead,
  Connector,
  CopyButton,
  Disclosure,
  Dotted,
  Field,
  FootNote,
  KeyValues,
  Page,
  QuoteWell,
  Textarea,
  type KV,
  type TileContent,
} from '../components'
import type { IconName } from '../icons'

/** An action on the error page that navigates: a link. */
export interface ErrorAction {
  label: string
  href: string
  icon?: IconName
  post?: false
}

/**
 * Primary only: an action with side effects (send a new code, request
 * access). It submits the card's form, POSTing to `href` with the page's CSRF
 * token and `fields`.
 */
export interface ErrorPostAction {
  label: string
  href: string
  icon?: IconName
  post: true
  /** The progressive label while posting ("Sending…"). */
  busyLabel?: string
}

export interface ErrorActions {
  /** The primary: on the right, or the full width when alone. */
  primary: ErrorAction | ErrorPostAction
  /** The outlined action on the left. Always a link. */
  secondary?: ErrorAction
}

/** Developer details: shown as key/values and copied as text. */
export interface ErrorDetails {
  /** The disclosure's label. Default "Details for the app’s developer". */
  label?: string
  /** Open on first render (7a). */
  open?: boolean
  /** The error code ("invalid_request"). */
  error: string
  /** The developer-facing reason ("redirect_uri not registered"). */
  reason: string
  client?: string
  /** A rejected redirect_uri: plain text only, never a link. */
  redirect?: string
  /** The request ID (X-Request-Id). */
  request: string
}

/** One catalogue entry: what the person reads and can do. */
export interface ErrorCatalogueEntry {
  title: string
  reason: string
  actions: ErrorActions
  /** Developer details, when the page has them (7a, and the generic errors' request ID). */
  details?: ErrorDetails
  /** The safety line under the buttons (7c: send icon, "Admins get an email…"). */
  footnote?: { icon?: IconName; text: string }
}

interface ErrorPageCommon extends ErrorCatalogueEntry {
  /**
   * The right tile, after id.org.ai: the app when it is known (7a, 7c),
   * otherwise an icon for the kind (clock for expired).
   */
  tile: TileContent
  /** Hidden fields posted with the primary (client, org, flow). */
  fields?: Record<string, string>
  /**
   * 7c: the access request. The optional note to the admins (max 500
   * characters) while asking; once `sent`, the note is quoted back and the
   * catalogue's "Request sent" copy is shown in place.
   */
  accessRequest?: { note?: string; sent?: boolean }
  /** Gallery only: the copy button's copied state. */
  copied?: boolean
}

/** Every action is a link, so there is no form. */
export interface ErrorLinkPageProps extends ErrorPageCommon {
  actions: { primary: ErrorAction; secondary?: ErrorAction }
  csrf?: string
}

/** The primary posts, so the card is a form and the CSRF token is required. */
export interface ErrorPostPageProps extends ErrorPageCommon {
  actions: { primary: ErrorPostAction; secondary?: ErrorAction }
  csrf: string
}

export type ErrorPageProps = ErrorLinkPageProps | ErrorPostPageProps

/** The primary posts (and so the props carry a CSRF token). */
export function postsPrimary(p: ErrorPageProps): p is ErrorPostPageProps {
  return p.actions.primary.post === true
}

const ORG: TileContent = { kind: 'org' }
const NOTE_ID = 'access-note'
export const NOTE_MAX = 500

function detailRows(d: ErrorDetails): KV[] {
  const rows: KV[] = [
    { k: 'Error', v: d.error, mono: true },
    { k: 'Reason', v: d.reason },
  ]
  if (d.client) rows.push({ k: 'Client', v: d.client, mono: true })
  if (d.redirect) rows.push({ k: 'Redirect', v: d.redirect, mono: true })
  rows.push({ k: 'Request', v: d.request, mono: true })
  return rows
}

/** The text "Copy details" writes: exactly the values shown. */
export function detailsText(d: ErrorDetails): string {
  return detailRows(d)
    .map((r) => `${r.k}: ${String(r.v)}`)
    .join('\n')
}

function Details({ d, copied }: { d: ErrorDetails; copied?: boolean }): JSX.Element {
  return (
    <Disclosure summary={d.label ?? 'Details for the app’s developer'} open={d.open}>
      <KeyValues items={detailRows(d)} />
      <CopyButton value={detailsText(d)} labelled copied={copied} />
    </Disclosure>
  )
}

/** A posting primary is the form's submit; everything else is a link. `grow` when it is the only action. */
function ActionButton({ a, variant, grow }: { a: ErrorAction | ErrorPostAction; variant: 'primary' | 'secondary'; grow?: boolean }): JSX.Element {
  if (a.post && variant === 'primary') {
    return (
      <Button variant="primary" block grow={grow} icon={a.icon} busyLabel={a.busyLabel}>
        {a.label}
      </Button>
    )
  }
  return (
    <Button variant={variant} block grow={grow} href={a.href} icon={a.icon}>
      {a.label}
    </Button>
  )
}

function Foot({ p }: { p: ErrorPageProps }): JSX.Element {
  const { primary, secondary } = p.actions
  const sent = p.accessRequest?.sent
  return (
    <CardFoot>
      {secondary ? (
        <Actions>
          <ActionButton a={secondary} variant="secondary" />
          <ActionButton a={primary} variant="primary" />
        </Actions>
      ) : (
        <ActionButton a={primary} variant="primary" grow />
      )}
      {p.footnote && !sent ? <FootNote icon={p.footnote.icon}>{p.footnote.text}</FootNote> : null}
    </CardFoot>
  )
}

function Body({ p }: { p: ErrorPageProps }): JSX.Element {
  const req = p.accessRequest
  return (
    <>
      <CardHead connector={<Connector left={ORG} right={p.tile} state="fail" />} title={p.title} description={p.reason} />
      {p.details ? (
        <>
          <Dotted />
          <Details d={p.details} copied={p.copied} />
        </>
      ) : null}
      {req && !req.sent ? (
        <Field id={NOTE_ID} label="Note to your admins (optional)">
          <Textarea id={NOTE_ID} name="note" placeholder="Why you need it" maxlength={NOTE_MAX} value={req.note} />
        </Field>
      ) : null}
      {req?.sent && req.note ? <QuoteWell>{req.note}</QuoteWell> : null}
      <span class="id-sr" role="status" data-status>
        {req?.sent ? p.title : ''}
      </span>
    </>
  )
}

/**
 * The error card on its own (and its form, when the primary posts), for
 * places that show a whole error card inside another page (5b's expired
 * template). ErrorPage is this card in the page shell. A posting form runs
 * submit.js, so list it in the page's scripts.
 */
export function ErrorCard(p: ErrorPageProps): JSX.Element {
  const card = (
    <Card foot={<Foot p={p} />}>
      <Body p={p} />
    </Card>
  )
  if (!postsPrimary(p)) return card
  return (
    <form class="id-form" method="post" action={p.actions.primary.href} data-js="submit">
      <input type="hidden" name="csrf" value={p.csrf} />
      {Object.entries(p.fields ?? {}).map(([name, value]) => (
        <input type="hidden" name={name} value={value} />
      ))}
      {card}
    </form>
  )
}

export function ErrorPage(p: ErrorPageProps): JSX.Element {
  return (
    <Page>
      <ErrorCard {...p} />
    </Page>
  )
}
