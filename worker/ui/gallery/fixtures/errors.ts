/** Errors (7a–7c) group fixtures: strings copied verbatim from the mocks. */
import { ErrorPage, type ErrorPageProps } from '../../screens/ErrorPage'
import { defineFixture, type FixtureGroup } from '../types'

const title = (p: ErrorPageProps) => `${p.title} · id.org.ai`
const home = { label: 'Go to id.org.ai', href: '/' }

const misconfigured: ErrorPageProps = {
  tile: { kind: 'monogram', text: 'sb' },
  title: 'We stopped this sign-in',
  reason: 'api.sb tried to send you to a page it never registered. The app may be misconfigured, or someone may be trying to intercept your sign-in.',
  details: {
    open: true,
    error: 'invalid_request',
    reason: 'redirect_uri not registered',
    client: 'cid_6024fce7…66a8',
    redirect: 'https://api.sb.example/cb',
    request: 'req_7Hk2Qp9w',
  },
  actions: { primary: home },
}

/** Derived (no mock): the same template with copy per case (screens.md#7). */
const serverError: ErrorPageProps = {
  tile: { kind: 'icon', icon: 'alert' },
  title: 'Something went wrong',
  reason: 'We couldn’t finish this request. Nothing was changed. Try again in a moment.',
  details: { label: 'Details for support', error: 'server_error', reason: 'Unexpected error', request: 'req_3Fw8Zt1m' },
  actions: { primary: home },
}

const rateLimited: ErrorPageProps = {
  tile: { kind: 'icon', icon: 'clock' },
  title: 'Too many tries',
  reason: 'Too many tries. Try again in 15 minutes.',
  details: { label: 'Details for support', error: 'rate_limited', reason: 'Guess budget used up', request: 'req_9Lc4Hs6v' },
  actions: { primary: home },
}

const csrfExpired: ErrorPageProps = {
  tile: { kind: 'icon', icon: 'clock' },
  title: 'This page expired',
  reason: 'This page expired. Start again.',
  actions: { primary: { label: 'Start again', href: '/login' } },
}

const notFound: ErrorPageProps = {
  tile: { kind: 'icon', icon: 'search' },
  title: 'Page not found',
  reason: 'This link doesn’t go anywhere. Check the address, or start from id.org.ai.',
  actions: { primary: home },
}

const expired: ErrorPageProps = {
  tile: { kind: 'icon', icon: 'clock' },
  title: 'This link has expired',
  reason: 'Sign-in links last 10 minutes and work once.',
  actions: {
    secondary: { label: 'Sign in another way', href: '/login' },
    primary: { label: 'Send a new code', href: '/login/code/flw_2Xn7Qe4k/resend', icon: 'mail', post: true, busyLabel: 'Sending…' },
  },
  csrf: 'gallery',
}

const chooseWorkspace = { label: 'Use another workspace', href: '/workspace/choose?continue=%2Foauth%2Fauthorize' }

const blocked: ErrorPageProps = {
  tile: { kind: 'monogram', text: 'Cx' },
  title: 'Drivly hasn’t approved Codex',
  reason: 'Your workspace only allows apps an admin has approved.',
  actions: {
    secondary: chooseWorkspace,
    primary: { label: 'Request access', href: '/admin/requests', post: true, busyLabel: 'Requesting…' },
  },
  footnote: { icon: 'send', text: 'Admins get an email and can approve in one click.' },
  csrf: 'gallery',
  fields: { client: 'https://chatgpt.com/codex/client.json', org: 'org_drivly' },
  accessRequest: {},
}

export const errorsFixtures: FixtureGroup = {
  '7a-error-app': defineFixture({
    screen: ErrorPage,
    title,
    scripts: ['copy.js'],
    default: misconfigured,
    states: {
      copied: { ...misconfigured, copied: true },
    },
    derived: {
      'server-error': serverError,
      'rate-limited': rateLimited,
      'csrf-expired': csrfExpired,
      'not-found': notFound,
    },
  }),
  // ErrorCard's posting form is data-js="submit" (its busy label).
  '7b-error-expired': defineFixture({
    screen: ErrorPage,
    title,
    scripts: ['submit.js'],
    default: expired,
  }),
  '7c-error-blocked': defineFixture({
    screen: ErrorPage,
    title,
    scripts: ['submit.js'],
    default: blocked,
    derived: {
      'request-sent': {
        ...blocked,
        title: 'Request sent',
        reason: 'We asked Drivly’s admins to approve Codex. You’ll get an email when they decide.',
        actions: { primary: chooseWorkspace },
        accessRequest: { sent: true, note: 'I use Codex to review pull requests on the API.' },
      },
    },
  }),
}
