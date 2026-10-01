/** Authorize (3a–3d) group fixtures: strings copied verbatim from the mocks. */
import type { PermissionItem } from '../../components'
import { AdminApprove, type AdminApproveProps } from '../../screens/AdminApprove'
import { Consent, type ConsentProps } from '../../screens/Consent'
import { defineFixture, type FixtureGroup } from '../types'

const account = { name: 'Bryant Skarda', email: 'bryant@driv.ly' }
const switchHref = '/login?prompt=login&continue=%2Foauth%2Fauthorize%3Fclient_id%3Dhttps%253A%252F%252Fchatgpt.com%252Foauth%252Fcodex%252Fclient.json'

/** The existing consent hidden fields (B2), with gallery values. */
function hidden(clientId: string, redirectUri: string, scope: string, resource?: string): Record<string, string> {
  const h: Record<string, string> = {
    client_id: clientId,
    redirect_uri: redirectUri,
    scope,
    state: 'gallery',
    code_challenge: 'gallery',
    code_challenge_method: 'S256',
    nonce: 'gallery',
  }
  if (resource) h.resource = resource
  return h
}

// ── 3a · Authorize app (read + act) ────────────────────────────────────────

const consentPermissions: PermissionItem[] = [
  { icon: 'user', title: 'See your name, email and photo', detail: 'Your profile from id.org.ai. Never your other apps or workspaces.', scope: 'openid profile email' },
  { icon: 'search', title: 'Search and read your Startups on api.sb', detail: 'Read-only search and fetch across Startups in .do Industries.', scope: 'sb:read · resource https://api.sb' },
  {
    icon: 'pen',
    title: 'Run Verbs that change your Startups',
    detail: 'Create, update and run Verbs. Every change is logged under your name.',
    scope: 'sb:do · resource https://api.sb',
    act: true,
    actNote: 'Changes are made in your name.',
  },
  { icon: 'clock', title: 'Stay connected while you’re away', detail: 'Keeps a refresh token until you revoke it in Connected apps.', scope: 'offline_access' },
]

const consent: ConsentProps = {
  variant: 'full',
  client: { name: 'Codex', tile: { kind: 'monogram', text: 'Cx' }, runsOnThisComputer: true },
  resource: 'api.sb',
  account,
  switchHref,
  workspaces: [
    { value: 'org_do', label: '.do Industries' },
    { value: 'org_drivly', label: 'Drivly' },
    { value: 'org_studio', label: 'Startups Studio' },
  ],
  selectedWorkspace: 'org_do',
  access: { value: 'act', choice: { read: 'Search and read your Startups', act: 'Also run Verbs that change them' } },
  permissions: consentPermissions,
  source: {
    display: 'chatgpt.com/oauth/codex/client.json',
    copyValue: 'https://chatgpt.com/oauth/codex/client.json',
    details: [
      { k: 'Runs on', v: 'This computer' },
      { k: 'Returns to', v: '127.0.0.1:57585', mono: true },
      { k: 'Identified by', v: 'chatgpt.com' },
    ],
    links: [
      { href: 'https://example.com/codex/privacy', label: 'Codex privacy policy' },
      { href: 'https://example.com/codex/terms', label: 'Codex terms' },
    ],
  },
  hidden: hidden('https://chatgpt.com/oauth/codex/client.json', 'http://127.0.0.1:57585/callback', 'openid profile email sb:read sb:do offline_access', 'https://api.sb'),
  action: '/oauth/authorize',
  csrf: 'gallery',
}

/**
 * A stand-in logo for the derived `logo` state: our own mark, served from this
 * origin (never a real third-party mark, logos.md#rules). Real clients bring an
 * https logo_uri; data: URIs aren't rendered (components/url.ts).
 */
const PLACEHOLDER_LOGO = '/orgLogo.svg'

/**
 * Codex's own logo_uri, exactly as its client metadata document publishes it
 * (https://chatgpt.com/oauth/codex/client.json, read 2026-10-01): what 3a
 * shows a real Codex sign-in once consent renders the client's logo. Derived
 * state only; the visual diff keeps the mocks' monogram.
 */
const CODEX_LOGO_URI = 'https://persistent.oaistatic.com/sonic/misc/openai-logo.png'

// ── 3b · Sign in with id.org.ai ────────────────────────────────────────────

const basic: ConsentProps = {
  variant: 'basic',
  client: { name: 'api.sb', tile: { kind: 'monogram', text: 'sb' } },
  resource: 'api.sb',
  scopesSummary: 'name, email address and profile photo',
  account,
  switchHref,
  source: {
    display: 'api.sb',
    copyValue: 'api.sb',
    details: [
      { k: 'Identified by', v: 'api.sb' },
      { k: 'Returns to', v: 'https://api.sb/auth/callback', mono: true },
    ],
    links: [
      { href: 'https://example.com/api.sb/privacy', label: 'api.sb privacy policy' },
      { href: 'https://example.com/api.sb/terms', label: 'api.sb terms' },
    ],
  },
  hidden: hidden('api.sb', 'https://api.sb/auth/callback', 'openid profile email'),
  action: '/oauth/authorize',
  csrf: 'gallery',
}

// ── 3c · Unverified app ────────────────────────────────────────────────────

const unverified: ConsentProps = {
  variant: 'unverified',
  client: { name: 'agent-tools.dev', tile: { kind: 'monogram', text: 'a' }, runsOnThisComputer: true },
  resource: 'api.sb',
  intent: 'read your Startups',
  account,
  switchHref,
  selectedWorkspace: 'org_do',
  access: { value: 'read' },
  permissions: [
    { icon: 'user', title: 'See your name, email and photo', detail: 'Your profile from id.org.ai.', scope: 'openid profile email' },
    { icon: 'search', title: 'Search and read your Startups on api.sb', detail: 'Read-only. It can’t change anything.', scope: 'sb:read · resource https://api.sb' },
  ],
  source: {
    display: 'agent-tools.dev/oauth/client.json',
    copyValue: 'https://agent-tools.dev/oauth/client.json',
    details: [
      { k: 'Runs on', v: 'This computer' },
      { k: 'Returns to', v: '127.0.0.1:61022', mono: true },
      { k: 'Verified', v: 'No' },
    ],
  },
  hidden: hidden('https://agent-tools.dev/oauth/client.json', 'http://127.0.0.1:61022/callback', 'openid profile email sb:read', 'https://api.sb'),
  action: '/oauth/authorize',
  csrf: 'gallery',
}

// ── 3d · Admin approves an app ─────────────────────────────────────────────

const approve: AdminApproveProps = {
  requester: { name: 'Alex Rivera' },
  client: { name: 'Codex', tile: { kind: 'monogram', text: 'Cx' } },
  workspace: { name: 'Drivly', tile: { kind: 'monogram', text: 'Dr' } },
  note: 'Need it to run the weekly pipeline cleanup on api.sb.',
  permissions: [
    { icon: 'search', title: 'Search and read Startups on api.sb', detail: 'Read-only search and fetch across Startups in Drivly.', scope: 'sb:read · resource https://api.sb' },
    {
      icon: 'pen',
      title: 'Run Verbs that change Startups',
      detail: 'Create, update and run Verbs, logged under each person’s name.',
      scope: 'sb:do · resource https://api.sb',
      act: true,
      actNote: 'Changes are made in each person’s name.',
    },
  ],
  scope: 'requester',
  admin: { name: 'Nathan Clevenger', email: 'nathan@do.industries' },
  source: {
    display: 'chatgpt.com/oauth/codex/client.json',
    copyValue: 'https://chatgpt.com/oauth/codex/client.json',
    details: [
      { k: 'Identified by', v: 'chatgpt.com' },
      { k: 'Runs on', v: 'Each person’s computer' },
    ],
  },
  action: '/admin/requests/req_gallery',
  csrf: 'gallery',
}

const consentTitle = (p: ConsentProps) => (p.variant === 'basic' ? `Sign in to ${p.client.name} · id.org.ai` : `Authorize ${p.client.name} · id.org.ai`)
const consentScripts: ['copy.js', 'submit.js', 'logo.js'] = ['copy.js', 'submit.js', 'logo.js']

export const authorizeFixtures: FixtureGroup = {
  '3a-consent': defineFixture({
    screen: Consent,
    title: consentTitle,
    scripts: consentScripts,
    default: consent,
    states: { copied: { ...consent, copied: true } },
    derived: {
      logo: { ...consent, client: { ...consent.client, tile: { kind: 'logo', src: PLACEHOLDER_LOGO, monogram: 'Cx' } } },
      'codex-logo': { ...consent, client: { ...consent.client, tile: { kind: 'logo', src: CODEX_LOGO_URI, monogram: 'Cx' } } },
      busy: { ...consent, busy: true },
    },
  }),
  '3b-consent-basic': defineFixture({
    screen: Consent,
    title: consentTitle,
    scripts: consentScripts,
    default: basic,
    states: { copied: { ...basic, copied: true } },
  }),
  '3c-consent-unverified': defineFixture({
    screen: Consent,
    title: consentTitle,
    scripts: consentScripts,
    default: unverified,
    states: { copied: { ...unverified, copied: true } },
  }),
  '3d-admin-approve': defineFixture({
    screen: AdminApprove,
    title: (p) => `Approve ${p.client.name} · id.org.ai`,
    scripts: ['copy.js', 'submit.js', 'logo.js'],
    default: approve,
    states: { copied: { ...approve, copied: true } },
    derived: {
      approved: { ...approve, state: 'approved' },
      declined: { ...approve, state: 'declined' },
    },
  }),
}
