/**
 * The scope registry (docs/product-update/spec/backend.md#b2): each context's
 * rows equal the mocks' strings (3a consent, 3c unverified, 4b device, 3d
 * admin); unknown scopes get a generic row; scope strings are never markup.
 */
import { describe, it, expect } from 'vitest'
import { describeScopes } from '../src/sdk/oauth/scope-registry'
import { SCOPE_DESCRIPTIONS } from '../src/sdk/oauth/delegation'

const SB = { resource: 'https://api.sb' }

describe('describeScopes', () => {
  it('3a consent: the mock’s four rows, in its order', () => {
    const rows = describeScopes(['openid', 'profile', 'email', 'sb:read', 'sb:do', 'offline_access'], { context: 'consent', ...SB, workspaceName: '.do Industries', appName: 'Codex' })
    expect(rows).toEqual([
      { icon: 'user', title: 'See your name, email and photo', detail: 'Your profile from id.org.ai. Never your other apps or workspaces.', scope: 'openid profile email' },
      { icon: 'search', title: 'Search and read your Startups on api.sb', detail: 'Read-only search and fetch across Startups in .do Industries.', scope: 'sb:read · resource https://api.sb' },
      {
        icon: 'pen',
        title: 'Run Verbs that change your Startups',
        detail: 'Create, update and run Verbs. Every change is logged under your name.',
        actNote: 'Changes are made in your name.',
        scope: 'sb:do · resource https://api.sb',
        act: true,
      },
      { icon: 'clock', title: 'Stay connected while you’re away', detail: 'Keeps a refresh token until you revoke it in Connected apps.', scope: 'offline_access' },
    ])
  })

  it('3c unverified: read-only copy that promises nothing about other apps', () => {
    const rows = describeScopes(['openid', 'profile', 'email', 'sb:read'], { context: 'consentUnverified', ...SB })
    expect(rows.map((r) => [r.title, r.detail])).toEqual([
      ['See your name, email and photo', 'Your profile from id.org.ai.'],
      ['Search and read your Startups on api.sb', 'Read-only. It can’t change anything.'],
    ])
  })

  it('4b device: the CLI wording', () => {
    const rows = describeScopes(['openid', 'profile', 'email', 'auto.dev:api', 'offline_access'], { context: 'device', workspaceName: 'Drivly' })
    expect(rows.map((r) => [r.icon, r.title, r.detail, r.scope])).toEqual([
      ['user', 'See your name and email', 'Shown in the CLI as who is signed in.', 'openid profile email'],
      ['terminal', 'Use the auto.dev API as you in Drivly', 'Calls count against Drivly’s auto.dev plan.', 'auto.dev:api'],
      ['clock', 'Stay signed in on this device', 'Until you sign out or revoke it in Connected apps.', 'offline_access'],
    ])
  })

  it('3d admin: everyone’s wording, act note included', () => {
    const rows = describeScopes(['sb:read', 'sb:do'], { context: 'admin', ...SB, workspaceName: 'Drivly' })
    expect(rows).toEqual([
      { icon: 'search', title: 'Search and read Startups on api.sb', detail: 'Read-only search and fetch across Startups in Drivly.', scope: 'sb:read · resource https://api.sb' },
      {
        icon: 'pen',
        title: 'Run Verbs that change Startups',
        detail: 'Create, update and run Verbs, logged under each person’s name.',
        actNote: 'Changes are made in each person’s name.',
        scope: 'sb:do · resource https://api.sb',
        act: true,
      },
    ])
  })

  it('a context without its own copy falls back to consent', () => {
    expect(describeScopes(['offline_access'], { context: 'admin' })[0]!.title).toBe('Stay connected while you’re away')
  })

  it('groups only the identity scopes actually requested', () => {
    expect(describeScopes(['openid'], { context: 'consent' })[0]!.scope).toBe('openid')
  })

  it('unknown scopes get a generic row titled with the raw scope', () => {
    const [row] = describeScopes(['calendar:write'], { context: 'consent' })
    expect(row).toMatchObject({ icon: 'globe', title: 'calendar:write', scope: 'calendar:write' })
  })

  it('a <script> scope stays a string (JSX escapes it when rendered)', () => {
    const [row] = describeScopes(['<script>alert(1)</script>'], { context: 'consent' })
    expect(row!.title).toBe('<script>alert(1)</script>')
  })

  it('SCOPE_DESCRIPTIONS keeps its long-standing values, now from the registry', () => {
    expect(SCOPE_DESCRIPTIONS).toMatchObject({
      openid: 'Verify your identity',
      profile: 'View your name and profile picture',
      email: 'View your email address',
      offline_access: 'Access your data while you are offline',
      'sb:read': 'Read your Startups on api.sb (search and fetch)',
      'sb:do': 'Act for you on api.sb: run Verbs that change your Startups',
    })
  })
})
