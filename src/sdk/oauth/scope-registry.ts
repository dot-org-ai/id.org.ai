/**
 * The scope registry (docs/product-update/spec/backend.md#b2): the single
 * source for the permission rows people see on consent (3a, 3c), device
 * confirm (4b) and admin approval (3d).
 *
 * The same scope is worded differently by context, so each entry carries copy
 * per context; a context without its own copy falls back to `consent`. `{res}`
 * is the resource host, `{ws}` the workspace and `{app}` the app.
 *
 * Rows come out in registry order (the mocks' order): who you are, what the
 * app may read, what it may change, API access, then staying connected.
 * Unknown scopes get a generic row titled with the raw scope (JSX escapes it).
 */

// The sb scopes (delegation.ts SB_SCOPE_READ / SB_SCOPE_DO). Spelled out here
// because delegation.ts derives SCOPE_DESCRIPTIONS from this registry.
const SB_SCOPE_READ = 'sb:read'
const SB_SCOPE_DO = 'sb:do'

export type ScopeContext = 'consent' | 'consentUnverified' | 'device' | 'admin'

/** Icon names the rows use (a subset of worker/ui/icons.tsx). */
export type ScopeIcon = 'user' | 'search' | 'pen' | 'clock' | 'terminal' | 'globe'

export interface ScopeCopy {
  icon: ScopeIcon
  title: string
  detail: string
  /** Act permissions: the accent sub-line under the title. */
  actNote?: string
}

export interface PermissionRow extends ScopeCopy {
  /** The raw scope line: the requested scopes, plus ` · resource <uri>` when resource-bound. */
  scope: string
  act?: boolean
}

interface RegistryEntry {
  /** The scopes this row stands for. The OIDC identity scopes share one row. */
  scopes: readonly string[]
  /** The one-line description kept for SCOPE_DESCRIPTIONS (API compatibility), per scope. */
  summaries: Record<string, string>
  /** Changes things in the person's name (accent icon, weight, act note). */
  act?: boolean
  /** Bound to an RFC 8707 resource: the scope line names it. */
  resourceBound?: boolean
  copy: { consent: ScopeCopy } & Partial<Record<Exclude<ScopeContext, 'consent'>, ScopeCopy>>
}

export const SCOPE_REGISTRY: readonly RegistryEntry[] = [
  {
    scopes: ['openid', 'profile', 'email'],
    summaries: { openid: 'Verify your identity', profile: 'View your name and profile picture', email: 'View your email address' },
    copy: {
      consent: { icon: 'user', title: 'See your name, email and photo', detail: 'Your profile from id.org.ai. Never your other apps or workspaces.' },
      consentUnverified: { icon: 'user', title: 'See your name, email and photo', detail: 'Your profile from id.org.ai.' },
      device: { icon: 'user', title: 'See your name and email', detail: 'Shown in the CLI as who is signed in.' },
    },
  },
  {
    scopes: [SB_SCOPE_READ],
    summaries: { [SB_SCOPE_READ]: 'Read your Startups on api.sb (search and fetch)' },
    resourceBound: true,
    copy: {
      consent: { icon: 'search', title: 'Search and read your Startups on {res}', detail: 'Read-only search and fetch across Startups in {ws}.' },
      consentUnverified: { icon: 'search', title: 'Search and read your Startups on {res}', detail: 'Read-only. It can’t change anything.' },
      admin: { icon: 'search', title: 'Search and read Startups on {res}', detail: 'Read-only search and fetch across Startups in {ws}.' },
    },
  },
  {
    scopes: [SB_SCOPE_DO],
    summaries: { [SB_SCOPE_DO]: 'Act for you on api.sb: run Verbs that change your Startups' },
    act: true,
    resourceBound: true,
    copy: {
      consent: {
        icon: 'pen',
        title: 'Run Verbs that change your Startups',
        detail: 'Create, update and run Verbs. Every change is logged under your name.',
        actNote: 'Changes are made in your name.',
      },
      admin: {
        icon: 'pen',
        title: 'Run Verbs that change Startups',
        detail: 'Create, update and run Verbs, logged under each person’s name.',
        actNote: 'Changes are made in each person’s name.',
      },
    },
  },
  {
    scopes: ['auto.dev:api'],
    summaries: { 'auto.dev:api': 'Use the auto.dev API as you' },
    copy: {
      consent: { icon: 'terminal', title: 'Use the auto.dev API as you in {ws}', detail: 'Calls count against {ws}’s auto.dev plan.' },
    },
  },
  {
    scopes: ['offline_access'],
    summaries: { offline_access: 'Access your data while you are offline' },
    copy: {
      consent: { icon: 'clock', title: 'Stay connected while you’re away', detail: 'Keeps a refresh token until you revoke it in Connected apps.' },
      device: { icon: 'clock', title: 'Stay signed in on this device', detail: 'Until you sign out or revoke it in Connected apps.' },
    },
  },
]

/** One-line descriptions per scope, derived from the registry (the long-standing export in delegation.ts). */
export const REGISTRY_SUMMARIES: Readonly<Record<string, string>> = Object.fromEntries(SCOPE_REGISTRY.flatMap((e) => Object.entries(e.summaries)))

export interface DescribeOptions {
  context: ScopeContext
  /** The RFC 8707 resource the request is bound to (https://api.sb). */
  resource?: string
  workspaceName?: string
  appName?: string
}

function hostOf(uri: string | undefined): string {
  if (!uri) return ''
  try {
    return new URL(uri).host
  } catch {
    return uri
  }
}

function fill(text: string, o: DescribeOptions): string {
  return text
    .replaceAll('{res}', hostOf(o.resource))
    .replaceAll('{ws}', o.workspaceName ?? 'your workspace')
    .replaceAll('{app}', o.appName ?? 'the app')
}

/** The permission rows for a set of requested scopes, in the context's words. */
export function describeScopes(scopes: readonly string[], o: DescribeOptions): PermissionRow[] {
  const requested = [...new Set(scopes.filter(Boolean))]
  const rows: PermissionRow[] = []
  const known = new Set<string>()
  for (const entry of SCOPE_REGISTRY) {
    const present = entry.scopes.filter((s) => requested.includes(s))
    for (const s of entry.scopes) known.add(s)
    if (present.length === 0) continue
    const copy = entry.copy[o.context] ?? entry.copy.consent
    rows.push({
      icon: copy.icon,
      title: fill(copy.title, o),
      detail: fill(copy.detail, o),
      ...(copy.actNote ? { actNote: fill(copy.actNote, o) } : {}),
      scope: present.join(' ') + (entry.resourceBound && o.resource ? ` · resource ${o.resource}` : ''),
      ...(entry.act ? { act: true } : {}),
    })
  }
  for (const s of requested) {
    if (known.has(s)) continue
    rows.push({ icon: 'globe', title: s, detail: 'A permission id.org.ai doesn’t describe. Only allow it if you expected it.', scope: s })
  }
  return rows
}
