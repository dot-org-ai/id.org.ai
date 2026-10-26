/**
 * Sign-in / sign-out destination policy beyond PR #27's allowlist:
 *
 *   - LOGIN_CONTINUE_HOSTS: config-listed estate hosts (exact, or `*.suffix`).
 *   - LOGIN_CONTINUE_POLICY=report: a syntactically safe absolute target
 *     outside the policy is still followed (the pre-policy behaviour) and
 *     reported, so estate callers can be listed before enforcing.
 *   - /logout?return_url= goes through the same policy as /login?continue=.
 *
 * The suite runs with production's LOGIN_CONTINUE_POLICY (worker/wrangler.jsonc,
 * `enforce` since H3); `report`, the opt-in escape hatch, is exercised by
 * passing an env override to the route module.
 */
import { describe, it, expect } from 'vitest'
import { SELF, env } from 'cloudflare:test'
import { parseContinueHosts, resolveBrowserRedirect, resolveBrowserRedirectStrict, continuePolicy } from '../worker/utils/relying-parties'
import { authRoutes } from '../worker/routes/auth'
import type { Env } from '../worker/types'

const BASE = 'https://id.org.ai'
const baseEnv = env as unknown as Env
const reportEnv = { ...baseEnv, LOGIN_CONTINUE_POLICY: 'report' } as Env
const enforceEnv = { ...baseEnv, LOGIN_CONTINUE_POLICY: 'enforce' } as Env

function decodeState(state: string): Record<string, any> {
  const padded = state.replace(/-/g, '+').replace(/_/g, '/')
  return JSON.parse(atob(padded + '='.repeat((4 - (padded.length % 4)) % 4)))
}

describe('parseContinueHosts', () => {
  it('keeps bare hosts and multi-label *. suffixes, drops anything that would widen the policy', () => {
    const { exact, suffixes } = parseContinueHosts(
      ' Management.Studio , *.dotdo.workers.dev, *, *.dev, *., https://evil.com, evil.com/x, evil.com:443, a b, *.*.example.com, user@evil.com,',
    )
    expect([...exact]).toEqual(['management.studio'])
    expect(suffixes).toEqual(['.dotdo.workers.dev'])
  })

  it('an unset value lists nothing', () => {
    const { exact, suffixes } = parseContinueHosts(undefined)
    expect(exact.size).toBe(0)
    expect(suffixes).toEqual([])
  })
})

describe('continuePolicy', () => {
  it('is report only when configured so; anything else enforces', () => {
    expect(continuePolicy({ ...baseEnv, LOGIN_CONTINUE_POLICY: 'report' } as Env)).toBe('report')
    expect(continuePolicy({ ...baseEnv, LOGIN_CONTINUE_POLICY: ' REPORT ' } as Env)).toBe('report')
    expect(continuePolicy({ ...baseEnv, LOGIN_CONTINUE_POLICY: undefined } as Env)).toBe('enforce')
    expect(continuePolicy({ ...baseEnv, LOGIN_CONTINUE_POLICY: 'off' } as Env)).toBe('enforce')
  })
})

describe('resolveBrowserRedirect', () => {
  const opts = { requestOrigin: BASE }

  it('accepts config-listed hosts (from worker/wrangler.jsonc) under enforce', async () => {
    for (const url of ['https://management.studio/api/auth/callback', 'https://sdb.dotdo.workers.dev/', 'https://a.b.dotdo.workers.dev/x']) {
      expect(await resolveBrowserRedirect(enforceEnv, url, opts)).toEqual({ url: new URL(url).href, outcome: 'accepted' })
    }
  })

  it('a *. entry does not match the bare suffix, a look-alike, or plain http', async () => {
    for (const url of ['https://dotdo.workers.dev/', 'https://evil-dotdo.workers.dev/', 'https://sdb.dotdo.workers.dev.evil.com/', 'http://sdb.dotdo.workers.dev/', 'https://evil.management.studio/']) {
      const r = await resolveBrowserRedirect(enforceEnv, url, opts)
      expect(r.outcome, url).toBe('refused')
      expect(r.url).toBeNull()
    }
  })

  it('under enforce, an unlisted absolute target is refused and its host reported', async () => {
    expect(await resolveBrowserRedirect(enforceEnv, 'https://evil.com/steal?x=1', opts)).toEqual({ url: null, outcome: 'refused', host: 'evil.com' })
  })

  it('under report, an unlisted but syntactically safe target is followed as unlisted', async () => {
    expect(await resolveBrowserRedirect(reportEnv, 'https://some-startup.example/auth/callback?continue=%2F', opts)).toEqual({
      url: 'https://some-startup.example/auth/callback?continue=%2F',
      outcome: 'unlisted',
      host: 'some-startup.example',
    })
  })

  it('under report, injection shapes are still refused', async () => {
    for (const bad of ['//evil.com', '/\\evil.com', '/\t/evil.com', 'javascript:alert(1)', 'data:text/html,x', 'ftp://evil.com/', 'https://evil.com/\nx']) {
      const r = await resolveBrowserRedirect(reportEnv, bad, opts)
      expect(r.outcome, JSON.stringify(bad)).toBe('refused')
      expect(r.url).toBeNull()
    }
  })

  it('nothing given is none', async () => {
    expect(await resolveBrowserRedirect(enforceEnv, undefined, opts)).toEqual({ url: null, outcome: 'none' })
    expect(await resolveBrowserRedirect(enforceEnv, '', opts)).toEqual({ url: null, outcome: 'none' })
  })
})

describe('/login?continue= with config-listed hosts', () => {
  it('management.studio continues to its callback (its /signin/oauth/:provider flow)', async () => {
    const cont = 'https://management.studio/api/auth/callback'
    const res = await SELF.fetch(`${BASE}/login?provider=GitHubOAuth&continue=${encodeURIComponent(cont)}`, { redirect: 'manual' })
    expect(res.status).toBe(302)
    expect(decodeState(new URL(res.headers.get('location')!).searchParams.get('state')!).continue).toBe(cont)
  })

  it('under report, an unlisted host is followed; under enforce it is not', async () => {
    const cont = 'https://some-startup.example/auth/callback'
    const url = `${BASE}/login?provider=GitHubOAuth&continue=${encodeURIComponent(cont)}`
    const reported = await authRoutes.request(url, { redirect: 'manual' }, reportEnv)
    expect(decodeState(new URL(reported.headers.get('location')!).searchParams.get('state')!).continue).toBe(cont)
    const enforced = await authRoutes.request(url, { redirect: 'manual' }, enforceEnv)
    expect(decodeState(new URL(enforced.headers.get('location')!).searchParams.get('state')!).continue).toBe('/dash/profile')
  })
})

describe('/logout?return_url= uses the same policy', () => {
  async function logoutTo(returnUrl: string | undefined, e?: Env): Promise<string | null> {
    const qs = returnUrl === undefined ? '' : `?return_url=${encodeURIComponent(returnUrl)}`
    const res = e ? await authRoutes.request(`${BASE}/logout${qs}`, { redirect: 'manual' }, e) : await SELF.fetch(`${BASE}/logout${qs}`, { redirect: 'manual' })
    expect(res.status).toBe(302)
    // Always clears the session, whatever the destination.
    expect(res.headers.getSetCookie().some((c) => c.startsWith('auth=') && /Max-Age=0|Expires=Thu, 01 Jan 1970/i.test(c))).toBe(true)
    return res.headers.get('location')
  }

  it('estate callers keep working: sdb (listed *.dotdo.workers.dev), relative paths, own origins', async () => {
    expect(await logoutTo('https://sdb.dotdo.workers.dev/')).toBe('https://sdb.dotdo.workers.dev/')
    expect(await logoutTo('/dash')).toBe('/dash')
    expect(await logoutTo('https://oauth.do/')).toBe('https://oauth.do/')
    expect(await logoutTo(undefined)).toBe('/')
  })

  it("api.sb's ?everywhere sign-out returns to api.sb (listed in LOGIN_CONTINUE_HOSTS)", async () => {
    expect(await logoutTo('https://api.sb/')).toBe('https://api.sb/')
    expect(await logoutTo('https://mcp.sb/')).toBe('https://mcp.sb/')
  })

  it("H3: a self-registered client's redirect origin is NOT a sign-out target", async () => {
    const reg = await SELF.fetch(`${BASE}/oauth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_name: 'logout-rp', redirect_uris: ['https://logout-rp.example/auth/callback'] }),
    })
    expect(reg.status).toBe(201)
    expect(await logoutTo('https://logout-rp.example/')).toBe('/')
    expect(await logoutTo('https://logout-rp.example/auth/callback')).toBe('/')
  })

  it('refuses open-redirect targets under enforce', async () => {
    for (const bad of ['https://evil.com/', '//evil.com', '/\\evil.com', '/\t/evil.com', 'javascript:alert(1)']) {
      expect(await logoutTo(bad), JSON.stringify(bad)).toBe('/')
    }
  })

  it('under report, follows an unlisted https target but still refuses injection shapes', async () => {
    expect(await logoutTo('https://some-startup.example/', reportEnv)).toBe('https://some-startup.example/')
    expect(await logoutTo('//evil.com', reportEnv)).toBe('/')
  })
})

describe('resolveBrowserRedirectStrict (the redesigned screens)', () => {
  const opts = { requestOrigin: BASE }

  it('refuses an unlisted target even under report', async () => {
    expect(await resolveBrowserRedirectStrict(reportEnv, 'https://some-startup.example/auth/callback', opts)).toEqual({
      url: null,
      outcome: 'refused',
      host: 'some-startup.example',
    })
  })

  it('accepts what the policy accepts, under either setting', async () => {
    for (const env of [enforceEnv, reportEnv]) {
      expect(await resolveBrowserRedirectStrict(env, 'https://management.studio/api/auth/callback', opts)).toEqual({
        url: 'https://management.studio/api/auth/callback',
        outcome: 'accepted',
      })
      expect(await resolveBrowserRedirectStrict(env, '/dash/profile', opts)).toEqual({ url: '/dash/profile', outcome: 'accepted' })
    }
  })

  it('refuses injection shapes and reports none for nothing', async () => {
    for (const bad of ['//evil.com', 'javascript:alert(1)', 'https://evil.com/\nx']) {
      expect((await resolveBrowserRedirectStrict(reportEnv, bad, opts)).outcome, bad).toBe('refused')
    }
    expect(await resolveBrowserRedirectStrict(reportEnv, '', opts)).toEqual({ url: null, outcome: 'none' })
  })
})

// ── H3: the open redirect on /login?continue= and /logout?return_url= ────────
//
// Production ran LOGIN_CONTINUE_POLICY=report (any https URL followed), and
// even `enforce` accepted the origin of ANY registered client's redirect_uri,
// while registration (RFC 7591) is open. Now: enforce in code and config, and
// a client's redirect URIs count only for the client in the flow, by exact
// match, and only when that client is established (an operator-seeded trusted
// client on the browser routes; an authenticated, listed client on
// /api/magic-link). Never any registered client's origin.
describe('H3: no open redirect on /login?continue= and /logout?return_url=', () => {
  const oauth = () => env.IDENTITY.get(env.IDENTITY.idFromName('oauth')) as unknown as { oauthStorageOp(op: unknown): Promise<unknown> }

  async function register(redirectUris: string[]): Promise<string> {
    const res = await SELF.fetch(`${BASE}/oauth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_name: 'h3-attacker', redirect_uris: redirectUris, token_endpoint_auth_method: 'none' }),
    })
    expect(res.status).toBe(201)
    return ((await res.json()) as { client_id: string }).client_id
  }

  async function putClient(id: string, redirectUris: string[], trusted: boolean): Promise<void> {
    await oauth().oauthStorageOp({
      op: 'put',
      key: `client:${id}`,
      value: { id, name: id, redirectUris, grantTypes: ['authorization_code'], responseTypes: ['code'], scopes: ['openid'], trusted, tokenEndpointAuthMethod: 'none', createdAt: 0 },
    })
  }

  /** The continue /login binds into the WorkOS state (what /api/callback follows). */
  async function loginContinue(cont: string, extra = ''): Promise<string> {
    const res = await SELF.fetch(`${BASE}/login?provider=GitHubOAuth&continue=${encodeURIComponent(cont)}${extra}`, { redirect: 'manual' })
    expect(res.status).toBe(302)
    return decodeState(new URL(res.headers.get('location')!).searchParams.get('state')!).continue
  }

  async function logoutTo(returnUrl: string): Promise<string | null> {
    const res = await SELF.fetch(`${BASE}/logout?return_url=${encodeURIComponent(returnUrl)}`, { redirect: 'manual' })
    expect(res.status).toBe(302)
    return res.headers.get('location')
  }

  it('production config enforces (worker/wrangler.jsonc), and so does the code default', () => {
    expect(continuePolicy(baseEnv)).toBe('enforce')
    expect(continuePolicy({ ...baseEnv, LOGIN_CONTINUE_POLICY: undefined } as Env)).toBe('enforce')
    expect(continuePolicy({ ...baseEnv, LOGIN_CONTINUE_POLICY: '' } as Env)).toBe('enforce')
  })

  it('an unlisted absolute target lands on the safe default', async () => {
    expect(await loginContinue('https://evil.example/fake-consent')).toBe('/dash/profile')
    expect(await logoutTo('https://evil.example/fake-consent')).toBe('/')
  })

  it("registering a client no longer allowlists its redirect origin, on /login or /logout", async () => {
    await register(['https://h3-attacker.example/cb'])
    expect(await loginContinue('https://h3-attacker.example/fake-consent')).toBe('/dash/profile')
    expect(await loginContinue('https://h3-attacker.example/cb')).toBe('/dash/profile')
    expect(await logoutTo('https://h3-attacker.example/')).toBe('/')
  })

  it("naming the self-registered client in the flow does not help either, even with its exact redirect_uri", async () => {
    const id = await register(['https://h3-named.example/cb'])
    expect(await loginContinue('https://h3-named.example/cb', `&client_id=${id}`)).toBe('/dash/profile')
  })

  it('a client registered before the fix (legacy origin index) is not followed', async () => {
    await putClient('cid_h3_legacy', ['https://h3-legacy.example/cb'], false)
    await oauth().oauthStorageOp({ op: 'put', key: 'rp-origin:https://h3-legacy.example', value: { clientIds: ['cid_h3_legacy'] } })
    expect(await loginContinue('https://h3-legacy.example/cb')).toBe('/dash/profile')
    expect(await logoutTo('https://h3-legacy.example/cb')).toBe('/')
  })

  it("a trusted (operator-seeded) client in the flow continues to its exact redirect_uri, and nowhere else", async () => {
    await putClient('cid_h3_first_party', ['https://h3-first-party.example/auth/callback'], true)
    const extra = '&client_id=cid_h3_first_party'
    expect(await loginContinue('https://h3-first-party.example/auth/callback', extra)).toBe('https://h3-first-party.example/auth/callback')
    // Same origin, other path / extra query / other scheme: refused (exact match only).
    expect(await loginContinue('https://h3-first-party.example/elsewhere', extra)).toBe('/dash/profile')
    expect(await loginContinue('https://h3-first-party.example/auth/callback?next=/x', extra)).toBe('/dash/profile')
    expect(await loginContinue('http://h3-first-party.example/auth/callback', extra)).toBe('/dash/profile')
    // Without the client in the flow, its redirect_uri is just another unlisted host.
    expect(await loginContinue('https://h3-first-party.example/auth/callback')).toBe('/dash/profile')
    // Another client's id does not lend its redirect_uris.
    expect(await loginContinue('https://h3-first-party.example/auth/callback', '&client_id=cid_unknown')).toBe('/dash/profile')
  })

  it('the provider picker keeps the flow client so a client-bound continue survives the click', async () => {
    await putClient('cid_h3_picker', ['https://h3-picker.example/auth/callback'], true)
    const html = await (await SELF.fetch(`${BASE}/login?client_id=cid_h3_picker&continue=${encodeURIComponent('https://h3-picker.example/auth/callback')}`)).text()
    expect(html).toContain('client_id=cid_h3_picker')
    expect(html).toContain(encodeURIComponent('https://h3-picker.example/auth/callback'))
  })

  it('still accepts: same-origin relative paths, own origins, the request origin, and the explicit estate allowlist', async () => {
    expect(await loginContinue('/dash/keys')).toBe('/dash/keys')
    expect(await loginContinue('/oauth/authorize?client_id=x&state=y')).toBe('/oauth/authorize?client_id=x&state=y')
    for (const own of ['https://id.org.ai/dash', 'https://oauth.do/x', 'https://auth.org.ai/y', 'https://auth.headless.ly/z']) {
      expect(await loginContinue(own), own).toBe(own)
    }
    for (const listed of ['https://startup.games/after-login', 'https://management.studio/api/auth/callback', 'https://sdb.dotdo.workers.dev/', 'https://api.sb/', 'https://mcp.sb/']) {
      expect(await loginContinue(listed), listed).toBe(listed)
      expect(await logoutTo(listed), listed).toBe(listed)
    }
    // A request served on another of this worker's hosts may continue on that host.
    const res = await SELF.fetch(`https://auth.headless.ly/logout?return_url=${encodeURIComponent('https://auth.headless.ly/after')}`, { redirect: 'manual' })
    expect(res.headers.get('location')).toBe('https://auth.headless.ly/after')
  })

  it('unit: resolveContinue never consults the registered-client origin index', async () => {
    await putClient('cid_h3_unit', ['https://h3-unit.example/cb'], false)
    await oauth().oauthStorageOp({ op: 'put', key: 'rp-origin:https://h3-unit.example', value: { clientIds: ['cid_h3_unit'] } })
    expect(await resolveBrowserRedirect(baseEnv, 'https://h3-unit.example/cb', { requestOrigin: BASE })).toEqual({ url: null, outcome: 'refused', host: 'h3-unit.example' })
    // Exact-match redirect URIs handed in by the caller (an established client) are accepted.
    expect(
      await resolveBrowserRedirect(baseEnv, 'https://h3-unit.example/cb', { requestOrigin: BASE, clientRedirectUris: ['https://h3-unit.example/cb'] }),
    ).toEqual({ url: 'https://h3-unit.example/cb', outcome: 'accepted' })
    expect(
      (await resolveBrowserRedirect(baseEnv, 'https://h3-unit.example/other', { requestOrigin: BASE, clientRedirectUris: ['https://h3-unit.example/cb'] })).outcome,
    ).toBe('refused')
  })
})
