/**
 * Sign-in / sign-out destination policy beyond PR #27's allowlist:
 *
 *   - LOGIN_CONTINUE_HOSTS: config-listed estate hosts (exact, or `*.suffix`).
 *   - LOGIN_CONTINUE_POLICY=report: a syntactically safe absolute target
 *     outside the policy is still followed (the pre-policy behaviour) and
 *     reported, so estate callers can be listed before enforcing.
 *   - /logout?return_url= goes through the same policy as /login?continue=.
 *
 * The suite runs with LOGIN_CONTINUE_POLICY=enforce (vitest.config.ts);
 * `report` is exercised by passing an env override to the route module.
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

  it("a registered client's redirect origin is a valid sign-out target (api.sb's ?everywhere)", async () => {
    const reg = await SELF.fetch(`${BASE}/oauth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_name: 'logout-rp', redirect_uris: ['https://logout-rp.example/auth/callback'] }),
    })
    expect(reg.status).toBe(201)
    expect(await logoutTo('https://logout-rp.example/')).toBe('https://logout-rp.example/')
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
