/**
 * Resource brands (worker/utils/resource-brands.ts): the one operator-seeded
 * entry, mcp.auto.dev → Auto.dev, and the pages that use it.
 *
 *   - Matching is by the exact https host of the `resource` parameter. A
 *     look-alike host, another scheme, userinfo or a port never gets a brand.
 *   - /login without a provider renders the new sign-in page. Its links are
 *     the same hrefs the old provider picker built (provider ids, forwarded
 *     params, encoding), and it is branded only when the continue URL is this
 *     origin's /oauth/authorize for the mapped resource.
 *   - Consent names the brand in the sentence, shows its mark, and keeps the
 *     real host in the details. The trust level is untouched.
 */
import { describe, it, expect } from 'vitest'
import { SELF } from 'cloudflare:test'
import { resourceBrand, signInResourceBrand } from '../worker/utils/resource-brands'
import { loginLinkHref, signInPageProps } from '../worker/ui/signin-props'
import { buildConsentViewModel } from '../src/sdk/oauth/consent-view'
import { consentProps } from '../worker/ui/consent-props'
import { Consent } from '../worker/ui/screens/Consent'
import { renderHtml } from '../worker/ui/render'

const BASE = 'https://id.org.ai'
const AUTO_DEV = { name: 'Auto.dev', monogram: 'A', markUrl: '/brand/auto-dev.svg', href: 'https://auto.dev' }

const authorize = (resource?: string, origin = BASE) =>
  `${origin}/oauth/authorize?response_type=code&client_id=${encodeURIComponent('https://claude.ai/oauth/client.json')}${resource === undefined ? '' : `&resource=${encodeURIComponent(resource)}`}`

/** Decode the entities hono/jsx writes into an attribute, as a browser does before following the link. */
const unescape = (s: string) => s.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>')
const hrefs = (html: string) => [...html.matchAll(/<a [^>]*href="(\/login\?[^"]*)"/g)].map((m) => unescape(m[1]!))
const h1 = (html: string) => unescape(html.match(/<h1[^>]*>(.*?)<\/h1>/s)?.[1] ?? '').replace(/<[^>]+>/g, '')

/**
 * The old picker's link, copied from worker/views/provider-picker.ts as it was
 * before this change (its `qs` test and its concatenation, character for character).
 */
function oldPickerHref(id: string, continueUrl: string, loginHint?: string, promptLogin = false, clientId?: string): string {
  const qs = continueUrl !== '/' ? `?continue=${encodeURIComponent(continueUrl)}` : ''
  return `/login?provider=${id}${qs ? '&continue=' + encodeURIComponent(continueUrl) : ''}${loginHint ? '&login_hint=' + encodeURIComponent(loginHint) : ''}${promptLogin ? '&prompt=login' : ''}${clientId ? '&client_id=' + encodeURIComponent(clientId) : ''}`
}
/** The old picker's five links in order: GitHub, Google, Microsoft, Apple, Email. */
const OLD_ORDER = ['GitHubOAuth', 'GoogleOAuth', 'authkit', 'authkit', 'authkit']

describe('resourceBrand: exact https host only', () => {
  it('maps mcp.auto.dev, as the origin or with a path', () => {
    for (const r of ['https://mcp.auto.dev', 'https://mcp.auto.dev/', 'https://mcp.auto.dev/mcp', 'https://MCP.Auto.Dev/mcp', 'https://mcp.auto.dev:443/mcp']) {
      expect(resourceBrand(r), r).toEqual(AUTO_DEV)
    }
  })

  it('has exactly one entry: no other auto.dev host, and no other resource, gets the brand', () => {
    for (const r of ['https://auto.dev', 'https://www.auto.dev', 'https://api.auto.dev', 'https://api.sb', 'https://id.org.ai/mcp', 'https://claude.ai']) {
      expect(resourceBrand(r), r).toBeUndefined()
    }
  })

  it('refuses look-alike hosts', () => {
    for (const r of [
      'https://mcp.auto.dev.evil.com',
      'https://mcp.auto.dev.evil.com/mcp',
      'https://evil-mcp.auto.dev',
      'https://evilmcp.auto.dev',
      'https://x.mcp.auto.dev',
      'https://mcp.auto.dev.',
      'https://mcp-auto.dev',
      'https://mcp.auto.dev.co',
      'https://mcp.auto.dеv', // Cyrillic е
      'https://evil.com/mcp.auto.dev',
      'https://evil.com/?https://mcp.auto.dev',
      'https://evil.com#https://mcp.auto.dev',
    ]) {
      expect(resourceBrand(r), r).toBeUndefined()
    }
  })

  it('refuses any scheme but https, a port, and userinfo', () => {
    for (const r of [
      'http://mcp.auto.dev',
      'http://mcp.auto.dev/mcp',
      'ftp://mcp.auto.dev',
      'javascript://mcp.auto.dev/%0aalert(1)',
      '//mcp.auto.dev',
      'mcp.auto.dev',
      'https://mcp.auto.dev:8443',
      'https://mcp.auto.dev@evil.com',
      'https://mcp.auto.dev:pw@evil.com',
      'https://evil.com@mcp.auto.dev',
      'https://user:pw@mcp.auto.dev/mcp',
      'https://mcp.auto.dev\\@evil.com',
      'https://evil.com\\@mcp.auto.dev',
      'https:\\\\mcp.auto.dev',
      ' https://mcp.auto.dev',
      'https://mcp.auto.dev\n',
      'https://mcp.auto.dev\t/mcp',
    ]) {
      expect(resourceBrand(r), JSON.stringify(r)).toBeUndefined()
    }
  })

  it('an absent or malformed resource means no brand', () => {
    for (const r of [undefined, null, '', 'not a url', 'https://', 'https:///mcp', '[]', 'https://[mcp.auto.dev]']) {
      expect(resourceBrand(r), String(r)).toBeUndefined()
    }
  })
})

describe('signInResourceBrand: only this origin’s /oauth/authorize, only its one resource', () => {
  it('reads the resource from an absolute or relative authorize URL on this origin', () => {
    expect(signInResourceBrand(authorize('https://mcp.auto.dev/mcp'), BASE)).toEqual(AUTO_DEV)
    expect(signInResourceBrand(authorize('https://mcp.auto.dev'), BASE)).toEqual(AUTO_DEV)
    expect(signInResourceBrand(`/oauth/authorize?resource=${encodeURIComponent('https://mcp.auto.dev/mcp')}`, BASE)).toEqual(AUTO_DEV)
  })

  it('no brand for another resource, no resource, or a look-alike', () => {
    for (const r of [undefined, '', 'https://api.sb', 'https://mcp.auto.dev.evil.com', 'http://mcp.auto.dev', 'https://evil.com@mcp.auto.dev']) {
      expect(signInResourceBrand(authorize(r), BASE), String(r)).toBeUndefined()
    }
  })

  it('no brand when the resource is named twice (which one would the grant bind?)', () => {
    const twice = `${authorize('https://mcp.auto.dev/mcp')}&resource=${encodeURIComponent('https://api.sb')}`
    expect(signInResourceBrand(twice, BASE)).toBeUndefined()
    expect(signInResourceBrand(`${authorize('https://mcp.auto.dev')}&resource=${encodeURIComponent('https://mcp.auto.dev')}`, BASE)).toBeUndefined()
  })

  it('no brand for any other destination, even one that mentions the resource', () => {
    const q = `resource=${encodeURIComponent('https://mcp.auto.dev/mcp')}`
    for (const cont of [
      `/dash/profile?${q}`,
      `/oauth/authorize/extra?${q}`,
      `/oauth/authorized?${q}`,
      `/OAuth/Authorize?${q}`,
      `/device?${q}`,
      `https://headless.ly/oauth/authorize?${q}`,
      `https://id.org.ai.evil.com/oauth/authorize?${q}`,
      `//evil.com/oauth/authorize?${q}`,
      `https://mcp.auto.dev/oauth/authorize?${q}`,
      '/dash/profile',
      '/',
      '',
      'not a url at all',
    ]) {
      expect(signInResourceBrand(cont, BASE), cont).toBeUndefined()
    }
    // The same authorize URL, reached on another origin than the one serving the page.
    expect(signInResourceBrand(authorize('https://mcp.auto.dev/mcp'), 'https://oauth.dotdo.workers.dev')).toBeUndefined()
    expect(signInResourceBrand(authorize('https://mcp.auto.dev/mcp', 'https://oauth.dotdo.workers.dev'), 'https://oauth.dotdo.workers.dev')).toEqual(AUTO_DEV)
  })
})

describe('sign-in links: the same hrefs the old picker built', () => {
  const cases: Array<[string, string, string | undefined, boolean, string | undefined]> = [
    ['the default destination', '/dash/profile', undefined, false, undefined],
    ['"/" (the old picker left continue off)', '/', undefined, false, undefined],
    ['"/" with a hint and prompt', '/', 'ada@example.com', true, undefined],
    ['a relative path with a query', '/device?user_code=ABCD-1234', undefined, false, undefined],
    ['an absolute authorize URL', authorize('https://mcp.auto.dev/mcp'), undefined, false, undefined],
    ['a hint with characters that need encoding', '/dash/profile', 'ada+tag@example.com', false, undefined],
    ['prompt=login', '/oauth/authorize?client_id=x', undefined, true, undefined],
    ['a flow client', 'https://h3-picker.example/auth/callback', undefined, false, 'cid_h3_picker'],
    ['everything at once, with a CIMD client_id', authorize('https://mcp.auto.dev'), 'ada+tag@example.com', true, 'https://claude.ai/oauth/client.json?a=1&b=2'],
    ['a continue with spaces, quotes and ampersands', '/dash/profile?q=a b&x="y"&z=<1>', 'o\'hara@example.com', false, undefined],
  ]

  it.each(cases)('%s', async (_name, cont, hint, prompt, clientId) => {
    for (const id of new Set(OLD_ORDER)) expect(loginLinkHref(id, cont, hint, prompt, clientId)).toBe(oldPickerHref(id, cont, hint, prompt, clientId))
    // And through the rendered page: email first, then GitHub, Google, Microsoft, Apple.
    const props = signInPageProps({ continueUrl: cont, loginHint: hint, promptLogin: prompt, clientId })
    const { SignIn } = await import('../worker/ui/screens/SignIn')
    const html = await renderHtml(SignIn(props), { title: 't' })
    const old = OLD_ORDER.map((id) => oldPickerHref(id, cont, hint, prompt, clientId))
    expect(hrefs(html)).toEqual([old[4], old[0], old[1], old[2], old[3]])
  })
})

describe('GET /login without a provider: the new sign-in page', () => {
  it('a bare /login is a 200 (the cron’s synthetic probe) with the id.org.ai look and the old links', async () => {
    const res = await SELF.fetch(`${BASE}/login`)
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toBe('text/html; charset=utf-8')
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(res.headers.get('x-frame-options')).toBe('DENY')
    expect(res.headers.get('content-security-policy')).toContain("frame-ancestors 'none'")
    const html = await res.text()
    expect(h1(html)).toBe('Sign in')
    expect(html).toContain('<title>Sign in · id.org.ai</title>')
    expect(hrefs(html)).toEqual(['authkit', 'GitHubOAuth', 'GoogleOAuth', 'authkit', 'authkit'].map((id) => oldPickerHref(id, '/dash/profile')))
    // No email form (POST /login/email doesn't exist), no brand, the usual footer.
    expect(html).not.toMatch(/<form/)
    expect(html).not.toContain('Auto.dev')
    expect(html).not.toContain('Secured by')
    expect(html).not.toContain('Choose a provider')
  })

  it('forwards continue, login_hint, prompt=login and a client-bound client_id exactly as before', async () => {
    const cont = '/oauth/authorize?client_id=x&scope=openid'
    const html = await (await SELF.fetch(`${BASE}/login?prompt=login&login_hint=${encodeURIComponent('ada+tag@example.com')}&continue=${encodeURIComponent(cont)}`)).text()
    expect(hrefs(html)).toEqual(['authkit', 'GitHubOAuth', 'GoogleOAuth', 'authkit', 'authkit'].map((id) => oldPickerHref(id, cont, 'ada+tag@example.com', true)))
    // A client_id that didn't let the continue through isn't kept (auth.ts).
    const stray = await (await SELF.fetch(`${BASE}/login?client_id=cid_nobody&continue=%2Fdash%2Fprofile`)).text()
    expect(stray).not.toContain('cid_nobody')
    // An unsafe login_hint is dropped, an unsafe continue falls back.
    const unsafe = await (await SELF.fetch(`${BASE}/login?login_hint=${encodeURIComponent('"><script>')}&continue=${encodeURIComponent('https://evil.com')}`)).text()
    expect(hrefs(unsafe)).toEqual(['authkit', 'GitHubOAuth', 'GoogleOAuth', 'authkit', 'authkit'].map((id) => oldPickerHref(id, '/dash/profile')))
  })

  it('is branded Auto.dev for this origin’s authorize request for mcp.auto.dev', async () => {
    for (const resource of ['https://mcp.auto.dev/mcp', 'https://mcp.auto.dev']) {
      const cont = authorize(resource)
      const html = await (await SELF.fetch(`${BASE}/login?continue=${encodeURIComponent(cont)}`)).text()
      expect(h1(html)).toBe('Sign in to Auto.dev')
      expect(html).toContain('<title>Sign in to Auto.dev · id.org.ai</title>')
      expect(html).toContain('Sign in to connect Auto.dev to your AI assistant.')
      expect(html).toContain('Secured by')
      expect(html).toContain('src="/brand/auto-dev.svg"')
      expect(html).not.toContain('.do apps')
      // The links are the old ones: branding changes the look, not where anything goes.
      expect(hrefs(html)).toEqual(['authkit', 'GitHubOAuth', 'GoogleOAuth', 'authkit', 'authkit'].map((id) => oldPickerHref(id, cont)))
    }
  })

  it('is not branded for any other resource, a look-alike, or a request that only supplies text', async () => {
    const q = (resource: string) => `${BASE}/login?continue=${encodeURIComponent(authorize(resource))}`
    for (const url of [
      q('https://api.sb'),
      q('https://mcp.auto.dev.evil.com/mcp'),
      q('https://evil-mcp.auto.dev'),
      q('http://mcp.auto.dev/mcp'),
      q('https://evil.com@mcp.auto.dev'),
      `${BASE}/login?continue=${encodeURIComponent(authorize())}`,
      // Not an authorize request: the resource, a brand or a name in the query changes nothing.
      `${BASE}/login?continue=${encodeURIComponent('/dash/profile?resource=https://mcp.auto.dev')}`,
      `${BASE}/login?resource=${encodeURIComponent('https://mcp.auto.dev/mcp')}&brand=Auto.dev&name=Auto.dev&app=Auto.dev`,
    ]) {
      const html = await (await SELF.fetch(url)).text()
      expect(h1(html), url).toBe('Sign in')
      expect(html, url).not.toContain('Sign in to Auto.dev')
      expect(html, url).not.toContain('/brand/')
      expect(html, url).not.toContain('Secured by')
    }
  })
})

describe('consent for a branded resource', () => {
  const REDIRECT = 'https://claude.ai/api/mcp/auth_callback'
  const CLAUDE = 'https://claude.ai/oauth/client.json'

  function props(resource: string | undefined, verified: boolean) {
    const vm = buildConsentViewModel({
      client: { id: CLAUDE, name: 'Claude', redirectUris: [REDIRECT], grantTypes: ['authorization_code'], responseTypes: ['code'], scopes: [], trusted: false, tokenEndpointAuthMethod: 'none', createdAt: 0 },
      verifiedHosts: new Set(verified ? ['claude.ai'] : []),
      redirectUri: REDIRECT,
      scopes: ['openid', 'profile', 'email', 'offline_access'],
      state: 's',
      codeChallenge: 'c',
      codeChallengeMethod: 'S256',
      resource,
      identityId: 'unused',
    })
    return consentProps(vm, { account: { name: 'Ada Lovelace', email: 'ada@example.com' }, workspaces: [], switchHref: '/login?prompt=login', fields: vm.fields, csrf: 'tok' })
  }
  const page = async (resource: string | undefined, verified: boolean) => renderHtml(Consent(props(resource, verified)), { title: 't' })
  const details = (html: string) => [...html.matchAll(/<div class="id-kv[^"]*">(.*?)<\/div>/gs)].map((m) => unescape(m[1]!.replace(/<[^>]+>/g, '|')).split('|').filter(Boolean).join(': '))

  it('names Auto.dev in the sentence, shows its mark, and keeps the real host in the details', async () => {
    const html = await page('https://mcp.auto.dev/mcp', true)
    expect(h1(html)).toBe('Claude wants to use Auto.dev as you')
    expect(html).toContain('src="/brand/auto-dev.svg"')
    expect(details(html)).toContain('Resource: mcp.auto.dev')
    // The form still posts the resource the request named, untouched.
    expect(html).toContain('name="resource" value="https://mcp.auto.dev/mcp"')
  })

  it('leaves the trust level alone: an unverified client still gets its host, the warning and Verified: No', async () => {
    const html = await page('https://mcp.auto.dev/mcp', false)
    expect(h1(html)).toBe('claude.ai wants to use Auto.dev as you')
    expect(html).toContain('can’t vouch for this app')
    expect(details(html)).toContain('Verified: No')
    expect(details(html)).toContain('Resource: mcp.auto.dev')
    expect(html).not.toContain('>Claude<')
  })

  it('any other resource, a look-alike or none renders exactly as before', async () => {
    for (const [resource, shown] of [
      ['https://api.sb', 'api.sb'],
      ['https://mcp.auto.dev.evil.com/mcp', 'mcp.auto.dev.evil.com'],
      ['http://mcp.auto.dev/mcp', 'mcp.auto.dev'],
      [undefined, 'id.org.ai'],
    ] as const) {
      const p = props(resource, true)
      expect(p.resourceBrand, String(resource)).toBeUndefined()
      const html = await renderHtml(Consent(p), { title: 't' })
      expect(h1(html)).toBe(`Claude wants to use ${shown} as you`)
      expect(html).not.toContain('/brand/')
      expect(html).not.toContain('Auto.dev')
      expect(details(html).some((d) => d.startsWith('Resource:'))).toBe(false)
    }
  })
})
