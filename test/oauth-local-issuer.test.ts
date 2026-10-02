/**
 * Local development never reaches production: with the WorkOS stub configured
 * (WORKOS_API_BASE on loopback) and a loopback request, the OAuth provider's
 * issuer is this server, so its sign-in and consent redirects stay local.
 * Anything else keeps https://id.org.ai. (PROGRESS.md, Incidents, phase 5.)
 */
import { describe, it, expect } from 'vitest'
import { env } from 'cloudflare:test'
import { createOAuthProvider } from '../worker/routes/oauth'
import type { Env } from '../worker/types'

const STUB = { WORKOS_API_BASE: 'http://127.0.0.1:8798' }
const withEnv = (extra: Partial<Env>) => ({ ...(env as unknown as Env), ...extra }) as Env

describe('the OAuth issuer in local development', () => {
  it('is the local server when the WorkOS stub is configured and the request is loopback', () => {
    expect(createOAuthProvider(withEnv(STUB), new Request('http://127.0.0.1:8797/oauth/authorize')).issuer).toBe('http://127.0.0.1:8797')
  })

  it('stays https://id.org.ai in production, for a non-loopback request, and without a request', () => {
    expect(createOAuthProvider(withEnv({ WORKOS_API_BASE: undefined }), new Request('http://127.0.0.1:8797/oauth/authorize')).issuer).toBe('https://id.org.ai')
    expect(createOAuthProvider(withEnv(STUB), new Request('https://id.org.ai/oauth/authorize')).issuer).toBe('https://id.org.ai')
    expect(createOAuthProvider(withEnv(STUB)).issuer).toBe('https://id.org.ai')
  })

  it('an unauthenticated authorize request is sent to the local sign-in, not production', async () => {
    const provider = createOAuthProvider(withEnv(STUB), new Request('http://127.0.0.1:8797/oauth/authorize'))
    const reg = await provider.handleRegister(
      new Request('http://127.0.0.1:8797/oauth/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ client_name: 'Local', redirect_uris: ['http://127.0.0.1:9999/cb'], token_endpoint_auth_method: 'none' }),
      }),
    )
    const clientId = ((await reg.json()) as { client_id: string }).client_id
    const u = new URL('http://127.0.0.1:8797/oauth/authorize')
    for (const [k, v] of Object.entries({ response_type: 'code', client_id: clientId, redirect_uri: 'http://127.0.0.1:9999/cb', code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256' })) u.searchParams.set(k, v)
    const res = await provider.handleAuthorize(new Request(u.toString()), null)
    expect(res.status).toBe(302)
    expect(new URL(res.headers.get('location')!).origin).toBe('http://127.0.0.1:8797')
  })
})
