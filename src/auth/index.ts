/**
 * Auth utilities for id.org.ai
 *
 * Wraps WorkOS AuthKit for human authentication.
 * Custom AuthKit domain: id.org.ai
 */

export function buildAuthUrl(options: {
  redirectUri: string
  scope?: string
  state?: string
}): string {
  const url = new URL('https://id.org.ai/oauth/authorize')
  url.searchParams.set('redirect_uri', options.redirectUri)
  url.searchParams.set('scope', options.scope ?? 'openid profile email')
  url.searchParams.set('response_type', 'code')
  if (options.state) url.searchParams.set('state', options.state)
  return url.toString()
}
