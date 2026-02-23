/**
 * JWT decode + claim assertions for E2E tests.
 *
 * Handles chunked cookies (auth.0, auth.1, ...) and
 * verifies camelCase claims + nested org object.
 */

import { expect } from 'vitest'

/**
 * Extract the JWT from a Set-Cookie header array or cookie string.
 * Handles both single `auth=...` and chunked `auth.0=...; auth.1=...` formats.
 */
export function extractJwtFromCookies(cookies: string | string[]): string {
  const cookieStr = Array.isArray(cookies) ? cookies.join('; ') : cookies

  // Try single auth cookie first
  const single = cookieStr.match(/(?:^|;\s*)auth=([^;]+)/)
  if (single) return decodeURIComponent(single[1])

  // Try chunked cookies (auth.0, auth.1, ...)
  let result = ''
  for (let i = 0; ; i++) {
    const chunk = cookieStr.match(new RegExp(`(?:^|;\\s*)auth\\.${i}=([^;]+)`))
    if (!chunk) break
    result += decodeURIComponent(chunk[1])
  }

  if (!result) throw new Error('No auth cookie found in cookies')
  return result
}

/**
 * Decode a JWT payload without verification (for E2E claim inspection).
 * In E2E tests we trust the server — we just want to inspect the claims.
 */
export function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split('.')
  if (parts.length !== 3) throw new Error(`Invalid JWT format: expected 3 parts, got ${parts.length}`)

  const payload = parts[1]
  const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4)
  const decoded = atob(padded.replace(/-/g, '+').replace(/_/g, '/'))
  return JSON.parse(decoded) as Record<string, unknown>
}

/**
 * Extract and decode JWT claims from cookie headers.
 */
export function decodeJwtFromCookies(cookies: string | string[]): Record<string, unknown> {
  const jwt = extractJwtFromCookies(cookies)
  return decodeJwtPayload(jwt)
}

/**
 * Assert standard JWT claims are correct (camelCase, nested org, proper issuer).
 */
export function assertJwtClaims(claims: Record<string, unknown>) {
  // Standard claims
  expect(claims.sub).toBeTruthy()
  expect(claims.email).toBeTruthy()
  expect(claims.iss).toBe('https://id.org.ai')
  expect(claims.exp).toBeGreaterThan(Date.now() / 1000)

  // camelCase enforcement — these legacy snake_case fields must NOT be present
  expect(claims.org_id).toBeUndefined()
  expect(claims.github_id).toBeUndefined()

  // If org exists, it should be a nested object with id
  if (claims.org) {
    expect(claims.org).toHaveProperty('id')
    expect(typeof (claims.org as Record<string, unknown>).id).toBe('string')
  }
}

/**
 * Assert JWT has a valid GitHub ID claim (numeric string from WorkOS profile).
 */
export function assertGitHubIdClaim(claims: Record<string, unknown>) {
  expect(claims.githubId).toBeTruthy()
  // GitHub IDs are numeric strings
  expect(typeof claims.githubId).toBe('string')
  expect(Number(claims.githubId)).toBeGreaterThan(0)
}

/**
 * Assert the org claim is a properly nested object (not a flat org_id string).
 */
export function assertNestedOrgClaim(claims: Record<string, unknown>) {
  expect(claims.org).toBeTruthy()
  const org = claims.org as Record<string, unknown>
  expect(org.id).toBeTruthy()
  expect(typeof org.id).toBe('string')
  if (org.name) {
    expect(typeof org.name).toBe('string')
  }
}

/**
 * Collect Set-Cookie headers from a fetch response into a cookie jar string.
 */
export function collectSetCookies(response: Response): string {
  const setCookies: string[] = []
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'set-cookie') {
      // Extract just the name=value part (before the first ;)
      const nameValue = value.split(';')[0]
      setCookies.push(nameValue)
    }
  })
  return setCookies.join('; ')
}
