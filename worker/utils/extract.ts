/**
 * Credential extraction utilities.
 * Pure functions for extracting API keys and session tokens from incoming requests.
 */

export function isApiKeyPrefix(s: string): boolean {
  return s.startsWith('oai_') || s.startsWith('hly_sk_') || s.startsWith('sk_')
}

export function extractApiKey(request: Request): string | null {
  const header = request.headers.get('x-api-key')
  if (header && isApiKeyPrefix(header)) return header
  const auth = request.headers.get('authorization')
  if (auth?.startsWith('Bearer ')) {
    const token = auth.slice(7)
    if (isApiKeyPrefix(token)) return token
  }
  try {
    const url = new URL(request.url)
    const keyParam = url.searchParams.get('api_key')
    if (keyParam && isApiKeyPrefix(keyParam)) return keyParam
  } catch {
    /* ignore */
  }
  return null
}

/**
 * Extract the session token from a request (ses_* prefix).
 */
export function extractSessionToken(request: Request): string | null {
  const auth = request.headers.get('authorization')
  if (auth?.startsWith('Bearer ses_')) return auth.slice(7)
  return null
}
