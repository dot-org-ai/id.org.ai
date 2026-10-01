/**
 * App-supplied URLs (CIMD policy_uri / tos_uri / logo_uri) render only when
 * they are https (spec/backend.md#b2, logos.md). CSP would stop javascript:
 * anyway; this keeps http: and anything else out of the markup altogether.
 */
export function httpsOnly(url: string | undefined): string | undefined {
  if (!url) return undefined
  try {
    return new URL(url).protocol === 'https:' ? url : undefined
  } catch {
    return undefined
  }
}

/** An image an app tile may load: an https logo_uri, or a first-party file under our own origin ("/brand/…"). */
export function safeImageUrl(url: string | undefined): string | undefined {
  if (url?.startsWith('/') && !url.startsWith('//')) return url
  return httpsOnly(url)
}
