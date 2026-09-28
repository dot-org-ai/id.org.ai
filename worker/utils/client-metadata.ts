/**
 * Fetch a Client ID Metadata Document (src/sdk/oauth/cimd.ts validates it).
 *
 * The client_id is chosen by whoever sends the authorization request, so this
 * is a caller-controlled outbound fetch. Guards (worker/utils/ssrf.ts posture):
 *   - https only, on a publicly routable host (no loopback / private /
 *     link-local / metadata addresses, no .local/.internal names);
 *   - no redirects (a public URL cannot bounce onto a private host, and the
 *     document must live at its own client_id);
 *   - CIMD_TIMEOUT_MS to answer, CIMD_MAX_BYTES of body, read incrementally so
 *     an endless body is cut off rather than buffered;
 *   - JSON only; no cookies or credentials are sent.
 * The provider caches the outcome (a failure for a minute), so one client_id
 * cannot make id.org.ai fetch in a loop.
 */
import { assertPublicHttpsUrl } from './ssrf'
import { CIMD_MAX_BYTES, CIMD_TIMEOUT_MS } from '../../src/sdk/oauth/cimd'
import type { ClientMetadataFetcher } from '../../src/sdk/oauth/provider'

async function readCapped(res: Response, maxBytes: number): Promise<string> {
  const declared = Number(res.headers.get('content-length') ?? '')
  if (Number.isFinite(declared) && declared > maxBytes) throw new Error('document too large')
  if (!res.body) return ''
  const reader = res.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > maxBytes) {
      await reader.cancel().catch(() => {})
      throw new Error('document too large')
    }
    chunks.push(value)
  }
  const all = new Uint8Array(total)
  let off = 0
  for (const c of chunks) {
    all.set(c, off)
    off += c.byteLength
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(all)
}

export const fetchClientMetadataDocument: ClientMetadataFetcher = async (clientId) => {
  let url: URL
  try {
    url = assertPublicHttpsUrl(clientId)
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'refused' }
  }
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), CIMD_TIMEOUT_MS)
  try {
    const res = await fetch(url.toString(), {
      method: 'GET',
      redirect: 'manual',
      signal: controller.signal,
      headers: { accept: 'application/json' },
    })
    if (res.status >= 300 && res.status < 400) return { ok: false, error: `redirect (HTTP ${res.status}) refused` }
    if (res.status !== 200) return { ok: false, error: `HTTP ${res.status}` }
    const type = (res.headers.get('content-type') ?? '').toLowerCase()
    if (type && !type.includes('json')) return { ok: false, error: `not JSON (${type.split(';')[0]})` }
    const text = await readCapped(res, CIMD_MAX_BYTES)
    let doc: unknown
    try {
      doc = JSON.parse(text)
    } catch {
      return { ok: false, error: 'not valid JSON' }
    }
    return { ok: true, doc, cacheControl: res.headers.get('cache-control') }
  } catch (err) {
    return { ok: false, error: controller.signal.aborted ? 'timed out' : err instanceof Error ? err.message : 'fetch failed' }
  } finally {
    clearTimeout(timer)
  }
}
