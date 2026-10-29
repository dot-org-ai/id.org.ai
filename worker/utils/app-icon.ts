/**
 * An app's icon, read from its own site (logos.md: a declared logo_uri first, then the site's icon).
 *
 * For the apps that sign in through the one shared trusted-account client (TRUSTED_ACCOUNT_DOMAINS, ADR-0007): they
 * have no client metadata, so no logo_uri, but id.org.ai knows which of them sent the person (the host the code goes
 * back to). Only those hosts are ever fetched. The icon is the one the site's home page declares
 * (<link rel="icon"> or "apple-touch-icon"), an SVG first, then the largest; /favicon.ico when it declares none.
 * The answer, or that there is none, is cached in KV for a day; a failed fetch is not cached.
 */
import type { Env } from '../types'
import { parseTrustedAccountDomains } from '../routes/oauth'

const CACHE_TTL = 86400
const FETCH_TIMEOUT_MS = 1500
/** Enough of a home page to reach the end of its <head>. */
const HEAD_BYTES = 256 * 1024
/** A data: icon longer than this isn't an icon. */
const DATA_URI_MAX = 32 * 1024

const IMAGE_DATA_URI = /^data:image\/(svg\+xml|png|x-icon|vnd\.microsoft\.icon|jpeg|webp|gif)[;,]/i

function attr(tag: string, name: string): string | undefined {
  const m = tag.match(new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'))
  const v = m ? (m[1] ?? m[2] ?? m[3]) : undefined
  return v?.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
}

/** An icon URL an app tile can load: https, or an image data: URI of sane size. */
function usable(url: URL | string): string | undefined {
  const s = String(url)
  if (s.startsWith('https://')) return s
  return IMAGE_DATA_URI.test(s) && s.length <= DATA_URI_MAX ? s : undefined
}

/** The icon a page's <head> declares: SVG first, then the largest `sizes` (apple-touch-icon counts as 180). */
export function pickIcon(html: string, pageUrl: string): string | undefined {
  let best: { url: string; score: number } | undefined
  for (const [tag] of html.matchAll(/<link\b[^>]*>/gi)) {
    const rel = (attr(tag, 'rel') ?? '').toLowerCase().split(/\s+/)
    const touch = rel.includes('apple-touch-icon')
    if (!touch && !rel.includes('icon')) continue
    const href = attr(tag, 'href')
    if (!href) continue
    let url: string | undefined
    try {
      url = usable(new URL(href, pageUrl))
    } catch {
      continue
    }
    if (!url) continue
    const svg = /svg/i.test(attr(tag, 'type') ?? '') || /^data:image\/svg\+xml/i.test(url) || /\.svg(\?|#|$)/i.test(url)
    const size = Math.max(0, ...(attr(tag, 'sizes') ?? '').split(/\s+/).map((s) => Number(s.split(/x/i)[0]) || 0))
    const score = svg ? 1e6 : size || (touch ? 180 : 16)
    if (!best || score > best.score) best = { url, score }
  }
  return best?.url
}

/** The first HEAD_BYTES of a response, stopping early at </head>. */
async function headOf(res: Response): Promise<string> {
  const reader = res.body?.getReader()
  if (!reader) return ''
  const decoder = new TextDecoder()
  let text = ''
  while (text.length < HEAD_BYTES) {
    const { done, value } = await reader.read()
    if (done) break
    text += decoder.decode(value, { stream: true })
    if (/<\/head>/i.test(text)) break
  }
  await reader.cancel().catch(() => {})
  return text
}

/** The icon `host`'s site declares, when `host` is a trusted-account app; undefined otherwise or when it has none. */
export async function siteIcon(env: Env, host: string): Promise<string | undefined> {
  if (!parseTrustedAccountDomains(env.TRUSTED_ACCOUNT_DOMAINS).has(host)) return undefined
  const key = `app-icon:${host}`
  const cached = await env.SESSIONS.get(key)
  if (cached !== null) return cached || undefined
  try {
    const page = await fetch(`https://${host}/`, { headers: { accept: 'text/html' }, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) })
    let icon = page.ok ? pickIcon(await headOf(page), page.url || `https://${host}/`) : undefined
    if (!page.ok) await page.body?.cancel()
    if (!icon) {
      const ico = await fetch(`https://${host}/favicon.ico`, { method: 'HEAD', signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) })
      if (ico.ok && (ico.headers.get('content-type') ?? '').startsWith('image/')) icon = `https://${host}/favicon.ico`
    }
    await env.SESSIONS.put(key, icon ?? '', { expirationTtl: CACHE_TTL })
    return icon
  } catch {
    return undefined
  }
}
