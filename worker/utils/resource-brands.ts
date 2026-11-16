/**
 * Resource brands: the look id.org.ai gives a sign-in or consent page when the
 * request is for a resource the operators have listed here.
 *
 * A resource is the API a grant is bound to (RFC 8707, the `resource`
 * parameter on /oauth/authorize). Most requests name none, or one of our own,
 * and the pages look like id.org.ai. For a listed resource the pages show its
 * name and mark instead, because the person started at that product (for
 * example, adding the Auto.dev connector in Claude) and is signing in to it.
 *
 * Operator-seeded, like the trusted clients: an entry is added here by hand,
 * in a reviewed change. Nothing in a request can add one or supply any of its
 * text. The brand changes what a page looks like and nothing else: not which
 * client is verified, not what is granted, not where anyone is sent.
 *
 * Matching is by the exact https host of the resource. A look-alike host
 * (mcp.auto.dev.evil.com, evil-mcp.auto.dev), another scheme, a port, or
 * userinfo (https://mcp.auto.dev@evil.com) never matches; neither does
 * anything the URL parser would have to repair first (a backslash, whitespace).
 */
import type { AppBrandProps } from '../ui/components'

/** A listed resource's brand: a name, a monogram, a mark under /brand/ (worker/ui/static/brand/) and its home page. */
export type ResourceBrand = Required<AppBrandProps>

/** Resource host → brand. Lower-case hosts, no port. */
const RESOURCE_BRANDS: ReadonlyMap<string, ResourceBrand> = new Map([
  // Auto.dev's hosted MCP server. Chris Risner approved this entry on 2026-11-16.
  ['mcp.auto.dev', { name: 'Auto.dev', monogram: 'A', markUrl: '/brand/auto-dev.svg', href: 'https://auto.dev' }],
])

/** The brand for a `resource` value, or undefined: id.org.ai's own look. */
export function resourceBrand(resource: string | null | undefined): ResourceBrand | undefined {
  if (typeof resource !== 'string' || !resource.startsWith('https://')) return undefined
  // Characters a URL parser drops or rewrites (so what we read might not be what another reader sees), and userinfo.
  if (/[\s\\@\u0000-\u001f\u007f]/.test(resource)) return undefined
  let url: URL
  try {
    url = new URL(resource)
  } catch {
    return undefined
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.port) return undefined
  const brand = RESOURCE_BRANDS.get(url.hostname)
  return brand ? { ...brand } : undefined
}

/**
 * The brand for the sign-in page, from the continue URL /login already
 * validated: only when that URL is this origin's own /oauth/authorize and it
 * names exactly one resource, a listed one. Any other destination gets no
 * brand, whatever its query says.
 */
export function signInResourceBrand(continueUrl: string, requestOrigin: string): ResourceBrand | undefined {
  let url: URL
  try {
    url = new URL(continueUrl, requestOrigin)
  } catch {
    return undefined
  }
  if (url.origin !== requestOrigin || url.pathname !== '/oauth/authorize') return undefined
  const resources = url.searchParams.getAll('resource')
  return resources.length === 1 ? resourceBrand(resources[0]) : undefined
}
