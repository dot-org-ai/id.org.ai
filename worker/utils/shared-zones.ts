/**
 * Zones whose subdomains belong to different owners. The session cookie must
 * never be scoped to one of these (security review H4): `Domain=.svc.st` on
 * acme.svc.st would hand every other Startup on svc.st the bearer.
 * getRootDomain treats each as a public suffix, so a host directly under one
 * gets a host-only cookie and a deeper host shares only within its owner's
 * own subdomain (auth.acme.svc.st → .acme.svc.st).
 *
 * Three groups:
 *   - multi-label public suffixes the estate's hosts sit under;
 *   - platform zones that serve many tenants or previews (workers.do custom
 *     hostnames, workers.dev, pages.dev);
 *   - the builder base zones, where Startups get `name.zone`. Source of truth:
 *     ~/projects/domains/data/builder.tsv (all classes, as of af15f99). A zone
 *     added there and not here falls back to the old parent-domain cookie, so
 *     keep this list in step, or extend it at deploy with
 *     SESSION_COOKIE_SHARED_ZONES (comma-separated).
 */

const PUBLIC_SUFFIXES = [
  'org.ai', 'com.ai', 'net.ai',
  'co.uk', 'com.au', 'co.jp',
  'com.se', 'co.lc', 'com.lc', 'co.at', 'co.bz', 'com.de',
  'gr.com', 'jp.net', 'hu.net', 'us.org', 'net.in', 'ac.nz', 'gen.nz',
]

const PLATFORM_SHARED_ZONES = ['workers.do', 'workers.dev', 'pages.dev']

const BUILDER_BASE_ZONES = [
  'io.sb', 'ful.st', 'kit.st', 'llc.st', 'management.st', 'mgmt.st', 'service.sn', 'svc.st',
  'api.sb', 'db.sb', 'directory.sb', 'hq.sb', 'mcp.sb', 'sh.sb', 'studio.sb',
  'do.com.se', 'api.net.ai', 'saas.ac', 'ist.com.se', 'ed.com.se', 'fy.com.se', 'ly.com.se', 'ty.com.se',
  'or.com.se', 'ion.com.se', 'ng.com.se', 'app.gr.com', 'studio.com.se', 'hq.com.se', 'kit.com.se',
  'research.com.se', 'directory.cafe', 'directory.com.se', 'ing.casa', 'app.jp.net', 'app.hu.net',
  'ing.us.org', 'ing.gr.com', 'ing.com.se', 'app.horse', 'cdn.land', 'edge.land', 'cdn.us.org',
  'gif.net.in', 'gif.com.se', 'icon.com.se', 'logo.com.se', 'mdx.land', 'chatbox.land', 'directory.cx',
  'app.com.se', 'inc.com.se', 'llc.com.se', 'games.com.se', 'db.net.ai', 'agint.land', 'hq.co.lc',
  'app.ac.nz', 'app.gen.nz', 'app.co.lc', 'app.com.lc', 'app.co.bz', 'site.com.lc', 'net.com.lc',
  'biz.com.lc', 'llc.com.lc', 'site.com.de', 'studio.com.de', 'inc.com.de', 'do.com.ai', 'hq.com.ai',
  'services.com.ai', 'cdn.net.ai', 'ing.com.ai', 'do.net.ai', 'example.com.ai', 'app.net.ai',
  'apí.com', 'aí.net', 'apí.dev', 'aí.studio', 'aüth.com', 'dëv.co', 'ïo.co', 'aï.co', 'apı.com',
  'apı.net', 'apı.dev', 'aı.dev', 'aı.app', 'ılıl.net', 'ılıl.com', 'ııl.com', '彡.studio', 'studỉo.com',
  'assocỉates.com', 'agỉ.com', 'servỉces.com', 'agentỉc.com', 'ỉdea.com', 'dỉrectory.com', 'solutỉons.com',
  'marketỉng.com', 'ỉng.com', 'ỉo.com', 'api.co.at', 'cdn.co.at', 'marketing.st', 'management.sh',
  'blogs.sh', 'agentic.services',
]

/** A zone as the Worker sees it in a request URL: lowercase, IDN labels in punycode. */
function asHostname(zone: string): string | null {
  try {
    return new URL(`https://${zone.trim()}/`).hostname
  } catch {
    return null
  }
}

function toSet(zones: readonly string[]): Set<string> {
  const out = new Set<string>()
  for (const z of zones) {
    const h = z.trim() ? asHostname(z) : null
    if (h) out.add(h)
  }
  return out
}

const DEFAULT_SHARED_ZONES: ReadonlySet<string> = toSet([...PUBLIC_SUFFIXES, ...PLATFORM_SHARED_ZONES, ...BUILDER_BASE_ZONES])

/** The shared zones, plus any a deploy adds through SESSION_COOKIE_SHARED_ZONES. */
export function sharedZones(extra?: string | null): ReadonlySet<string> {
  if (!extra) return DEFAULT_SHARED_ZONES
  return new Set([...DEFAULT_SHARED_ZONES, ...toSet(extra.split(','))])
}
