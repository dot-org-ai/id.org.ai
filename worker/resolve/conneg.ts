/**
 * conneg.ts — content negotiation for the GS1 Digital Link resolver door.
 *
 * HAND-PORTED (intentional fork, by-copy not by-gate) from
 * barcoding.dev/engine/src/resolver/conneg.js — the GS1-resolver-shaped
 * variant that models the json / jsonld / linkset faces ADR 0001 D2 needs.
 * The generic axp-faces three-face (html/json/md) does NOT carry jsonld or
 * linkset, so that package is deliberately NOT a dependency here (it is also
 * `private:true`, cross-repo, with no drift-gate target for id.org.ai).
 *
 * Estate conneg law (ruled 2026-07-31), on every GET: faces selected
 * deterministically —
 *   1. extension forces (.json .jsonld .linkset)  [.html/.md not served here]
 *   2. Accept header infers
 *   3. client-class defaults: browser (Sec-Fetch-*, never UA sniffing) → html
 *      (this resolver renders that as a 303 to the entry's defaultLink),
 *      known agent UAs → markdown, everything else incl. bare curl → json.
 *
 * NORMATIVE REFERENCE the port aligns to:
 *   axp.org.ai/packages/axp-faces/src/conneg.js (A.7 selectors).
 *
 * DRIFT: there is NO automated gate against either upstream (unlike axp-faces'
 * `vendor --check`). Tracked as a bd model-gap issue — accept as an intentional
 * fork or establish a cross-repo drift gate later.
 *
 * STAGE-1 SCOPE: `available` defaults to ['jsonld','json'] (+ 'html' handled by
 * the route as a 303). 'linkset' and 'md' are deliberately left out until the
 * RFC 9264 linkset stage lands (ADR 0001 D2, deferred + ticketed).
 *
 * Zero-dependency, Workers-safe.
 */

/** The full face vocabulary the estate conneg law models. */
export const FACES = Object.freeze(['html', 'md', 'json', 'jsonld', 'linkset'] as const)
export type Face = (typeof FACES)[number]

const EXT_FACE: Record<string, Face> = {
  '.html': 'html',
  '.md': 'md',
  '.json': 'json',
  '.jsonld': 'jsonld',
  '.linkset': 'linkset',
}

const AGENT_UA = /\b(claude|gpt|openai|anthropic|perplexity|gemini|copilot|llm|agent|langchain|mcp)\b/i

export interface NegotiateResult {
  face: Face
  cleanPath: string
  /** How the face was chosen — 'extension' | 'accept' | 'client-class (...)'. */
  forced: string
}

/**
 * negotiate(request, pathname, { available }) → { face, cleanPath, forced }.
 * `cleanPath` has any recognised face extension stripped.
 *
 * STAGE-1 default `available` = ['jsonld','json','html']: html is a legal
 * outcome (the route maps it to a 303), but there is no .html face body here.
 */
export function negotiate(
  request: Request,
  pathname: string,
  { available = ['html', 'jsonld', 'json'] as Face[] }: { available?: Face[] } = {},
): NegotiateResult {
  // 1. extension forces
  for (const [ext, face] of Object.entries(EXT_FACE)) {
    if (pathname.endsWith(ext) && available.includes(face)) {
      return { face, cleanPath: pathname.slice(0, -ext.length), forced: 'extension' }
    }
  }

  // 2. Accept header infers (most specific first)
  const accept = request.headers.get('accept') ?? ''
  if (/application\/linkset\+json/.test(accept) && available.includes('linkset')) {
    return { face: 'linkset', cleanPath: pathname, forced: 'accept' }
  }
  if (/application\/ld\+json/.test(accept) && available.includes('jsonld')) {
    return { face: 'jsonld', cleanPath: pathname, forced: 'accept' }
  }
  if (/text\/markdown/.test(accept) && available.includes('md')) {
    return { face: 'md', cleanPath: pathname, forced: 'accept' }
  }
  if (/text\/html/.test(accept) && available.includes('html')) {
    return { face: 'html', cleanPath: pathname, forced: 'accept' }
  }
  if (/application\/json/.test(accept) && available.includes('json')) {
    return { face: 'json', cleanPath: pathname, forced: 'accept' }
  }

  // 3. client-class defaults
  const secFetchMode = request.headers.get('sec-fetch-mode')
  const dest = request.headers.get('sec-fetch-dest')
  if ((secFetchMode === 'navigate' || dest === 'document') && available.includes('html')) {
    return { face: 'html', cleanPath: pathname, forced: 'client-class (browser via Sec-Fetch)' }
  }
  const ua = request.headers.get('user-agent') ?? ''
  if (AGENT_UA.test(ua) && available.includes('md')) {
    return { face: 'md', cleanPath: pathname, forced: 'client-class (agent UA)' }
  }
  // Default: JSON-LD when it is the identity face on offer, else JSON.
  if (available.includes('jsonld')) {
    return { face: 'jsonld', cleanPath: pathname, forced: 'client-class (default → jsonld)' }
  }
  return { face: 'json', cleanPath: pathname, forced: 'client-class (default)' }
}

export const FACE_CONTENT_TYPE: Readonly<Record<Face, string>> = Object.freeze({
  html: 'text/html; charset=utf-8',
  md: 'text/markdown; charset=utf-8',
  json: 'application/json; charset=utf-8',
  jsonld: 'application/ld+json; charset=utf-8',
  linkset: 'application/linkset+json; charset=utf-8',
})

const ALTERNATE_TYPE: Record<Face, string> = {
  html: 'text/html',
  md: 'text/markdown',
  json: 'application/json',
  jsonld: 'application/ld+json',
  linkset: 'application/linkset+json',
}

/**
 * Link rel="alternate" header advertising the sibling faces. `html` is not
 * advertised as a `.html` extension address (it is the redirect face), so it
 * is emitted against the bare cleanPath.
 */
export function alternatesHeader(cleanPath: string, available: Face[]): string {
  return available
    .map((f) => {
      const href = f === 'html' ? cleanPath : `${cleanPath}.${f}`
      return `<${href}>; rel="alternate"; type="${ALTERNATE_TYPE[f]}"`
    })
    .join(', ')
}
