/**
 * resolve.ts — the public, anonymous-first GS1 Digital Link resolver door
 * (ADR 0001 stage 1 + Phase-4 registry expansion).
 *
 * Additive to the shipped `oauth` worker: mounted BEFORE `authenticateRequest`
 * so it is keyless-first-value. Owns:
 *   GET /vin/{vin}
 *   GET /01/{gtin}[/21/{serial}]
 *   GET /00/{sscc}  /414/{gln}  /8004/{giai}  /8003/{grai}  /253/{gdti}   (Phase-4)
 *   GET /.well-known/gs1resolver                                          (Phase-4)
 *
 * Flow per request:
 *   parse + validate identifier  → typed 400 on bad grammar / check digit
 *   registry lookup (PORT)       → a ResolvedManifest joins owner/linkset/policy;
 *                                   a miss (or the unprovisioned default) keeps
 *                                   the existence-neutral self-derived doc
 *   linkType dispatch            → ?linkType=linkset|all or
 *                                   Accept: application/linkset+json → 200 RFC 9264
 *                                   linkset (no redirect); ?linkType=id:* → typed stub
 *   content-negotiate (ported)   → 200 JSON-LD identity doc; browser/text-html →
 *                                   303 See Other to the resolved defaultLink when
 *                                   a manifest carries one, else the documented
 *                                   html→jsonld fallback
 *   Who                          → broker.identify(req); attach only when a
 *                                   credential resolves (L0 anonymous omits it)
 *   capture                      → conservative stamp, no-op sink (never G5)
 *
 * PHASE-4: the resolver reads owner/linkset/defaultLink THROUGH the RegistryPort
 * (injected; the production singleton keeps the honest `emptyRegistryPort` until
 * the live binding is provisioned — RAILS). When the registry is unprovisioned
 * the door behaves EXACTLY as stage-1 (the shipped resolve.test.ts is green).
 *
 * The response never 406s. Every JSON face carries Content-Type, a Vary over the
 * conneg inputs + credential headers, and a Link rel="alternate".
 */
import { Hono } from 'hono'
import type { Context } from 'hono'
import type { Env, Variables } from '../types'
import type { Identity, IdentityStub } from '../../src/sdk/types'
import { AuthBrokerImpl } from '../../src/sdk/auth/broker-impl'
import {
  negotiate,
  alternatesHeader,
  FACE_CONTENT_TYPE,
  type Face,
  type NegotiateResult,
} from '../resolve/conneg'
import {
  isVinShape,
  vinVerify,
  mod10Verify,
  parseDlPath,
  parseDlKey,
  type Grain,
} from '../resolve/identifiers'
import {
  buildVinDoc,
  buildGtinDoc,
  buildKeyDoc,
  keyCanonicalUri,
  vinCanonicalUri,
  dlCanonicalUri,
  type WhoBlock,
} from '../resolve/jsonld'
import { stampResolve } from '../resolve/capture'
import { buildLinkset, buildLinkTypeStub, isIdLinkType } from '../resolve/linkset'
import { buildResolverDescription } from '../resolve/wellknown'
import { emptyRegistryPort, type RegistryPort, type ResolvedManifest } from '../registry/port'

// ── Typed resolver error surface (contract-specified nested shape) ─────────
type ResolverErrorCode = 'CONFORMANCE' | 'CHECKSUM_FAIL'

type ResolveContext = Context<{ Bindings: Env; Variables: Variables }>

function resolverError(c: ResolveContext, code: ResolverErrorCode, message: string, hint: string) {
  return c.json({ error: { code, message, hint } }, 400)
}

// ── Conneg availability ─────────────────────────────────────────────────────
// html is a legal outcome (→ 303 when a manifest carries a defaultLink, else the
// documented jsonld fallback). Phase-4 enables the linkset face.
const STAGE1_AVAILABLE: Face[] = ['html', 'jsonld', 'json', 'linkset']
const ADVERTISED_FACES: Face[] = ['jsonld', 'json', 'linkset']

const VARY = 'Accept, Sec-Fetch-Mode, Sec-Fetch-Dest, User-Agent, Authorization, Cookie'

const NO_STUB = {
  validateApiKey: async () => ({ valid: false }),
  getSession: async () => ({ valid: false }),
  getIdentity: async () => null,
  getAgent: async () => null,
  touchAgent: async () => {},
  checkRateLimit: async () => ({ allowed: true, remaining: 0, resetAt: 0 }),
} as unknown as IdentityStub

async function resolveWho(c: ResolveContext): Promise<Identity | null> {
  try {
    const stub = c.get('identityStub') as IdentityStub | undefined
    const resolvedId = c.get('resolvedIdentityId') as string | undefined
    const broker = new AuthBrokerImpl({
      stubFor: () => stub ?? NO_STUB,
      verifyJwt: async () => (resolvedId ? { identityId: resolvedId } : null),
    })
    const identity = await broker.identify(c.req.raw)
    return identity.id === 'anon' ? null : identity
  } catch {
    return null
  }
}

function whoBlock(identity: Identity): WhoBlock {
  const $type: WhoBlock['$type'] =
    identity.type === 'human'
      ? 'Person'
      : identity.type === 'agent' || identity.type === 'service'
        ? 'SoftwareAgent'
        : 'Organization'
  return { $type, identifier: identity.id, level: identity.level }
}

/**
 * The resolved 303 target for a manifest's defaultLink: the href of the link
 * whose relation matches `defaultLink`. Returns null when no target resolves
 * (then the html face keeps the documented jsonld fallback).
 */
function resolveDefaultTarget(manifest: ResolvedManifest): string | null {
  const want = manifest.defaultLink
  const hit = manifest.linkset.links.find((l) => l.linkType === want)
  return hit ? hit.href : null
}

function baseHeaders(c: ResolveContext, canonical: string, personalized: boolean, bodyFace: Face) {
  c.header('Content-Type', FACE_CONTENT_TYPE[bodyFace])
  c.header('Vary', VARY)
  c.header('Link', `<${canonical}>; rel="canonical", ${alternatesHeader(canonical, ADVERTISED_FACES)}`)
  // A who-bearing response MUST NOT be shared-cached; the anonymous
  // keyless-first-value document is safe to cache publicly.
  c.header('Cache-Control', personalized ? 'private, no-store' : 'public, max-age=3600')
}

/**
 * Emit the negotiated identity face. When html is negotiated AND a manifest
 * carries a resolvable defaultLink, emit a real 303 See Other to that target
 * (closing the stage-1 html→jsonld fallback for provisioned records). Otherwise
 * html falls back to the jsonld body, as documented. Never 406.
 */
function emitFace(
  c: ResolveContext,
  neg: NegotiateResult,
  canonical: string,
  doc: unknown,
  personalized: boolean,
  manifest?: ResolvedManifest,
) {
  if (neg.face === 'html') {
    const target = manifest ? resolveDefaultTarget(manifest) : null
    if (target) {
      // The abstract identifier is not the page — 303 See Other to gs1:defaultLink.
      c.header('Vary', VARY)
      c.header('Cache-Control', personalized ? 'private, no-store' : 'public, max-age=3600')
      return c.redirect(target, 303)
    }
    // Declared narrowing: no defaultLink target -> serve the identity face.
    baseHeaders(c, canonical, personalized, 'jsonld')
    c.header('X-Resolver-Fallback', 'html->jsonld (no registry defaultLink target, ADR 0001 D2)')
    return c.body(JSON.stringify(doc, null, 2), 200)
  }
  const bodyFace: Face = neg.face
  baseHeaders(c, canonical, personalized, bodyFace)
  return c.body(JSON.stringify(doc, null, 2), 200)
}

/**
 * The shared finisher for every resolved identifier. Reads the manifest through
 * the injected registry, dispatches the ?linkType / linkset faces, resolves Who,
 * builds the doc via `docFor`, stamps the capture, and emits.
 */
async function finish(
  c: ResolveContext,
  registry: RegistryPort,
  key: string,
  grain: Grain,
  canonical: string,
  routePath: string,
  docFor: (who: WhoBlock | undefined, manifest: ResolvedManifest | undefined) => unknown,
) {
  const lookup = await registry.lookup(key, grain)
  const manifest = lookup.found ? lookup.manifest : undefined

  // ?linkType dispatch (independent of Accept): linkset / all / id:* faces.
  const linkType = new URL(c.req.url).searchParams.get('linkType')
  const neg = negotiate(c.req.raw, routePath, { available: STAGE1_AVAILABLE })

  const who = await resolveWho(c)
  const personalized = who !== null
  stampResolve(canonical, who ? who.id : 'anon')

  // Linkset face — ?linkType=linkset|all OR Accept: application/linkset+json.
  if (linkType === 'linkset' || linkType === 'all' || neg.face === 'linkset') {
    const body = buildLinkset(canonical, manifest)
    c.header('Content-Type', FACE_CONTENT_TYPE.linkset)
    c.header('Vary', VARY)
    c.header('Cache-Control', personalized ? 'private, no-store' : 'public, max-age=3600')
    return c.body(JSON.stringify(body, null, 2), 200)
  }

  // Extended id:* typed stub faces — each an addressable draft-superset envelope.
  if (linkType && isIdLinkType(linkType)) {
    const stub = buildLinkTypeStub(linkType, canonical, manifest)
    c.header('Content-Type', FACE_CONTENT_TYPE.json)
    c.header('Vary', VARY)
    c.header('Cache-Control', personalized ? 'private, no-store' : 'public, max-age=3600')
    return c.body(JSON.stringify(stub, null, 2), 200)
  }

  const doc = docFor(who ? whoBlock(who) : undefined, manifest)
  return emitFace(c, neg, canonical, doc, personalized, manifest)
}

export function createResolveApp(deps: { registry?: RegistryPort } = {}) {
  const registry = deps.registry ?? emptyRegistryPort()
  const app = new Hono<{ Bindings: Env; Variables: Variables }>()

  // ── /.well-known/gs1resolver — the resolver description doc ──────────────
  app.get('/.well-known/gs1resolver', (c) => {
    const desc = buildResolverDescription()
    return c.json(desc, 200, { 'Cache-Control': 'public, max-age=3600' })
  })

  // ── GET /vin/{vin} ──────────────────────────────────────────────────────
  app.get('/vin/:vin', async (c) => {
    const raw = c.req.param('vin')
    const vin = raw.toUpperCase()
    if (!isVinShape(vin)) {
      return resolverError(
        c,
        'CONFORMANCE',
        `"${raw}" is not a well-formed VIN`,
        'a VIN is exactly 17 chars from the VIN alphabet (A–Z 0–9, excluding I, O, Q); ISO 3779',
      )
    }
    const check = vinVerify(vin)
    if (!check.pass) {
      return resolverError(
        c,
        'CHECKSUM_FAIL',
        `VIN check digit (position 9) is ${check.got}, expected ${check.expected}`,
        `ISO 3779 / 49 CFR 565.15 transliteration+weights (${check.algorithm})`,
      )
    }
    const canonical = vinCanonicalUri(vin)
    return finish(c, registry, `vin/${vin}`, 'instance', canonical, `/vin/${vin}`, (who, manifest) =>
      buildVinDoc(vin, who, manifest),
    )
  })

  // ── GET /01/{gtin}[/21/{serial}] ─────────────────────────────────────────
  const gtinHandler = async (c: ResolveContext) => {
    const { pathname } = new URL(c.req.url)
    const segs = pathname.split('/').filter(Boolean)
    const parsed = parseDlPath(segs)
    if ('error' in parsed) {
      return resolverError(c, parsed.error, parsed.message, parsed.hint)
    }
    const check = mod10Verify(parsed.gtin)
    if (!check.pass) {
      return resolverError(
        c,
        'CHECKSUM_FAIL',
        `GTIN check digit is ${check.got}, expected ${check.expected}`,
        `GS1 mod-10 (${check.algorithm})`,
      )
    }
    const canonical = dlCanonicalUri(parsed.gtin, parsed.serial)
    const key = parsed.serial ? `01/${parsed.gtin}/21/${parsed.serial}` : `01/${parsed.gtin}`
    const grain: Grain = parsed.serial ? 'instance' : 'class'
    const routePath = `/01/${parsed.gtin}${parsed.serial ? `/21/${parsed.serial}` : ''}`
    return finish(c, registry, key, grain, canonical, routePath, (who, manifest) =>
      buildGtinDoc(parsed.gtin, parsed.serial, who, manifest),
    )
  }
  app.get('/01/:gtin', gtinHandler)
  app.get('/01/:gtin/21/:serial', gtinHandler)

  // ── GET Phase-4 generalised keys: /00 /414 /8004 /8003 /253 ──────────────
  const keyHandler = async (c: ResolveContext) => {
    const { pathname } = new URL(c.req.url)
    const segs = pathname.split('/').filter(Boolean)
    const parsed = parseDlKey(segs)
    if ('error' in parsed) {
      return resolverError(c, parsed.error, parsed.message, parsed.hint)
    }
    if (parsed.checkDigit && parsed.numericCore) {
      const check = mod10Verify(parsed.numericCore)
      if (!check.pass) {
        return resolverError(
          c,
          'CHECKSUM_FAIL',
          `${parsed.name} check digit is ${check.got}, expected ${check.expected}`,
          `GS1 mod-10 (${check.algorithm})`,
        )
      }
    }
    const canonical = keyCanonicalUri(parsed.keyAi, parsed.primaryValue)
    const key = `${parsed.keyAi}/${parsed.primaryValue}`
    return finish(c, registry, key, parsed.grain, canonical, `/${parsed.keyAi}/${parsed.primaryValue}`, (who, manifest) =>
      buildKeyDoc(parsed.keyAi, parsed.primaryValue, parsed.grain, parsed.serial, who, manifest),
    )
  }
  app.get('/00/:sscc', keyHandler)
  app.get('/414/:gln', keyHandler)
  app.get('/8004/:giai', keyHandler)
  app.get('/8003/:grai', keyHandler)
  app.get('/253/:gdti', keyHandler)

  return app
}

/** Production mount used by worker/index.ts. Empty registry until the live binding is provisioned. */
export const resolveRoutes = createResolveApp()
