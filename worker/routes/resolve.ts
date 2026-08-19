/**
 * resolve.ts — the public, anonymous-first GS1 Digital Link resolver door
 * (ADR 0001 stage 1).
 *
 * Additive to the shipped `oauth` worker: mounted BEFORE `authenticateRequest`
 * so it is keyless-first-value. Owns:
 *   GET /vin/{vin}
 *   GET /01/{gtin}
 *   GET /01/{gtin}/21/{serial}
 *
 * Flow per request:
 *   parse + validate identifier  → typed 400 on bad grammar / check digit
 *   content-negotiate (ported)   → 200 JSON-LD identity doc for
 *                                   application/ld+json | application/json,
 *                                   303 → defaultLink for browser/text-html*
 *   Who                          → broker.identify(req); attach only when a
 *                                   credential resolves (L0 anonymous omits it)
 *   capture                      → conservative stamp, no-op sink (never G5)
 *
 * *STAGE-1 NARROWING (declared): there is NO registry / defaultLink store in
 * this repo yet, so the ADR D2 `text/html → 303 to gs1:defaultLink` cannot
 * resolve a real target. A 303-to-nothing is impossible, so the browser/html
 * face FALLS BACK to the 200 JSON-LD identity face. The 303 + defaultLink store
 * is deferred + ticketed (bd model-gap).
 *
 * The response never 406s. Every face carries Content-Type, a Vary over the
 * conneg inputs, and a Link rel="alternate" advertising sibling faces.
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
import { isVinShape, vinVerify, mod10Verify, parseDlPath } from '../resolve/identifiers'
import { buildVinDoc, buildGtinDoc, vinCanonicalUri, dlCanonicalUri, type WhoBlock } from '../resolve/jsonld'
import { stampResolve } from '../resolve/capture'

// ── Typed resolver error surface (contract-specified nested shape) ─────────
// The resolver uses a domain-specific typed error {error:{code,message,hint}},
// distinct from the OAuth flat {error, error_description} shape, because the
// contract pins CONFORMANCE / CHECKSUM_FAIL as the machine codes a Digital Link
// client switches on.
type ResolverErrorCode = 'CONFORMANCE' | 'CHECKSUM_FAIL'

type ResolveContext = Context<{ Bindings: Env; Variables: Variables }>

function resolverError(c: ResolveContext, code: ResolverErrorCode, message: string, hint: string) {
  return c.json({ error: { code, message, hint } }, 400)
}

// ── Conneg availability for stage 1 ────────────────────────────────────────
// html is a legal outcome (→ 303 today falls back to jsonld) but not a body
// face here; linkset + md are deferred.
const STAGE1_AVAILABLE: Face[] = ['html', 'jsonld', 'json']
// Sibling faces advertised via Link rel="alternate" (the two real body faces).
const ADVERTISED_FACES: Face[] = ['jsonld', 'json']

const VARY = 'Accept, Sec-Fetch-Mode, Sec-Fetch-Dest, User-Agent'

/**
 * A no-op stub satisfying the IdentityStub contract, for the broker's WorkOS
 * sk_* fallback path when tenant resolution produced no id.org.ai stub. Every
 * lookup reports "not found"; the broker then resolves anonymous (no WorkOS key
 * wired into the resolver door) — existence-neutral by construction.
 */
const NO_STUB = {
  validateApiKey: async () => ({ valid: false }),
  getSession: async () => ({ valid: false }),
  getIdentity: async () => null,
  getAgent: async () => null,
  touchAgent: async () => {},
  checkRateLimit: async () => ({ allowed: true, remaining: 0, resetAt: 0 }),
} as unknown as IdentityStub

/**
 * Resolve the optional Who for a GET. Anonymous-first: returns null when no
 * credential resolves (L0), a full Identity otherwise. Never throws — a read
 * must succeed regardless of credential state.
 *
 * Constructs AuthBrokerImpl mirroring worker/middleware/auth.ts: `stubFor`
 * returns the identityStub the identityStubMiddleware already staged (or a
 * no-op), `verifyJwt` trusts the already-resolved identityId. No new identity
 * mechanism — this is exactly the ADR D3 Who wiring.
 */
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
    // Existence-neutral: any resolution failure yields anonymous (no Who).
    return null
  }
}

/** Map an Identity to the existence-neutral Who block attached to the doc. */
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
 * Emit the negotiated face. In stage 1 both the html (redirect) fallback and
 * the jsonld/json faces resolve to a JSON-LD body — html falls back with an
 * extra header noting the deferred 303. Never 406.
 */
function emitFace(c: ResolveContext, neg: NegotiateResult, canonical: string, doc: unknown) {
  // Faces that carry a JSON-LD body in stage 1: jsonld, json, and the html
  // fallback (303 target store deferred).
  const bodyFace: Face = neg.face === 'html' ? 'jsonld' : neg.face
  c.header('Content-Type', FACE_CONTENT_TYPE[bodyFace])
  c.header('Vary', VARY)
  c.header('Link', `<${canonical}>; rel="canonical", ${alternatesHeader(canonical, ADVERTISED_FACES)}`)
  c.header('Cache-Control', 'public, max-age=3600')
  if (neg.face === 'html') {
    // Declared narrowing: no defaultLink store yet → serve the identity face
    // instead of a 303-to-nothing. Advertise the deferral for observability.
    c.header('X-Resolver-Fallback', 'html→jsonld (defaultLink 303 store deferred, ADR 0001 D2)')
  }
  return c.body(JSON.stringify(doc, null, 2), 200)
}

export function createResolveApp() {
  const app = new Hono<{ Bindings: Env; Variables: Variables }>()

  // ── GET /vin/{vin} ──────────────────────────────────────────────────────
  app.get('/vin/:vin', async (c) => {
    const raw = c.req.param('vin')
    const vin = raw.toUpperCase()

    // Grammar (CONFORMANCE) before check digit (CHECKSUM_FAIL).
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

    const neg = negotiate(c.req.raw, `/vin/${vin}`, { available: STAGE1_AVAILABLE })
    const who = await resolveWho(c)
    const canonical = vinCanonicalUri(vin)
    const doc = buildVinDoc(vin, who ? whoBlock(who) : undefined)
    // Conservative capture stamp — no-op sink, never a G5 write.
    stampResolve(canonical, who ? who.id : 'anon')
    return emitFace(c, neg, canonical, doc)
  })

  // ── GET /01/{gtin} and GET /01/{gtin}/21/{serial} ────────────────────────
  // One handler over the DL path form: parse the leftmost primary key and the
  // optional /21 qualifier from the raw pathname (tolerating unknown trailing
  // AIs), so both routes flow through the same grammar + check-digit gate.
  const gtinHandler = async (c: ResolveContext) => {
    const { pathname } = new URL(c.req.url)
    const segs = pathname.split('/').filter(Boolean)
    // segs starts at the primary key AI '01'.
    const parsed = parseDlPath(segs)
    if ('error' in parsed) {
      return resolverError(c, parsed.error, parsed.message, parsed.hint)
    }

    // GTIN shape is re-checked in parseDlPath; run the mod-10 check digit.
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
    const neg = negotiate(c.req.raw, `/01/${parsed.gtin}${parsed.serial ? `/21/${parsed.serial}` : ''}`, {
      available: STAGE1_AVAILABLE,
    })
    const who = await resolveWho(c)
    const doc = buildGtinDoc(parsed.gtin, parsed.serial, who ? whoBlock(who) : undefined)
    stampResolve(canonical, who ? who.id : 'anon')
    return emitFace(c, neg, canonical, doc)
  }

  app.get('/01/:gtin', gtinHandler)
  app.get('/01/:gtin/21/:serial', gtinHandler)

  return app
}

/** Production mount used by worker/index.ts. */
export const resolveRoutes = createResolveApp()
