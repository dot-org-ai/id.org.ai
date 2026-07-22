/**
 * Agent Auth Protocol (AAP) v1.0-draft wire surface — id-9s0.
 *
 * Implements the subset of agent-auth-protocol.com endpoints that the
 * AgentService (id-ax7) makes well-defined:
 *
 *   GET  /.well-known/agent-configuration   discovery (no auth)
 *   POST /agent/register                    register a new agent under a tenant
 *   GET  /agent/status?agent_id=...         agent record
 *   POST /agent/revoke                      permanent revocation
 *   POST /agent/reactivate                  expired → active
 *   GET  /agent/identity                    ID-JAG identity-resolution descriptor
 *   POST /agent/identity                    resolve an agent identity from an ID-JAG
 *   POST /agent/events                      accept a SET (RFC 8417) for revocation
 *
 * AAP terminology translation (per project_positioning.md): AAP "host" =
 * id.org.ai Tenant. Wire-format `host_*` parameters are mapped to
 * `tenant_*` internally by this module — the rest of the codebase only
 * sees the Tenant vocabulary.
 *
 * Authentication (ax-e6b.21.3 — SECURITY FIX, see "host registration" below):
 * the AAP surface accepts BOTH
 *   (a) a strict AAP **host+jwt** — an EdDSA/Ed25519 (or any JWKS-advertised
 *       alg) JWT signed by the host, verified ONLY against a fixed TRUST
 *       ANCHOR: either id.org.ai's OWN signing JWKS (self-issued, `iss` ===
 *       this origin) or a jwks_uri/iss bound to the claimed `host_id` via a
 *       prior AUTHENTICATED registration (POST /agent/host/register) —
 *       NEVER a caller-supplied or token-`iss`-derived JWKS URL, and NEVER a
 *       tenant named by an unverified token claim; fail-closed on
 *       bad/missing/expired/wrong-key/unregistered-host; and
 *   (b) the existing id.org.ai session (`ses_*`) / API key (`oai_*`/`hly_sk_*`)
 *       path (unchanged — additive, not a replacement).
 * When a host+jwt is presented it MUST verify; a bad host+jwt never silently
 * falls back to session auth.
 *
 * SECURITY NOTE (ax-e6b.21.3): an earlier revision of this module verified a
 * host+jwt / ID-JAG / SET against a JWKS the CALLER supplied (a header or a
 * JWKS derived from the token's OWN `iss` claim) and then read the tenant
 * from an unverified token claim (`host_id`/`tenant`/`sub`). That let anyone
 * mint a fresh keypair, sign a token over it, and authenticate as ANY tenant
 * — a critical cross-tenant auth bypass. The fix below removes every
 * caller/token-supplied verification key and anchors trust to either
 * id.org.ai's own JWKS or a pre-registered host record (see below).
 *
 * Capability execution (`/capability/list,describe,execute`) is NOT
 * implemented here — that pairs with FGA migration (id-lkj) which gives
 * capabilities structured grants instead of flat strings.
 */

import { Hono } from 'hono'
import type { Env, Variables } from '../types'
import { errorResponse, ErrorCode, errorMessage } from '../../src/sdk/errors'
import type { AgentMode } from '../../src/sdk/types'
import { verifyJWT, decodeJWT, importPublicJwk, type JWK, type JWTHeader } from '../../src/sdk/oauth/jwt-verify'
import { safeFetchJson, assertPublicHttpsUrl } from '../utils/ssrf'
import { getSigningKeyManager, getStubForIdentity } from '../middleware/tenant'

/** ID-JAG token type (RFC 8693 token-exchange subject token) and JWT `typ`. */
const IDJAG_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id-jag'
const IDJAG_TYP = 'oauth-id-jag+jwt'
/** RFC 8417 Security Event Token media/typ. */
const SET_TYP = 'secevent+jwt'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

// ── Discovery (RFC-style well-known doc) ──────────────────────────────────
// No authentication required. Cached for 1 hour upstream.

app.get('/.well-known/agent-configuration', (c) => {
  const origin = new URL(c.req.url).origin
  return c.json(
    {
      version: '1.0-draft',
      provider_name: 'id.org.ai',
      description: 'Agent-First Identity — humans, agents, organizations',
      issuer: origin,
      algorithms: ['Ed25519'],
      modes: ['delegated', 'autonomous'],
      // Advertised HONESTLY: id.org.ai's native approval ceremony is
      // claim-by-commit (a GitHub-commit proof-of-control), NOT AAP's
      // `device_authorization`. We advertise the accurate custom value rather
      // than a ceremony we do not run. `claim_endpoint` (below + the
      // agent_auth block in the RFC 8414 metadata) points at that ceremony.
      approval_methods: ['claim_by_commit'],
      // The subject-token / assertion type the identity_endpoint accepts.
      subject_token_types_supported: [IDJAG_TOKEN_TYPE],
      conformance_notes: [
        'Default mode is claim-continuity: when a tenant gets claimed, agents stay active and become delegated. AAP-strict (autonomous → terminal claimed) requires `strict: true` on /agent/register.',
        'Authentication: strict AAP host+jwt (EdDSA/Ed25519 or any JWKS-advertised alg) is verified ONLY against a trust anchor — either self-issued (id.org.ai\'s own signing JWKS) or a host registered via an AUTHENTICATED POST /agent/host/register call (host_id bound to iss + jwks_uri); a caller-supplied or token-derived JWKS is NEVER trusted, and the tenant is ALWAYS the registered/self-issued tenant, never an unverified token claim. Third-party host+jwt from an UNREGISTERED host_id is rejected (401, fail-closed). The existing id.org.ai session/API-key path is also accepted (additive).',
        'approval_methods advertises the accurate native value `claim_by_commit` (a proof-of-control commit ceremony), not `device_authorization` — id.org.ai does not run a device_authorization ceremony.',
        'identity_endpoint (POST /agent/identity) verifies an ID-JAG assertion ONLY against the same trust anchor (self-issued or a registered issuer) — never a caller-supplied jwks_uri; events_endpoint (POST /agent/events) verifies a SET (RFC 8417) the same way, and a registered issuer may only revoke subjects (sessions/agents) under ITS OWN registered tenant (cross-tenant SET subjects are rejected, 403). Revocation processing acts on session/agent subjects it can resolve; broader downstream propagation is phased.',
      ],
      endpoints: {
        register: '/agent/register',
        status: '/agent/status',
        revoke: '/agent/revoke',
        reactivate: '/agent/reactivate',
        // Host-registration trust anchor onboarding (ses_/API-key AUTHENTICATED
        // only): binds a host_id to {iss, jwks_uri} — the trust anchor a
        // third-party host+jwt / ID-JAG / SET is verified against.
        register_host: '/agent/host/register',
        // Agent-identity provider surface (auth.md). These RESOLVE — they are
        // not null stubs: identity verifies an ID-JAG, events verifies a SET,
        // claim points at the native claim-by-commit ceremony.
        identity: '/agent/identity',
        events: '/agent/events',
        claim: '/api/claim',
        // Endpoints below are NOT yet implemented — declared as `null` so
        // AAP clients see them missing rather than 404 their way through.
        request_capability: null,
        rotate_key: null,
        introspect: null,
        revoke_host: null,
        rotate_host_key: null,
        capabilities: null,
        describe_capability: null,
        execute: null,
      },
      jwks_uri: `${origin}/.well-known/jwks.json`,
    },
    200,
    { 'Cache-Control': 'public, max-age=3600' },
  )
})

// ── Auth helper ───────────────────────────────────────────────────────────

function requireTenant(c: Parameters<Parameters<typeof app.post>[1]>[0]) {
  const auth = c.get('auth')
  if (!auth?.authenticated || !auth.identityId) {
    return null
  }
  // Tenants are identified by the auth principal: a session for the tenant
  // OR an API key issued to an agent under that tenant. For agent
  // principals, prefer auth.tenantId (set by AuthBroker.hydrateAgent).
  const tenantId = auth.tenantId ?? auth.identityId
  return { tenantId, principal: auth.identityId }
}

// ── host+jwt / assertion verification primitives ──────────────────────────
//
// All three of the graduated flows (AAP host+jwt, ID-JAG resolution, SET
// revocation) verify a caller-presented JWT. They share one crypto path:
//   1. decode the header for alg/kid (reject `none`/unsupported at verifyJWT),
//   2. obtain the verification key from a FIXED TRUST ANCHOR — id.org.ai's OWN
//      signing JWKS for self-issued tokens (`iss` === this origin), or a
//      PRE-REGISTERED host's jwks_uri (see "host registration" below) —
//      NEVER a JWKS the caller/token names at verification time,
//   3. delegate the signature + exp/nbf/iat/iss/aud checks to verifyJWT.
// verifyJWT is the single source of cryptographic truth — this module never
// re-implements a signature check.

interface RemoteJwks {
  keys?: unknown[]
}

// ── host registration (trust anchor for third-party host+jwt / ID-JAG / SET) ─
//
// A THIRD-PARTY host+jwt / ID-JAG / SET (one whose `iss` is not id.org.ai
// itself) is trusted ONLY when its issuer has a registration record,
// established via POST /agent/host/register — an AUTHENTICATED
// (ses_*/API-key) call. The record binds `host_id -> {iss, jwks_uri,
// tenantId}`. Verification ALWAYS re-fetches the JWKS from the REGISTERED
// `jwks_uri` (never from a caller-supplied header or a URL derived from the
// token's own `iss`), and the tenant bound to a verified token is ALWAYS the
// REGISTERED tenant — never a claim inside the token itself.
//
// This closes the ax-e6b.21.3 cross-tenant bypass: previously the caller
// could supply ANY jwks_uri (or have it derived from their OWN token's
// `iss`) and name ANY tenant via a `host_id`/`tenant`/`sub` claim — a valid
// signature over an attacker-generated key then authenticated as any
// tenant. Registration records live in `env.SESSIONS` (KV), keyed both by
// `host_id` (host+jwt lookup) and by `iss` (ID-JAG/SET lookup, which don't
// carry a `host_id` claim).
interface HostRegistration {
  hostId: string
  tenantId: string
  iss: string
  jwksUri: string
  registeredAt: number
}

const hostRegistrationKey = (hostId: string) => `aap:host:${hostId}`
const hostRegistrationByIssKey = (iss: string) => `aap:host-iss:${iss}`

// ax-p18: shard key for the atomic host_id claim. Derived ONLY from host_id
// (never the tenant) so that two DIFFERENT tenants racing to register the
// SAME brand-new host_id both resolve to the SAME Durable Object instance —
// that instance's input-gate serialization is what closes the race (see
// IdentityDO#claimHostRegistration). This is a dedicated shard purely for
// cross-isolate atomicity; it stores nothing but the claim itself.
const aapHostClaimShardKey = (hostId: string) => `aap-host-claim-shard:${hostId}`

async function lookupHostRegistrationById(env: Env, hostId: string): Promise<HostRegistration | null> {
  const raw = await env.SESSIONS.get(hostRegistrationKey(hostId))
  if (!raw) return null
  try {
    return JSON.parse(raw) as HostRegistration
  } catch {
    return null
  }
}

async function lookupHostRegistrationByIss(env: Env, iss: string): Promise<HostRegistration | null> {
  const raw = await env.SESSIONS.get(hostRegistrationByIssKey(iss))
  if (!raw) return null
  try {
    return JSON.parse(raw) as HostRegistration
  } catch {
    return null
  }
}

/** Pick the JWK matching the token header (by kid, else first importable). */
async function selectKeyFromJwks(jwks: unknown, header: JWTHeader): Promise<CryptoKey | null> {
  const keys = (jwks as RemoteJwks | undefined)?.keys
  if (!Array.isArray(keys) || keys.length === 0) return null
  const candidates = header.kid
    ? keys.filter((k) => (k as JWK).kid === header.kid)
    : keys
  const ordered = candidates.length > 0 ? candidates : keys
  for (const k of ordered) {
    try {
      const key = await importPublicJwk(k as JWK, header.alg)
      if (key) return key
    } catch {
      // Wrong alg/shape for this JWK — try the next candidate.
    }
  }
  return null
}

/** Verification key from id.org.ai's OWN signing JWKS (self-issued tokens). */
async function selectLocalKey(env: Env, header: JWTHeader): Promise<CryptoKey | null> {
  const jwks = await getSigningKeyManager(env).getJWKS()
  return selectKeyFromJwks(jwks, header)
}

type AapAuth = { tenantId: string; principal: string; via: 'host+jwt' | 'session' }

/**
 * AAP host+jwt: an EdDSA/Ed25519 (or any JWKS-advertised alg) JWT signed by the
 * host, presented in `X-AAP-Host-JWT`. Verified ONLY against a fixed trust
 * anchor — NEVER a caller/token-supplied JWKS:
 *   - self-issued (`iss` === this origin)  → verified against id.org.ai's OWN
 *     signing JWKS; the tenant is taken from the (self-signed, therefore
 *     trustworthy) `host_id`/`tenant`/`sub` claim.
 *   - third-party (`iss` !== this origin)  → the claimed host_id (the
 *     `host_id` claim, else `sub` — used ONLY as a registry lookup key, never
 *     as the trusted identity) MUST resolve to a registration record (see
 *     POST /agent/host/register below) whose `iss` matches the token's `iss`;
 *     the verification key comes from the REGISTERED `jwks_uri` (re-fetched
 *     here, SSRF-gated) — never from a request header or a URL derived from
 *     the token itself — and the tenant is the REGISTERED tenant, NEVER a
 *     token claim. An unregistered/unknown host_id is rejected (401,
 *     fail-closed): an attacker who mints a fresh keypair over an arbitrary
 *     `host_id` cannot pass verification because the registered jwks_uri
 *     belongs to the REAL host, not the attacker.
 * The token's audience MUST be this AAP origin. Returns:
 *   - null                → no host+jwt presented (caller may fall back)
 *   - { error }           → host+jwt WAS presented but failed (fail-closed)
 *   - AapAuth (host+jwt)  → verified
 */
async function verifyHostJwt(c: any): Promise<AapAuth | { error: string } | null> {
  const jwt = c.req.header('X-AAP-Host-JWT') ?? c.req.header('x-aap-host-jwt')
  if (!jwt) return null

  const decoded = decodeJWT(jwt)
  if (!decoded) return { error: 'malformed host jwt' }
  if (decoded.header.alg === 'none') return { error: 'unsigned host jwt rejected' }

  const iss = typeof decoded.payload.iss === 'string' ? decoded.payload.iss : undefined
  const selfOrigin = new URL(c.req.url).origin
  const selfIssued = iss === selfOrigin

  let key: CryptoKey | null
  let tenantId: string | undefined
  let trustedIss: string | undefined

  if (selfIssued) {
    key = await selectLocalKey(c.env, decoded.header)
    if (!key) return { error: 'no matching key in id.org.ai signing jwks for self-issued host jwt' }
    trustedIss = selfOrigin
  } else {
    const hostIdClaim =
      (typeof decoded.payload.host_id === 'string' && decoded.payload.host_id) ||
      (typeof decoded.payload.sub === 'string' && decoded.payload.sub) ||
      undefined
    if (!hostIdClaim) return { error: 'host jwt missing host_id/sub to resolve a registration' }

    const reg = await lookupHostRegistrationById(c.env, hostIdClaim)
    if (!reg) {
      return { error: `unregistered host_id "${hostIdClaim}" — register via POST /agent/host/register first` }
    }
    if (!iss || iss !== reg.iss) {
      return { error: 'host jwt iss does not match the registered issuer for this host_id' }
    }

    let jwks: unknown
    try {
      jwks = await safeFetchJson(reg.jwksUri)
    } catch (err: unknown) {
      return { error: `registered host jwks fetch refused: ${errorMessage(err)}` }
    }
    key = await selectKeyFromJwks(jwks, decoded.header)
    if (!key) return { error: 'no matching host key in the registered jwks' }
    // The tenant is the REGISTERED tenant — fixed here, never overwritten by
    // any claim inside the (as yet unverified-signature) token.
    tenantId = reg.tenantId
    trustedIss = reg.iss
  }

  const audience = selfOrigin
  const result = await verifyJWT(jwt, { publicKey: key, issuer: trustedIss, audience })
  if (!result.valid) return { error: result.error }

  const sub = typeof result.payload.sub === 'string' ? result.payload.sub : undefined
  if (!sub) return { error: 'host jwt missing sub claim' }

  if (selfIssued) {
    // Self-issued: id.org.ai signed this token itself, so its own claims are
    // trustworthy — same derivation as before the fix.
    tenantId =
      (typeof result.payload.host_id === 'string' && result.payload.host_id) ||
      (typeof result.payload.tenant === 'string' && result.payload.tenant) ||
      sub
  }
  if (!tenantId) return { error: 'unable to resolve tenant for host jwt' }

  return { tenantId, principal: sub, via: 'host+jwt' }
}

/**
 * Resolve the AAP caller. host+jwt is tried first; if presented it MUST verify
 * (a bad host+jwt is terminal, never a silent downgrade to session auth). When
 * no host+jwt is presented, fall back to the existing session/API-key path.
 */
async function authenticateAap(
  c: any,
): Promise<{ ok: true; auth: AapAuth } | { ok: false; status: 401; message: string }> {
  const hj = await verifyHostJwt(c)
  if (hj && 'error' in hj) {
    return { ok: false, status: 401, message: `host+jwt verification failed: ${hj.error}` }
  }
  if (hj) {
    // A host+jwt principal is first-class: bind the tenant's DO stub so the
    // downstream handler resolves against the verified host, exactly as the
    // session/API-key path does via identityStubMiddleware.
    if (!c.get('identityStub')) {
      c.set('identityStub', getStubForIdentity(c.env, hj.tenantId))
    }
    return { ok: true, auth: hj }
  }

  const t = requireTenant(c)
  if (!t) return { ok: false, status: 401, message: 'Authentication required' }
  return { ok: true, auth: { tenantId: t.tenantId, principal: t.principal, via: 'session' } }
}

// ── /agent/host/register — host-registration trust anchor onboarding ────────
//
// Binds a `host_id` to `{iss, jwks_uri}` under the AUTHENTICATED caller's own
// tenant. This binding is the trust anchor a THIRD-PARTY host+jwt / ID-JAG /
// SET is verified against (see "host registration" above). Deliberately
// authenticated via the EXISTING ses_/API-key path ONLY (`requireTenant`,
// NOT `authenticateAap`) — a host+jwt can never be used to register itself
// (or another host), which would otherwise let an unregistered caller
// bootstrap its own trust anchor.
app.post('/agent/host/register', async (c) => {
  const tenant = requireTenant(c)
  if (!tenant) return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required (ses_/API key)')

  const body = (await c.req.json().catch(() => ({}))) as {
    host_id?: string
    iss?: string
    jwks_uri?: string
  }
  const hostId = typeof body.host_id === 'string' ? body.host_id.trim() : ''
  if (!hostId) return errorResponse(c, 400, ErrorCode.InvalidRequest, 'host_id is required')

  let issUrl: URL
  let jwksUrl: URL
  try {
    // `iss` is compared against the token's `iss` claim, never fetched — but
    // requiring it to be a well-formed https origin keeps registrations
    // canonical and comparable.
    issUrl = assertPublicHttpsUrl(body.iss)
  } catch (err: unknown) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, `iss: ${errorMessage(err)}`)
  }
  try {
    // `jwks_uri` WILL be fetched (at verification time) — SSRF-gate it here,
    // at registration time, so a private/loopback/metadata URL is never
    // stored as a trust anchor in the first place.
    jwksUrl = assertPublicHttpsUrl(body.jwks_uri)
  } catch (err: unknown) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, `jwks_uri: ${errorMessage(err)}`)
  }
  const iss = issUrl.toString().replace(/\/$/, '')
  const jwksUri = jwksUrl.toString()

  // Prevent hijacking an ALREADY-registered iss owned by a DIFFERENT tenant.
  // (This is a plain KV read — the iss-collision race across DIFFERENT
  // host_ids is not the race ax-p18 closes; that race is scoped to the
  // host_id keyspace, see below.)
  const existingByIss = await lookupHostRegistrationByIss(c.env, iss)
  if (existingByIss && existingByIss.tenantId !== tenant.tenantId) {
    return errorResponse(c, 409, ErrorCode.Forbidden, 'iss is already registered to a different tenant')
  }

  // ax-p18: the host_id existence-check + claim MUST be atomic — a
  // concurrent race on a BRAND-NEW (never-registered) host_id must not be
  // last-write-wins between two different tenants. Route the claim through a
  // Durable Object instance dedicated to THIS host_id (see
  // aapHostClaimShardKey above); the DO's input-gate serialization decides
  // the race, not this handler's own read+write. An ALREADY-registered
  // host_id owned by a different tenant is unaffected — still a hard 409.
  const claimStub = getStubForIdentity(c.env, aapHostClaimShardKey(hostId))
  const claim = await claimStub.claimHostRegistration({ hostId, tenantId: tenant.tenantId })
  if (!claim.claimed) {
    return errorResponse(c, 409, ErrorCode.Forbidden, 'host_id is already registered to a different tenant')
  }

  const record: HostRegistration = { hostId, tenantId: tenant.tenantId, iss, jwksUri, registeredAt: Date.now() }
  await c.env.SESSIONS.put(hostRegistrationKey(hostId), JSON.stringify(record))
  await c.env.SESSIONS.put(hostRegistrationByIssKey(iss), JSON.stringify(record))

  return c.json(
    {
      host_id: record.hostId,
      tenant_id: record.tenantId,
      iss: record.iss,
      jwks_uri: record.jwksUri,
      registered_at: new Date(record.registeredAt).toISOString(),
    },
    201,
  )
})

// ── /agent/register ───────────────────────────────────────────────────────
//
// Body shape mirrors AAP v1.0-draft §registration:
//   {
//     name: string,                 // human label
//     host_name?: string,           // ignored — tenant is derived from auth
//     mode: 'delegated' | 'autonomous',
//     capabilities?: string[],
//     public_key?: string,          // base64 raw 32-byte Ed25519
//     jwks_url?: string,            // alternative: JWKS URL
//     strict?: boolean,             // AAP-strict claim semantics (D7)
//     reason?: string               // ignored at L1
//   }

app.post('/agent/register', async (c) => {
  const authed = await authenticateAap(c)
  if (!authed.ok) return errorResponse(c, authed.status, ErrorCode.Unauthorized, authed.message)
  const tenant = authed.auth

  const stub = c.get('identityStub')
  if (!stub) return errorResponse(c, 500, ErrorCode.ServerError, 'Identity stub not resolved')

  const body = (await c.req.json().catch(() => ({}))) as {
    name?: string
    mode?: AgentMode
    capabilities?: string[]
    public_key?: string
    jwks_url?: string
    strict?: boolean
    sessionTtlMs?: number
    maxLifetimeMs?: number
    absoluteLifetimeMs?: number
  }

  if (!body.name?.trim()) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'name is required')
  }
  if (body.mode !== 'delegated' && body.mode !== 'autonomous') {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'mode must be "delegated" or "autonomous"')
  }
  if (!body.public_key && !body.jwks_url) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'public_key or jwks_url is required')
  }

  try {
    const result = await stub.registerAgent({
      tenantId: tenant.tenantId,
      name: body.name,
      publicKey: body.public_key,
      jwksUrl: body.jwks_url,
      mode: body.mode,
      capabilities: body.capabilities,
      strict: body.strict,
      sessionTtlMs: body.sessionTtlMs,
      maxLifetimeMs: body.maxLifetimeMs,
      absoluteLifetimeMs: body.absoluteLifetimeMs,
    })
    if (!result.success || !result.agent) {
      return errorResponse(c, 400, ErrorCode.InvalidRequest, result.error ?? 'Agent registration failed')
    }
    return c.json(
      {
        agent_id: result.agent.id,
        host_id: result.agent.tenantId,
        name: result.agent.name,
        mode: result.agent.mode,
        status: result.agent.status,
        agent_capability_grants: result.agent.capabilities.map((capability) => ({
          capability,
          status: 'active',
        })),
      },
      201,
    )
  } catch (err: unknown) {
    return errorResponse(c, 500, ErrorCode.ServerError, errorMessage(err))
  }
})

// ── /agent/status ─────────────────────────────────────────────────────────

app.get('/agent/status', async (c) => {
  const authed = await authenticateAap(c)
  if (!authed.ok) return errorResponse(c, authed.status, ErrorCode.Unauthorized, authed.message)
  const tenant = authed.auth

  const stub = c.get('identityStub')
  if (!stub) return errorResponse(c, 500, ErrorCode.ServerError, 'Identity stub not resolved')

  const agentId = c.req.query('agent_id')
  if (!agentId) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'agent_id query parameter required')
  }

  const agent = await stub.getAgent(agentId)
  if (!agent) {
    return errorResponse(c, 404, ErrorCode.NotFound, 'Agent not found')
  }

  // Cross-tenant lookup is forbidden.
  if (agent.tenantId !== tenant.tenantId) {
    return errorResponse(c, 403, ErrorCode.Forbidden, 'Agent is in a different tenant')
  }

  return c.json({
    agent_id: agent.id,
    host_id: agent.tenantId,
    name: agent.name,
    status: agent.status,
    mode: agent.mode,
    agent_capability_grants: agent.capabilities.map((capability) => ({ capability, status: 'active' })),
    activated_at: agent.activatedAt ? new Date(agent.activatedAt).toISOString() : undefined,
    created_at: new Date(agent.createdAt).toISOString(),
    last_used_at: agent.lastUsedAt ? new Date(agent.lastUsedAt).toISOString() : undefined,
    expires_at: agent.expiresAt ? new Date(agent.expiresAt).toISOString() : undefined,
  })
})

// ── /agent/revoke ─────────────────────────────────────────────────────────

app.post('/agent/revoke', async (c) => {
  const authed = await authenticateAap(c)
  if (!authed.ok) return errorResponse(c, authed.status, ErrorCode.Unauthorized, authed.message)
  const tenant = authed.auth

  const stub = c.get('identityStub')
  if (!stub) return errorResponse(c, 500, ErrorCode.ServerError, 'Identity stub not resolved')

  const body = (await c.req.json().catch(() => ({}))) as { agent_id?: string; reason?: string }
  if (!body.agent_id) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'agent_id required')
  }

  const agent = await stub.getAgent(body.agent_id)
  if (!agent) {
    return errorResponse(c, 404, ErrorCode.NotFound, 'Agent not found')
  }
  if (agent.tenantId !== tenant.tenantId) {
    return errorResponse(c, 403, ErrorCode.Forbidden, 'Agent is in a different tenant')
  }

  const result = await stub.revokeAgent(body.agent_id, body.reason)
  if (!result.success || !result.agent) {
    return errorResponse(c, 409, ErrorCode.Forbidden, result.error ?? 'Revoke failed')
  }
  return c.json({
    agent_id: result.agent.id,
    status: result.agent.status,
    revoked_at: result.agent.revokedAt ? new Date(result.agent.revokedAt).toISOString() : undefined,
  })
})

// ── /agent/reactivate ─────────────────────────────────────────────────────

app.post('/agent/reactivate', async (c) => {
  const authed = await authenticateAap(c)
  if (!authed.ok) return errorResponse(c, authed.status, ErrorCode.Unauthorized, authed.message)
  const tenant = authed.auth

  const stub = c.get('identityStub')
  if (!stub) return errorResponse(c, 500, ErrorCode.ServerError, 'Identity stub not resolved')

  const body = (await c.req.json().catch(() => ({}))) as { agent_id?: string }
  if (!body.agent_id) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'agent_id required')
  }

  const agent = await stub.getAgent(body.agent_id)
  if (!agent) {
    return errorResponse(c, 404, ErrorCode.NotFound, 'Agent not found')
  }
  if (agent.tenantId !== tenant.tenantId) {
    return errorResponse(c, 403, ErrorCode.Forbidden, 'Agent is in a different tenant')
  }

  const result = await stub.reactivateAgent(body.agent_id)
  if (!result.success || !result.agent) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, result.error ?? 'Reactivation failed')
  }
  return c.json({
    agent_id: result.agent.id,
    status: result.agent.status,
    activated_at: result.agent.activatedAt ? new Date(result.agent.activatedAt).toISOString() : undefined,
  })
})

// ── /agent/identity (auth.md identity_endpoint) ──────────────────────────────
//
// Resolves an agent identity from an ID-JAG (Identity Assertion JWT
// Authorization Grant, token type urn:ietf:params:oauth:token-type:id-jag /
// JWT typ oauth-id-jag+jwt).
//
//   GET  → a resolvable descriptor (the probe api.qa runs to confirm the
//          advertised identity_endpoint is live; never a 404/5xx).
//   POST → verify the ID-JAG and return the resolved identity, or fail closed.

app.get('/agent/identity', (c) => {
  const origin = new URL(c.req.url).origin
  return c.json({
    endpoint: 'agent-identity',
    description: 'POST an ID-JAG assertion to resolve an agent identity.',
    method: 'POST',
    // NOTE: `jwks_uri` is NOT an accepted request field — a verification key
    // is never taken from the caller. See the trust-anchor doc on
    // verifyHostJwt() above: self-issued (this origin's own JWKS) or a
    // registered issuer (POST /agent/host/register) only.
    request: { assertion: '<ID-JAG JWT>' },
    accepted_token_type: IDJAG_TOKEN_TYPE,
    accepted_assertion_typ: IDJAG_TYP,
    subject_token_types_supported: [IDJAG_TOKEN_TYPE],
    jwks_uri: `${origin}/.well-known/jwks.json`,
  })
})

app.post('/agent/identity', async (c) => {
  const origin = new URL(c.req.url).origin
  const body = (await c.req.json().catch(() => ({}))) as { assertion?: string }
  const assertion = typeof body.assertion === 'string' ? body.assertion : undefined
  if (!assertion) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'assertion (an ID-JAG JWT) is required')
  }

  const decoded = decodeJWT(assertion)
  if (!decoded) return errorResponse(c, 401, ErrorCode.InvalidToken, 'malformed ID-JAG assertion')
  if (decoded.header.alg === 'none') {
    return errorResponse(c, 401, ErrorCode.InvalidToken, 'unsigned assertion rejected')
  }
  // Correct token-type handling: the assertion MUST declare the ID-JAG typ.
  if (decoded.header.typ !== IDJAG_TYP) {
    return errorResponse(
      c,
      400,
      ErrorCode.InvalidRequest,
      `assertion is not an ID-JAG (expected JWT typ "${IDJAG_TYP}")`,
    )
  }

  // Verification key: SAME trust anchor as verifyHostJwt() — id.org.ai's own
  // signing JWKS for a self-issued ID-JAG (`iss` === this origin), or a
  // PRE-REGISTERED issuer's jwks_uri. NEVER a caller-supplied jwks_uri (that
  // was the ax-e6b.21.3 bypass: a caller could name its own verification key).
  const iss = typeof decoded.payload.iss === 'string' ? decoded.payload.iss : undefined
  let key: CryptoKey | null
  let trustedIss: string | undefined
  if (iss === origin) {
    key = await selectLocalKey(c.env, decoded.header)
    trustedIss = origin
  } else if (iss) {
    const reg = await lookupHostRegistrationByIss(c.env, iss)
    if (!reg) {
      return errorResponse(c, 401, ErrorCode.InvalidToken, `unregistered issuer "${iss}" — ID-JAG rejected`)
    }
    let jwks: unknown
    try {
      jwks = await safeFetchJson(reg.jwksUri)
    } catch (err: unknown) {
      return errorResponse(c, 401, ErrorCode.InvalidToken, `registered issuer jwks fetch refused: ${errorMessage(err)}`)
    }
    key = await selectKeyFromJwks(jwks, decoded.header)
    trustedIss = reg.iss
  } else {
    return errorResponse(c, 401, ErrorCode.InvalidToken, 'ID-JAG missing iss claim')
  }
  if (!key) return errorResponse(c, 401, ErrorCode.InvalidToken, 'no verification key for ID-JAG assertion')

  // The ID-JAG is presented TO this resource — its audience must be this origin.
  const result = await verifyJWT(assertion, { publicKey: key, audience: origin, issuer: trustedIss })
  if (!result.valid) return errorResponse(c, 401, ErrorCode.InvalidToken, `ID-JAG verification failed: ${result.error}`)

  const sub = typeof result.payload.sub === 'string' ? result.payload.sub : undefined
  if (!sub) return errorResponse(c, 401, ErrorCode.InvalidToken, 'ID-JAG missing sub claim')

  const agent =
    (typeof result.payload.agent_id === 'string' && result.payload.agent_id) ||
    (typeof result.payload.agent === 'string' && result.payload.agent) ||
    undefined
  return c.json({
    resolved: true,
    token_type: IDJAG_TOKEN_TYPE,
    sub,
    issuer: result.payload.iss,
    audience: result.payload.aud,
    ...(agent ? { agent_id: agent } : {}),
    ...(typeof result.payload.act === 'object' && result.payload.act ? { act: result.payload.act } : {}),
  })
})

// ── /agent/events (auth.md events_endpoint) ──────────────────────────────────
//
// Accepts a SET (Security Event Token, RFC 8417 — a signed JWT with an `events`
// claim) for REVOCATION and processes it (RFC 8935 push delivery: 202 on
// accept, 400/401/403 on an invalid/untrusted/cross-tenant SET). The SET is
// verified (signature + typ + `events` shape + audience) against the SAME
// trust anchor as verifyHostJwt()/`/agent/identity` (self-issued or a
// registered issuer — NEVER a caller-supplied JWKS) before any action; a
// verified-but-third-party SET may ONLY revoke subjects (sessions/agents)
// that belong to the ISSUER'S OWN registered tenant — a cross-tenant subject
// is rejected (403), never silently accepted. A self-issued SET is held to
// the SAME ownership standard (ax-19o): it may only revoke a subject whose
// ownership resolves to a tenant the SET's own claims name — a self-issued
// SET with no resolvable tenant claim can establish ownership of nothing and
// is a safe no-op, never a revocation.

const SET_ERR = (c: any, err: string, description: string, status: 400 | 401 | 403 = 400) =>
  c.json({ err, description }, status)

app.post('/agent/events', async (c) => {
  const origin = new URL(c.req.url).origin

  // A SET may arrive as application/secevent+jwt (raw JWT) or JSON { set }.
  const raw = await c.req.text().catch(() => '')
  let token = raw.trim()
  if (token.startsWith('{')) {
    try {
      const parsed = JSON.parse(token) as { set?: unknown }
      token = typeof parsed.set === 'string' ? parsed.set : ''
    } catch {
      return SET_ERR(c, 'invalid_request', 'body is neither a compact SET nor a JSON object with a `set`')
    }
  }
  if (!token) return SET_ERR(c, 'invalid_request', 'missing security event token')

  const decoded = decodeJWT(token)
  if (!decoded) return SET_ERR(c, 'invalid_request', 'malformed security event token')
  if (decoded.header.alg === 'none') return SET_ERR(c, 'invalid_request', 'unsigned SET rejected')
  if (decoded.header.typ !== SET_TYP) {
    return SET_ERR(c, 'invalid_request', `SET must carry JWT typ "${SET_TYP}" (RFC 8417)`)
  }
  const events = decoded.payload.events
  if (!events || typeof events !== 'object' || Array.isArray(events)) {
    return SET_ERR(c, 'invalid_request', 'SET is missing a valid `events` claim (RFC 8417)')
  }

  // Verification key: SAME trust anchor as verifyHostJwt()/`/agent/identity` —
  // id.org.ai's own signing JWKS for a self-issued SET (`iss` === this
  // origin), or a PRE-REGISTERED issuer's jwks_uri. NEVER a caller-supplied
  // JWKS header (that was the ax-e6b.21.3 bypass — a forged SET at an
  // attacker-advertised JWKS could trigger a revocation for any subject).
  const iss = typeof decoded.payload.iss === 'string' ? decoded.payload.iss : undefined
  const selfIssued = iss === origin
  let key: CryptoKey | null
  let trustedIss: string | undefined
  let registeredTenantId: string | undefined // set ONLY for a registered (non-self) trust anchor
  if (selfIssued) {
    key = await selectLocalKey(c.env, decoded.header)
    trustedIss = origin
  } else if (iss) {
    const reg = await lookupHostRegistrationByIss(c.env, iss)
    if (!reg) return SET_ERR(c, 'invalid_key', `unregistered issuer "${iss}" — SET rejected`, 401)
    let jwks: unknown
    try {
      jwks = await safeFetchJson(reg.jwksUri)
    } catch (err: unknown) {
      return SET_ERR(c, 'invalid_key', `registered issuer jwks fetch refused: ${errorMessage(err)}`, 401)
    }
    key = await selectKeyFromJwks(jwks, decoded.header)
    trustedIss = reg.iss
    registeredTenantId = reg.tenantId
  } else {
    return SET_ERR(c, 'invalid_request', 'SET missing iss claim', 401)
  }
  if (!key) return SET_ERR(c, 'invalid_key', 'no verification key for SET', 401)

  // The SET is delivered TO this receiver — its audience must be this origin.
  const result = await verifyJWT(token, { publicKey: key, audience: origin, issuer: trustedIss })
  if (!result.valid) return SET_ERR(c, 'invalid_key', `SET verification failed: ${result.error}`, 401)

  // Process revocation idempotently. Recognise a session/agent subject from the
  // SET's `sub_id`, then AUTHORIZE it against the trust anchor's tenant before
  // acting: a registered (third-party) issuer may only revoke subjects under
  // ITS OWN registered tenant; a self-issued SET (id.org.ai's own key) may
  // additionally declare an explicit `tenant`/`host_id` claim (trustworthy,
  // since id.org.ai signed it) to scope an agent revocation. Unknown/
  // unresolvable subjects are a safe no-op (still 202 after verification) —
  // but a subject that resolves to a DIFFERENT tenant than the trust anchor is
  // a hard 403, never a silent 202.
  const subId = decoded.payload.sub_id as { format?: string; agent_id?: string; session?: string } | undefined
  const agentId = (subId && typeof subId.agent_id === 'string' && subId.agent_id) || undefined
  const sessionToken = (subId && typeof subId.session === 'string' && subId.session) || undefined

  const selfIssuedClaimedTenant =
    (typeof decoded.payload.tenant === 'string' && decoded.payload.tenant) ||
    (typeof decoded.payload.host_id === 'string' && decoded.payload.host_id) ||
    undefined
  const actingTenantId = registeredTenantId ?? (selfIssued ? selfIssuedClaimedTenant : undefined)

  if (agentId && actingTenantId) {
    const stub = getStubForIdentity(c.env, actingTenantId)
    const agent = await stub.getAgent(agentId).catch(() => null)
    if (!agent) {
      // A REGISTERED (non-self) trust anchor naming a subject outside its own
      // tenant is a hard cross-tenant violation. A self-issued SET with an
      // unresolved claimed tenant is treated as an unknown-subject no-op.
      if (registeredTenantId) {
        return SET_ERR(c, 'invalid_target', "SET subject agent is not registered under the issuer's tenant", 403)
      }
    } else {
      await stub.revokeAgent?.(agentId, 'SET revocation event').catch(() => {
        // Best-effort — the SET was cryptographically accepted; a downstream
        // store hiccup does not un-accept the event.
      })
    }
  }

  if (sessionToken) {
    // ax-19o: ownership MUST be established and match the SET's authorized
    // tenant (`actingTenantId`) before ANY revocation — for BOTH a
    // registered third-party issuer AND a self-issued SET. Previously this
    // check only ran `if (registeredTenantId)`, so a genuinely SELF-ISSUED
    // SET (real id.org.ai signature) carrying NO tenant/host_id claim
    // skipped ownership entirely and deleted the named session
    // unconditionally. That requires possessing id.org.ai's own signing key
    // (not externally exploitable today), but is closed here as
    // future-proofing for when self-issuance of SETs exists: a self-issued
    // SET with no resolvable tenant claim cannot establish ownership of ANY
    // subject and MUST be a safe no-op — never delete a session whose
    // ownership can't be verified against the SET's authority.
    if (actingTenantId) {
      const owner = await c.env.SESSIONS.get(`session:${sessionToken}`).catch(() => null)
      if (owner && owner !== actingTenantId) {
        return SET_ERR(c, 'invalid_target', "SET subject session is not owned by the issuer's tenant", 403)
      }
      // Revoke the session by deleting its KV binding (idempotent no-op if
      // the session is already gone/unknown).
      await c.env.SESSIONS?.delete?.(`session:${sessionToken}`).catch(() => {})
    }
    // actingTenantId undefined => a self-issued SET with no resolvable
    // tenant/host_id claim. Ownership cannot be established — safe no-op,
    // the session is NEVER deleted on this path.
  }

  // RFC 8935 push delivery: 202 Accepted, empty body, on a validated SET.
  return c.body(null, 202)
})

export { app as aapRoutes }
