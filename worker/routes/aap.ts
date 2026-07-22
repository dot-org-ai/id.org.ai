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
 * Authentication (ax-e6b.21.3 — graduated): the AAP surface accepts BOTH
 *   (a) a strict AAP **host+jwt** — an EdDSA/Ed25519 (or any JWKS-advertised
 *       alg) JWT signed by the host, VERIFIED against the host's advertised
 *       `jwks_uri` (SSRF-gated), fail-closed on bad/missing/expired/wrong-key;
 *       and
 *   (b) the existing id.org.ai session (`ses_*`) / API key (`oai_*`/`hly_sk_*`)
 *       path (unchanged — additive, not a replacement).
 * When a host+jwt is presented it MUST verify; a bad host+jwt never silently
 * falls back to session auth.
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
import { safeFetchJson } from '../utils/ssrf'
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
        'Authentication: strict AAP host+jwt (EdDSA/Ed25519 or any JWKS-advertised alg, verified against the host jwks_uri, fail-closed) AND the existing id.org.ai session/API-key path are both accepted.',
        'approval_methods advertises the accurate native value `claim_by_commit` (a proof-of-control commit ceremony), not `device_authorization` — id.org.ai does not run a device_authorization ceremony.',
        'identity_endpoint (POST /agent/identity) accepts + verifies an ID-JAG assertion; events_endpoint (POST /agent/events) accepts + verifies a SET (RFC 8417) for revocation. Revocation processing acts on session/agent subjects it can resolve; broader downstream propagation is phased.',
      ],
      endpoints: {
        register: '/agent/register',
        status: '/agent/status',
        revoke: '/agent/revoke',
        reactivate: '/agent/reactivate',
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
//   2. obtain the verification key — either a key from the caller's SSRF-gated
//      JWKS, or id.org.ai's OWN signing JWKS for self-issued assertions,
//   3. delegate the signature + exp/nbf/iat/iss/aud checks to verifyJWT.
// verifyJWT is the single source of cryptographic truth — this module never
// re-implements a signature check.

interface RemoteJwks {
  keys?: unknown[]
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
 * host, presented in `X-AAP-Host-JWT`. The host's JWKS is taken from
 * `X-AAP-Host-JWKS-URI` when present, else derived from the token's `iss` as
 * `<iss>/.well-known/jwks.json`. The JWKS fetch is SSRF-gated. The token's
 * audience MUST be this AAP origin. Returns:
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
  let jwksUri = c.req.header('X-AAP-Host-JWKS-URI') ?? c.req.header('x-aap-host-jwks-uri')
  if (!jwksUri && iss) {
    try {
      jwksUri = new URL('/.well-known/jwks.json', iss).toString()
    } catch {
      /* fall through to the missing-jwks error */
    }
  }
  if (!jwksUri) return { error: 'no jwks_uri available to verify host jwt' }

  let jwks: unknown
  try {
    jwks = await safeFetchJson(jwksUri)
  } catch (err: unknown) {
    return { error: `host jwks fetch refused: ${errorMessage(err)}` }
  }

  const key = await selectKeyFromJwks(jwks, decoded.header)
  if (!key) return { error: 'no matching host key in jwks' }

  const audience = new URL(c.req.url).origin
  const result = await verifyJWT(jwt, {
    publicKey: key,
    ...(iss ? { issuer: iss } : {}),
    audience,
  })
  if (!result.valid) return { error: result.error }

  const sub = typeof result.payload.sub === 'string' ? result.payload.sub : undefined
  if (!sub) return { error: 'host jwt missing sub claim' }

  // The host (tenant) is named by an explicit host claim when present, else by
  // the verified subject.
  const tenantId =
    (typeof result.payload.host_id === 'string' && result.payload.host_id) ||
    (typeof result.payload.tenant === 'string' && result.payload.tenant) ||
    sub
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
    request: { assertion: '<ID-JAG JWT>', jwks_uri: '<optional https JWKS to verify against>' },
    accepted_token_type: IDJAG_TOKEN_TYPE,
    accepted_assertion_typ: IDJAG_TYP,
    subject_token_types_supported: [IDJAG_TOKEN_TYPE],
    jwks_uri: `${origin}/.well-known/jwks.json`,
  })
})

app.post('/agent/identity', async (c) => {
  const origin = new URL(c.req.url).origin
  const body = (await c.req.json().catch(() => ({}))) as { assertion?: string; jwks_uri?: string }
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

  // Verification key: a caller-advertised JWKS (SSRF-gated) or id.org.ai's own
  // signing JWKS for a self-issued ID-JAG.
  let key: CryptoKey | null
  if (body.jwks_uri !== undefined) {
    let jwks: unknown
    try {
      jwks = await safeFetchJson(body.jwks_uri)
    } catch (err: unknown) {
      return errorResponse(c, 400, ErrorCode.InvalidRequest, `jwks_uri fetch refused: ${errorMessage(err)}`)
    }
    key = await selectKeyFromJwks(jwks, decoded.header)
  } else {
    key = await selectLocalKey(c.env, decoded.header)
  }
  if (!key) return errorResponse(c, 401, ErrorCode.InvalidToken, 'no verification key for ID-JAG assertion')

  const iss = typeof decoded.payload.iss === 'string' ? decoded.payload.iss : undefined
  // The ID-JAG is presented TO this resource — its audience must be this origin.
  const result = await verifyJWT(assertion, { publicKey: key, audience: origin, ...(iss ? { issuer: iss } : {}) })
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
// accept, 400 on an invalid SET). The SET is verified (signature + typ +
// `events` shape + audience) before any action; an invalid SET is never acted
// on. Revocation acts idempotently on session/agent subjects it can resolve;
// broader downstream propagation is phased (advertised in conformance_notes).

const SET_ERR = (c: any, err: string, description: string) =>
  c.json({ err, description }, 400)

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

  // Verification key: header-advertised JWKS (SSRF-gated) or id.org.ai's own
  // signing JWKS for a self-issued SET.
  const remoteJwks = c.req.header('X-SET-JWKS-URI') ?? c.req.header('x-set-jwks-uri')
  let key: CryptoKey | null
  if (remoteJwks) {
    let jwks: unknown
    try {
      jwks = await safeFetchJson(remoteJwks)
    } catch (err: unknown) {
      return SET_ERR(c, 'invalid_request', `SET jwks fetch refused: ${errorMessage(err)}`)
    }
    key = await selectKeyFromJwks(jwks, decoded.header)
  } else {
    key = await selectLocalKey(c.env, decoded.header)
  }
  if (!key) return SET_ERR(c, 'invalid_key', 'no verification key for SET')

  const iss = typeof decoded.payload.iss === 'string' ? decoded.payload.iss : undefined
  // The SET is delivered TO this receiver — its audience must be this origin.
  const result = await verifyJWT(token, { publicKey: key, audience: origin, ...(iss ? { issuer: iss } : {}) })
  if (!result.valid) return SET_ERR(c, 'invalid_key', `SET verification failed: ${result.error}`)

  // Process revocation idempotently. Recognise a session/agent subject from the
  // SET's `sub`/`sub_id` and act where we can resolve it; unknown subjects are a
  // no-op (revocation is idempotent) but still yield 202 after verification.
  const subId = decoded.payload.sub_id as { format?: string; agent_id?: string; session?: string } | undefined
  const sub = typeof decoded.payload.sub === 'string' ? decoded.payload.sub : undefined
  const agentId = (subId && typeof subId.agent_id === 'string' && subId.agent_id) || undefined
  const sessionToken = (subId && typeof subId.session === 'string' && subId.session) || undefined

  try {
    if (sessionToken) {
      // Revoke the session by deleting its KV binding.
      await c.env.SESSIONS?.delete?.(`session:${sessionToken}`)
    }
    if (agentId) {
      const stub = getStubForIdentity(c.env, agentId)
      await stub.revokeAgent?.(agentId, 'SET revocation event')
    }
  } catch {
    // Best-effort revocation — the SET was cryptographically accepted; a
    // downstream store hiccup does not un-accept the event. Never leak details.
  }

  // RFC 8935 push delivery: 202 Accepted, empty body, on a validated SET.
  return c.body(null, 202)
})

export { app as aapRoutes }
