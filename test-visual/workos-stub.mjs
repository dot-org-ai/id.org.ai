#!/usr/bin/env node
/**
 * A tiny local stand-in for the WorkOS API, for browser-level flow tests
 * against `wrangler dev` (docs/product-update/prompts/01-foundation.md).
 *
 *   node test-visual/workos-stub.mjs                 # listens on 127.0.0.1:8788
 *   STUB_PORT=8798 node test-visual/workos-stub.mjs  # another port
 *
 * Point the worker at it with WORKOS_API_BASE=http://127.0.0.1:<port> in
 * worker/.dev.vars. Production never sees it: src/sdk/workos/base.ts only
 * honours loopback bases.
 *
 * It implements the endpoints the auth flows call (authorize redirect,
 * authenticate for every grant the worker uses, magic_auth, users,
 * organizations, memberships, invitations, MFA, JWKS) with fixture data, keeps
 * state in memory, and never sends email. Test controls live under /__stub:
 *   GET  /__stub/codes?email=…        the last Magic Auth code for an address
 *   POST /__stub/reset                forget everything created since start
 *   GET  /__stub/state                dump users, orgs, memberships, invitations
 *
 * Behaviour switches, for tests:
 *   authorize?provider=StubDeny       redirects back with error=access_denied
 *   authorize?login_hint=<email>      signs in as that fixture user (else Bryant)
 *   authenticate as mfa@example.com   returns an MFA challenge (code 123456)
 *   authenticate as multi@example.com returns organization_selection_required
 */
import { createServer } from 'node:http'
import { randomBytes } from 'node:crypto'

const PORT = Number(process.env.STUB_PORT || 8788)
const HOST = '127.0.0.1'
const MAGIC_CODE = '482913'
const TOTP_CODE = '123456'

const id = (prefix) => `${prefix}_stub_${randomBytes(6).toString('hex')}`
const now = () => new Date().toISOString()

function fixtures() {
  const users = [
    { id: 'user_stub_bryant', email: 'bryant@driv.ly', first_name: 'Bryant', last_name: 'Skarda', identities: [{ type: 'OAuth', provider: 'GitHubOAuth', idp_id: '1000001' }] },
    { id: 'user_stub_nathan', email: 'nathan@do.industries', first_name: 'Nathan', last_name: 'Clevenger', identities: [] },
    { id: 'user_stub_mfa', email: 'mfa@example.com', first_name: 'Mia', last_name: 'Factor', identities: [] },
    { id: 'user_stub_multi', email: 'multi@example.com', first_name: 'Max', last_name: 'Orgs', identities: [] },
  ].map((u) => ({ object: 'user', email_verified: true, profile_picture_url: null, created_at: now(), updated_at: now(), ...u }))
  const orgs = [
    { id: 'org_stub_drivly', name: 'Drivly', domains: [{ domain: 'driv.ly' }], metadata: {} },
    { id: 'org_stub_personal_bryant', name: 'Bryant Skarda', domains: [], metadata: { type: 'personal', owner: 'user_stub_bryant' } },
    { id: 'org_stub_acme', name: 'Acme', domains: [{ domain: 'acme.com' }], metadata: {}, sso: { connection_id: 'conn_stub_acme', type: 'OktaSAML', enforced: true } },
    { id: 'org_stub_beta', name: 'Beta', domains: [], metadata: {} },
  ].map((o) => ({ object: 'organization', allow_profiles_outside_organization: false, created_at: now(), updated_at: now(), ...o }))
  const memberships = [
    { user_id: 'user_stub_bryant', organization_id: 'org_stub_drivly', role: 'owner' },
    { user_id: 'user_stub_bryant', organization_id: 'org_stub_personal_bryant', role: 'owner' },
    { user_id: 'user_stub_nathan', organization_id: 'org_stub_drivly', role: 'admin' },
    { user_id: 'user_stub_multi', organization_id: 'org_stub_drivly', role: 'member' },
    { user_id: 'user_stub_multi', organization_id: 'org_stub_beta', role: 'member' },
  ].map((m) => ({ object: 'organization_membership', id: id('om'), status: 'active', created_at: now(), updated_at: now(), ...m, role: { slug: m.role } }))
  return { users, orgs, memberships, invitations: [], codes: new Map(), pending: new Map(), challenges: new Map() }
}

let db = fixtures()

const userByEmail = (email) => db.users.find((u) => u.email.toLowerCase() === String(email || '').toLowerCase())
const userById = (uid) => db.users.find((u) => u.id === uid)

/** An unsigned JWT-shaped access token: the worker only base64-decodes the payload. */
function accessToken(user, orgId) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url')
  const m = db.memberships.find((x) => x.user_id === user.id && x.organization_id === orgId)
  const payload = { sub: user.id, org_id: orgId, role: m?.role.slug, iss: 'https://api.workos.com', exp: Math.floor(Date.now() / 1000) + 300 }
  return `${enc({ alg: 'none', typ: 'JWT' })}.${enc(payload)}.stub`
}

function authResult(user, method, orgId) {
  const org = orgId ?? db.memberships.find((m) => m.user_id === user.id)?.organization_id
  return {
    user,
    organization_id: org,
    access_token: accessToken(user, org),
    refresh_token: id('rt'),
    authentication_method: method,
  }
}

/** Shared by every authenticate grant: MFA and org-selection switches, else success. */
function completeSignIn(res, user, method) {
  if (!user) return send(res, 400, { error: 'invalid_grant', error_description: 'Unknown user' })
  if (user.email === 'mfa@example.com') {
    const pending = id('pat')
    db.pending.set(pending, { userId: user.id, method })
    return send(res, 403, {
      code: 'mfa_challenge',
      message: 'The user must complete an MFA challenge to finish authenticating.',
      pending_authentication_token: pending,
      authentication_factors: [{ object: 'authentication_factor', id: 'auth_factor_stub_totp', type: 'totp' }],
      user,
    })
  }
  if (user.email === 'multi@example.com') {
    const pending = id('pat')
    db.pending.set(pending, { userId: user.id, method })
    const organizations = db.memberships
      .filter((m) => m.user_id === user.id)
      .map((m) => ({ id: m.organization_id, name: db.orgs.find((o) => o.id === m.organization_id)?.name }))
    return send(res, 403, { code: 'organization_selection_required', message: 'The user must choose an organization.', pending_authentication_token: pending, organizations, user })
  }
  return send(res, 200, authResult(user, method))
}

function send(res, status, body, headers = {}) {
  const text = body === undefined ? '' : JSON.stringify(body)
  res.writeHead(status, { 'content-type': 'application/json', ...headers })
  res.end(text)
}

async function readBody(req) {
  const chunks = []
  for await (const c of req) chunks.push(c)
  const raw = Buffer.concat(chunks).toString('utf8')
  if (!raw) return {}
  const type = req.headers['content-type'] || ''
  if (type.includes('application/x-www-form-urlencoded')) return Object.fromEntries(new URLSearchParams(raw))
  try {
    return JSON.parse(raw)
  } catch {
    return {}
  }
}

const list = (data) => ({ object: 'list', data, list_metadata: { before: null, after: null } })

const routes = [
  // ── Browser redirect: hosted AuthKit / OAuth providers / SSO ─────────────
  ['GET', /^\/user_management\/authorize$/, (req, res, _m, url) => {
    const redirect = url.searchParams.get('redirect_uri')
    const state = url.searchParams.get('state') || ''
    if (!redirect) return send(res, 400, { error: 'invalid_request', error_description: 'redirect_uri is required' })
    const back = new URL(redirect)
    // A stub must never walk a browser into production: loopback redirect_uris only.
    if (!['localhost', '127.0.0.1', '[::1]'].includes(back.hostname)) {
      return send(res, 400, { error: 'invalid_request', error_description: `workos-stub only redirects to loopback hosts, not ${back.hostname}. Run wrangler dev with --local-upstream (pnpm dev:worker).` })
    }
    if (url.searchParams.get('provider') === 'StubDeny') {
      back.searchParams.set('error', 'access_denied')
      back.searchParams.set('error_description', 'The user denied the request at the identity provider.')
    } else {
      const user = userByEmail(url.searchParams.get('login_hint')) ?? db.users[0]
      const code = id('code')
      db.codes.set(code, { userId: user.id, provider: url.searchParams.get('provider') || 'authkit', organizationId: url.searchParams.get('organization_id') })
      back.searchParams.set('code', code)
    }
    back.searchParams.set('state', state)
    res.writeHead(302, { location: back.toString() })
    res.end()
  }],

  // ── Every grant the worker uses ───────────────────────────────────────────
  ['POST', /^\/user_management\/authenticate$/, async (req, res) => {
    const b = await readBody(req)
    switch (b.grant_type) {
      case 'authorization_code': {
        const rec = db.codes.get(b.code)
        db.codes.delete(b.code)
        if (!rec) return send(res, 400, { error: 'invalid_grant', error_description: 'The code is invalid or expired.' })
        const method = { authkit: 'MagicAuth', GitHubOAuth: 'GitHubOAuth', GoogleOAuth: 'GoogleOAuth', MicrosoftOAuth: 'MicrosoftOAuth', AppleOAuth: 'AppleOAuth' }[rec.provider] ?? (rec.organizationId ? 'SSO' : 'GitHubOAuth')
        return completeSignIn(res, userById(rec.userId), method)
      }
      case 'urn:workos:oauth:grant-type:magic-auth:code': {
        const user = userByEmail(b.email)
        if (!user || b.code !== MAGIC_CODE) return send(res, 400, { code: 'invalid_one_time_code', message: 'The code is invalid.' })
        return completeSignIn(res, user, 'MagicAuth')
      }
      case 'urn:workos:oauth:grant-type:organization-selection': {
        const p = db.pending.get(b.pending_authentication_token)
        if (!p) return send(res, 400, { error: 'invalid_grant' })
        db.pending.delete(b.pending_authentication_token)
        return send(res, 200, authResult(userById(p.userId), p.method, b.organization_id))
      }
      case 'urn:workos:oauth:grant-type:mfa-totp': {
        const p = db.pending.get(b.pending_authentication_token)
        if (!p || b.code !== TOTP_CODE) return send(res, 400, { code: 'authentication_challenge_failed', message: 'The code is invalid.' })
        db.pending.delete(b.pending_authentication_token)
        return send(res, 200, authResult(userById(p.userId), p.method))
      }
      case 'refresh_token':
        return send(res, 200, { access_token: accessToken(db.users[0], b.organization_id), refresh_token: id('rt') })
      default:
        return send(res, 400, { error: 'unsupported_grant_type' })
    }
  }],

  // ── Magic Auth: never emails; the code is fixed and readable at /__stub/codes ──
  ['POST', /^\/user_management\/magic_auth$/, async (req, res) => {
    const b = await readBody(req)
    if (!b.email) return send(res, 422, { code: 'invalid_request', message: 'email is required' })
    let user = userByEmail(b.email)
    if (!user) {
      user = { object: 'user', id: id('user'), email: b.email, first_name: null, last_name: null, email_verified: true, identities: [], created_at: now(), updated_at: now() }
      db.users.push(user)
    }
    db.codes.set(`magic:${b.email.toLowerCase()}`, MAGIC_CODE)
    console.log(`[workos-stub] magic auth code for ${b.email}: ${MAGIC_CODE}`)
    return send(res, 201, { object: 'magic_auth', id: id('magic_auth'), user_id: user.id, email: b.email, expires_at: new Date(Date.now() + 600_000).toISOString(), code: MAGIC_CODE })
  }],

  // ── Users ──────────────────────────────────────────────────────────────
  ['GET', /^\/user_management\/users\/([^/]+)$/, (req, res, m) => {
    const u = userById(m[1])
    return u ? send(res, 200, u) : send(res, 404, { message: 'Not found' })
  }],
  ['PUT', /^\/user_management\/users\/([^/]+)$/, async (req, res, m) => {
    const u = userById(m[1])
    if (!u) return send(res, 404, { message: 'Not found' })
    Object.assign(u, await readBody(req), { updated_at: now() })
    return send(res, 200, u)
  }],

  // ── Organizations ───────────────────────────────────────────────────────
  ['GET', /^\/organizations$/, (req, res, _m, url) => {
    const domains = url.searchParams.getAll('domains').flatMap((d) => d.split(','))
    const data = domains.length ? db.orgs.filter((o) => o.domains.some((d) => domains.includes(d.domain))) : db.orgs
    return send(res, 200, list(data))
  }],
  ['GET', /^\/organizations\/([^/]+)$/, (req, res, m) => {
    const o = db.orgs.find((x) => x.id === m[1])
    return o ? send(res, 200, o) : send(res, 404, { message: 'Not found' })
  }],
  ['POST', /^\/organizations$/, async (req, res) => {
    const b = await readBody(req)
    const o = { object: 'organization', id: id('org'), name: b.name, domains: [], metadata: b.metadata ?? {}, created_at: now(), updated_at: now() }
    db.orgs.push(o)
    return send(res, 201, o)
  }],
  ['PUT', /^\/organizations\/([^/]+)$/, async (req, res, m) => {
    const o = db.orgs.find((x) => x.id === m[1])
    if (!o) return send(res, 404, { message: 'Not found' })
    Object.assign(o, await readBody(req), { updated_at: now() })
    return send(res, 200, o)
  }],

  // ── SSO connections (for SSO discovery by domain) ─────────────────────────
  ['GET', /^\/connections$/, (req, res, _m, url) => {
    const orgId = url.searchParams.get('organization_id')
    const data = db.orgs
      .filter((o) => o.sso && (!orgId || o.id === orgId))
      .map((o) => ({ object: 'connection', id: o.sso.connection_id, organization_id: o.id, connection_type: o.sso.type, name: o.name, state: 'active' }))
    return send(res, 200, list(data))
  }],

  // ── Memberships ─────────────────────────────────────────────────────────
  ['GET', /^\/user_management\/organization_memberships$/, (req, res, _m, url) => {
    const uid = url.searchParams.get('user_id')
    const oid = url.searchParams.get('organization_id')
    const limit = Number(url.searchParams.get('limit') || 100)
    const data = db.memberships.filter((x) => (!uid || x.user_id === uid) && (!oid || x.organization_id === oid)).slice(0, limit)
    return send(res, 200, list(data))
  }],
  ['POST', /^\/user_management\/organization_memberships$/, async (req, res) => {
    const b = await readBody(req)
    const mbr = { object: 'organization_membership', id: id('om'), user_id: b.user_id, organization_id: b.organization_id, role: { slug: b.role_slug || 'member' }, status: 'active', created_at: now(), updated_at: now() }
    db.memberships.push(mbr)
    return send(res, 201, mbr)
  }],
  ['PUT', /^\/user_management\/organization_memberships\/([^/]+)$/, async (req, res, m) => {
    const mbr = db.memberships.find((x) => x.id === m[1])
    if (!mbr) return send(res, 404, { message: 'Not found' })
    const b = await readBody(req)
    if (b.role_slug) mbr.role = { slug: b.role_slug }
    return send(res, 200, mbr)
  }],
  ['DELETE', /^\/user_management\/organization_memberships\/([^/]+)$/, (req, res, m) => {
    db.memberships = db.memberships.filter((x) => x.id !== m[1])
    return send(res, 202, undefined)
  }],

  // ── Invitations ─────────────────────────────────────────────────────────
  ['POST', /^\/user_management\/invitations$/, async (req, res) => {
    const b = await readBody(req)
    const token = randomBytes(12).toString('hex')
    const inv = {
      object: 'invitation', id: id('invitation'), email: b.email, state: 'pending', organization_id: b.organization_id, inviter_user_id: b.inviter_user_id ?? null,
      token, accept_invitation_url: `https://id.org.ai/invite/${token}`, role_slug: b.role_slug || 'member',
      expires_at: new Date(Date.now() + 6 * 86_400_000).toISOString(), created_at: now(), updated_at: now(),
    }
    db.invitations.push(inv)
    return send(res, 201, inv)
  }],
  ['GET', /^\/user_management\/invitations$/, (req, res, _m, url) => {
    const oid = url.searchParams.get('organization_id')
    return send(res, 200, list(db.invitations.filter((i) => !oid || i.organization_id === oid)))
  }],
  ['GET', /^\/user_management\/invitations\/by_token\/([^/]+)$/, (req, res, m) => {
    const inv = db.invitations.find((i) => i.token === m[1])
    return inv ? send(res, 200, inv) : send(res, 404, { message: 'Not found' })
  }],
  ['GET', /^\/user_management\/invitations\/([^/]+)$/, (req, res, m) => {
    const inv = db.invitations.find((i) => i.id === m[1])
    return inv ? send(res, 200, inv) : send(res, 404, { message: 'Not found' })
  }],
  ['POST', /^\/user_management\/invitations\/([^/]+)\/(accept|revoke)$/, (req, res, m) => {
    const inv = db.invitations.find((i) => i.id === m[1])
    if (!inv) return send(res, 404, { message: 'Not found' })
    inv.state = m[2] === 'accept' ? 'accepted' : 'revoked'
    if (m[2] === 'accept') {
      const user = userByEmail(inv.email)
      if (user) db.memberships.push({ object: 'organization_membership', id: id('om'), user_id: user.id, organization_id: inv.organization_id, role: { slug: inv.role_slug }, status: 'active', created_at: now(), updated_at: now() })
    }
    return send(res, 200, inv)
  }],

  // ── MFA challenge helpers ────────────────────────────────────────────────
  ['POST', /^\/auth\/factors\/([^/]+)\/challenge$/, (req, res, m) => {
    const challenge = { object: 'authentication_challenge', id: id('auth_challenge'), authentication_factor_id: m[1], expires_at: new Date(Date.now() + 600_000).toISOString() }
    db.challenges.set(challenge.id, challenge)
    return send(res, 201, challenge)
  }],
  ['POST', /^\/auth\/challenges\/([^/]+)\/verify$/, async (req, res, m) => {
    const b = await readBody(req)
    if (!db.challenges.has(m[1])) return send(res, 404, { message: 'Not found' })
    return send(res, 200, { challenge: db.challenges.get(m[1]), valid: b.code === TOTP_CODE })
  }],

  // ── Keys and JWKS (verification paths that must not reach api.workos.com) ──
  ['GET', /^\/sso\/jwks\/[^/]+$/, (req, res) => send(res, 200, { keys: [] })],
  ['POST', /^\/api_keys\/validations$/, (req, res) => send(res, 200, { api_key: null })],

  // ── Test controls ──────────────────────────────────────────────────────
  ['GET', /^\/__stub\/codes$/, (req, res, _m, url) => {
    const code = db.codes.get(`magic:${String(url.searchParams.get('email') || '').toLowerCase()}`)
    return code ? send(res, 200, { code }) : send(res, 404, { message: 'No code for that address' })
  }],
  ['POST', /^\/__stub\/reset$/, (req, res) => {
    db = fixtures()
    return send(res, 200, { ok: true })
  }],
  ['GET', /^\/__stub\/state$/, (req, res) => send(res, 200, { users: db.users, orgs: db.orgs, memberships: db.memberships, invitations: db.invitations })],
]

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${HOST}:${PORT}`)
  for (const [method, re, handler] of routes) {
    const m = url.pathname.match(re)
    if (m && req.method === method) {
      try {
        await handler(req, res, m, url)
      } catch (e) {
        send(res, 500, { message: String(e?.message || e) })
      }
      return
    }
  }
  send(res, 404, { message: `workos-stub: no route for ${req.method} ${url.pathname}` })
})

server.listen(PORT, HOST, () => console.log(`[workos-stub] listening on http://${HOST}:${PORT}`))
