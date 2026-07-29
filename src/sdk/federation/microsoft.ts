/**
 * Upstream Microsoft OIDC — Entra ID (formerly Azure AD) as an upstream IdP.
 *
 * ## Why this shape
 *
 * The target case is a viewer at a large enterprise (Zebra Technologies) whose
 * Entra tenant federates to Ping Identity. We integrate **Microsoft only**.
 * When `alice@zebra.com` signs in, Entra performs home-realm discovery, sees
 * that zebra.com is federated, and bounces her to Ping; Ping authenticates her
 * and asserts back to Entra; Entra issues US an id_token. Ping traversal is
 * free — there is nothing Ping-specific to implement, and implementing against
 * Ping directly would require a per-customer SAML/OIDC connection we cannot
 * get without Zebra IT's involvement.
 *
 * ## Multi-tenant, minimal scopes
 *
 * The app registration is **multi-tenant** (`signInAudience:
 * AzureADMultipleOrgs`) and the authority is `/organizations`, so ANY work or
 * school account can sign in with no per-tenant setup on our side.
 *
 * We request exactly `openid profile email` and nothing else. This is a
 * survival strategy, not minimalism for its own sake: those three are OIDC
 * standard scopes that most tenants' user-consent policies permit users to
 * grant themselves. Add a single Graph scope (`User.Read`, `offline_access`
 * on a resource) and a tenant with "user consent disabled" or "consent allowed
 * only for verified publishers" turns the sign-in into an admin-consent
 * request, which no viewer can complete on their own. See
 * `classifyMicrosoftError` — when it fails anyway, we fall back to email codes.
 *
 * ## PKCE, always
 *
 * Authorization code + PKCE S256 (OAuth 2.1 mandatory; the repo's own OAuth
 * provider already enforces it). The client secret is OPTIONAL here: a
 * confidential web app sends both secret and verifier; a public client sends
 * verifier alone. Supporting both means the owner can register either app type
 * without a code change.
 *
 * Portable: no `cloudflare:workers` import, no worker-relative imports.
 */
import * as jose from 'jose'
import { generatePkce } from '../oauth/pkce'
import { FederationError, emailDomainOf } from './types'
import type { FederatedPrincipal, FederationProvenance } from './types'

// ── Constants ─────────────────────────────────────────────────────────────

export const MICROSOFT_AUTHORITY = 'https://login.microsoftonline.com'

/**
 * The only scopes we ever request. Exported so a test can assert nobody
 * quietly widened it — scope creep here is the single most likely cause of a
 * Zebra sign-in failing.
 */
export const MICROSOFT_SCOPES = ['openid', 'profile', 'email'] as const

/**
 * `organizations` = work/school accounts in ANY Entra tenant, personal
 * Microsoft accounts excluded. `common` would also admit consumer MSAs
 * (outlook.com, hotmail.com), which for a corporate deck gate is noise, not
 * reach — a personal MSA proves nothing about employment.
 */
export const MICROSOFT_DEFAULT_TENANT = 'organizations'

/**
 * The well-known `tid` of the Microsoft consumer (MSA) tenant. Rejected: a
 * personal account carries no organisational meaning. Kept explicit because
 * `/organizations` already blocks it — this is defence in depth in case an
 * operator switches the authority to `/common`.
 */
export const MSA_CONSUMER_TENANT_ID = '9188040d-6c67-4c5b-b112-36a304b66dad'

// ── Configuration ─────────────────────────────────────────────────────────

export interface MicrosoftConfig {
  /** Entra application (client) ID — a GUID. */
  clientId: string
  /** Client secret. Omit for a public-client registration (PKCE only). */
  clientSecret?: string
  /** Redirect URI, registered verbatim in the app registration. */
  redirectUri: string
  /** Authority tenant segment. Defaults to `organizations`. */
  tenant?: string
}

/** True iff enough config exists to attempt an upstream Microsoft sign-in. */
export function isMicrosoftConfigured(config: Partial<MicrosoftConfig> | undefined): config is MicrosoftConfig {
  return !!(config && config.clientId && config.redirectUri)
}

// ── Authorization request ─────────────────────────────────────────────────

/** Everything the callback needs to finish what `startMicrosoftAuth` began. */
export interface MicrosoftAuthState {
  /** PKCE verifier — never leaves the broker. */
  codeVerifier: string
  /** OIDC nonce — echoed in the id_token, binds the token to this request. */
  nonce: string
  /** Where to send the browser after a successful sign-in. */
  continueUrl: string
  /** Epoch ms after which this transaction is dead. */
  expiresAt: number
  /** Login hint the viewer was sent with, if any. Advisory. */
  loginHint?: string
}

export interface StartMicrosoftAuthResult {
  /** Where to redirect the browser. */
  authorizationUrl: string
  /** Opaque state value — the storage key AND the CSRF token. */
  state: string
  /** Store under `state`; hand back to `completeMicrosoftAuth`. */
  transaction: MicrosoftAuthState
}

export interface StartMicrosoftAuthOptions {
  continueUrl: string
  /**
   * Pre-fills the account picker (`login_hint`). Passing the viewer's work
   * email makes Entra's home-realm discovery jump straight to Ping for a
   * federated domain — one fewer screen for a Zebra viewer.
   */
  loginHint?: string
  /** Transaction lifetime. Default 10 minutes. */
  ttlMs?: number
  /**
   * `select_account` (default) forces the account chooser, which avoids
   * silently reusing a personal account that happens to be signed in.
   */
  prompt?: 'login' | 'select_account' | 'consent' | 'none'
}

/**
 * Build the Entra authorization URL and the transaction the callback will
 * need. Pure apart from `crypto.getRandomValues` — the caller owns storage.
 */
export async function startMicrosoftAuth(
  config: MicrosoftConfig,
  options: StartMicrosoftAuthOptions,
): Promise<StartMicrosoftAuthResult> {
  const { verifier, challenge } = await generatePkce()
  const state = randomUrlSafe(32)
  const nonce = randomUrlSafe(32)
  const ttlMs = options.ttlMs ?? 10 * 60 * 1000

  const url = new URL(`${MICROSOFT_AUTHORITY}/${config.tenant ?? MICROSOFT_DEFAULT_TENANT}/oauth2/v2.0/authorize`)
  url.searchParams.set('client_id', config.clientId)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('redirect_uri', config.redirectUri)
  url.searchParams.set('response_mode', 'query')
  url.searchParams.set('scope', MICROSOFT_SCOPES.join(' '))
  url.searchParams.set('state', state)
  url.searchParams.set('nonce', nonce)
  url.searchParams.set('code_challenge', challenge)
  url.searchParams.set('code_challenge_method', 'S256')
  url.searchParams.set('prompt', options.prompt ?? 'select_account')
  if (options.loginHint) url.searchParams.set('login_hint', options.loginHint)

  return {
    authorizationUrl: url.toString(),
    state,
    transaction: {
      codeVerifier: verifier,
      nonce,
      continueUrl: options.continueUrl,
      expiresAt: Date.now() + ttlMs,
      loginHint: options.loginHint,
    },
  }
}

// ── Token exchange ────────────────────────────────────────────────────────

export interface MicrosoftTokenResponse {
  id_token: string
  access_token?: string
  token_type?: string
  expires_in?: number
  scope?: string
}

/**
 * Exchange the authorization code for tokens. Sends the PKCE verifier always;
 * sends the client secret only when one is configured.
 */
export async function exchangeMicrosoftCode(
  config: MicrosoftConfig,
  code: string,
  codeVerifier: string,
): Promise<MicrosoftTokenResponse> {
  const tokenUrl = `${MICROSOFT_AUTHORITY}/${config.tenant ?? MICROSOFT_DEFAULT_TENANT}/oauth2/v2.0/token`

  const body: Record<string, string> = {
    client_id: config.clientId,
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.redirectUri,
    code_verifier: codeVerifier,
    scope: MICROSOFT_SCOPES.join(' '),
  }
  if (config.clientSecret) body.client_secret = config.clientSecret

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body).toString(),
  })

  const text = await response.text()
  if (!response.ok) {
    let parsed: { error?: string; error_description?: string } = {}
    try {
      parsed = JSON.parse(text)
    } catch {
      // Non-JSON upstream error — surfaced verbatim below.
    }
    throw classifyMicrosoftError(parsed.error, parsed.error_description ?? text)
  }

  const json = JSON.parse(text) as MicrosoftTokenResponse
  if (!json.id_token) {
    throw new FederationError('invalid-token', 'Microsoft token response carried no id_token')
  }
  return json
}

// ── id_token verification ─────────────────────────────────────────────────

/**
 * The id_token claims we consume. Entra emits more; we deliberately read only
 * what maps to a principal.
 */
export interface MicrosoftIdTokenClaims {
  iss: string
  aud: string
  sub: string
  /** Immutable per-user-per-tenant object id. THE stable subject. */
  oid: string
  /** Tenant id GUID. */
  tid: string
  nonce?: string
  email?: string
  /** Usually the UPN for work accounts; the fallback when `email` is absent. */
  preferred_username?: string
  upn?: string
  name?: string
  exp: number
  iat: number
}

export interface VerifyMicrosoftIdTokenOptions {
  clientId: string
  /** The nonce issued in the authorization request. Required — no exceptions. */
  nonce: string
  /**
   * Allow-list of Entra tenant GUIDs. Empty/undefined = any tenant (the point
   * of a multi-tenant app). Present = only these tenants pass, which is how an
   * operator would later lock the broker to Zebra alone.
   */
  allowedTenants?: string[]
  /** Reject personal Microsoft accounts. Default true. */
  rejectConsumerTenant?: boolean
  /** Clock skew tolerance in seconds. Default 60. */
  clockToleranceSec?: number
}

/**
 * Key-set resolution is injectable so tests can verify a locally-signed token
 * without reaching login.microsoftonline.com. Production uses the default,
 * which fetches the TENANT-SPECIFIC JWKS.
 */
export interface MicrosoftVerifyDeps {
  getKeySet(tenantId: string): jose.JWTVerifyGetKey | Promise<jose.JWTVerifyGetKey>
}

const remoteKeySets = new Map<string, jose.JWTVerifyGetKey>()

const defaultVerifyDeps: MicrosoftVerifyDeps = {
  getKeySet(tenantId: string) {
    const cached = remoteKeySets.get(tenantId)
    if (cached) return cached
    const keySet = jose.createRemoteJWKSet(new URL(`${MICROSOFT_AUTHORITY}/${tenantId}/discovery/v2.0/keys`))
    remoteKeySets.set(tenantId, keySet)
    return keySet
  },
}

/**
 * Verify a Microsoft id_token and return its claims.
 *
 * The multi-tenant subtlety this function exists to get right: with a
 * multi-tenant app the issuer is NOT a constant — it is
 * `https://login.microsoftonline.com/<tid>/v2.0`, different per customer. So
 * we (1) read `tid` from the UNVERIFIED payload only to pick which key set and
 * which issuer to expect, then (2) verify signature + issuer + audience +
 * nonce against that choice. Step 1 alone proves nothing; every claim used for
 * identity comes from step 2's verified output.
 */
export async function verifyMicrosoftIdToken(
  idToken: string,
  options: VerifyMicrosoftIdTokenOptions,
  deps: MicrosoftVerifyDeps = defaultVerifyDeps,
): Promise<MicrosoftIdTokenClaims> {
  let unverifiedTid: string | undefined
  try {
    const decoded = jose.decodeJwt(idToken) as { tid?: string }
    unverifiedTid = decoded.tid
  } catch {
    throw new FederationError('invalid-token', 'id_token is not a well-formed JWT')
  }

  if (!unverifiedTid || !/^[0-9a-fA-F-]{36}$/.test(unverifiedTid)) {
    throw new FederationError('invalid-token', 'id_token carries no usable tenant id (tid)')
  }

  if (options.rejectConsumerTenant !== false && unverifiedTid.toLowerCase() === MSA_CONSUMER_TENANT_ID) {
    throw new FederationError(
      'access-denied',
      'Personal Microsoft accounts are not accepted — sign in with your work account',
    )
  }

  if (options.allowedTenants?.length) {
    const allowed = options.allowedTenants.map((t) => t.toLowerCase())
    if (!allowed.includes(unverifiedTid.toLowerCase())) {
      throw new FederationError('access-denied', 'Your Microsoft tenant is not permitted for this resource')
    }
  }

  const keySet = await deps.getKeySet(unverifiedTid)
  const expectedIssuer = `${MICROSOFT_AUTHORITY}/${unverifiedTid}/v2.0`

  let payload: jose.JWTPayload
  try {
    const result = await jose.jwtVerify(idToken, keySet, {
      issuer: expectedIssuer,
      audience: options.clientId,
      clockTolerance: options.clockToleranceSec ?? 60,
    })
    payload = result.payload
  } catch (err) {
    throw new FederationError('invalid-token', `id_token verification failed: ${(err as Error).message}`)
  }

  // Nonce binding — without this a token minted for a different sign-in
  // attempt (or replayed) would be accepted.
  if (payload.nonce !== options.nonce) {
    throw new FederationError('invalid-token', 'id_token nonce does not match this sign-in attempt')
  }

  // Re-assert tid from the VERIFIED payload. The unverified read above only
  // chose a key set; if the signed body disagrees, something is very wrong.
  const verifiedTid = payload.tid as string | undefined
  if (!verifiedTid || verifiedTid.toLowerCase() !== unverifiedTid.toLowerCase()) {
    throw new FederationError('invalid-token', 'id_token tenant id mismatch between header scan and signed payload')
  }

  const oid = payload.oid as string | undefined
  if (!oid) {
    throw new FederationError('invalid-token', 'id_token carries no oid — cannot form a stable subject')
  }

  return payload as unknown as MicrosoftIdTokenClaims
}

// ── Principal mapping ─────────────────────────────────────────────────────

/**
 * Map verified Entra claims onto the broker's principal shape.
 *
 * Email resolution order — `email`, then `preferred_username`, then `upn`.
 * Entra only emits `email` when the optional claim is configured OR the user
 * has a mail attribute; for a great many work accounts `preferred_username` IS
 * the work email, so falling back is the difference between working and not.
 * A value without an `@` is refused rather than guessed at.
 */
export function microsoftPrincipal(claims: MicrosoftIdTokenClaims): FederatedPrincipal {
  const candidate = [claims.email, claims.preferred_username, claims.upn].find((v) => !!v && v.includes('@'))
  if (!candidate) {
    throw new FederationError(
      'invalid-token',
      'Microsoft account exposed no email address — ask your admin to release the email claim, or use the email code option',
    )
  }
  const email = candidate.toLowerCase()
  const tid = claims.tid.toLowerCase()

  const provenance: FederationProvenance = {
    provider: 'microsoft',
    issuer: `${MICROSOFT_AUTHORITY}/${tid}/v2.0`,
    tenantId: tid,
    subject: claims.oid,
    assurance: 'federated-idp',
    verifiedAt: Date.now(),
    emailDomain: emailDomainOf(email),
    displayName: claims.name,
  }

  return {
    identityId: `human:ms:${tid}:${claims.oid}`,
    email,
    name: claims.name?.trim() || email.split('@')[0]!,
    provenance,
  }
}

// ── Error classification ──────────────────────────────────────────────────

/**
 * Entra error codes that mean "this tenant will not let this user consent to
 * this app". Every one of them is a signal to offer the email-code fallback,
 * NOT to show a stack trace.
 *
 *   AADSTS65001 — user or admin has not consented to the application
 *   AADSTS65004 — user declined to consent
 *   AADSTS90094 — the grant requires admin permission (admin consent required)
 *   AADSTS900xx/AADSTS50105 — app not assigned / assignment required
 *   AADSTS530xxx — conditional access blocked the sign-in for this app
 */
const CONSENT_CODES = ['AADSTS65001', 'AADSTS65004', 'AADSTS90094', 'AADSTS90093', 'AADSTS50105']

/**
 * Turn an OAuth `error` + `error_description` pair into a typed
 * FederationError. Used for BOTH the redirect-back error params and token
 * endpoint failures, because Entra reports the same conditions through both.
 */
export function classifyMicrosoftError(error: string | undefined, description: string | undefined): FederationError {
  const desc = description ?? ''
  const upstreamCode = desc.match(/AADSTS\d+/)?.[0] ?? error

  if (error === 'consent_required' || error === 'interaction_required' || CONSENT_CODES.some((c) => desc.includes(c))) {
    return new FederationError(
      'consent-required',
      'Your organisation blocks sign-in to apps it has not approved',
      upstreamCode,
    )
  }

  if (error === 'access_denied') {
    // access_denied covers both "user clicked cancel" and "policy said no".
    // The description carries an AADSTS code in the policy case; without one,
    // treat it as a user cancellation.
    return new FederationError('access-denied', desc || 'Sign-in was cancelled', upstreamCode)
  }

  if (!error && !desc) {
    return new FederationError('upstream-error', 'Microsoft returned an unspecified error')
  }

  return new FederationError('upstream-error', desc || error || 'Microsoft sign-in failed', upstreamCode)
}

// ── Internals ─────────────────────────────────────────────────────────────

/** URL-safe random string. Same charset discipline as sdk/oauth/pkce.ts. */
function randomUrlSafe(bytes: number): string {
  const buf = crypto.getRandomValues(new Uint8Array(bytes))
  let binary = ''
  for (let i = 0; i < buf.length; i++) binary += String.fromCharCode(buf[i]!)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
