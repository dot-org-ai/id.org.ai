/**
 * Upstream Microsoft OIDC — unit tests.
 *
 * Covers the four things that decide whether a Zebra viewer gets in:
 *   1. The authorization request (multi-tenant authority, PKCE, MINIMAL scopes)
 *   2. The code exchange (verifier always, secret only when configured)
 *   3. id_token verification (per-tenant issuer + JWKS, nonce binding)
 *   4. Error classification (consent-blocked → the fallback, not a 500)
 *
 * The id_token tests sign real RS256 tokens with a locally generated key and
 * inject the key set, so signature/issuer/audience/nonce logic is exercised for
 * real without reaching login.microsoftonline.com.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import * as jose from 'jose'
import {
  startMicrosoftAuth,
  exchangeMicrosoftCode,
  verifyMicrosoftIdToken,
  microsoftPrincipal,
  classifyMicrosoftError,
  isMicrosoftConfigured,
  MICROSOFT_SCOPES,
  MICROSOFT_AUTHORITY,
  MSA_CONSUMER_TENANT_ID,
} from '../src/sdk/federation/microsoft'
import type { MicrosoftConfig, MicrosoftIdTokenClaims } from '../src/sdk/federation/microsoft'
import { FederationError } from '../src/sdk/federation/types'

// ── Fixtures ──────────────────────────────────────────────────────────────

/** A plausible Zebra tenant id. Any GUID works; naming it keeps tests legible. */
const ZEBRA_TID = '1cd51b26-8a29-4b1f-9e7a-6f2c05a3d417'
const ZEBRA_OID = '7c1b0d34-2f55-4c9a-b3e1-9a4d8f2e6b70'
const CLIENT_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

const config: MicrosoftConfig = {
  clientId: CLIENT_ID,
  clientSecret: 'entra-secret',
  redirectUri: 'https://id.org.ai/federation/microsoft/callback',
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

/** Generate a signing key + a matching local JWKS resolver. */
async function makeSigner() {
  const { privateKey, publicKey } = await jose.generateKeyPair('RS256', { extractable: true })
  const jwk = await jose.exportJWK(publicKey)
  jwk.kid = 'test-key'
  jwk.alg = 'RS256'
  const keySet = jose.createLocalJWKSet({ keys: [jwk] })

  async function sign(claims: Record<string, unknown>, overrides: { issuer?: string; audience?: string } = {}) {
    return new jose.SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuedAt()
      .setExpirationTime('5m')
      .setIssuer(overrides.issuer ?? `${MICROSOFT_AUTHORITY}/${ZEBRA_TID}/v2.0`)
      .setAudience(overrides.audience ?? CLIENT_ID)
      .sign(privateKey)
  }

  return { sign, deps: { getKeySet: () => keySet } }
}

// ── 1. Authorization request ──────────────────────────────────────────────

describe('startMicrosoftAuth', () => {
  it('targets the /organizations authority by default — work accounts, any tenant', async () => {
    const { authorizationUrl } = await startMicrosoftAuth(config, { continueUrl: '/deck' })
    expect(authorizationUrl.startsWith(`${MICROSOFT_AUTHORITY}/organizations/oauth2/v2.0/authorize`)).toBe(true)
  })

  it('honours an explicit tenant override', async () => {
    const { authorizationUrl } = await startMicrosoftAuth({ ...config, tenant: ZEBRA_TID }, { continueUrl: '/' })
    expect(authorizationUrl).toContain(`/${ZEBRA_TID}/oauth2/v2.0/authorize`)
  })

  it('requests ONLY openid profile email — scope creep here is what breaks locked-down tenants', async () => {
    const { authorizationUrl } = await startMicrosoftAuth(config, { continueUrl: '/' })
    const scope = new URL(authorizationUrl).searchParams.get('scope')
    expect(scope).toBe('openid profile email')
    // Guard the constant itself, so widening it fails here rather than in a
    // customer's tenant six weeks later.
    expect([...MICROSOFT_SCOPES]).toEqual(['openid', 'profile', 'email'])
  })

  it('never requests offline_access or a Graph scope', async () => {
    const { authorizationUrl } = await startMicrosoftAuth(config, { continueUrl: '/' })
    const scope = new URL(authorizationUrl).searchParams.get('scope') ?? ''
    expect(scope).not.toContain('offline_access')
    expect(scope).not.toContain('User.Read')
    expect(scope).not.toContain('https://graph.microsoft.com')
  })

  it('uses PKCE S256', async () => {
    const { authorizationUrl, transaction } = await startMicrosoftAuth(config, { continueUrl: '/' })
    const params = new URL(authorizationUrl).searchParams
    expect(params.get('code_challenge_method')).toBe('S256')
    expect(params.get('code_challenge')).toBeTruthy()
    expect(transaction.codeVerifier.length).toBeGreaterThanOrEqual(43)
    // The verifier must NOT appear in the URL — that would defeat PKCE entirely.
    expect(authorizationUrl).not.toContain(transaction.codeVerifier)
  })

  it('binds the request with a nonce carried in the transaction', async () => {
    const { authorizationUrl, transaction } = await startMicrosoftAuth(config, { continueUrl: '/' })
    expect(new URL(authorizationUrl).searchParams.get('nonce')).toBe(transaction.nonce)
  })

  it('issues a fresh state and verifier on every call', async () => {
    const a = await startMicrosoftAuth(config, { continueUrl: '/' })
    const b = await startMicrosoftAuth(config, { continueUrl: '/' })
    expect(a.state).not.toBe(b.state)
    expect(a.transaction.codeVerifier).not.toBe(b.transaction.codeVerifier)
    expect(a.transaction.nonce).not.toBe(b.transaction.nonce)
  })

  it('passes login_hint through so a federated domain skips the account chooser', async () => {
    const { authorizationUrl } = await startMicrosoftAuth(config, {
      continueUrl: '/',
      loginHint: 'alice@zebra.com',
    })
    expect(new URL(authorizationUrl).searchParams.get('login_hint')).toBe('alice@zebra.com')
  })

  it('carries the continue URL and an expiry on the transaction', async () => {
    const before = Date.now()
    const { transaction } = await startMicrosoftAuth(config, { continueUrl: '/deck/zebra' })
    expect(transaction.continueUrl).toBe('/deck/zebra')
    expect(transaction.expiresAt).toBeGreaterThan(before)
  })
})

describe('isMicrosoftConfigured', () => {
  it('needs a client id and a redirect uri, but NOT a secret (public client)', () => {
    expect(isMicrosoftConfigured({ clientId: 'x', redirectUri: 'https://id.org.ai/cb' })).toBe(true)
    expect(isMicrosoftConfigured({ clientId: 'x' })).toBe(false)
    expect(isMicrosoftConfigured(undefined)).toBe(false)
  })
})

// ── 2. Code exchange ──────────────────────────────────────────────────────

describe('exchangeMicrosoftCode', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })
  afterEach(() => vi.restoreAllMocks())

  it('posts the PKCE verifier and the secret to the tenant token endpoint', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ id_token: 'header.body.sig' }))
    await exchangeMicrosoftCode(config, 'code_abc', 'verifier_xyz')

    const [url, options] = mockFetch.mock.calls[0]
    expect(url).toBe(`${MICROSOFT_AUTHORITY}/organizations/oauth2/v2.0/token`)
    const body = new URLSearchParams(options.body as string)
    expect(body.get('grant_type')).toBe('authorization_code')
    expect(body.get('code')).toBe('code_abc')
    expect(body.get('code_verifier')).toBe('verifier_xyz')
    expect(body.get('client_secret')).toBe('entra-secret')
    expect(body.get('redirect_uri')).toBe(config.redirectUri)
  })

  it('omits client_secret for a public-client registration', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ id_token: 'header.body.sig' }))
    await exchangeMicrosoftCode({ ...config, clientSecret: undefined }, 'code_abc', 'verifier_xyz')

    const body = new URLSearchParams(mockFetch.mock.calls[0][1].body as string)
    expect(body.get('client_secret')).toBeNull()
    expect(body.get('code_verifier')).toBe('verifier_xyz')
  })

  it('classifies an AADSTS65001 token error as consent-required', async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse(
        {
          error: 'invalid_grant',
          error_description: "AADSTS65001: The user or administrator has not consented to use the application",
        },
        400,
      ),
    )
    await expect(exchangeMicrosoftCode(config, 'c', 'v')).rejects.toMatchObject({
      kind: 'consent-required',
      upstreamCode: 'AADSTS65001',
    })
  })

  it('rejects a token response with no id_token', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ access_token: 'at' }))
    await expect(exchangeMicrosoftCode(config, 'c', 'v')).rejects.toBeInstanceOf(FederationError)
  })
})

// ── 3. id_token verification ──────────────────────────────────────────────

describe('verifyMicrosoftIdToken', () => {
  const nonce = 'nonce-123'

  const baseClaims = {
    tid: ZEBRA_TID,
    oid: ZEBRA_OID,
    nonce,
    email: 'Alice@Zebra.com',
    name: 'Alice Anders',
  }

  it('accepts a token signed by the tenant key with matching issuer, audience and nonce', async () => {
    const { sign, deps } = await makeSigner()
    const token = await sign(baseClaims)
    const claims = await verifyMicrosoftIdToken(token, { clientId: CLIENT_ID, nonce }, deps)
    expect(claims.oid).toBe(ZEBRA_OID)
    expect(claims.tid).toBe(ZEBRA_TID)
  })

  it('rejects a token whose nonce is not the one we issued (replay)', async () => {
    const { sign, deps } = await makeSigner()
    const token = await sign({ ...baseClaims, nonce: 'some-other-nonce' })
    await expect(verifyMicrosoftIdToken(token, { clientId: CLIENT_ID, nonce }, deps)).rejects.toMatchObject({
      kind: 'invalid-token',
    })
  })

  it('rejects a token minted for a different audience', async () => {
    const { sign, deps } = await makeSigner()
    const token = await sign(baseClaims, { audience: 'some-other-app' })
    await expect(verifyMicrosoftIdToken(token, { clientId: CLIENT_ID, nonce }, deps)).rejects.toMatchObject({
      kind: 'invalid-token',
    })
  })

  it("rejects a token whose issuer is not that tenant's issuer", async () => {
    const { sign, deps } = await makeSigner()
    // Correct tid in the body, but issued by a different tenant's authority —
    // the multi-tenant trap this function exists to avoid.
    const token = await sign(baseClaims, {
      issuer: `${MICROSOFT_AUTHORITY}/00000000-0000-0000-0000-000000000000/v2.0`,
    })
    await expect(verifyMicrosoftIdToken(token, { clientId: CLIENT_ID, nonce }, deps)).rejects.toMatchObject({
      kind: 'invalid-token',
    })
  })

  it('rejects a token signed by a key that is not the tenant key', async () => {
    const { sign } = await makeSigner()
    const other = await makeSigner()
    const token = await sign(baseClaims)
    await expect(verifyMicrosoftIdToken(token, { clientId: CLIENT_ID, nonce }, other.deps)).rejects.toMatchObject({
      kind: 'invalid-token',
    })
  })

  it('rejects personal Microsoft accounts (consumer tenant) by default', async () => {
    const { sign, deps } = await makeSigner()
    // Signed correctly and by the right key — the rejection must come from the
    // tenant check, not from a signature failure, so this proves the policy.
    const token = await sign(
      { ...baseClaims, tid: MSA_CONSUMER_TENANT_ID },
      { issuer: `${MICROSOFT_AUTHORITY}/${MSA_CONSUMER_TENANT_ID}/v2.0` },
    )
    await expect(verifyMicrosoftIdToken(token, { clientId: CLIENT_ID, nonce }, deps)).rejects.toMatchObject({
      kind: 'access-denied',
    })
    // …and admits it when an operator explicitly opts in.
    const claims = await verifyMicrosoftIdToken(
      token,
      { clientId: CLIENT_ID, nonce, rejectConsumerTenant: false },
      deps,
    )
    expect(claims.tid).toBe(MSA_CONSUMER_TENANT_ID)
  })

  it('enforces an allowedTenants list when one is configured', async () => {
    const { sign, deps } = await makeSigner()
    const token = await sign(baseClaims)
    await expect(
      verifyMicrosoftIdToken(
        token,
        { clientId: CLIENT_ID, nonce, allowedTenants: ['99999999-9999-9999-9999-999999999999'] },
        deps,
      ),
    ).rejects.toMatchObject({ kind: 'access-denied' })

    // …and admits the tenant when it IS on the list.
    const ok = await verifyMicrosoftIdToken(token, { clientId: CLIENT_ID, nonce, allowedTenants: [ZEBRA_TID] }, deps)
    expect(ok.tid).toBe(ZEBRA_TID)
  })

  it('rejects a token with no tid at all', async () => {
    const { sign, deps } = await makeSigner()
    const token = await sign({ oid: ZEBRA_OID, nonce })
    await expect(verifyMicrosoftIdToken(token, { clientId: CLIENT_ID, nonce }, deps)).rejects.toMatchObject({
      kind: 'invalid-token',
    })
  })

  it('rejects a token with no oid — there would be no stable subject', async () => {
    const { sign, deps } = await makeSigner()
    const token = await sign({ tid: ZEBRA_TID, nonce, email: 'a@zebra.com' })
    await expect(verifyMicrosoftIdToken(token, { clientId: CLIENT_ID, nonce }, deps)).rejects.toMatchObject({
      kind: 'invalid-token',
    })
  })

  it('rejects a malformed token without throwing a raw jose error', async () => {
    const { deps } = await makeSigner()
    await expect(verifyMicrosoftIdToken('not-a-jwt', { clientId: CLIENT_ID, nonce }, deps)).rejects.toBeInstanceOf(
      FederationError,
    )
  })
})

// ── 4. Principal mapping ──────────────────────────────────────────────────

describe('microsoftPrincipal', () => {
  const claims = {
    iss: `${MICROSOFT_AUTHORITY}/${ZEBRA_TID}/v2.0`,
    aud: CLIENT_ID,
    sub: 'pairwise-sub',
    oid: ZEBRA_OID,
    tid: ZEBRA_TID,
    email: 'Alice@Zebra.com',
    name: 'Alice Anders',
    exp: 0,
    iat: 0,
  } satisfies MicrosoftIdTokenClaims

  it('keys the principal on tid + oid, not on the pairwise sub', () => {
    const principal = microsoftPrincipal(claims)
    expect(principal.identityId).toBe(`human:ms:${ZEBRA_TID}:${ZEBRA_OID}`)
    expect(principal.identityId).not.toContain('pairwise-sub')
  })

  it('lowercases the email and derives the domain a gate keys on', () => {
    const principal = microsoftPrincipal(claims)
    expect(principal.email).toBe('alice@zebra.com')
    expect(principal.provenance.emailDomain).toBe('zebra.com')
  })

  it('records federated-idp assurance and the upstream issuer as provenance', () => {
    const { provenance } = microsoftPrincipal(claims)
    expect(provenance.provider).toBe('microsoft')
    expect(provenance.assurance).toBe('federated-idp')
    expect(provenance.issuer).toBe(`${MICROSOFT_AUTHORITY}/${ZEBRA_TID}/v2.0`)
    expect(provenance.tenantId).toBe(ZEBRA_TID)
    expect(provenance.subject).toBe(ZEBRA_OID)
  })

  it('falls back to preferred_username when the email claim is absent', () => {
    const principal = microsoftPrincipal({ ...claims, email: undefined, preferred_username: 'bob@zebra.com' })
    expect(principal.email).toBe('bob@zebra.com')
  })

  it('falls back to upn when neither email nor preferred_username is usable', () => {
    const principal = microsoftPrincipal({
      ...claims,
      email: undefined,
      preferred_username: 'not-an-email',
      upn: 'carol@zebra.com',
    })
    expect(principal.email).toBe('carol@zebra.com')
  })

  it('refuses to guess when no claim carries an email address', () => {
    expect(() => microsoftPrincipal({ ...claims, email: undefined, name: 'Nameless' })).toThrow(FederationError)
  })

  it('falls back to the email local-part when no display name is released', () => {
    const principal = microsoftPrincipal({ ...claims, name: undefined })
    expect(principal.name).toBe('alice')
  })
})

// ── 5. Error classification ───────────────────────────────────────────────

describe('classifyMicrosoftError', () => {
  it('maps consent_required to consent-required', () => {
    expect(classifyMicrosoftError('consent_required', '').kind).toBe('consent-required')
  })

  it('maps AADSTS90094 (admin consent required) to consent-required', () => {
    const err = classifyMicrosoftError('invalid_grant', 'AADSTS90094: The grant requires admin permission.')
    expect(err.kind).toBe('consent-required')
    expect(err.upstreamCode).toBe('AADSTS90094')
  })

  it('maps AADSTS65004 (user declined consent) to consent-required', () => {
    expect(classifyMicrosoftError('access_denied', 'AADSTS65004: User declined to consent').kind).toBe(
      'consent-required',
    )
  })

  it('maps a bare access_denied (user cancelled) to access-denied, not consent-required', () => {
    expect(classifyMicrosoftError('access_denied', 'the user cancelled').kind).toBe('access-denied')
  })

  it('falls back to upstream-error for anything unrecognised', () => {
    expect(classifyMicrosoftError('server_error', 'something broke').kind).toBe('upstream-error')
  })

  it('never returns undefined for an empty error pair', () => {
    expect(classifyMicrosoftError(undefined, undefined)).toBeInstanceOf(FederationError)
  })
})
