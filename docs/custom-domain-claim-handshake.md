# Custom-domain claim handshake

How a human's claimed, owned page gets projected onto a **custom domain** by
`builder.domains` — and where `env.AUTH.verifyToken(token)` sits in that flow.

This is the permanent + custom-domain rung of `page.ax`: a page that a human has
**claimed** (proven ownership of) at id.org.ai can be served from that human's own
domain, with every projected request re-verified against id.org.ai's live signing
keys before it is served.

## The seam

id.org.ai is the canonical auth origin (`https://id.org.ai`). It **issues**
RS256-signed JWTs (login/callback flow, OAuth token endpoint) and **verifies**
them. `verifyToken` is the stable primitive that turns one of those tokens into a
verified identity:

```
verifyToken(token) -> { valid: true, identity } | { valid: false, error }
```

- Core primitive: [`src/sdk/auth/verify-token.ts`](../src/sdk/auth/verify-token.ts)
  — a thin wrapper over the shipped JWT verifier
  [`src/sdk/oauth/jwt-verify.ts`](../src/sdk/oauth/jwt-verify.ts) (`verifyJWT`).
  It does **not** re-implement any check: signature (via the live JWKS),
  `exp`/`nbf`/`iat`, `iss === https://id.org.ai`, and `aud` (when an expected
  audience is supplied) are all enforced by `verifyJWT`.
- Exposed **two** ways, both thin wrappers over that one core:
  - **RPC** — `AuthIdentity` `WorkerEntrypoint` in
    [`worker/index.ts`](../worker/index.ts): `env.AUTH.verifyToken(token)`.
  - **HTTP** — `POST /auth/verify` in
    [`worker/routes/auth-verify.ts`](../worker/routes/auth-verify.ts).

Both load the live JWKS from the signing-key manager (no self-fetch to the public
JWKS endpoint) and pin the canonical issuer.

## Flow

### 1. Human claim (WorkOS / GitHub-OIDC login → owned page)

1. Human logs in at id.org.ai via WorkOS AuthKit (SSO / social, incl. GitHub
   OAuth): `GET /login` → WorkOS → `GET /api/callback`.
2. id.org.ai mints an **id.org.ai-issued JWT** (`iss: https://id.org.ai`, RS256,
   `sub` = identity id) and sets it as the `auth` cookie. Signing keys live in the
   `oauth` IdentityDO; the public half is served at
   `GET /.well-known/jwks.json`.
3. The human **claims** a page (proves ownership). The claim is recorded against
   their `sub`. This claimed, owned page is the thing that may now be projected
   onto a custom domain.

### 2. builder.domains binding

`builder.domains` sits in the same Cloudflare account. It **service-binds** to the
id.org.ai worker (Wrangler `name: "oauth"`) as `AUTH`, targeting the
`AuthIdentity` entrypoint:

```jsonc
// builder.domains wrangler.jsonc — DOCUMENTED here, provisioned on that side.
{
  "services": [
    { "binding": "AUTH", "service": "oauth", "entrypoint": "AuthIdentity" }
  ]
}
```

This gives builder.domains a zero-HTTP-overhead, inherently-trusted RPC call:
`env.AUTH.verifyToken(token)`.

Callers that **cannot** service-bind (cross-origin / off-account) use the HTTP
counterpart instead:

```
POST https://id.org.ai/auth/verify
Content-Type: application/json

{ "token": "<id.org.ai JWT>" }
```

→ `200 { "valid": true, "identity": { "sub": "...", "scope": "...", "tenant": "...", ... } }`
→ `401 { "valid": false, "error": "..." }`  (expired / tampered / wrong-issuer / malformed)

### 3. verifyToken on the projected request → serve

When a request arrives on the human's custom domain, `builder.domains`:

1. Extracts the id.org.ai token (auth cookie or `Authorization: Bearer`).
2. Calls `const { valid, identity } = await env.AUTH.verifyToken(token)`.
3. If `valid`, checks that `identity.sub` (and, where relevant, `identity.tenant`
   / `identity.scopes`) **owns the claimed page** for this custom domain, then
   serves the projected page.
4. If `!valid`, refuses to project — no page is served for an unverified token.

Because every projected request is re-verified against id.org.ai's **live** keys,
key rotation and token expiry take effect immediately, and a tampered or
wrong-issuer token can never cause someone else's owned page to be served.

## What verifyToken enforces

| Check      | Enforced by                                  |
| ---------- | -------------------------------------------- |
| signature  | `verifyJWT` (Web Crypto, against live JWKS)   |
| exp / iat  | `verifyJWT` (with clock tolerance)            |
| issuer     | `verifyJWT` (`iss === https://id.org.ai`)     |
| audience   | `verifyJWT` (only when an expected `aud` given) |
| subject    | `verify-token.ts` (`sub` required for identity) |

On any failure the primitive returns `{ valid: false, error }` and never throws.

## Real endpoints & references

- Issue (human login): `GET /login` → `GET /api/callback` — [`worker/routes/auth.ts`](../worker/routes/auth.ts)
- Issue (OAuth token endpoint): `POST /oauth/token` — [`src/sdk/oauth/provider.ts`](../src/sdk/oauth/provider.ts)
- Public keys: `GET /.well-known/jwks.json` — [`worker/index.ts`](../worker/index.ts)
- Verify (RPC): `AuthIdentity.verifyToken` — [`worker/index.ts`](../worker/index.ts)
- Verify (HTTP): `POST /auth/verify` — [`worker/routes/auth-verify.ts`](../worker/routes/auth-verify.ts)
- Core primitive: [`src/sdk/auth/verify-token.ts`](../src/sdk/auth/verify-token.ts)
- Underlying verifier: [`src/sdk/oauth/jwt-verify.ts`](../src/sdk/oauth/jwt-verify.ts)
- Signing path (used to mint hermetic test tokens): [`src/sdk/jwt/signing.ts`](../src/sdk/jwt/signing.ts)
- Acceptance tests: [`test/auth-verify-token.test.ts`](../test/auth-verify-token.test.ts)
