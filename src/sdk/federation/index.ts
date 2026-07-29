/**
 * Upstream federation — id.org.ai as the broker.
 *
 * Upstream identity (Microsoft Entra today) terminates HERE. Downstream
 * clients consume an id.org.ai identity and never talk to the upstream IdP.
 * Two entry paths, one principal shape:
 *
 *   ./microsoft   — Entra multi-tenant OIDC, authorization code + PKCE,
 *                   scopes `openid profile email` and nothing else.
 *   ./email-code  — mailbox-custody fallback for tenants that block consent.
 *
 * Both produce a `FederatedPrincipal` carrying `FederationProvenance`, which
 * records the assurance actually achieved — the broker clamps capability level
 * to that assurance rather than trusting a stored row.
 */
export * from './types'
export * from './microsoft'
export * from './email-code'
