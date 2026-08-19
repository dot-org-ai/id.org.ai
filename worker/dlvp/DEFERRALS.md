# DLVP v1 — DEFERRALS (honest-grade)

Phase-5 ships the DLVP symmetric consent handshake v1: mutual SD-JWT-VC + OIDC4VP
co-presentation, one resolution nonce binding two presentations to one EPCIS event,
the dual-verifier counter-verification tier, and the ISO 27560 consent receipt as an
addressable/revocable VC. Everything below is deliberately deferred, each with a
`model-gap` bd ticket. No gap is papered over: the production issuer-trust map is
empty (settle fail-closes), all keys are test-generated, and provisional bizSteps are
openly marked non-ratified.

| Deferred | Why v1 stops here | Ticket |
|---|---|---|
| Real issuer **trust list** (GS1-rooted did:web / ID-JAG registry) | v1 injects an iss→JWK map; the production map is EMPTY so `/dlvp/settle` fail-closes on every presentation | `id.org.ai-e9a` |
| Full **OIDC4VP wallet-issuance** flow (auth request/response, presentation_definition / DCQL, OpenID4VCI) | v1 VERIFIES presentations only | `id.org.ai-06t` |
| Async single-sided `/dlvp/present` with server-held half-session | v1 ships the synchronous atomic `/dlvp/settle`; needs a binding | `id.org.ai-2s1` |
| **Persistent** status-list + durable revocation + receipt GRAI registry write + **cross-isolate replay/nonce-spend + revocation-token store** | v1 status list, spent-nonce set, and revocation-capability map are in-memory/per-isolate; a restart clears them | `id.org.ai-56v` |
| ZK set-membership / BBS+ unlinkable multi-show / PSI-OPRF blind exchange / mDL-mdoc | SYNTHESIS §D2 hardening phase | `id.org.ai-ac3` |
| Atomic disclosure↔**VALUE** settlement + dual-leg `OFFER.minConfidence` gating — **shipped in Phase-6** (`/dlvp/settle-offer`, the two-phase `SettlementPort`, the C5 gate). The **LIVE value rail** (payments.do / x402·MPP) stays deferred: the production port is fail-closed `noopSettlementPort`, `LiveValueRailSettlement` returns `not-provisioned`, NO keys / NO binding. C5 crypto-presence rung 4 / signed-chain rung 5 still unreachable (settle caps at `V1_MAX_SETTLE_TIER = 3`) | `id.org.ai-67g` |
| Durable cross-isolate settlement **escrow** + 2-phase atomic commit over a real rail + durable nonce lock/release | v1 `SettlementPort` prepare/commit/void + `store.tryLockNonce/releaseNonce` are in-isolate synchronous | `id.org.ai-5gv` |
| **Refunds / disputes / chargebacks** / reversal of a committed settlement | v1 has no post-commit reversal; revoke flips the consent status bit only, it does not claw back value | `id.org.ai-kzj` |
| The **instrument zoo** (provenance-share, option, future, attention-future, bonding-curve, consent-dividend, liability-swap, provenance-collateral, reverse-disclosure auction, mutual-credit/running-tab) | a **FENCE, not a gap**: `value-types.ts` fails closed on every non-present-value type; instruments are a separate counsel-gated post-v1 securities/Howey track | `id.org.ai-8h2` |
| Real **credential-grant** VC minting into a wallet (OpenID4VCI) | v1 records the entitlement in the settlement receipt but mints a MOCK receipt only | `id.org.ai-06t` |
| GS1-ratified **BizStep-clearing** CBV verb | ships as a provisional `gs1.org.ai/cbv/BizStep-clearing` constant; author in standards.org.ai | `id.org.ai-qmp` |
| GS1-ratified **Consenting/Disclosing/Revoking** CBV bizSteps | v1 uses provisional `gs1.org.ai/cbv/BizStep-*` constants; author in standards.org.ai | `id.org.ai-qmp` |
| **Brand-leg counter-verification** — v1 counter-checks only the CONSUMER's ownership VC against the registry; the brand's genuineness/provenance leg is trust-map-only | symmetric registry counter-check of the brand leg | `id.org.ai-dug` |
| **Full-receipt read policy** — `GET /dlvp/receipt/:grai` returns the full receipt (pseudonym + disclosed predicate labels); status is meant to be public, full content should be party-gated | gate full read; keep a public status-only view | `id.org.ai-rvu` |
| **Session party-binding** — the co-presentation request `aud` is a placeholder; a session is not yet bound to specific holder keys | bind the session to the two holder keys at `/dlvp/session` | `id.org.ai-nnj` |
