# Spike: anon-provision -> agent-attest -> durable handoff

- **bd issue:** ax-e6b.17.5 (de-risk spike for ax-e6b.17.1)
- **Date:** 2026-07-22
- **Status:** SPIKE — a standalone runnable prototype + friction analysis. **Not** a production auth change.
- **Prototype:** [`test/spike-provision-attest-handoff.test.ts`](../../test/spike-provision-attest-handoff.test.ts) — drives the **real** worker routes in-process via `SELF` (`cloudflare:test`), so `IDENTITY` DO + `SESSIONS` KV are wired exactly as production wires them. Runs under `npm test` (workers pool). Nothing is mocked away — real `authenticateRequest` + `requireTenant`.
- **Downstream dependency being de-risked:** page.ax durable retention needs a durable, attested agent identity that a cold-anonymous caller can reach without a human in the loop.

## TL;DR

**A cold-anonymous caller can create a durable, attested, active agent record in TWO network hops — `POST /api/provision` then `POST /agent/register` — using only the `ses_` session token from provision. The `ses_` token DOES satisfy `requireTenant`; a provisioned-but-unclaimed principal already IS a level-1 tenant.**

The `clm_` claim token is **not** a request credential (presenting it as a bearer 401s). It is the **durability gate**: the L1 tenant (and the agent inside it) is ephemeral — a 24h session and a freeze-with-30-day-preservation window — until the `clm_` is redeemed via claim-by-commit (GitHub OIDC -> level 2). **Registration is cheap and open; durable retention is what's gated.**

## Actual minimal hop sequence (observed, real routes)

```
COLD ANON (no credentials)
     │
     │  HOP 1 ── POST /api/provision            (NO auth)
     │            └─> 201
     │                identityId  = 5e552e3a-76bf-497c-b3f1-1939e8b7772b   (UUID; DO shard key)
     │                tenantId    = anon_xxxxxxxx                          (display name)
     │                sessionToken= ses_…   ← the request credential        (lifetime 24h)
     │                claimToken  = clm_…   ← the durability gate           (lifetime 30d)
     │                level = 1, limits {maxEntities:1000, ttlHours:24, maxRequestsPerMinute:100}
     │                upgrade {nextLevel:2, action:"claim", url:/claim/clm_…}
     ▼
  HOP 2 ── Ed25519 keypair  (Web Crypto crypto.subtle.generateKey{name:'Ed25519'})
             export 'raw' public key -> 32 bytes -> base64 (44 chars)
             (identical primitive to src/sdk/crypto/keys#generateKeypair)
     │
     │  HOP 3 ── POST /agent/register
     │            Authorization: Bearer ses_…            ← ses_, NOT clm_
     │            { name, mode:"autonomous", public_key:<b64 raw>, capabilities:[…] }
     │            └─> 201
     │                agent_id = agent_5b9748b9164b42cf
     │                host_id  = 5e552e3a-…              ← equals identityId (agent bound to the provisioned tenant)
     │                status   = "active"                ← autonomous => active immediately (attested)
     │                mode     = "autonomous"
     │                agent_capability_grants = [{read,active},{write,active}]
     ▼
  HOP 4 ── GET /agent/status?agent_id=agent_5b97…
             Authorization: Bearer ses_…
             └─> 200  { agent_id, host_id=identityId, status:"active", mode:"autonomous",
                        created_at, activated_at }        ← durable attested identity resolves
```

**Minimal path to an attested, active agent from cold-anon = 2 credentialed HTTP calls (provision, register).** `status` is a read-back, not required to create the agent.

## Token lifetimes (source-of-truth constants)

| Token / record | Prefix | Lifetime | Where enforced |
| --- | --- | --- | --- |
| Session token | `ses_` | **24h** (`86_400_000 ms`) | `IdentityDO.provisionAnonymous` -> `sessionService.create(id, 1, 86_400_000)`; KV `session:<ses_>` TTL `86_400 s` |
| Claim token | `clm_` | **30d** (`2_592_000 s`) | KV `claim:<clm_>` TTL in `worker/routes/claim.ts` |
| Frozen-tenant data preservation | — | **30d** after freeze | `IdentityDO.freezeIdentity` -> `frozenAt + 30d` |
| Agent `sessionTtlMs` (default) | — | 24h | `agents/types.ts DEFAULT_SESSION_TTL_MS` |
| Agent `maxLifetimeMs` (default) | — | 30d | `DEFAULT_MAX_LIFETIME_MS` |
| Agent `absoluteLifetimeMs` (default) | — | 365d | `DEFAULT_ABSOLUTE_LIFETIME_MS` |

The HTTP seam only directly exposes `limits.ttlHours = 24` and `upgrade.action = "claim"`; the exact ms lifetimes are the DO/service constants above.

## Error shapes (observed)

| Call | Status | Body |
| --- | --- | --- |
| `POST /agent/register` — **no** credential | `401` | `{"error":"unauthorized","error_description":"Authentication required to register an agent"}` |
| `POST /agent/register` — `clm_` as bearer | `401` | same as above — `clm_` matches neither the `ses_` nor the API-key extractor, so it reads as "no credential presented" -> anonymous -> `requireTenant` rejects |
| `POST /agent/register` — missing `name` | `400` | `{"error":"invalid_request", …}` (per aap.ts validation) |
| `POST /agent/register` — bad `mode` / no key material | `400` | invalid_request |
| `GET /agent/status` — cross-tenant `agent_id` | `403` | forbidden (tenant isolation) |
| `GET /agent/status` — unknown `agent_id` | `404` | not_found |

## Friction analysis

**Overall friction is LOW: 2 calls, no human, no WorkOS, no GitHub — to a live attested agent.** The friction is not in *reaching* an agent; it's in three non-obvious semantics:

1. **`ses_` is the credential; `clm_` is not.** Provision hands back two tokens. The obvious-looking "claim" token 401s if used as a request bearer. A caller must know to authenticate with `ses_` and treat `clm_` purely as a redemption artifact. **Non-obvious; the single biggest confusion risk.**
2. **Registration success ≠ durability.** `/agent/register` returns `201 status:"active"` for a tenant whose session expires in 24h and whose data freezes thereafter. Nothing at the register seam signals "this agent is ephemeral until you redeem `clm_`." A consumer (page.ax) that wants *durable* retention can get a green 201 and still lose the agent after the freeze/reap window. **Non-obvious; the correctness trap.**
3. **`mode` gates immediate usability.** `autonomous` -> `active` at once; `delegated` -> `pending` (awaits approval). A self-attesting cold-anon agent must register `autonomous` to be usable without an approver. **Non-obvious.**

There is **no 401 wall on the durable path at registration** — the wall (a proof-of-control gate) is deliberately at *durability* (claim-by-commit), not at *creation*.

## Recommendation for ax-e6b.17.1

**Yes — a single anonymous `/agent/register-with-provision` endpoint is warranted, as an ergonomic wrapper, provided it is gated as below. It must not grant anything the existing two-hop path doesn't already grant.**

Rationale: the two-hop path already lets an unauthenticated caller create an attested autonomous agent, so a combined endpoint **opens no new capability** — it removes one round-trip and eliminates the `ses_`-vs-`clm_` confusion (friction #1) and the "success ≠ durable" trap (friction #2, by letting the endpoint document/return the durability posture in one place). page.ax's cold-anon durable-retention flow is exactly the caller that wants this.

**It is security-sound only if all of the following hold:**

1. **Keep `clm_` redemption as the durability gate — do NOT make anonymous registration durable.** An anon-provisioned agent stays **L1 / ephemeral** (24h session, 30-day freeze) until the `clm_` is redeemed via claim-by-commit (verifiable GitHub identity -> L2). This is the anti-abuse economics: spam agents evaporate on freeze/reap; only claimed ones persist. The expensive, durable resource stays behind a proof-of-control gate; the cheap, ephemeral one is open. **Removing this gate as a "shortcut" is the one thing not to do.**
2. **Rate-limit the unauthenticated mint by IP.** The real abuse surface is **provision spam**: each `POST /api/provision` mints a new DO shard, and a combined endpoint would *also* write an agent row + a `agent-by-pubkey:` index entry per call — write-amplified, unauthenticated resource creation. The primary control is per-IP rate-limiting on the unauthenticated endpoint(s). (See "Bug candidate" below — provision currently appears unthrottled.)
3. **Bind the Ed25519 public key at creation and derive the tenant from the freshly-provisioned shard.** The endpoint must NOT accept a caller-supplied `identityId`/`tenantId` (that would be a cross-tenant agent-injection vector) — it derives the tenant from the shard it just minted, and it must attest the supplied `public_key`.
4. **No privilege escalation over the two-hop path.** Same L1 level, same `autonomous -> active` semantics, same capability defaults. A convenience wrapper, not a new trust level.

**Security tradeoff, stated plainly:** letting an anon-provisioned principal register an agent does **not** widen the abuse surface beyond what `/api/provision` already exposes, *because durability is separately gated by `clm_`*. The residual risk is write-amplified provision spam (unbounded DO shards + agent rows + pubkey-index entries) from an unauthenticated endpoint. Mitigate with (a) per-IP rate-limiting on the unauthenticated mint and (b) keeping freeze/reap for unclaimed tenants so ephemeral spam self-collects. Do not weaken the `clm_` durability gate to save a step.

## Bug candidate to RECORD for ax-e6b.17.1 (NOT fixed in this spike)

`POST /api/provision` (`worker/routes/claim.ts`) has **no per-IP rate-limit guard** — `cf-connecting-ip` is read only to *log* an audit event, not to throttle. The `limits.maxRequestsPerMinute: 100` in the response is a *post-provision, per-tenant* limit, not a guard on the unauthenticated mint itself. This is the abuse vector any anon-register work must close first. **Recorded here only — deliberately not patched in this spike (do-not-touch-production-auth-routes constraint).**

## Verification

- Prototype `test/spike-provision-attest-handoff.test.ts` **runs green** and drives real routes (real `authenticateRequest`/`requireTenant`, real DO+KV) — no auth mocked.
- Full existing suite: workers pool `57 files / 1806 tests` green + node config `27 / 520` green **with the spike included**. Note: `test/auth-verify-token.test.ts`'s two "TAMPERED signature" cases are a **pre-existing non-deterministic flake** (observed failing 1/run at baseline *without* this spike, and passing on re-run) — unrelated to this change.
- `tsc --noEmit` clean.
- No production auth route modified; no deploy.
