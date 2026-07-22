# Spike: anon-provision -> agent-attest -> durable handoff

- **bd issue:** ax-e6b.17.5 (de-risk spike for ax-e6b.17.1)
- **Date:** 2026-07-22
- **Status:** SPIKE — a standalone runnable prototype + friction analysis. **Not** a production auth change.
- **Prototype:** [`test/spike-provision-attest-handoff.test.ts`](../../test/spike-provision-attest-handoff.test.ts) — drives the **real** worker routes in-process via `SELF` (`cloudflare:test`), so `IDENTITY` DO + `SESSIONS` KV are wired exactly as production wires them. Runs under `npm test` (workers pool). Nothing is mocked away — real `authenticateRequest` + `requireTenant`.
- **Downstream dependency being de-risked:** page.ax durable retention needs a durable, attested agent identity that a cold-anonymous caller can reach without a human in the loop.

## TL;DR

**A cold-anonymous caller can create a durable, attested, active agent record in TWO network hops — `POST /api/provision` then `POST /agent/register` — using only the `ses_` session token from provision. The `ses_` token DOES satisfy `requireTenant`; a provisioned-but-unclaimed principal already IS a level-1 tenant.**

The `clm_` claim token is **not** a request credential (presenting it as a bearer 401s). It is **not a durability gate either** — verified against the code (see "Durability model" below): the agent record written by `/agent/register` is **permanent DO storage from the moment of registration**, with no TTL and no reaper. `clm_` redemption only raises identity level 1->2 and links a GitHub account — a trust/capability upgrade, not a retention control. **Registration is cheap, open, AND already durable; nothing further gates retention today.**

## Actual minimal hop sequence (observed, real routes)

```
COLD ANON (no credentials)
     │
     │  HOP 1 ── POST /api/provision            (NO auth)
     │            └─> 201
     │                identityId  = 5e552e3a-76bf-497c-b3f1-1939e8b7772b   (UUID; DO shard key)
     │                tenantId    = anon_xxxxxxxx                          (display name)
     │                sessionToken= ses_…   ← the request credential        (lifetime 24h)
     │                claimToken  = clm_…   ← trust upgrade (L1->L2 + GitHub link), NOT a durability gate (lifetime 30d)
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
| Frozen-tenant data preservation | — | **30d** after freeze | `IdentityDO.freezeIdentity` -> `frozenAt + 30d`. **Freeze itself is never automatic** — its only caller is the auth-gated `POST /api/freeze` (reason `'user-initiated'`). No scheduled job, alarm, or expiry path ever triggers it. |
| Agent `sessionTtlMs` (default) | — | 24h | `agents/types.ts DEFAULT_SESSION_TTL_MS` |
| Agent `maxLifetimeMs` (default) | — | 30d | `DEFAULT_MAX_LIFETIME_MS` |
| Agent `absoluteLifetimeMs` (default) | — | 365d | `DEFAULT_ABSOLUTE_LIFETIME_MS` |

The HTTP seam only directly exposes `limits.ttlHours = 24` and `upgrade.action = "claim"`; the exact ms lifetimes are the DO/service constants above.

## Durability model (verified in code — corrects an earlier draft of this doc)

**An agent record is durable from `/agent/register`, full stop. `clm_` redemption does not gate retention — no such gate exists today.** Verified directly against the code:

- **No reaper exists.** The only `scheduled()` handler (`worker/index.ts` ~L845) does signing-key rotation on a 90-day cadence. It does nothing else — no sweep of unclaimed tenants/agents.
- **`freezeIdentity` is never automatic.** Its only caller is the auth-gated `POST /api/freeze` (`worker/routes/claim.ts` ~L235, 401s without a session), which calls `identityService.freeze(id, 'user-initiated')` (`Identity.ts` ~L355). Nothing invokes it on a timer, on expiry, or on session end.
- **No alarms are set.** `grep -rn setAlarm src/ worker/` (excluding `.d.ts`) returns zero matches. `IdentityDO` never arms a Durable Object alarm, so there is no DO-native expiry mechanism either.
- **`registerAgent` writes permanent storage with no TTL.** `agents/service.ts` `register()` (~L142-172) writes three keys with plain `storage.put` and no expiration: `agent:<id>` (the record), `agent-by-pubkey:<key>` (auth index), and `agent-by-tenant:<tenantId>` (an appended array, also unbounded). The `sessionTtlMs` / `maxLifetimeMs` / `absoluteLifetimeMs` fields stored on the agent record are informational — nothing reads or enforces them automatically; the only place `absoluteLifetimeMs` is even checked is inside the *manual* `reactivate()` call path, and even that never deletes storage, only flips `status`.
- **Only the `ses_` session credential and its KV mappings actually expire.** `session:<ses_>` and `claim:<clm_>` are KV entries with `expirationTtl` (24h and 30d respectively, `claim.ts` ~L57-59) — that TTL governs the *credential*, not the underlying DO-stored identity, agent row, or pubkey index, all of which persist indefinitely regardless of whether `clm_` is ever redeemed.
- **`clm_` redemption changes trust, not retention.** `Identity.ts` claim handling (~L258-279) raises `level` 1->2 and calls `linkAccount` for the GitHub identity. It does not touch storage TTL, does not delete anything, and has no interaction with the agent record's lifetime.

**Net effect:** the moment `POST /agent/register` returns `201`, the agent row + its two index entries are permanent DO storage — claimed or not. There is currently no code path that ever removes them.

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
2. **~~Registration success ≠ durability~~ — CORRECTED: registration success = durability, and that's the actual risk.** (An earlier draft of this doc claimed the opposite — that `201` was ephemeral until `clm_` redemption. That was fabricated; see "Durability model" above.) `/agent/register` returns `201 status:"active"` and that record is **permanent DO storage immediately**, with no TTL and no reaper, whether or not `clm_` is ever redeemed. Nothing at the register seam signals this either — a consumer (page.ax) that wants durable retention gets exactly that, unconditionally, which is good for page.ax's ergonomics but means there is currently no lever to make retention conditional on claim/payment. **Non-obvious; the actual trap is the opposite of what was previously written here — silent unconditional durability, not silent ephemerality.**
3. **`mode` gates immediate usability.** `autonomous` -> `active` at once; `delegated` -> `pending` (awaits approval). A self-attesting cold-anon agent must register `autonomous` to be usable without an approver. **Non-obvious.**

There is **no 401 wall on the durable path at registration, and — contrary to an earlier draft of this doc — there is no wall anywhere else either.** `clm_`/claim-by-commit is a proof-of-control gate on *trust level* (L1 -> L2 + GitHub link), not on *durability*. Durability is granted unconditionally at `/agent/register`.

## Recommendation for ax-e6b.17.1

**⚠️ REVISED — an earlier draft of this section relied on a durability gate (`clm_` redemption / freeze-and-reap) that does not exist in the code. The recommendation below is grounded in the actual, verified behavior: registration is durable, unconditionally, today.**

**A single anonymous `/agent/register-with-provision` endpoint is still reasonable ergonomics** — the existing two-hop path already lets an unauthenticated caller create a durable, attested, active agent, so a combined endpoint opens **no new capability**; it just removes a round-trip and fixes the `ses_`-vs-`clm_` confusion (friction #1). But because durability is *not* gated today, **the abuse mitigations below are REQUIRED to ship alongside it, not optional hardening**:

1. **Per-IP rate-limit on the unauthenticated mint — currently missing.** `/api/provision` (and by extension any combined register-with-provision endpoint) has no per-IP throttle. This is a real gap today, independent of any new endpoint — see bug candidate (i) below.
2. **A genuine retention control must exist before "claim = durability" can be treated as the security model — it currently doesn't.** Pick one and build it explicitly, don't assume it:
   - **Option A — add a reaper/TTL for unclaimed agents/tenants.** Arm a DO alarm (or an actual `scheduled()` sweep) that reaps `agent:`/`agent-by-pubkey:`/`agent-by-tenant:` entries and the identity record for tenants that never redeem `clm_` within a bounded window. This is what would make the "ephemeral until claimed" model real — today it is aspirational only.
   - **Option B — explicitly accept that anon-registered agents are permanent**, and instead bound abuse purely by mint rate (hard per-IP limits, possibly CAPTCHA/PoW at `/api/provision`) plus operational cleanup tooling. If this option is chosen, say so explicitly in any downstream design (page.ax) rather than implying a claim-gated retention model that isn't there.
3. **Bind the Ed25519 public key at creation and derive the tenant from the freshly-provisioned shard.** The endpoint must NOT accept a caller-supplied `identityId`/`tenantId` (cross-tenant agent-injection vector) — it derives the tenant from the shard it just minted, and it must attest the supplied `public_key`.
4. **No privilege escalation over the two-hop path.** Same L1 level, same `autonomous -> active` semantics, same capability defaults. A convenience wrapper, not a new trust level.

**Flag clearly for page.ax:** if page.ax's design wants "durable retention gated by claim/payment," **that gating must be built — it does not exist today.** Registration alone is durable right now; `clm_` redemption only changes trust level (L1->L2) and links GitHub, it does not change what gets retained or for how long. Any page.ax design that assumes unclaimed agents "expire" or "get reaped" is assuming a mechanism that is not present in this codebase as of this spike.

**Security tradeoff, stated plainly — corrected:** because there is no reaper and no per-IP rate-limit, **every unauthenticated `POST /api/provision` + `POST /agent/register` call creates permanent storage (a new DO shard + agent row + two index keys) that is never reclaimed.** This is unbounded permanent-storage amplification from an anonymous endpoint — a real, currently-unmitigated abuse surface, not a self-collecting one. A combined register-with-provision endpoint doesn't make this worse in kind (the two-hop path already has the same exposure), but it does make it one call cheaper, which raises the urgency of closing bug candidates (i) and (ii) below before shipping it.

## Bug candidates to RECORD for ax-e6b.17.1 (NOT fixed in this spike)

(i) `POST /api/provision` (`worker/routes/claim.ts`) has **no per-IP rate-limit guard** — `cf-connecting-ip` is read only to *log* an audit event, not to throttle. The `limits.maxRequestsPerMinute: 100` in the response is a *post-provision, per-tenant* limit, not a guard on the unauthenticated mint itself.

(ii) **No reaper/TTL exists for unclaimed agent records**, which — combined with (i) — means unbounded permanent storage (DO shards + `agent:`/`agent-by-pubkey:`/`agent-by-tenant:` entries) can be created from a single anonymous endpoint with no cleanup path. This is the abuse vector any anon-register work must close first.

**Recorded here only — deliberately not patched in this spike (do-not-touch-production-auth-routes constraint).**

## Verification

- Prototype `test/spike-provision-attest-handoff.test.ts` **runs green** and drives real routes (real `authenticateRequest`/`requireTenant`, real DO+KV) — no auth mocked.
- Full existing suite: workers pool `57 files / 1806 tests` green + node config `27 / 520` green **with the spike included**. Note: `test/auth-verify-token.test.ts`'s two "TAMPERED signature" cases are a **pre-existing non-deterministic flake** (observed failing 1/run at baseline *without* this spike, and passing on re-run) — unrelated to this change.
- `tsc --noEmit` clean.
- No production auth route modified; no deploy.
