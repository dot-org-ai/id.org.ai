# ADR 0002 — The authority verbs: `grant · introspect · revoke · refuse`

**Status:** PROPOSED — implemented on `feat/authority-verbs`, ratification is an estate act.
**Deciders:** Nathan Clevenger
**Date:** 2026-08-05
**Implements:** `dot-do/vis` `docs/requirements/id.org.ai.md` **REQ-5 … REQ-9**, and the `refuse`
requirement filed at §3.3 of `docs/specs/surfaces/id.org.ai-approvals.md` (vis issue #358).
**Code:** `src/server/services/authority/` · `worker/routes/authority.ts` ·
`src/server/do/Identity.ts` (RPC) · 130 tests in `test/authority-*.test.ts`.

## Context

Canon claims revocation is instant **four separate times** and shipped **zero verbs** that perform
it. `deputize` (B2H2A) and `engage` (B2A2H) are ratified ceremonies with no implementation, and
`grep -rn deputize src/ worker/` returned 0 matches when the consumer measured it on 2026-08-04.

That ordering is not a backlog detail. **Shipping `deputize` before `revoke` ships an irrevocable
authority grant**, which is a security incident rather than a release. And `introspect` is not
optional beside it: *you cannot revoke what you cannot list*, and a deputized agent that cannot
introspect discovers its authority **by probing**, writing denial events into a customer's evidence
ledger.

Separately, the deny path lands on nothing. `grant` settles an approval; a refusal has no verb, and
on an append-only ledger a decline that leaves no trace is indistinguishable from a request never
seen. An agent that cannot tell *no answer yet* from *a human read this and said no* retries a
refusal until the SLA kills it.

What already existed and is reused rather than reinvented: `src/sdk/auth/scope.ts` — a structured
`ScopeGrant {verb, resource, ceiling?}` with `narrows(child, parent)`, honest in its own docs that
`ceiling` is per-call and not a cumulative wallet.

## Decision

### D1 — Four verbs, in one service, over the tenant's Durable Object

`AuthorityService` (`src/server/services/authority/`) implements `grant`, `introspect`, `revoke`,
`refuse`, plus `claim` (REQ-9's second half), `authorize` (the decision call), `listGrants` and
`settlement`. Records live in the **tenant's** `IdentityDO`, never an agent's — two authority stores
would make *"revocation kills access instantly"* false.

### D2 — A grant is never authored from parameters

Every grant carries **exactly one** origin: a concrete ask a HUMAN settled (`fromAsk`), or an
attenuation of a grant that already exists (`parentGrantId`). Neither, or both, is
`authority-authoring-refused`. On the ask path, `narrows(minted, askedScope)` is checked at mint
time, so an envelope can never be wider than something a human read. On the attenuation path,
`narrows(child, parent)` plus a bound on expiry plus an inherited warrantor.

This is *"no surface in this family is permitted to be an authority-authoring UI"* enforced in the
service rather than in a review of the UI. A screen cannot violate it, because the door refuses.

**A standing envelope (REQ-20) may only be minted from an ask**, never by attenuation, and it must
name the cascade rung it binds to or nothing can read it.

### D3 — `revoke` is free, seatless, non-retroactive, and it cascades

Three authorised callers, no seat on any path: the warrantor, the holder, and anyone presenting the
grant's own revoke secret — a credential good for exactly one act on exactly one grant, which no
other handler consults. The mint receipt returns the secret **once**; the address it pairs with is
tenant-addressable (`/authority/revoke/{tenantId}/{grantId}`) because a caller holding only a secret
has no session from which to resolve a tenant.

The secret is **not** composed into the address. A bearer secret in a URL leaks through referrers
and proxy logs; the caller receives it separately and decides where to put it.

**The cascade fails closed.** Descendants are collected before anything is written; an indexed but
unreadable child refuses the whole revocation with `revocation-incomplete` and writes nothing. A
parent reported revoked while a descendant of it still authorises calls is worse than a refusal the
caller can retry.

**The limit is stated in copy or the claim is false.** Every receipt and every introspection carries
`NON_RETROACTIVE_DISCLOSURE` verbatim:

> Revoking stops future use. It cannot retract what has already been read. Revoking is free and
> needs no seat.

### D4 — `introspect` returns the chain with EXPLICIT GAPS

An unresolvable hop is returned **as an unresolved hop**, with a typed `gap` — `grant-missing`,
`subject-unclaimed`, `cycle-detected`, `depth-exceeded`, `tenant-mismatch`. The chain is never
silently shortened, and `chainComplete: false` / `rootsAtHuman: false` are the honest report.

`introspect` returns **Ok** on a broken chain. Erroring instead would destroy the gap information
REQ-6 exists to deliver, and would send the agent back to probing.

### D5 — `refuse` is a record, and four settlement states are four facts

`settlement(askId)` returns `unasked · pending · granted · refused`. A refusal blocks a later
`grant` on the same ask with `ask-already-settled`, so it is load-bearing rather than decorative.
The cause is a **fixed enum**, never free text — the same discipline as `worklists.dev`'s `block`,
and for the same reason: a free-text field on a human decision is a per-person note on an
append-only ledger.

Only a human settles. An agent presented as `refusedBy` is `not-the-warrantor`, because a refusal
recorded against an agent claims a human read something no human read.

### D6 — Our ledger enforces RFC 8693's `act` claim, which the RFC leaves informational

Delegation travels as an OBO token with a nested `act` claim (RFC 8693 §4.1). The specification
defines the syntax and obliges no verifier to check that the delegation it describes ever happened —
so a token can assert a chain no record supports while its signature, issuer, audience and expiry
are all valid.

`verifyActChain` holds a presented envelope against the ledger elementwise and refuses an extra hop,
a missing hop, a reordering, a substituted principal, a fabricated root, a cycle and an over-deep
nest. Eleven poison fixtures ship as `ACT_CHAIN_POISON` so consumers test the same forgeries rather
than each inventing a happy path. The RFC's own §4.1 worked example is pinned as a test, because the
direction of the nesting is the one thing here that is easy to get backwards and impossible to
notice.

### D7 — Every mint, attenuation, claim, use and revocation is an Action — through ONE write door

Actions are handed to an injected `ActionSink`; production is `CaptureActionSink`, which POSTs to
the public capture door. **It never fabricates a hash and never throws into a verb path.** When the
door is unset, unreachable or answers a 2xx with no hash, the receipt's artifact is `unconfirmed` —
a presence state the Frame contract already carries and renders distinguishably in every face.

Failing the verb instead would make `revoke` unavailable exactly when a customer most needs it, and
REQ-7 says you never pay, wait or log in to stop an agent.

**A DENIAL WRITES NOTHING.** `authorize` records an Action when it allows and nothing when it
denies. A service that wrote a denial event per probe would turn REQ-6's complaint into the
customer's evidence ledger.

### D8 — `/authority/*`, not `/oauth/revoke` and `/oauth/introspect`

This worker already serves RFC 7009 token revocation and RFC 7662 token introspection. Those act on
**tokens**; these verbs act on **authority grants**. Two different acts sharing two names cannot be
resolved by any dispatcher, so the estate verbs mount in their own namespace and neither OAuth route
is touched. **The collision itself is still an open ruling** (vis approvals spec §9 U-4); this
layout means the ruling can go either way without a migration.

Auth is applied by **naming the paths** in `worker/index.ts` rather than by a wildcard, so the two
exemptions are visible at the mount point: `/authority/revoke/*` is seatless (REQ-7) and
`/authority/claim` is keyless (REQ-9, the subject has never resolved).

### D9 — RFC 9457, with six slugs the cross-door registry already pinned

`application/problem+json`, `type` dereferenceable at `https://id.org.ai/errors/{slug}`, carrying
`door`, `verb`, `retryable`, `costed`. `AUTHORITY_SLUGS` marks each row `pinned` (already in
`dot-do/vis` `packages/shared-surface/src/errors.ts`) or `proposed`. A test asserts the pinned six
are spelled exactly as the registry spells them and that no second spelling of one of them exists —
one registry, one spelling, and a door may add an error but never re-spell a shared one.

**The fifteen `proposed` slugs are a filing against that registry, not a private catalogue.** They
must be added there before `id.org.ai` claims registry conformance.

## Consequences

- `deputize` and `engage` are now safe to implement: what they mint is revocable, listable and
  refusable.
- The vis approvals Views (`id.approvals.ask`, `.queue`, `.settled`, `id.authority.envelope`,
  `id.authority.grants`) and the console's V-A4/V-A5 have real verbs to read.
- `EPCIS_CAPTURE_URL` is unset in every environment today, so **every artifact is `unconfirmed`.**
  That is the honest state and it must render as `unconfirmed`, not as absent and not as a hash.
- Nothing here is deployed. The routes are mounted and tested; no environment has been configured
  and no claim about a live `https://id.org.ai/authority/*` is made by this ADR.

## What this ADR does not decide

- **The `revoke`/`introspect` name collision** with the OAuth endpoints (U-4). D8 sidesteps it; it
  does not rule it.
- **`withdraw`** — whether a requesting agent may retract a moot ask (U-7).
- **`timeout`** — the state a DO alarm fires an expired ask into. Named as missing, not built.
- **The standing-envelope duration list** (*this shift · 7 days · 30 days*). Cheap to reverse; pick
  and test rather than gate.
- **Metering.** No authority verb is metered here and `costed: false` rides every refusal. `revoke`
  and `refuse` are free by ruling; the rest are unpriced, not priced at zero.
