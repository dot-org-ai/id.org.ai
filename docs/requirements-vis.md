# The vis family's requirements on this property — our answer, requirement by requirement

**What this is.** `dot-do/vis` maintains `docs/requirements/id.org.ai.md`: **25 numbered
requirements**, written from the consumer's side, stating what Visibility Cloud, Inc. needs in order
to build on this property. That document deliberately asserts nothing about our offer — the entity
boundary is real, and our offer is ours to write. This file is the other half: **which requirements
we accept, which we accept as future work, which we refuse today, and which need a ruling we do not
own.** A refused requirement is a design input for them, not a failure for us.

**Companion to [`../PRODUCT.md`](../PRODUCT.md)**, which is the offer itself. Where the two touch,
PRODUCT.md governs — this file is a crosswalk, not a second offer.

**Verified 2026-08-05** by live request against `https://id.org.ai` and by reading this repository.
Verdicts:

| verdict | meaning |
|---|---|
| **ACCEPTED — live** | in the offer and answering at the URL today |
| **ACCEPTED — future** | in the offer, stated in future tense, not yet answering |
| **PARTIAL** | some of it is live and the rest is named honestly |
| **REFUSED TODAY** | we are not committing to it now, and here is what would change that |
| **NEEDS A RULING** | the decision is not ours alone |

---

## 1 · Identity — the grains

| REQ | Verdict | Answer |
|---|---|---|
| **REQ-1** — resolve the who-grains; delegate foreign schemes with provenance | **ACCEPTED — future** | The read face is scoped (`org.ai ADR-0013` ratified, `docs/adr/0001` proposed) and is the first thing we build. `GET /humans/{id}` returns **404** today. |
| **REQ-2** — numeric-first segment is GS1 Digital Link, alphabetic is an estate grain, non-colliding | **ACCEPTED — future** | This is the routing partition the resolver is specified against. We commit to it as an invariant, not a convention: barcoding.dev's decoder routes on it. |
| **REQ-3** — retire `/gln/`; company is `/417/`, physical location `/414/` | **ACCEPTED** | Nothing is built, so nothing is broken. `/gln/` is struck from the grain list; a second spelling of a GS1 key on one host is a defect we would rather not ship than fix. |
| **REQ-4** — resolution is free and keyless, **permanently** | **ACCEPTED — live as a commitment** | Stated in the Offer as a property of the offer, not as a launch state. Every resolver in the world is free at the point of use and monetised one layer over; we monetise one layer over. |

## 2 · Authority

| REQ | Verdict | Answer |
|---|---|---|
| **REQ-5** — `grant` · `revoke` · `introspect`, and **`revoke` ships before `deputize`** | **PARTIAL, with the sequencing accepted** | Live today for the credentials that exist: `POST /oauth/revoke` (RFC 7009), `POST /oauth/introspect` (RFC 7662), `POST /agent/revoke`, `DELETE /api/keys/{id}`. Future: `grant` as a first-class authority object (Mandate / Representation / GrantEdge, `org.ai ADR-0012`, zero implementations today). **We accept the ordering constraint: no deputization ceremony ships before revocation covers what it confers.** Shipping an irrevocable grant is not a milestone. |
| **REQ-6** — `introspect` returns the full chain to its human root | **ACCEPTED — future** | Token introspection is live; chain-to-root introspection lands with the authority objects. The reasoning is accepted verbatim: an agent that cannot introspect discovers its authority by probing, and writes denial events into someone else's evidence ledger. |
| **REQ-7** — `revoke` is **free**, reachable **without a seat**, record-class, **non-retroactive and said so** | **ACCEPTED — live** | In the Offer under "You never pay to stop something." No meter attaches to revocation at any tier, and the warrantor needs no paid seat. The non-retroactivity limit is published in PRODUCT.md and belongs on the button that performs it. |
| **REQ-8** — one authority store | **ACCEPTED** | In Boundaries. A consuming door's `share` compiles down to a grant here; two stores would make "revocation ends access" false. |
| **REQ-9** — `grant` accepts a subject that has never resolved (pending scope + claim URL) | **ACCEPTED — future** | The mechanism already exists in a different ceremony: `POST /api/provision` mints a `clm_*` claim token today, and claim-by-commit binds it to a GitHub identity afterwards. A pending, revocable-before-claim Scope is the same shape pointed at authority instead of ownership. |

## 3 · Custody

| REQ | Verdict | Answer |
|---|---|---|
| **REQ-10** — `connect` / `disconnect` for OAuth **and AS2 certificates + SFTP keys** | **PARTIAL — and one half is REFUSED TODAY** | OAuth brokering and tenant-isolated secret custody are live on WorkOS Vault and Pipes. **AS2 certificates and SFTP credentials are not handled, and the legacy-rail custody surface is unscoped** — no AS2, SFTP or certificate code exists in this repository. ⚠ **`transactions.dev/PRODUCT.md` claims this capability in present tense.** That claim is false at the URL and should be corrected on their side; we would rather be quoted honestly than sold. |
| **REQ-11** — a mandate, never raw credentials; every use witnessed; revocation ends access | **ACCEPTED — future**, with one correction | Accepted as the model. The correction is REQ-7's: revocation ends *future* use. It does not unmake an act already performed or a copy already taken, and neither of us should say "instantly" without that clause. |

## 4 · Subject privacy

| REQ | Verdict | Answer |
|---|---|---|
| **REQ-12** — person-grain `who` downstream is an opaque pseudonym; the map lives on our record | **ACCEPTED** | In Boundaries. The map lives on the Human or Agent record here and nowhere else, which is what makes this property the estate's single point of erasure. |
| **REQ-13** — `forget(subject)`, cascading, failing closed | **ACCEPTED — future** | Named in PRODUCT.md's forward set. Forgetting a warrantor revokes its agents first and fails closed if it cannot; a partial erasure that reports success is worse than a refusal. |
| **REQ-14** — pseudonyms are random, never derived | **ACCEPTED** | In Boundaries. `hash(email)` is recomputable and makes deletion cosmetic. |
| **REQ-15** — a worker-held / games-namespace subject is **non-resolvable at any tier** | **ACCEPTED** | In Boundaries, stated generically so it holds for any such subject rather than naming one consumer's arrangement: *some subjects are registered non-resolvable by construction; no tier, key or contract dereferences one.* It is refused at the routing layer, in code, with a test — and the test lands with the resolver, before the first resolvable address does. |
| **REQ-16** — `legal hold` must not silently outrank `forget` | **NEEDS A RULING** | Agreed on the framing: a hold that silently outranks erasure disables erasure at the moment it exists for. The interaction is legal-adjacent and is not an engineering call. What we commit to now is that **whatever the ruling is, it is disclosed on the surface that performs erasure** — not discovered by a `BLOCKED_BY_LEGAL_HOLD` at the counter. |

## 5 · Attestation and the ceremonies

| REQ | Verdict | Answer |
|---|---|---|
| **REQ-17** — `attest` emits **through** epcis.dev's `capture` | **ACCEPTED — future** | In Boundaries: one public write door, and we do not open a second. The audit log is the event source; the emitter is the work. |
| **REQ-18** — `deputize` (B2H2A), `engage` (B2A2H), **and a ruling on A2H2A** | **ACCEPTED — future**, and the A2H2A question is answered | Both ceremonies are scoped at draft level (`docs/PRODUCT-approval-flows.draft.md`). **A2H2A — an agent requesting, a human approving, an agent receiving — is supported by construction and is not a fourth ceremony.** A Handoff types the *act*, not the requester's species: the requester and the recipient are separate principals under one human root, and the human signs one act either way. If it needed its own ceremony, the model would be wrong. |
| **REQ-19** — multi-channel ceremony delivery: browser, terminal QR, link, **and push** | **ACCEPTED — future** | Push is accepted as required, not optional: it is the only channel that reaches someone who is not at a desk. |
| **REQ-20** — pre-approved standing envelopes beat per-act approval | **ACCEPTED — future** | It is the "stop asking" half of the model and it is already the draft's design: a standing grant is minted **only** by generalising an act the principal just approved, one notch, from a menu — never from a blank form. Per-act approval is a throughput ceiling and a signature nobody reads. |

## 6 · Serving and the resolver product

| REQ | Verdict | Answer |
|---|---|---|
| **REQ-21** — resolver-as-a-service on a customer's domain (`id.{customer}.com`) | **ACCEPTED — future**, and it is an Enterprise line item | It is in the published Enterprise feature table. It is also the mechanism that removes free-tier printed-host lock-in, which is why it belongs at the top of the offer rather than in the middle. |
| **REQ-22** — publish `/.well-known/gs1resolver`; run GS1's resolver test suite and **publish the result** | **ACCEPTED — future** | `GET /.well-known/gs1resolver` returns **404** today, verified 2026-08-05. We claim no conformance until the suite passes and the result is published; a conformance claim without a published run is an adjective. |
| **REQ-23** — state the durability posture for a printed hostname | **PARTIAL — stated as an open commitment, not a number** | PRODUCT.md says plainly that no durability commitment is published today and that it publishes **with** the resolver. `.ai` is a ccTLD and the sovereign-delegation question is not ours to answer alone; what is ours is not to print a promise on someone else's physical goods before we can keep it. The Enterprise answer — the customer's own hostname — is the structural mitigation and it is in the offer. |

## 7 · Shared-surface conformance

| REQ | Verdict | Answer |
|---|---|---|
| **REQ-24** — three conneg faces · RFC 9457 errors · opaque forward cursors · `{door}.{verb}` MCP tool ids · a published digest-pinned test suite | **PARTIAL** | The pinned test suite exists and is the scoreboard: `specs/axp-acceptance.spec.json`, 39 requirements, digest `eaae6c2b…`. It does not pass yet, and that is the point of pinning it. **Errors today are OAuth-shaped (`error` / `error_description`), not RFC 9457** — `Accept: text/markdown` serves `text/html`. Both are accepted as targets and neither is claimed as met. |
| **REQ-25** — agent self-service: keys and the free tier with **no human in the loop**, no "contact us" | **ACCEPTED — live** | Verified 2026-08-05: `POST /oauth/register` → **201** with a real `client_id` to a credential-free request; `POST /api/provision` → **201** with a tenant and its published limits. There is no "contact us" path at any tier, including Enterprise. *(Note for their side: the correct path is `/oauth/register`; `/oauth2/register` returns **405**.)* |

---

## What they asked us **not** to do, and we agree

- **No wallet brand in front of their users.** Downstream of a white-labelled instance this property
  is login-only and invisible. A brand a worker carries on their phone is not blameless.
- **No enrichment.** We consume barcoding.dev's data to resolve; we build none of it.
- **No second write door.** See REQ-17.

## What is open on our side, so they can plan around it

1. **The free/paid boundary** — *free to emit, paid to be believed* — is adopted in PRODUCT.md and
   amends the reading in `vis/CONTEXT.md:1200-1204`, which draws the line twice in opposite
   directions in one sentence. It is cheap to reverse and reversing it is a copy edit.
2. **The identity-class enum.** Shipped: `'human' | 'agent' | 'organization' | 'service'`. Canon:
   Human, Agent, Code. This is the least reversible item on our board, because every spine event's
   `who` grain depends on it and changing it after the spine ships is a migration across the event
   lake. **It should be settled before the first vis event carries a `who`.**
3. **The credential-verification runtime's home** — a door on this property, or its own property with
   its own budget line. It does not change anything they consume; it may change which brand invoices
   for a verdict.
