# id.org.ai — Brand, Identity and Purpose

**Status:** PARTLY RULED. **§2 — the hero — is RULED and in force** ([OWNER], 2026-08-03, recorded
in `vis/CONTEXT.md`). Every other ruling below remains this document's recommendation. Items marked
**[OWNER]** amend a ruling recorded in `vis/CONTEXT.md` or `org.ai/docs/adr/` and are not in force
until the owner ratifies them.
**Date:** 2026-08-03
**Revised:** 2026-08-03, **on an owner correction.** The prior pass amputated the purpose statement
against a set of 404s — see §0, *"The governing law, and the error this revision corrects."* The
research is unchanged and every probe result stands; the conclusion drawn from it was wrong. §1 (the
one sentence), §2's reasoning, §7 (now three categories, not a binary) and §10 (THE BACKLOG) are
rewritten accordingly. §§3–6, the door structure, the persona map and the open questions are
substantially as they were.
**Author:** identity/purpose grill session, called by the owner; the session `vis/CONTEXT.md` has
deferred since 2026-07-31.
**Supersedes as the property's positioning source:** the hero and problem framing in `README.md`.
The hero half is **superseded now** — *Agent. Human. Identity.* is ruled (§2), and the live
"Humans. Agents. Identity." is retired on its nouns, with only its **word order** left open (§8 Q13).
The *"open identity standard"* copy is superseded on ratification of §6 / §8 Q11.
**Binds to:** `org.ai/docs/adr/0013` (RATIFIED), `org.ai/docs/adr/0012`, `org.ai/CONTEXT.md`
(the layer/TLD glossary), `id.org.ai/docs/adr/0001` (PROPOSED).
**Live probes in this document were run 2026-08-03 against `https://id.org.ai`.** Every status code
quoted below was observed, not inferred.

---

## 0. Why this document exists

Four positionings were live in the estate at the same address on 2026-08-03:

| | Where | Hero | Core claim | Scope |
|---|---|---|---|---|
| **A** | `vis/CONTEXT.md` (rulings, 2026-07-31 → 2026-08-02) | "Agent. Human. Thing." | identity → authority → witness; *authority is the business* | vis's who/authority/resolution rail |
| **B** | `id.org.ai/README.md` (live) | "Humans. Agents. Identity." | *the commit IS the identity*; agents can't click | estate-wide |
| **C** | `docs/PRODUCT-approval-flows.draft.md` (draft, squatting `$id: https://id.org.ai/product.md`) | "Nothing goes out in your name until you say so" | outbound act approval | principal / agent / integrator |
| **D** | `org.ai/CONTEXT.md` (constitutional) | — | *"id.org.ai is .do-layer work on an .org.ai name"* | the layer, not the property |

A and B are not wrong; they answer different questions at different scopes. C is a scoping draft
holding the canonical product address. D overrides both A and B on one point neither noticed: **A
files id.org.ai under `.org.ai = Standards` (`CONTEXT.md:831`) and B calls it "an open identity
standard for the agent era" — and the constitution already ruled it managed infrastructure.**

This document ends the ambiguity by ruling one sentence, one hero, one spine, one boundary, one
door structure, and one scope story, and by publishing the gap between them as a backlog.

### The governing law, and the error this revision corrects **[CORRECTED 2026-08-03 by the owner]**

A prior pass of this document read a set of 404s and **removed resolver, wallet, witness-of-every-act
and the who-address grammar from the purpose statement** on the grounds that they were "all 404 or
zero code." That is backwards, and it violates a ratified law. The owner, verbatim:

> *"id.org.ai has existed for months as a live workos custom domain, and we added some agent self
> registration and delegated authorization stuff (and need more) — but everything else has simply
> been brainstormed here in this repo and hasn't been scoped or built yet — and until the start of
> this session the domains weren't even in the same org so that they could be on the workers.do
> enterprise zone with the rest of the .org.ai estate — so no, we are not watering down the message.
> These are simply gaps that you and the subagents haven't scoped or built yet — and if they are
> built, then the gap is that it hasn't been deployed yet!"*

**The two laws, stated so they cannot be confused again:**

1. **The claim-the-vision law** (`vis/CONTEXT.md:1009`) bans hedges and build-state prose — *"the
   writer narrating himself instead of stating the offer."* It has never said *"do not claim what is
   unbuilt."* **The fix for a gap is to build it, never to soften the sentence.**
2. **The honesty rule** (`vis/CONTEXT.md:1454`): *"Present tense only for what is written and tested;
   explicit future tense for everything else."* Note the second half. The instrument for an unbuilt
   capability is **future tense**, not deletion.

**Therefore, the operative distinction — and it governs every section below:**

| | Register | Gate |
|---|---|---|
| **The purpose statement** (§1) — what id.org.ai IS and is FOR | Timeless. It states the offer. | The 100× test. Resolver, wallet, witness and the who-address grammar all belong in it. |
| **Per-surface copy** (home page, README, discovery documents, package description) | Present tense for what answers at the URL; **explicit future tense for the rest** | No present-tense capability claim that 404s. Equally: **no hedge prose, no "coming soon," no build-state narration.** |
| **The delta** | Neither. It is a dated ledger entry. | §10 — THE BACKLOG, ready to become issues on `dot-do/vis`. |

§7 is therefore **the backlog, not an indictment**, and it is classified three ways — **not scoped**,
**scoped but not built**, **built but not deployed** — because those are three different pieces of
work with three different owners.

Still absolute, and untouched by any of the above: **no customers, no adoption counts, no conformance
attestation ever issued, and no present-tense capability claim that a probe falsifies.**

---

## 1. THE ONE SENTENCE

> **id.org.ai is the estate's *who* layer: it resolves any address to what it names, issues and holds
> the keys that humans, agents and code act with, bounds what those keys may do, witnesses every act
> they take, and answers — from the source of record — whether they are still allowed to.**

Five verbs, one job — resolve · issue and hold · bound · witness · answer. Nothing in it is filler,
and nothing in it is a volume, customer or conformance claim:

| Clause | What it carries | Why it is in the purpose statement |
|---|---|---|
| *resolves any address to what it names* | the **resolver** and the **who-address grammar** — `/01/{gtin}`, `/{grain}/{id}`, linksets, conneg | An identity layer a stranger cannot dereference is a user table. `org.ai ADR-0013 R2` (**RATIFIED**) commits this property to the role, and vis's one-resolver ruling depends on it. **This is also where *Thing* lives** — resolved here, never attested here, exactly as `vis/CONTEXT.md:1123` rules. |
| *issues and holds the keys* | **identity issuance** and **custody** — the OAuth 2.1 AS, agent keypairs, and the **wallet**: the estate holding a borrowed secret so the principal never does | Issuance without custody puts the secret back in the principal's hands, which is the failure the authority layer exists to prevent. |
| *that humans, agents and code act with* | the three identity classes, in the model | **Agent and Human are the two act-grains, and they lead the ruled hero** (§2). *Code* stays a documented detail for developers, per canon's own presentation ruling — right in the model, absent from the hero. |
| *bounds what those keys may do* | **authority** — scope ceilings, the L0–L4 ladder, FGA, `Mandate` / `Representation` / `GrantEdge`, spend ceilings, the approval ceremony | *Authority is the business.* This is the clause the estate charges against. |
| *witnesses every act they take* | **witness** — every act lands as an attested event on the one spine | The layer vis depends on and the layer nobody has built. It is named here because it is what the property is for, not because it answers today. |
| *and answers — from the source of record — whether they are still allowed to* | **primary-source credential verification** | The differentiated module, the only real price in the repository, and the only one with no upstream vendor. |

**Does it survive 100× scale?** Yes, and it gets *more* true: the sentence names one job, and every
part of the job is more valuable the more principals exist that no person is watching. A credible
company at 100× our size puts this sentence on its landing page.

### Which clauses answer at the URL today — the per-surface gate, not an edit to the sentence

The sentence above is the **purpose**. What follows governs **copy**: present tense here, explicit
future tense there. Verified by live probe and code inspection, 2026-08-03.

| Clause | Register on a published surface | Evidence |
|---|---|---|
| *issues and holds the keys* | **PRESENT** | `POST /oauth2/register` keyless → **201** with a real `client_id`. `POST /api/provision` keyless → **201**. `/.well-known/oauth-authorization-server` **200**, `/.well-known/jwks.json` **200**, `/.well-known/agent-configuration` **200**. WorkOS AuthKit for humans; Ed25519 `did:agent:ed25519:` for agents. Custody ships as WorkOS Vault (tenant-isolated) and Pipes (brokered third-party OAuth). |
| *bounds what those keys may do* | **PRESENT for the ceiling; FUTURE for the objects** | Present: scope-shaped API keys with delegated mint and an authority ceiling (`src/server/services/keys/`), WorkOS FGA, the L0–L4 ladder. Future: `Mandate` / `Representation` / `GrantEdge` (`org.ai ADR-0012`, scoped, zero implementations); the approval ceremony. |
| *answers — from the source of record* | **PRESENT** | `GET /credentials/registries` **200** with the live roster and each adapter's `status`; `POST /credentials/verify {}` → **400** (typed). Six real primary-source adapters (MN DVS, TX DMV ×2, CA DMV OLSIS, AZ MVD, USPTO OED); a verdict tier that never collapses `live` and `goodStanding`; typed freshness failure; holder-attested evidence never satisfies an act-class gate. |
| *resolves any address to what it names* | **FUTURE** | `GET /01/09506000134352` → **404**, `GET /humans/test` → **404**. Scoped (`org.ai ADR-0013` RATIFIED, `id.org.ai/docs/adr/0001` PROPOSED), not built. §10 item **B1**. |
| *witnesses every act they take* | **FUTURE** | The insert-only audit log is built and typed; there is no emitter and no Pipelines/R2/queue binding in `worker/wrangler.jsonc`. §10 item **B4**. |

The correct future-tense sentences for the three most-claimed unbuilt capabilities are given at the
end of §7. They are **release-register statements of what ships**, not hedges: *"a GS1-conformant
Digital Link resolver ships on this property"* is legal; *"a resolver is coming soon, once the zone
move lands"* is banned build-state prose under `vis/CONTEXT.md:1009`.

### The one word that stays out, and why it is a different case

- **Not "standard."** This is the single item removed by the prior pass that **survives the
  correction** — and it survives for a reason that has nothing to do with a probe. `org.ai/CONTEXT.md`
  (the constitution, superior on *nature* — §6) already rules: *"The TLD is a layer's characteristic
  address, never its membership test: **id.org.ai is .do-layer work on an .org.ai name**."* That is a
  ratified ruling about what the property **is**, not an observation about what is built. The
  property *implements* other people's standards — better-auth's AAP verbatim, ID-JAG advertised,
  RFC 9728 / RFC 8707 on the MCP seam — which is the honest and stronger posture.
  **[OWNER]** *If the intent is that id.org.ai does publish a specification others implement, this is
  a constitutional amendment, not a copy edit — and the two credible candidates already exist in the
  estate: the ASN↔GLN CC BY crosswalk, and this repo's 39-requirement pinned acceptance spec
  (`specs/axp-acceptance.spec.json`), which is a conformance surface with a digest. Say "standard"
  the day a spec document and one external implementer exist, and re-file the vis roster row then.*

---

## 2. THE HERO — **RULED BY THE OWNER, 2026-08-03**

### First, the distinction that the first draft collapsed

**The hero and the purpose statement are two different artifacts, and conflating them is what
produced this document's original error.** Recording the difference explicitly so no future reader
repeats it:

| | The hero (§2) | The purpose statement (§1) |
|---|---|---|
| **What it is** | A **recognition device** — three words a reader can hold, repeat and file the property under | A **specification of the offer** — what id.org.ai is and is for, in one sentence |
| **Job** | Get filed in the right category, in five seconds, by a stranger | Carry the whole layer, every clause load-bearing, 100×-testable |
| **Where it lives** | The home page, `APP_TAGLINE`, the README title, the discovery-document description | `PRODUCT.md`, the spec, the Product Purpose block (§9) |
| **Register** | Nouns. It names. | Verbs. It commits. |
| **Ruled as** | *Agent. Human. Identity.* | *id.org.ai is the estate's who layer: it resolves… issues and holds… bounds… witnesses… and answers…* |

A hero is not a compressed purpose statement, and a purpose statement is not an expanded hero. The
first draft judged a hero by whether every noun in it returned 200 — a purpose-statement test applied
to a recognition device, on top of a build-state test that should never have been applied to either.

---

### THE RATIFIED HERO **[RULED 2026-08-03 by the owner — recorded in `vis/CONTEXT.md`, amending the presentation ruling of 2026-07-31]**

> # Agent. Human. Identity.
>
> ### The who layer — for whoever acts, and whatever they act on.

This is **in force**, not proposed. It supersedes *"Agent. Human. Thing."* (`vis/CONTEXT.md:1314`,
[RULED 2026-07-31]) and the live *"Humans. Agents. Identity."* in
`site/components/auth-hero.tsx:48-51` and `APP_TAGLINE`.

### What this ruling is not **[CLARIFICATION — agent-drafted 2026-08-24, pending owner ratification: the brand triad is not the identity model]**

The ruling above is the **human-facing brand ruling only**, and it must never be read as "id.org.ai
has no Thing identity." id.org.ai remains the estate's **default GS1 Digital Link resolver**
(`org.ai/docs/adr/0013`, RATIFIED) and **holds Thing identity**: Things dereference **here**, as
`https://id.org.ai/thing_<sqid>` lease-pointers under the id grammar of `org.ai/docs/adr/0003` R12.
*"Resolved, never attested"* is a claim about **authentication, not address** — Things are
**dereferenced** at this property but never **authenticated**; attestation is for the act-grains,
Agents and Humans. The hero decides what the property *says to a human*; ADR 0013 decides what the
property *serves* — and the 2026-08-03 ruling changed only the former. Do not derive an identity
model from a tagline.

**How the ruled hero works, in one line each:**

- **Agent. Human.** — the two grains that *act*, and therefore the two that can hold authority and be
  answerable. Agent leads because every incumbent IdP leads with humans.
- **Identity.** — the category noun, and the term that **absorbs Thing by construction**: resolution
  *is* what identity means for an object. The object grain is served without being promoted to a peer
  of the two that act.
- **The subline does the differentiating.** *"The who layer — for whoever acts, and whatever they act
  on"* is what keeps the triad out of the CIAM default; it names a **layer**, not a product category,
  and its second half is precisely where the object grain lands.

### The approved differentiator subline **[APPROVED — retained, not adopted as the hero]**

The verb triad proposed by this document was **not** adopted as the hero. It is **retained and
approved as the differentiator subline**, for surfaces that need a sharper positioning line than the
who-layer subline — the developer door, the verdict door, the README's opening paragraph, a deck
slide, any surface where the reader has already filed the property and now needs the point of view:

> **Keys for what acts. Limits on what it may do. Proof it was allowed.**

Two sublines, one hero, and they are not interchangeable: the **who-layer subline** answers *what
layer is this?*; the **differentiator subline** answers *why this one?* One live value per surface —
never both on the same screen.

### The candidates, re-scored against the ruling

**Build state was struck as a hero-selection criterion** before this ruling was made. Under the
claim-the-vision law, unshipped is not disqualifying for a hero any more than it is for a purpose
statement; it only selects the *tense*. Every score below rests on merits that hold whether or not
the code exists.

| Candidate | Source | Five-second test | Outcome | Why |
|---|---|---|---|---|
| **"Agent. Human. Identity."** | **[RULED 2026-08-03]** | ✓ — two act-grains and a category noun | **✅ RULED** | Thing is not promoted to a peer; *Identity* absorbs the object grain by construction; the subline carries the differentiation the bare noun cannot. |
| **"Agent. Human. Thing."** | `vis/CONTEXT.md:1314` [RULED 2026-07-31] | ✗ — no verb, no category noun | **✗ SUPERSEDED** | **Thing was never a peer of Agent and Human.** Canon: *"Thing itself stays the object grain: resolved (barcoding.dev), never attested (id.org.ai)"* — the triad claimed **another property's grain** in this property's hero. |
| **"Humans. Agents. Identity."** | `README.md:3`, live in `auth-hero.tsx:48-51` and `APP_TAGLINE` | ✓ | **~ SUPERSEDED on nouns; word order OPEN** | The bare noun set is close to the ruling, but the CIAM objection below is real and unanswered without a subline. Its *word order* is now an open owner question (§8 **Q13**). |
| **"Agents. Humans. Code."** | canon's three identity classes (`CONTEXT.md:1091`) | ✗ — a noun stack of three classes | **✗ REJECTED** | A **taxonomy** as a headline. Canon's own presentation ruling already files Code as *"a documented detail for developers."* |
| **"Keys for what acts. Limits… Proof…"** | this document | ✓ | **~ RETAINED as the differentiator subline** | Right register, wrong artifact. It answers *why this one?*, which is a subline's job, not a hero's. |

**Copy-gate consequences, recorded and not used to score:** the live page's promise
("connects — no auth") is **false** today — keyless `POST /mcp {tools/list}` → `-32001` (§10 item
**D3**, a four-line fix on code that already exists). The shipped enum is
`workerType: 'human' | 'agent' | 'organization' | 'service'` (`src/sdk/credential/types.ts:94`) — it
ships `'service'`, the exact word canon bans, and omits `Code` (§8 Q3, §10 item **B11**). Both are
backlog items. Neither is an argument about what the hero should say.

### Reasoning — which arguments were upheld, which were answered, which fell away

#### ✅ UPHELD AND STRENGTHENED — Thing does not belong in this property's hero

The objection carried, and **the decisive reason is not the one this document originally gave.** It
is not that `/01/{gtin}` returns 404, and it is not that the word confuses a reader. It is
structural: **Thing was never a peer of Agent and Human.** Canon says so directly —

> *"Thing itself stays the object grain: resolved (barcoding.dev), never attested (id.org.ai)."*
> — `vis/CONTEXT.md:1123`

Agent and Human are grains that **act**, hold authority and are answerable for what they do. Thing is
a grain that is **pointed at**. Listing them as three peers claims a symmetry canon denies, and
placing Thing in *id.org.ai's* hero specifically claims **another property's grain** — barcoding.dev
resolves things; id.org.ai never attests them. **This argument survives the claim-the-vision
correction cleanly**, because it says nothing about what is deployed: it would hold identically the
day `/01/{gtin}` returns 200.

**And Thing is not exiled.** It is served in two places, correctly: by *Identity*, the third word of
the ruled hero, which absorbs the object grain by construction; and by the purpose statement's
*resolve* clause (§1). What was removed is only the false promotion to peerhood.

#### ❌ FELL AWAY — *"the one path a GS1-literate reader knows how to type returns 404"*

**Struck, and it was never load-bearing.** The resolver is scoped (`org.ai ADR-0013` RATIFIED) and
unbuilt — a backlog item (§10 **B1**), not a reason to keep a grain out of the property's message.
The 100× test asks whether a credible large company would print the sentence, not whether the sprint
has landed.

#### ✅ RECORDED AND ANSWERED — the CIAM objection stands; the subline answers it

**The objection was not overruled.** *"Identity"* as a bare landing noun does file the property in
CIAM — the one category where the buyer's alternative to id.org.ai is **the WorkOS that id.org.ai is
built out of** (`README.md:282` — *"wraps WorkOS AuthKit for all human authentication"*), at the same
price, on a roadmap this property does not control. And it duplicates two funded competitors
word-for-word: Stytch ships *"The identity platform for humans & AI agents,"* Descope ships
*"Identity journeys for customers and AI agents."*

**The answer is the subline, not a denial of the objection.** *"The who layer — for whoever acts, and
whatever they act on"* names a **layer in a stack**, which no CIAM vendor claims and which the
estate's own architecture makes true. The differentiator subline — *"Keys for what acts. Limits on
what it may do. Proof it was allowed"* — carries it further wherever a surface needs more.

**The operative consequence, and it is now a standing constraint on copy:** *Identity* must **never
ship bare.** A hero of three nouns with no subline is the CIAM default, and the objection above then
applies in full. Any surface carrying the hero carries one of the two approved sublines with it.

#### ✅ UPHELD — a taxonomy is not a headline, and *Code* is a developer detail

"Agents. Humans. Code." publishes the **enum** as the headline — structurally the human-era IdP's
move ("Users. Groups. Roles."), advertising the substrate that §4 rules the estate gives away.
Canon's own presentation ruling — *"Code is a documented detail for developers"* — is **upheld
unchanged**, and it is a ruling about presentation, not about build state.

**Note the boundary of this argument precisely, because the ruled hero is also three nouns.** The
objection is to publishing a **taxonomy** — a complete enumeration of the classes the directory
stores. *"Agent. Human. Identity."* is not one: it is **two act-grains plus the category noun of the
layer**. The third term names what the property *is*, not a third row in the table. That distinction
is what lets the ruled hero pass an argument that correctly disqualifies the enum triad.

#### ❌ FELL AWAY — *"and Code is not shipped"*

**Struck.** The shipped enum is wrong (`'service'` where canon says `'code'`) and must be fixed —
§8 Q3, the least reversible item in this document. An unfixed enum is a data-model backlog item, not
an argument about hero real estate. The fix is to ship `'code'`, not to stop saying it.

#### ~ RE-ARGUED — the verb triad's own case, and where it landed

The prior form was *"every clause is checkable from a terminal today."* **That leg is struck** —
checkability-today is a copy-gate criterion, not a hero-selection criterion, and using it as one is
precisely how the vision got amputated in the first draft. What survives is that the verb triad
**states a point of view** — *identity alone is not enough; the question is whether the act was
allowed and whether you can prove it*. That is a real virtue, and it is why the line is retained as
the **differentiator subline**. It is not a hero's job: a stranger cannot file a property under a
point of view in five seconds, and the register a hero needs is nouns.

### The screens, reconciled to the ruled hero

Screen 1 changes: the ruled hero takes the headline and the verb triad moves to the subline slot.
Screens 2 and 3 are unchanged and remain present tense and true today. Screen 4 is unchanged and
remains explicit future tense, with no hedge, no date-narration and no "coming soon."

> # Agent. Human. Identity.
>
> ### The who layer — for whoever acts, and whatever they act on.
>
> **Differentiator subline:** *Keys for what acts. Limits on what it may do. Proof it was allowed.*
>
> **Body:** One OAuth 2.1 authorization server for the people, agents and code in your product.
> Humans sign in with SSO. Agents register a keypair and go — no human in the loop. Every key carries
> a scope ceiling, every use lands in an insert-only log, and before an agent acts for a business you
> can verify that business's licence against the issuing registry.
>
> **Screen 2 (the twist):** *An agent's word is worth nothing to a third party.* Check standing at
> the source: six state and federal registries, a verdict that never collapses "licensed" with "in
> good standing," and a typed failure when the answer is stale.
>
> **Screen 3 (the demo):** *The agent starts. The human confirms.* An agent provisions a workspace
> with no credential, operates, and hands a person a claim URL. Nothing is re-sent — the work was
> already theirs to take.
>
> **Screen 4 (the layer):** *One address for everything that acts.* Every human, agent and piece of
> code gets an address a stranger can dereference; every act taken under a key lands as an attested
> event on the one spine. The resolver and the event emitter ship on this property.

Screen 4 is where the hero's own third word is made good: *Identity* absorbs the object grain, and
Screen 4 is where dereferencing an address is stated. If Screen 4 cannot be written without hedging,
that is a signal to build, not to cut. See §10.

### What must change in code, now that the hero is ruled

- `site/components/auth-hero.tsx:48-51` — the headline becomes the ruled triad, and **the subline is
  not optional**: *Identity* never ships bare (see the CIAM answer above).
- `worker/wrangler.jsonc` — `APP_TAGLINE`, currently `"Humans. Agents. Identity."`. **Blocked only on
  §8 Q13, the word-order question** — the noun set is ruled; the order is not.
- `README.md:1-5` — the title, the hero, and the phrase *"an open identity standard for the agent
  era"* (see §6, §7 **C1**).
- `/.well-known/agent-configuration` — the `"humans, agents, organizations"` description string.
  Note it currently ships a *third* noun set, agreeing with neither the ruling nor the site.
- **Add Screen 4**, so the page carries the resolver and the witness in explicit future tense rather
  than omitting them. A home page that names only what answers today is not honest — it is
  incomplete, and under the claim-the-vision law that is the failure this revision corrects.
- **Move the sign-in form off `/` to `/login`.** Today the property's most valuable surface is spent
  on the one arrival that is not a market: the end user of a customer's app, who makes no buying
  decision and belongs to no ICP (§5, A14).

---

## 3. THE SPINE

### RULED — keep `identity → authority → witness`, and add the two-face rule

The ratified spine (`vis/CONTEXT.md:1197`) is upheld as a **layer stack**, not as a three-bucket
partition. The inventory's proposed six-movement replacement (*resolve · identify · authorize ·
verify · witness · settle*) is **rejected**: it is a list of endpoints wearing a model's clothes, and
it dissolves the one thing the three-stage spine gets right — that these layers *depend on each other
in order*.

The three reported failures of the spine are all artifacts of reading it as a partition. The fix is
one additional rule:

> **Every layer has two faces. The read face answers what an address affords — it is free, keyless,
> stateless, and never a protected resource. The write face changes state or binds a relying party —
> it is gated, and it is where the money is.**

With the two-face rule, every reported orphan lands:

| Reported orphan | Home | Why |
|---|---|---|
| **Resolution** (`/01/{gtin}`, `/{grain}/{id}`) | **identity, read face** | Dereferencing an address to a description *is* identity made public. An identity layer a stranger cannot dereference is a user table. ADR-0001 D3's invented verb *"GET stages, POST captures"* is not evidence of a missing fourth stage — it is the read/write split inside identity, correctly observed and mislabelled. |
| **Credential verification** | **witness, external source** | Canon defined witness narrowly as *acts land as events* — witness with an **internal** source. The general form is: a relying party must believe something it cannot check itself. `POST /credentials/verify` is that exact shape with an **external** source. One layer, two source classes. |
| **Claim-by-commit** | **identity, write face** | Not identity establishment (the tenant exists) and not authority conferral (nothing is delegated) — it is **ownership transfer of an already-operating workspace**, i.e. a second write door onto the bottom layer. |
| **Payment broker (x402 / MPP)** | **authority, enforcement instrument** | x402 and MPP exist so a mandate with a spend ceiling can be exercised without a human. `src/sdk/auth/scope.ts:54` says so in an inline comment: the missing piece is the *"spend-ceiling/Mandate persistence primitive."* The payment broker is the half of Mandate that got built. |

### The full capability map

Legend: **● built · ◐ partial · ○ not yet serving**. Face: **R** read (free/keyless) · **W** write
(gated).

**Read `○` as a backlog marker, never as a boundary of the offer.** Every row below is the property's
work; §7 says which of three kinds of work each one needs — scope, build, or deploy — and §10 orders
them. A `○` on a row that `org.ai ADR-0013` ratified means an engineer has not reached it yet.

#### Layer 1 — IDENTITY: who or what is this, and can a stranger dereference it

| Face | Capability | State |
|---|---|---|
| **R** | OIDC discovery, JWKS, 90-day cron rotation | ● live 200 |
| **R** | `/.well-known/agent-configuration` (AAP discovery) | ● live 200 |
| **R** | `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource` | ● live 200 |
| **R** | GS1 Digital Link resolver `/01/{gtin}[/21/{serial}]`, SSCC/GIAI/GRAI/LGTIN | ○ **404** |
| **R** | who-address grammar `/{grain}/{identifier}` over `/humans/ /agents/ /accounts/ /code/ /asn/ /ip/ /gln/ /lei/ /domain/` | ○ **404** |
| **R** | 303-vs-200 conneg matrix, `gs1:defaultLink`, `?linkType=` lens taxonomy | ○ |
| **R** | RFC 9264 linkset | ○ |
| **R** | AXP Tier 0: `/llms.txt`, `/.well-known/agents.json`, `/icp.json`, root markdown conneg | ○ **404 · 404 · 404 · serves `text/html`** |
| **R** | OpenAPI 3.1 for the real surface | ○ |
| **R** | MCP `initialize` + `tools/list` (discovery) | ○ **`-32001`** — see the boundary defect below |
| **R** | ASN↔GLN crosswalk, CC BY projection | ○ |
| **R** | Free stateless serialization (Sqids serials at the edge) | ○ |
| **W** | OAuth 2.1 AS — auth code + PKCE S256, token, refresh, introspect, revoke, device flow, consent | ● |
| **W** | Dynamic Client Registration, keyless | ● **201** |
| **W** | Trusted-account OAuth (`cid_trusted_account_v1`) | ◐ allowlist holds one host: `startup.games` |
| **W** | WorkOS AuthKit — SSO, social, sessions, orgs, invitations, admin portal, webhooks | ● |
| **W** | Cookie/JWT session + CSRF | ● |
| **W** | Ed25519 agent keypairs, `did:agent:ed25519:`, signed requests | ● |
| **W** | Agent records — register / status / revoke / reactivate, AAP §5.4 state machine | ● |
| **W** | AAP wire, verbatim | ● |
| **W** | Anonymous tenant provisioning, keyless | ● **201** |
| **W** | Claim token issue / status / redeem, claim landing page, GitHub App + Action, CLI | ● |
| **W** | Upstream Microsoft Entra federation | ◐ built, **not configured** (`MICROSOFT_CLIENT_ID` unset) |
| **W** | Email-code federation fallback | ● |
| **W** | ID-JAG conformance seam | ◐ advertised; trust list open |
| **W** | Agent lifecycle expiry sweep | ○ stored, never enforced |
| **W** | The **Code** identity class | ○ enum ships `'service'`, the banned term |

#### Layer 2 — AUTHORITY: what may this principal do, and who says so

| Face | Capability | State |
|---|---|---|
| **R** | L0–L4 capability ladder + `_meta` upgrade instructions on every MCP response | ◐ hardcoded table; open bead |
| **R** | Typed negative capability in discovery (`request_capability: null`, `rotate_key: null`, …) | ● — **see the design law below** |
| **W** | AuthBroker — `identify` / `gate` / `check`; anonymous L0 never throws | ● |
| **W** | Scope-shaped API keys, rate limits, delegated mint with authority ceiling | ● |
| **W** | WorkOS FGA (Zanzibar) | ◐ real, but its 35 resource types are headless.ly CRM entities |
| **W** | WorkOS Vault — tenant-isolated secrets, `{{vault:NAME}}` resolution | ● |
| **W** | WorkOS Pipes — brokered third-party OAuth | ● the only shipped thing resembling credential custody |
| **W** | SCIM directory sync | ◐ present, no route wires it |
| **W** | Payment broker — x402 + MPP | ◐ 2 of 6 rails real; Stripe SPT / Solana / Lightning / Card throw `unimplemented()` |
| **W** | `Mandate` / `Representation` / `GrantEdge` (org.ai ADR-0012) | ○ zero implementations; only `ScopeGrant`, ratified by no ADR |
| **W** | Deputization (B2H2A) and engagement (B2A2H) **as ceremonies** | ○ protocol plumbing exists; no approve/deny surface |
| **W** | AS2 certificate / SFTP credential custody | ○ zero code |
| **W** | Chat-native grant flow (Slack/Teams ask) | ○ zero code |
| **W** | Mobile wallet / agent-approval centre / scanner | ○ no repo anywhere in the estate |

#### Layer 3 — WITNESS: will a third party act on what you say

| Face | Source | Capability | State |
|---|---|---|---|
| **R** | external | `GET /credentials/registries` — the roster, each adapter's `status` and `cadence`, **including the stubs** | ● live 200 |
| **W** | external | `POST /credentials/verify` — verdict tier (`live` and `goodStanding` never collapsed), typed freshness failure, holder-attested never satisfies act-class | ● live |
| **W** | external | Registry adapters | ◐ 6 real (MN DVS, TX DMV ×2, CA DMV OLSIS, AZ MVD, USPTO OED), 1 real-interim, 5 honest stubs each returning a typed cure |
| **W** | external | Structured 402 offer at the paid boundary, with a free registry-mode alternative | ● |
| **W** | internal | Audit log — typed, queryable, insert-only | ● local journal |
| **W** | internal | Per-principal credential-verification journal | ● |
| **W** | internal | **Every act lands as an attested event on the one spine** | ○ **no Pipelines binding, no R2, no queue; zero `epcis`/`otel` references in `src/` or `worker/`** |
| **W** | internal | Key-usage events as record-class on the spine | ○ same |
| **W** | internal | Auth + analytics as an embeddable SDK ("the witness generalized") | ○ no emitter to dogfood |

### The design law the spine already obeys, and which should be named

`/.well-known/agent-configuration` returns `request_capability: null, rotate_key: null,
introspect: null, capabilities: null, execute: null` — **typed negative capability in the same schema
as positive capability**, with the source comment stating the intent: *"declared as `null` so AAP
clients see them missing rather than 404 their way through."* `approval_methods:
['claim_by_commit']` carries the same discipline — the accurate custom value rather than a ceremony
we do not run.

**RULED — this is the property's design law, binding on every surface:** *machine-legible negative
capability.* An agent must never have to guess, retry, or ask a human what it is allowed to do or
what it costs. This is the same law as vis's banned-"Contact us" ruling and the no-ask-zone law,
seen one layer down. A human-era IdP *could* emit typed nulls; it structurally will not, because the
gap between what the docs imply and what the tier delivers is where its enterprise motion is created.

### The boundary defect — one fix, not five tickets

Five items currently fail: keyless `tools/list` (`-32001`), `/llms.txt` (404),
`/.well-known/agents.json` (404), `/icp.json` (404), and root markdown conneg (serves `text/html`).
They are **one architectural defect**: the service gates by **endpoint** where it should gate by
**layer face**.

`tools/list` asks *what does this address afford?* — identically the question `/llms.txt`,
`/.well-known/agents.json`, `/icp.json` and `/01/{gtin}` ask. All five are identity's read face and
must be free, keyless and stateless **by layer, not by exception**. Verified in code:
`worker/middleware/auth.ts:168` already sets `MCPAuth.anonymousResult()` and calls `next()` for a
credential-free request — the middleware is not the gate. The gate is `worker/routes/mcp.ts:240` and
`:265`; immediately below, `buildToolList` gates only at `auth.level >= 1`, so the L0 tool set
(`explore`, `search`, `fetch`) is constructed and then made unreachable.

**The rule: dispatch the tool, then gate by the tool's face.** `initialize` and `tools/list` always
answer; read-face tools (`explore`, `search`, `schema`, `fetch`, `identity`) keyless; write-face
tools (`try`, `do`, `provision`) gated per-tool by the `requiredLevel > auth.level` branch that is
already correct at `:335`, with the L0 30 req/min limit that `RATE_LIMITS[0]` already defines.

This is a **live conformance failure against a RATIFIED vis law** (the agent-self-service law,
`CONTEXT.md` 2026-08-02) and against this repo's own pinned requirement `A-mcp-keyless-tools-list`.
It is not a positioning question. Either fix the code or amend the pinned spec — do not leave it
split. *If the 401 turns out to be a deliberate MCP-client-compatibility workaround, that must be
recorded as such and the pinned requirement amended.*

### Build-order finding — and the serving-substrate finding underneath it

The paid layers are ~80% built; the free read face is ~0% built — and **every unbuilt read-face item
is a stateless GET**, which by canon's own Snippet ruling is the cheapest thing on the board to serve
*and* to write (no secrets, no database, no state machine). The build order followed the revenue
instead of the stack. A platform cannot sell layer N+1 before layer N exists, because nobody is
standing on layer N.

**And there is a deployment fact under the build fact.** `vis/CONTEXT.md:931` rules that **nothing
serves from a Free-plan zone** — every property CNAMEs to **workers.do (Enterprise)** and is added
there as a Cloudflare-for-SaaS custom hostname, because **Snippets are unavailable on Free-plan
zones**. Verified in this repo, `worker/wrangler.jsonc`:

```jsonc
{ "pattern": "oauth.do/*",          "zone_name": "oauth.do"   },
{ "pattern": "auth.headless.ly/*",  "zone_name": "workers.do" },   // ← enterprise zone
{ "pattern": "id.org.ai/*",         "zone_name": "id.org.ai"  },   // ← its own zone
{ "pattern": "auth.org.ai/*",       "zone_name": "workers.do" },   // ← enterprise zone
```

**Two of this worker's four hostnames already route through the enterprise zone; `id.org.ai` itself
does not.** That is the routing residue of the org move the owner describes — the `.org.ai` domains
were only just consolidated into the same org so they *could* join `workers.do`. The consequence is
concrete and it changes the build order: **the entire unbuilt read face is exactly the Snippet-native
class** (Digital Link parsing, check-digit validation, linkset/resolver doors, redirects, the conneg
face selector — canon names them one by one at `CONTEXT.md:928`), and Snippets are the mechanism that
makes them cost nothing. Building the read face onto a non-enterprise zone builds it onto the wrong
substrate. **Move the route first; it is a deploy action, it unblocks the cheapest layer on the
board, and it inherits Bot Management and the rest of the Enterprise entitlements at the same time.**
§10 item **D1**.

---

## 4. THE FREE / PAID BOUNDARY

### The problem being fixed

`vis/CONTEXT.md:1200-1204` reads: *"the resolver and the wallet are deliberately free, and the
witness is never behind a paywall — you always can emit and always can resolve; you pay to govern at
organizational scale **and to prove things to third parties**."* But proving things to third parties
**is** witness. Canon draws the boundary twice, in opposite directions, in one sentence, at exactly
the point where the money is — and the code has already picked a side: `worker/routes/credentials.ts:96`
prices a verdict at **$2.50**, with a **$0** registry-mode alternative at `:100`.

### RULED — free to emit, paid to be believed **[OWNER — this amends `vis/CONTEXT.md:1200-1204`.]**

The boundary moves off the *stage* axis and onto the *face* axis, where it was always running:

> **Every layer gives away the face a principal turns toward itself, and charges for the face it
> turns toward someone else.**

Stated so an agent can act on it without asking anyone:

#### FREE FOREVER — no key, no card, no human, no rate-limit negotiation

Everything stateless and self-directed. The estate gives away what costs it nothing and what a
principal does for itself.

- **Dereference any address.** `/{grain}/{id}`, `/01/{gtin}`, linksets, conneg faces. *(§7 **B1**, **B2** — scoped, not built)*
- **Read the machine face.** `/llms.txt`, `/.well-known/agents.json`, `/icp.json`, `/openapi.json`,
  MCP `initialize` and `tools/list`, and every read-face tool. *(§7 **B3**, **B6** — scoped, not built;
  **D3** — built, not serving)*
- **Read the discovery documents.** OIDC, JWKS, OAuth AS metadata, AAP agent-configuration. *(live)*
- **Register a client.** Keyless DCR. *(live, 201)*
- **Provision a workspace.** Keyless. *(live, 201)*
- **Obtain keys, sign requests, register and revoke an agent.** *(live)*
- **Emit.** Attested events are never metered on the write path. *(§7 **B4** — the audit path is built;
  the emitter is scoped, not built)*
- **Self-attest.** A claim about yourself, signed by you, is free forever — and by the verdict tier's
  own rule it never satisfies an act-class gate, which is exactly why it can be free.
- **The registry roster, including its gaps.** `GET /credentials/registries` publishes each adapter's
  `status` — six `real`, one interim, five `stub` — as machine-readable data. *(live)*

#### METERED — published price, self-serve, card, no human in the loop

You pay when the estate spends a relationship with a third party on your behalf.

- **A verdict you cannot self-issue.** Primary-source verification: **$2.50 per PSV check**
  (`credentials.ts:96`), offered through a structured 402 whose **first listed alternative is the
  free registry mode**. This is the only real price in the repository and it is the canonical price
  shape, not an anomaly.
- **Retention and query at scale** on the witness record, past the free line. *(price $TBD — §9)*
- **Attested acts at third-party grade** — an act countersigned so a relying party can act on it.
  *(§7 **B4** — scoped, not built; price $TBD)*
- **Durable statefulness past the free tier** — persistent workspaces, entity ceilings lifted.
  *(price $TBD — §9)*

**Rejected as the meter:** *per-agent seats.* No comparable prices a per-agent seat; the one vendor
that has priced agents did it as a percentage add-on. More importantly, a per-agent seat prices the
exact moment the RATIFIED agent-self-service law says must be free. The units with precedent are
**verifications, connections, and retained events**.

#### ENTERPRISE — the only unpublished number in the family, per the tier-gate law

Governance at organizational scale, and the buying ceremony itself. The feature table publishes; only
the number says custom. **"Contact us" remains banned** — the enterprise motion enters self-serve
like everyone else and upgrades in-product.

- SSO/SAML/OIDC connections, SCIM directory sync, domain verification, MFA/session policies.
- RBAC + FGA at org scale; audit-log export and SIEM streaming; admin portal; IP allowlisting.
- **A customer's own resolver hostname** (`id.{brand}.com`) operated by us, with the enterprise
  entitlements a brand cannot assemble alone. *(depends on §7 **B1**, the scoped-and-unbuilt resolver)*
- Data residency; custody-grade retention and legal hold; single-tenant options.
- MSA / DPA / security review / PO invoicing.

### Why this boundary is structurally stable

Four independent estate rulings turn out to be the same line: the **Snippet ruling** (free = stateless)
is this line viewed as cost; the **no-ask-zone law** (an agent must never ask a human what something
costs) is this line viewed as ethics — self-directed acts never need a human, other-directed ones
legitimately do; the **tier-gate principle** (*SMB buys the product; Enterprise buys governance,
proof, and the buying ceremony*) is this line viewed as packaging; and the **capture ladder's**
decoded-vs-interpreted discipline is this line viewed as evidence. Canon already noted the first
coincidence. It is the same line four times.

### A named risk

Free resolution creates lock-in only through **the printed address** — a QR carrying `id.org.ai` on a
ten-year artifact is unswitchable. But the Enterprise upgrade is `id.{brand}.com`, which deliberately
*removes* the printed hostname that created the lock. That is the right call (GS1 Best Practice
requires it), and it must be stated plainly rather than left implicit: **printed-host lock-in exists
only on the free tier and is sold away at the top.** The durable lock is being the party a relying
party believes — which is the credential runtime, which already ships and already charges.

---

## 5. THE PERSONA MAP AND DOOR STRUCTURE

### Five candidate ICPs, and one refusal

Ids are **candidates, not ratified**. None passes the reality gate — there is no firm table, no
Persona store, no `workerType` column, zero Trigger rows. These are authored.

| Id | ICP | Principal-kind | Build state of its arrival path |
|---|---|---|---|
| **ID-1** | The product engineering team shipping an app that needs sign-in | Developer | ● **complete** |
| **ID-2** | The platform operator reselling identity to its own tenants | Business | ◐ DCR open; trusted-account path is a `wrangler.jsonc` edit |
| **ID-4** | The self-principal agent population | Agent | ◐ provisioning ✓, discovery ✗ |
| **ID-5** | The firm that has agents acting for it | Business | ○ Mandate = zero code |
| **ID-6** | The relying party that must know a counterparty's standing | Business | ● built, priced, **unexported** |
| **~~ID-3~~** | The estate-captive consumer | — | **NOT AN ICP — recorded refusal** |

**The refusal matters.** Eleven properties consume id.org.ai at runtime — `startup-builder`
(`packages/auth-id-org-ai`, documented as *"the only path for identity"*), `builder.domains`
(`env.AUTH.verifyToken`), `agentic-inbox` (`ID_ORG_AI_ISSUER`), `nanoclaw` (hardcoded issuer + JWKS),
`startup.games` (the sole `TRUSTED_ACCOUNT_DOMAINS` entry), `mdxui`, `headless.ly/.do/oauth/core`,
`primitives.org.ai`, `digital-tools`, plus `oauth.do` / `auth.headless.ly` / `auth.org.ai` on the same
worker. **A captive consumer has no capital structure, no alternative, no procurement act and no
trigger — it did not decide, it was wired.** Governed by an internal dependency paper and a
breaking-change contract, never by targeting. **vis is a member of this non-ICP, and today it holds
zero runtime binding.**

### The door structure — four doors and one channel

A door is defined by its route set. The count is fixed by law, not taste: **R-1.5 caps an offer at
1 ICP / 2–4 Personas / exactly 1 primary**, and a home page is an offer surface — so a home page
addressing seven arrivals is illegal under the estate's own cardinality rule. **AL-4** bifurcates
register by `workerType` (humans get STORY, agents get SPEC), so a minimum of two faces exists by
law. Today the machine face returns 404 on all four discovery documents and `-32001` on `tools/list`:
**id.org.ai has one door, and it is the half AL-4 says you cannot persuade with.**

| Door | Routes | Serves | Register | Surface | State |
|---|---|---|---|---|---|
| **Channel 0 — the resolver** | `null` (no principal-kind readable) | anyone dereferencing an address or reading the machine face | none | `/{grain}/{id}`, `/01/{gtin}`, `/llms.txt`, `/.well-known/agents.json`, `/icp.json`, `/openapi.json` | ○ **all 404** |
| **Door 1 — the machine face** | B2A · B2A2D · B2A2B | self-principal and deputized agents | **SPEC** | keyless `tools/list`, `/api/provision`, `/.well-known/agent-configuration`, entry verb per class | ◐ provision ✓, discovery ✗ |
| **Door 2 — the developer door** | **B2D** | the engineer embedding auth; the human claiming a workspace | **STORY**, authority beats machine-checkable | `npm i`, quickstart, OIDC discovery, React SDK, CLI, claim-by-commit | ● **built** |
| **Door 3 — the governance door** | B2B · B2H2A | the firm governing agents; the human deputizing one | STORY | agent roster, mandates, seats, custody, the approval ceremony | ○ **mostly unbuilt — keep shut** |
| **Door 4 — the verdict door** | B2B · B2A2B · B2A | the relying party buying an answer about a third party | STORY + SPEC | `POST /credentials/verify`, the registry roster, the 402 | ● built, priced, **unexported** |

**Channel 0 is not a door.** It has no ICP, no principal-kind, and no budget line anywhere in the
economy — every resolver that exists is free at the point of use and monetised one layer over (DNS,
DOI, GS1). It gets no hero, no CTA, no copy. **It is distribution, and it should be built first
because every item in it is a stateless GET.**

**Door 4 is the open call** (§8, Q5): because its subject is a *third party* rather than the arriver,
it is the one arrival with a genuine case for being a **separate property** — a metered verdict API
in the KYB / vendor-qualification budget, not the identity budget.

### The single arrival the home page addresses

> **ID-1 / Door 2 / route B2D — the product engineer embedding auth.**

The case, on evidence rather than preference:

- **It is the only arrival whose full path is built and independently checkable today.** Verified
  this session: keyless DCR → **201**; OIDC discovery → **200**; JWKS → **200**. 72 test files,
  ~2,076 assertions, four zones deployed.
- **Its entry verb needs no human** (`npm i id.org.ai` / `POST /oauth2/register`), so AL-6 and the
  RATIFIED agent-self-service law are satisfied by construction on this path.
- **It is the only arrival with revealed demand.** All eleven runtime consumers arrived through it.
- **Every alternative fails a hard test at the URL.** Door 1's keyless discovery returns `-32001`.
  Door 3's capability is zero code. Channel 0 404s. Door 4 is built but is a different subject-grain,
  a different budget, and is not exported from the package.

**The offer's persona set (R-1.5: one ICP, four personas, exactly one primary):**

| Seat | Persona | `workerType` | Route | Register |
|---|---|---|---|---|
| **PRIMARY** | The Product / Platform Engineer × ID-1 | human | B2D | STORY, authority beats machine-checkable |
| supporting | The Engineering Manager × ID-1 | human | B2D | STORY |
| supporting | The Security / Architecture Reviewer × ID-1 | human | B2D | STORY |
| supporting | The `coding`-class agent in the engineer's session × ID-1 | agent | B2A2D | **SPEC** |

The agent row is not optional: per V19a, where an ICP's table carries a `workerType: agent` row and
the offer's motion asserts an agent arrival — and claim-by-commit's entire story is an agent
operating first — that row must be in the addressed set.

**Recorded alternative `[C]`, not live:** the Compliance / Vendor-Qualification Lead × ID-6. It is
the only arrival with a published price and the only module with no upstream vendor. If the business
is the verdict, the hero belongs to the compliance lead and the auth surface becomes documented
infrastructure rather than the headline. **One live value, one recorded alternative — never two live
values.** The call is the owner's (§8, Q5).

*To be precise about what `[C]` would and would not change: it changes **which arrival the home page
addresses**, not the hero words. **"Agent. Human. Identity." is ruled and is not reopened by Q5.**
Under `[C]` the ruled hero stands and the **differentiator subline** — *"Keys for what acts. Limits on
what it may do. Proof it was allowed"* — becomes the working subline on that surface, because a
compliance lead arrives already knowing what identity is and needing to know why this one.*

**Blocking prerequisite before any offer ships:** `package.json` exports thirteen paths — `.`,
`./server`, `./auth`, `./oauth`, `./mcp`, `./github`, `./claim`, `./jwt`, `./workos`, `./federation`
and three CLI paths — and **not `./credential`, `./payment` or `./audit`**, despite all three being
implemented and tested. The most differentiated module in the repo cannot be imported by any consumer
of the package. **That is one line of configuration, it makes a present-tense verifiable claim that
requires no promise about anything unbuilt, and it gates the `[C]` alternative entirely.**

### Two conflations that must be separated in copy

- **Claim ≠ deputize.** "The human confirms" names two ceremonies with opposite build states.
  *Claim-by-commit* is a human taking **ownership of a workspace** — route B2D, **built and live**.
  *Deputization* is a human **conferring bounded authority on an agent** — route B2H2A, **zero code**.
  Copy that runs them together sells an unbuilt ceremony on the credibility of a built one.
- **The end user of a customer's app is not a market.** They make no buying decision, have no
  principal-kind readable at arrival, and belong to no ICP. Route `null`. They are almost certainly
  the largest arrival at the origin, and they currently own the home page.

---

## 6. THE SCOPE RECONCILIATION — one story, both true

### The precedence order **[OWNER — must be ratified; neither canon currently cites the other as superior]**

> 1. **The org.ai constitution governs what the property IS** — its layer, its category, whether it is
>    a standard or a service. Superior on *nature*.
> 2. **This document (and the PRODUCT.md it produces) governs what the property OFFERS** — hero,
>    spine, boundary, doors. Superior on *the offer*, within the constitution.
> 3. **A consuming family's canon governs what that family REQUIRES of it** — vis's `CONTEXT.md` is
>    superior on vis's requirements, and on nothing else.

Nature and requirements are different questions, so there is no conflict to arbitrate — each canon
should cite the other's jurisdiction explicitly. Under that order, one already-recorded ruling settles
the standard/service question without a new decision.

### The one story

> **id.org.ai is estate-shared identity and authority infrastructure with a differentiated
> verification runtime on top. Its identity and authority layers serve the whole estate, and
> headless.ly is their principal tenant today. Its witness layer is the one vis depends on, and it is
> the layer nobody has built. vis is a tenant of two layers it need not own, and the sole tenant of a
> third that does not yet exist.**

Both views are true under this story, with these corrections:

**What the constitution corrects in both A and B.**
`org.ai/CONTEXT.md` rules: *"The TLD is a layer's characteristic address, never its membership test:
**id.org.ai is .do-layer work on an .org.ai name**."* There is no specification in this repo that
another party could implement — there is a deployed worker, an npm package, a React SDK and a CLI.
Therefore:
- **Strike *"an open identity standard for the agent era"*** from `README.md:5`. The honest and
  stronger posture is that the property **implements** other people's standards — AAP verbatim,
  ID-JAG advertised, RFC 9728/8707 on the MCP seam.
- **Re-file the vis roster row.** `vis/CONTEXT.md:831` lists id.org.ai under *".org.ai = **Standards**"*.
  It is not one. **[OWNER]**
- *If the estate genuinely intends to publish a spec others implement — the ASN↔GLN CC BY crosswalk
  is the one credible candidate — say "standard" the day a spec document and one external
  implementer exist. Not before.*

**What is upheld from vis's view (A).**
- The **one-resolver ruling** is architecturally correct and stands: resolution is identity's read
  face, so it belongs on the identity property and barcoding.dev builds no resolver. The ruling is
  upheld; **its execution is indicted** — the resolver is unbuilt and it is the cheapest thing on the
  board. `org.ai ADR-0013 R2` (RATIFIED) commits the property to this role.
- **identity → authority → witness** is upheld as the spine (§3), with the two-face rule added.
- **Code as the third identity class** is upheld in the model (§8, Q3) and confined to developer
  documentation, exactly as `CONTEXT.md:1314` already ruled — only the *hero* half is amended.
- The **agent-self-service law** binds and is currently violated on one route (§3).
- The **tier-gate principle** and the **no-ask-zone law** are upheld and are the same line as §4.

**What must be corrected in vis's view.**
- **vis's language must move from ownership to dependency.** Five files publish present-tense
  dependent claims against capabilities that do not exist: `vis/PRODUCT.md:97`
  (*"One resolver. Identity resolution is id.org.ai's alone"*), `epcis.dev/PRODUCT.md:82`,
  `barcoding.dev/PRODUCT.md:78,92`, `transactions.dev/PRODUCT.md:92` (*"credential custody for the
  legacy rails (AS2…)"* — zero code), `visibility.associates/PRODUCT.md:103,112`,
  `visibility.cloud/PRODUCT.md:24,97`. **[OWNER — these files are outside this document's write
  scope; listed in §8 as amendments.]**
- **The "papered default-provider dependency"** (`CONTEXT.md:1198`) is a sentence, not an agreement.
  Under this story the paper is narrow and writable: **not a claim on the property, but a commitment
  that the witness layer emits to vis's spine in a conformant shape**, with identity and authority
  explicitly acknowledged as shared estate infrastructure carrying no vis-specific obligation.

**Why no fork is needed.** The layers have different tenants. Identity and authority are genuinely
shared — which is why `startup-builder`, `builder.domains`, `agentic-inbox`, `startup.games`,
`nanoclaw` and mdxui bind to them without vis's involvement, and why the FGA schema, MCP catalog,
`.headless.ly/agents/*.pub` pubkey path and three of four zone routes are .do-estate shaped. Witness
is different in kind, and building it is **additive at the top of the stack**: bind Pipelines, emit
from the existing audit path, break none of the eleven runtime consumers. *This is checkable before
committing — if nothing in the shared layers has to change, the layer separation is real.*

**The entanglement that is a defect, not a scope fact.** The FGA schema hardcodes 35 headless.ly CRM
resource types and `explore` describes a fixed 32-entity CRM catalog. That is the authorization
engine knowing its tenant's domain vocabulary — the same category error as an IdP shipping a
hardcoded role list. Make the resource-type registry tenant-supplied and make `explore` describe *the
caller's capability surface* rather than a catalog, and the question of whether the property is
"vis-shaped" stops having meaning. *Gate the FGA migration on a second real tenant; do the `explore`
change first, since it is additive and independently correct.*

**Housekeeping the constitution already decides.** `org.ai/CONTEXT.md`: *"Venue names are leases;
identity never lives on them."* `LICENSE` reads `Copyright (c) 2026 headless.ly` — a venue name, on
the estate's identity property. Any buyer in a security or compliance category opens the LICENSE
first. **Reconcile to the owning entity before the offer ships.** **[OWNER]**

**And the draft that must move.** `docs/PRODUCT-approval-flows.draft.md` claims
`$id: https://id.org.ai/product.md` — the canonical product address — while marked *"PROPOSED —
scoping only. Nothing built, deployed, or filed."* It is the **authority layer's write-face ceremony
surface**, one face of the middle layer, not a competing product. **Vacate its `$id` and re-file it as
the roadmap item the spine predicts.** It cannot hold the canonical product address while no
PRODUCT.md exists.

---

## 7. THE GAP LIST — three categories, not two

**This list is the backlog, not an indictment.** Every row is work the estate intends; the only
question each row answers is **what kind of work is left**. A binary built/unbuilt audit collapses
three different jobs — writing a spec, writing code, and shipping code that already exists — into one
undifferentiated accusation, and that collapse is what caused the framing error this revision fixes.

| Category | Definition | What unblocks it |
|---|---|---|
| **NOT SCOPED** (`S`) | Brainstormed — named in `vis/CONTEXT.md` or a session doc. No spec, no ADR, no pinned requirement, no tickets. | **Scope work.** A ruling or an ADR. |
| **SCOPED, NOT BUILT** (`B`) | A spec, ADR or pinned acceptance requirement exists. Code does not. | **Build work.** An engineer. |
| **BUILT, NOT DEPLOYED** (`D`) | Code exists and is tested. It is not serving — because of a route, a binding, an export, a config value, or a gate. | **Deploy work.** Usually one line. |
| *(NOT A GAP)* (`C`) | Copy that is stale or present-tense-false against a built or unbuilt capability. | **A copy edit** — or the build it is waiting on. |

**The per-surface copy gate is unchanged and still binds:** nothing in `S` or `B` may appear in
present tense on any published surface. It may — and under the claim-the-vision law generally
**should** — appear in explicit future tense. Nothing anywhere may hedge, narrate build state, or say
"coming soon."

Each row was verified by live probe or direct code inspection on 2026-08-03. The original §7
numbering is preserved in the last column so nothing is lost in the re-classification.

---

### D — BUILT, NOT DEPLOYED

*Code exists. It is not serving. These are the cheapest items on the board and they lead the backlog.*

| ID | Item | Why it is not serving | Evidence | was |
|---|---|---|---|---|
| **D1** | **Enterprise-zone routing for `id.org.ai`** | `worker/wrangler.jsonc` routes `id.org.ai/*` to `zone_name: "id.org.ai"`, while `auth.headless.ly/*` and `auth.org.ai/*` already route through `zone_name: "workers.do"`. The `.org.ai` domains were only just consolidated into one org so they *could* join the enterprise zone. | `vis/CONTEXT.md:931` — *"nothing serves from a Free-plan zone"*; Snippets, the mechanism that makes the whole read face free, are unavailable off the Enterprise zone | **new** |
| **D2** | **`./credential`, `./payment`, `./audit` are not exported** | `package.json` exports thirteen paths (`.`, `./server`, `./auth`, `./oauth`, `./mcp`, `./github`, `./claim`, `./jwt`, `./workos`, `./federation`, three CLI paths) — and none of those three. The **most differentiated module in the repository cannot be imported by any consumer of the package.** | `src/sdk/credential/` (`verify.ts`, `gates.ts`, `freshness.ts`, `sources/`), `src/sdk/payment/`, `src/sdk/audit/` all exist, implemented and tested | **new** |
| **D3** | **Keyless MCP `initialize` + `tools/list`** | The L0 tool set is **constructed and then made unreachable**. The middleware is not the gate — `worker/middleware/auth.ts:168` already returns `MCPAuth.anonymousResult()` and calls `next()`. The gate is the route-level `if (!auth?.authenticated) return unauthorizedChallenge(c)` at `worker/routes/mcp.ts:240` and `:265`. | `explore` is defined at `mcp.ts:118`; `buildToolList` withholds at `:164`/`:192` on `auth.level >= 1`; the correct per-tool gate already exists at `:335`; `RATE_LIMITS[0]` already defines the L0 30 req/min limit | 6 |
| **D4** | **Upstream Microsoft Entra federation** | Built and wired; `MICROSOFT_CLIENT_ID` is unset. Fails soft by design — `/federation/microsoft/start` falls back to email-code, `/federation/status` reports `configured=false`, nothing 500s. | `wrangler.jsonc`: *"NOT YET SET — the app registration is an owner action"* **[OWNER]** | 20 |
| **D5** | **Trusted-account onboarding** | DCR is genuinely open and keyless (**201**), so the open path ships. The trusted-account path is a `wrangler.jsonc` edit per host and `TRUSTED_ACCOUNT_DOMAINS` holds exactly one: `startup.games`. *(Self-service for it is `S6`.)* | `wrangler.jsonc` `vars.TRUSTED_ACCOUNT_DOMAINS` | 23 |
| **D6** | **SCIM directory sync** | Present in the codebase; **no route wires it**. An Enterprise-tier line item that cannot be sold because nothing dispatches to it. | §3 capability map, Layer 2 | 12 (part) |

---

### B — SCOPED, NOT BUILT

*A spec, a ratified ADR or a pinned acceptance requirement exists. Code does not. These need an
engineer, not a decision — except where noted.*

| ID | Item | The scope that exists | Actual state | was |
|---|---|---|---|---|
| **B1** | **GS1 Digital Link resolver** — `/01/{gtin}[/21/{serial}]`, SSCC / GIAI / GRAI / LGTIN | `org.ai ADR-0013` **RATIFIED** (2026-07-20, merged `96366e0`, reconciled `a16c848`); `id.org.ai/docs/adr/0001` **PROPOSED** | Zero code — no `gtin` / `DigitalLink` reference anywhere in `src/`, `worker/` or `site/`. `GET /01/09506000134352` → **404** | 1 |
| **B2** | **The who-address grammar** `/{grain}/{identifier}` over `/humans/ /agents/ /accounts/ /code/ /asn/ /ip/ /gln/ /lei/ /domain/` | `vis/CONTEXT.md:1053` names the grain set; ADR-0001 covers the routing shape | Zero code. `GET /humans/test` → **404** | 2 |
| **B3** | **The machine face** — `/llms.txt`, `/.well-known/agents.json`, `/icp.json`, root markdown conneg | **Scoped to the requirement level.** `specs/axp-acceptance.spec.json` pins nine of them by name: `A-llms-txt-surface`, `A-llms-txt-agent-actionable`, `A-agents-json-surface`, `A-agents-json-parses`, `A-icp-json-surface`, `A-icp-json-self-classification`, `A-content-negotiation`, `A-agents-json-declares-mcp-and-ladder`, `A-icp-json-declares-ladder` | **No such file exists anywhere in the repository** — verified by filesystem search, not only by probe. **404 · 404 · 404**; `Accept: text/markdown` serves `text/html` | 3 |
| **B4** | **Spine emission** — *"every act lands as an attested event on the one spine"* | `vis/CONTEXT.md:1197` [RULED]; the event shape is scoped vis-side | **The event source is built; the emitter is not.** A typed, queryable, insert-only audit log and a per-principal verification journal exist. No Pipelines binding, no R2, no queue in `worker/wrangler.jsonc`; zero `epcis` / `otel` / `pipeline` hits in `src/` + `worker/`. **Additive at the top of an existing path** — it breaks none of the eleven runtime consumers | 7 |
| **B5** | **Key-usage events as a record-class on the spine** | `vis/CONTEXT.md` [RULED 2026-07-31] | Depends entirely on B4 | 8 |
| **B6** | **OpenAPI 3.1 for the real surface** | pinned `B-openapi-published`, `B-openapi-31-honest` | Absent — no `/openapi.json` | 4 |
| **B7** | **RFC 9264 linkset**, the 303-vs-200 conneg matrix, `gs1:defaultLink`, the `?linkType=` lens taxonomy | pinned `B-linkset`; ADR-0001 D2 | Zero code | 5 |
| **B8** | **`Mandate` / `Representation` / `GrantEdge`** | `org.ai ADR-0012` — a merged nine-ruling vocabulary spec (M1–M9) reconciled across five binders | **Zero implementations.** Only `ScopeGrant` ships — the may-do reach under a different name, ratified by no ADR, carrying an inline note that the *"spend-ceiling/Mandate persistence primitive"* is missing (`src/sdk/auth/scope.ts:54`) | 10 |
| **B9** | **`autonomous` as a derived reading** | `org.ai ADR-0012 M7`: `autonomous ⟺ a live Mandate covers the action` | **Asserted, not derived.** `/.well-known/agent-configuration` advertises `modes: ['delegated','autonomous']` while no Mandate persistence exists, so the wire states a stored default as a derivation. **A live honesty defect in a machine-readable document, in SPEC register, where no story softens it.** Depends on B8; until B8 lands, either derive from `ScopeGrant` or stop advertising the mode | 18 |
| **B10** | **Deputization (B2H2A) and engagement (B2A2H) as ceremonies** | Scoped **at draft level only**: `docs/PRODUCT-approval-flows.draft.md` (24 KB) and `docs/scoping-outbound-identity-plane.md` (340 KB). Promotion to a spec is §8 Q9 | No approve/deny surface. AAP register + claim (`worker/routes/aap.ts`) are protocol plumbing, not a ceremony | 11 |
| **B11** | **`Code` as a shipped identity class** | Named `vis/CONTEXT.md:1091` (2026-07-31); §8 **Q3** carries the standing recommendation | Enum ships `'human' \| 'agent' \| 'organization' \| 'service'` (`src/sdk/credential/types.ts:94`) — `'service'` is the exact term canon bans, and `Code` is absent. **Blocked on an owner ruling, not on engineering. Least reversible item in this document** | 17 |
| **B12** | **Agent lifecycle expiry sweep** | The AAP §5.4 state machine is specified and its register / status / revoke / reactivate transitions are built | Expiry is **stored and never enforced** — *"NOT enforced inside this service"* | 12 (part) |
| **B13** | **Payment rails 3–6** | The rail adapter interface is the spec, and the two live rails are the reference implementation | **2 of 6 real.** Stripe SPT / Solana / Lightning / Card are `StubAdapter` throwing `unimplemented()` (`src/sdk/payment/rails.ts:335,363-378`) | 21 |
| **B14** | **Registry coverage expansion** | Every stub returns a **typed cure** — the contract is specified per source | **6 real, 1 real-interim, 5 honest stubs** (NIPR PDB, NMLS, FL FLHSMV among them). **This is published as data via `GET /credentials/registries`, which is correct behaviour, not a defect.** A coverage backlog. NIPR PDB and NMLS are the two that would prove the runtime horizontal (§8 Q5) | 22 |
| **B15** | **`PRODUCT.md` at the repo root** | `vis/CONTEXT.md:1406` [RULED 2026-08-02]; §9 of this document is the drafted skeleton | Does not exist. **Q1 is ruled**; still blocked on Q2 (boundary) and Q9 (vacating the draft's `$id`) | 25 |

---

### S — NOT SCOPED

*Brainstormed in the vis repo or named in a session ruling. No spec, no ADR, no pinned requirement.
**These need scope work before they can become build work** — and until they do, they must not be
counted as engineering debt.*

| ID | Item | Where it was brainstormed | What is actually missing | was |
|---|---|---|---|---|
| **S1** | **Credential custody for legacy rails — AS2 certificates, SFTP credentials** | `vis/CONTEXT.md:1206`; claimed **in present tense** by `transactions.dev/PRODUCT.md:92` | No AS2, SFTP or certificate handling anywhere in `src/` or `worker/`. WorkOS Vault and Pipes are real and are **OAuth-era only**. **The highest-risk unscoped item**, because a sibling PRODUCT.md already sells it (§8 Q8) | 13 |
| **S2** | **Mobile app — wallet, agent-approval centre, scanner** | `vis/CONTEXT.md:885` — *"direction ruled 2026-08-01"*, a direction, not a spec | No repo anywhere in the estate; no Expo chassis. Carries the human face of the purpose statement's **wallet** clause | 16 |
| **S3** | **Chat-native grant flow** (the Slack / Teams ask) | `vis/CONTEXT.md:1206` | Zero code, no interaction spec. Pairs with B10 — the same ceremony in a different surface | 14 |
| **S4** | **ASN↔GLN crosswalk + CC BY projection** | `vis/CONTEXT.md:880` | No route, no dataset, no licence analysis. **This is the estate's one credible "standard" candidate** (§1) — scoping it is what would let the property claim the word | 15 |
| **S5** | **Auth + analytics as an embeddable SDK** ("the witness generalized") | `vis/CONTEXT.md:1359` — *"v1 dogfoods it"* | No spec, and no emitter to dogfood. Strictly downstream of B4 | 9 |
| **S6** | **Agent roster and governance at scale** as a product surface | Positioning A — *"authority is the business"* | No roster surface, no ceiling UI, no seat model. **The pricing half is already settled** (§4 rules the meter is verifications, connections and retained events — never per-agent seats); the product half is unscoped | 12 (part) |
| **S7** | **R2 cold storage for frozen tenants** | `README.md` claims *"30 days in R2"* | `POST /api/freeze` (`worker/routes/claim.ts:235`) marks tenant state and is built. **There is no R2 code and no R2 binding, and no retention spec exists.** The 30-day figure has no source | 19 |
| **S8** | **The papered vis dependency** | `vis/CONTEXT.md:1198` calls it *"papered"* | No paper, and no runtime binding at all. §6 sketches its shape — narrow: a commitment that the witness layer emits to vis's spine in a conformant shape, with identity and authority acknowledged as shared estate infrastructure. **A sketch, not a spec** | 27 |

---

### C — NOT A GAP: copy corrections

*These are not missing capabilities. They are sentences that must change — some because they are
present-tense-false, one because a ratified ruling governs the word, one because it is stale in the
direction of understatement.*

| ID | Correction | Fix | was |
|---|---|---|---|
| **C1** | **"An open identity standard for the agent era"** (`README.md:5`) and the vis roster row filing id.org.ai under *".org.ai = Standards"* (`vis/CONTEXT.md:831`) | Governed by the constitution, not by build state (§1). Strike from README; re-file the roster row. **[OWNER]** | 26 |
| **C2** | **README package tree and test count are stale** | `src/db/schema.ts` and Drizzle do not exist (storage is a `StorageAdapter`); the layout is `src/sdk/` + `src/server/`. The test count is **understated** — 72 files and ~2,076 assertions against a claimed 29 suites / 1,296 tests. *An honesty defect that undersells the property* | 28 |
| **C3** | **"30 days in R2"** (`README.md`) | Present tense for something with no code and no binding. Strike, or scope S7 and state it in future tense | 19 |
| **C4** | **"Connects — no auth"** (`README.md`) | Present tense for a surface that returns `-32001`. **The fix is D3 — ship the four-line ungate — not delete the sentence.** This is the model case for the whole revision | 6 |
| **C5** | **The pinned acceptance spec has never passed** — 39 requirements, digest `eaae6c2b…`, at least five failing on the deployed host today | **Reframed: this is not a gap, it is the scoreboard.** Its existence is the evidence that B3, B6, B7 and D3 are *scoped* rather than brainstormed. Treat a failing requirement as a ticket, not as a claim to retract | 24 |
| **C6** | **`docs/PRODUCT-approval-flows.draft.md` squats `$id: https://id.org.ai/product.md`** | The canonical product address cannot be held by a file marked *"nothing built, deployed, or filed."* Vacate and re-file as B10's roadmap (§8 Q9) | — |

---

### The correct future-tense sentences for the three most-claimed capabilities

These are **release-register statements**, not hedges. They state what the property does and what
ships; they narrate no build state, carry no date, and say "coming soon" nowhere.

- **Resolver:** *"A GS1-conformant Digital Link resolver ships on this property — `/01/{gtin}`,
  `/{grain}/{id}`, linksets and the conneg faces, free and keyless. It is specified in
  `org.ai ADR-0013` and `docs/adr/0001`."* On a surface that must disclose current state: *"`/01/{gtin}`
  does not resolve today."*
- **Spine emission:** *"Verification and authorization events are recorded in an insert-only audit
  log. Emission to the event spine — every act as an attested event — ships from that same path."*
- **Custody:** *"Third-party OAuth credentials are brokered and held (WorkOS Vault and Pipes). AS2
  certificates and SFTP credentials are not handled today; the legacy-rail custody surface is
  unscoped."*

---

## 8. OPEN QUESTIONS — owner rulings only

| # | Question | Why only the owner | Standing recommendation |
|---|---|---|---|
| **~~Q1~~** | ~~Ratify or reject the hero amendment.~~ | — | **✅ RULED 2026-08-03 — CLOSED.** The owner ruled **"Agent. Human. Identity."** with the subline *"The who layer — for whoever acts, and whatever they act on,"* amending `vis/CONTEXT.md:1314`. This document's proposed verb triad was **not** adopted as the hero and is **retained as the approved differentiator subline**. Of this document's arguments: the **Thing objection was upheld and strengthened** — the decisive reason is that Thing was never a peer of Agent and Human and the triad claimed *another property's grain*, not that it 404s; the **CIAM objection stands and is recorded** — it is answered by the subline, not overruled, and it hardens into a standing rule that *Identity never ships bare*; **Code stays a developer detail**; and the build-state legs are struck. Screen 4 is adopted with it. See §2, and §Q13 for the one remaining open piece. |
| **Q2** | **Ratify the free/paid boundary amendment.** `vis/CONTEXT.md:1200-1204` says the witness is never paywalled **and** that you pay to prove things to third parties. | Two halves of one ratified sentence contradict; the code already prices a verdict. | **Adopt §4:** emission free forever and unmetered; the *verdict* priced. If even the verdict must be free, there is no business in the model — the verdict is the only thing anyone has agreed to pay for. |
| **Q3** | **Settle the identity-class enum before any spine event carries a `who` grain.** Shipped: `'human' \| 'agent' \| 'organization' \| 'service'`. Canon: Human, Agent, Code. | This is the **least reversible item in the document** — every vis event's `who` grain depends on it, and changing it after the spine ships is a data migration across the event lake. | **Ship `'human' \| 'agent' \| 'code'`.** Organization does not *act*, it *grants* — an authority-layer construct that leaked into an identity-layer enum, where it already lives correctly as the WorkOS org, FGA subject and billing unit. `'service'` is a deployment location, not an answerable principal, and is the exact word canon bans. **Additionally ship the orthogonal, additive `pattern: deputized \| self-principal` (`org.ai ADR-0012 M6`, already ratified)** — it is the axis that actually changes agent behaviour, and it can land without waiting on the enum. |
| **Q4** | **Fix keyless MCP `tools/list`, or amend the pinned spec.** | It breaks a RATIFIED vis law and this repo's own pinned requirement; leaving it split is the only illegal option. | **Fix it** per §3's layer-face rule, with the L0 rate limit that is already defined. *Unless the 401 is a deliberate MCP-client-compatibility workaround — in which case record that and amend `A-mcp-keyless-tools-list`.* |
| **Q5** | **Is the credential-verification runtime a door on this property, or a separate property?** It is the only module with no upstream vendor, the only one carrying a real price, and its subject is a *third party* rather than the arriver — a different question, a different budget (KYB / vendor qualification), a different buyer. | It decides whether the `[C]` alternative hero is ever live, and whether a second brand is minted. | **Keep it as Door 4 on this property for now, and export `./credential` this week regardless.** Revisit when NIPR PDB and NMLS land — those two are what would prove the runtime is horizontal rather than an auto-dealer vertical feature. |
| **Q6** | **Ratify the precedence order** (§6): constitution → property offer → consuming-family canon. | Two RATIFIED canons in two repos assign the same property and neither cites the other. | **Adopt.** It settles the standard/service question from a ruling already on the books, with no new decision. |
| **Q7** | **Reconcile the LICENSE copyright line.** It reads `headless.ly`, a venue, against the constitution's *"venue names are leases; identity never lives on them."* | Legal / entity assignment. | Reconcile to the owning entity **before** any offer ships. It is the first file a security or vendor reviewer opens. |
| **Q8** | **Amend the five vis PRODUCT.md files** from ownership to dependency, and remove the two present-tense claims that are false at the URL (resolution; AS2/SFTP custody). | Those files are outside this document's write scope and other agents are active there. | Do it in the same sweep as Q1, so the family's copy and this property's copy never disagree in public. |
| **Q9** | **Vacate `$id: https://id.org.ai/product.md` from the Handoffs draft**, or promote the draft. | The canonical product address cannot be held by a file marked *"nothing built, deployed, or filed"*. | **Vacate and re-file** as the authority layer's ceremony roadmap. Promoting it makes three unbuilt things P0 — spine emission, Mandate persistence, and the approval surface — which is the furthest-from-shipping option on the board. |
| **Q10** | **Where does the id.org.ai `entry_verb` view for the agent-class enumeration live?** `vis/CONTEXT.md` §4.0 is the single `AGENT_CLASSES` enumeration and V17a fails the build on a second copy — but its `entry_verb` column is EPCIS-shaped (`translate`, `trace_epc`, `get_event`) and cannot serve this property. | Cross-repo enumeration ownership. | Either §4.0 gains an id.org.ai `entry_verb` view over the same five row ids, or the enumeration is lifted to the estate and both properties publish subsets by id. **Writing an `AC-*` array into this repo is the exact drift §4.0 was rewritten to end.** |
| **Q11** | **Does id.org.ai publish a specification others implement — i.e. is "standard" restored to the message?** §1 keeps the word out, but on a *constitutional* ground (`org.ai/CONTEXT.md`: *"id.org.ai is .do-layer work on an .org.ai name"*), never on a build-state ground. It is the one item the prior pass removed that survives the correction, and the owner named it. | Amending the constitution's ruling on the property's **nature** — the one thing §6's precedence order makes superior to this document. | **Keep it out until a spec document and one external implementer exist — and scope the spec, because two credible candidates already sit in the estate.** The **ASN↔GLN CC BY crosswalk** (`S4`) is the strongest: a dataset projection under an open licence that another party could implement against. The **39-requirement pinned acceptance spec** (`specs/axp-acceptance.spec.json`, digest `eaae6c2b…`) is the second: a conformance surface with a digest, already written. *If the owner intends "standard" to be true, `S4` moves from unscoped to P1 and the word follows the spec — not the other way round.* |
| **Q12** | **Confirm the `id.org.ai` zone move to `workers.do` (Enterprise).** `worker/wrangler.jsonc` still pins `id.org.ai/*` to `zone_name: "id.org.ai"` while two sibling hostnames on the same worker already route through `workers.do`. | Cloudflare account/zone administration is an owner action, and it gates the serving substrate for the entire free read face. | **Move it, and move it first.** `vis/CONTEXT.md:931` rules nothing serves from a Free-plan zone; Snippets — the mechanism that makes every read-face GET cost nothing — ride the enterprise zone. Building B1/B2/B3/B6/B7 before the move builds them onto the wrong substrate. **[OWNER]** |
| **Q13** | **Word order in the ruled hero — `Agent. Human. Identity.` or `Human. Agent. Identity.`?** The ruling records **agent-first**; the repo ships **human-first** today (`APP_TAGLINE`, `site/components/auth-hero.tsx:48-51`, and a third variant — *"humans, agents, organizations"* — in `/.well-known/agent-configuration`). **The noun set is ruled and closed; only the order is open.** | It is a positioning call, not an engineering one, and it may legitimately **differ by door** — §5 already rules the property has a machine face and a human face bifurcated by `workerType` under **AL-4**. | **Agent-first as the default, and treat per-door variance as legitimate rather than as drift.** Two arguments for agent-first: every incumbent IdP leads with humans, so agent-first is the more distinctive claim and the one that does not read as the CIAM default; and it matches the register of the arrival that this property actually serves without a human in the loop. The argument for human-first is that *"agent"* reads as jargon to a supply-chain executive, which is a real risk on the commercial surfaces. **The natural split, if the owner wants one: agent-first on the `.dev` and machine surfaces (Door 1, Door 2), human-first on the commercial ones (Door 3, Door 4, visibility.cloud).** Whichever way it goes, it must be ruled once and applied to all three live variants in the same sweep — the current three-way disagreement is the actual defect. **[OWNER — do not resolve without a ruling; `APP_TAGLINE` is blocked on this and on nothing else.]** |

---

## 9. PRODUCT.md — skeleton

**Destination:** `/Users/nathanclevenger/projects/id.org.ai/PRODUCT.md`, published at
`https://id.org.ai/product.md`. Layer-1 conformant to the product.md spec; house format follows
`vis/docs/product/epcis.dev/PRODUCT.md`.

**Not yet written to that path.** **Q1 (the hero) is now RULED** and no longer blocks it; it requires
Q2 (boundary) and Q9 (vacating the draft's `$id`), and its copy carries the ruled hero of §2 with a
subline (Q13 governs word order only). Every price below is a **placeholder marked as such and must never publish as-is**.

**Register discipline in this file:** *Product Purpose* opens with the full purpose statement (§1) —
that paragraph is timeless and carries the whole layer. The paragraphs after it are the per-surface
gate at work: **"Live today, in production"** is the present-tense inventory, **"Shipping next"** is
explicit future tense. Neither hedges, neither carries a date, and neither says "coming soon."

---

```markdown
---
$id: https://id.org.ai/product.md
$type: Product
$context: https://schema.org.ai
productmd: 1
register: product
---

# Product

## Register

story  <!-- the human face; the SPEC face is /.well-known/agents.json + /openapi.json, unbuilt -->

## Users

Product and platform engineers embedding sign-in, agent identity, and authorization into an
application they own — typically 1–50 engineers, with an enterprise prospect asking for SSO or a
sprint where auth work displaced the roadmap. They evaluate by running a command, not by taking a
call, and they disqualify on a broken quickstart faster than on price.

Agents are first-class arrivals at this surface and this file is written to be read by them: an
agent registers a client, provisions a workspace, obtains keys, and uses the free tier with no human
in the loop. `POST /oauth2/register` and `POST /api/provision` both accept a credential-free request
today.

## Product Purpose

id.org.ai is the estate's *who* layer: it resolves any address to what it names, issues and holds the
keys that humans, agents and code act with, bounds what those keys may do, witnesses every act they
take, and answers — from the source of record — whether they are still allowed to.

Live today, in production: a full **OAuth 2.1 authorization server** (authorization code with PKCE
S256, refresh, introspection, revocation, device flow, dynamic client registration, consent),
**OIDC discovery with JWKS and 90-day signing-key rotation**, **human authentication via WorkOS
AuthKit** (SSO, social, sessions, organizations, invitations, admin portal), **agent identity** as
Ed25519 keypairs with `did:agent:ed25519:` addresses and a first-class agent record supporting
register / status / revoke / reactivate, **the better-auth Agent Auth Protocol at its wire**,
**scope-shaped API keys** with rate limits and delegated mint under an authority ceiling,
**tenant-isolated secret custody and brokered third-party OAuth connections** (WorkOS Vault and
Pipes), an **insert-only audit log**, and a **primary-source credential-verification runtime** that
checks a party's licence or registration against the issuing authority and returns a verdict that
never collapses "licensed" with "in good standing," fails typed when the answer is stale, and never
accepts holder-attested evidence for an act-class check.

Distributed as an npm package with a React SDK and a CLI, and deployed as a service.

Shipping next, stated in the future tense until live: the **read face** — a GS1-conformant Digital
Link resolver, the who-address grammar, keyless MCP discovery, and the machine-face documents
(`/llms.txt`, `/.well-known/agents.json`, `/icp.json`, OpenAPI). Then the **authority objects** —
Mandate, Representation and GrantEdge, with a spend ceiling and an approval ceremony. Then
**emission to the event spine**, so an act performed under conferred authority lands as an attested
event.

## Brand Personality

Engineer-literal and audit-proof. Proof is a status code, a published rotation cadence, a pinned
discovery document, a typed verdict — show the artifact, skip the adjective. Present tense only for
what answers at the URL today; explicit future tense for everything else. Gaps are published as
data, not hidden: the registry roster names its own stubs.

## Anti-references

- No "the identity platform for humans and AI agents." Two funded competitors ship that sentence.
- No "open identity standard." This is a managed service that implements other people's standards.
- No **taxonomy** as a headline — no publishing the class enum ("Agents. Humans. Code."). A directory
  schema is not a headline. *The ruled hero is not one: two act-grains plus the layer's category noun.*
- **Never ship *Identity* bare.** The hero always carries one of the two approved sublines — the
  who-layer subline or the differentiator subline. Three nouns alone is the CIAM default (§2).
- No "Contact us," anywhere, at any tier.
- No docs behind a lead form, and no capability claimed **in present tense** that returns 404.
- **No hedges and no build-state prose, in either direction.** Not "coming soon," not "will be X
  once Y," not "under test" — and equally, never solve an overclaim by deleting the capability from
  the property's purpose. State it in future tense and ledger the gap.

## Design Principles

1. **Evaluated by curl.** Every claimed capability is demonstrable from a terminal in one command.
2. **Machine-legible negative capability.** What is unavailable is declared as a typed null in the
   same schema as what is available. An agent never 404s its way through discovery, and never has to
   ask a human what it may do or what it costs.
3. **Gate by layer, not by endpoint.** Reading what an address affords is always free and keyless.
   Changing state is always gated.
4. **Free to emit, paid to be believed.** Self-directed acts are free forever; you pay when we spend
   a relationship with a third party on your behalf.
5. **One address, three faces:** HTML, JSON, and markdown, selected by content negotiation.

## Accessibility & Inclusion

WCAG 2.2 AA on the site. Full function without color; honors prefers-reduced-motion and
prefers-color-scheme; keyboard-reachable everything. Machine readers are included by design: every
documented address serves a machine face alongside HTML.

## Offer

Self-serve at every tier. The CTA everywhere is **Get started**.

- **Free** — the authorization server, human and agent authentication, dynamic client registration,
  keyless provisioning, key issuance, the audit log, and registry-mode credential checks, at a
  disclosed volume. Dereference and discovery join the free tier when the read face ships, and are
  free permanently thereafter.
- **Paid** (published price, self-serve, card) — primary-source verification at
  **$2.50 per check** *(shipped price; a pricing pass is pending and this number is subject to it)*,
  with a free registry-mode alternative offered in the same 402. Higher volume, durable statefulness,
  and witness retention and query at scale: **$TBD — placeholder, pricing pass pending, never
  publishes as-is.**
- **Enterprise** — SSO/SAML/OIDC connections, SCIM directory sync, domain verification, MFA and
  session policy, FGA at org scale, audit-log export and SIEM streaming, admin portal, IP
  allowlisting, data residency, legal hold, a customer-operated resolver hostname, and the contract
  ceremony. The feature table publishes; **the number is the only one deliberately absent.**

## Boundaries

- **Not a standard.** A managed service on an `.org.ai` name that implements other people's
  standards — AAP at its wire, OAuth 2.1 and OIDC, and the MCP authorization profile.
- **Not an enrichment layer.** Barcode reading, generation, labels, serials and product data belong
  to barcoding.dev; this property consumes that data to resolve, and builds none of it.
- **Not an event store.** Events are stored and served by epcis.dev; this property attests and
  emits.
- **Not a dashboard.** Traces, grants, seats and the commercial layer are visibility.cloud's.
- **The object grain is resolved here, never attested here.** A pallet can be dereferenced; it
  cannot hold authority and cannot be answerable for an act.

## Stack

- epcis.dev: the event spine — capture, query, the catalog
- barcoding.dev: the codec and enrichment layer this property resolves against
- transactions.dev: the business-document layer
- visibility.cloud: the UI and commercial layer over all four
- WorkOS: human authentication, FGA, Vault and Pipes underneath this property
```

---

## 10. THE BACKLOG

§7 classified the gap. This section orders it **by what unblocks the most**, ready to become issues on
`dot-do/vis`. Three kinds of work, and they are not interchangeable: **deploy work** ships something
that already exists, **build work** needs an engineer against an existing spec, **scope work** needs a
ruling before an engineer can start.

### Settle this before anything downstream of it — the least reversible item on the board

> **Q3 — the identity-class enum.** Shipped: `'human' | 'agent' | 'organization' | 'service'`
> (`src/sdk/credential/types.ts:94`). Canon: Human, Agent, Code. `'service'` is the exact term canon
> bans; `Code` is absent.
>
> **Every vis spine event's `who` grain depends on this enum, and changing it after the spine ships
> is a data migration across the event lake.** It is not expensive to decide and it is very expensive
> to decide late. **It must settle before B4 (spine emission) writes its first event** — that is the
> real dependency edge, not a calendar date.
>
> Standing recommendation (§8 Q3): ship `'human' | 'agent' | 'code'`. Organization does not *act*, it
> *grants* — an authority-layer construct that leaked into an identity-layer enum, where it already
> lives correctly as the WorkOS org, the FGA subject and the billing unit. Additionally ship the
> orthogonal, additive `pattern: deputized | self-principal` (`org.ai ADR-0012 M6`, already ratified),
> which can land without waiting on the enum. **[OWNER]**

### P0 — deploy work: code that exists and is not serving

*Ordered by what each unblocks. Every one of these is measured in lines, not sprints.*

| # | Item | Kind | Unblocks |
|---|---|---|---|
| 0 | **H1 — roll out the ruled hero** across `site/components/auth-hero.tsx:48-51`, `README.md:1-5`, `/.well-known/agent-configuration`, and `worker/wrangler.jsonc` `APP_TAGLINE` | copy + code — **ruled, not proposed** | The one item here that is already decided (§2, [OWNER] 2026-08-03). Three surfaces currently ship **three different noun sets**, none of them the ruled one. **The hero never ships bare** — every surface carries the who-layer subline or the differentiator subline. **`APP_TAGLINE` alone waits on §8 Q13 (word order); the other three do not**, since they can carry the ruled nouns in the ruled order and be re-ordered in the same sweep if Q13 goes the other way. |
| 1 | **D1 — move `id.org.ai/*` onto the `workers.do` Enterprise zone** (§8 Q12) | deploy **[OWNER]** | **The entire free read face.** Snippets are unavailable off the Enterprise zone, and every unbuilt read-face item is exactly the Snippet-native class. This is the substrate B1, B2, B3, B6 and B7 build onto — doing it after them means building twice. Also inherits Bot Management and the rest of the Enterprise entitlements. |
| 2 | **D2 — export `./credential`, `./payment`, `./audit`** from `package.json` | deploy (one config line) | The most differentiated module in the repository, currently importable by nobody. Gates the `[C]` alternative hero entirely (§5), and it is a present-tense verifiable claim requiring no promise about anything unbuilt. |
| 3 | **D3 — ungate keyless MCP `initialize` + `tools/list`** | deploy (≈4 lines at `mcp.ts:240`/`:265`) | Clears a **live conformance failure against a RATIFIED vis law** (the agent-self-service law) and this repo's own pinned `A-mcp-keyless-tools-list`. The L0 tools are already built and already unreachable; the correct per-tool gate already exists at `:335` and `RATE_LIMITS[0]` is already defined. Also makes README's *"Connects — no auth"* (C4) true instead of deleted. |
| 4 | **D6 — wire a route to SCIM directory sync** | deploy | An Enterprise-tier line item that cannot be sold because nothing dispatches to it. |
| 5 | **D4 — register the Entra app and set `MICROSOFT_CLIENT_ID`** | deploy **[OWNER]** | Upstream Microsoft federation, built and failing soft today. |
| 6 | **C1 · C2 · C3 — the copy corrections** | copy **[OWNER on C1]** | C1 strikes *"an open identity standard"* and re-files the vis roster row (constitutional, §8 Q11). C2 fixes a README that **understates** the property. C3 removes *"30 days in R2"*, which has no source. |

### P1 — build work: scoped, needs an engineer

| # | Item | Spec that already exists | Note |
|---|---|---|---|
| 7 | **B3 — the machine face**: `/llms.txt`, `/.well-known/agents.json`, `/icp.json`, root markdown conneg | nine pinned requirements in `specs/axp-acceptance.spec.json` | Stateless GETs, Snippet-native, no secrets and no state machine. **The cheapest differentiated work on the board.** Do it immediately after D1. |
| 8 | **B1 + B2 — the resolver and the who-address grammar** | `org.ai ADR-0013` **RATIFIED**; `id.org.ai/docs/adr/0001` | The one-resolver ruling is architecturally correct and its execution is the estate's largest open commitment. Five sibling `PRODUCT.md` files depend on it (§8 Q8). Also stateless GETs. |
| 9 | **B6 + B7 — OpenAPI 3.1, RFC 9264 linkset, the conneg matrix** | pinned `B-openapi-published`, `B-openapi-31-honest`, `B-linkset`; ADR-0001 D2 | Completes the read face and moves the pinned spec (C5) toward green. |
| 10 | **B9 — stop asserting `autonomous`, or derive it** | `org.ai ADR-0012 M7` | **P0 by honesty, P1 by effort.** A live honesty defect in a machine-readable document, in SPEC register, where no story softens it. Until B8 lands, either derive from `ScopeGrant` or withdraw the mode from `/.well-known/agent-configuration`. |
| 11 | **B4 + B5 — spine emission** | `vis/CONTEXT.md:1197` [RULED]; event shape scoped vis-side | **Gated on Q3.** Additive at the top of the existing audit path: bind Pipelines, emit from the path that already writes the insert-only log, break none of the eleven runtime consumers. §6 predicts this is checkable in advance — if nothing in the shared layers has to change, the layer separation is real. |
| 12 | **B8 — `Mandate` / `Representation` / `GrantEdge`** | `org.ai ADR-0012`, nine merged rulings | The authority layer's missing objects. `ScopeGrant` already ships the may-do reach under a different name; the missing piece is named in its own source comment — the *"spend-ceiling/Mandate persistence primitive."* Unblocks B9, B10 and the §4 Enterprise story. |
| 13 | **B11 — ship the corrected identity-class enum** | §8 Q3 | Mechanical once Q3 rules. |
| 14 | **B15 — write `PRODUCT.md` to the repo root** | §9 skeleton; `vis/CONTEXT.md:1406` [RULED] | Blocked on Q1, Q2 and Q9 (C6 — vacating the draft's `$id`). |
| 15 | **B10 — the deputization / engagement approve-deny surface** | draft-level only (`docs/PRODUCT-approval-flows.draft.md`) — **promote the draft to a spec first** | Opens Door 3, which §5 rules stays shut until then. |
| 16 | **B12 · B13 · B14** — the expiry sweep, payment rails 3–6, registry coverage | AAP §5.4; the rail adapter interface; the typed-cure contract | B14 is a coverage backlog, not a defect — the roster publishes its own stubs as data, which is correct. NIPR PDB and NMLS are the two that would prove the credential runtime horizontal (§8 Q5). |

### P2 — scope work: brainstormed, needs a ruling before an engineer

| # | Item | Why it is next | Note |
|---|---|---|---|
| 17 | **S1 — legacy-rail custody (AS2 certificates, SFTP credentials)** | **Highest-risk unscoped item.** `transactions.dev/PRODUCT.md:92` sells it in present tense today (§8 Q8) | WorkOS Vault and Pipes are real and OAuth-era only. Either scope it or correct the sibling copy — leaving both is the only illegal option. |
| 18 | **S4 — ASN↔GLN crosswalk + CC BY projection** | It is the estate's one credible **"standard"** candidate (§8 Q11) | Scoping this is what would let the property claim the word. Needs a dataset plan and a licence analysis. |
| 19 | **S6 — agent roster and governance at scale** | *"Authority is the business,"* and the meter is already ruled | §4 settles the pricing half (verifications, connections, retained events — never per-agent seats). The product half is unscoped. |
| 20 | **S2 — the mobile app**: wallet, agent-approval centre, scanner | Carries the human face of the purpose statement's **wallet** clause | A direction was ruled 2026-08-01; no repo exists anywhere in the estate. Pairs with B10 and S3 — one ceremony, three surfaces. |
| 21 | **S3 — the chat-native grant flow** (Slack / Teams ask) | Same ceremony as B10 and S2 | Scope all three together or the approval surface forks. |
| 22 | **S7 — retention and cold storage for frozen tenants** | `README.md` already claims *"30 days in R2"* (C3) | Freeze is built; retention has no spec, no code and no binding. |
| 23 | **S8 — the vis dependency paper** | `vis/CONTEXT.md:1198` calls it papered; it is a sentence | §6 sketches the narrow shape: witness-emission conformance only, with identity and authority acknowledged as shared estate infrastructure carrying no vis-specific obligation. |
| 24 | **S5 — auth + analytics as an embeddable SDK** ("the witness generalized") | Strictly downstream of B4 | There is no emitter to dogfood until B4 ships. Do not scope before then. |

### The two entanglement items, from §6

- **`explore` describes a fixed 32-entity headless.ly CRM catalog.** Change it to describe *the
  caller's capability surface*. Additive, independently correct, no second tenant required — do it
  alongside D3, since both live in `worker/routes/mcp.ts`.
- **The FGA schema hardcodes 35 headless.ly CRM resource types.** Make the resource-type registry
  tenant-supplied. **Gate this on a second real tenant** — it is the more expensive half and it buys
  nothing until someone else is standing on it.

### Also open, and owner-gated

**Q7 — the LICENSE copyright line** reads `headless.ly`, a venue name, on the estate's identity
property, against the constitution's *"venue names are leases; identity never lives on them."*
Reconcile to the owning entity **before any offer ships**; it is the first file a security or vendor
reviewer opens. **[OWNER]**

---

## 11. The one-paragraph summary

id.org.ai is the estate's *who* layer — resolution, issuance, custody, authority, witness and the
verdict — and it is today a substantially complete, well-tested, deployed OAuth 2.1 + WorkOS +
agent-protocol service carrying a genuinely differentiated primary-source credential-verification
runtime, with the resolver and the witness scoped and unbuilt. **That is a backlog, not a smaller
product.** It has three doors' worth of built product and is showing none of them: the developer door
is complete and carries all eleven real consumers, and is not what the home page says; the verdict
door is the only differentiated module and the only real price, and is not exported from the package;
the machine face is what the README is entirely about, and four of its five surfaces 404. The fix is
not a rewrite and it is not a retraction. It is: ship the ruled hero (§2), move the zone (§10 D1), export
one module (§10 D2), ungate one boundary (§3, §10 D3), settle the enum before the spine writes its
first event (§8 Q3), state one price rule (§4) — and build the rest of the sentence rather than
shortening it.
