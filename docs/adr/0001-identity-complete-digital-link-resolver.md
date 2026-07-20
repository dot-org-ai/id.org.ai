# ADR 0001 — Building the identity-complete Digital Link resolver

**Status:** PROPOSED
**Deciders:** Nathan Clevenger
**Date:** 2026-07-20
**Binds to:** **org.ai ADR 0013** (the constitutional *what/why*: the GS1/EPCIS superset and the Who) and **org.ai `docs/annexes/RESOLVER.md`** (the resolver contract, AMD-2). This ADR is the *how* — the id.org.ai build. The seam grammar is owned upstream; changes to it are made in org.ai, not here.
**Composes with:** org.ai ADR 0012 (the resolved principal is a `human_…`/`agent_…`; its authorization is a `Scope` at a tier — the `CapabilityLevel` realign), and the existing `AuthBroker` (`src/sdk/auth/broker.ts`, `broker-impl.ts`).
**GS1 conformance target:** the GS1-Conformant Resolver Standard; GS1 Digital Link URI Syntax (AI `01`=GTIN, `21`=serial); RFC 9264 Linkset. Verified 2026-07-20.

## Context

org.ai ADR 0013 rules that id.org.ai is *the* GS1 Digital Link resolver, that the resolver is the GET face of the authority membrane, and that — because it is the identity layer — it supplies the authenticated **Who** that completes EPCIS's 5W+H (the delta `id.gs1.org` structurally cannot provide). This repo currently has **no resolver code** (greenfield). This ADR records how we build it without contradicting the identity/auth model already shipped (the `AuthBroker`, `CapabilityLevel`, the AAP `Agent`/`Host` split, the claim-by-commit flow).

The one non-obvious build fact: **we already have the Who.** `AuthBroker.identify(req)` (`broker-impl.ts:276`) resolves the principal from any request's credential, returning the L0 anonymous identity when none is presented and never throwing. The resolver does not need a new identity mechanism — it needs to route GS1 keys through the broker and attach the resolved principal to the staged/captured event.

## Decision

### D1 — One resolver route, two id forms

A new worker route (`worker/routes/resolve.ts`) owns `GET` for both id grammars, dispatched by shape:
- **`/{type}_{sqid}`** — the existing typed-sqid identity IRI (RESOLVER.md §1–2). Unchanged behavior.
- **`/01/{gtin}[/21/{serial}]`** (and further GS1 AIs as trailing path/query) — the **GS1 Digital Link path form** (org.ai ADR 0013 R2), parsed per the GS1 URI Syntax. Presence of AI `21` selects **instance** grain (SGTIN → G5/Tier-3 object); its absence selects **class** grain (GTIN → the product's dimension entry) — ADR 0013 R7.

Parsing is GS1-conformant: unknown AIs are tolerated, the primary key is the leftmost, and the compressed/uncompressed forms both resolve.

### D2 — Content negotiation & `linkType` (delegate to the contract)

Behavior is exactly RESOLVER.md §2–3 — implemented here, ruled there:
- default (`text/html`) → **303** to the primary surface; for a GS1 class key with no override, the default is GS1's **`gs1:pip`** (product-information page).
- `application/ld+json` / MDX → **200** identity/product document (`$context: https://schema.org.ai`, tier rules §4).
- `?linkType=linkset` **or** `Accept: application/linkset+json` → **200** RFC 9264 linkset; **no redirect** (GS1-conformant). `?linkType=all` → the same linkset (GS1 convention).
- `?linkType=<lens>` → the R13 lens taxonomy (`identity`/`scope`/`representation`/`redirect`/`action`), plus GS1 linkTypes (`gs1:pip`, …) served from the object's registered links.

### D3 — The Who wiring (GET stages, POST captures)

- **GET is resolution + staging** (ADR 0013 R4). The route calls `AuthBroker.identify(req)` → the resolved principal (`human_…` / `agent_…`, or L0 anonymous). It returns the negotiated lens **and** stages a candidate EPCIS event carrying `Who = <principal>` (or `Who` **absent** when anonymous — the existence-neutral gate, RESOLVER.md §4). A GET never writes G5.
- **POST is capture.** A separate `POST` capture endpoint mints the EPCIS event: it re-gates via `AuthBroker.gate(req, need)`, sets `Who` to the attested principal, stamps the CBV `bizStep`/`disposition` (supply-chain verbatim; consumer/agent scans take the ADR 0013 R6 extension verbs `inspecting`/`verifying`), and writes it as a CBV-typed event into the **object's owning startup's G5 books** (org.ai R17), membrane-governed.
- The `Who` is a first-class principal ref, **not** an EPCIS party string. At the EPCIS-emit seam it degrades to EPCIS's party fields (ADR 0013 R1, lossy downward); natively it is retained whole. An `agent_…` Who is a native superset case EPCIS never modeled.

### D4 — The membrane is preserved, not re-implemented

G5 dereference stays gated and existence-neutral (RESOLVER.md §4) via the *same* `AuthBroker.gate` path used everywhere else — the resolver adds no second auth story. Class-grain (GTIN) product pages are public and cacheable; instance-grain (SGTIN) scan records sit behind the gate. `?linkType=scope` at a venue may 404 at that surface without denying existence (a lens fact, R13).

### D5 — The EPCIS 2.0 seam surface

Expose a conformant EPCIS 2.0 capture/query interface (the machine face that **epcis.dev** — the B2A/B2D lens — and **visibility.cloud** — the B2B lens — consume, org.ai ADR 0013 blast radius). Capture accepts standard EPCIS documents (inbound scans from stock systems) and our native-superset events alike; query returns valid EPCIS. Conformance is the floor (ADR 0013 R1): a stock EPCIS client never sees our extensions unless it asks.

### D6 — Authorization vocabulary aligns to ADR 0012

The resolved principal's authorization to capture (and to see private lenses) is a **`Scope`** at a tier — not a `Capability`. This is the id.org.ai side of ADR 0012 M5: the `CapabilityLevel` access-tier and the `Agent.capabilities: string[]` grant-names realign to the scope/tier vocabulary (`Identity.scopes`, which `AuthBroker.check()` already consumes). The realignment is additive and rides the queued FGA migration (id-lkj) — see ADR 0012's id.org.ai blast-radius; the resolver is a *new* consumer, so it adopts the target vocabulary from day one rather than inheriting the old field name.

## Consequences

- **Sunrise 2027 readiness is a build target, not a slogan.** A brand pointing its 2D Digital Link at id.org.ai gets identity-complete resolution the day the resolver ships; the differentiator over `id.gs1.org` is structural (D3).
- **No new identity surface.** The resolver is a route over the existing `AuthBroker` + membrane; it introduces the GS1 path grammar and the EPCIS seam, nothing else in the auth model.
- **Greenfield, so vocabulary-clean from day one** (D6): the resolver names authorization `Scope`, never `Capability` — it never carries the legacy field, so its half of the ADR 0012 realignment is free.
- **Conformance tests are the acceptance bar.** The GS1-Conformant Resolver Standard's test vectors + RESOLVER.md's worked examples (`startup_xioNCf7…`, the pharma SGTIN `01/00840034001234/21/A1B2C3`) are the resolver's regression suite; an implementation that fails a row fails the ADR.
- **Open (upstream):** the attested-dereference credential + caching for a private-lens G5 scan (org.ai docket 9.6); the final CBV-extension verb names (org.ai ADR 0013 R6). Both finalize in org.ai; this build follows.
