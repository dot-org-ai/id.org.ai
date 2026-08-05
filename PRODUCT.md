---
$id: https://id.org.ai/product.md
$type: Product
$context: https://schema.org.ai
productmd: 1
register: brand
---

# Product

**Package `id.org.ai@0.3.1` — pre-1.0.** Breaking changes to the package surface are possible and
land in the changelog. The wire surfaces are the stable half: OAuth 2.1, OIDC discovery, JWKS and
the AAP agent-configuration document are pinned by the standards they implement, and eleven runtime
consumers already depend on them.

Every present-tense sentence in this file was verified against `https://id.org.ai` on 2026-08-05 by
live request; the status codes are quoted where they carry weight. Everything not yet answering at
the URL is stated in **explicit future tense**. Prices marked `$TBD` are placeholders and **must not
publish as-is**; the one real number below is the one already charged in code.

## Register

brand

<!-- `brand` on the product.md axis is the estate's STORY register (AL-4): the persuading, human
     face. The SPEC face — /.well-known/agents.json, /icp.json, /openapi.json — is future work and
     will carry `register: product` when it ships. One live value per surface. -->

## Users

**The product or platform engineer embedding sign-in, agent identity and authorization into an
application they own.** Typically a team of 1–50 engineers, with an enterprise prospect asking for
SSO or a sprint where auth work displaced the roadmap. They evaluate by running a command, not by
taking a call, and they disqualify on a broken quickstart faster than on price. Two colleagues read
this surface beside them — the engineering manager who owns the sprint, and the security or
architecture reviewer who opens `LICENSE` and the discovery documents first.

**Agents are first-class arrivals here, and this file is written to be read by one.** An agent
registers a client, provisions a workspace, obtains keys and uses the free tier with no human in the
loop and no card. `POST /oauth/register` returns **201** with a real `client_id` to a credential-free
request; `POST /api/provision` returns **201** with a tenant, a session token and its published
limits. There is no "contact us" path at any tier and there is no human in any entry path.

A third arrival exists and is served rather than sold to: **the relying party that must know a
counterparty's standing** — a compliance or vendor-qualification lead who does not want an identity
system and wants one answer about somebody else. They meet `POST /credentials/verify` and the
published registry roster.

## Product Purpose

id.org.ai is the estate's *who* layer: it resolves any address to what it names, issues and holds
the keys that humans, agents and code act with, bounds what those keys may do, witnesses every act
they take, and answers — from the source of record — whether they are still allowed to.

**Live today, in production.** A full **OAuth 2.1 authorization server** — authorization code with
PKCE S256, refresh, introspection, revocation, device flow, dynamic client registration and consent —
with **OIDC discovery, JWKS and 90-day signing-key rotation** (`/.well-known/openid-configuration`,
`/.well-known/oauth-authorization-server` and `/.well-known/jwks.json` each answer **200**).
**Human authentication is WorkOS** — this property is a custom WorkOS domain, every authenticated
human is a WorkOS user, and SSO, social login, sessions, organizations, invitations and the admin
portal are WorkOS's; the authority layer sits above it, never instead of it. **Agent identity** ships
as Ed25519 keypairs with `did:agent:ed25519:` addresses and a first-class agent record supporting
register, status, revoke and reactivate, speaking the **better-auth Agent Auth Protocol** at its
wire (`/.well-known/agent-configuration` answers **200**). **Scope-shaped API keys** carry rate
limits and delegated mint under an authority ceiling. **Secret custody and brokered third-party OAuth
connections** are tenant-isolated, on WorkOS Vault and Pipes. An **insert-only audit log** records
every verification and authorization decision. And a **primary-source credential-verification
runtime** checks a party's licence or registration against the issuing authority and returns a
verdict that never collapses *licensed* with *in good standing*, fails typed when the answer is
stale, and never accepts holder-attested evidence for an act-class check.
`GET /credentials/registries` answers **200** and publishes each adapter's `status`, including its
own gaps: six real sources, one interim, five declared stubs.

Distributed as an npm package with a React SDK and a CLI, and operated as a service.

**Shipping next.** The **read face** — a GS1-conformant Digital Link resolver (`/01/{gtin}`, the
who-address grammar `/{grain}/{identifier}`, RFC 9264 linksets and the content-negotiated faces),
keyless MCP discovery, and the machine-face documents `/llms.txt`, `/.well-known/agents.json`,
`/icp.json` and OpenAPI 3.1. It is specified in `org.ai ADR-0013` (ratified) and `docs/adr/0001`,
and it ships **free and keyless, permanently**. *On a surface that must disclose current state:
`/01/{gtin}` and `/humans/{id}` return 404 today.* Then the **authority objects** — Mandate,
Representation and GrantEdge (`org.ai ADR-0012`), with a spend ceiling, an approval ceremony
delivered over browser, terminal, link and push, and pre-approved standing envelopes so approval
volume does not scale with agent count. Then **emission to the event spine**: the audit log is the
event source, and every act performed under conferred authority lands as an attested event on
epcis.dev's one write door. Then **`forget(subject)`** — this property is the estate's single point
of erasure, and a subject's deletion renders every downstream pseudonym permanently unresolvable.

## Brand Personality

Engineer-literal and audit-proof. Proof is a status code, a published rotation cadence, a pinned
discovery document, a typed verdict — show the artifact, skip the adjective. Present tense only for
what answers at the URL today; explicit future tense for everything else. Gaps are published as
data, not hidden: the registry roster names its own stubs, and a 402 names the free alternative
first.

## Anti-references

- No "the identity platform for humans and AI agents." Two funded competitors ship that sentence.
- No "open identity standard." This is a managed service that implements other people's standards.
  The word returns the day a specification document and one external implementer exist.
- No **taxonomy** as a headline — no publishing the class enum as copy. A directory schema is not a
  positioning line.
- **Never ship *Identity* bare.** The hero always carries one of its two approved sublines.
- No "Contact us," anywhere, at any tier — including Enterprise.
- No docs behind a lead form, and no capability claimed **in present tense** that returns 404.
- **No hedges and no build-state prose, in either direction.** Not "coming soon," not "will be X
  once Y," not "under test" — and equally, never fix an overclaim by deleting the capability from
  the property's purpose. State it in future tense and ledger the gap.

## Design Principles

1. **Evaluated by curl.** Every claimed capability is demonstrable from a terminal in one command.
2. **Machine-legible negative capability.** What is unavailable is declared as a typed null in the
   same schema as what is available. An agent never 404s its way through discovery, never has to ask
   a human what it may do, and never has to ask a human what something costs.
3. **Gate by layer, not by endpoint.** Reading what an address affords is always free and keyless.
   Changing state is always gated.
4. **Free to emit, paid to be believed.** Self-directed acts are free forever; you pay when we spend
   a relationship with a third party on your behalf.
5. **You never pay to stop something.** Revocation is free at every tier, and reachable by the human
   who conferred the authority without a seat, a plan or a card.
6. **One address, three faces** — HTML, JSON and markdown, selected by content negotiation.

## Accessibility & Inclusion

WCAG 2.2 AA on every human surface. Full function without colour; honours `prefers-reduced-motion`
and `prefers-color-scheme`; keyboard-reachable throughout. Machine readers are included by design
rather than tolerated: every documented address serves a machine face alongside HTML, and a verdict,
a limit and a refusal are all typed data before they are ever styled.

## Offer

Self-serve at every tier. The CTA everywhere is **Get started**. Rate limits are published as real
numbers, not as "reasonable use."

**Free — permanently, and the parts that must never be metered are named.**

- **Resolution and dereference are free and keyless, permanently.** `/{grain}/{identifier}`,
  `/01/{gtin}`, linksets and the conneg faces. No key, no account, no rate-limit negotiation. This is
  a commitment about the offer, not a launch state: when the read face ships it ships free, and it
  stays free. Printed addresses depend on it.
- **Revocation is free at every tier and needs no seat.** `POST /oauth/revoke` (RFC 7009),
  `POST /agent/revoke`, `DELETE /api/keys/{id}`. The human who conferred an authority can end it
  without holding a paid seat, and no meter attaches to stopping anything. **Revocation is not
  retroactive** — it ends future use of a credential; it does not unmake an act already performed or
  a copy already taken. That limit is stated on the surface that performs it, not in a footnote.
- **Discovery is free and keyless.** OIDC, OAuth AS metadata, JWKS, the AAP agent-configuration
  document, and — when the read face ships — `/llms.txt`, `/.well-known/agents.json`, `/icp.json`
  and OpenAPI.
- **Register a client and provision a workspace, keyless.** **30 requests/minute** unauthenticated.
- **A provisioned sandbox** — **100 requests/minute**, 1,000 entities, 24-hour TTL. Claiming it with
  a GitHub identity or a WorkOS sign-in makes it persistent and lifts the entity ceiling.
- **An identified workspace** — **1,000 requests/minute**, persistent, no entity limit. Key
  issuance, agent registration, the audit log, and **registry-mode credential checks at $0**.
- **Emission is never metered on the write path.** You always can emit.
- **Self-attestation is free forever** — and by the verdict tier's own rule it never satisfies an
  act-class gate, which is exactly why it can be free.

**Metered — published price, self-serve, card, no human in the loop.** You pay when this property
spends a relationship with a third party on your behalf.

- **Vendor-brokered primary-source verification — $2.50 per check.** The only real price in the
  repository, charged today through a structured **402** whose **first listed alternative is the free
  registry mode**. A pricing pass is pending and this number is subject to it.
- **Retained witness — query and retention past the free line.** `$TBD`.
- **Attested acts at third-party grade** — an act countersigned so a relying party can act on it.
  `$TBD`.
- **Durable statefulness past the free tier** — persistent workspaces above the published ceilings.
  `$TBD`.

The meter is **verifications, connections and retained events**. It is deliberately **not per-agent
seats**: a per-agent seat prices the exact moment agent self-service must be free.

**Enterprise — the feature table publishes; the number is the only one deliberately absent.**
SSO/SAML/OIDC connections, SCIM directory sync, domain verification, MFA and session policy, RBAC
and fine-grained authorization at organizational scale, audit-log export and SIEM streaming, admin
portal, IP allowlisting, data residency, custody-grade retention and legal hold, single-tenant
options, **a customer-operated resolver hostname (`id.{brand}.com`)**, and the contract ceremony —
MSA, DPA, security review, PO invoicing. Enterprise enters self-serve like everyone else and upgrades
in-product. `$TBD — custom`.

```json product.md#pricing
{
  "currency": "USD",
  "tiers": [
    {
      "id": "free",
      "price": 0,
      "model": "free",
      "permanent": true,
      "rateLimits": [
        { "state": "keyless", "requestsPerMinute": 30 },
        { "state": "sandbox", "requestsPerMinute": 100, "maxEntities": 1000, "ttlHours": 24 },
        { "state": "identified", "requestsPerMinute": 1000, "maxEntities": null }
      ],
      "neverMetered": ["resolve", "dereference", "discover", "revoke", "emit", "self-attest"]
    },
    {
      "id": "metered",
      "model": "metered",
      "units": [
        { "unit": "primary-source-verification", "price": 2.5, "status": "charged" },
        { "unit": "retained-event", "price": null, "status": "TBD" },
        { "unit": "attested-act", "price": null, "status": "TBD" },
        { "unit": "durable-workspace", "price": null, "status": "TBD" }
      ]
    },
    { "id": "enterprise", "model": "custom", "price": null, "published": false }
  ],
  "contactSalesRequired": false,
  "humanRequiredToBuy": false
}
```

## Boundaries

- **Not a standard.** A managed service on an `.org.ai` name that implements other people's
  standards — AAP at its wire, OAuth 2.1 and OIDC, RFC 7009 revocation and RFC 7662 introspection,
  and the MCP authorization profile.
- **Not a replacement for WorkOS, and never presented as one.** This is a custom WorkOS domain with
  an authority layer above it. Identity, the enterprise checklist and Vault are WorkOS's; grants,
  ceilings, delegation and introspection to a human root are this property's; the record is the
  spine's.
- **Not an enrichment layer.** Barcode reading, generation, labels, serials and product data belong
  to barcoding.dev. This property consumes that data to resolve, and builds none of it.
- **Not an event store.** Events are stored and served by epcis.dev, through its one public write
  door. This property attests and emits; it never opens a second ingest path.
- **Not a dashboard.** Traces, evidence packs, grants-as-a-commercial-object, seats and the
  composition layer are visibility.cloud's.
- **One authority, as there is one resolver.** A consuming door's `share` compiles down to a grant
  here. Two authority stores would make "revocation ends access" false, so there is only one.
- **The object grain is resolved here, never attested here.** A pallet can be dereferenced; it
  cannot hold authority and cannot be answerable for an act.
- **Not every subject is resolvable, and no tier lifts it.** Some subjects are registered
  **non-resolvable by construction** — refused at the routing layer, in code, with a test. There is
  no commercial tier, key or contract that dereferences one. A pseudonym issued for such a subject is
  random, never derived from an attribute, so deletion is real rather than cosmetic.
- **Person-grain references downstream are opaque pseudonyms.** The map from pseudonym to person
  lives on the Human or Agent record here and nowhere else, which is what makes this property the
  estate's single point of erasure.
- **Revocation is not retroactive**, and legal hold's interaction with erasure is ruled and
  disclosed rather than discovered. A hold that silently outranks a deletion request would disable
  erasure at the moment it exists for.
- **A printed address is a long-lived dependency, and the durability posture is part of the offer.**
  Free-tier lock-in exists only through the hostname on the artifact; the Enterprise upgrade is
  `id.{brand}.com`, which deliberately removes it. *No durability commitment for printed addresses
  is published today; it publishes with the resolver, because a resolver that ships without one is
  an unpriced promise on somebody else's physical goods.*

## Stack

- **WorkOS** — human authentication and the enterprise layer beneath this property: SSO/SAML/OIDC,
  SCIM, MFA and session policy, FGA, the admin portal, Vault for secret custody, Pipes for brokered
  third-party OAuth
- **epcis.dev** — the event spine this property emits to: capture, query, the catalog
- **barcoding.dev** — the codec and enrichment layer this property resolves against
- **transactions.dev** — the business-document layer
- **visibility.cloud** — the composition and commercial layer over the family
- **Cloudflare Workers** — the runtime, with Durable Objects for the authorization server's state
