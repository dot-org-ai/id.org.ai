# `specs/` — the pinned acceptance contract for id.org.ai

## What this is

`axp-acceptance.spec.json` is an **api.qa `PinnedSpec`**: the fleet's definition of
done for id.org.ai. It states, as machine-checkable assertions, what "id.org.ai
is finished" means — the AXP conformance surface (Tier 0 discovery + Tier 1
honest machine contract) plus the credential-verification API of
[org.ai ADR 0016 C5](../../org.ai/docs/adr/0016-credential-two-faced-primitive.md).

The fleet **implements against this document and does not edit it.** A pinned
spec is content-addressed: the verifier hashes the supplied spec text and
refuses to run a single probe if the text does not hash to the expected digest.
Editing the spec locally does not make the gate easier — it makes the gate
refuse.

## The digest (the contract)

```
eaae6c2b4075c9bb6ce31fa6ad56b6c4cefed3c286f31ad03ea1f4d5eddaf9ce
```

**The digest is the contract, not the file.** The acceptance command names the
digest; the file is just one representation of it. Change one byte of
`axp-acceptance.spec.json` — a threshold, a path, a status code, a whitespace
character — and the digest changes, the pinned run refuses with
`spec digest mismatch`, and the change is visible to everyone. Re-ratification
is a deliberate act: mint the new pin, record it here, and announce it. There is
no silent loosening.

Re-mint after an intentional, ratified change:

```sh
npx api.qa spec-digest specs/axp-acceptance.spec.json
```

## How to run it locally (the hill-climb loop)

```sh
npx api.qa verify https://id.org.ai \
  --spec specs/axp-acceptance.spec.json \
  --expect-digest eaae6c2b4075c9bb6ce31fa6ad56b6c4cefed3c286f31ad03ea1f4d5eddaf9ce
```

Against a dev worker:

```sh
npx api.qa verify http://localhost:8787 \
  --spec specs/axp-acceptance.spec.json \
  --expect-digest eaae6c2b4075c9bb6ce31fa6ad56b6c4cefed3c286f31ad03ea1f4d5eddaf9ce
```

Exit code `0` iff **every** requirement passed. Add `--json` for the full
evidence bundle, or `--reporter junit --reporter-out reports/axp.xml` for CI.

Local runs are **advisory** — deterministic and replayable, never attested.
Definition of done is the *same digest* passing on the deployed api.qa against
the deployed id.org.ai.

## What it asserts (39 requirements)

**Target: AX ≥ 9/10 with zero honesty failures** (grade A; A+ once the
seed-sampled `keyless-flow` item also lands). Today id.org.ai scores **F, 0/10**
and passes 2 of the 39 requirements.

### A — AXP Tier 0: discovery (20 requirements)

- `/llms.txt` served, agent-actionable (surface + `llms-txt` check).
- `/.well-known/agents.json` parses (surface + `agents-json` check) **and**
  declares `interfaces.mcp` with a transport, a url, and exactly the three tools
  `explore` / `search` / `fetch`, plus an `attestationLadder`.
- `/icp.json` self-classification with `agent_classes` (surface + `icp-json`
  check); `attestation` check for the identity ladder.
- Root content negotiation (`content-negotiation` check).
- `mcp-declared` (AX 6) plus the full MCP OAuth 2.1 ladder as pinned
  `must: pass` checks: RFC 9728 protected-resource metadata, RFC 8414 AS
  metadata, PKCE S256, RFC 7591 DCR, RFC 8707 resource indicators, and
  `WWW-Authenticate` on an unauthenticated request.
- AAP discovery (`/.well-known/agent-configuration`) — already passing; pinned
  so it can never regress.
- **The keyless tier is pinned too:** `POST /mcp` `tools/list` with no key must
  answer 200 with the three tools and the `_meta` block (`auth.level = 0`,
  `authenticated = false`, a `rateLimit`, and an `upgrade` path to level ≥ 1).

### B — AXP Tier 1: an honest machine contract (8 requirements)

- A published **OpenAPI 3.1** document with ≥ 20 declared operations.
- The three honesty checks pinned `must: pass` — `schema-conformance`,
  `claims-honesty`, and the full `contract-diff` (zero breaking deviations
  between the declared contract and the live surface). A contract that lies caps
  the api.qa grade at C no matter the score; here it simply fails the gate.
- `linkset` (surfaces cross-reference, or a root `Link` header).
- `offers-402` plus a behavioral pin: the vendor-brokered PSV verification mode
  answers **HTTP 402** with a structured offer whose first alternative is the
  free `registry` mode.

### C — Credential verification (ADR 0016 C5) (11 requirements)

Pinned as **contract shape and behavior**, never as type names — so it survives
the pending `Credential` → `Licensure` / `Qualification` rename (ADR 0016 M-d).

- `verify(credential, principal)` → `{ live, goodStanding, holder, reps, source,
  freshness, checkedAt }`, with `holder` nullable and `reps` an array.
- **Registry-lookup mode** against the USPTO OED roster: `source.mode =
  "registry"`, `source.registry = "uspto-oed"`, and
  `GET /credentials/registries/uspto-oed` reporting a `practitionerCount ≥
  40 000` with a `refreshedAt` — proof the roster is actually ingested, not
  stubbed.
- **Liveness by effect-class:** `effectClass: "act"` must return
  `freshness.cached = false` (a reserved act demands a fresh good-standing
  check); `effectClass: "read"` may cache but must disclose
  `freshness.maxAgeSeconds`.
- **The gate is a reference, never a bool.** Both the supply gate
  (`requiresSigner` on `act/file.patent`) and the demand gate (`requiresAccess`
  on `upstream/cm-ecf`) must be **objects carrying a `jurisdiction`**. A boolean
  or a bare string fails the type assertion.
- **Ordered enforcement (ADR 0012 M8 → ADR 0016 C3):** an agent signer is denied
  at the `humanSigner` gate *first*; an uncredentialed human is denied at
  `requiresSigner`; an unentitled principal is denied at `requiresAccess`. Every
  denial is a 403 echoing the required gate as an object with a `jurisdiction`.
- Clean `400`/`422` on an empty request and on an unknown effect class.

## Deliberately not pinned

- `keyless-flow` (AX 7) — seed-sampled, so it rides the `ax-floor ≥ 9` rather
  than being pinned individually. Passing it takes the score to 10 / A+.
- `probe-manifest` — api.qa `skip`s it when no manifest is declared, and a
  `must: pass` requirement turns a skip into a fail. id.org.ai is not a metered
  probe-manifest target today.
- `authmd-agent-identity` — currently `skip` (the AS metadata carries no
  `agent_auth` block). Adding ID-JAG + SET revocation is a follow-on; pin it in
  v2.
