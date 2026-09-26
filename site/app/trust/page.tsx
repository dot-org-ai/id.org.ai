import type { Metadata } from "next";
import { Navbar } from "@/components/navbar";

export const metadata: Metadata = {
  title: "The Record — id.org.ai for Regulators",
  description:
    "What id.org.ai logs, what it refuses to log, and which parts are built today versus designed. Written for lawyers, bar committees, and regulators.",
  alternates: {
    canonical: "/trust",
  },
  openGraph: {
    type: "website",
    url: "https://id.org.ai/trust",
    siteName: "id.org.ai",
    title: "The Record — id.org.ai for Regulators",
    description:
      "What id.org.ai logs, what it refuses to log, and which parts are built today versus designed.",
  },
};

type Status = "built" | "partial" | "designed";

const statusStyles: Record<Status, string> = {
  built: "border-foreground/60 text-foreground",
  partial: "border-foreground/30 text-muted-foreground",
  designed: "border-dashed border-foreground/30 text-muted-foreground",
};

const statusLabels: Record<Status, string> = {
  built: "BUILT",
  partial: "PARTIALLY BUILT",
  designed: "DESIGNED, NOT BUILT",
};

function StatusBadge({ status }: { status: Status }) {
  return (
    <span
      className={`inline-block shrink-0 border px-2 py-0.5 text-[11px] tracking-wider ${statusStyles[status]}`}
    >
      {statusLabels[status]}
    </span>
  );
}

function Section({
  id,
  title,
  children,
}: {
  id: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section id={id} className="scroll-mt-24 border-t border-border pt-10">
      <h2 className="text-foreground text-2xl font-semibold">{title}</h2>
      <div className="mt-6 space-y-5">{children}</div>
    </section>
  );
}

function Item({
  status,
  title,
  children,
}: {
  status: Status;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="border border-border p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-foreground font-semibold">{title}</h3>
        <StatusBadge status={status} />
      </div>
      <div className="text-muted-foreground mt-3 space-y-3 text-[15px] leading-relaxed">
        {children}
      </div>
    </div>
  );
}

const summaryRows: Array<{ capability: string; status: Status; note?: string }> = [
  { capability: "Verified human sign-in", status: "built" },
  { capability: "Agent identity: per-agent keypairs, lifecycle, revocation", status: "built" },
  { capability: "Scoped authorization — narrowing-only, fail-closed", status: "built" },
  { capability: "Per-call ceilings on a scope", status: "built" },
  { capability: "Cumulative budgets across calls", status: "designed" },
  {
    capability: "Professional-registry credential verification",
    status: "built",
    note: "USPTO practitioner roster wired; state bar rosters are not",
  },
  {
    capability: "First-class delegation record (principal, agent, matter, expiry)",
    status: "designed",
  },
  { capability: "Reserved-decisions catalog with recorded acknowledgment", status: "designed" },
  { capability: "Append-only audit log of identity and authorization events", status: "built" },
  { capability: "Cryptographic tamper-evidence (verifiable hash chain)", status: "designed" },
  { capability: "Vendor-chain attestations (retention and training configuration)", status: "designed" },
  {
    capability: "Matter-scoped logging: direction, chronology, review and adoption",
    status: "designed",
  },
];

export default function TrustPage() {
  return (
    <>
      <Navbar />
      <main className="bg-background min-h-screen">
        <div className="mx-auto max-w-3xl px-6 pt-32 pb-24">
          {/* Header */}
          <header>
            <p className="text-muted-foreground text-sm tracking-wider uppercase">
              For lawyers, bar committees, and regulators
            </p>
            <h1 className="text-foreground mt-4 text-4xl font-semibold sm:text-5xl">
              The record
            </h1>
            <div className="text-muted-foreground mt-6 space-y-4 text-[15px] leading-relaxed">
              <p>
                id.org.ai is an identity and authorization layer for humans and AI
                agents. It answers three questions: who is this human, who is this
                agent, and what has the human authorized the agent to do.
              </p>
              <p>
                Some of the people reading this page arrived from{" "}
                <a
                  href="https://law.org.ai"
                  className="text-foreground underline underline-offset-4"
                >
                  law.org.ai
                </a>
                , a program of the Org.AI Foundation. That site makes a legal
                argument: professional privilege can survive AI assistance when the
                professional directs the agent — and direction is only worth
                arguing about if there is a record that proves it. This page
                describes that record.
              </p>
              <p>
                It also says, for every piece, whether it is built today, partially
                built, or designed and not yet built. We label the gaps because a
                blank is information. A regulator reading a page with no gaps
                should assume the gaps were hidden.
              </p>
            </div>

            {/* Legend */}
            <dl className="mt-8 space-y-3 border border-border p-5 text-[14px]">
              <div className="flex flex-wrap items-baseline gap-3">
                <StatusBadge status="built" />
                <dd className="text-muted-foreground">
                  running in the production codebase, covered by tests
                </dd>
              </div>
              <div className="flex flex-wrap items-baseline gap-3">
                <StatusBadge status="partial" />
                <dd className="text-muted-foreground">
                  the primitive exists; the professional-facing shape does not
                </dd>
              </div>
              <div className="flex flex-wrap items-baseline gap-3">
                <StatusBadge status="designed" />
                <dd className="text-muted-foreground">
                  written down and committed to, not yet code
                </dd>
              </div>
            </dl>
          </header>

          <div className="mt-14 space-y-14">
            {/* ── Delegated authority ─────────────────────────────── */}
            <Section id="delegation" title="Delegated authority">
              <p className="text-muted-foreground text-[15px] leading-relaxed">
                The design commitment: an agent never acts as a free-floating
                identity. It acts under authority delegated from a verified human,
                with explicit scopes, bounded lifetimes, and revocation that takes
                effect immediately.
              </p>

              <Item status="built" title="Verified human identity">
                <p>
                  Humans sign in through established identity providers. A tenant —
                  the account an agent operates under — is bound to a verified
                  human when that human claims it. The claim event is logged.
                </p>
              </Item>

              <Item status="built" title="Agent identity and lifecycle">
                <p>
                  Each agent holds its own cryptographic keypair (Ed25519) and is
                  registered under a tenant. Agents have independent lifecycles:
                  revoking one agent does not disturb the tenant or its other
                  agents. Lifetimes are bounded by default — a 24-hour session, a
                  30-day maximum, a 365-day absolute limit. An expired agent stays
                  expired until a person or process explicitly reactivates it.
                </p>
              </Item>

              <Item status="built" title="Scoped authorization">
                <p>
                  A scope is a set of explicit may-dos: a verb, a resource, and
                  optionally a ceiling on what one call may consume. A scope
                  derived from another scope can only narrow — it can never grant
                  more than its parent. Authorization fails closed: a request that
                  no grant covers is refused.
                </p>
                <p>
                  One honest limit, stated because the distinction matters: a
                  ceiling caps a single call. It is not a cumulative budget. The
                  system does not track spend across calls, so no part of it
                  claims to. A cumulative budget is designed, not built.
                </p>
              </Item>

              <Item status="designed" title="The delegation record">
                <p>
                  Today the chain of authority is structural: the human claims the
                  tenant, the agent lives under the tenant, the agent&apos;s
                  credentials carry scopes. What does not exist yet is a
                  first-class delegation record — one signed object naming the
                  human principal, the agent, the matter, the scopes, and the
                  expiry. That object is the thing a reviewer would want to hold.
                  It is designed. It is not built.
                </p>
              </Item>

              <Item status="built" title="Professional-registry verification">
                <p>
                  The layer can verify a professional&apos;s standing against an
                  authoritative registry and report exactly one of three verdicts:
                  registry-verified, holder-attested, or unverifiable-by-registry.
                  It never invents a verdict. When a registry cannot answer, it
                  says so instead of guessing.
                </p>
                <p>
                  The USPTO practitioner roster is the working exemplar today.
                  State bar rosters are not yet wired. That is a blank, and the
                  blank is information.
                </p>
              </Item>
            </Section>

            {/* ── Reserved decisions ──────────────────────────────── */}
            <Section id="reserved-decisions" title="Reserved decisions">
              <p className="text-muted-foreground text-[15px] leading-relaxed">
                Some decisions belong to the verified human, always. In a legal
                engagement: retention, fee terms, changes of scope, conflict
                waivers, settlement, and consent to AI involvement. The
                reserved-decisions catalog routes each of these to the human. The
                agent may prepare the decision. It may never make it. The
                human&apos;s acknowledgment is recorded.
              </p>

              <Item status="designed" title="The catalog and the acknowledgment gate">
                <p>
                  This is the honest status: designed, not built. The scoping
                  draft exists and binds rules we consider non-negotiable — only
                  an authenticated human can decide; opening a link decides
                  nothing; anything unresolved fails closed; an expired request is
                  a denial, never a hold.
                </p>
                <p>
                  What exists nearest to it today: consent screens for
                  third-party access, and the claim step that binds a tenant to a
                  verified person. Those are gates. The per-decision catalog with
                  recorded acknowledgment is not one of them yet.
                </p>
              </Item>
            </Section>

            {/* ── The audit trail ─────────────────────────────────── */}
            <Section id="audit" title="The audit trail">
              <p className="text-muted-foreground text-[15px] leading-relaxed">
                The design goal is stated on law.org.ai and adopted here: a
                regulator who can read the log should not need to interview
                anyone.
              </p>

              <Item status="built" title="Append-only event log">
                <p>
                  Every identity, authentication, key, claim, and authorization
                  event is recorded with actor, target, timestamp, and origin
                  metadata. The log exposes two operations: write and read. There
                  is no update. There is no delete.
                </p>
              </Item>

              <Item status="designed" title="Cryptographic tamper-evidence">
                <p>
                  Append-only is a promise the code keeps by not offering an edit
                  path. Tamper-evident is a stronger property: a hash chain a
                  third party can verify without trusting us. We have the first.
                  We have designed the second. They are not the same thing, and
                  this page will say so until they are.
                </p>
              </Item>

              {/* Must-log */}
              <div className="border border-border p-5">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <h3 className="text-foreground font-semibold">
                    What the log must hold
                  </h3>
                  <StatusBadge status="designed" />
                </div>
                <p className="text-muted-foreground mt-3 text-[15px] leading-relaxed">
                  These are design commitments for the professional-grade trail.
                  The event log above exists; the matter-scoped shape below does
                  not yet.
                </p>
                <ul className="text-muted-foreground mt-4 space-y-2.5 text-[15px] leading-relaxed">
                  {[
                    "Which professional or principal directed which task, on which matter, and when.",
                    "The engagement chronology — evidence that the relationship preceded the drafting.",
                    "The client's identification and acceptance of the agent.",
                    "Delegation scopes and per-transaction authorizations: hashes, timestamps, scope identifiers.",
                    "Review and adoption events — the professional's review of the agent's work, recorded when it happens.",
                    "Vendor-chain attestations — that a zero-data-retention, no-training configuration was in force at each link in the chain.",
                  ].map((line) => (
                    <li key={line} className="flex gap-3">
                      <span className="text-foreground select-none" aria-hidden>
                        +
                      </span>
                      <span>{line}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Must-never-log */}
              <div className="border border-foreground/40 p-5">
                <h3 className="text-foreground font-semibold">
                  What the log must never hold
                </h3>
                <p className="text-muted-foreground mt-3 text-[15px] leading-relaxed">
                  This list is as binding as the one above. An audit trail that
                  captures everything is a privilege leak with good intentions.
                </p>
                <ul className="text-muted-foreground mt-4 space-y-2.5 text-[15px] leading-relaxed">
                  {[
                    "Message or prompt content. Hashes and metadata only. The content stays in the professional's file, under the professional's control.",
                    "Attorney mental impressions or commentary, in any form.",
                    "Draft history beyond the close of the matter.",
                  ].map((line) => (
                    <li key={line} className="flex gap-3">
                      <span className="text-foreground select-none" aria-hidden>
                        −
                      </span>
                      <span>{line}</span>
                    </li>
                  ))}
                </ul>
                <p className="text-muted-foreground mt-4 text-[15px] leading-relaxed">
                  A statement of current fact, distinct from the commitment: the
                  identity layer today never receives message content at all. It
                  authenticates and authorizes; it does not carry the work. The
                  list above is the commitment that this stays true by design as
                  the audit layer grows — not by accident of scope.
                </p>
              </div>
            </Section>

            {/* ── Summary table ───────────────────────────────────── */}
            <Section id="status" title="Status, in one table">
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-[14px]">
                  <thead>
                    <tr className="border-b border-border text-left">
                      <th className="text-muted-foreground py-2 pr-4 font-normal tracking-wider uppercase text-[11px]">
                        Capability
                      </th>
                      <th className="text-muted-foreground py-2 font-normal tracking-wider uppercase text-[11px]">
                        Status
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {summaryRows.map((row) => (
                      <tr key={row.capability} className="border-b border-border/60">
                        <td className="text-foreground py-3 pr-4 align-top">
                          {row.capability}
                          {row.note ? (
                            <span className="text-muted-foreground block text-[13px]">
                              {row.note}
                            </span>
                          ) : null}
                        </td>
                        <td className="py-3 align-top">
                          <StatusBadge status={row.status} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>

            {/* ── Footer ──────────────────────────────────────────── */}
            <footer className="border-t border-border pt-8">
              <p className="text-muted-foreground text-[14px] leading-relaxed">
                Nothing on this page is legal advice. The legal argument — agency
                law, supervised-practice precedent, and what a court would need to
                see — is made at{" "}
                <a
                  href="https://law.org.ai"
                  className="text-foreground underline underline-offset-4"
                >
                  law.org.ai
                </a>
                , with sources. This page covers only the record. When the status
                of a capability changes, this page changes with it.
              </p>
            </footer>
          </div>
        </div>
      </main>
    </>
  );
}
