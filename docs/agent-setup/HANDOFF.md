# id.org.ai agent setup: implementation handoff

Nov 22, 2026, revision 2. For whoever builds these screens in the id.org.ai repo.

Revision 2 adds sections 16 to 24 (workflows, payments, connect from Claude), four changes to earlier screens, and the components and states they need. It replaces revision 1 in full.

The HTML in `screens/html/` is the visual source of truth. This file holds everything the HTML cannot show: the flows, the states, the rules, the component props, the data contract, and what is real versus sample. Where the two disagree on a visual value, the HTML wins. Where they disagree on behaviour, this file wins.

## 0. How to use this folder

```
HANDOFF.md            this file
STRIPE.md             what backs each payment screen in Stripe, and the open payment decisions
screens/html/         66 standalone screens, open in a browser
screens/png/          the same screens as images, 2x, plus two ".all-open" images (24a, 24b)
source/               the original canvas files (.dc.html), for reference only
fonts/                Geist and Geist Mono (variable), with their licence
```

Before writing code:

1. Read this file fully, then `STRIPE.md` before touching anything in sections 19 to 24.
2. Inventory what the repo already has from the auth redesign (`product-update` branch): card, action band, buttons, select, radio card, checkbox row, permission row, key-value well, signed-in row, connect header, dotted rule, copy button, email template, step-up (6a), action approval (5b), claim (5c). **Reuse them. Do not restyle them.**
3. Build only the new components in section 5.
4. Copy numeric values (sizes, radii, paddings, colours) exactly from the HTML. Do not round to a spacing scale.

The screens use inline styles because they came from a design canvas. Do not copy inline styles into components; map each value to the repo's existing tokens, and add a token only where none matches.

Expandable things in the HTML are native `<details>`. Two PNGs show every one of them open: `24a-ConnectPlan.all-open.png` and `24b-ConnectPay.all-open.png`.

## 1. What this is

The human half of agent onboarding. An agent sets up a product (first case: Auto.dev through APIs.ax). The person approves the agent once on id.org.ai, then watches each step happen. The same page runs any ordered list of observed steps, so it also runs migrations, multi-API jobs and headless SaaS setup (sections 16 to 18).

**The rule that shapes everything: id.org.ai displays, the product decides.** Each product posts step events. id.org.ai renders them and knows nothing about APIs, keys or calls beyond what an event says.

Four more rules:

- **A step ticks only when the product reports it.** No screen lets the agent or the person mark a step done.
- **The agent never declares setup finished.** The setup is live when the product says so.
- **id.org.ai holds the permission, never the money.** It knows who the agent is, who approved it, how much it may spend and how to stop it. Stripe moves the money. Card fields are always Stripe's.
- **These screens appear after sign-in only.** Nothing here belongs on a marketing page.

## 2. Screens

Numbering continues the existing auth canvas (sections 0 to 8).

| ID | File | Size | What it is |
| --- | --- | --- | --- |
| 9a | `9a-SetupApprove` | 720×1100 | Approve an agent that a product's setup sent |
| 9b | `9b-SetupRunning` | 720×880 | Setup in progress |
| 9c | `9c-SetupNeedsYou` | 720×1220 | Waiting on the person: approve spending |
| 9d | `9d-SetupStalled` | 720×920 | Agent went quiet |
| 9e | `9e-SetupLive` | 720×1060 | Done, with the link to the developer dashboard |
| 9f | `9f-SetupPhone` | 390×892 | 9b at phone width |
| 9g | `9g-SetupApprovePhone` | 390×1216 | 9a at phone width |
| 9h | `9h-SetupNeedsYouPhone` | 390×1232 | 9c at phone width |
| 9i | `9i-SetupTerminal` | 800×560 | The same run in the agent's terminal. Reference, not a web screen |
| 10a | `10a-Agents` | 720×1140 | Your agents |
| 10b | `10b-AgentRemove` | 720×740 | Remove an agent |
| 10c | `10c-AgentsEmpty` | 720×640 | No agents yet |
| 10d | `10d-AgentPause` | 720×760 | Pause an agent |
| 10e | `10e-AgentActivity` | 720×860 | What one agent did |
| 11a | `11a-SetupCallFailed` | 720×960 | The call keeps failing |
| 11b | `11b-SetupDeclined` | 720×840 | Payment declined |
| 11c | `11c-SetupNoCard` | 720×900 | No payment method |
| 11d | `11d-SetupLiveWarn` | 720×940 | Live, production check failed |
| 11e | `11e-SetupRejected` | 720×640 | Person rejected the agent |
| 11f | `11f-SetupCancelled` | 720×640 | Setup cancelled |
| 12a | `12a-SetupSecond` | 720×880 | A second API, no approval needed |
| 12b | `12b-LimitRaise` | 390×844 | Agent asks for a higher limit (phone) |
| 12c | `12c-AgentExpiring` | 720×740 | Agent expires in 3 days |
| 12d | `12d-SetupPaused` | 720×840 | Setup held because the agent is paused |
| 13a | `13a-AgentBlocked` | 720×780 | Workspace needs an admin for agent spending |
| 13b | `13b-AgentAdminApprove` | 720×1020 | Admin approves agent spending |
| 14a | `14a-MailNeedsYou` | 640×640 | Email: agent needs you |
| 14b | `14b-MailStalled` | 640×600 | Email: setup stalled |
| 14c | `14c-MailLive` | 640×640 | Email: live, with receipt |
| 15a | `15a-AddRunning` | 720×940 | apis.directory: adding an API, in progress |
| 15b | `15b-AddPickReview` | 720×1180 | apis.directory: pick the review |
| 15c | `15c-AddDomainFailed` | 720×1000 | apis.directory: domain not proved |
| 15d | `15d-AddInReview` | 720×800 | apis.directory: in review |
| 15e | `15e-AddListed` | 720×960 | apis.directory: listed |
| 16a | `16a-MigRunning` | 720×1000 | Migration: old and new API run side by side |
| 16b | `16b-MigDecide` | 720×1120 | Migration: two calls with no match, person chooses |
| 16c | `16c-MigSwitch` | 720×1000 | Migration: ready to switch, waiting on the person |
| 16d | `16d-MigDone` | 720×1000 | Migration: done |
| 17a | `17a-JobApprove` | 720×1140 | One approval and one limit across three APIs |
| 17b | `17b-JobRunning` | 720×940 | A job across three APIs, each step tagged |
| 17c | `17c-JobDone` | 720×960 | Job done, one bill |
| 18a | `18a-SaasMap` | 720×960 | Headless SaaS: two import columns need mapping |
| 18b | `18b-SaasRunning` | 720×980 | Headless SaaS: waiting for a real webhook event |
| 18c | `18c-SaasLive` | 720×960 | Headless SaaS: live |
| 19a | `19a-PayAdd` | 720×1000 | Add a payment method (Stripe fields) |
| 19b | `19b-PayPlanUsage` | 720×1300 | Agent flow: approve a plan plus usage |
| 19c | `19c-PayOnce` | 390×844 | One purchase over the ask-first amount (phone) |
| 19d | `19d-PayStepUp` | 390×844 | Passkey before a bigger limit (phone) |
| 19e | `19e-PayConfirmBank` | 720×900 | The bank demands the person |
| 19f | `19f-PayRenewalFailed` | 720×880 | A renewal was declined after go-live |
| 19g | `19g-PayLimitReached` | 720×800 | The agent's limit is reached |
| 20a | `20a-Spending` | 720×1140 | Spend by agent and recent charges, across every API |
| 20b | `20b-PayMethods` | 720×860 | Payment methods and billing details |
| 20c | `20c-Charge` | 720×840 | One charge, traced to the approval that allowed it |
| 20d | `20d-SpendRules` | 720×960 | Workspace spending rules |
| 21a | `21a-PayPerCall` | 720×900 | Live with pay per call: no plan, no key |
| 21b | `21b-PayWallet` | 720×920 | Agent pays from a Link wallet; approval is in Link |
| 22a | `22a-PayoutSetup` | 720×1020 | Seller: set up payouts with Stripe |
| 22b | `22b-PayoutMore` | 720×840 | Seller: Stripe needs one more thing |
| 22c | `22c-PayoutOn` | 720×980 | Seller: selling, payouts on |
| 23a | `23a-MailBank` | 640×640 | Email: bank needs to confirm |
| 23b | `23b-MailPayFailed` | 640×640 | Email: renewal failed |
| 23c | `23c-MailUsage` | 640×640 | Email: automatic spend alert |
| 24a | `24a-ConnectPlan` | 720×1200 | Connect from Claude: pick a plan |
| 24b | `24b-ConnectPay` | 720×1080 | Connect from Claude: subscribe and connect |
| 24c | `24c-ConnectDone` | 720×700 | Connect from Claude: connected |

The phone files (9f, 9g, 9h) are the same markup as 9b, 9a, 9c at 390 wide. They are not separate screens to build; they show the responsive result. 12b, 19c and 19d are drawn at phone width because they arrive by push; they are the same fluid page.

The 720 screens are fluid pages. The 720 is only the frame they were drawn in; the card is `max-width: 560px`, centred.

Existing screens these relate to, already in the auth canvas: **1a** Sign in, **1d** First run, **2a** Choose account, **2c** Handing off, **3a** Authorize app, **5a** Approve an agent, **5b** Approve an action (phone), **5c** Claim agent work, **6a** Confirm it's you, **7c** Blocked by workspace policy, **3d** Admin approves an app, **8a to 8c** emails.

### Changed since revision 1

| Screen | Change |
| --- | --- |
| 9a, 9g | A "Pays with Visa ending 4417 · Change" line under the spend limit and expiry |
| 9c, 9h | Same line inside the step. Step detail now reads "Growth is $299 a month plus data fees…" |
| 10a | "Spending" link next to "View activity" → 20a |
| 11b, 11c | Primary button opens 19a instead of leaving for billing. 11c footer: "The card fields are Stripe's. id.org.ai never sees the number." |

## 3. Flows

### Agent setup (sections 9 to 15)

**Happy path.** Agent starts setup in a terminal (9i) and prints an approval link. Person opens it → 9a → Approve → 9b, no redirect in between. Steps tick. → 9e.

**Spending not approved up front.** In 9a the person picks "$0 — decide later". Setup runs to the first real call, then → 9c. Approve → live key issued → 9e. When the product is a plan plus usage, the waiting screen is 19b instead of 9c.

**No card on file.** Spending is approved but the workspace has no payment method → 11c → 19a. On save the setup continues.

**Declined.** → 11b → 19a. Setup resumes when payment succeeds.

**Agent goes quiet.** No event for the stall threshold → 9d. The person copies one line and pastes it to the agent. Any new event returns to 9b.

**Call keeps failing.** The agent is calling but getting errors → 11a. Not terminal; the agent can keep trying.

**Production check fails.** Live key is issued anyway → 11d. This warns. It never holds back the key.

**Reject / cancel.** Reject in 9a → 11e (agent gets no identity). Cancel from 9d or 11a or 11b → 11f (agent stays approved, test key revoked).

**Second API.** Same agent, within the limit → 12a. No approval screen. If it would exceed the limit → push to the person → 12b.

**Manage.** 10a lists agents. Open one: Pause → 10d → 12d shows on any running setup. Remove → 10b. View activity → 10e. Spending → 20a.

**Expiry.** Three days before an agent expires → 12c (reached from an email or from 10a).

**Workspace policy.** Workspace requires an admin for any agent with a spend limit → person sees 13a → admin gets an email → 13b.

**After live.** 9e and 11d send the person to the product's developer dashboard, where usage, logs and keys live. id.org.ai is not that dashboard.

**Adding an API on apis.directory.** The same setup page with the directory's steps: 15a (the directory calls the API itself) → 15b (free or $100 review, the only time the person is asked) → 15d → 15e. 15c is the domain-proof failure.

### Workflows on the same page (sections 16 to 18)

No new page. Each is a different step list posted by the product.

**Migration (16).** 16a: both APIs get the same real requests and answers are compared per call. If some old calls have no equivalent → 16b, the person picks "keep these on the old API" or "have the agent replace them". When every answer matches → 16c, the person clicks Switch (the agent opens a pull request). → 16d. The old key is the person's to retire.

**One job across several APIs (17).** 17a is 9a with several permission rows and one limit covering all of them. 17b: each step carries a small tag naming the API it belongs to; the right tile is the layers icon. → 17c.

**Headless SaaS setup (18).** 18a: an import where two columns need a destination; the person maps or skips them. 18b: the gate is a real event reaching the person's webhook; a test event the agent sends itself does not count. → 18c.

### Paying (sections 19 to 23)

**Add a card.** From 11b, 11c, 20b, or the "Change" link on any pays-with line → 19a → back to where the person came from.

**Plan plus usage, agent flow.** After the first real call → 19b. The person sees the plan and its data fees, sets a spend limit (default none), leaves alerts on or off, ticks the terms line and approves. → live key → 9e.

**One purchase.** A single charge above the workspace's ask-first amount → push → 19c. "Stop asking for purchases like this" is off by default.

**Bigger limit.** Any limit above the workspace's passkey line → 19d after 12b or 19g. Same mechanics as 6a.

**Bank confirmation.** A charge comes back needing the cardholder → email 23a → 19e → the bank's screen through Stripe → setup continues. "Use another card" → 19a.

**Renewal fails after go-live.** Email 23b → 19f. The live key keeps working until the stop date.

**Limit reached.** 19g. Paid calls are refused until the reset or a raise. Raising above the passkey line → 19d.

**Money views.** 20a (from 10a) → a row opens 20c. 20a → 20b and 20d from the two buttons.

**Pay per call (21a)** and **wallet (21b)** are alternate endings of the setup run. See `STRIPE.md`.

**Seller payouts (22).** After 15e, if the person wants to charge for the API: 22a → Stripe's own onboarding → 22c. 22b is Stripe asking for more later.

### Connect from Claude (section 24)

A person clicks Connect on Auto.dev in Claude's connector directory. Claude opens id.org.ai's authorize URL in the browser. The whole pass:

1. **1a** sign in (or **1d** first run for a new account).
2. **24a** pick a plan. Skipped if the workspace already has a plan for this API.
3. **24b** subscribe and connect: charge summary, card, spend limit, spend alerts, what Claude may do, terms. One button.
4. **24c** connected.
5. Redirect to Claude's OAuth callback with the code.

Branches:

- **Free plan.** 24a → **3a** (plain consent, no charge) → 24c. No card.
- **No card on file and a paid plan.** 24a → **19a** → 24b.
- **Already subscribed.** 1a → **3a** → redirect. 24a to 24c do not show.

The person is present for the whole pass, so there is no test key, no first-call wait and no step list.

## 4. State model

One setup = one agent setting up one API (or running one workflow) for one workspace.

| Setup state | Screen | Connector | Header status |
| --- | --- | --- | --- |
| `awaiting_approval` | 9a, 17a | still | none |
| `rejected` | 11e | X | none |
| `running` | 9b, 12a, 15a, 16a, 17b, 18b | pulse, ring on right tile | green dot, "Updated Ns ago" |
| `needs_spend_approval` | 9c | hold | amber dot, "Updated Ns ago" |
| `needs_plan_approval` | 19b | hold | amber dot |
| `needs_person` | 15b, 16b, 16c, 18a, 22a, 22b | hold | amber dot |
| `needs_payment_method` | 11c | hold | amber dot |
| `needs_bank_confirmation` | 19e | hold | amber dot |
| `needs_wallet_approval` | 21b | hold | amber dot |
| `payment_declined` | 11b | X | amber dot |
| `call_failing` | 11a, 15c | hold | amber dot |
| `stalled` | 9d | hold | amber dot, "Last seen N min ago" |
| `paused` | 12d | still | none |
| `in_review` | 15d | still | none |
| `cancelled` | 11f | X | none |
| `live` | 9e, 15e, 16d, 17c, 18c, 21a, 22c | check | none |
| `live_with_warning` | 11d | check | none |

`needs_person` is the general case: the product names what it needs in the step's evidence. The more specific `needs_*` states exist because id.org.ai, not the product, renders their controls.

Account-level states, shown outside a setup run:

| State | Screen | Connector |
| --- | --- | --- |
| `needs_purchase_approval` | 19c | still (agent left, id.org.ai right, as 5b) |
| `needs_step_up` | 19d | still (id.org.ai left, fingerprint tile right) |
| `renewal_failed` | 19f | hold |
| `limit_reached` | 19g | hold |

**Connector** is the row of five dots between the two tiles:

- **still:** five dots at 0.3 opacity.
- **pulse:** the existing connecting wave.
- **hold:** new. Still dots, middle dot solid amber. Means "not moving, needs someone".
- **check / X:** the existing verdicts. **X is only for things that have ended or are refused** (rejected, declined, cancelled, and blocked by policy in 13a, as in 7c). A failing call is not X.

**Tiles.** On setup screens: agent on the left, product on the right (letter tile: `Ad` Auto.dev, `@` apis.email, `Di` apis.directory, `Ax` APIs.ax, `h` headless.ly, layers icon for a multi-API job). On approval and management screens: id.org.ai on the left, agent on the right, as in 5a. 12b, 19c and 19g follow 5b (agent left, id.org.ai right). Section 24: `Cl` (Claude) left, product right. Single-tile pages (10a, 20a, 20b, 20d) use one icon tile. No real product logos; letter tiles only.

### Steps

A setup carries an ordered list of steps. id.org.ai renders whatever list the product sends. For APIs.ax the list is:

1. Agent approved
2. Test key issued
3. First real call
4. *(conditional)* Approve spending, Approve the plan, Add a payment method, Confirm with your bank, or Approve in Link
5. Live key
6. Ready for production

Step 4 exists only when the person has to act. If spending was approved in 9a and a card is on file, it is absent.

Other lists, same component: apis.directory (15), migration (16), job (17), headless SaaS (18), pay per call (21a: Agent approved, First paid call, Ready for production), seller (22: Agent approved, Listed, Prices sent, Payouts set up, First paid call, Selling).

Each step has one state:

| Step state | Glyph | Title | Detail | Right-side label |
| --- | --- | --- | --- | --- |
| `done` | green check | primary | tertiary | time, mono |
| `now` | white dot with pulsing ring | primary | secondary | "Now" or "In review", secondary |
| `you` | amber dot | primary | secondary | amber text: "Waiting on you", "Stalled", "Failing", "Needs a fix", "Not found", "Due [DATE]" |
| `fail` | amber X | primary | secondary | amber text: "Declined", or a date |
| `held` | pause icon | primary | secondary | "Paused", secondary |
| `todo` | small dim dot | tertiary | tertiary | none |

The rail between glyphs is a vertical dotted line. Brighter (`white / 0.26`) below a `done` step, dimmer (`white / 0.11`) otherwise. No rail after the last step.

A step's detail may start with a **tag** (17b): a small mono, bordered label naming the API the step belongs to.

A step may carry **evidence**, drawn under its detail:

| Evidence | Screens | What it draws |
| --- | --- | --- |
| listening | 9b, 12a, 15a, 17b, 18b | Pulsing dot, one mono line, elapsed time, one note |
| call result | 9c, 11a, 15b | Method and path, status dot with code and latency, up to three key-value rows, a link. Green dot for 2xx, amber otherwise |
| prompt | 9d, 11d, 10c, 15c | A label, a copy button, one line of mono text to paste to the agent |
| field | 9c | A form control, here the spend limit select |
| key-values | 15b, 18b, 22a | A plain inset well of key-value rows |
| compare | 16a, 16c | Rows of "name … n of m match", green dot when complete, blinking white dot while running, one note |
| choice | 16b | An inset list of the unmatched items, then two radio cards |
| field mapping | 18a | Rows of source column (mono) → a select of destinations |
| plan | 19b | The rates well, then the Spend block and pays-with line (section 5) |

Steps with no detail (9e, 11d top rows) collapse to one line.

## 5. Components

### Reuse (already in the auth redesign)

Card and card body · action band · primary and secondary button · select · radio card · checkbox row · permission row (expandable) · key-value row and inset well · signed-in row with Switch · connect header · dotted rule · copy button with its 1.5 s check · identity row (the `ed25519 · 7f3a…c21d` expander) · quoted note · textarea · light email template · footer links · the header timer (5b).

### New in revision 1

| Component | Used in | Notes |
| --- | --- | --- |
| `StepList`, `Step` | every setup screen | Section 4. `role="list"` / `role="listitem"` |
| Connector `hold` mode | section 4 table | One new mode on the existing connect header |
| `CallResult`, `Listening`, `PromptWell` | section 4 evidence table | Evidence types. `PromptWell` is also standalone in 10c |
| `HeaderStatus` | setup screens | Dot + text in the header's right slot |
| `AgentRow` | 10a | Expandable box. Closed: mini tile, name, optional chip, one line. Open: key-values, connections, actions |
| `ConnectionRow` | 10a | Product name, state line, one link |
| `ActivityRow` | 10e | Icon, text, optional second line, time. Amber icon and second line when money moved |
| Mini tile | 10a, 20a | 36px version of the 56px tile, radius 11 |
| Icon note | 13a | 12px line with a 14px icon, centred, under the actions |

### New in revision 2

| Component | Used in | Props and behaviour |
| --- | --- | --- |
| `StepTag` | 17b | `label`. Mono 11.5px, 1px border, radius 6, sits before the detail text |
| `CompareWell` | 16a, 16c | `rows: [{name, text, state: "ok" \| "running"}]`, `note` |
| `FieldMapRow` | 18a | `column`, `options[]`. Two-column grid, 0.8fr / 1.2fr |
| `PayLine` | 9a, 9c, 19b, 19c, 24b | `method` ("Visa ending 4417"), `href`. One 13px line: card icon, "Pays with **{method}**", a "Change" link → 20b. If the workspace has no method, render "Add a payment method" → 19a instead |
| `StripeFields` | 19a | Stripe's Payment Element, themed to match the mock through its appearance settings. The mock's inputs are a picture of it. Never build real card inputs |
| `SegTabs` | 19a | Full-width, 3 options (Card, Bank account, Link). 36px cells in a 4px padded well |
| `BillingToggle` | 24a | Small pill, auto width, right-aligned on the "Plan" label row. Options Monthly, Yearly. **Default Monthly.** 26px cells. Switching swaps every card's price |
| `PlanCard` | 24a | See below |
| `SpendLimit` | 19b, 24b | See below |
| `SpendAlerts` | 19b, 24b | See below |
| `TermsAgree` | 19b, 24b | See below |
| `Toggle` | 19b, 20d, 24b | 36×22 track, 18px knob. On: track primary text colour, knob page background. `role="switch"` |
| `MethodRow` | 20b | `icon` (card \| bank), `title`, `sub`, optional chip ("Default"), one link |
| `SpendRow` | 20a | Mini tile, name, "amount of limit" in mono, a 4px bar, one line under. Whole row is a link |
| `ChargeRow` | 20a | Name with optional chip ("Running"), one line under, amount in mono, chevron. Whole row links to 20c |
| `Bar` | 19g, 20a | 4px, fully rounded. Fill is primary text at 0.82, or amber at 1.0 when at the limit |
| `Total` | 20a | 40px / 44px semibold number, tabular, with one 13px line under it |

#### PlanCard

One card per plan, stacked, 8px apart. Everything comes from the product.

```ts
type PlanCard = {
  id: string
  name: string                 // "Growth"
  price: string                // "$299" (monthly) or "$249" (yearly, per month)
  priceNote?: string           // "a month + data fees". Omitted on Free
  summary: string              // "Unlimited calls · 10 requests a second"
  included: { label: string; value?: string }[]   // rows behind the chevron
  selected: boolean
  open: boolean
}
```

- The row is a radio: one plan selected at a time. Selected card: border `white / 0.55`, the lighter fill, a 3px `white / 0.07` ring, filled radio dot.
- The chevron on the right is a **separate** control. It shows or hides `included` and does not change the selection. It points down when closed and rotates 180° when open.
- In the HTML the whole header is a `<summary>`, so a click toggles the list. That is a canvas shortcut. Build it as a radio plus a disclosure button with `aria-expanded`.
- `included` rows: a 14px check, the label, and an optional right-aligned mono value (a data fee, or "Included").
- On load: the product's recommended plan is selected and open; the rest are closed.
- The primary button label follows the selection: "Continue with {name}".
- The footer line ("Growth and Scale start with 7 days for $1.") shows only when the product has a trial.

#### Spend block: SpendLimit and SpendAlerts

One component that renders the limit, the alerts, or both, depending on what the API offers.

```ts
type Spend = {
  planPrice?: string                 // "$299", used in the helper line
  limit?: { options: (number | null)[]; value: number | null }   // null = "No limit"
  alerts?: { marks: number[]; on: boolean }
}
```

**The marks.** Both controls use the same values: **$100, $500, $1,000, $2,000, $5,000**. They count usage (data fees) in the billing month, **on top of the subscription price**.

**SpendLimit.** A full-width select labelled "Spend limit". Options: "No limit", then each mark as "$100 a month" and so on. Default "No limit". Helper line under it: "On top of the {planPrice} plan. Past a limit, calls are refused until next month."

**SpendAlerts.** Its own line under the limit, built exactly like a permission row: 16px bell icon, "Spend alerts" (14px, no sub copy), then a `Toggle`, then the row chevron.

- The toggle is **on by default**. It turns the automatic emails on or off. It is the same setting as the one in the developer dashboard.
- The chevron opens one line: "Emails at $100, $500, $1,000, $2,000 and $5,000." Build that sentence from `marks`. The chevron points right when closed and rotates 90° when open, like the permission rows.
- Toggle and chevron are separate controls. Flipping the toggle does not open the row.
- When on, the person gets email 23c each time the month's usage passes a mark. Nothing is stopped by an alert.

If the API offers only alerts, render the row alone with no helper line. If it offers only a limit, render the select and helper alone.

#### TermsAgree

A single checkbox (not a radio: it has to be un-tickable) with the text "I agree to {Product}'s Terms of Service and Privacy Policy." Both are links that open in a new tab, to URLs the product sends. It sits at the top of the action band, above the buttons.

- Unticked on load. **The primary button is disabled until it is ticked.** The mocks show it ticked so the button reads as active.
- Store the acceptance: who, when, and which version of each document.

## 6. Rules the HTML does not show

**Live updates.** The setup page updates in place as events arrive; no reload. "Updated Ns ago" ticks every second from the last event. Announce step changes to assistive tech (`aria-live="polite"` on the step list).

**Stall threshold.** A `running` setup with no event for 10 minutes becomes `stalled`. The 10 is a placeholder; make it configurable per product.

**Approving lands on progress.** After Approve in 9a, show 9b at once. The mock's line "Next, you watch each setup step as it happens" is a promise; keep it true.

**Account and workspace.** 9a, 17a and 24a must show who is signed in, with Switch (→ 2a). The approval and the bill are for that workspace only.

**Two kinds of limit. Do not merge them.**

- **Agent limit** (9a, 9c, 12b, 17a, 19g, 20a): monthly, per agent, per workspace, across every API that agent touches. Held by id.org.ai.
- **Spend limit on one API** (19b, 24b): usage on top of that API's subscription, at the marks in section 5. Held by the product.

A charge has to pass both.

**Second API.** Same agent, same workspace, total within the agent limit: no approval, just 12a. Otherwise 12b by push.

**Workspace spending rules (20d).** Four settings and one toggle: the limit a new agent starts with, the single-charge amount above which the person is asked (19c), the limit above which a passkey is required (19d), who can approve an agent that spends (13a, 13b), and whether every charge emails a receipt. An agent's own limit can be lower than the workspace's, never higher.

**Keys.** A live key is shown once, to the agent. The person only ever sees the last four characters. Never render a full key on any screen.

**Developer dashboard.** id.org.ai never issues, shows or rotates keys. Usage, logs and keys live in the product's developer dashboard (UI in the headless-ui repo). Agents can use it too, because they sign in through id.org.ai. Every live state links to it using the `dashboard_url` the product sends. "Create a key for yourself" in 9e goes to the dashboard's keys view.

**What id.org.ai shows about money, and what it does not.** It shows spend by agent, charges, limits and payment methods, because those cross every API. It does not show calls or logs (developer dashboard) or invoices, receipts and tax details (Stripe's billing portal, opened by "Invoices" in 20b and "View receipt" in 20c).

**"Running" usage.** In 20a a row with the "Running" chip is usage not yet billed. The amount and the call count come from the product. id.org.ai never computes them.

**Card details never touch id.org.ai.** 19a hosts Stripe's fields. The footer sentence in 19a ("By saving, you let agents you approve for Drivly charge this card inside the limits you set.") is the consent for charging later without the person present. Do not shorten or remove it.

**Things only a person can do.** Bank confirmation (19e), a passkey (19d), Stripe's identity and bank questions for a seller (22a, 22b). An agent is never offered these, and the copy says so.

**Pause.** The agent keeps its identity and keys. Its calls are refused and it cannot spend. Subscriptions keep billing. Resume returns a held setup to `running`.

**Remove.** Revokes the agent's identity and every key it holds, at once. Any setup in progress is cancelled.

**Expiry.** Set at approval (sample: 30 days). One prompt three days before.

**Workspace policy.** A workspace can require an admin for any agent with a spend limit. "Continue without spending" in 13a lets the agent proceed on the test key while the request is pending.

**Emails.** Six, and only these: the person is needed (14a), the setup stalled (14b), money moved (14c), the bank needs the person (23a), a renewal failed (23b), usage passed an alert mark (23c). Each button deep-links to the screen that resolves it. From address in the mocks is `agents@id.org.ai`; confirm it.

**Connect from Claude (24).**

- The connection is not complete until the browser is redirected to Claude's OAuth callback with the code. 24c is shown before that redirect.
- **"Back to Claude" (secondary, left) performs the redirect.** "Open developer dashboard" (primary, right) must open in a new tab so this tab can still finish. See open decision 11.
- If the person abandons at 24a or 24b, nothing is charged and no token is issued.
- 24b's summary well changes with the plan: with a trial it is "Today $1.00 for 7 days / From {date} $299.00 a month / Data fees"; without one, "Today $299.00 / Data fees".
- The permission rows in 24b are the existing permission row. The first is amber because it spends money as it is used.
- "Change plans anytime" and "Change the plan or disconnect in Agents" both lead to 10a.

**Phones.** Under 480px the card goes edge to edge, buttons stack full width at 48px with the primary on top. This is the existing auth rule and the CSS for it is in every file's `<style>`. Two-up inputs in 19a stay two-up.

**Motion.** All of it is in each file's `<style>` block:

- `idwave`: connector pulse, 2.0s linear, dots staggered 0.155s. Existing.
- `idring`: ring on the destination tile, 2.0s, 0.9s delay. Existing.
- `idpulse`: ring on the current step's dot, 2.0s.
- `idlisten`: the listening dot and the running compare dot, 1.6s.
- Chevrons rotate over 0.2s.
- Everything animated carries `data-m`; `prefers-reduced-motion` turns it all off.

**Accessibility.** Real `<button>`, `<a>`, `<label>`. Decorative SVG is `aria-hidden`. The copy button swaps to a check with a visually hidden "Copied" in a `role="status"`. Touch targets are 44px or more, except the billing toggle cells (26px) and the alerts toggle (22px), which are small by design; give each a 44px hit area. Plan cards are a radio group with a label. The alerts toggle is `role="switch"` with the label "Spend alerts".

**Copy.** Sentence case. Plain sentences. Name the agent and the product in every title. Never say "check" or "verify" as a noun to the person; steps "tick" or "happen". Amber is for money and for "needs someone"; there is no red in this system. Money is written "$299 a month", never "/mo".

## 7. Data contract (proposal, for Nathan to mark up)

Not confirmed. This is the minimum the screens need.

Product → id.org.ai, on every change:

```json
{
  "setup_id": "su_8f2k",
  "product": { "id": "apis.ax", "api": "auto.dev", "name": "Auto.dev", "tile": "Ad", "dashboard_url": "…", "terms_url": "…", "privacy_url": "…" },
  "agent_id": "ag_7f3a",
  "workspace_id": "ws_drivly",
  "state": "running",
  "steps": [
    { "id": "approved",   "title": "Agent approved",  "detail": "Trusted in Drivly, up to $500 a month.", "state": "done", "at": "2026-11-22T19:14:02Z" },
    { "id": "test_key",   "title": "Test key issued", "detail": "Real endpoints, capped at [TEST ALLOWANCE].", "state": "done", "at": "2026-11-22T19:14:05Z" },
    { "id": "first_call", "title": "First real call", "detail": "Waiting for Claude Code to call Auto.dev with the test key.", "state": "now",
      "evidence": { "type": "listening", "key_last4": "a91c", "since": "2026-11-22T19:14:05Z", "note": "A call copied from the docs example doesn’t count." } },
    { "id": "live_key",   "title": "Live key",        "detail": "Issued once a real call succeeds.", "state": "todo" },
    { "id": "production", "title": "Ready for production", "detail": "Auto.dev checks that it backs off and retries.", "state": "todo" }
  ],
  "next_for_person": null
}
```

A step may also carry `"tag": "apis.email"` (17b).

Evidence shapes:

```json
{ "type": "call", "method": "GET", "path": "/vin/1HGCM82633A004352", "status": 200, "ms": 212,
  "rows": [["Vehicle", "2003 Honda Accord Cpe"], ["Trim", "EX Auto V6 w/Leather"], ["Engine", "3.0, V6 Cylinder Engine"]],
  "more_url": "…" }
{ "type": "prompt", "label": "Paste this to Claude Code", "text": "Continue the Auto.dev setup. Read apis.ax/setup/su_8f2k and do what “next” says." }
{ "type": "rows", "rows": [["Saved", "1,228 contacts"], ["Skipped", "12, no email address"]] }
{ "type": "compare", "rows": [{ "name": "Decode a VIN", "matched": 250, "of": 250, "state": "ok" }, { "name": "Search listings", "matched": 181, "of": 250, "state": "running" }],
  "note": "A difference stops the switch and shows you both answers." }
{ "type": "choice", "items": [["[OLD CALL A]", "No equivalent yet"]], "options": [{ "id": "keep", "title": "…", "detail": "…" }, { "id": "replace", "title": "…", "detail": "…" }], "value": "keep" }
{ "type": "field_map", "rows": [{ "column": "lead_src", "options": ["Source", "A new field: lead_src", "Skip this column"], "value": "Source" }] }
```

The person's answer to `choice` and `field_map` goes back to the product as `setup.person_answered` with the step id and values.

Pricing, sent by the product for 19b and 24a/24b:

```json
{
  "plans": [
    { "id": "growth", "name": "Growth", "recommended": true,
      "price": { "monthly": 29900, "yearly_per_month": 24900 }, "price_note": "a month + data fees",
      "summary": "Unlimited calls · 10 requests a second",
      "included": [{ "label": "Global VIN Decode", "value": "$0.0025 a call" }, { "label": "MCP server, CLI and SDK" }],
      "trial": { "days": 7, "price": 100 } }
  ],
  "spend": {
    "basis": "usage_on_top_of_plan",
    "limit": { "options": [null, 10000, 50000, 100000, 200000, 500000], "default": null },
    "alerts": { "marks": [10000, 50000, 100000, 200000, 500000], "default_on": true }
  }
}
```

Omit `spend.limit` or `spend.alerts` when the API does not offer it. Amounts are cents.

Money events, product → id.org.ai, so 20a and 20c can render: `charge.succeeded`, `charge.failed`, `charge.needs_person`, `charge.refunded`, `usage.running` (amount, count, bill date), `alert.passed` (mark).

Before any charge the product asks: `authorize(agent_id, product, amount, kind)` → `allow`, `ask_person` (→ 19c, 12b or 19d) or `refuse` (→ 19g). This is what makes one agent limit hold across APIs.

id.org.ai owns: the agent (identity, trust, agent limit, expiry, paused), the approval, the workspace policy and spending rules, the payment methods, and the activity log. The product owns: keys, calls, subscriptions, usage, the per-API spend limit and alerts, and every step.

id.org.ai → product: `agent.approved`, `agent.paused`, `agent.resumed`, `agent.removed`, `agent.limit_changed`, `setup.spend_approved`, `setup.plan_approved` (plan id, billing period, spend limit, alerts on, terms accepted at), `setup.person_answered`, `setup.cancelled`.

Suggested routes: `/agent?code=…` (9a), `/setup/:id` (every setup state), `/agents` (10a, 10c), `/agents/:id/activity` (10e), `/spending` (20a), `/spending/charges/:id` (20c), `/spending/rules` (20d), `/payment-methods` (20b), `/payment-methods/new` (19a), `/connect/:client/plan` (24a), `/connect/:client/pay` (24b), `/connect/:client/done` (24c).

## 8. Real, sample and placeholder

**Real:**

- `GET https://api.auto.dev/vin/{vin}`. The response for VIN `1HGCM82633A004352` (2003 Honda Accord Cpe, EX Auto V6 w/Leather). The error code `INVALID_VIN_FORMAT`.
- Auto.dev plans, read from auto.dev/pricing on Nov 22, 2026: Free $0 (1,000 calls a month, 5 requests a second); Growth $299 a month plus data fees, $249 a month billed yearly (10 requests a second); Scale $599, $499 yearly (50 requests a second). Growth and Scale have a 7-day trial for $1.
- Growth data fees per call: Global VIN Decode $0.0025, Vehicle Listings $0.0015, Vehicle Photos $0.0009, Specifications $0.0015, OEM Build Data $0.10, Interest Rates $0.005, Vehicle Payments $0.005, Vehicle Recalls $0.01, Total Cost of Ownership $0.06.
- The alert and limit marks ($100, $500, $1,000, $2,000, $5,000), alerts on by default, monthly as the billing default, and the $100 fast review on apis.directory (from Bryant).

**Sample, change freely:** all times, dates, latencies, key endings, card ending `4417`, bank ending `2210`, setup id `su_8f2k`, device code `WDJB-MJHT`, host `bryant-mbp`, the people, the agents (Claude Code, Codex, Susan), every spend total and call count, agent limits ($500, $250, $100), the workspace rule amounts in 20d ($50, $500), the retry dates in 19f, the scope strings (`autodev:test`, `autodev:subscribe`, `autodev:call`), the MarketCheck migration numbers, and the command `npx apis.ax setup auto.dev`.

**Placeholders, keep bracketed until supplied:** `[TEST ALLOWANCE]`, `[AGENT GUIDE URL]`, `[YOUR API]`, `[YOUR DOMAIN]`, `[YOUR DOMAIN API]`, `[YOUR ENDPOINT]`, `[YOUR WEBHOOK URL]`, `[MS]`, `[FREE REVIEW TIME]`, `[PRIORITY REVIEW TIME]`, `[OLD CALL A]`, `[OLD CALL B]`, `[PRICE]`, `[PRICE PER 1,000]`, `[TOTAL]`, `[FEE]`, `[PAYOUT SCHEDULE]`, `[TIME]`, `[DATE]`, `[BUSINESS NAME]`, `[STATEMENT NAME]`, `[TAX ID]`.

**Assumed, not confirmed:** that apis.email proves a sending domain by DNS and that a domain API exists (17); that the headless CRM takes a file import and a webhook (18); that data fees bill monthly with the plan (19b, 19f); that Scale's extra APIs are listed in 24a without their fees because two published prices for Plate-to-VIN disagree.

## 9. Open decisions

Do not guess these. Ask.

1. **Who the seller is on the card statement:** each API, or one .do name. Drives the Stripe Connect charge type. See `STRIPE.md`.
2. **Where the agent limit is enforced.** Proposed in section 7: the product asks id.org.ai before every charge.
3. **Does approving spend always require step-up (6a)?** Drawn as: only above the workspace's passkey line (19d, 20d).
4. **Does removing an agent cancel its subscriptions?** 10b draws it as an unchecked choice.
5. **Does a failed production check block or warn?** Drawn as warn (11d).
6. **Stall threshold** and whether it differs per product.
7. **Activity retention** and what "Export" in 10e produces.
8. **Push delivery** for 12b, 9c, 19c and 19d: which channel.
9. **5a still shows a $50 a month sample limit;** these screens use $500.
10. **The developer dashboard URL per product,** and whether "Create a key for yourself" deep-links to a keys view.
11. **24c and the redirect.** The dashboard is the primary button, but the connection only completes when the browser returns to Claude. Options: open the dashboard in a new tab and leave 24c in place (drawn), or redirect to Claude automatically after a few seconds.
12. **Do agents and connectors get the $1 trial,** or start on the full plan? Drawn with the trial in 24b and 24c, without it in 19b.
13. **What the marks count.** Drawn as usage on top of the subscription, per billing month. Confirm calendar month versus billing month.
14. **Who decides a refund** (20c): the API or .do.
15. **Do third parties sell through APIs.ax?** Section 22 only matters if they do.
16. **Whether data fees bill at month end or sooner past a mark.**
17. **Default spend limit for a plan plus usage.** Drawn as "No limit" with alerts on.

## 10. Not designed yet

Loading and skeleton states · errors when an action itself fails (approve, pause, remove, save card, subscribe) and validation states for Stripe's fields · the unticked-terms and disabled-button state (described in section 5, not drawn) · the yearly state of 24a (prices in section 8) · a plan change asked by an agent (Growth to Scale) · an agent that paid from a stablecoin wallet with no account, then claimed (reuse 5c) · an agent buying a sponsor spot on apis.directory (same component, different step list) · the developer dashboard itself, including the spend alerts toggle there (headless-ui repo) · invoices, receipts and tax (Stripe's portal) · light theme · localisation.
