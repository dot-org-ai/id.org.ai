# Agent payments on id.org.ai: Stripe and Stripe Connect

Companion to `HANDOFF.md`. Nov 22, 2026, revision 2. Covers what sits behind the payment screens (sections 19 to 24) and the payment decisions still open.

Screens, flows, states, components and rules are in `HANDOFF.md`. This file is only the Stripe side.

Status: design only. Nothing here is built. As of this date no .do API lets an agent sign up or pay. The backend will be Stripe and Stripe Connect.

Stripe's agent and machine payment APIs are in preview and changing. **Confirm every mapping below against current Stripe docs before building.**

## 1. The rule

id.org.ai holds the permission, never the money. Stripe moves the money. Card fields are always Stripe's.

## 2. What backs each screen

| Screen | Stripe side (proposed) |
| --- | --- |
| Workspace | One Stripe Customer on the platform account |
| 19a Add a payment method | A SetupIntent for off-session use, with the Payment Element themed to match. The consent sentence in the footer is what allows charging later without the person present |
| 19b, 24b Subscribe | One subscription: a flat price for the plan plus metered prices for data fees. Monthly or yearly per 24a. Trial per the product (Auto.dev: 7 days for $1) |
| 24a Pick a plan | Plans and included items come from the product, not from Stripe. Prices must match the Stripe prices the product will subscribe to |
| Spend limit (19b, 24b) | Not a Stripe feature. The product refuses paid calls once the month's usage passes the limit |
| Spend alerts (19b, 24b, 23c) | Stripe Billing usage alerts at each mark, or the product's own meter. Either way the product sends `alert.passed` and id.org.ai sends the email |
| Terms (19b, 24b) | Not Stripe. Store who, when and which version |
| 19c One purchase | A one-off PaymentIntent on the saved method, created only after the person approves |
| 19e Bank confirmation | The payment needs authentication (`requires_action`, or the invoice's payment-action-required event). The person completes it on Stripe's screen |
| 19f Renewal failed | A failed invoice and Stripe's retry schedule. The date the key stops is our rule |
| 19g Limit reached | Not Stripe. id.org.ai's agent limit |
| 20a Spending | Built from the product's money events. "Running" usage is the product's meter, not Stripe's invoice |
| 20b Invoices, tax details | Stripe's customer portal |
| 20c Receipt, refund | Stripe's hosted receipt. Refund through Stripe; who decides is open |
| 21a Pay per call | Stripe machine payments. MPP takes cards (through shared payment tokens) and stablecoins; x402 takes stablecoins. id.org.ai would issue a token scoped to the seller with a cap and expiry that mirror the person's limit |
| 21b Wallet | Link's agent wallet sends the person a spend request and returns a one-time card or a shared payment token. Limits live in Link |
| 22a Payouts | Connect onboarding, hosted by Stripe |
| 22b More info | The connected account has `requirements.currently_due` |
| 22c Selling | `payouts_enabled` is true |

## 3. Connect from Claude (section 24) in order

1. Claude opens id.org.ai's authorize URL. Claude's OAuth callback is `https://claude.ai/api/mcp/auth_callback`.
2. Sign in (1a, 1d).
3. 24a. Nothing is created in Stripe yet.
4. 24b. On "Subscribe and connect": confirm terms, create the subscription on the saved method, store the spend limit and alerts setting with the product, issue the OAuth grant.
5. If the payment needs the bank → 19e, then back to 24b's result.
6. 24c, then the redirect to Claude with the code.

If the subscription fails, issue no grant. Free plan: no Stripe call at all.

## 4. Open decisions

1. **Seller on the statement.** Each API as its own connected account, or one .do name. This picks between charging on the platform and charging on the connected account, and decides whether one saved card works across every API without extra steps.
2. **Where the agent limit is enforced.** Proposed: the product calls id.org.ai's `authorize` before every charge.
3. **When data fees bill.** Auto.dev's pricing page says only "billed monthly". Month end, or sooner past a mark.
4. **Who decides a refund:** the API or .do.
5. ~~Shared payment tokens and a monthly limit.~~ Answered in section 6: a token can be recurring with a per-period limit, but covers one seller.
6. **Third-party sellers.** Section 22 only matters if other people sell through APIs.ax.
7. **Trial for agents and connectors.** Drawn in 24b and 24c, not in 19b.
8. **Access.** Machine payments need a request to Stripe, and accepting stablecoins is limited to US businesses.

## 5. Sources read on Nov 22, 2026

- Stripe machine payments: https://docs.stripe.com/payments/machine
- Stripe shared payment tokens: https://docs.stripe.com/agentic-commerce/concepts/shared-payment-tokens
- Link's wallet for agents: https://stripe.com/blog/giving-agents-the-ability-to-pay
- Claude custom connectors: https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp
- Auto.dev pricing: https://www.auto.dev/pricing

## 6. Checked against Stripe's docs, Nov 23, 2026

Read in full: docs.stripe.com/agentic-commerce and every page under it, /payments/machine (MPP, x402, sessions), the Link agent wallet pages, /billing/subscriptions/usage-based/alerts, /elements/appearance-api and /security/guide. Most of it is preview API and the pages disagree in places (the token API version, which countries have stablecoins), so re-read before building the backend. Where this section and sections 2 to 4 differ, this section wins.

### What changes in section 2

| Screen | Was | Is |
| --- | --- | --- |
| 19a Add a payment method | We draw Card, Bank account and Link tabs above Stripe's fields | Stripe's Payment Element draws its own method tabs. Ours are gone; the picture shows Stripe's, inside the well. Which methods appear is Stripe's call at mount (Link agent payments are US and Canada only) |
| 19a, 19e | Not stated | Both pages run Stripe.js, so they are rendered with `stripe: true`, which adds Stripe's hosts to that page's security policy and no other: script `js.stripe.com`, `*.js.stripe.com`; frames those plus `hooks.stripe.com` (3DS) and `link.com`; connect `api.stripe.com`, `link.com` |
| 19e Bank confirmation | "The person completes it on Stripe's screen" | The token or payment goes to `requires_action` with `next_action.type: "use_stripe_sdk"`; the page calls `stripe.handleNextAction` and Stripe shows the bank's challenge in its own frame, then returns to `return_url` |
| 21a Pay per call | Stripe machine payments, one payment per call | Calls are counted and billed monthly on the saved method (owner direction). Nothing is charged per call, so the 0.50 USD card minimum for machine payments never applies, and no stablecoin wallet is needed |
| 21b Wallet | One waiting state; "sent to your phone" | Link asks at the `approval_url` it returns, on its site or app. The person has 30 minutes. A spend request is `created`, `pending_approval`, `requires_action`, `approved`, `submitted`, `succeeded`, `failed`, `denied`, `expired` or `canceled`. Built: waiting (with the time it runs out), denied, ran out, and "Link needs you", which shows Link's `next_action.display_message` as written |
| Spend alerts (19b, 24b, 23c) | "Stripe Billing usage alerts at each mark, or the product's own meter" | The product's own meter. Stripe's alerts count meter units, not dollars, fire once per customer (`recurrence: one_time`), and cap at 25 per meter and customer. Dollar alerts that repeat each month can't be built on them; spend alerts are early access |
| Terms (19b, 24b) | Terms and privacy | Unchanged. Stripe asks retail sellers for a return policy too; that is for physical goods. An API's refund terms live in its terms page |
| Tax | Not shown | A purchase (19c) and a subscription summary (24b) can carry a tax row when the seller charges it. Stripe computes it; the screen shows what it comes to before the person agrees |

### Shared payment tokens: what is now known

Open decision 5 is answered. A token is a grant to use the customer's payment method, scoped to **one seller** (`seller_details[network_business_profile]`), with `usage_limits[max_amount]`, `usage_limits[currency]` and `usage_limits[expires_at]`. It stays usable until it expires, is revoked (`POST /v1/shared_payment/issued_tokens/{id}/revoke`), or captured payments reach the maximum. It can be recurring (`usage_limits[recurring_interval]`, for example `month`), where the amount is the limit per period; the seller then charges it off-session. Statuses: `active`, `requires_action`, `deactivated`.

What follows for these screens:

- **The agent limit is still ours to hold.** A token covers one seller, and the agent limit covers every API the agent touches. id.org.ai issues one token per seller, never for more than what is left of the limit, and answers `authorize` itself (open decision 2 stands).
- **Pause and remove map to revoke.** Revoking is final, so resume issues a new token.
- **Revoking does not cancel a subscription with the seller.** That is why 10b keeps "Also cancel the subscription" as its own choice.
- **Availability:** US, Canada and 32 European countries.

### The Payment Element

- It is themed through the Appearance API: `variables` for colours, font and radius, and `rules` for its own parts (`.Label`, `.Input`, `.Tab`, `.Tab--selected`). The colour variables accept no `rgba()` and no `var()`, so the mount script resolves our tokens to plain colours first.
- Stripe asks for inputs of at least 16px on phones; the script uses 16px there, 14px on desktop, as our own fields do.
- **Not yet seen against Stripe.** The script and its styling are written from the docs; matching the element to the card by eye needs a test publishable key.
- The fetched pages do not say whether Appearance works with a SetupIntent or a deferred intent; Stripe now recommends the Checkout Sessions API for the Payment Element. Confirm which one 19a uses before building it.

### Not built, on purpose

- **Stablecoin and x402.** Stripe accepts x402 natively and settles it to the seller's balance, so adding it later changes nothing on the seller side. It is left out now (owner direction): nothing here charges per call, the payer would need a funded wallet, and id.org.ai does not hold money. `PaymentMethodKind` in the contract lists card, bank and Link only.
- **Seller notices.** Stripe requires product warnings at checkout when a seller supplies them (safety, Prop 65). They are for physical goods.
- **Agent checkout for physical goods** (catalog feeds, fulfilment, orders). Private preview, and not what these APIs sell.
