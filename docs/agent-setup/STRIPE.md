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
5. **Shared payment tokens and a monthly limit.** Stripe's overview describes a token as covering a single transaction; the token docs mention usage limits and expiry. Unconfirmed whether one token can back a month.
6. **Third-party sellers.** Section 22 only matters if other people sell through APIs.ax.
7. **Trial for agents and connectors.** Drawn in 24b and 24c, not in 19b.
8. **Access.** Machine payments need a request to Stripe, and accepting stablecoins is limited to US businesses.

## 5. Sources read on Nov 22, 2026

- Stripe machine payments: https://docs.stripe.com/payments/machine
- Stripe shared payment tokens: https://docs.stripe.com/agentic-commerce/concepts/shared-payment-tokens
- Link's wallet for agents: https://stripe.com/blog/giving-agents-the-ability-to-pay
- Claude custom connectors: https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp
- Auto.dev pricing: https://www.auto.dev/pricing
