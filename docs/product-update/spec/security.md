# Security requirements for every auth page

These apply to every new or rewritten screen. They are review gates: a phase is not done while any of them fails.

## Headers (set them in the shared `renderPage()`)

```
Cache-Control: no-store
X-Frame-Options: DENY
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Content-Security-Policy:
  default-src 'none';
  style-src 'self';
  script-src 'self';
  img-src 'self' https: data:;
  font-src 'self';
  connect-src 'self';
  form-action 'self' <the validated redirect origin when this page posts or redirects to it>;
  frame-ancestors 'none';
  base-uri 'none'
```

- **No inline scripts or styles.** Styles come from `/auth/ui.<hash>.css` and scripts from `/auth/<name>.<hash>.js`. This is why the mocks' inline `style` attributes are a reference for values, not markup to copy.
- If some inline style is truly needed (for example a CSS variable for a computed value), use a per-response nonce. Never use `'unsafe-inline'`.
- `img-src https:` is there for CIMD `logo_uri` and provider avatars. Logos are rendered as `<img>` with `referrerpolicy="no-referrer"`, `decoding="async"` and fixed dimensions, and never as CSS backgrounds.
- `form-action` must allow the OAuth redirect target, because the consent POST answers with a redirect to the client.
  - Compute it per response from the already-validated `redirect_uri` origin.
  - Test it, because browsers apply `form-action` to redirects after a form submission.

## Forms

- Every state-changing POST carries a CSRF token: the double-submit cookie plus a server-side single-use record, as consent does today (`worker/routes/oauth.ts`). This includes device decisions, chooser posts, sign out, invitations, approvals, claim and passkeys.
- `SameSite=Lax` cookies alone are not enough.
- Fetch submissions send the token in a header (`X-CSRF-Token`) and get JSON back. The server accepts either form, but only one per request (reject duplicates, as consent does).
- Do not rely on the Origin header alone. It is absent on some navigations.

## Output

- JSX escapes text by default. Never use `dangerouslySetInnerHTML` / `raw()` with request data.
- Scope strings, client names, hosts, emails and error details are all request data.
- Never render a rejected `redirect_uri` as a link (7a).
- Show the CIMD host as the app's name for unverified clients. The self-asserted `client_name` is display text only for verified clients.

## Redirects

- Every `continue`, `return_url`, `post_logout_redirect_uri` and resume URL goes through `resolveBrowserRedirect` (`worker/utils/relying-parties.ts`) in **enforce** mode, including on new routes, whatever the global `LOGIN_CONTINUE_POLICY` says.
- Step-up and consent resume URLs are server-side single-use records (`takeOnce`), never a client-supplied URL.

## Codes and budgets

- Reuse `consumeBudget` and `takeOnce` for every code flow (email code, step-up code, TOTP, device decision).
- Budgets per path. Sends: 5 per email per hour. Guesses: 5 per flow, 5 per email per 15 minutes, 50 per IP per hour.
- Error copy never reveals whether an account exists ("If that address has an account, we sent a code").

## Copy button

- Copy only values that are already visible on the page.
- Never put secrets (tokens, codes) in a copy action or the clipboard. The device code and claim token are fine: they are already shown to the person.

## Logging

- Log the request ID, route, outcome and identity ID.
- Never log codes, tokens, full emails (hash or mask them) or IP addresses beyond what the audit service already stores.
