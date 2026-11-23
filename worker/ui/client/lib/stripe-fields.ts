/**
 * Stripe's Payment Element for 19a: [data-js=stripe-fields]. Mounts only when
 * the page supplies a publishable key and a SetupIntent client secret and
 * Stripe.js is on the page; otherwise the picture stays. The element is themed
 * from the page's tokens, read at run time, so no colour is written here.
 *
 * Not yet rendered against Stripe: there is no key or backend. The appearance follows
 * docs.stripe.com/elements/appearance-api (colour variables take no rgba() or var(), so
 * tokens are resolved to plain colours here); the look still has to be checked by eye with a
 * test key. The page must be rendered with `stripe: true` so its security policy admits
 * Stripe's hosts. See docs/agent-setup/STRIPE.md.
 */
interface StripeLike {
  elements(o: unknown): { create(type: 'payment', o?: unknown): { mount(el: Element): void } }
}

/** Any CSS colour as plain rgb() or rgba(), by painting one pixel and reading it back. */
function plain(colour: string): string {
  const ctx = document.createElement('canvas').getContext('2d', { willReadFrequently: true })
  if (!ctx) return colour
  ctx.fillStyle = colour
  ctx.fillRect(0, 0, 1, 1)
  const [r, g, b, a] = ctx.getImageData(0, 0, 1, 1).data
  return a === 255 ? `rgb(${r}, ${g}, ${b})` : `rgba(${r}, ${g}, ${b}, ${+((a ?? 0) / 255).toFixed(3)})`
}

/**
 * The appearance the server wrote against our tokens, made readable to Stripe: each
 * `var(--id-…)` becomes the token's value, and every oklch() colour becomes rgb()/rgba().
 */
export function resolveAppearance(json: string, css: CSSStyleDeclaration): unknown {
  return JSON.parse(json, (_k, v) =>
    typeof v === 'string' ? v.replace(/var\((--[\w-]+)\)/g, (_m, t: string) => css.getPropertyValue(t).trim()).replace(/oklch\([^)]*\)/g, plain) : v,
  )
}

export function initStripeFields(box: HTMLElement, make = (window as unknown as { Stripe?: (key: string) => StripeLike }).Stripe): void {
  const { publishableKey, clientSecret, mode, appearance: json } = box.dataset
  const mount = box.querySelector<HTMLElement>('[data-stripe-mount]')
  if (!publishableKey || !(clientSecret || mode) || !make || !mount || !json) return
  const appearance = resolveAppearance(json, getComputedStyle(box)) as { variables: Record<string, string>; rules: Record<string, Record<string, string>> }
  // Stripe asks for 16px inputs on phones (iOS zooms below that); our own fields are 16px and 48px tall there.
  if (matchMedia('(max-width: 480px), (pointer: coarse)').matches) {
    appearance.variables.fontSizeBase = '16px'
    for (const k in appearance.rules) if (k.startsWith('.Input')) appearance.rules[k]!.padding = '14px 14px'
  }
  const elements = make(publishableKey).elements({
    // A client secret when the intent exists; otherwise Stripe renders ahead of it (deferred),
    // offering only what an agent can be allowed to charge later.
    ...(clientSecret ? { clientSecret } : { mode, currency: 'usd', paymentMethodTypes: ['card', 'us_bank_account', 'link'] }),
    // Geist inside Stripe's frame, from our own origin (the font files allow cross-origin use).
    fonts: [{ family: 'Geist', src: 'url(https://id.org.ai/fonts/geist/Geist-Variable.woff2)', weight: '100 900' }],
    appearance,
  })
  // No `terms` option: Stripe's mandate under the card fields is the consent for charging later
  // (19a carries no sentence of its own for it), so it must always show.
  elements.create('payment', { layout: 'tabs' }).mount(mount)
  mount.hidden = false
  for (const p of box.querySelectorAll<HTMLElement>('[data-stripe-picture]')) p.hidden = true
}
