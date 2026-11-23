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

/** A token's colour as rgb()/hex, which Stripe's appearance settings accept (tokens are oklch). */
function colour(el: Element, token: string): string {
  const ctx = document.createElement('canvas').getContext('2d')
  if (!ctx) return ''
  ctx.fillStyle = getComputedStyle(el).getPropertyValue(token).trim()
  return ctx.fillStyle
}

export function initStripeFields(box: HTMLElement, make = (window as unknown as { Stripe?: (key: string) => StripeLike }).Stripe): void {
  const { publishableKey, clientSecret, mode } = box.dataset
  const mount = box.querySelector<HTMLElement>('[data-stripe-mount]')
  if (!publishableKey || !(clientSecret || mode) || !make || !mount) return
  const css = getComputedStyle(box)
  const c = (t: string) => colour(box, t)
  const v = (t: string) => css.getPropertyValue(t).trim()
  const phone = matchMedia('(max-width: 480px), (pointer: coarse)').matches
  const line = c('--id-line-2')
  const flat = { boxShadow: 'none', outline: 'none' }
  const field = { ...flat, backgroundColor: c('--id-panel'), border: `1px solid ${line}`, padding: phone ? '13px 14px' : '12px 14px', lineHeight: '18px' }
  const tab = { ...flat, backgroundColor: 'transparent', border: '1px solid transparent', color: c('--id-fg-2'), padding: '8px 12px' }
  const tabOn = { ...tab, backgroundColor: c('--id-raised'), borderColor: line, color: c('--id-fg') }
  const elements = make(publishableKey).elements({
    // A client secret when the intent exists; otherwise Stripe renders ahead of it (deferred),
    // offering only what an agent can be allowed to charge later.
    ...(clientSecret ? { clientSecret } : { mode, currency: 'usd', paymentMethodTypes: ['card', 'us_bank_account', 'link'] }),
    // Geist inside Stripe's frame, from our own origin (the font files allow cross-origin use).
    fonts: [{ family: 'Geist', src: 'url(https://id.org.ai/fonts/geist/Geist-Variable.woff2)', weight: '100 900' }],
    appearance: {
      theme: 'night',
      variables: {
        fontFamily: v('--id-font'),
        // Stripe asks for 16px inputs on phones (iOS zooms below that), as our own fields use.
        fontSizeBase: phone ? '16px' : '14px',
        fontSizeSm: '13px',
        borderRadius: v('--id-r-control'),
        gridRowSpacing: '12px',
        gridColumnSpacing: '12px',
        colorBackground: c('--id-panel'),
        colorText: c('--id-fg'),
        colorTextSecondary: c('--id-fg-2'),
        colorTextPlaceholder: c('--id-fg-3'),
        colorPrimary: c('--id-fg'),
        colorDanger: c('--id-accent'),
        iconColor: c('--id-fg-3'),
      },
      // The element's own parts, matched to ours: labels, fields, and its method tabs as the segmented cells.
      rules: {
        '.Label': { fontSize: '13px', fontWeight: '500', color: c('--id-fg-2'), marginBottom: '6px' },
        '.Input': field,
        '.Input:focus': { ...field, borderColor: c('--id-fg-2') },
        '.Tab': tab,
        '.Tab:hover': { ...tab, color: c('--id-fg') },
        '.Tab--selected': tabOn,
        '.Tab--selected:focus': tabOn,
        '.TabLabel': { fontSize: '13px', fontWeight: '500' },
      },
    },
  })
  elements.create('payment', { layout: 'tabs' }).mount(mount)
  mount.hidden = false
  for (const p of box.querySelectorAll<HTMLElement>('[data-stripe-picture]')) p.hidden = true
}
