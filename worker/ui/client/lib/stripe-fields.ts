/**
 * Stripe's Payment Element for 19a: [data-js=stripe-fields]. Mounts only when
 * the page supplies a publishable key and a SetupIntent client secret and
 * Stripe.js is on the page; otherwise the picture stays. The element is themed
 * from the page's tokens, read at run time, so no colour is written here.
 *
 * Not yet exercised against Stripe: there is no key or backend, and the page's
 * Content-Security-Policy does not allow js.stripe.com. See docs/agent-setup/STRIPE.md.
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
  const { publishableKey, clientSecret } = box.dataset
  const mount = box.querySelector<HTMLElement>('[data-stripe-mount]')
  if (!publishableKey || !clientSecret || !make || !mount) return
  const css = getComputedStyle(box)
  const c = (t: string) => colour(box, t)
  const elements = make(publishableKey).elements({
    clientSecret,
    appearance: {
      theme: 'night',
      variables: {
        fontFamily: css.getPropertyValue('--id-font').trim(),
        fontSizeBase: '14px',
        borderRadius: css.getPropertyValue('--id-r-control').trim(),
        colorBackground: c('--id-panel'),
        colorText: c('--id-fg'),
        colorTextSecondary: c('--id-fg-2'),
        colorTextPlaceholder: c('--id-fg-3'),
        colorPrimary: c('--id-fg'),
        colorDanger: c('--id-accent'),
      },
    },
  })
  elements.create('payment', { layout: 'tabs' }).mount(mount)
  mount.hidden = false
  for (const p of box.querySelectorAll<HTMLElement>('[data-stripe-picture]')) p.hidden = true
}
