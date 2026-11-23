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
  const { publishableKey, clientSecret } = box.dataset
  const mount = box.querySelector<HTMLElement>('[data-stripe-mount]')
  if (!publishableKey || !clientSecret || !make || !mount) return
  const css = getComputedStyle(box)
  const c = (t: string) => colour(box, t)
  const v = (t: string) => css.getPropertyValue(t).trim()
  const edge = `1px solid ${c('--id-line-2')}`
  const field = { backgroundColor: c('--id-panel'), border: edge, boxShadow: 'none' }
  const elements = make(publishableKey).elements({
    clientSecret,
    appearance: {
      theme: 'night',
      variables: {
        fontFamily: v('--id-font'),
        // Stripe asks for 16px inputs on phones (iOS zooms below that), as our own fields use.
        fontSizeBase: matchMedia('(max-width: 480px), (pointer: coarse)').matches ? '16px' : '14px',
        borderRadius: v('--id-r-control'),
        colorBackground: c('--id-panel'),
        colorText: c('--id-fg'),
        colorTextSecondary: c('--id-fg-2'),
        colorTextPlaceholder: c('--id-fg-3'),
        colorPrimary: c('--id-fg'),
        colorDanger: c('--id-accent'),
      },
      // The element's own parts, matched to ours: labels, fields, and its method tabs as the segmented cells.
      rules: {
        '.Label': { fontSize: '13px', fontWeight: '500', color: c('--id-fg-2') },
        '.Input': field,
        '.Input:focus': { ...field, borderColor: c('--id-fg') },
        '.Tab': { ...field, backgroundColor: 'transparent', borderColor: 'transparent', color: c('--id-fg-2') },
        '.Tab--selected': { ...field, backgroundColor: c('--id-raised'), color: c('--id-fg') },
      },
    },
  })
  elements.create('payment', { layout: 'tabs' }).mount(mount)
  mount.hidden = false
  for (const p of box.querySelectorAll<HTMLElement>('[data-stripe-picture]')) p.hidden = true
}
