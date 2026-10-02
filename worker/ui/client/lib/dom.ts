/** Shared helpers for the client scripts. Imported, never an entry point of its own. */

/**
 * The design gallery renders `<html data-frozen>`: scripts must not start timers,
 * poll, redirect or autofocus there (docs/product-update/prompts/01-foundation.md#gallery-contract).
 */
export function isFrozen(): boolean {
  return document.documentElement.hasAttribute('data-frozen')
}

/**
 * Enter on a radio or checkbox would submit the form with its first submit
 * button, which in an action band is the secondary (Cancel, Deny, Decline,
 * Reject). Choosing an option never submits.
 */
export function guardEnter(form: HTMLFormElement): void {
  form.addEventListener('keydown', (e) => {
    const type = (e.target as HTMLInputElement).type
    if (e.key === 'Enter' && (type === 'radio' || type === 'checkbox')) e.preventDefault()
  })
}

/**
 * Run `init` on every `[data-js="<name>"]` element, once each. The scripts are
 * `type="module"`, which always run after the document is parsed, so there's
 * no DOMContentLoaded to wait for.
 */
export function enhance<T extends HTMLElement>(name: string, init: (el: T) => void): void {
  for (const el of document.querySelectorAll<T>(`[data-js="${name}"]`)) {
    if (el.dataset.jsReady) continue
    el.dataset.jsReady = '1'
    init(el)
  }
}
