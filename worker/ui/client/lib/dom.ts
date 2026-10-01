/** Shared helpers for the client scripts. Imported, never an entry point of its own. */

/**
 * The design gallery renders `<html data-frozen>`: scripts must not start timers,
 * poll, redirect or autofocus there (docs/product-update/prompts/01-foundation.md#gallery-contract).
 */
export function isFrozen(doc: Document = document): boolean {
  return doc.documentElement.hasAttribute('data-frozen')
}

/** Run `init` on every `[data-js="<name>"]` element once the DOM is parsed. */
export function enhance<T extends HTMLElement>(name: string, init: (el: T) => void): void {
  const run = () => {
    for (const el of document.querySelectorAll<T>(`[data-js="${name}"]`)) {
      if (el.dataset.jsReady === '1') continue
      el.dataset.jsReady = '1'
      init(el)
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', run, { once: true })
  else run()
}
