/**
 * Disclosure buttons: button[data-js=disclose][aria-controls]. Shows or hides
 * the panel it controls and keeps aria-expanded in step. Used where the
 * disclosure must be its own control (a plan card's chevron beside its radio,
 * the spend alerts chevron beside its switch), so a native <details>, whose
 * whole summary toggles, won't do.
 */
export function initDisclose(btn: HTMLButtonElement): void {
  const panel = document.getElementById(btn.getAttribute('aria-controls') ?? '')
  if (!panel) return
  btn.addEventListener('click', () => {
    const open = btn.getAttribute('aria-expanded') !== 'true'
    btn.setAttribute('aria-expanded', String(open))
    panel.hidden = !open
  })
}
