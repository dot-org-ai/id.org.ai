/**
 * Shared form behaviour (docs/product-update/spec/motion.md#where-the-person-goes-next):
 * the busy button, disabling the rest, and keeping the clicked submitter's
 * value once it is disabled.
 */

/** The primary submit (the one with a progressive label) goes busy; every other action button is disabled. */
export function setBusy(form: HTMLFormElement, busyButton: HTMLButtonElement | null): void {
  for (const b of form.querySelectorAll<HTMLButtonElement>('button')) {
    if (b === busyButton) {
      b.disabled = true
      b.setAttribute('aria-busy', 'true')
      const label = b.dataset.busyLabel
      const span = b.querySelector('span:last-child')
      if (label && span) span.textContent = label
    } else if (b.closest('[data-actions]') || b.type === 'submit') {
      b.disabled = true
    }
  }
}

/** Keep the clicked submitter's name/value in the post after the button is disabled. */
export function keepSubmitter(form: HTMLFormElement, submitter: HTMLButtonElement | null): void {
  if (!submitter?.name) return
  const hidden = document.createElement('input')
  hidden.type = 'hidden'
  hidden.name = submitter.name
  hidden.value = submitter.value
  form.appendChild(hidden)
}
