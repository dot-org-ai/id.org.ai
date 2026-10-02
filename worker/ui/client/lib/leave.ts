/**
 * Forms that leave id.org.ai (consent Allow, choosers, sign-in, step-up;
 * spec/motion.md#where-the-person-goes-next): on submit the connector goes
 * `connecting` (when the submitter has a progressive label, or the form has
 * data-connect), the clicked primary goes busy, every button is disabled, and
 * the browser posts and follows the redirect (D7: no verdict before leaving).
 * The submitter's name/value survive the disabling. Without JS the form posts.
 */
import { setConnector } from './connector'

/** A Button's last child is always its label span (components/Button.tsx). */
export function busy(btn: HTMLButtonElement, label: string): void {
  btn.setAttribute('aria-busy', 'true')
  btn.lastElementChild!.textContent = label
}

export function initLeave(form: HTMLFormElement): void {
  const card = form.closest('.id-card') ?? form.querySelector('.id-card') ?? form
  form.addEventListener('submit', (e) => {
    const btn = (e as SubmitEvent).submitter as HTMLButtonElement | null
    const label = btn?.dataset.busyLabel
    if (btn?.name) form.append(Object.assign(document.createElement('input'), { type: 'hidden', name: btn.name, value: btn.value }))
    if (label || form.hasAttribute('data-connect')) setConnector(card, 'connecting')
    for (const b of form.querySelectorAll('button')) b.disabled = true
    if (btn && label) busy(btn, label)
  })
}
