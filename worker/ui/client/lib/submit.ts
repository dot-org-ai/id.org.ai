/**
 * Forms that leave id.org.ai (consent Allow, choosers, sign-in, step-up):
 * [data-js=submit]. On submit the connector goes `connecting` and the clicked
 * primary goes busy with its progressive label; the form then posts normally
 * and the browser follows the redirect (D7: no verdict before leaving).
 * Without JS the form simply posts.
 */
import { setConnector } from './connector'
import { keepSubmitter, setBusy } from './form'

export function initSubmit(form: HTMLFormElement): void {
  form.addEventListener('submit', (e) => {
    const submitter = (e as SubmitEvent).submitter instanceof HTMLButtonElement ? ((e as SubmitEvent).submitter as HTMLButtonElement) : null
    keepSubmitter(form, submitter)
    const card = form.closest('.id-card') ?? form
    if (submitter?.dataset.busyLabel) setConnector(card, 'connecting')
    setBusy(form, submitter?.dataset.busyLabel ? submitter : null)
  })
}

