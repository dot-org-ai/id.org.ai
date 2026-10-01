/**
 * Forms that stay on id.org.ai, including 4b's device-confirm state machine:
 * fetch, verdict, then the server-rendered template swaps in (lib/fetch-form.ts).
 */
import { enhance, isFrozen } from './lib/dom'
import { initFetchForm } from './lib/fetch-form'

enhance<HTMLFormElement>('fetch-form', (form) => {
  if (!isFrozen()) initFetchForm(form)
})
addEventListener('pageshow', (e) => {
  if ((e as PageTransitionEvent).persisted) location.reload()
})
