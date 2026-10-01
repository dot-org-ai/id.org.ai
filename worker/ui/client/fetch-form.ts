/**
 * Forms that stay on id.org.ai, including 4b's device-confirm state machine:
 * fetch, verdict, then the server-rendered template swaps in (lib/fetch-form.ts).
 */
import { enhance, guardEnter, isFrozen } from './lib/dom'
import { initFetchForm } from './lib/fetch-form'

enhance<HTMLFormElement>('fetch-form', (form) => {
  guardEnter(form)
  if (!isFrozen()) initFetchForm(form)
})
