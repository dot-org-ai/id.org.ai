/**
 * Forms that leave id.org.ai: busy label and connector, then the normal post
 * (lib/leave.ts). A page restored from the back/forward cache reloads, so it
 * never comes back busy.
 */
import { enhance, guardEnter, isFrozen } from './lib/dom'
import { initLeave } from './lib/leave'

enhance<HTMLFormElement>('submit', (form) => {
  guardEnter(form)
  if (!isFrozen()) initLeave(form)
})
addEventListener('pageshow', (e) => {
  if ((e as PageTransitionEvent).persisted) location.reload()
})
