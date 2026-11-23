/** Action labels that follow a choice (plans, limits): see lib/follow.ts. */
import { guardEnter, enhance } from './lib/dom'
import { initFollow } from './lib/follow'

enhance('follow', (el) => {
  initFollow(el)
  const form = el.closest('form')
  if (form) guardEnter(form)
})
