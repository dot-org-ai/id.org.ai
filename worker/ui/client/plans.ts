/** The plan picker (24a): see lib/plans.ts. */
import { guardEnter, enhance } from './lib/dom'
import { initPlans } from './lib/plans'

enhance('plans', (el) => {
  initPlans(el)
  const form = el.closest('form')
  if (form) guardEnter(form)
})
