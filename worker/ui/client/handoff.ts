/**
 * 2c · Handing off: replace this page with the app on the next frame. The
 * <meta http-equiv="refresh"> in the head is the no-JS fallback (1s), and the
 * foot link is the manual one. Frozen gallery pages never redirect.
 */
import { enhance, isFrozen } from './lib/dom'

enhance('handoff', (el) => {
  const target = el.dataset.target
  if (!isFrozen() && target) requestAnimationFrame(() => location.replace(target))
})
