/**
 * Countdowns (components.md#countdown-5b-header-right): [data-js=countdown][data-expires-at].
 * Ticks every second in m:ss ("4:32 left"); with data-urgent-at="60" it turns
 * accent at <=60s (5b only). Announces once at 60s and at 0 through the page's
 * status region, then: data-expired-template swaps that template into the
 * card (5b's expired state), and a [data-countdown-done] sibling is revealed
 * (1b's "Resend code" link). Frozen pages never tick.
 */
import { initCountdown } from './lib/countdown'
import { enhance, isFrozen } from './lib/dom'

enhance('countdown', (el) => {
  if (!isFrozen()) initCountdown(el)
})
