import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon } from '../icons'

/** m:ss with no leading zero on minutes ("4:32", "0:42"). */
export function formatCountdown(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}

/**
 * The 5b header countdown: clock + "4:32 left". countdown.ts ticks it, turns
 * it accent at <=60s (urgent) and swaps to the expired state at 0. Frozen in
 * the gallery.
 */
export function Countdown({ expiresAt, secondsLeft, urgent }: { expiresAt: string; secondsLeft: number; urgent?: boolean }): JSX.Element {
  return (
    <span class="id-countdown" data-js="countdown" data-expires-at={expiresAt} data-suffix=" left" data-urgent-at={urgent ? '60' : undefined}>
      <Icon name="clock" size={14} />
      <span data-countdown-text>{`${formatCountdown(secondsLeft)} left`}</span>
    </span>
  )
}
