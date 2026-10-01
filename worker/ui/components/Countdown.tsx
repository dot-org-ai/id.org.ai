import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon } from '../icons'

/** m:ss with no leading zero on minutes ("4:32", "0:42"). */
export function formatCountdown(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}

export interface CountdownProps {
  /** Seconds left, computed on the server (the client counts down from it, never from its own clock). */
  secondsLeft: number
  /** 5b: accent at <=60s, and announced at 60s and at expiry. */
  urgent?: boolean
  /** 5b: the <template data-state> that replaces the card at 0. */
  expiredTemplate?: string
}

/**
 * The 5b header countdown: clock + "4:32 left" (components.md#countdown-5b-header-right).
 * countdown.ts ticks it; frozen in the gallery. Rendered accent server-side
 * when it starts at 60s or less, so the gallery can show the urgent state.
 */
export function Countdown({ secondsLeft, urgent, expiredTemplate }: CountdownProps): JSX.Element {
  return (
    <span
      class="id-countdown"
      data-js="countdown"
      data-seconds-left={String(Math.max(0, Math.floor(secondsLeft)))}
      data-suffix=" left"
      data-urgent-at={urgent ? '60' : undefined}
      data-urgent={urgent && secondsLeft <= 60 ? '' : undefined}
      data-announce={urgent ? '' : undefined}
      data-expired-template={expiredTemplate}
    >
      <Icon name="clock" size={14} />
      <span data-countdown-text>{`${formatCountdown(secondsLeft)} left`}</span>
    </span>
  )
}

/**
 * 1b's resend timer: "Resend in 0:42" (m:ss, always fg-3), which becomes the
 * "Resend code" button at 0. Quiet: no announcements, never urgent.
 */
export function ResendTimer({ secondsLeft, children }: { secondsLeft: number; children: JSX.Element }): JSX.Element {
  return (
    <div class="id-resend">
      <span data-js="countdown" data-seconds-left={String(Math.max(0, Math.floor(secondsLeft)))} hidden={secondsLeft <= 0 ? true : undefined}>
        {'Resend in '}
        <span data-countdown-text>{formatCountdown(secondsLeft)}</span>
      </span>
      <span data-countdown-done hidden={secondsLeft > 0 ? true : undefined}>
        {children}
      </span>
    </div>
  )
}
