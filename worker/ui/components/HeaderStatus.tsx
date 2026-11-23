import type { JSX } from 'hono/jsx/jsx-runtime'

export interface HeaderStatusProps {
  /** `ok`: green, the setup is moving. `warn`: amber, it needs someone. */
  tone: 'ok' | 'warn'
  /** "Updated", "Last seen": what happened `seconds` ago. */
  verb: string
  /** Seconds since the last event, computed on the server (ago.ts counts up from it). */
  seconds: number
}

/** 4 → "4s ago", 600 → "10 min ago", 7200 → "2 h ago". */
export function formatAgo(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  return `${Math.floor(s / 3600)} h ago`
}

/**
 * The setup page's header status: a dot and "Updated 4s ago" in the header's
 * right slot. ago.ts ticks it every second from the last event; it is frozen
 * in the gallery.
 */
export function HeaderStatus({ tone, verb, seconds }: HeaderStatusProps): JSX.Element {
  return (
    <span class="id-hstatus" data-js="ago" data-seconds={String(Math.max(0, Math.floor(seconds)))} data-verb={verb}>
      <span class={tone === 'ok' ? 'id-sdot' : 'id-sdot id-sdot--warn'} aria-hidden="true"></span>
      <span data-ago-text>{`${verb} ${formatAgo(seconds)}`}</span>
    </span>
  )
}
