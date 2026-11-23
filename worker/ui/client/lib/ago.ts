/**
 * The setup page's header status: [data-js=ago][data-seconds][data-verb].
 * Counts up every second from the server's figure ("Updated 4s ago"), never
 * from the client clock. Frozen pages never tick.
 */
import { isFrozen } from './dom'

/** 4 → "4s ago", 600 → "10 min ago", 7200 → "2 h ago" (the same wording as HeaderStatus.tsx). */
export function formatAgo(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  return `${Math.floor(s / 3600)} h ago`
}

export function initAgo(el: HTMLElement): void {
  const text = el.querySelector<HTMLElement>('[data-ago-text]')
  if (!text || isFrozen()) return
  let seconds = Number(el.dataset.seconds ?? 0)
  setInterval(() => {
    seconds += 1
    text.textContent = `${el.dataset.verb ?? ''} ${formatAgo(seconds)}`
  }, 1000)
}
