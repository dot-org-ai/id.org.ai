/**
 * 5d · live claim-by-commit status: polls data-status-url every 5s and maps
 * unclaimed → waiting, pending → pending on a branch, claimed → claimed. The
 * status list updates in place and the connector goes connecting → done → ok.
 * Frozen pages never poll.
 */
import { setConnector } from './connector'

export const POLL_MS = 5000
const ORDER = ['unclaimed', 'pending', 'claimed'] as const
type ClaimStatus = (typeof ORDER)[number]

/** Mark the list row for `status` current, the rest upcoming (or done when past). */
export function applyStatus(root: Element, status: ClaimStatus): void {
  const rows = Array.from(root.querySelectorAll('.id-status'))
  const at = ORDER.indexOf(status)
  rows.forEach((row, i) => row.classList.toggle('id-status--current', i === at))
}

export function initClaimStatus(root: HTMLElement, fetchImpl: typeof fetch = fetch, every: (fn: () => void, ms: number) => () => void = (fn, ms) => {
  const t = setInterval(fn, ms)
  return () => clearInterval(t)
}): void {
  const url = root.dataset.statusUrl
  if (!url) return
  const card = root.closest('.id-card') ?? document
  let last: ClaimStatus | null = null
  let stop: () => void = () => {}
  const poll = async () => {
    try {
      const res = await fetchImpl(url, { headers: { Accept: 'application/json' }, credentials: 'same-origin' })
      const json = (await res.json()) as { status?: string }
      const status = json.status as ClaimStatus
      if (!ORDER.includes(status) || status === last) return
      last = status
      applyStatus(root, status)
      if (status === 'claimed') {
        stop()
        setConnector(card instanceof Element ? card : document.documentElement, 'done')
      }
    } catch {
      // Keep polling; a blip shouldn't end the page.
    }
  }
  stop = every(() => void poll(), POLL_MS)
}

