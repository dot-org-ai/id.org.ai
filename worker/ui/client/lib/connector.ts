/**
 * The connector's states and timings (docs/product-update/spec/motion.md).
 * The markup never changes between states: setConnector swaps data-state and
 * restarts the animations, and CSS (ui.css, "Connector") does the rest.
 */

export type ConnectorState = 'idle' | 'connecting' | 'done' | 'broken' | 'ok' | 'fail'

/** Pulse period. */
export const WAVE = 2000
/** Stagger per dot. */
export const ST = 155
/** Time for a dot to reach its peak (14% of WAVE). */
export const RISE = 280
/** RISE + 4 × ST: the pulse leaves the first dot and lands on the last. */
export const CROSS = 900
/** One-shot states start after a beat. */
export const T0 = 200
/** CROSS + 50: the success verdict lands just after the pulse. */
export const S_AT = 950
/** RISE + 2 × ST + 30: the failure verdict lands as the pulse peaks on the middle dot. */
export const F_AT = 620
/** Verdict plus a 0.6s hold, before the done content swaps in. */
export const SUCCESS_SWAP_MS = T0 + S_AT + 400 + 600
/** Failure verdict plus the hold, before the cancelled or error content swaps in. */
export const FAIL_SWAP_MS = T0 + F_AT + 400 + 600

/** Switch a connector (or the first one inside `root`) to `state`, restarting its animations. */
export function setConnector(root: Element, state: ConnectorState): void {
  const el = (root.matches('[data-js=connector]') ? root : root.querySelector('[data-js=connector]')) as HTMLElement | null
  if (!el) return
  el.removeAttribute('data-state')
  // Force a style flush so a repeated state (or one sharing keyframes) restarts from zero.
  void el.offsetWidth
  el.setAttribute('data-state', state)
}

export function connectorState(root: Element): ConnectorState | null {
  const el = root.matches('[data-js="connector"]') ? root : root.querySelector('[data-js="connector"]')
  return (el?.getAttribute('data-state') as ConnectorState | null) ?? null
}
