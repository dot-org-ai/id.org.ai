/**
 * Countdowns (components.md#countdown-5b-header-right): [data-js=countdown][data-expires-at].
 * Ticks every second in m:ss ("4:32 left"); with data-urgent-at="60" it turns
 * accent at <=60s (5b only). Announces once at 60s and at 0 through the page's
 * status region, then: data-expired-template swaps that template into the
 * card (5b's expired state), and a [data-countdown-done] sibling is revealed
 * (1b's "Resend code" link). Frozen pages never tick.
 */

export function formatCountdown(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}

export function initCountdown(el: HTMLElement, now: () => number = Date.now): void {
  const expiresAt = Date.parse(el.dataset.expiresAt ?? '')
  if (!Number.isFinite(expiresAt)) return
  const text = el.querySelector('[data-countdown-text]') ?? el
  const suffix = el.dataset.suffix ?? ''
  const urgentAt = el.dataset.urgentAt ? Number(el.dataset.urgentAt) : null
  const status = document.querySelector('[data-status]')
  let announced60 = false
  let timer: ReturnType<typeof setInterval> | undefined

  const tick = () => {
    const left = Math.ceil((expiresAt - now()) / 1000)
    text.textContent = `${formatCountdown(left)}${suffix}`
    if (urgentAt !== null && left <= urgentAt) el.setAttribute('data-urgent', '')
    if (left <= 60 && left > 0 && !announced60) {
      announced60 = true
      if (status) status.textContent = 'One minute left.'
    }
    if (left <= 0) {
      if (timer) clearInterval(timer)
      if (status) status.textContent = 'This request expired.'
      const done = el.parentElement?.querySelector<HTMLElement>('[data-countdown-done]')
      if (done) {
        done.hidden = false
        el.hidden = true
      }
      const tplName = el.dataset.expiredTemplate
      if (tplName) {
        const tpl = document.querySelector<HTMLTemplateElement>(`template[data-state="${tplName}"]`)
        const card = document.querySelector('.id-card')
        if (tpl && card) card.replaceWith(tpl.content.cloneNode(true))
      }
    }
  }
  tick()
  timer = setInterval(tick, 1000)
}

