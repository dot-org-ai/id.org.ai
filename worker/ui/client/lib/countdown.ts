/**
 * Countdowns (components.md#countdown-5b-header-right): [data-js=countdown][data-seconds-left].
 * Ticks every second in m:ss ("4:32 left") from the server-rendered seconds
 * left, so a skewed client clock can't expire a page early. With
 * data-urgent-at="60" it turns accent at <=60s (5b only). With data-announce
 * it announces once at 60s and at 0 through the page's status region (5b; the
 * 1b resend timer stays quiet). At 0: data-expired-template swaps that
 * template in for the card (5b's expired state), and a [data-countdown-done]
 * sibling is revealed (1b's "Resend code"). Frozen pages never tick.
 */

export function formatCountdown(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}

export function initCountdown(el: HTMLElement, now: () => number = () => performance.now()): void {
  const secondsLeft = Number(el.dataset.secondsLeft)
  if (!Number.isFinite(secondsLeft)) return
  const deadline = now() + secondsLeft * 1000
  const text = el.querySelector('[data-countdown-text]') ?? el
  const suffix = el.dataset.suffix ?? ''
  const urgentAt = el.dataset.urgentAt ? Number(el.dataset.urgentAt) : null
  const status = el.hasAttribute('data-announce') ? document.querySelector('[data-status]') : null
  let announced60 = false
  let timer: ReturnType<typeof setInterval> | undefined

  const tick = () => {
    const left = Math.ceil((deadline - now()) / 1000)
    text.textContent = `${formatCountdown(left)}${suffix}`
    if (urgentAt !== null && left <= urgentAt) el.setAttribute('data-urgent', '')
    if (left <= 60 && left > 0 && !announced60) {
      announced60 = true
      if (status) status.textContent = 'One minute left.'
    }
    if (left <= 0) {
      clearInterval(timer)
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
