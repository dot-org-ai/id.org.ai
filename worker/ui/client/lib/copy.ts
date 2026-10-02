/**
 * Copy buttons (components.md#copy-button): [data-js=copy][data-value].
 * Unhides itself (hidden without JS), writes the clipboard, shows the green
 * check and announces "Copied" for 1.5s; a second click restarts the timer.
 * Never resets a server-rendered copied state; frozen pages never time out.
 */
import { isFrozen } from './dom'

export const COPIED_MS = 1500

export function initCopy(btn: HTMLButtonElement, clipboard: Pick<Clipboard, 'writeText'> = navigator.clipboard): void {
  btn.hidden = false
  const status = btn.nextElementSibling?.matches('[role="status"]') ? btn.nextElementSibling : null
  let timer: ReturnType<typeof setTimeout> | undefined
  btn.addEventListener('click', async () => {
    try {
      await clipboard.writeText(btn.dataset.value ?? '')
    } catch {
      return
    }
    btn.setAttribute('data-copied', '')
    if (status) status.textContent = 'Copied'
    if (timer) clearTimeout(timer)
    if (isFrozen()) return
    timer = setTimeout(() => {
      btn.removeAttribute('data-copied')
      if (status) status.textContent = ''
      timer = undefined
    }, COPIED_MS)
  })
}

