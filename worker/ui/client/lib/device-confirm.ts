/**
 * 4b · the device-confirm state machine (spec/motion.md#device-confirm-4b-the-reference-state-machine).
 *
 *   idle ─Confirm→ connecting ─OK→ done ─2150ms→ signed
 *                      └─error→ broken ─1820ms→ error content
 *   idle ─Cancel→ cancelling (broken, both disabled) ─1820ms and deny OK→ cancelled
 *                                                     └─deny failed→ error content
 *
 * The server renders the signed, cancelled and error bodies and feet into
 * <template data-state> elements; this swaps them into [data-region]. Without
 * JS the form posts and the server answers with 4d or the cancelled page.
 */
import { FAIL_SWAP_MS, SUCCESS_SWAP_MS, setConnector } from './connector'

export interface DeviceConfirmDeps {
  /** POST the decision; resolves true only for { ok: true }. */
  post: (form: HTMLFormElement, decision: 'approve' | 'deny') => Promise<boolean>
  later: (fn: () => void, ms: number) => void
}

/** fetch with the CSRF token in X-CSRF-Token and not in the body (the server refuses both). */
export async function postDecision(form: HTMLFormElement, decision: 'approve' | 'deny'): Promise<boolean> {
  const data = new FormData(form)
  const body = new URLSearchParams()
  for (const [k, v] of data) if (k !== 'csrf' && k !== 'decision' && typeof v === 'string') body.append(k, v)
  body.set('decision', decision)
  try {
    // Same-origin credentials are fetch's default.
    const res = await fetch(form.action, {
      method: 'POST',
      headers: { Accept: 'application/json', 'X-CSRF-Token': String(data.get('csrf') ?? '') },
      body,
    })
    return res.ok && ((await res.json()) as { ok?: boolean }).ok === true
  } catch {
    return false
  }
}

/** Replace each [data-region]'s content with its sibling <template data-state=state>. */
export function swap(card: Element, state: string): boolean {
  let done = false
  for (const region of card.querySelectorAll('[data-region]')) {
    const tpl = region.parentElement?.querySelector<HTMLTemplateElement>(`:scope>template[data-state="${state}"]`)
    if (tpl) {
      region.replaceChildren(tpl.content.cloneNode(true))
      done = true
    }
  }
  return done
}

export function initDeviceConfirm(form: HTMLFormElement, deps: DeviceConfirmDeps = { post: postDecision, later: (f, ms) => void setTimeout(f, ms) }): void {
  const card = form.querySelector('.id-card') ?? form
  const status = card.querySelector('[data-status]')
  const say = (t: string) => status && (status.textContent = t)
  const [cancelBtn, confirmBtn] = ['deny', 'approve'].map((v) => form.querySelector<HTMLButtonElement>(`button[value="${v}"]`))
  let started = false
  const fail = () => {
    swap(card, 'error')
    say('Something went wrong.')
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault()
    if (started) return
    started = true
    if (cancelBtn) cancelBtn.disabled = true
    if (confirmBtn) confirmBtn.disabled = true
    if ((e as SubmitEvent).submitter === cancelBtn) {
      // The timer starts at the click, as in the mock; the swap waits for both.
      setConnector(card, 'broken')
      say('Cancelling…')
      let elapsed = false
      let ok: boolean | null = null
      const settle = () => {
        if (!elapsed || ok === null) return
        if (!ok) return fail()
        swap(card, 'cancelled')
        say('Cancelled')
      }
      deps.later(() => {
        elapsed = true
        settle()
      }, FAIL_SWAP_MS)
      ok = await deps.post(form, 'deny')
      settle()
      return
    }
    setConnector(card, 'connecting')
    if (confirmBtn) {
      confirmBtn.setAttribute('aria-busy', 'true')
      const label = confirmBtn.querySelector('span:last-child')
      if (label && confirmBtn.dataset.busyLabel) label.textContent = confirmBtn.dataset.busyLabel
    }
    say('Confirming…')
    if (await deps.post(form, 'approve')) {
      setConnector(card, 'done')
      deps.later(() => {
        swap(card, 'signed')
        say('Signed in')
      }, SUCCESS_SWAP_MS)
    } else {
      setConnector(card, 'broken')
      deps.later(fail, FAIL_SWAP_MS)
    }
  })
}

