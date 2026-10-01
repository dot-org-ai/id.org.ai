/**
 * Forms that stay on id.org.ai (4b, 5a, 5b, 5c, 2e, 3d, 6b): [data-js=fetch-form].
 * It posts with fetch (CSRF in X-CSRF-Token, never also in the body) and gets
 * JSON back (spec/motion.md#where-the-person-goes-next and the 4b reference
 * state machine).
 *   - The primary: `connecting` and busy; on { ok } `done`, then 2150ms later
 *     the template named by its data-done (default `done`) swaps in. { redirect } leaves at once.
 *   - A data-deny submitter (Cancel, Deny): `broken` at once and every action
 *     disabled; its data-done template swaps in once 1820ms have passed AND the
 *     server agreed.
 *   - Failures: `broken`; 1820ms after the click the template `error-<code>`,
 *     `error-cancel` (a failed deny) or `error` swaps in. With no template the
 *     buttons come back and the status region says so.
 * Every template is server-rendered into the page; the swapped-in title takes
 * focus, which announces the outcome. Without JS the form simply posts.
 */
import { FAIL_SWAP_MS, SUCCESS_SWAP_MS, type ConnectorState } from './connector'
import { busy } from './leave'

type Result = { ok: boolean; error?: string; redirect?: string }

export interface FetchDeps {
  post: (form: HTMLFormElement, submitter: HTMLButtonElement | null) => Promise<Result>
  later: (fn: () => void, ms: number) => unknown
  go: (url: string) => unknown
}

export async function postForm(form: HTMLFormElement, submitter: HTMLButtonElement | null): Promise<Result> {
  const data = new FormData(form)
  const body = new URLSearchParams()
  // These forms carry no files, so every value is a string.
  for (const [k, v] of data) if (k !== 'csrf') body.append(k, v as string)
  if (submitter?.name) body.set(submitter.name, submitter.value)
  try {
    const res = await fetch(form.action, { method: 'POST', headers: { Accept: 'application/json', 'X-CSRF-Token': data.get('csrf') + '' }, body })
    const json = (await res.json()) as Result
    return { ...json, ok: res.ok && json.ok !== false }
  } catch {
    return { ok: false }
  }
}

/** Replace each [data-region]'s content with its sibling <template data-state>, and focus the new title. */
export function swap(card: Element, state: string): boolean {
  let done = false
  for (const region of card.querySelectorAll('[data-region]')) {
    const tpl = region.parentElement?.querySelector<HTMLTemplateElement>(`:scope>template[data-state="${state}"]`)
    if (tpl) {
      region.replaceChildren(tpl.content.cloneNode(true))
      done = true
    }
  }
  card.querySelector<HTMLElement>('[data-region] h1')?.focus()
  return done
}

export function initFetchForm(
  form: HTMLFormElement,
  deps: FetchDeps = { post: postForm, later: (f, ms) => setTimeout(f, ms), go: (u) => (location.href = u) },
): void {
  // The form wraps the card, so it holds the connector, the regions and the status line.
  const card = form
  const conn = form.querySelector<HTMLElement>('[data-js=connector]')
  // Restart the connector's animations for each state (see lib/connector.ts setConnector).
  const setConnector = (_: unknown, s: ConnectorState) => {
    if (!conn) return
    conn.removeAttribute('data-state')
    void conn.offsetWidth
    conn.setAttribute('data-state', s)
  }
  const buttons = form.querySelectorAll('button')
  const status = card.querySelector('[data-status]')
  let started = false

  form.addEventListener('submit', async (e) => {
    e.preventDefault()
    if (started) return
    started = true
    const btn = (e as SubmitEvent).submitter as HTMLButtonElement | null
    const label = btn?.dataset.busyLabel
    const deny = btn?.hasAttribute('data-deny')
    for (const b of buttons) b.disabled = true
    if (status && label) status.textContent = label
    const showError = (code?: string) => {
      if (swap(card, `error-${code}`) || swap(card, deny ? 'error-cancel' : 'error')) return
      started = false
      for (const b of buttons) b.disabled = false
      if (status) status.textContent = 'Something went wrong. Try again.'
    }
    let elapsed = false
    let res: Result | null = null
    // A deny settles when both the 1820ms (from the click) and the server are done.
    const settle = () => elapsed && res && (res.ok ? swap(card, btn?.dataset.done ?? 'cancelled') : showError(res.error))
    if (deny) {
      setConnector(card, 'broken')
      deps.later(() => {
        elapsed = true
        settle()
      }, FAIL_SWAP_MS)
      res = await deps.post(form, btn)
      return void settle()
    }
    setConnector(card, 'connecting')
    if (btn && label) busy(btn, label)
    res = await deps.post(form, btn)
    if (res.redirect) return deps.go(res.redirect)
    const r = res
    setConnector(card, r.ok ? 'done' : 'broken')
    deps.later(() => (r.ok ? swap(card, btn?.dataset.done ?? 'done') : showError(r.error)), r.ok ? SUCCESS_SWAP_MS : FAIL_SWAP_MS)
  })
}
