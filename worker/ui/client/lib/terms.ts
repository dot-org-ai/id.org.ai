/**
 * The terms line (19b, 24b): input[data-js=terms]. The primary action, marked
 * [data-needs-terms], is disabled until the box is ticked. CSS already dims
 * it and the box is `required`; this sets the real `disabled` state.
 */
export function initTerms(box: HTMLInputElement): void {
  const actions = box.closest('form, [data-card]')?.querySelectorAll<HTMLButtonElement>('[data-needs-terms]') ?? []
  const sync = () => {
    for (const a of actions) a.disabled = !box.checked
  }
  box.addEventListener('change', sync)
  sync()
}
