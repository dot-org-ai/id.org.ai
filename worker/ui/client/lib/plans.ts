/**
 * The plan picker (24a): [data-js=plans]. Keeps the primary action's label in
 * step with the selected plan ("Continue with Growth"). The label lives in the
 * card's [data-plan-label], whose data-template holds "Continue with {name}".
 * Prices swap between monthly and yearly in CSS; nothing here touches them.
 */
export function initPlans(root: HTMLElement): void {
  const label = root.closest('form, [data-card]')?.querySelector<HTMLElement>('[data-plan-label]')
  if (!label) return
  const sync = () => {
    const name = root.querySelector<HTMLInputElement>('[data-plan-name]:checked')?.dataset.planName
    if (name) label.textContent = (label.dataset.template ?? '{name}').replace('{name}', name)
  }
  root.addEventListener('change', sync)
  sync()
}
