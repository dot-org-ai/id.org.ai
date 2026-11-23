/**
 * Labels that follow a choice: [data-follow="<control name>"][data-template].
 * The primary action names what was picked: "Continue with Growth" follows the
 * plan radios (24a), "Approve $500/month" and "Raise to $750" follow a
 * select (9c, 12b, 19g). `{label}` in the template is the picked option's
 * data-short, or its text. Prices swap between monthly and yearly in CSS;
 * nothing here touches them.
 */
export function initFollow(label: HTMLElement): void {
  const scope = label.closest('form, [data-card]') ?? document
  const name = label.dataset.follow ?? ''
  const controls = [...scope.querySelectorAll<HTMLInputElement | HTMLSelectElement>(`[name="${name}"]`)]
  if (!controls.length) return
  const picked = (): string | undefined => {
    for (const c of controls) {
      if (c instanceof HTMLSelectElement) {
        const o = c.options[c.selectedIndex]
        return o?.dataset.short ?? o?.textContent?.trim()
      }
      if (c.checked) return c.dataset.short ?? c.value
    }
    return undefined
  }
  const sync = () => {
    const text = picked()
    if (text) label.textContent = (label.dataset.template ?? '{label}').replace('{label}', text)
  }
  for (const c of controls) c.addEventListener('change', sync)
  sync()
}
