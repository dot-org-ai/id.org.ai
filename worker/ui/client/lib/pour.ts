/**
 * The header's mark (OrgMark `pour`, ui.css): it pours on load from the markup's
 * data-pour="load"; hovering the brand pours it again once it has settled.
 * The last mark's animationend clears data-pour, which is what "settled" means.
 */

export function initPour(mark: SVGSVGElement): void {
  const last = mark.lastElementChild
  if (!last) return
  const settle = () => mark.removeAttribute('data-pour')
  // The load pour can end before this module runs; nothing animates under reduced motion.
  const running = typeof last.getAnimations === 'function' && last.getAnimations().some((a) => a.playState !== 'finished')
  if (!running) settle()
  last.addEventListener('animationend', settle)
  const brand = mark.closest('a') ?? mark
  brand.addEventListener('mouseenter', () => {
    if (!mark.hasAttribute('data-pour')) mark.setAttribute('data-pour', 'hover')
  })
}
