/**
 * The header's mark (logos.md): [data-js=pour] pours on load and again on hover.
 * Frozen pages show it still.
 */
import { initPour } from './lib/pour'
import { enhance, isFrozen } from './lib/dom'

enhance<SVGSVGElement>('pour', (el) => {
  if (!isFrozen()) initPour(el)
})
