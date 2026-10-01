import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'

/**
 * Radio cards stacked 8px apart in a fieldset whose legend is visually hidden,
 * for a group with no visible label (6b's sign-out scope). RadioGroup is the
 * labelled form (accessibility.md#structure).
 */
export function RadioStack({ legend, children }: { legend: string; children: Child }): JSX.Element {
  return (
    <fieldset class="id-fieldset">
      <legend class="id-sr">{legend}</legend>
      {children}
    </fieldset>
  )
}
