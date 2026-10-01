import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'

/**
 * Radio cards stacked with no visible group label (2b's workspaces): a
 * fieldset whose legend is visually hidden (accessibility.md#structure), gap 8px.
 * RadioGroup is the variant with a visible label.
 */
export function RadioList({ legend, children }: { legend: string; children: Child }): JSX.Element {
  return (
    <fieldset class="id-fieldset">
      <legend class="id-sr">{legend}</legend>
      {children}
    </fieldset>
  )
}
