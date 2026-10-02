import type { JSX } from 'hono/jsx/jsx-runtime'

/** The dotted rule between open sections (layout.md#dividers); `label` gives the "or" form. */
export function Dotted({ label }: { label?: string }): JSX.Element {
  if (label) {
    return (
      <div class="id-rule id-rule--label">
        <div class="id-dots" aria-hidden="true"></div>
        <span>{label}</span>
        <div class="id-dots" aria-hidden="true"></div>
      </div>
    )
  }
  return (
    <div class="id-rule">
      <div class="id-dots" aria-hidden="true"></div>
    </div>
  )
}
