import type { JSX } from 'hono/jsx/jsx-runtime'

/** Full-width segmented choice (19a: Card, Bank account, Link): 36px cells in a 4px padded well. */
export function SegTabs({ legend, name, options, selected }: { legend: string; name: string; options: { value: string; label: string }[]; selected: string }): JSX.Element {
  return (
    <fieldset class="id-fieldset">
      <legend class="id-sr">{legend}</legend>
      <div class="id-seg">
        {options.map((o) => (
          <label class="id-seg__cell" for={`${name}-${o.value}`}>
            <input class="id-hidden-input" type="radio" id={`${name}-${o.value}`} name={name} value={o.value} checked={o.value === selected ? true : undefined} />
            {o.label}
          </label>
        ))}
      </div>
    </fieldset>
  )
}
