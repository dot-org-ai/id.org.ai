import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon } from '../icons'

export interface FieldProps {
  id: string
  label: string
  /** The right-hand hint on the label row ("From GitHub"). */
  aside?: string
  /** The hint under the control. */
  hint?: string
  /** Replaces the hint, in accent; the control gets aria-invalid. */
  error?: string
  children: Child
}

/** Label + control + hint (components.md#field-label--input). */
export function Field({ id, label, aside, hint, error, children }: FieldProps): JSX.Element {
  return (
    <div class="id-field">
      {aside ? (
        <div class="id-field__row">
          <label class="id-label" for={id}>
            {label}
          </label>
          <span class="id-field__aside">{aside}</span>
        </div>
      ) : (
        <div class="id-field__row">
          <label class="id-label" for={id}>
            {label}
          </label>
        </div>
      )}
      {children}
      {error ? (
        <span class="id-field__error" id={`${id}-error`}>
          {error}
        </span>
      ) : hint ? (
        <span class="id-field__hint" id={`${id}-hint`}>
          {hint}
        </span>
      ) : null}
    </div>
  )
}

export interface InputProps {
  id: string
  name: string
  type?: 'text' | 'email' | 'search' | 'url'
  value?: string
  placeholder?: string
  autocomplete?: string
  required?: boolean
  /**
   * Only for the invalid field on a server-rendered error, so focus lands on it
   * (accessibility.md#forms-and-errors). Never on a page's first render.
   */
  autofocus?: boolean
  maxlength?: number
  /** Matches the Field's hint/error ids. */
  hint?: boolean
  error?: boolean
}

export function Input(p: InputProps): JSX.Element {
  const describedBy = p.error ? `${p.id}-error` : p.hint ? `${p.id}-hint` : undefined
  // An address is typed as is: phone keyboards don't capitalise or correct it.
  const literal = p.type === 'email'
  return (
    <input
      class="id-input"
      id={p.id}
      name={p.name}
      type={p.type ?? 'text'}
      value={p.value}
      placeholder={p.placeholder}
      autocomplete={p.autocomplete}
      autocapitalize={literal ? 'none' : undefined}
      autocorrect={literal ? 'off' : undefined}
      spellcheck={literal ? false : undefined}
      required={p.required ? true : undefined}
      autofocus={p.autofocus ? true : undefined}
      maxlength={p.maxlength}
      aria-invalid={p.error ? 'true' : undefined}
      aria-describedby={describedBy}
    />
  )
}

export interface SelectOption {
  value: string
  label: string
}

/** Select: the input box, no native arrow, a chevrons-up-down icon at the right. */
export function Select({ id, name, options, selected, describedBy, invalid }: { id: string; name: string; options: SelectOption[]; selected?: string; describedBy?: string; invalid?: boolean }): JSX.Element {
  return (
    <div class="id-select-wrap">
      <select class="id-input id-select" id={id} name={name} aria-describedby={describedBy} aria-invalid={invalid ? 'true' : undefined}>
        {options.map((o) => (
          <option value={o.value} selected={o.value === selected ? true : undefined}>
            {o.label}
          </option>
        ))}
      </select>
      <span class="id-select__chev">
        <Icon name="chev_ud" size={14} />
      </span>
    </div>
  )
}

export function Textarea({ id, name, placeholder, maxlength, value, describedBy, invalid }: { id: string; name: string; placeholder?: string; maxlength?: number; value?: string; describedBy?: string; invalid?: boolean }): JSX.Element {
  return (
    <textarea class="id-input id-textarea" id={id} name={name} rows={3} placeholder={placeholder} maxlength={maxlength} aria-describedby={describedBy} aria-invalid={invalid ? 'true' : undefined}>
      {value ?? ''}
    </textarea>
  )
}
