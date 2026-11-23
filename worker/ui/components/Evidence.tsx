import type { JSX } from 'hono/jsx/jsx-runtime'
import { CopyButton } from './CopyButton'
import { Select } from './Field'
import { KeyValue } from './KeyValue'
import { Link } from './Link'

/** Evidence a step can carry (docs/agent-setup/HANDOFF.md section 4, the evidence table). */

/** Listening: a pulsing dot, one mono line, the elapsed time, one note. */
export function Listening({ text, elapsed, note }: { text: string; elapsed?: string; note?: string }): JSX.Element {
  return (
    <div class="id-well">
      <div class="id-evrow">
        <span class="id-listen">
          <span class="id-sdot id-sdot--busy" aria-hidden="true"></span>
          <span class="id-listen__text">{text}</span>
        </span>
        {elapsed ? <span class="id-listen__time">{elapsed}</span> : null}
      </div>
      {note ? <span class="id-help">{note}</span> : null}
    </div>
  )
}

export interface CallResultProps {
  method: string
  path: string
  /** HTTP status. 2xx reads green; anything else amber. */
  status: number
  /** "212 ms", or an error code such as "INVALID_VIN_FORMAT". */
  result?: string
  /** Up to three key-value rows from the answer. */
  rows?: [string, string][]
  link?: { href: string; label: string }
}

/** A call result: method and path, the status dot with code and latency, rows, a link. */
export function CallResult({ method, path, status, result, rows = [], link }: CallResultProps): JSX.Element {
  const ok = status >= 200 && status < 300
  return (
    <div class="id-well id-well--10">
      <div class="id-evrow id-evrow--wrap">
        <span class="id-call__req">
          <span class="id-call__method">{`${method} `}</span>
          {path}
        </span>
        <span class="id-call__status">
          <span class={ok ? 'id-sdot' : 'id-sdot id-sdot--warn'} aria-hidden="true"></span>
          {result ? `${status} · ${result}` : String(status)}
        </span>
      </div>
      {rows.length ? (
        <div class="id-call__rows">
          {rows.slice(0, 3).map(([k, v]) => (
            <KeyValue k={k} v={v} />
          ))}
        </div>
      ) : null}
      {link ? <Link href={link.href}>{link.label}</Link> : null}
    </div>
  )
}

/** A prompt: a label, a copy button, one line of mono text to paste to the agent. Also standalone (10c). */
export function PromptWell({ label, text, copied }: { label: string; text: string; copied?: boolean }): JSX.Element {
  return (
    <div class="id-well id-well--prompt">
      <div class="id-evrow">
        <span class="id-label">{label}</span>
        <CopyButton value={text} copied={copied} />
      </div>
      <span class="id-prompt__text">{text}</span>
    </div>
  )
}

export interface CompareRow {
  name: string
  /** "250 of 250 match", "181 of 250 so far". */
  text: string
  state: 'ok' | 'running'
}

/** Compare (16a, 16c): one row per call, green when every answer matches, blinking while running. */
export function CompareWell({ rows, note }: { rows: CompareRow[]; note?: string }): JSX.Element {
  return (
    <div class="id-well">
      {rows.map((r) => (
        <div class="id-compare__row">
          <span class="id-compare__name">{r.name}</span>
          <span class="id-compare__state">
            <span class={r.state === 'ok' ? 'id-sdot' : 'id-sdot id-sdot--busy'} aria-hidden="true"></span>
            {r.text}
          </span>
        </div>
      ))}
      {note ? <span class="id-help id-help--top">{note}</span> : null}
    </div>
  )
}

/** Field mapping (18a): a source column, then where it goes. The select's label is spoken, not shown. */
export function FieldMapRow({ id, name, column, options, value }: { id: string; name: string; column: string; options: string[]; value?: string }): JSX.Element {
  return (
    <div class="id-fieldmap">
      <span class="id-fieldmap__col">{column}</span>
      <div class="id-field">
        <label class="id-sr" for={id}>{`${column} goes to`}</label>
        <Select id={id} name={name} options={options.map((o) => ({ value: o, label: o }))} selected={value} />
      </div>
    </div>
  )
}
