import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon } from '../icons'

export type StepState = 'done' | 'now' | 'you' | 'fail' | 'held' | 'todo'

export interface StepItemProps {
  state: StepState
  title: string
  detail?: Child
  /** The API a step belongs to (17b), before the detail text. */
  tag?: string
  /** The right-hand label: a time when done, "Now", "Waiting on you", "Declined", "Paused". None when todo. */
  when?: string
  /** Evidence under the detail: Listening, CallResult, PromptWell, a field, a well. */
  children?: Child
}

/** What a screen reader hears for the glyph, when the right-hand label doesn't already say it. */
const SPOKEN: Record<StepState, string> = { done: 'Done', now: 'In progress', you: 'Needs you', fail: 'Stopped', held: 'On hold', todo: 'Not started' }

function Glyph({ state }: { state: StepState }): JSX.Element {
  switch (state) {
    case 'done':
      return <Icon name="check" size={16} />
    case 'fail':
      return <Icon name="x" size={16} />
    case 'held':
      return <Icon name="pause" size={14} />
    case 'now':
      return (
        <>
          <span class="id-sstep__pulse"></span>
          <span class="id-sstep__dot"></span>
        </>
      )
    default:
      return <span class="id-sstep__dot"></span>
  }
}

/** A small mono label naming the API a step belongs to (17b). */
export function StepTag({ label }: { label: string }): JSX.Element {
  return <span class="id-steptag">{label}</span>
}

/**
 * One observed step (docs/agent-setup/HANDOFF.md section 4, Steps). The glyph
 * and rail are decorative; the state is spoken through visually hidden text.
 * A step ticks only when the product reports it: nothing here is a control.
 */
export function StepItem({ state, title, detail, tag, when, children }: StepItemProps): JSX.Element {
  return (
    <div class={`id-sstep id-sstep--${state}`} role="listitem">
      <div class="id-sstep__rail" aria-hidden="true">
        <span class="id-sstep__glyph">
          <Glyph state={state} />
        </span>
        <span class="id-sstep__line"></span>
      </div>
      <div class="id-sstep__body">
        <div class="id-sstep__head">
          <span class="id-sstep__title">
            {title}
            <span class="id-sr">{`. ${SPOKEN[state]}.`}</span>
          </span>
          {when ? <span class="id-sstep__when">{when}</span> : null}
        </div>
        {detail || tag ? (
          <span class="id-sstep__detail">
            {tag ? <StepTag label={tag} /> : null}
            {detail}
          </span>
        ) : null}
        {children ? <div class="id-sstep__evidence">{children}</div> : null}
      </div>
    </div>
  )
}

/**
 * The ordered list of steps a product posts. Changes are announced politely,
 * so a step ticking is heard without moving focus (HANDOFF.md section 6).
 */
export function StepList({ label, children }: { label: string; children: Child }): JSX.Element {
  return (
    <div class="id-steps" role="list" aria-label={label} aria-live="polite">
      {children}
    </div>
  )
}
