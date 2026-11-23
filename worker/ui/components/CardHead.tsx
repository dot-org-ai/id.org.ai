import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'

export interface CardHeadProps {
  /** The connector (two tiles and five dots), or a single tile (1d). */
  connector?: Child
  title: Child
  /** Rich text: highlight names with <Em>. */
  description?: Child
}

/** The card head: connector, then the title and description, centred. */
export function CardHead({ connector, title, description }: CardHeadProps): JSX.Element {
  return (
    <div class="id-head">
      {connector}
      <div class="id-head__text">
        <h1 class="id-title" tabindex={-1}>{title}</h1>
        {description ? <p class="id-desc">{description}</p> : null}
      </div>
    </div>
  )
}

/** A name inside a description (app, email, workspace, person): fg, weight 500. */
export function Em({ children }: { children: Child }): JSX.Element {
  return <span class="id-em">{children}</span>
}
