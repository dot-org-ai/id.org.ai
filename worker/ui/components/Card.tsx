import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'

export interface CardProps {
  /** The card body: head, then blocks, separated by the body gap. */
  children: Child
  /** The action band under the body. */
  foot?: Child
}

export function Card({ children, foot }: CardProps): JSX.Element {
  return (
    <div class="id-card" data-card>
      <div class="id-card__body" data-card-body>
        {children}
      </div>
      {foot}
    </div>
  )
}

export function CardFoot({ children }: { children: Child }): JSX.Element {
  return <div class="id-card__foot">{children}</div>
}
