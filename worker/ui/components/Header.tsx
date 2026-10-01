import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { LINKS } from '../links'
import { OrgMark } from './OrgMark'

export interface HeaderProps {
  /** Replaces the id.org.ai brand on branded first-party sign-in (1g). */
  brand?: Child
  /** Right-hand slot: usually empty (the phone action approval puts its countdown here). */
  right?: Child
}

export function Header({ brand, right }: HeaderProps): JSX.Element {
  return (
    <header class="id-header">
      {brand ?? (
        <a class="id-brand" href={LINKS.home}>
          <OrgMark size={18} />
          <span>id.org.ai</span>
        </a>
      )}
      {right}
    </header>
  )
}
