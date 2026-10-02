import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Avatar } from './Avatar'

export interface WhoProps {
  name: string
  /** The second line: usually the email ("nathan@do.industries · Drivly admin" on 3d). */
  sub: string
  email?: string
  avatar?: string
  /** Right slot: the Switch link, a meta text ("Confirmed 3 hours ago"), or nothing. */
  right?: Child
}

/** Who row: the signed-in account, inside the card where the decision is made. */
export function Who({ name, sub, email, avatar, right }: WhoProps): JSX.Element {
  return (
    <div class="id-who">
      <Avatar name={name} email={email ?? sub} src={avatar} />
      <NameSub name={name} sub={sub} />
      {right}
    </div>
  )
}

/** Two-line text: name 14/500, sub-line 13 fg-3. */
export function NameSub({ name, sub }: { name: Child; sub: Child }): JSX.Element {
  return (
    <div class="id-namesub">
      <span class="id-namesub__name">{name}</span>
      <span class="id-namesub__sub">{sub}</span>
    </div>
  )
}

/** The who row's right-hand meta text ("Confirmed 3 hours ago"). */
export function WhoMeta({ children }: { children: Child }): JSX.Element {
  return <span class="id-who__meta">{children}</span>
}
